// Package archive analyses a compressed container — ZIP, TAR, gzip and their
// tar.gz nesting — as the subject of inspection in its own right. It asks
// container-hygiene questions (is this a decompression bomb, does a member
// escape the extraction root, is the single member a disguised executable, is
// the payload locked away behind encryption) rather than package-identity
// questions, which the linuxpkg detector owns. It never writes to disk, never
// executes a member, and bounds every read so a hostile archive cannot make it
// allocate or decompress without limit.
//
// One zip shape is looked into further: an Office Open XML document
// (.docm/.xlsm/.pptm and their macro-free siblings), whose embedded VBA
// project and attached-template relationship are inspected in ooxml.go.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/safefs"
	"github.com/s-b-repo/cau/scanner/ole"
)

// Parsing and safety limits.
const (
	// DefaultMaxSize is the largest archive read into memory.
	DefaultMaxSize int64 = 256 << 20
	// maxMembers bounds the entry count walked; a benign source tree is well
	// under this, and a central directory claiming more is itself suspicious.
	maxMembers = 100000
	// maxDecompress caps the bytes any single stream is decompressed to when
	// content must be inspected (gzip body, member magic), so a bomb cannot
	// expand without limit.
	maxDecompress = 64 << 20
	// maxMagicPeek is how many bytes of a member are decompressed to read its
	// magic; a few hundred is plenty and keeps streaming-deflate bombs bounded.
	maxMagicPeek = 512
	// maxMembersPeeked bounds how many members are opened for magic.
	maxMembersPeeked = 512
)

// Bomb thresholds. A ratio alone is not a bomb (a mostly-zero disk image
// compresses enormously and benignly), so the ratio must come with real
// absolute size, or the absolute size must be large on its own.
const (
	bombRatio    = 100
	bombRatioAbs = 50 << 20
	bombAbsolute = 1 << 30
)

// Scoring. The scale mirrors the sibling lnk/pdf/iso detectors
// (DefaultThreshold 8).
const (
	scoreBomb          = 7
	scorePathTraversal = 6
	scoreLureDoubleExt = 6
	scoreSingleExec    = 5
	scoreEncrypted     = 3
	scoreScriptMember  = 3
	scoreExecMember    = 2
	scoreNested        = 2
)

// ATT&CK techniques this detector maps to.
const (
	techMasquerade = "T1036"     // double-extension lure
	techUserExec   = "T1204.002" // a lone malicious file delivered in a container
	techObfuscated = "T1027"     // encrypted member, nesting to evade inspection
)

// DefaultThreshold is the shipped score at which a container is reported
// suspicious.
const DefaultThreshold = 8

// Threshold is used when a caller passes none. A variable so operators can
// retune it without a rebuild.
var Threshold = DefaultThreshold

// Options tunes an analysis.
type Options struct {
	Threshold int
	MaxSize   int64
	// OLEThreshold is handed to the OLE pass run over an OOXML document's
	// embedded vbaProject.bin (0 = the ole package default). It sets
	// EmbeddedVBA.Threshold only; the container's own verdict uses Threshold.
	OLEThreshold int
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one labeled container observation.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	// Evidence names the triggering member; it never carries member content.
	// For a finding carried out of an embedded VBA project it is the OLE
	// pass's evidence (a matched needle or stream name); for the remote
	// template it is the target host.
	Evidence string `json:"evidence,omitempty"`
	// Via names the member the finding was read out of, for findings that
	// came from inspecting one member's content (an OOXML vbaProject.bin or
	// relationship part). Empty for container-level findings.
	Via string `json:"via,omitempty"`
}

// Summary is the enumerated shape of the container, for the report.
type Summary struct {
	// Format is "zip", "tar", "gzip" or "tar.gz"; a zip recognised as an
	// Office Open XML document reads "ooxml-word", "ooxml-excel" or
	// "ooxml-powerpoint" instead.
	Format       string `json:"format"`
	Members      int    `json:"members"`
	Compressed   int64  `json:"compressed_bytes"`
	Uncompressed int64  `json:"uncompressed_bytes"`
	Encrypted    int    `json:"encrypted_members,omitempty"`
	Executables  int    `json:"executable_members,omitempty"`
	NotInspected string `json:"not_inspected,omitempty"`
	// VBAMember names the vbaProject.bin member the OLE pass was run over.
	VBAMember string `json:"vba_member,omitempty"`
}

// Result is the analysis of one container.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	Parsed    *Summary  `json:"parsed,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
	Error     error     `json:"-"`
	// EmbeddedVBA is the OLE pass's full result for an OOXML document's
	// vbaProject.bin member (has_vba, modules, the per-module source-state
	// table, its own score and threshold). Its findings are also carried into
	// Findings under the archive.ooxml.* classes and counted in Score, so it
	// is detail, not a second verdict. Nil when no VBA project was inspected.
	EmbeddedVBA *ole.Result `json:"embedded_vba,omitempty"`
}

// EffectiveThreshold returns the threshold applied to this result.
func (r *Result) EffectiveThreshold() int {
	if r == nil {
		return Threshold
	}
	if r.Threshold > 0 {
		return r.Threshold
	}
	return Threshold
}

// Detected reports whether the score reached the threshold.
func (r *Result) Detected() bool {
	return r != nil && r.Error == nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// HasObservation reports whether any finding fired below the threshold.
func (r *Result) HasObservation() bool {
	return r != nil && len(r.Findings) > 0
}

// IsArchive reports whether the buffer begins like a supported container.
func IsArchive(data []byte) bool {
	return isZip(data) || isGzip(data) || isTar(data)
}

func isZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		(data[2] == 3 && data[3] == 4 || data[2] == 5 && data[3] == 6 || data[2] == 7 && data[3] == 8)
}

func isGzip(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8
}

func isTar(data []byte) bool {
	// "ustar" lives at offset 257; also accept the older magic variants.
	if len(data) < 262 {
		return false
	}
	m := data[257:262]
	return string(m) == "ustar" || (m[0] == 'u' && m[1] == 's' && m[2] == 't' && m[3] == 'a' && m[4] == 'r')
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// supported container gets an immediate zero-score result.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	switch {
	case isZip(data):
		r.analyzeZip(data, opts)
	case isGzip(data):
		r.analyzeGzip(data)
	case isTar(data):
		r.analyzeTar(data)
	default:
		return r
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Class < r.Findings[j].Class })
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	return r
}

// ScanFile reads a file (subject to the size cap) and analyses it.
func ScanFile(path string, opts Options) *Result {
	max := opts.MaxSize
	if max <= 0 {
		max = DefaultMaxSize
	}
	fi, err := os.Stat(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "stat: " + err.Error()}
	}
	if fi.Size() > max {
		return &Result{FilePath: path, Threshold: opts.threshold(), Size: int(fi.Size()),
			Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit", fi.Size(), max)}
	}
	data, err := safefs.ReadFile(path, max)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── member classification ────────────────────────────────────────────────────

type memberKind int

const (
	kindOther memberKind = iota
	kindExecutable
	kindScript
)

// executable and script extensions that make a member a payload rather than
// data. Names are compared lower-cased.
var execExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true, ".cpl": true,
	".dll": true, ".jar": true, ".msi": true, ".msix": true, ".appx": true,
}
var scriptExts = map[string]bool{
	".js": true, ".jse": true, ".vbs": true, ".vbe": true, ".wsf": true, ".wsh": true,
	".hta": true, ".ps1": true, ".bat": true, ".cmd": true, ".lnk": true, ".scf": true,
	".reg": true, ".jnlp": true,
}

// lureFirstExts are the benign-looking extensions a double-extension lure wears
// before the real executable one (report.pdf.exe).
var lureFirstExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".txt": true, ".csv": true, ".rtf": true,
	".htm": true, ".html": true, ".mp4": true, ".mp3": true, ".invoice": true,
}

var archiveExts = map[string]bool{
	".zip": true, ".gz": true, ".tgz": true, ".tar": true, ".rar": true, ".7z": true,
	".bz2": true, ".xz": true, ".cab": true, ".iso": true,
}

func extKind(name string) memberKind {
	ext := strings.ToLower(path.Ext(name))
	switch {
	case execExts[ext]:
		return kindExecutable
	case scriptExts[ext]:
		return kindScript
	}
	return kindOther
}

// doubleExtensionLure reports the disguised name when a member wears a
// benign-looking extension immediately before an executable or script one.
func doubleExtensionLure(name string) bool {
	base := strings.ToLower(path.Base(name))
	last := path.Ext(base)
	if !execExts[last] && !scriptExts[last] {
		return false
	}
	stem := strings.TrimSuffix(base, last)
	prev := path.Ext(stem)
	return lureFirstExts[prev]
}

// pathEscapes reports whether a member name escapes the extraction root: an
// absolute path, a Windows drive path, or any ".." component (Zip-Slip).
func pathEscapes(name string) bool {
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") {
		return true
	}
	if len(n) >= 2 && n[1] == ':' { // C:\...
		return true
	}
	for _, c := range strings.Split(n, "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

func isNestedArchive(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	if ext == ".gz" { // foo.tar.gz counts once as nested
		return true
	}
	return archiveExts[ext]
}

// magicKind classifies up to maxMagicPeek bytes of member content.
func magicKind(b []byte) memberKind {
	if len(b) >= 2 && b[0] == 'M' && b[1] == 'Z' {
		return kindExecutable
	}
	if len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return kindExecutable
	}
	if len(b) >= 4 {
		switch {
		case b[0] == 0xfe && b[1] == 0xed && b[2] == 0xfa && (b[3] == 0xce || b[3] == 0xcf),
			b[0] == 0xcf && b[1] == 0xfa && b[2] == 0xed && b[3] == 0xfe,
			b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe:
			return kindExecutable
		}
	}
	if len(b) >= 2 && b[0] == '#' && b[1] == '!' {
		return kindScript
	}
	return kindOther
}

// ── collector ────────────────────────────────────────────────────────────────

// collector accumulates the signals a walk produces, then renders findings.
type collector struct {
	format        string
	members       int
	compressed    int64
	uncompressed  int64
	encrypted     int
	execMembers   int
	scriptMembers int
	traversal     []string
	doubleExt     []string
	nested        []string
	notInspected  string
	truncated     bool
	// ooxml holds the findings read out of an Office document's members
	// (ooxml.go); vbaMember names the VBA project they came from.
	ooxml     []Finding
	vbaMember string
}

// addNotInspected records why something was not inspected; the first reason
// is kept for the summary, as a hostile container can produce many.
func (c *collector) addNotInspected(why string) {
	if c.notInspected == "" {
		c.notInspected = why
	}
}

func (c *collector) note(name string, uncompressed, compressed int64, encrypted bool) {
	c.members++
	c.uncompressed += uncompressed
	c.compressed += compressed
	if encrypted {
		c.encrypted++
	}
	if pathEscapes(name) {
		c.traversal = append(c.traversal, name)
	}
	if doubleExtensionLure(name) {
		c.doubleExt = append(c.doubleExt, name)
	}
	if isNestedArchive(name) {
		c.nested = append(c.nested, name)
	}
}

func (c *collector) classify(name string, content []byte) memberKind {
	k := extKind(name)
	if k == kindOther && len(content) > 0 {
		k = magicKind(content)
	}
	switch k {
	case kindExecutable:
		c.execMembers++
	case kindScript:
		c.scriptMembers++
	}
	return k
}

func (c *collector) result(r *Result) {
	add := func(class string, score int, tech, detail, evidence string) {
		r.Findings = append(r.Findings, Finding{Class: class, Score: score, Technique: tech, Detail: detail, Evidence: evidence})
	}
	// Decompression bomb (declared sizes; a lying header is itself the tell).
	ratio := int64(0)
	if c.compressed > 0 {
		ratio = c.uncompressed / c.compressed
	}
	if (ratio >= bombRatio && c.uncompressed >= bombRatioAbs) || c.uncompressed >= bombAbsolute {
		add("archive.bomb", scoreBomb, "",
			fmt.Sprintf("decompresses to %d bytes from %d (%dx): decompression-bomb profile", c.uncompressed, c.compressed, ratio), "")
	}
	if len(c.traversal) > 0 {
		add("archive.path-traversal", scorePathTraversal, "",
			fmt.Sprintf("%d member name(s) escape the extraction root (Zip-Slip)", len(c.traversal)), firstOf(c.traversal))
	}
	if len(c.doubleExt) > 0 {
		add("archive.lure-double-extension", scoreLureDoubleExt, techMasquerade,
			fmt.Sprintf("%d member(s) wear a benign extension before an executable one", len(c.doubleExt)), firstOf(c.doubleExt))
	}
	switch {
	case c.members == 1 && c.execMembers == 1:
		add("archive.single-executable", scoreSingleExec, techUserExec,
			"the container holds exactly one member and it is an executable (malspam lure profile)", "")
	case c.execMembers > 0:
		add("archive.executable-member", scoreExecMember, "",
			fmt.Sprintf("%d executable member(s) carried inside the container", c.execMembers), "")
	}
	if c.scriptMembers > 0 {
		add("archive.script-member", scoreScriptMember, techUserExec,
			fmt.Sprintf("%d script member(s) (%s) carried inside the container", c.scriptMembers, "js/vbs/hta/ps1/…"), "")
	}
	if c.encrypted > 0 {
		add("archive.encrypted-entry", scoreEncrypted, techObfuscated,
			fmt.Sprintf("%d member(s) are encrypted and cannot be inspected", c.encrypted), "")
	}
	if len(c.nested) > 0 {
		add("archive.nested-archive", scoreNested, techObfuscated,
			fmt.Sprintf("%d nested archive member(s): a layer that must be unwrapped to inspect", len(c.nested)), firstOf(c.nested))
	}
	r.Findings = append(r.Findings, c.ooxml...)
	if c.truncated {
		// Members past the cap are not inspected, so the summary says so
		// rather than reading as a complete walk.
		c.addNotInspected("member cap reached: entries past it were not inspected")
	}
	r.Parsed = &Summary{
		Format: c.format, Members: c.members, Compressed: c.compressed, Uncompressed: c.uncompressed,
		Encrypted: c.encrypted, Executables: c.execMembers, NotInspected: c.notInspected,
		VBAMember: c.vbaMember,
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	if len(s[0]) > 200 {
		return s[0][:200]
	}
	return s[0]
}

// ── format walks ───────────────────────────────────────────────────────────

func (r *Result) analyzeZip(data []byte, opts Options) {
	c := &collector{format: "zip"}
	defer c.result(r)
	// The member limit is applied to the central directory's records before
	// zip.NewReader materialises one entry per record: that reader appends a
	// *zip.File for every record it reads, so a directory with millions of
	// records would allocate them all before the walk's own cap was consulted.
	if n, located := countZipMembers(data); located && n > maxMembers {
		c.truncated = true
		c.addNotInspected(fmt.Sprintf("zip central directory holds %d entries, over the %d-member limit", n, maxMembers))
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		c.notInspected = "zip central directory unreadable: " + err.Error()
		return
	}
	var office ooxml
	peeked := 0
	for _, f := range zr.File {
		if c.members >= maxMembers {
			c.truncated = true
			break
		}
		// bit 0 of the general-purpose flag marks an encrypted entry.
		encrypted := f.Flags&0x1 != 0
		c.note(f.Name, int64(f.UncompressedSize64), int64(f.CompressedSize64), encrypted)
		if f.FileInfo().IsDir() {
			continue
		}
		office.note(f)
		var content []byte
		if !encrypted && peeked < maxMembersPeeked {
			peeked++
			content = peekZip(f)
		}
		c.classify(f.Name, content)
	}
	// An Office Open XML document: the only zip whose members are opened
	// beyond the magic peek, and only the two that carry code or fetch it.
	if format := office.format(); format != "" {
		c.format = format
		office.inspect(r, c, opts.OLEThreshold)
	}
}

// ── zip central directory ───────────────────────────────────────────────────
//
// The walk above counts members by checking c.members inside its loop, but by
// then zip.NewReader has already appended a *zip.File for every
// central-directory record, so a directory holding millions of records
// allocates millions of entries before the cap takes effect. These helpers
// read the same records that reader does — signature, name/extra/comment
// lengths, next record — but allocate nothing but a counter, so the member
// limit is decided before the entry list exists.

const (
	zipCDHeaderLen  = 46         // fixed part of a central-directory record
	zipCDNameLen    = 28         // name-length field
	zipCDExtraLen   = 30         // extra-field length field
	zipCDCommentLen = 32         // comment-length field
	zipCDSignature  = 0x02014b50 // "PK\x01\x02"
)

const (
	zipEOCDSignature = 0x06054b50 // "PK\x05\x06"
	zipEOCDLen       = 22         // fixed part of the end-of-central-directory record
	zipEOCDEntries   = 10         // entries on this disk (uint16)
	zipEOCDSize      = 12         // central-directory size (uint32)
	zipEOCDOffset    = 16         // central-directory offset (uint32)
	zipEOCDTailScan  = 65 * 1024  // the record plus the longest comment it may carry
)

const (
	zip64EOCDSignature    = 0x06064b50 // "PK\x06\x06"
	zip64EOCDLen          = 56         // fixed part of the Zip64 end record
	zip64EOCDSize         = 40         // central-directory size (uint64) field
	zip64EOCDOffset       = 48         // central-directory offset (uint64) field
	zip64LocatorSignature = 0x07064b50 // "PK\x06\x07"
	zip64LocatorLen       = 20         // fixed part of the Zip64 locator
	zip64Saturated16      = 0xffff     // a 16-bit entry count holding this means "see Zip64"
	zip64Saturated32      = 0xffffffff // likewise for a 32-bit size or offset field
)

// countZipMembers counts the central directory's records without building
// them. It stops one past maxMembers, which is all the cap needs to know.
// ok is false when no usable end-of-central-directory record exists — the
// same failure zip.NewReader reports — and the caller then falls back to it.
func countZipMembers(data []byte) (n int, ok bool) {
	start, size, located := findZipDirectoryEnd(data)
	if !located {
		return 0, false
	}
	end := start + size
	if end < start || end > len(data) {
		end = len(data)
	}
	for p := start; p+zipCDHeaderLen <= end; {
		if le32(data, p) != zipCDSignature {
			break // a malformed record ends the directory, as it does for zip.NewReader
		}
		nameLen := int(le16(data, p+zipCDNameLen))
		extraLen := int(le16(data, p+zipCDExtraLen))
		commentLen := int(le16(data, p+zipCDCommentLen))
		step := zipCDHeaderLen + nameLen + extraLen + commentLen
		if step <= 0 || p+step > end {
			break
		}
		p += step
		n++
		if n > maxMembers {
			break
		}
	}
	return n, true
}

// findZipDirectoryEnd locates the end-of-central-directory record in the tail
// and derives where the central directory starts. A Zip64 record is consulted
// when the 16/32-bit end-record fields are saturated.
func findZipDirectoryEnd(data []byte) (cdStart, cdSize int, ok bool) {
	scan := zipEOCDTailScan
	if scan > len(data) {
		scan = len(data)
	}
	tail := data[len(data)-scan:]
	for p := len(tail) - zipEOCDLen; p >= 0; p-- {
		if le32(tail, p) != zipEOCDSignature {
			continue
		}
		if int(le16(tail, p+zipEOCDLen-2))+zipEOCDLen+p > len(tail) {
			continue // the comment is truncated: this is not a directory end
		}
		eocd := len(data) - scan + p
		off, size := le32(tail, p+zipEOCDOffset), le32(tail, p+zipEOCDSize)
		if off == zip64Saturated32 || size == zip64Saturated32 ||
			le16(tail, p+zipEOCDEntries) == zip64Saturated16 {
			if o, s, found := findZip64DirectoryEnd(data, eocd); found {
				off, size = o, s
			}
		}
		start, n := int(off), int(size)
		if start < 0 || n < 0 || start > len(data) {
			continue
		}
		// The declared offset is relative to the start of the archive, so a
		// self-extracting stub shifts it; the directory length then fixes
		// where it really begins.
		if le32(data, start) != zipCDSignature {
			alt := eocd - n - zipTrailerLen(data, eocd)
			if alt < 0 || alt+zipCDHeaderLen > len(data) || le32(data, alt) != zipCDSignature {
				continue
			}
			start = alt
		}
		return start, n, true
	}
	return 0, 0, false
}

// zipTrailerLen reports the length of the Zip64 end-of-central-directory
// records that may sit between the central directory and the end record.
func zipTrailerLen(data []byte, eocd int) int {
	if eocd-zip64EOCDLen >= 0 && le32(data, eocd-zip64LocatorLen) == zip64LocatorSignature &&
		le32(data, eocd-zip64EOCDLen) == zip64EOCDSignature {
		return zip64EOCDLen + zip64LocatorLen
	}
	return 0
}

// findZip64DirectoryEnd reads the Zip64 locator just before an end record and
// the Zip64 end record it points at.
func findZip64DirectoryEnd(data []byte, eocd int) (off, size uint32, ok bool) {
	loc := eocd - zip64LocatorLen
	if loc < 0 || le32(data, loc) != zip64LocatorSignature {
		return 0, 0, false
	}
	if le32(data, loc+4) != 0 || le32(data, loc+16) != 1 {
		return 0, 0, false // a multiple-disk archive is not walked
	}
	p := le64(data, loc+8)
	// The record must fit whole: the bound is written as a subtraction, so an
	// offset near the end of the address space cannot wrap the sum back
	// inside the buffer.
	if uint64(len(data)) < zip64EOCDLen || p > uint64(len(data))-zip64EOCDLen {
		return 0, 0, false
	}
	start := int(p)
	if le32(data, start) != zip64EOCDSignature {
		return 0, 0, false
	}
	o, s := le64(data, start+zip64EOCDOffset), le64(data, start+zip64EOCDSize)
	if o > uint64(len(data)) || s > uint64(len(data)) {
		return 0, 0, false
	}
	return uint32(o), uint32(s), true
}

func peekZip(f *zip.File) []byte {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	buf := make([]byte, maxMagicPeek)
	n, _ := io.ReadFull(io.LimitReader(rc, maxMagicPeek), buf)
	return buf[:n]
}

func (r *Result) analyzeTar(data []byte) {
	c := &collector{format: "tar"}
	defer c.result(r)
	c.walkTar(bytes.NewReader(data), int64(len(data)))
}

func (c *collector) walkTar(rd io.Reader, compressedSize int64) {
	tr := tar.NewReader(rd)
	// A tar carries no global compressed size per member; attribute the stream's
	// compressed size once so the bomb ratio is meaningful for tar.gz callers.
	c.compressed += compressedSize
	for c.members < maxMembers {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			c.notInspected = "tar stream error: " + err.Error()
			break
		}
		c.note(hdr.Name, hdr.Size, 0, false)
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		buf := make([]byte, maxMagicPeek)
		n, _ := io.ReadFull(io.LimitReader(tr, maxMagicPeek), buf)
		c.classify(hdr.Name, buf[:n])
	}
}

func (r *Result) analyzeGzip(data []byte) {
	c := &collector{format: "gzip"}
	defer c.result(r)
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		c.notInspected = "gzip header unreadable: " + err.Error()
		return
	}
	defer gr.Close()
	// Decompress a bounded prefix to classify the inner stream and measure the
	// expansion ratio. A real bomb trips the cap and is reported as one.
	limited := io.LimitReader(gr, maxDecompress+1)
	head := make([]byte, 512)
	hn, _ := io.ReadFull(limited, head)
	head = head[:hn]
	name := gzipName(data)

	if looksLikeTar(head) {
		c.format = "tar.gz"
		// Re-open and stream the inner tar from the start, bounded.
		gr2, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer gr2.Close()
			c.walkTar(io.LimitReader(gr2, maxDecompress), int64(len(data)))
		}
		return
	}
	// Single-stream gzip (foo.gz): drain the rest to size it, bounded.
	rest, _ := io.Copy(io.Discard, limited)
	c.members = 1
	c.compressed = int64(len(data))
	c.uncompressed = int64(len(head)) + rest
	if c.uncompressed > maxDecompress {
		c.uncompressed = maxDecompress
		c.notInspected = "gzip body exceeds the decompression cap"
	}
	c.classify(name, head)
}

func looksLikeTar(head []byte) bool {
	// A tar block is 512 bytes with "ustar" at offset 257; the gzip prefix we
	// read is 512, so the magic is visible when the inner stream is a tar.
	return len(head) >= 262 && string(head[257:262]) == "ustar"
}

func gzipName(data []byte) string {
	// FNAME (flag bit 3) stores the original name after the 10-byte header.
	if len(data) < 11 || data[3]&0x08 == 0 {
		return "gzip-member"
	}
	end := bytes.IndexByte(data[10:], 0)
	if end < 0 || end > 256 {
		return "gzip-member"
	}
	return string(data[10 : 10+end])
}

// ── little-endian field readers ──────────────────────────────────────────────
//
// Every record field is read through these, so a hostile length field can never
// index past the buffer: an out-of-range read returns 0.

func le16(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func le32(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func le64(b []byte, off int) uint64 {
	if off < 0 || off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

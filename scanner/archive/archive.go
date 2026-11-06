// Package archive analyses a compressed container — ZIP, TAR, gzip and their
// tar.gz nesting — as the subject of inspection in its own right. It asks
// container-hygiene questions (is this a decompression bomb, does a member
// escape the extraction root, is the single member a disguised executable, is
// the payload locked away behind encryption) rather than package-identity
// questions, which the linuxpkg detector owns. It never writes to disk, never
// executes a member, and bounds every read so a hostile archive cannot make it
// allocate or decompress without limit.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/safefs"
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
	Evidence string `json:"evidence,omitempty"`
}

// Summary is the enumerated shape of the container, for the report.
type Summary struct {
	Format       string `json:"format"` // "zip","tar","gzip","tar.gz"
	Members      int    `json:"members"`
	Compressed   int64  `json:"compressed_bytes"`
	Uncompressed int64  `json:"uncompressed_bytes"`
	Encrypted    int    `json:"encrypted_members,omitempty"`
	Executables  int    `json:"executable_members,omitempty"`
	NotInspected string `json:"not_inspected,omitempty"`
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
		r.analyzeZip(data)
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
	r.Parsed = &Summary{
		Format: c.format, Members: c.members, Compressed: c.compressed, Uncompressed: c.uncompressed,
		Encrypted: c.encrypted, Executables: c.execMembers, NotInspected: c.notInspected,
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

func (r *Result) analyzeZip(data []byte) {
	c := &collector{format: "zip"}
	defer c.result(r)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		c.notInspected = "zip central directory unreadable: " + err.Error()
		return
	}
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
		var content []byte
		if !encrypted && peeked < maxMembersPeeked {
			peeked++
			content = peekZip(f)
		}
		c.classify(f.Name, content)
	}
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

// Package chm analyses a Microsoft Compiled HTML Help file (CHM / ITSS). CHM is
// a long-standing malware-delivery vector: hh.exe will run embedded script and
// shortcut objects, and a .chm is a common lure wrapper around an executable.
//
// The ITSF/ITSP/PMGL directory lists every internal file's name and size
// WITHOUT decompression, so this pass enumerates the members and scores the
// payloads a help file has no business carrying — an embedded executable, a
// shortcut, a dangerous script type. It does NOT decompress the LZX content
// section, so HTML/script bodies (and the <OBJECT> shortcut/WinExec tradecraft
// inside them) are not inspected in v1; the report says so rather than guessing.
package chm

import (
	"os"
	"path"
	"sort"
	"strings"
)

// Parsing and safety limits.
const (
	DefaultMaxSize  int64 = 128 << 20
	maxCHMChunks          = 1 << 16
	maxCHMEntries         = 1 << 18
	maxCHMNameLen         = 1024
	maxCHMChunkSize       = 1 << 20
	itspHeaderLen         = 0x54
)

// Scoring (threshold 8, mirrors the sibling document detectors).
const (
	// A help file carrying an executable crosses the threshold on its own: no
	// legitimate CHM ships a PE, so the single signal is the verdict.
	scoreExecutable = 8
	scoreLNK        = 5
	scoreScript     = 4
	scoreManyExec   = 2
)

// ATT&CK techniques.
const (
	techUserExec  = "T1204.002" // a help file delivering an executable/shortcut
	techScripting = "T1059"     // an embedded dangerous-script member
)

// DefaultThreshold is the shipped score at which a CHM is reported suspicious.
const DefaultThreshold = 8

// Threshold is used when a caller passes none.
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

// Finding is one labeled CHM observation.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Summary is the enumerated shape of the CHM, for the report.
type Summary struct {
	Entries      int    `json:"entries"`
	ContentDirs  int    `json:"content_files,omitempty"`
	NotInspected string `json:"not_inspected,omitempty"`
}

// Result is the analysis of one CHM.
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
func (r *Result) HasObservation() bool { return r != nil && len(r.Findings) > 0 }

// IsCHM reports whether the buffer begins with the ITSF magic.
func IsCHM(data []byte) bool {
	return len(data) >= 0x60 && data[0] == 'I' && data[1] == 'T' && data[2] == 'S' && data[3] == 'F'
}

// dangerous member extensions carried inside a CHM.
var execExts = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true, ".ocx": true,
	".cpl": true, ".pif": true, ".msi": true, ".sys": true, ".drv": true,
}

// scriptExts are the dangerous script types. Plain .js/.jse are deliberately
// absent: help-file table-of-contents navigation uses JavaScript legitimately,
// so flagging it would be a false-positive machine.
var scriptExts = map[string]bool{
	".hta": true, ".vbs": true, ".vbe": true, ".wsf": true,
	".wsh": true, ".ps1": true, ".bat": true, ".cmd": true, ".reg": true, ".scf": true,
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// CHM gets an immediate zero-score result.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsCHM(data) {
		return r
	}
	names, truncated := enumerate(data)
	r.detect(names, truncated)
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
		return &Result{FilePath: path, Threshold: opts.threshold(), Size: int(fi.Size()), Skipped: "file over the in-memory size limit"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── detection ────────────────────────────────────────────────────────────────

func (r *Result) detect(names []string, truncated bool) {
	var execs, scripts, lnks []string
	content := 0
	for _, n := range names {
		if strings.HasPrefix(n, "/") {
			content++
		}
		ext := strings.ToLower(path.Ext(n))
		switch {
		case execExts[ext]:
			execs = append(execs, n)
		case ext == ".lnk":
			lnks = append(lnks, n)
		case scriptExts[ext]:
			scripts = append(scripts, n)
		}
	}
	add := func(class string, score int, tech, detail, evidence string) {
		r.Findings = append(r.Findings, Finding{Class: class, Score: score, Technique: tech, Detail: detail, Evidence: evidence})
	}
	if len(execs) > 0 {
		add("chm.embedded-executable", scoreExecutable, techUserExec,
			"a help file carries executable member(s): no legitimate CHM does", firstOf(execs))
		if len(execs) >= 2 {
			add("chm.multiple-executables", scoreManyExec, techUserExec,
				"multiple executable members carried in the CHM", "")
		}
	}
	if len(lnks) > 0 {
		add("chm.embedded-lnk", scoreLNK, techUserExec,
			"a Windows shortcut (.lnk) member — a user-execution delivery vector", firstOf(lnks))
	}
	if len(scripts) > 0 {
		add("chm.embedded-script", scoreScript, techScripting,
			"dangerous script member(s) (.hta/.vbs/.ps1/.bat/.cmd/.wsf/…) carried in the CHM", firstOf(scripts))
	}
	r.Parsed = &Summary{
		Entries:      len(names),
		ContentDirs:  content,
		NotInspected: "HTML/script bodies are LZX-compressed and not decompressed in v1",
	}
	if truncated {
		r.Parsed.NotInspected += "; directory walk hit a parse bound"
	}
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}
	n := s[0]
	if len(n) > 200 {
		n = n[:200]
	}
	return n
}

// ── ITSF/ITSP/PMGL directory walk ──────────────────────────────────────────────

// enumerate returns the internal file names listed in the CHM directory. It
// reads only the uncompressed directory (ITSP header + PMGL listing chunks);
// the LZX content section is never touched. truncated is true when a parse
// bound was hit.
func enumerate(data []byte) (names []string, truncated bool) {
	if len(data) < 0x60 {
		return nil, false
	}
	// ITSF header: header section 1 (the directory) at 0x48 (offset) / 0x50 (len).
	dirOff := le64(data, 0x48)
	dirLen := le64(data, 0x50)
	if dirOff == 0 || dirOff+0x54 > uint64(len(data)) {
		return nil, true
	}
	dir := data[dirOff:]
	if dirLen > 0 && dirLen <= uint64(len(dir)) {
		dir = dir[:dirLen]
	}
	if len(dir) < 0x54 || string(dir[0:4]) != "ITSP" {
		return nil, true
	}
	chunkSize := int(le32(dir, 0x10))
	firstPMGL := int32(le32(dir, 0x20))
	lastPMGL := int32(le32(dir, 0x24))
	numChunks := int(le32(dir, 0x2c))
	if chunkSize <= 0 || chunkSize > maxCHMChunkSize || numChunks < 0 || numChunks > maxCHMChunks {
		return nil, true
	}
	if firstPMGL < 0 {
		firstPMGL = 0
	}
	if lastPMGL < 0 || int(lastPMGL) >= numChunks {
		lastPMGL = int32(numChunks - 1)
	}
	seen := map[string]bool{}
	for ci := int(firstPMGL); ci <= int(lastPMGL) && ci < numChunks; ci++ {
		start := itspHeaderLen + ci*chunkSize
		if start < 0 || start+chunkSize > len(dir) || start+0x14 > len(dir) {
			truncated = true
			break
		}
		chunk := dir[start : start+chunkSize]
		if string(chunk[0:4]) != "PMGL" {
			continue // PMGI index chunk or padding; skip
		}
		freeSpace := int(le32(chunk, 0x4))
		end := chunkSize - freeSpace
		if end <= 0x14 || end > chunkSize {
			end = chunkSize
		}
		p := 0x14
		for p < end {
			nameLen, n, ok := encint(chunk, p, end)
			if !ok || nameLen == 0 || nameLen > maxCHMNameLen {
				break
			}
			p += n
			if p+int(nameLen) > end {
				break
			}
			name := string(chunk[p : p+int(nameLen)])
			p += int(nameLen)
			// Three ENCINTs follow: content section, offset, length.
			for k := 0; k < 3; k++ {
				_, n, ok := encint(chunk, p, end)
				if !ok {
					p = end
					break
				}
				p += n
			}
			name = printableName(name)
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
				if len(names) >= maxCHMEntries {
					return names, true
				}
			}
		}
	}
	return names, truncated
}

// encint decodes a CHM variable-length integer (big-endian, high bit =
// continuation) from b[p:limit].
func encint(b []byte, p, limit int) (val uint64, n int, ok bool) {
	for n < 10 && p+n < limit {
		c := b[p+n]
		val = (val << 7) | uint64(c&0x7f)
		n++
		if c&0x80 == 0 {
			return val, n, true
		}
	}
	return 0, 0, false
}

func le32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func le64(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return uint64(le32(b, off)) | uint64(le32(b, off+4))<<32
}

// printableName trims a member name to printable ASCII and bounds its length.
func printableName(s string) string {
	if len(s) > maxCHMNameLen {
		s = s[:maxCHMNameLen]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		} else if c >= 0x80 {
			b.WriteByte(c) // keep UTF-8 bytes for non-ASCII names
		}
	}
	return b.String()
}

// Package encchain detects an executable hidden behind one or more layers of
// text encoding — the NOVEL-012 / T1140 / T1027.013 gap the string detectors
// cannot see, because a base64- or hex-encoded PE/ELF has no contiguous
// MZ/ELF byte sequence to match.
//
// It is content-anchored by design: the signal is that a decoded layer IS a
// valid PE or ELF header, which an attacker cannot shed without losing the
// payload. It never matches on names or on the mere presence of base64. It is
// bounded by construction (layer, size and candidate caps) so a decompression
// or decode bomb cannot exhaust the scanner, and it is SUSPICIOUS-tier
// evidence, never a MALICIOUS verdict.
package encchain

import (
	"encoding/base64"
	"encoding/hex"
	"os"

	"github.com/s-b-repo/cau/internal/safefs"
)

// Tunables. Defaults are conservative to keep false positives low; the eval
// harness measures them.
const (
	// DefaultMaxLayers bounds how many times a candidate is peeled
	// (base64 of base64 of ...). 4 covers observed packers without inviting
	// a decode bomb.
	DefaultMaxLayers = 4
	// DefaultMinRun is the smallest encoded run (in alphabet characters)
	// considered. A valid PE needs e_lfanew + "PE\0\0", so a short run cannot
	// hold a validatable header; a larger floor also makes benign hits rarer.
	DefaultMinRun = 320
	// DefaultMaxDecoded caps the total bytes produced across every candidate
	// and layer of one file (the global budget).
	DefaultMaxDecoded = 64 << 20
	// DefaultMaxCandidates caps how many distinct encoded runs are peeled.
	DefaultMaxCandidates = 128
)

// Technique ids and the plan's NOVEL id.
const (
	techDecode   = "T1140"     // Deobfuscate/Decode Files or Information
	techEncoded  = "T1027.013" // Encrypted/Encoded File
	novelChain   = "NOVEL-012"
	weightPE     = 8 // a decoded PE/ELF is a strong, content-anchored signal
	weightNested = 2 // extra weight per layer beyond the first
)

// DefaultThreshold is the shipped score at which a file is reported
// suspicious; a single decoded executable crosses it.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can
// be retuned without a rebuild.
var Threshold = DefaultThreshold

// Options configure a scan. The zero value uses the defaults above.
type Options struct {
	MaxLayers     int
	MinRun        int
	MaxDecoded    int
	MaxCandidates int
	Threshold     int
}

func (o Options) maxLayers() int {
	if o.MaxLayers > 0 {
		return o.MaxLayers
	}
	return DefaultMaxLayers
}
func (o Options) minRun() int {
	if o.MinRun > 0 {
		return o.MinRun
	}
	return DefaultMinRun
}
func (o Options) maxDecoded() int {
	if o.MaxDecoded > 0 {
		return o.MaxDecoded
	}
	return DefaultMaxDecoded
}
func (o Options) maxCandidates() int {
	if o.MaxCandidates > 0 {
		return o.MaxCandidates
	}
	return DefaultMaxCandidates
}
func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one decoded executable.
type Finding struct {
	// Class is a stable id ("encchain.pe" / "encchain.elf").
	Class string `json:"class"`
	Score int    `json:"score"`
	// Encoding is the outermost layer's encoding ("base64" or "hex").
	Encoding string `json:"encoding"`
	// Depth is how many layers were peeled to reach the executable (1 = the
	// run decoded straight to a header).
	Depth int `json:"depth"`
	// Offset is the byte offset of the encoded run in the original file.
	Offset int `json:"offset"`
	// RunBytes is the length of the encoded run in alphabet characters.
	RunBytes  int    `json:"run_bytes"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	Detail    string `json:"detail"`
}

// Result is the outcome for one file.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	// Candidates is how many encoded runs were examined; LayersPeeled the
	// total decode operations; Budget true when the byte budget was hit.
	Candidates   int    `json:"candidates,omitempty"`
	LayersPeeled int    `json:"layers_peeled,omitempty"`
	Budget       bool   `json:"budget_exhausted,omitempty"`
	Skipped      string `json:"skipped,omitempty"`
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
	return r != nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// Analyze scans data for encoded executables.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	budget := opts.maxDecoded()
	spent := 0
	seen := map[string]bool{} // dedupe identical findings by class+depth+offset

	for _, run := range base64Runs(data, opts.minRun()) {
		if r.Candidates >= opts.maxCandidates() || spent >= budget {
			r.Budget = spent >= budget
			break
		}
		r.Candidates++
		for _, att := range run.attempts() {
			r.peel(att, "base64", run.offset, len(run.chars), 1, opts, &spent, budget, seen)
		}
	}
	for _, run := range hexRuns(data, opts.minRun()) {
		if r.Candidates >= opts.maxCandidates() || spent >= budget {
			r.Budget = spent >= budget
			break
		}
		r.Candidates++
		for _, att := range run.attempts() {
			r.peel(att, "hex", run.offset, len(run.chars), 1, opts, &spent, budget, seen)
		}
	}
	return r
}

// peel decodes one candidate and, if the decode is itself an encoded blob,
// recurses up to MaxLayers. origin is the encoding name reported; offset and
// runBytes describe the ORIGINAL run for the report.
func (r *Result) peel(encoded []byte, origin string, offset, runBytes, depth int, opts Options, spent *int, budget int, seen map[string]bool) {
	if depth > opts.maxLayers() || *spent >= budget {
		return
	}
	remaining := budget - *spent
	dec, ok := decodeBounded(encoded, origin, remaining)
	if !ok || len(dec) == 0 {
		return
	}
	*spent += len(dec)
	r.LayersPeeled++

	if class, detail, ok := executableHeader(dec); ok {
		key := class + ":" + itoa(depth) + ":" + itoa(offset)
		if seen[key] {
			return
		}
		seen[key] = true
		score := weightPE + (depth-1)*weightNested
		r.Findings = append(r.Findings, Finding{
			Class: class, Score: score, Encoding: origin, Depth: depth,
			Offset: offset, RunBytes: runBytes, Technique: pickTech(depth), Novel: novelChain,
			Detail: detail,
		})
		r.Score += score
		return
	}
	// Not an executable: if the decode is itself an encoded blob, go deeper.
	if inner := firstEncodedRun(dec, opts.minRun()); inner != nil {
		for _, att := range inner.attempts() {
			r.peel(att, inner.kind, offset, runBytes, depth+1, opts, spent, budget, seen)
		}
	}
}

func pickTech(depth int) string {
	// A straight decode is T1027.013 (an encoded file); peeling layers is the
	// decode activity T1140.
	if depth > 1 {
		return techDecode
	}
	return techEncoded
}

// decodeBounded decodes a base64/hex alphabet blob, capping output at max.
// kind is the known encoding ("base64" or "hex"); the alphabets overlap, so
// sniffing would be ambiguous. ok is false when the blob does not decode.
func decodeBounded(encoded []byte, kind string, max int) ([]byte, bool) {
	if kind == "hex" {
		return decodeHexBounded(encoded, max)
	}
	return decodeBase64Bounded(encoded, max)
}

func decodeBase64Bounded(encoded []byte, max int) ([]byte, bool) {
	// A base64 message ends at its '=' padding. If the run carries padding
	// followed by more alphabet text (an adjacent word merged across a line
	// break), truncate at the end of the padding quad so the blob decodes
	// cleanly in isolation.
	s := encoded
	if i := indexByte(s, '='); i >= 0 {
		end := ((i / 4) + 1) * 4
		if end <= len(s) {
			s = s[:end]
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if out, ok := tryBase64(enc, s, max); ok && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func tryBase64(enc *base64.Encoding, s []byte, max int) ([]byte, bool) {
	// Work on a 4-aligned prefix for padded encodings.
	trimmed := s
	if enc == base64.StdEncoding || enc == base64.URLEncoding {
		// drop a trailing partial quad unless it carries '='
		if n := len(trimmed) % 4; n != 0 {
			trimmed = trimmed[:len(trimmed)-n]
		}
	}
	if len(trimmed) == 0 {
		return nil, false
	}
	out := make([]byte, enc.DecodedLen(len(trimmed)))
	n, err := enc.Decode(out, trimmed)
	if err != nil {
		return nil, false
	}
	if n > max {
		n = max
	}
	return out[:n], true
}

func decodeHexBounded(encoded []byte, max int) ([]byte, bool) {
	s := encoded
	if len(s)%2 != 0 {
		s = s[:len(s)-1]
	}
	if len(s) == 0 {
		return nil, false
	}
	out := make([]byte, hex.DecodedLen(len(s)))
	n, err := hex.Decode(out, s)
	if err != nil || n == 0 {
		return nil, false
	}
	if n > max {
		n = max
	}
	return out[:n], true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// DefaultMaxSize is the largest file ScanFile reads into memory.
const DefaultMaxSize int64 = 64 << 20

// ScanFile reads a file (subject to the size cap) and analyses it. A file over
// the cap is reported Skipped, never an error.
func ScanFile(path string, opts Options) *Result {
	fi, err := osStat(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "stat: " + err.Error()}
	}
	if fi > DefaultMaxSize {
		return &Result{FilePath: path, Size: int(min64(fi, 1<<62)), Threshold: opts.threshold(),
			Skipped: "file over the in-memory size limit"}
	}
	data, err := safefs.ReadFile(path, DefaultMaxSize)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

func osStat(p string) (int64, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

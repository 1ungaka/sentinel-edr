// Package tradecraft asks what a file does rather than what it is called. The
// signature, string and structure passes answer "have we seen this?" and "is it
// built oddly?", and both are silent on a plain-text webshell or on shellcode
// pasted into a script as a byte array: such a file names no malware family and
// has no structure to be odd about. Measured on the lab corpus (docs/evaluation.md)
// that gap was the difference between 0 % and useful recall on the classes most
// intrusions actually use.
//
// It has two halves, one Analyze:
//
//   - Script vectors (script.go): language-specific behaviour in text. A request
//     parameter reaching an exec sink, a socket wired to an interpreter, a
//     PowerShell or VBA loader allocating and running memory. Vectors name
//     behaviour, never a tool, so they do not lean on a project's name or
//     author strings surviving.
//
//   - Payload bytes (shellcode.go): what position-independent code has to do to
//     run at all. Walking the PEB to find modules while hashing export names,
//     API-hash constants computed from the API names themselves, self-decoding
//     stubs, and raw Linux socket syscalls.
//
// Carriers (carrier.go) connect the two: byte arrays and encoded blobs in text
// are decoded and analysed again, so shellcode in a C array, a PowerShell list,
// a VBA Array() or a base64-gzip chain meets the same checks as raw bytes.
//
// It only reads bytes. Nothing decoded here is ever executed.
package tradecraft

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// DefaultMaxSize is the largest file analysed. Payload checks run to this size;
// script vectors stop at maxScriptBytes.
const DefaultMaxSize = 64 << 20

// DefaultThreshold is the shipped score at which a file is reported suspicious.
const DefaultThreshold = 8

// Threshold is used when a caller passes none.
var Threshold = DefaultThreshold

// Options tunes an analysis.
type Options struct {
	Threshold int
	MaxSize   int
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

func (o Options) maxSize() int {
	if o.MaxSize > 0 {
		return o.MaxSize
	}
	return DefaultMaxSize
}

// Finding is one labeled observation.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Result is the analysis of one file.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	// Decoded counts the carrier layers that were decoded and analysed.
	Decoded int    `json:"decoded,omitempty"`
	Skipped string `json:"skipped,omitempty"`
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

// walker is the state of one analysis across its decoded layers. Each class
// counts once however many layers show it: the same stub in three encodings is
// one piece of evidence.
type walker struct {
	seen    map[string]bool
	out     []Finding
	decoded int
	budget  int // bytes of decoded output left
}

func (w *walker) add(class string, c catalogEntry, origin, evidence string) {
	if w.seen[class] {
		return
	}
	w.seen[class] = true
	evidence = strings.Clone(evidence) // a substring of the text would pin all of it
	detail := c.detail
	if origin != "" {
		detail += " (after decoding " + origin + ")"
	}
	w.out = append(w.out, Finding{Class: class, Score: c.score, Technique: c.technique, Detail: detail, Evidence: evidence})
}

// Analyze inspects data and returns a non-nil Result.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if len(data) > opts.maxSize() {
		r.Skipped = fmt.Sprintf("file is %d bytes, over the %d byte limit", len(data), opts.maxSize())
		return r
	}
	w := &walker{seen: map[string]bool{}, budget: maxDecodedTotal}
	w.analyze(data, 0, "")
	sort.SliceStable(w.out, func(i, j int) bool {
		if w.out[i].Score != w.out[j].Score {
			return w.out[i].Score > w.out[j].Score
		}
		return w.out[i].Class < w.out[j].Class
	})
	for _, f := range w.out {
		r.Score += f.Score
	}
	r.Findings = w.out
	r.Decoded = w.decoded
	return r
}

func (w *walker) analyze(data []byte, depth int, origin string) {
	if len(data) == 0 {
		return
	}
	if text, ok := asText(data); ok {
		text = unescape(text)
		w.scanScript(text, origin)
		for _, blob := range carriers(text, w) {
			next := blob.kind
			if origin != "" {
				next = origin + ">" + blob.kind
			}
			w.decoded++
			if depth < maxDepth {
				w.analyze(blob.data, depth+1, next)
			}
		}
		return
	}
	w.scanBytes(data, origin)
}

// asText returns data as text when it is a script rather than a binary: UTF-16
// with a byte-order mark is decoded, and anything with a NUL near the start or
// too few printable bytes is not text.
func asText(data []byte) (string, bool) {
	if len(data) >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)) {
		return decodeUTF16(data[2:], data[0] == 0xFF), true
	}
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	control, high := 0, 0
	for _, b := range head {
		switch {
		case b == 0:
			return "", false
		case b < 9 || (b > 13 && b < 32) || b == 127:
			control++
		case b >= 0x80:
			high++
		}
	}
	// Encoded shellcode is built to contain no NUL, so a NUL check alone calls
	// it text. Real text is mostly ASCII or valid UTF-8.
	if control*10 > len(head) || (high*4 > len(head) && !utf8.Valid(trimRune(head))) {
		return "", false
	}
	// A view, not a copy: nothing here writes to data, and it outlives this scan.
	return unsafe.String(unsafe.SliceData(data), len(data)), true // audit:ok safe only while scan buffers are never pooled or written; add clones the evidence it keeps
}

// trimRune drops a multi-byte sequence the 8 KiB head may have cut in half.
func trimRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		if r, _ := utf8.DecodeLastRune(b); r != utf8.RuneError {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}

func decodeUTF16(b []byte, little bool) string {
	var s strings.Builder
	s.Grow(len(b) / 2)
	for i := 0; i+1 < len(b); i += 2 {
		u := uint16(b[i+1])<<8 | uint16(b[i])
		if !little {
			u = uint16(b[i])<<8 | uint16(b[i+1])
		}
		s.WriteRune(rune(u))
	}
	return s.String()
}

// unescape undoes the shell quoting that msfvenom and hand-written one-liners
// wrap around a payload (exec\(__import__\(\'zlib\'\)), so a vector written
// against the language still reads it.
var unescaper = strings.NewReplacer(`\(`, `(`, `\)`, `)`, `\'`, `'`)

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return unescaper.Replace(s)
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

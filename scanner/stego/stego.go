package stego

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/s-b-repo/cau/internal/safefs"
)

// DefaultThreshold is the shipped score at which a text artifact is reported
// as suspicious. Every scored class weighs at least this much, so the default
// is presence-based; raising it to 8 requires one of the modifiers (payload
// run, ASCII carrier) as well.
const DefaultThreshold = 4

// Threshold is the threshold used when a caller does not pass one. It is a
// variable so operators can retune it without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory.
const DefaultMaxSize int64 = 64 << 20

// Class weights and modifiers.
const (
	weightZeroWidth  = 6
	weightBidi       = 6
	weightTag        = 6
	weightVS         = 4
	weightRun        = 2
	weightASCII      = 2
	payloadRunLength = 8
	maxExamples      = 2
	exampleRadius    = 16
	maxControlShare  = 0.01
)

// Technique and novel-technique ids attached to the findings.
const (
	techObfuscation = "T1027"
	novelDeadDrop   = "NOVEL-001"
)

// Codepoint summarises every occurrence of one invisible codepoint.
type Codepoint struct {
	Rune rune `json:"-"`
	// Code is the U+XXXX spelling.
	Code  string `json:"codepoint"`
	Name  string `json:"name"`
	Class string `json:"class"`
	// Count is how many times the codepoint occurred; Benign how many of
	// those a context rule excused. Count-Benign is what scored.
	Count  int `json:"count"`
	Benign int `json:"benign_context,omitempty"`
	// FirstOffset / FirstLine locate the first occurrence that was not
	// excused (or the first occurrence at all when every one was).
	FirstOffset int `json:"first_offset"`
	FirstLine   int `json:"first_line"`
	// Excuses names the context rules that applied, with counts.
	Excuses map[string]int `json:"excuses,omitempty"`
	// Examples are bounded snippets around unexcused occurrences with the
	// invisible codepoints rendered as <U+XXXX>.
	Examples []string `json:"examples,omitempty"`
}

// Finding is one labeled, scored class of evidence.
type Finding struct {
	// Class is "stego.<class>" or a modifier ("stego.payload-run",
	// "stego.ascii-carrier"); stable, like static anomaly classes.
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Detail    string `json:"detail"`
	Technique string `json:"technique,omitempty"`
	// Novel is the plan's NOVEL-xxx id when the finding belongs to a
	// technique without an ATT&CK entry of its own.
	Novel string `json:"novel,omitempty"`
}

// Result is the outcome for one artifact.
type Result struct {
	FilePath string `json:"path,omitempty"`
	Size     int    `json:"size"`
	// IsText reports whether the bytes decoded as a text artifact. Encoding
	// is "utf-8", "utf-16le" or "utf-16be" when they did.
	IsText   bool   `json:"is_text"`
	Encoding string `json:"encoding,omitempty"`
	// Skipped is the reason the content was not examined (not text, too
	// large). A skipped file is neither detected nor an error.
	Skipped string `json:"skipped,omitempty"`

	Codepoints []Codepoint `json:"codepoints,omitempty"`
	// Suspicious is the number of occurrences that scored; Benign the number
	// a context rule excused; Info the number of unscored marks seen.
	Suspicious int `json:"suspicious"`
	Benign     int `json:"benign,omitempty"`
	Info       int `json:"info,omitempty"`
	// LongestRun is the longest run of consecutive scored codepoints.
	LongestRun int `json:"longest_run,omitempty"`
	// ASCIICarrier counts scored occurrences embedded between ASCII text.
	ASCIICarrier int `json:"ascii_carrier,omitempty"`
	Lines        int `json:"lines,omitempty"`

	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	Error     error     `json:"-"`
}

// Options tunes a scan.
type Options struct {
	// Threshold overrides the package Threshold (0 = package default).
	Threshold int
	// MaxSize overrides DefaultMaxSize for ScanFile (0 = default).
	MaxSize int64
}

// EffectiveThreshold returns the threshold that applies to this result.
func (r *Result) EffectiveThreshold() int {
	if r.Threshold > 0 {
		return r.Threshold
	}
	return Threshold
}

// Detected reports whether the score reached the threshold.
func (r *Result) Detected() bool {
	if r == nil || r.Error != nil || r.Skipped != "" {
		return false
	}
	return r.Score >= r.EffectiveThreshold()
}

// HasObservation reports whether any invisible codepoint was recorded at all,
// scored or not.
func (r *Result) HasObservation() bool {
	return r != nil && len(r.Codepoints) > 0
}

// ScanFile reads a file (subject to the size cap) and scans it.
func ScanFile(path string, opts Options) *Result {
	r := &Result{FilePath: path, Threshold: opts.Threshold}
	max := opts.MaxSize
	if max <= 0 {
		max = DefaultMaxSize
	}
	fi, err := os.Stat(path)
	if err != nil {
		r.Error = fmt.Errorf("could not stat file: %w", err)
		return r
	}
	if fi.IsDir() {
		r.Error = fmt.Errorf("%s is a directory", path)
		return r
	}
	if fi.Size() > max {
		r.Size = int(fi.Size())
		r.Skipped = fmt.Sprintf("file is %d bytes, over the %d byte size limit", fi.Size(), max)
		return r
	}
	data, err := safefs.ReadFile(path, max)
	if err != nil {
		r.Error = fmt.Errorf("could not read file: %w", err)
		return r
	}
	out := Scan(data, opts)
	out.FilePath = path
	return out
}

// Scan examines an in-memory buffer. It never panics on hostile input.
func Scan(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.Threshold}
	it, enc, why := decoder(data)
	if it == nil {
		r.Skipped = "not a text artifact: " + why
		return r
	}
	r.IsText = true
	r.Encoding = enc

	s := &state{r: r, byRune: map[rune]*Codepoint{}}
	s.run(it)
	s.finish()
	return r
}

// ── decoding ─────────────────────────────────────────────────────────────────

// iterator yields (rune, byte offset, byte length) in order.
type iterator func() (r rune, off, size int, ok bool)

// decoder picks the text encoding and rejects binary content. It returns a nil
// iterator with a reason when the bytes are not a text artifact.
func decoder(data []byte) (iterator, string, string) {
	if len(data) == 0 {
		return nil, "", "empty file"
	}
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return utf16Iterator(data, binary.LittleEndian, "utf-16le")
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return utf16Iterator(data, binary.BigEndian, "utf-16be")
	}
	if !utf8.Valid(data) {
		return nil, "", "not valid UTF-8"
	}
	controls := 0
	for _, b := range data {
		switch {
		case b == 0:
			return nil, "", "contains NUL bytes"
		case b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != '\f' && b != '\v' && b != 0x1B, b == 0x7F:
			controls++
		}
	}
	if float64(controls) > maxControlShare*float64(len(data)) {
		return nil, "", fmt.Sprintf("%d control bytes in %d (binary content)", controls, len(data))
	}
	off := 0
	return func() (rune, int, int, bool) {
		if off >= len(data) {
			return 0, 0, 0, false
		}
		r, n := utf8.DecodeRune(data[off:])
		o := off
		off += n
		return r, o, n, true
	}, "utf-8", ""
}

func utf16Iterator(data []byte, order binary.ByteOrder, name string) (iterator, string, string) {
	if len(data)%2 != 0 {
		return nil, "", name + " with an odd byte count"
	}
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:]))
	}
	controls := 0
	for _, u := range units[1:] { // skip the BOM
		switch {
		case u == 0:
			return nil, "", name + " contains NUL code units"
		case u < 0x20 && u != '\t' && u != '\n' && u != '\r' && u != '\f' && u != '\v' && u != 0x1B, u == 0x7F:
			controls++
		}
	}
	if float64(controls) > maxControlShare*float64(len(units)) {
		return nil, "", fmt.Sprintf("%d control code units in %d (binary content)", controls, len(units))
	}
	i := 0 // unit index; the BOM itself is reported as U+FEFF at offset 0
	return func() (rune, int, int, bool) {
		if i >= len(units) {
			return 0, 0, 0, false
		}
		u := units[i]
		off := i * 2
		if utf16.IsSurrogate(rune(u)) {
			if i+1 < len(units) {
				if r := utf16.DecodeRune(rune(u), rune(units[i+1])); r != utf8.RuneError {
					i += 2
					return r, off, 4, true
				}
			}
			i++
			return utf8.RuneError, off, 2, true
		}
		i++
		return rune(u), off, 2, true
	}, name, ""
}

// ── scanning ─────────────────────────────────────────────────────────────────

// pending is an occurrence waiting for the visible characters that follow it,
// so the context rule can look both ways and the example can show both sides.
type pending struct {
	r        rune
	k        kind
	off      int
	line     int
	prevBase rune // nearest visible rune before, -1 at start of file
	prevVS   bool // immediately preceded by another invisible codepoint
	before   []rune
	after    []rune
	// classified is set once the context rule has run; example is set when
	// the occurrence still wants context collected for an example.
	classified bool
	example    bool
	lineRTL    bool // the line holds right-to-left text (set when classified)
}

type state struct {
	r      *Result
	byRune map[rune]*Codepoint

	line     int
	prevBase rune
	prevInv  bool
	runLen   int
	lineRTL  bool                // a right-to-left character occurred on the current line
	recent   [exampleRadius]rune // ring of the last runes, visible or not, for examples
	pushed   int                 // runes ever pushed, so pushed%exampleRadius is the next slot
	pend     []*pending
}

// maxPending bounds the occurrences held back for line-level context on a
// pathological single-line input; past it they are judged with what is known.
const maxPending = 4096

func (s *state) run(next iterator) {
	s.line = 1
	s.prevBase = -1
	for {
		r, off, _, ok := next()
		if !ok {
			break
		}
		if k, inv := classify(r); inv {
			s.runLen++
			p := &pending{r: r, k: k, off: off, line: s.line, prevBase: s.prevBase, prevVS: s.prevInv}
			p.before = s.appendRecent(p.before)
			s.pushRecent(r) // earlier occurrences see it on their right; this one must not
			s.pend = append(s.pend, p)
			s.prevInv = true
			continue
		}
		// A visible rune: resolve everything waiting for its right-hand side.
		if isRTLScript(r) {
			s.lineRTL = true
		}
		s.resolve(r)
		if r == '\n' {
			s.line++
			s.lineRTL = false
		}
		s.prevBase = r
		s.prevInv = false
		if s.runLen > s.r.LongestRun {
			s.r.LongestRun = s.runLen
		}
		s.runLen = 0
		s.pushRecent(r)
	}
	s.resolve(-1)
	if s.runLen > s.r.LongestRun {
		s.r.LongestRun = s.runLen
	}
	s.r.Lines = s.line
}

// appendRecent appends the ring to dst, oldest first.
func (s *state) appendRecent(dst []rune) []rune {
	for i := max(0, s.pushed-exampleRadius); i < s.pushed; i++ {
		dst = append(dst, s.recent[i%exampleRadius])
	}
	return dst
}

func (s *state) pushRecent(r rune) {
	s.recent[s.pushed%exampleRadius] = r
	s.pushed++
	for _, p := range s.pend {
		if len(p.after) < exampleRadius {
			p.after = append(p.after, r)
		}
	}
}

// resolve settles the pending occurrences against the visible rune that
// follows them (-1 at end of file). Occurrences keep collecting example
// context until the window is full or the line ends.
func (s *state) resolve(nextBase rune) {
	keep := s.pend[:0]
	lineEnd := nextBase == '\n' || nextBase == -1 || len(s.pend) > maxPending
	for _, p := range s.pend {
		if !p.classified {
			// Directional controls are judged against the whole line: the
			// embedding that opens a right-to-left run comes before the
			// first right-to-left character.
			if p.k.class == ClassBidiControl && !lineEnd {
				keep = append(keep, p)
				continue
			}
			p.classified = true
			p.lineRTL = s.lineRTL
			p.example = s.classifyOccurrence(p, nextBase)
		}
		if !p.example {
			continue
		}
		if len(p.after) >= exampleRadius || nextBase == '\n' || nextBase == -1 {
			s.emitExample(p)
			continue
		}
		keep = append(keep, p)
	}
	s.pend = keep
}

// classifyOccurrence applies the context rules and records the occurrence.
// It reports whether an example should be collected for it (scored, and the
// codepoint has room for another example).
func (s *state) classifyOccurrence(p *pending, nextBase rune) bool {
	cp := s.byRune[p.r]
	if cp == nil {
		cp = &Codepoint{Rune: p.r, Code: fmt.Sprintf("U+%04X", p.r), Name: p.k.name, Class: p.k.class, FirstOffset: p.off, FirstLine: p.line}
		s.byRune[p.r] = cp
		s.r.Codepoints = append(s.r.Codepoints, *cp)
	}
	cp.Count++

	if p.k.class == ClassInfo {
		s.r.Info++
		s.sync(cp)
		return false
	}
	if why := excuse(p, nextBase); why != "" {
		cp.Benign++
		if cp.Excuses == nil {
			cp.Excuses = map[string]int{}
		}
		cp.Excuses[why]++
		s.r.Benign++
		s.sync(cp)
		return false
	}
	// Scored.
	if cp.Count-cp.Benign == 1 {
		cp.FirstOffset, cp.FirstLine = p.off, p.line
	}
	s.r.Suspicious++
	if isASCIIText(p.prevBase) && (isASCIIText(nextBase) || nextBase == -1) && p.prevBase != -1 {
		s.r.ASCIICarrier++
	}
	s.sync(cp)
	return len(cp.Examples) < maxExamples
}

// excuse returns the context rule that makes this occurrence benign, or "".
func excuse(p *pending, next rune) string {
	r := p.r
	switch {
	case r == 0xFEFF && p.off == 0:
		return "byte-order mark"
	case r == 0x200D && (isPictographic(p.prevBase) || isEmojiModifier(p.prevBase) || isPictographic(next)):
		return "emoji sequence"
	case (r == 0x200D || r == 0x200C) && (isJoiningScript(p.prevBase) || isJoiningScript(next)):
		return "joining script"
	case r == 0x200B && (isSpacelessScript(p.prevBase) || isSpacelessScript(next)):
		return "spaceless script"
	case p.k.class == ClassBidiControl && p.lineRTL:
		return "bidirectional text"
	case r == 0x180E && (isJoiningScript(p.prevBase) || isJoiningScript(next)):
		return "joining script"
	case p.k.class == ClassVariationSelector && !p.prevVS:
		switch {
		case (r == 0xFE0E || r == 0xFE0F) && (isPictographic(p.prevBase) || isEmojiModifier(p.prevBase)):
			return "emoji presentation"
		case r >= 0xFE00 && r <= 0xFE0D && isCJKIdeograph(p.prevBase):
			return "ideographic variant"
		case r >= 0xE0100 && isCJKIdeograph(p.prevBase):
			return "ideographic variant"
		}
	case p.k.class == ClassTag && p.prevBase == 0x1F3F4:
		return "subdivision flag"
	}
	return ""
}

func (s *state) sync(cp *Codepoint) {
	for i := range s.r.Codepoints {
		if s.r.Codepoints[i].Rune == cp.Rune {
			s.r.Codepoints[i] = *cp
			return
		}
	}
}

func (s *state) emitExample(p *pending) {
	cp := s.byRune[p.r]
	if cp == nil || len(cp.Examples) >= maxExamples {
		return
	}
	var b strings.Builder
	render := func(r rune) {
		switch {
		case r == -1:
		case r == '\n':
			b.WriteString("\\n")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7F:
			fmt.Fprintf(&b, "<U+%04X>", r)
		default:
			if _, inv := classify(r); inv {
				fmt.Fprintf(&b, "<U+%04X>", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	for _, r := range p.before {
		render(r)
	}
	render(p.r)
	for _, r := range p.after {
		render(r)
	}
	cp.Examples = append(cp.Examples, fmt.Sprintf("line %d: %s", p.line, b.String()))
	s.sync(cp)
}

// finish derives the findings and the score.
func (s *state) finish() {
	r := s.r
	sort.Slice(r.Codepoints, func(i, j int) bool {
		a, b := r.Codepoints[i], r.Codepoints[j]
		if (a.Count - a.Benign) != (b.Count - b.Benign) {
			return (a.Count - a.Benign) > (b.Count - b.Benign)
		}
		return a.Rune < b.Rune
	})
	if r.Suspicious == 0 {
		return
	}
	perClass := map[string][]Codepoint{}
	for _, cp := range r.Codepoints {
		if cp.Count-cp.Benign > 0 {
			perClass[cp.Class] = append(perClass[cp.Class], cp)
		}
	}
	add := func(class string, weight int, novel string, cps []Codepoint) {
		if len(cps) == 0 {
			return
		}
		parts := make([]string, 0, len(cps))
		first := cps[0]
		for _, cp := range cps {
			parts = append(parts, fmt.Sprintf("%d× %s %s", cp.Count-cp.Benign, cp.Code, cp.Name))
			if cp.FirstLine < first.FirstLine {
				first = cp
			}
		}
		r.Findings = append(r.Findings, Finding{
			Class:     "stego." + class,
			Score:     weight,
			Detail:    fmt.Sprintf("%s; first at line %d", strings.Join(parts, ", "), first.FirstLine),
			Technique: techObfuscation,
			Novel:     novel,
		})
		r.Score += weight
	}
	add(ClassZeroWidth, weightZeroWidth, novelDeadDrop, perClass[ClassZeroWidth])
	add(ClassBidiControl, weightBidi, "", perClass[ClassBidiControl])
	add(ClassTag, weightTag, novelDeadDrop, perClass[ClassTag])
	add(ClassVariationSelector, weightVS, novelDeadDrop, perClass[ClassVariationSelector])

	if r.LongestRun >= payloadRunLength {
		r.Findings = append(r.Findings, Finding{Class: "stego.payload-run", Score: weightRun, Technique: techObfuscation,
			Detail: fmt.Sprintf("%d consecutive invisible codepoints (encoded payload length)", r.LongestRun)})
		r.Score += weightRun
	}
	if r.ASCIICarrier > 0 {
		r.Findings = append(r.Findings, Finding{Class: "stego.ascii-carrier", Score: weightASCII, Technique: techObfuscation,
			Detail: fmt.Sprintf("%d of %d scored codepoints sit between ASCII text (dead-drop carrier pattern)", r.ASCIICarrier, r.Suspicious)})
		r.Score += weightASCII
	}
}

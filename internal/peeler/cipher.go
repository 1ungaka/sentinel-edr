package peeler

import (
	"sort"
	"strconv"
	"strings"
)

// Decoded is one output of a layer, under the name the chain records for it: the
// Caesar shift that fit, or the radix a list of numbers turned out to be, so
// "caesar-7" and "caesar-9" stay different families.
type Decoded struct {
	Data  []byte
	Label string
}

// multiUnwrapper is a layer that can yield several outputs from one blob. Each is
// its own branch: a script carrying three payloads is three chains, and each
// goes on through whatever layers that payload has.
type multiUnwrapper interface {
	UnwrapAll(blob []byte, limit int64) ([]Decoded, error)
}

// unwrapLayer decodes one layer into the branches it opens.
func unwrapLayer(u Unwrapper, blob []byte, limit int64) ([]Decoded, error) {
	if m, ok := u.(multiUnwrapper); ok {
		return m.UnwrapAll(blob, limit)
	}
	out, err := u.Unwrap(blob, limit)
	if err != nil {
		return nil, err
	}
	return []Decoded{{Data: out, Label: u.Name()}}, nil
}

// firstOf adapts a multiUnwrapper to the single-output Unwrap every layer has.
func firstOf(ds []Decoded, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, ErrNotThisLayer
	}
	return ds[0].Data, nil
}

// cipher is one candidate substitution, written as the transform that undoes it.
type cipher struct {
	name    string
	table   [256]byte
	reverse bool
}

func (c *cipher) apply(dst, src []byte) {
	if c.reverse {
		for i, b := range src {
			dst[len(src)-1-i] = b
		}
		return
	}
	for i, b := range src {
		dst[i] = c.table[b]
	}
}

func identity() (t [256]byte) {
	for i := range t {
		t[i] = byte(i)
	}
	return t
}

// rotate maps a contiguous range of size n back by shift.
func rotate(t *[256]byte, first byte, n, shift int) {
	for i := 0; i < n; i++ {
		t[int(first)+i] = first + byte((i-shift+n)%n)
	}
}

func caesarTable(shift int) [256]byte {
	t := identity()
	rotate(&t, 'A', 26, shift)
	rotate(&t, 'a', 26, shift)
	return t
}

// ciphers is every substitution there is to try. The list is the fixed set the
// name "rot" covers in practice: rot13 first because it is by far the most common,
// then the remaining Caesar shifts, rot47, rot5 and rot18, atbash, and reversal.
var (
	caesarCiphers = buildCaesar()
	rot13Cipher   = caesarCiphers[13]
	rot5Cipher    = &cipher{name: "rot5", table: rot5Table()}
	rot18Cipher   = &cipher{name: "rot18", table: rot18Table()}
	rot47Cipher   = &cipher{name: "rot47", table: rot47Table()}
	atbashCipher  = &cipher{name: "atbash", table: atbashTable()}
	reverseCipher = &cipher{name: "reverse", reverse: true}
	ciphers       = buildCiphers()
)

// buildCaesar indexes the shifts by amount. Slot 0 is unused, because shift 0 is
// the text as it stands, and a blob is never rotated by 0.
func buildCaesar() (out [26]*cipher) {
	for shift := 1; shift <= 25; shift++ {
		name := "caesar-" + strconv.Itoa(shift)
		if shift == 13 {
			name = "rot13"
		}
		out[shift] = &cipher{name: name, table: caesarTable(shift)}
	}
	return out
}

func rot5Table() [256]byte {
	t := identity()
	rotate(&t, '0', 10, 5)
	return t
}

func rot18Table() [256]byte {
	t := caesarTable(13)
	rotate(&t, '0', 10, 5)
	return t
}

func rot47Table() [256]byte {
	t := identity()
	rotate(&t, '!', 94, 47)
	return t
}

func atbashTable() [256]byte {
	t := identity()
	for i := 0; i < 26; i++ {
		t['A'+i] = byte('Z' - i)
		t['a'+i] = byte('z' - i)
	}
	return t
}

func buildCiphers() []*cipher {
	out := []*cipher{rot13Cipher}
	for shift := 1; shift <= 25; shift++ {
		if shift != 13 {
			out = append(out, caesarCiphers[shift])
		}
	}
	return append(out, rot47Cipher, rot5Cipher, rot18Cipher, atbashCipher, reverseCipher)
}

// isCipher reports a chain step that is a substitution. No packaging tool
// produces one, which is why a single such layer already counts as obfuscation.
func isCipher(step string) bool {
	return strings.HasPrefix(step, "rot") || strings.HasPrefix(step, "caesar-") ||
		step == "atbash" || step == "reverse"
}

// cipherLayer tries every substitution and yields the one that reveals something,
// if any does, so thirty candidates are at most one child and the frontier width
// stays honest. It carries binary too: the PHP webshell staple
// gzinflate(str_rot13(base64_decode(...))) rotates compressed bytes.
type cipherLayer struct{}

func (cipherLayer) Name() string { return "cipher" }

func (cipherLayer) Detect(b []byte) bool { return len(b) >= minLayerLen }

func (l cipherLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	return firstOf(l.UnwrapAll(b, limit))
}

const (
	// binaryTrialWindow is enough for a header, and for the 512 bytes of a
	// compressed stream inflatesToText reads.
	binaryTrialWindow = 1024
	// minFitWindow is the least text that letter frequencies can be trusted on.
	// Below it, trying everything is both safer and cheap.
	minFitWindow = 96
)

// englishLetters is the percentage frequency of a to z in English text.
var englishLetters = [26]float64{8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4,
	6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074}

// bestShifts ranks the Caesar shifts by how much like English the letters read
// once undone, by chi-squared over a single histogram. Shift 0 means the text
// already does.
func bestShifts(w []byte) (best, second int) {
	var counts [26]float64
	total := 0.0
	for _, c := range w {
		c |= 0x20
		if c >= 'a' && c <= 'z' {
			counts[c-'a']++
			total++
		}
	}
	bestFit, secondFit := -1.0, -1.0
	for shift := 0; shift < 26; shift++ {
		fit := 0.0
		for i, want := range englishLetters {
			expected := want / 100 * total
			got := counts[(i+shift)%26]
			fit += (got - expected) * (got - expected) / (expected + 1)
		}
		switch {
		case bestFit < 0 || fit < bestFit:
			second, secondFit = best, bestFit
			best, bestFit = shift, fit
		case secondFit < 0 || fit < secondFit:
			second, secondFit = shift, fit
		}
	}
	return best, second
}

// candidates narrows the thirty ciphers to the ones worth a trial, because this
// runs on every text file and each trial is a keyword search. Rotated text gives
// its shift away in the letter frequencies, and text that already reads as itself
// has no shift to find. An encoding gives nothing away, its letters being evenly
// spread, so a token still gets every cipher. So does anything too short to
// count, and binary, whose trial is only a magic check.
func candidates(w []byte, binary bool) []*cipher {
	if binary || len(w) < minFitWindow || isToken(textBody(w)) {
		return ciphers
	}
	best, second := bestShifts(w)
	if best == 0 {
		return []*cipher{reverseCipher} // a reversal keeps the letter counts
	}
	out := []*cipher{caesarCiphers[best]}
	if second != 0 { // shift 0 is the text as it stands: there is no such cipher
		out = append(out, caesarCiphers[second])
	}
	if best == 13 || second == 13 {
		out = append(out, rot18Cipher)
	}
	return append(out, rot47Cipher, atbashCipher, reverseCipher)
}

// maxCipherHits bounds the branches one blob can open here. More than one fits
// only when rotations collide, which the walk's sibling check folds together.
const maxCipherHits = 3

func (cipherLayer) UnwrapAll(b []byte, limit int64) ([]Decoded, error) {
	if int64(len(b)) > limit {
		return nil, errBombCap
	}
	w := window(b)
	binary := printableFraction(w) < minPlainFraction
	if binary {
		w = w[:min(len(w), binaryTrialWindow)]
		// Header bytes are not letters, so a rotated gzip would still read as gzip.
		if knownFormat(w) {
			return nil, ErrNotThisLayer
		}
	} else if revealsAt(w, 0, true) {
		return nil, ErrNotThisLayer // already readable: nothing to undo
	}
	trial := make([]byte, len(w))
	var hits []Decoded
	for _, c := range candidates(w, binary) {
		src := w
		if c.reverse {
			src = b[len(b)-len(w):] // the head of the reversed blob
		}
		c.apply(trial, src)
		if binary {
			// Only a header or a compressed stream can be hiding in binary.
			if !knownFormat(trial) && !(c == rot13Cipher && inflatesToText(trial)) {
				continue
			}
		} else if !reveals(trial) {
			continue
		}
		out := make([]byte, len(b))
		c.apply(out, b)
		if hits = append(hits, Decoded{Data: out, Label: c.name}); len(hits) >= maxCipherHits {
			break
		}
	}
	if hits == nil {
		return nil, ErrNotThisLayer
	}
	return hits, nil
}

// carveLayer lifts an encoded blob out of the script around it. Every other layer
// reads a whole blob, but a dropper is a line of shell or PowerShell around one
// long literal. Only a run that reveals something is carved, so the identifiers,
// hashes and data URIs in ordinary files are left alone.
type carveLayer struct{}

const (
	carveStep   = "carve"
	minCarveRun = 64
	// maxCarveRuns bounds how many runs are tried. A certificate bundle has a
	// run on every line, and longest-first keeps the real candidates in range.
	maxCarveRuns = 64
)

func (carveLayer) Name() string { return carveStep }

func (carveLayer) Detect(b []byte) bool {
	return len(b) >= minCarveRun && printableFraction(window(b)) >= 0.85
}

func (l carveLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	return firstOf(l.UnwrapAll(b, limit))
}

// UnwrapAll yields every run that reveals something, longest first, so a dropper
// holding several payloads opens a branch for each of them.
func (carveLayer) UnwrapAll(b []byte, limit int64) ([]Decoded, error) {
	var runs [][]byte
	for i := 0; i < len(b); {
		if !base64Byte(b[i]) {
			i++
			continue
		}
		start := i
		for i < len(b) && (base64Byte(b[i]) || b[i] == '=') {
			i++
		}
		if i-start == len(b) {
			return nil, ErrNotThisLayer // the blob itself: a job for the base layers
		}
		if i-start >= minCarveRun {
			runs = append(runs, b[start:i])
		}
	}
	sort.SliceStable(runs, func(i, j int) bool { return len(runs[i]) > len(runs[j]) })
	var hits []Decoded
	for _, run := range runs[:min(len(runs), maxCarveRuns)] {
		if !revealsPayload(run) {
			continue
		}
		if int64(len(run)) > limit {
			return nil, errBombCap
		}
		limit -= int64(len(run))
		hits = append(hits, Decoded{Data: append([]byte(nil), run...), Label: carveStep})
	}
	if hits == nil {
		return nil, ErrNotThisLayer
	}
	return hits, nil
}

// utf16Layer drops the NUL bytes of UTF-16LE text, which is what PowerShell's
// -EncodedCommand decodes to and so what sits under most of its base64.
type utf16Layer struct{}

func (utf16Layer) Name() string { return "utf16" }

func (utf16Layer) Detect(b []byte) bool {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
	}
	if len(b) < minLayerLen {
		return false
	}
	for i := 1; i < minLayerLen; i += 2 {
		if b[i] != 0 || b[i-1] == 0 {
			return false
		}
	}
	return true
}

func (utf16Layer) Unwrap(b []byte, limit int64) ([]byte, error) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
	}
	out := make([]byte, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] != 0 {
			return nil, ErrNotThisLayer // not ASCII-range text: leave it alone
		}
		out = append(out, b[i])
	}
	if int64(len(out)) > limit {
		return nil, errBombCap
	}
	if !plausible(out) {
		return nil, ErrNotThisLayer
	}
	return out, nil
}

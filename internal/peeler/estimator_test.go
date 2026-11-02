package peeler

import (
	"bytes"
	"testing"
)

func TestShannonEntropyBounds(t *testing.T) {
	// All-identical bytes → entropy 0.
	if p := estimate(bytes.Repeat([]byte{0x41}, 256)); p.entropy != 0 {
		t.Errorf("uniform-byte entropy = %f, want 0", p.entropy)
	}
	// A perfectly uniform distribution over all 256 values → entropy 8.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if p := estimate(all); p.entropy < 7.99 || p.entropy > 8.0 {
		t.Errorf("uniform-dist entropy = %f, want ~8", p.entropy)
	}
	// Empty input → zero profile, no panic.
	if p := estimate(nil); p.entropy != 0 {
		t.Errorf("empty entropy = %f, want 0", p.entropy)
	}
}

func TestPrintableFraction(t *testing.T) {
	p := estimate([]byte("plain ascii text only"))
	if p.printableFraction < 0.99 {
		t.Errorf("printable fraction = %f, want ~1", p.printableFraction)
	}
	p = estimate([]byte{0x00, 0x01, 0x02, 0x03})
	if p.printableFraction != 0 {
		t.Errorf("binary printable fraction = %f, want 0", p.printableFraction)
	}
}

func TestRankPrefersMagicLayers(t *testing.T) {
	// A blob that both gzip (magic) and flate (length-only) would "detect":
	// gzip must rank ahead of flate.
	blob := encodeLayer("gzip", bytes.Repeat([]byte("abc"), 32))
	ranked := rankUnwrappers(blob, DefaultUnwrappers(), estimate(blob))
	if len(ranked) == 0 {
		t.Fatal("no unwrapper ranked for a gzip blob")
	}
	if ranked[0].Name() != "gzip" {
		t.Errorf("top-ranked = %s, want gzip", ranked[0].Name())
	}
}

func TestRankTextEncodingWhenPrintable(t *testing.T) {
	// A base64 blob is highly printable → base64 should rank ahead of flate
	// (which also "detects" on length alone).
	blob := []byte("QUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJD") // base64 of "ABC"*...
	ranked := rankUnwrappers(blob, DefaultUnwrappers(), estimate(blob))
	var sawBase64, sawFlate int = -1, -1
	for i, u := range ranked {
		if u.Name() == "base64" {
			sawBase64 = i
		}
		if u.Name() == "flate" {
			sawFlate = i
		}
	}
	if sawBase64 == -1 {
		t.Fatal("base64 not ranked for a base64 blob")
	}
	if sawFlate != -1 && sawBase64 > sawFlate {
		t.Errorf("base64 (idx %d) ranked below flate (idx %d)", sawBase64, sawFlate)
	}
}

func TestRankOnlyReturnsDetectors(t *testing.T) {
	// Plain prose matches no compression magic and is not a valid encoding;
	// ranking returns only genuine detectors (here: none that fully match).
	blob := []byte("The quick brown fox jumps over the lazy dog. ")
	for _, u := range rankUnwrappers(blob, DefaultUnwrappers(), estimate(blob)) {
		if !u.Detect(blob) {
			t.Errorf("%s ranked but does not Detect the blob", u.Name())
		}
	}
}

func TestRootEntropyReported(t *testing.T) {
	// A gzipped (high-entropy) chain should report a high root entropy.
	blob := compose(fakeELF, "gzip", "base64")
	r := New().Peel(nil, blob)
	if r.RootEntropy <= 0 {
		t.Errorf("root entropy not reported: %f", r.RootEntropy)
	}
}

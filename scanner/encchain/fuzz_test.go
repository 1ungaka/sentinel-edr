package encchain

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// FuzzAnalyze drives the encoded-executable layer peeler with mutated input.
// The peeler decodes untrusted base64/hex runs, recursively, up to its layer
// and byte budgets; the invariant is that it never panics and always returns a
// non-nil result, however malformed or adversarial the bytes are. Seeds cover
// clean text, a PE/ELF header encoded once and nested, and deliberately broken
// encodings.
func FuzzAnalyze(f *testing.F) {
	peHeader := append([]byte("MZ"), make([]byte, 64)...)
	elfHeader := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	b64 := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }
	hx := func(b []byte) []byte {
		out := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(out, b)
		return out
	}

	seeds := [][]byte{
		{},
		[]byte("just some clean ascii text, nothing encoded here"),
		b64(peHeader),      // one base64 layer -> PE
		hx(elfHeader),      // one hex layer -> ELF
		b64(b64(peHeader)), // nested base64 -> base64 -> PE
		b64(append([]byte("powershell -enc "), b64(peHeader)...)),
		[]byte("TVqQAAMAAAAEAAAA"), // real base64 MZ prefix
		[]byte("====not=valid=base64===="),
		[]byte("zzzz not hex gggg"),
		append([]byte("prefix "), b64(peHeader)...),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		// Reported counters must stay internally consistent: a finding cannot
		// exist without a layer having been peeled.
		if len(r.Findings) > 0 && r.LayersPeeled == 0 {
			t.Fatalf("findings reported with zero layers peeled: %+v", r)
		}
	})
}

package static

import (
	"bytes"
	"testing"
)

// Structural-detection robustness: a dropper profile (RWX + high-entropy
// executable segment, non-system interpreter, loader-only imports) must keep
// crossing the threshold when benign data is appended. Structural anomalies
// live in the headers/segments, so appending an overlay can only add findings,
// never remove them; this locks that in and catches a regression that made an
// append hide the signal. Synthetic fixtures only.
func dropperELFSpec() elfSpec {
	s := benignELFSpec()
	s.sections[0].pflags = pfR | pfW | pfX
	hi := make([]byte, 4096) // high-entropy executable segment (unpack target)
	for i := range hi {
		hi[i] = byte((uint64(i)*2654435761 + 7) >> 8)
	}
	s.sections[0].data = hi
	s.interp = "/tmp/.x/ld.so"
	s.imports = []string{"dlopen", "dlsym"}
	return s
}

func TestStaticDetectionRobustness(t *testing.T) {
	base := buildELF(t, dropperELFSpec())
	if r := Analyze(base, Options{NoFuzzy: true}); !r.Detected() {
		t.Fatalf("dropper baseline not detected: score %d, %+v", r.Score, classesOf(r))
	}

	lowOverlay := bytes.Repeat([]byte("benign license text. "), 400)
	highOverlay := make([]byte, 8192)
	for i := range highOverlay {
		highOverlay[i] = byte((uint64(i)*2654435761 + 13) & 0xff)
	}
	transforms := []struct {
		name string
		fn   func([]byte) []byte
	}{
		{"identity", func(b []byte) []byte { return b }},
		{"append-lowentropy-overlay", func(b []byte) []byte { return append(append([]byte{}, b...), lowOverlay...) }},
		{"append-highentropy-overlay", func(b []byte) []byte { return append(append([]byte{}, b...), highOverlay...) }},
	}
	for _, tr := range transforms {
		r := Analyze(tr.fn(base), Options{NoFuzzy: true})
		if !r.Detected() {
			t.Errorf("BRITTLE: appending data (%s) dropped the structural detection: score %d, %+v",
				tr.name, r.Score, classesOf(r))
		}
	}
}

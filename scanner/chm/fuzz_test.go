package chm

import "testing"

// FuzzAnalyze drives the ITSF/ITSP/PMGL directory walk with mutated input. The
// parser reads attacker-controlled section offsets, chunk sizes, chunk counts,
// PMGL free-space values and ENCINT name lengths through range-checked accesses
// with caps on chunks, entries and name length. The invariant is that Analyze
// never panics and always returns a non-nil result, that a non-CHM buffer stays
// a clean zero-score result, and that the score equals the sum of the findings.
//
// Seeds: an empty buffer, plain text, a benign CHM, a CHM with an embedded exe,
// an ITSF header with no directory, and a header-only truncation.
func FuzzAnalyze(f *testing.F) {
	benign := buildCHM(&testing.T{}, []string{"/default.html", "/toc.hhc", "::DataSpace/NameList"})
	exe := buildCHM(&testing.T{}, []string{"/a.html", "/payload.exe"})
	headerOnly := append([]byte(nil), benign[:0x60]...)
	noDir := make([]byte, 0x60)
	copy(noDir, "ITSF")

	seeds := [][]byte{
		{}, []byte("not a chm file, just some bytes here"),
		benign, exe, headerOnly, noDir,
		[]byte("ITSF"), append([]byte("ITSF"), make([]byte, 0x5c)...),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if !IsCHM(data) {
			if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
				t.Fatalf("non-CHM buffer produced output: %+v", r)
			}
			return
		}
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}
	})
}

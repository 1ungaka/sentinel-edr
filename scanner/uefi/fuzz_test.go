package uefi

import "testing"

// FuzzAnalyze drives the FV/FFS walk with mutated input. The parser reads
// attacker-controlled FV lengths, header lengths, block maps, 24-bit FFS sizes
// and section sizes through range-checked accesses with caps on volumes, files
// and sections and an 8-byte-aligned bounded scan for the next volume. The
// invariant is that Analyze never panics and always returns a non-nil result,
// that a non-firmware buffer stays a clean zero-score result, and that the
// score equals the sum of the finding weights.
func FuzzAnalyze(f *testing.F) {
	benign := buildFirmware(ffsFile(guid16(0x11), 0x07, append(
		section(0x15, ucs2le("DxeMain")), section(0x10, []byte("MZ pe"))...)))
	badsum := append([]byte(nil), benign...)
	badsum[0x32] ^= 0xff
	twoVol := append(append([]byte(nil), benign...), benign...)
	headerOnly := append([]byte(nil), benign[:0x48]...)

	seeds := [][]byte{
		{}, []byte("not firmware at all, ordinary bytes"),
		benign, badsum, twoVol, headerOnly,
		append(make([]byte, 0x28), []byte("_FVH")...), // signature only
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if !IsFirmware(data) {
			if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
				t.Fatalf("non-firmware buffer produced output: %+v", r)
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

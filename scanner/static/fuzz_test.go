package static

import "testing"

// seedsStatic are small, diverse byte strings the fuzzers start from: the PE
// and ELF magics in several shapes, the tiny-entsize .symtab pattern, and
// truncations. Coverage-guided mutation explores outward from these. The
// invariant under test is simple and absolute: no detector may panic on any
// input, however malformed.
func seedsStatic(f *testing.F) {
	f.Helper()
	seeds := [][]byte{
		{},
		{'M', 'Z'},
		append([]byte("MZ"), make([]byte, 128)...),
		{0x7f, 'E', 'L', 'F', 1, 1, 1}, // ELF32 LE header stub
		{0x7f, 'E', 'L', 'F', 2, 1, 1}, // ELF64 LE header stub
		{0x7f, 'E', 'L', 'F', 2, 2, 1}, // ELF64 BE header stub
		{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 62, 0},
		[]byte("not an executable at all, just text\x00\x00"),
	}
	// A minimal ELF64 header padded out, to reach deeper parse paths.
	hdr := make([]byte, 128)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	hdr[16] = 2 // ET_EXEC
	hdr[18] = 62
	seeds = append(seeds, hdr)
	for _, s := range seeds {
		f.Add(s)
	}
}

// FuzzAnalyze exercises the whole structural pass (entropy, PE, ELF, packers,
// overlay, fuzzy digests) which is what the engine calls on every file.
func FuzzAnalyze(f *testing.F) {
	seedsStatic(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{NoFuzzy: false})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
	})
}

func FuzzParsePE(f *testing.F) {
	seedsStatic(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if IsPE(data) {
			_, _ = ParsePE(data)
		}
	})
}

func FuzzParseELF(f *testing.F) {
	seedsStatic(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if IsELF(data) {
			_, _ = ParseELF(data)
		}
	})
}

// FuzzParseMachO reaches the universal and load-command parsers, which only see
// a Mach-O magic the seeds above never produce.
func FuzzParseMachO(f *testing.F) {
	f.Add(machoSegment64(0, 16))
	f.Add(machoSegment64(1, wrapMax))
	f.Add([]byte{0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseMachO(data)
	})
}

// FuzzParseELFDynamic starts from a mapped dynamic section, the path that
// resolves relocations and symbols through file-supplied strides.
func FuzzParseELFDynamic(f *testing.F) {
	const slot = loadVA + elfTagsEnd
	f.Add(dynELF([][2]uint64{{7, slot + 64}, {8, wrapMax}, {9, 1<<63 - 1}, {25, slot}, {27, 8}}))
	f.Add(dynELF([][2]uint64{{6, slot}, {5, slot}, {10, 16}, {11, 1<<63 - 1}, {4, slot + 64}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseELF(data)
	})
}

package static

import (
	"encoding/binary"
	"testing"
)

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

// contentSeedELF is a sectionless ELF64 whose single executable PT_LOAD maps
// the whole file, with a DT_NEEDED entry so the image counts as dynamically
// linked, and with body placed in the mapped bytes: the path that reaches the
// marker pass and the system-call decoder.
func contentSeedELF(body []byte) []byte {
	const strOff = elfTagsEnd
	b := dynELF([][2]uint64{{dtNeeded, 1}, {dtStrtab, loadVA + strOff}, {dtStrsz, 16}})
	copy(b[strOff:], "\x00libc.so.6\x00")
	b = append(b, body...)
	binary.LittleEndian.PutUint64(b[64+32:], uint64(len(b))) // p_filesz
	binary.LittleEndian.PutUint64(b[64+40:], uint64(len(b))) // p_memsz
	return b
}

// FuzzELFContent drives the content pass (elf_content.go): the marker scan
// and its validators directly on arbitrary bytes, and the whole analysis on an
// image carrying those bytes. Invariants: no panic, the input is not written
// to, nothing is read past maxContentScan, and what is quoted from the file is
// short and printable.
func FuzzELFContent(f *testing.F) {
	for _, tok := range contentTokens {
		f.Add([]byte("\x00" + tok.tok + "\n"))
	}
	f.Add([]byte("\x00*/5 * * * * root /bin/true\n\x00/etc/cron.d/x\x00@reboot %s\n"))
	f.Add([]byte("/root/.ssh/authorized_keys\x00ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHN5bnRoZXRpYy1maXh0dXJlLWtleS1ub3QtYS1yZWFsLW9uZQ x"))
	f.Add([]byte("/etc/systemd/system/x.service\x00[Service]\nExecStart=/x\n[Install]\nWantedBy=multi-user.target\n"))
	f.Add([]byte{0xb8, 0x3b, 0, 0, 0, 0x0f, 0x05, 0xc3, 0x48, 0xc7, 0xc0, 0x3f, 0x01, 0, 0, 0x0f, 0x05, 0xb8, 0x65, 0, 0, 0, 0x0f, 0x05})
	f.Add([]byte("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *"))
	f.Fuzz(func(t *testing.T, data []byte) {
		before := string(data)
		var c ELFContent
		scanMarkers(data, &c)
		for m, ex := range c.first {
			if len(ex) > maxContentExcerpt+32 {
				t.Fatalf("marker %s excerpt is %d bytes", markerNames[m], len(ex))
			}
			for i := 0; i < len(ex); i++ {
				if ex[i] < 0x20 || ex[i] > 0x7e {
					t.Fatalf("marker %s excerpt carries byte 0x%02x", markerNames[m], ex[i])
				}
			}
		}
		for i := range data {
			decodeSyscallAMD64(data, i)
		}
		img := contentSeedELF(data)
		r := Analyze(img, Options{NoFuzzy: true})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if r.ELF != nil && r.ELF.Content != nil {
			if n := r.ELF.Content.ScannedBytes; n < 0 || n > len(img) || n > maxContentScan {
				t.Fatalf("scanned %d bytes of a %d byte image", n, len(img))
			}
		}
		if string(data) != before {
			t.Fatal("the content pass wrote to its input")
		}
	})
}

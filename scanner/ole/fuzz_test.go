package ole

import (
	"encoding/binary"
	"testing"
)

// FuzzAnalyze drives the CFB parser, the MS-OVBA decompressor and the detector
// with mutated input. The parser reads untrusted, attacker-controlled values
// (sector/mini-sector shifts, FAT / MiniFAT / DIFAT chains, directory entry
// sizes and start sectors, and CompressedChunk headers) through bounds-checked
// accessors with visited-set cycle detection and hard step caps. The invariant
// is that Analyze never panics and always returns a non-nil result, and that the
// reported score always equals the sum of the finding weights — however
// truncated or adversarial the bytes are.
//
// Seeds cover an empty buffer, a valid synthetic compound file, a file with a
// cyclic FAT chain, a directory entry declaring an enormous stream size, a
// truncated header, a raw CompressedContainer with adversarial token headers,
// and plain non-OLE bytes.
func FuzzAnalyze(f *testing.F) {
	valid := buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", content: []byte("not a container")},
		oleEntry{name: "Module1", content: moduleStream(
			"Sub AutoOpen()\r\n    Shell \"powershell -enc ZQBjAGgA\"\r\nEnd Sub\r\n")},
	)

	// A valid file whose first FAT entry points at its own sector (a 1-cycle).
	cyclic := append([]byte(nil), valid...)
	firstFatSector := binary.LittleEndian.Uint32(cyclic[76:]) // DIFAT[0]
	if off := (int(firstFatSector) + 1) * 512; off+4 <= len(cyclic) {
		binary.LittleEndian.PutUint32(cyclic[off:], 0) // sector 0 -> sector 0
	}

	// A valid file whose first provided stream declares a 4 GiB+ size.
	hugeSize := buildCFB(oleEntry{name: "Module1", content: moduleStream("x")})
	dirStart := binary.LittleEndian.Uint32(hugeSize[48:])
	if base := (int(dirStart)+1)*512 + 128; base+128 <= len(hugeSize) { // entry index 1
		binary.LittleEndian.PutUint32(hugeSize[base+120:], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(hugeSize[base+124:], 0x000000FF)
	}

	// A CompressedContainer with a valid chunk signature but adversarial tokens:
	// a FlagByte of all copy tokens, the first of which sits at the chunk start
	// (an impossible back-reference) — carried inside a module stream.
	adv := []byte{0x01}
	adv = append(adv, u16(uint16(0xB000)|uint16(20))...) // sig=0b011, flag=compressed
	adv = append(adv, 0xFF)                              // FlagByte: 8 copy tokens
	adv = append(adv, 0xFF, 0xFF, 0x00, 0x10, 0xFF, 0x7F, 0x01, 0x80, 0x55, 0xAA)
	advFile := buildCFB(oleEntry{name: "Module1", content: adv})

	seeds := [][]byte{
		{},
		[]byte("not a compound file"),
		valid,
		valid[:len(valid)/2],
		valid[:600], // past the header, into the (now missing) sectors
		valid[:8],   // signature only
		cyclic,
		hugeSize,
		advFile,
		compressVBA([]byte("Sub Document_Open(): Shell \"cmd\": End Sub")), // raw container (not OLE)
		append(append([]byte(nil), oleSignature[:]...), make([]byte, 600)...),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if !IsOLE(data) {
			if r.Score != 0 || len(r.Findings) != 0 {
				t.Fatalf("non-OLE buffer produced findings: %+v", r)
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

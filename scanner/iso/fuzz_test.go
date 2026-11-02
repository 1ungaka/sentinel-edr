package iso

import (
	"encoding/binary"
	"testing"
)

// FuzzAnalyze drives the ISO 9660 enumerator and detector with mutated input.
// The reader walks untrusted, attacker-controlled structures — volume-descriptor
// types and escape sequences, root extent LBA and length, per-record lengths,
// identifier lengths and child extent LBAs — through range-checked accesses with
// a depth cap, a visited-set of extent LBAs, and caps on records, sectors and
// entries. The invariant is that Analyze never panics and always returns a
// non-nil result, however truncated or adversarial the bytes are, and that the
// reported score equals the sum of the finding weights.
//
// Seeds cover an empty buffer, a valid synthetic malicious image, a buffer with
// just enough bytes for IsISO, a header-only buffer, an image whose root extent
// references itself (cycle), an image declaring a 4 GiB root directory, an image
// with a directory record whose length byte runs past its sector, a zeroed
// descriptor area, and random bytes.
func FuzzAnalyze(f *testing.F) {
	valid := buildISO(isoSpec{volID: "FUZZ", files: []isoFile{
		{name: "invoice.lnk", size: 1500},
		{name: "payload.exe", hidden: true, size: 40000},
	}})

	headerOnly := append([]byte(nil), valid[:vdSetOffset+300]...)

	// An image whose "sub" directory record points back at the root extent
	// (sector 18). The visited-set must break the cycle instead of looping.
	cycle := buildISO(isoSpec{volID: "LOOP", files: []isoFile{{name: "sub", isDir: true}}})
	rootStart := vdSetLBA * sectorSize // root extent at sector 18 (non-Joliet)
	// Records in the root extent: "." (34) + ".." (34), then "SUB" at +68; its
	// extent LBA (both-endian) begins at record offset 2.
	if subExt := rootStart + 68 + recExtentLE; subExt+4 <= len(cycle) {
		binary.LittleEndian.PutUint32(cycle[subExt:], uint32(vdSetLBA))
	}

	// An image that declares a 4 GiB root directory. The per-extent sector cap
	// and the range checks must bound the read.
	hugeDir := buildISO(isoSpec{volID: "HUGE", files: []isoFile{{name: "a.txt", size: 10}}})
	binary.LittleEndian.PutUint32(hugeDir[vdSetOffset+rootRecOffset+recDataLenLE:], 0xFFFFFFFF)

	// An image with a directory record whose length byte runs past the sector.
	pastSector := buildISO(isoSpec{volID: "PAST", files: []isoFile{{name: "a.txt", size: 10}}})
	{
		sec := pastSector[rootStart : rootStart+sectorSize]
		for i := range sec {
			sec[i] = 0
		}
		filler := buildDirRecord([]byte{'A'}, false, false, 2, 1) // recLen 34
		p := 0
		for p+len(filler) <= sectorSize-8 {
			copy(sec[p:], filler)
			p += len(filler)
		}
		sec[p] = 0xFF // a 255-byte record this close to the end overruns the sector
	}

	zeroed := make([]byte, vdSetOffset+sectorSize)

	seeds := [][]byte{
		{},
		[]byte("not an iso image"),
		valid,
		append([]byte(nil), valid[:vdSetOffset+6]...), // just enough for IsISO
		headerOnly,
		cycle,
		hugeDir,
		pastSector,
		zeroed,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		// A non-ISO buffer must stay a clean zero-score result.
		if !IsISO(data) {
			if r.Score != 0 || len(r.Findings) != 0 {
				t.Fatalf("non-ISO buffer produced findings: %+v", r)
			}
			return
		}
		// The reported score must equal the sum of the finding weights.
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}
	})
}

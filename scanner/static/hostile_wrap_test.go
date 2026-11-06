package static

import (
	"encoding/binary"
	"testing"
)

// Header fields in these images are chosen so the bounds check itself wraps: the
// sum of a hostile offset and size lands back inside the file, the check passes,
// and the slice that follows panics. The engine's recover keeps the process
// alive, but it also abandons every detector still to run on that file, so a
// crafted header is a way to dodge the rest of the scan.

const wrapMax = ^uint64(0)

// machoSegment64 is a thin little-endian Mach-O with one LC_SEGMENT_64.
func machoSegment64(fileOff, fileSize uint64) []byte {
	const hdr, cmd = 32, 72
	b := make([]byte, hdr+cmd+64)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x01000007) // x86_64
	le.PutUint32(b[12:], 2)         // MH_EXECUTE
	le.PutUint32(b[16:], 1)         // ncmds
	le.PutUint32(b[20:], cmd)       // sizeofcmds
	c := b[hdr:]
	le.PutUint32(c[0:], 0x19) // LC_SEGMENT_64
	le.PutUint32(c[4:], cmd)
	copy(c[8:], "__TEXT")
	le.PutUint64(c[24:], 0x1000) // vmaddr
	le.PutUint64(c[32:], 0x1000) // vmsize
	le.PutUint64(c[40:], fileOff)
	le.PutUint64(c[48:], fileSize)
	return b
}

func TestMachOSegmentRangeThatWrapsIsTruncated(t *testing.T) {
	m, err := ParseMachO(machoSegment64(1, wrapMax))
	if err != nil {
		t.Fatal(err)
	}
	segs := m.Arches[0].Segments
	if len(segs) != 1 || !segs[0].Truncated {
		t.Fatalf("segment past the end of the file not marked truncated: %+v", segs)
	}
}

func TestMachOSegmentInFatSliceThatWrapsIsTruncated(t *testing.T) {
	// base+fileoff wraps on its own, before the size is even added.
	thin := machoSegment64(wrapMax-7, 16)
	const sliceAt = 0x40
	b := make([]byte, sliceAt+len(thin))
	be := binary.BigEndian
	be.PutUint32(b[0:], 0xcafebabf) // FAT_MAGIC_64
	be.PutUint32(b[4:], 1)
	be.PutUint32(b[8:], 0x01000007)
	be.PutUint64(b[16:], sliceAt)
	be.PutUint64(b[24:], uint64(len(thin)))
	copy(b[sliceAt:], thin)

	m, err := ParseMachO(b)
	if err != nil {
		t.Fatal(err)
	}
	if segs := m.Arches[0].Segments; len(segs) != 1 || !segs[0].Truncated {
		t.Fatalf("segment past the end of the file not marked truncated: %+v", segs)
	}
}

func TestMachOFatSliceSizeThatWrapsIsRejected(t *testing.T) {
	thin := machoSegment64(0, 16)
	const sliceAt = 0x40
	b := make([]byte, sliceAt+len(thin))
	be := binary.BigEndian
	be.PutUint32(b[0:], 0xcafebabf) // FAT_MAGIC_64
	be.PutUint32(b[4:], 1)
	be.PutUint32(b[8:], 0x01000007)
	be.PutUint64(b[16:], sliceAt)
	be.PutUint64(b[24:], wrapMax-sliceAt+1) // sliceAt+size wraps to 0
	copy(b[sliceAt:], thin)

	if _, err := ParseMachO(b); err == nil {
		t.Fatal("a fat slice whose size runs off the end of the file was accepted")
	}
}

// dynELF is a little-endian ELF64 whose single PT_LOAD maps the whole file at
// loadVA, with a PT_DYNAMIC holding tags followed by a DT_NULL.
const (
	loadVA     = 0x10000
	dynOffset  = 64 + 2*56
	elfTagsEnd = dynOffset + 16*32
)

func dynELF(tags [][2]uint64) []byte {
	b := make([]byte, elfTagsEnd+512)
	le := binary.LittleEndian
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
	le.PutUint16(b[16:], 3)  // ET_DYN
	le.PutUint16(b[18:], 62) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[32:], 64) // phoff
	le.PutUint16(b[52:], 64)
	le.PutUint16(b[54:], 56)
	le.PutUint16(b[56:], 2)

	load := b[64:]
	le.PutUint32(load[0:], 1) // PT_LOAD
	le.PutUint32(load[4:], 5)
	le.PutUint64(load[16:], loadVA)
	le.PutUint64(load[24:], loadVA)
	le.PutUint64(load[32:], uint64(len(b)))
	le.PutUint64(load[40:], uint64(len(b)))

	dyn := b[64+56:]
	le.PutUint32(dyn[0:], 2) // PT_DYNAMIC
	le.PutUint32(dyn[4:], 6)
	le.PutUint64(dyn[8:], dynOffset)
	le.PutUint64(dyn[16:], loadVA+dynOffset)
	le.PutUint64(dyn[24:], loadVA+dynOffset)
	le.PutUint64(dyn[32:], uint64(len(tags)+1)*16)
	le.PutUint64(dyn[40:], uint64(len(tags)+1)*16)

	for i, tag := range tags {
		le.PutUint64(b[dynOffset+i*16:], tag[0])
		le.PutUint64(b[dynOffset+i*16+8:], tag[1])
	}
	return b
}

func TestELFRelocEntrySizeThatGoesNegative(t *testing.T) {
	// n = sz/ent = 2. The second entry sits at base+MaxInt64, which wraps
	// negative, so p+want > len(data) is false and data[p:] panics.
	const dtInitArrayTag, dtInitArraySzTag = 25, 27
	initSlot := uint64(loadVA + elfTagsEnd) // a zeroed slot forces the relocation walk
	if _, err := ParseELF(dynELF([][2]uint64{
		{7, loadVA + elfTagsEnd + 64}, // DT_RELA
		{8, wrapMax},                  // DT_RELASZ
		{9, 1<<63 - 1},                // DT_RELAENT
		{dtInitArrayTag, initSlot},
		{dtInitArraySzTag, 8},
	})); err != nil {
		t.Fatal(err)
	}
}

func TestELFRelEntrySizeThatGoesNegative(t *testing.T) {
	const dtInitArrayTag, dtInitArraySzTag = 25, 27
	initSlot := uint64(loadVA + elfTagsEnd)
	if _, err := ParseELF(dynELF([][2]uint64{
		{17, loadVA + elfTagsEnd + 64}, // DT_REL
		{18, wrapMax},                  // DT_RELSZ
		{19, 1<<63 - 1},                // DT_RELENT
		{dtInitArrayTag, initSlot},
		{dtInitArraySzTag, 8},
	})); err != nil {
		t.Fatal(err)
	}
}

func TestELFSymbolEntrySizeThatWraps(t *testing.T) {
	// p+ent overflows at the first symbol, so the guard passes; the second
	// symbol's offset is then negative.
	const hashAt = elfTagsEnd + 64
	b := dynELF([][2]uint64{
		{6, loadVA + elfTagsEnd},     // DT_SYMTAB
		{5, loadVA + elfTagsEnd},     // DT_STRTAB
		{10, 16},                     // DT_STRSZ
		{11, 1<<63 - 1},              // DT_SYMENT: MaxInt64
		{4, loadVA + uint64(hashAt)}, // DT_HASH
	})
	binary.LittleEndian.PutUint32(b[hashAt+4:], 8) // nchain
	if _, err := ParseELF(b); err != nil {
		t.Fatal(err)
	}
}

func TestELFSectionHeaderOffsetThatWraps(t *testing.T) {
	// e_shnum == 0 means the real count is in section 0, read from e_shoff. A
	// value just short of 2^64 makes shoff+shent wrap past the check.
	b := dynELF(nil)
	le := binary.LittleEndian
	le.PutUint64(b[40:], wrapMax-8) // e_shoff
	le.PutUint16(b[58:], 64)        // e_shentsize
	le.PutUint16(b[60:], 0)         // e_shnum
	if _, err := ParseELF(b); err != nil {
		t.Fatal(err)
	}
}

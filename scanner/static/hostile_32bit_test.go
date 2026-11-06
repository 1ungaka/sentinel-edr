package static

import (
	"encoding/binary"
	"testing"
)

// These run on every platform, but they exist for the 32-bit builds that
// debian/control's "Architecture: any" allows. There, int(uint32) can be negative,
// so a check written in int passes and the index behind it panics.

const signedHuge = 0x90000000 // above MaxInt32

func TestMachOCodeSignatureOverflowingInt(t *testing.T) {
	const hdr, seg, sig = 32, 72, 16
	b := make([]byte, hdr+seg+sig+256)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x01000007)
	le.PutUint32(b[12:], 2)
	le.PutUint32(b[16:], 2)
	le.PutUint32(b[20:], seg+sig)
	c := b[hdr:]
	le.PutUint32(c[0:], 0x19) // LC_SEGMENT_64
	le.PutUint32(c[4:], seg)
	copy(c[8:], "__TEXT")
	le.PutUint64(c[40:], 0)
	le.PutUint64(c[48:], hdr+seg+sig) // leaves 256 bytes trailing
	s := b[hdr+seg:]
	le.PutUint32(s[0:], 0x1d) // LC_CODE_SIGNATURE
	le.PutUint32(s[4:], sig)
	le.PutUint32(s[12:], signedHuge)
	m, err := ParseMachO(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Overlay.Size > 256 || m.Overlay.Size < 0 {
		t.Fatalf("overlay of %d bytes in a 256 byte tail", m.Overlay.Size)
	}
}

func TestModuleSignatureLengthOverflowingInt(t *testing.T) {
	const marker = moduleSignatureMarker
	b := make([]byte, 128)
	copy(b[len(b)-len(marker):], marker)
	binary.BigEndian.PutUint32(b[len(b)-len(marker)-4:], 0x7ffffff0)
	if got := moduleSignatureSize(b); got < 0 || got > len(b) {
		t.Fatalf("signature size %d in a %d byte file", got, len(b))
	}
}

func TestELFVersionOffsetsOverflowingInt(t *testing.T) {
	for _, off := range []uint32{signedHuge, 0xfffffff0} {
		e := &ELF{order: binary.LittleEndian, size: 256}
		data := make([]byte, 256)
		rec := data[32:]
		binary.LittleEndian.PutUint16(rec[2:], 4) // vn_cnt
		binary.LittleEndian.PutUint32(rec[8:], off)
		binary.LittleEndian.PutUint32(rec[12:], off)
		e.Sections = []ELFSection{{Type: shtGNUVerneed, Offset: 32, Size: 128}, {Type: shtGNUVerdef, Offset: 32, Size: 128}}
		e.parseVersions(data)
	}
}

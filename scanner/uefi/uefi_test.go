package uefi

import (
	"encoding/binary"
	"testing"
)

// put24 writes a little-endian 24-bit value (FFS/section size field).
func put24(b []byte, off, v int) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
}

// ucs2le encodes an ASCII string as NUL-terminated little-endian UCS-2.
func ucs2le(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return append(out, 0, 0)
}

// section builds one EFI_COMMON_SECTION_HEADER + body, 4-byte aligned.
func section(typ uint8, body []byte) []byte {
	size := 4 + len(body)
	s := make([]byte, 4)
	put24(s, 0, size)
	s[3] = typ
	s = append(s, body...)
	for len(s)%4 != 0 {
		s = append(s, 0xff) // section padding (not part of this section's size)
	}
	return s
}

// ffsFile builds one FFS file (header + sections), 8-byte aligned.
func ffsFile(guid []byte, typ uint8, sections []byte) []byte {
	size := 24 + len(sections)
	f := make([]byte, 24)
	copy(f[0:16], guid)
	f[0x12] = typ
	f[0x17] = 0xf8 // state: data valid
	put24(f, 0x14, size)
	f = append(f, sections...)
	for len(f)%8 != 0 {
		f = append(f, 0xff)
	}
	return f
}

// fvHeader builds an FV header (hdrLen 0x48) with a valid 16-bit checksum.
func fvHeader(fvLen int) []byte {
	const hdrLen = 0x48
	h := make([]byte, hdrLen)
	// FileSystem GUID (EFI_FIRMWARE_FILE_SYSTEM2_GUID).
	copy(h[0x10:0x20], []byte{0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3})
	binary.LittleEndian.PutUint64(h[0x20:], uint64(fvLen))
	binary.LittleEndian.PutUint32(h[0x28:], fvSignature)
	binary.LittleEndian.PutUint16(h[0x30:], hdrLen)
	h[0x37] = 2 // revision
	// BlockMap: one block entry + terminator.
	binary.LittleEndian.PutUint32(h[0x38:], 1)             // NumBlocks
	binary.LittleEndian.PutUint32(h[0x3c:], uint32(fvLen)) // Length
	// checksum at 0x32 so the u16 word sum over the header is 0.
	var sum uint16
	for p := 0; p+2 <= hdrLen; p += 2 {
		sum += binary.LittleEndian.Uint16(h[p:])
	}
	binary.LittleEndian.PutUint16(h[0x32:], uint16(0)-sum)
	return h
}

func guid16(b byte) []byte {
	g := make([]byte, 16)
	for i := range g {
		g[i] = b
	}
	return g
}

// buildFirmware assembles one FV containing the given files.
func buildFirmware(files ...[]byte) []byte {
	var body []byte
	for _, f := range files {
		body = append(body, f...)
	}
	const hdrLen = 0x48
	fvLen := hdrLen + len(body)
	hdr := fvHeader(fvLen)
	return append(hdr, body...)
}

func has(r *Result, class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestUEFIBenignInventory(t *testing.T) {
	driver := ffsFile(guid16(0x11), 0x07, append(
		section(0x15, ucs2le("DxeMain")),
		section(0x10, []byte("MZ\x00\x00 fake pe"))...,
	))
	fw := buildFirmware(driver)
	if !IsFirmware(fw) {
		t.Fatal("IsFirmware false on a built FV")
	}
	r := Analyze(fw, Options{})
	if r.Score != 0 {
		t.Errorf("benign firmware scored %d: %+v", r.Score, r.Findings)
	}
	if r.Parsed == nil || r.Parsed.Volumes != 1 || r.Parsed.Modules != 1 {
		t.Fatalf("summary = %+v", r.Parsed)
	}
	m := r.Parsed.Inventory[0]
	if m.Type != "DRIVER" || m.Name != "DxeMain" || !m.HasPE {
		t.Errorf("module = %+v", m)
	}
	if !r.Parsed.ChecksumValid {
		t.Error("checksum should validate on a well-formed FV")
	}
}

func TestUEFIChecksumInvalid(t *testing.T) {
	fw := buildFirmware(ffsFile(guid16(0x22), 0x07, section(0x15, ucs2le("X"))))
	// Corrupt the stored checksum so the header no longer sums to zero.
	fw[0x32] ^= 0xff
	r := Analyze(fw, Options{})
	if !has(r, "uefi.volume-checksum-invalid") {
		t.Fatalf("expected uefi.volume-checksum-invalid: %+v", r.Findings)
	}
	if r.Parsed.ChecksumValid {
		t.Error("ChecksumValid should be false")
	}
}

func TestUEFIImplantBlocklist(t *testing.T) {
	implant := guid16(0xAB)
	fw := buildFirmware(
		ffsFile(guid16(0x11), 0x07, section(0x15, ucs2le("Good"))),
		ffsFile(implant, 0x0A, section(0x10, []byte("MZ payload"))),
	)
	g := formatGUID(implant)
	r := Analyze(fw, Options{ImplantGUIDs: map[string]string{g: "Lojax-like"}})
	if !has(r, "uefi.known-implant-guid") {
		t.Fatalf("expected uefi.known-implant-guid: %+v", r.Findings)
	}
	if !r.Detected() {
		t.Errorf("implant GUID match should cross the threshold; score %d", r.Score)
	}
	// Without the blocklist, the same image is clean.
	if r2 := Analyze(fw, Options{}); r2.Score != 0 {
		t.Errorf("no blocklist → no detection, got %d: %+v", r2.Score, r2.Findings)
	}
}

func TestUEFIMultipleVolumes(t *testing.T) {
	fw := buildFirmware(ffsFile(guid16(0x11), 0x07, section(0x15, ucs2le("A"))))
	fw = append(fw, buildFirmware(ffsFile(guid16(0x22), 0x06, section(0x15, ucs2le("B"))))...)
	r := Analyze(fw, Options{})
	if r.Parsed.Volumes != 2 {
		t.Errorf("volumes = %d, want 2", r.Parsed.Volumes)
	}
	if r.Parsed.Modules != 2 {
		t.Errorf("modules = %d, want 2", r.Parsed.Modules)
	}
}

func TestUEFIFormatGUID(t *testing.T) {
	// FFS2 GUID round-trips to its canonical text form.
	g := formatGUID([]byte{0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3})
	if g != "8c8ce578-8a3d-4f1c-9935-896185c32dd3" {
		t.Errorf("guid = %q", g)
	}
}

func TestUEFINonFirmwareInert(t *testing.T) {
	r := Analyze([]byte("this is not firmware, just some ordinary bytes here"), Options{})
	if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
		t.Errorf("non-firmware produced output: %+v", r)
	}
	if IsFirmware([]byte("nope")) {
		t.Error("IsFirmware true on short junk")
	}
}

// edk2 puts a pad file first in every volume that has an extended header, and
// a pad file's name is all 0xFF. It is a real file: the walk must step over it
// and inventory what follows, not mistake it for free space and stop.
func TestUEFIPadFileDoesNotEndTheWalk(t *testing.T) {
	allFF := make([]byte, 16)
	for i := range allFF {
		allFF[i] = 0xff
	}
	pad := ffsFile(allFF, 0xF0, make([]byte, 20))
	driver := ffsFile(guid16(0x42), 0x07, append(section(0x10, []byte("MZ-driver-body")), section(0x15, ucs2le("AfterPad"))...))
	r := Analyze(buildFirmware(pad, driver), Options{})
	if r.Parsed == nil || r.Parsed.Modules != 1 {
		t.Fatalf("the module after the pad file was not inventoried: %+v", r.Parsed)
	}
	if m := r.Parsed.Inventory[0]; m.Name != "AfterPad" || !m.HasPE || m.Type != "DRIVER" {
		t.Errorf("module: %+v", m)
	}
}

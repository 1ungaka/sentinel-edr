package uefi

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lzmaGUIDBytes is the on-disk form of the LZMA section GUID.
var lzmaGUIDBytes = []byte{0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf}

// guidedLZMA wraps an LZMA stream as a GUID-defined section.
func guidedLZMA(stream []byte) []byte {
	body := append([]byte(nil), lzmaGUIDBytes...)
	body = binary.LittleEndian.AppendUint16(body, 24) // data offset: 4 + 16 + 2 + 2
	body = binary.LittleEndian.AppendUint16(body, 1)  // attributes: processing required
	return section(0x02, append(body, stream...))
}

// innerVolume is the synthetic volume the nested fixtures carry: one DXE
// driver with a PE32 body and a UI name.
func innerVolume() []byte {
	driver := ffsFile(guid16(0x77), 0x07, append(section(0x10, []byte("MZ-inner-driver-body-CAU-FIXTURE")), section(0x15, ucs2le("InnerDriver"))...))
	return buildFirmware(driver)
}

// innerPayload is what the LZMA fixture decompresses to: a raw section, then
// the inner volume as a FIRMWARE_VOLUME_IMAGE section, as edk2 lays it out.
func innerPayload() []byte {
	return append(section(0x19, []byte("pad!")), section(0x17, innerVolume())...)
}

// The compressed fixture is committed (the standard library cannot write
// LZMA). This test pins it to the bytes the Go builders produce, so a change
// to the builders cannot silently leave the nested tests reading stale data.
// To regenerate after changing innerPayload:
//
//	CAU_WRITE_FIXTURE=1 go test ./scanner/uefi -run TestNestedFixtureIsCurrent
//	python3 -c "import lzma;d=open('scanner/uefi/testdata/nested_fv.raw','rb').read();open('scanner/uefi/testdata/nested_fv.lzma','wb').write(lzma.compress(d,format=lzma.FORMAT_ALONE))"
func TestNestedFixtureIsCurrent(t *testing.T) {
	raw := filepath.Join("testdata", "nested_fv.raw")
	if os.Getenv("CAU_WRITE_FIXTURE") != "" {
		if err := os.WriteFile(raw, innerPayload(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plain, err := lzmaDecode(nestedStream(t), 1<<20)
	if err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	if !bytes.Equal(plain, innerPayload()) {
		t.Fatal("testdata/nested_fv.lzma no longer matches innerPayload(); regenerate it (see the comment above)")
	}
}

func nestedStream(t testing.TB) []byte {
	t.Helper()
	stream, err := os.ReadFile(filepath.Join("testdata", "nested_fv.lzma"))
	if err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	return stream
}

func moduleNamed(r *Result, name string) *Module {
	for i := range r.Parsed.Inventory {
		if r.Parsed.Inventory[i].Name == name {
			return &r.Parsed.Inventory[i]
		}
	}
	return nil
}

func TestUEFIVolumeBehindLZMAIsInventoried(t *testing.T) {
	outer := ffsFile(guid16(0x0b), 0x0B, guidedLZMA(nestedStream(t)))
	top := ffsFile(guid16(0x01), 0x04, section(0x10, []byte("MZ-pei-core")))
	r := Analyze(buildFirmware(top, outer), Options{})
	if r.Parsed.Decompressed != 1 || r.Parsed.DecompressFailed != 0 {
		t.Fatalf("decompressed %d failed %d", r.Parsed.Decompressed, r.Parsed.DecompressFailed)
	}
	inner := moduleNamed(r, "InnerDriver")
	if inner == nil || inner.Depth != 1 || !inner.HasPE || inner.Type != "DRIVER" {
		t.Fatalf("inner driver: %+v (inventory %+v)", inner, r.Parsed.Inventory)
	}
	if r.Parsed.Volumes != 2 || r.Parsed.Modules != 3 {
		t.Errorf("volumes %d modules %d, want 2 and 3", r.Parsed.Volumes, r.Parsed.Modules)
	}
	if strings.Contains(r.Parsed.NotInspected, "could not be opened") {
		t.Errorf("note claims a failure: %s", r.Parsed.NotInspected)
	}

	// The executable bodies are available for rule scanning, inner one included.
	secs, cut := r.ExecutableSections()
	if cut || len(secs) != 2 {
		t.Fatalf("executable sections: %d (truncated %v)", len(secs), cut)
	}
	var got *ExecSection
	for i := range secs {
		if secs[i].ModuleName == "InnerDriver" {
			got = &secs[i]
		}
	}
	if got == nil || got.Kind != "PE32" || got.Depth != 1 || string(got.Data) != "MZ-inner-driver-body-CAU-FIXTURE" {
		t.Errorf("inner executable section: %+v", got)
	}
}

func TestUEFIUncompressedNestedVolume(t *testing.T) {
	outer := ffsFile(guid16(0x0b), 0x0B, section(0x17, innerVolume()))
	r := Analyze(buildFirmware(outer), Options{})
	inner := moduleNamed(r, "InnerDriver")
	if inner == nil || inner.Depth != 1 || r.Parsed.Decompressed != 0 {
		t.Fatalf("nested volume in a plain section: %+v decompressed %d", inner, r.Parsed.Decompressed)
	}
}

// A compressed section that cannot be opened is reported: what is behind it
// was not inventoried, and the result says so rather than looking complete.
func TestUEFICorruptLZMAIsReported(t *testing.T) {
	stream := append([]byte(nil), nestedStream(t)...)
	for i := 20; i < len(stream); i++ {
		stream[i] ^= 0xA5
	}
	outer := ffsFile(guid16(0x0b), 0x0B, guidedLZMA(stream))
	r := Analyze(buildFirmware(outer), Options{})
	if r.Parsed.DecompressFailed != 1 || r.Parsed.Decompressed != 0 || moduleNamed(r, "InnerDriver") != nil {
		t.Fatalf("corrupt stream: %+v", r.Parsed)
	}
	if !strings.Contains(r.Parsed.NotInspected, "could not be opened") {
		t.Errorf("the failure must be stated: %s", r.Parsed.NotInspected)
	}
	if r.Detected() {
		t.Error("a section that will not decompress is not a detection")
	}
}

// Volumes nested inside volumes without end must stop at the depth bound.
func TestUEFINestingDepthIsBounded(t *testing.T) {
	img := innerVolume()
	for i := 0; i < 12; i++ {
		img = buildFirmware(ffsFile(guid16(byte(i)), 0x0B, section(0x17, img)))
	}
	r := Analyze(img, Options{})
	deepest := 0
	for _, m := range r.Parsed.Inventory {
		if m.Depth > deepest {
			deepest = m.Depth
		}
	}
	if deepest > maxNestDepth || r.Parsed.DecompressFailed == 0 {
		t.Errorf("deepest module at depth %d (bound %d), failures %d", deepest, maxNestDepth, r.Parsed.DecompressFailed)
	}
	if moduleNamed(r, "InnerDriver") != nil {
		t.Error("the innermost volume is past the bound and must not be reached")
	}
}

// A GUID-defined section that is not LZMA is left alone, and lying offsets
// in an LZMA one are bounds-checked.
func TestUEFIGuidedSectionEdges(t *testing.T) {
	other := append(guid16(0x99), 24, 0, 0, 0)
	r := Analyze(buildFirmware(ffsFile(guid16(1), 0x0B, section(0x02, append(other, nestedStream(t)...)))), Options{})
	if r.Parsed.Decompressed != 0 || r.Parsed.DecompressFailed != 0 {
		t.Errorf("an unknown GUID-defined section must be neither opened nor counted as a failure: %+v", r.Parsed)
	}
	for _, dataOff := range []uint16{0, 3, 23, 0xFFFF} {
		body := append([]byte(nil), lzmaGUIDBytes...)
		body = binary.LittleEndian.AppendUint16(body, dataOff)
		body = binary.LittleEndian.AppendUint16(body, 1)
		Analyze(buildFirmware(ffsFile(guid16(1), 0x0B, section(0x02, append(body, nestedStream(t)...)))), Options{})
	}
	// An extended-size section header whose length points past the file.
	sec := []byte{0xFF, 0xFF, 0xFF, 0x10, 0xFF, 0xFF, 0xFF, 0x7F, 'M', 'Z'}
	Analyze(buildFirmware(ffsFile(guid16(1), 0x07, sec)), Options{})
}

func TestUEFIRuleMatchesScore(t *testing.T) {
	outer := ffsFile(guid16(0x0b), 0x0B, guidedLZMA(nestedStream(t)))
	r := Analyze(buildFirmware(outer), Options{})
	secs, _ := r.ExecutableSections()
	if len(secs) != 1 {
		t.Fatalf("sections: %d", len(secs))
	}
	r.AddRuleMatches(nil)
	if r.Score != 0 || len(r.Findings) != 0 {
		t.Fatalf("no matches must change nothing: %+v", r)
	}
	r.AddRuleMatches([]RuleMatch{{Rule: "b_rule", Section: secs[0]}, {Rule: "a_rule", Section: secs[0]}, {Rule: "a_rule", Section: secs[0]}})
	if len(r.Findings) != 1 || r.Findings[0].Class != "uefi.module-rule-match" || !r.Detected() {
		t.Fatalf("findings: %+v score %d", r.Findings, r.Score)
	}
	if ev := r.Findings[0].Evidence; !strings.Contains(ev, "InnerDriver") || !strings.HasSuffix(ev, "a_rule, b_rule") {
		t.Errorf("evidence: %q", ev)
	}
	found := false
	for _, c := range Classes() {
		if c.Class == "uefi.module-rule-match" && c.Weight == r.Findings[0].Score {
			found = true
		}
	}
	if !found {
		t.Error("the class is not in the catalog with the weight that was emitted")
	}
}

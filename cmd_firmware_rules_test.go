package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

// firmwareImage builds a one-volume UEFI image holding one DXE driver whose
// PE32 section is body. Synthetic: the structures are written here.
func firmwareImage(t *testing.T, body []byte) string {
	t.Helper()
	sec := make([]byte, 4, 4+len(body))
	size := 4 + len(body)
	sec[0], sec[1], sec[2], sec[3] = byte(size), byte(size>>8), byte(size>>16), 0x10
	sec = append(sec, body...)
	for len(sec)%4 != 0 {
		sec = append(sec, 0xff)
	}
	file := make([]byte, 24, 24+len(sec))
	for i := 0; i < 16; i++ {
		file[i] = 0x5a
	}
	file[0x12], file[0x17] = 0x07, 0xf8
	fsize := 24 + len(sec)
	file[0x14], file[0x15], file[0x16] = byte(fsize), byte(fsize>>8), byte(fsize>>16)
	file = append(file, sec...)
	for len(file)%8 != 0 {
		file = append(file, 0xff)
	}
	const hdrLen = 0x48
	hdr := make([]byte, hdrLen)
	copy(hdr[0x10:], []byte{0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3})
	binary.LittleEndian.PutUint64(hdr[0x20:], uint64(hdrLen+len(file)))
	binary.LittleEndian.PutUint32(hdr[0x28:], 0x4856465F) // "_FVH"
	binary.LittleEndian.PutUint16(hdr[0x30:], hdrLen)
	hdr[0x37] = 2
	binary.LittleEndian.PutUint32(hdr[0x38:], 1)
	binary.LittleEndian.PutUint32(hdr[0x3c:], uint32(hdrLen+len(file)))
	var sum uint16
	for p := 0; p+2 <= hdrLen; p += 2 {
		sum += binary.LittleEndian.Uint16(hdr[p:])
	}
	binary.LittleEndian.PutUint16(hdr[0x32:], -sum)
	path := filepath.Join(t.TempDir(), "image.rom")
	if err := os.WriteFile(path, append(hdr, file...), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A module whose body matches a bundled rule is reported; the same image
// without rules is not, and says the rules were not run.
func TestCLIFirmwareRunsRulesOverModuleBodies(t *testing.T) {
	// A smoke-corpus fixture: harmless bytes written to carry a bundled
	// rule's indicator strings.
	body, err := os.ReadFile(smokeYaraHit)
	if err != nil {
		t.Fatal(err)
	}
	img := firmwareImage(t, body)

	code, out, errOut := runCLI(t, "firmware", "--rules", "rules", img)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, report.ExitThreat, out, errOut)
	}
	for _, want := range []string{"[uefi.module-rule-match] 8", "Executables : 1 module bodies", "SUSPICIOUS", "5a5a5a5a-5a5a"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = runCLI(t, "firmware", "--no-yara", img)
	if code != report.ExitOK || strings.Contains(out, "module-rule-match") {
		t.Fatalf("--no-yara: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "detection rules were not run over module bodies (--no-yara)") {
		t.Errorf("the report must say the rules were not run:\n%s", out)
	}

	// A benign body: rules run, nothing fires.
	code, out, _ = runCLI(t, "firmware", "--rules", "rules", firmwareImage(t, []byte("MZ an ordinary driver body with nothing in it")))
	if code != report.ExitOK || strings.Contains(out, "module-rule-match") || strings.Contains(out, "were not run") {
		t.Errorf("benign body: exit %d\n%s", code, out)
	}

	// A rules path that was named and does not exist fails the run.
	if code, _, _ = runCLI(t, "firmware", "--rules", filepath.Join(t.TempDir(), "none"), img); code != report.ExitRunFailed {
		t.Errorf("missing --rules: exit %d, want %d", code, report.ExitRunFailed)
	}
}

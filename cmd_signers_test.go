package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

func TestCLIScanWithSignerBlocklist(t *testing.T) {
	work := t.TempDir()
	bl := filepath.Join(work, "signers.txt")
	// A valid blocklist (line format): one SHA-1 thumbprint with a reason.
	os.WriteFile(bl, []byte("# abused certs\naabbccddeeff00112233445566778899aabbccdd||stolen key\n"), 0o644)

	// Scanning a non-PE with a loaded blocklist runs clean (no cert to match)
	// and must not error — this exercises the load + wiring path.
	code, _, errOut := runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara", "--signers", bl, "LICENSE")
	if code != report.ExitOK {
		t.Fatalf("scan with blocklist: code=%d err=%s", code, errOut)
	}
}

func TestCLIScanBadSignerBlocklist(t *testing.T) {
	code, _, _ := runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara", "--signers", "/no/such/signers.txt", "LICENSE")
	if code != report.ExitRunFailed {
		t.Errorf("missing blocklist: code=%d, want %d", code, report.ExitRunFailed)
	}
}

func TestCLIScanSignerBlocklistJSON(t *testing.T) {
	work := t.TempDir()
	bl := filepath.Join(work, "signers.json")
	os.WriteFile(bl, []byte(`[{"thumbprint":"1111111111111111111111111111111111111111","reason":"test"}]`), 0o644)
	code, _, errOut := runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara", "--signers", bl, "LICENSE")
	if code != report.ExitOK {
		t.Fatalf("scan with JSON blocklist: code=%d err=%s", code, errOut)
	}
}

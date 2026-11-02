package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cau-edr/cau/internal/report"
)

// TestCLIScanAutoQuarantine confirms the free-prevention path: a scan with
// --quarantine moves a confirmed-malicious file into the vault, and leaves a
// clean file untouched.
func TestCLIScanAutoQuarantine(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")

	// A file whose SHA-256 is in the smoke DB (copy of the committed sample).
	malData, err := os.ReadFile(smokeHashHit)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	mal := filepath.Join(work, "evil.bin")
	os.WriteFile(mal, malData, 0o644)
	clean := filepath.Join(work, "clean.txt")
	os.WriteFile(clean, []byte("totally benign text\n"), 0o644)

	code, _, errOut := runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara",
		"--quarantine", "--quarantine-store", vault, mal, clean)
	// hash hit → ExitThreat; the quarantine action runs regardless of exit code.
	if code != report.ExitThreat {
		t.Fatalf("scan: code=%d (want %d) err=%s", code, report.ExitThreat, errOut)
	}
	// The malicious file was moved out.
	if _, err := os.Stat(mal); !os.IsNotExist(err) {
		t.Errorf("malicious file was not moved: %v", err)
	}
	// The clean file is untouched.
	if _, err := os.Stat(clean); err != nil {
		t.Errorf("clean file was disturbed: %v", err)
	}
	// Exactly one vault entry, pointing at the malicious file.
	_, out, _ := runCLI(t, "quarantine", "list", "--store", vault, "--format", "json")
	var entries []struct {
		OriginalPath string `json:"original_path"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("list json: %v (%s)", err, out)
	}
	if len(entries) != 1 || entries[0].OriginalPath != mal {
		t.Fatalf("unexpected vault contents: %+v", entries)
	}
}

func TestCLIScanNoQuarantineByDefault(t *testing.T) {
	work := t.TempDir()
	malData, _ := os.ReadFile(smokeHashHit)
	mal := filepath.Join(work, "evil.bin")
	os.WriteFile(mal, malData, 0o644)

	// Without --quarantine, a malicious file must NOT be moved.
	runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara", mal)
	if _, err := os.Stat(mal); err != nil {
		t.Errorf("file was moved without --quarantine: %v", err)
	}
}

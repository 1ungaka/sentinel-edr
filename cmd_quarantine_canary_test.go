package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

func TestCLIQuarantineLifecycle(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")
	sample := filepath.Join(work, "evil.bin")
	if err := os.WriteFile(sample, []byte("MZ malicious payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// add
	code, out, errOut := runCLI(t, "quarantine", "add", "--store", vault, "--threat", "Test.Agent", sample)
	if code != report.ExitOK {
		t.Fatalf("add: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "moved") {
		t.Errorf("add output: %q", out)
	}
	if _, err := os.Stat(sample); !os.IsNotExist(err) {
		t.Error("original not moved")
	}

	// list --format json → grab the id
	code, out, _ = runCLI(t, "quarantine", "list", "--store", vault, "--format", "json")
	if code != report.ExitOK {
		t.Fatalf("list code=%d", code)
	}
	var entries []struct {
		ID         string `json:"id"`
		ThreatName string `json:"threat_name"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("list json: %v (%s)", err, out)
	}
	if len(entries) != 1 || entries[0].ThreatName != "Test.Agent" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	id := entries[0].ID

	// verify whole vault
	if code, _, _ := runCLI(t, "quarantine", "verify", "--store", vault); code != report.ExitOK {
		t.Errorf("verify clean vault: code=%d", code)
	}

	// restore to a new path
	dest := filepath.Join(work, "recovered.bin")
	if code, _, errOut = runCLI(t, "quarantine", "restore", "--store", vault, "--to", dest, id); code != report.ExitOK {
		t.Fatalf("restore: code=%d err=%s", code, errOut)
	}
	if b, _ := os.ReadFile(dest); string(b) != "MZ malicious payload" {
		t.Errorf("restored content wrong: %q", b)
	}

	// delete
	if code, _, _ := runCLI(t, "quarantine", "delete", "--store", vault, id); code != report.ExitOK {
		t.Errorf("delete code=%d", code)
	}
	code, out, _ = runCLI(t, "quarantine", "list", "--store", vault)
	if code != report.ExitOK || !strings.Contains(out, "empty") {
		t.Errorf("vault not empty after delete: %q", out)
	}
}

func TestCLIQuarantineTamperExit(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")
	sample := filepath.Join(work, "a.bin")
	os.WriteFile(sample, []byte("payload-bytes-here"), 0o600)
	runCLI(t, "quarantine", "add", "--store", vault, sample)

	// Corrupt every blob.
	blobDir := filepath.Join(vault, "blobs")
	ents, _ := os.ReadDir(blobDir)
	for _, e := range ents {
		p := filepath.Join(blobDir, e.Name())
		b, _ := os.ReadFile(p)
		if len(b) > 0 {
			b[0] ^= 0xff
			os.WriteFile(p, b, 0o600)
		}
	}
	// verify should now fail with ExitThreat.
	if code, _, _ := runCLI(t, "quarantine", "verify", "--store", vault); code != report.ExitThreat {
		t.Errorf("verify tampered vault: code=%d, want %d", code, report.ExitThreat)
	}
}

func TestCLIQuarantineUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "quarantine"); code != report.ExitUsage {
		t.Errorf("no subcommand: code=%d", code)
	}
	if code, _, _ := runCLI(t, "quarantine", "bogus"); code != report.ExitUsage {
		t.Errorf("bad subcommand: code=%d", code)
	}
	if code, _, _ := runCLI(t, "quarantine", "add", "--store", t.TempDir()); code != report.ExitUsage {
		t.Errorf("add with no path: code=%d", code)
	}
}

func TestCLICanaryPlantCheck(t *testing.T) {
	work := t.TempDir()
	decoys := filepath.Join(work, "decoys")
	manifest := filepath.Join(work, "canary.json")

	code, out, errOut := runCLI(t, "canary", "plant", "--dir", decoys, "--manifest", manifest, "--count", "4")
	if code != report.ExitOK {
		t.Fatalf("plant: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "planted 4") {
		t.Errorf("plant output: %q", out)
	}

	// Fresh check: all intact → ExitOK.
	if code, _, _ := runCLI(t, "canary", "check", "--manifest", manifest); code != report.ExitOK {
		t.Errorf("fresh check: code=%d", code)
	}

	// Trip one canary.
	m, err := os.ReadDir(decoys)
	if err != nil || len(m) == 0 {
		t.Fatalf("decoys missing: %v", err)
	}
	os.WriteFile(filepath.Join(decoys, m[0].Name()), []byte("tampered"), 0o600)

	code, out, _ = runCLI(t, "canary", "check", "--manifest", manifest, "--format", "json")
	if code != report.ExitThreat {
		t.Errorf("tripped check: code=%d, want %d", code, report.ExitThreat)
	}
	if !strings.Contains(out, "modified") {
		t.Errorf("expected a modified status in output: %q", out)
	}
}

func TestCLICanaryUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "canary"); code != report.ExitUsage {
		t.Errorf("no subcommand: code=%d", code)
	}
	if code, _, _ := runCLI(t, "canary", "plant", "--dir", t.TempDir()); code != report.ExitUsage {
		t.Errorf("plant with no manifest: code=%d", code)
	}
	if code, _, _ := runCLI(t, "canary", "check"); code != report.ExitUsage {
		t.Errorf("check with no manifest: code=%d", code)
	}
}

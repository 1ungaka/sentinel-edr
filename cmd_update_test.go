package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/internal/updater"
)

// writeBundle builds a signed bundle directory and returns the dir and the
// hex public key file path.
func writeBundle(t *testing.T, payload []byte, minEngine string) (dir, pubFile string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	m := updater.BuildManifest(payload, "2026.11.02", minEngine)
	mb, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, mb)
	os.WriteFile(filepath.Join(dir, updater.PayloadName), payload, 0o644)
	os.WriteFile(filepath.Join(dir, updater.ManifestName), mb, 0o644)
	os.WriteFile(filepath.Join(dir, updater.SignatureName), []byte(hex.EncodeToString(sig)), 0o644)
	pubFile = filepath.Join(dir, "key.pub")
	os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)), 0o644)
	return dir, pubFile
}

func TestCLIUpdateInstallsAndRollsBack(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("0", 64)+"|Old\n"), 0o644)

	dir, pub := writeBundle(t, []byte("SHA256|"+strings.Repeat("1", 64)+"|New\n"), "0.1.0")

	code, out, errOut := runCLI(t, "update", "--from", dir, "--pubkey", pub, "--db", db)
	if code != report.ExitOK {
		t.Fatalf("update: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "installed") {
		t.Errorf("unexpected output: %q", out)
	}
	if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|New") {
		t.Errorf("db not updated: %q", got)
	}
	if got, _ := os.ReadFile(db + ".bak"); !strings.Contains(string(got), "|Old") {
		t.Errorf("rollback copy missing/old-wrong: %q", got)
	}
}

func TestCLIUpdateDryRun(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("0", 64)+"|Old\n"), 0o644)
	dir, pub := writeBundle(t, []byte("payload"), "")

	code, out, _ := runCLI(t, "update", "--from", dir, "--pubkey", pub, "--db", db, "--dry-run")
	if code != report.ExitOK {
		t.Fatalf("dry-run code=%d", code)
	}
	if !strings.Contains(out, "nothing installed") {
		t.Errorf("dry-run output: %q", out)
	}
	if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
		t.Error("dry-run modified the database")
	}
}

func TestCLIUpdateRejectsTamper(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("0", 64)+"|Old\n"), 0o644)
	dir, pub := writeBundle(t, []byte("good payload"), "")

	// Tamper with the payload after signing.
	os.WriteFile(filepath.Join(dir, updater.PayloadName), []byte("evil payload"), 0o644)

	code, _, errOut := runCLI(t, "update", "--from", dir, "--pubkey", pub, "--db", db)
	if code != report.ExitThreat {
		t.Fatalf("tampered bundle: code=%d, want %d", code, report.ExitThreat)
	}
	if !strings.Contains(errOut, "digest") {
		t.Errorf("expected a digest-mismatch error, got: %q", errOut)
	}
	if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
		t.Error("tampered update modified the database")
	}
}

func TestCLIUpdateWrongKeyRejected(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("x"), 0o644)
	dir, _ := writeBundle(t, []byte("payload"), "")

	// A different, valid key that did not sign this bundle.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyFile := filepath.Join(work, "other.pub")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(otherPub)), 0o644)

	code, _, errOut := runCLI(t, "update", "--from", dir, "--pubkey", keyFile, "--db", db)
	if code != report.ExitThreat {
		t.Errorf("wrong key: code=%d, want %d (%s)", code, report.ExitThreat, errOut)
	}
}

func TestCLIUpdateNoKeyFailsClosed(t *testing.T) {
	dir, _ := writeBundle(t, []byte("payload"), "")
	// No --pubkey and (in a test) no env/pinned key → must refuse.
	t.Setenv(envUpdateKey, "")
	code, _, errOut := runCLI(t, "update", "--from", dir)
	if code != report.ExitRunFailed {
		t.Errorf("no key: code=%d, want %d", code, report.ExitRunFailed)
	}
	if !strings.Contains(errOut, "no trusted public key") {
		t.Errorf("expected fail-closed message, got: %q", errOut)
	}
}

func TestCLIUpdateUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "update"); code != report.ExitUsage {
		t.Errorf("no source: code=%d", code)
	}
	if code, _, _ := runCLI(t, "update", "--from", "x", "--url", "http://y"); code != report.ExitUsage {
		t.Errorf("both sources: code=%d", code)
	}
}

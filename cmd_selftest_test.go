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
)

func TestCLISelftestRecordVerifyTamper(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("a", 64)+"|X\n"), 0o644)
	m := filepath.Join(work, "integrity.json")

	// record
	code, out, errOut := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m)
	if code != report.ExitOK {
		t.Fatalf("record: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "recorded integrity baseline") {
		t.Errorf("record output: %q", out)
	}

	// verify clean
	if code, _, _ := runCLI(t, "selftest", "--db", db, "--manifest", m); code != report.ExitOK {
		t.Errorf("verify clean: code=%d", code)
	}

	// tamper → ExitThreat
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("b", 64)+"|Evil\n"), 0o644)
	code, _, errOut = runCLI(t, "selftest", "--db", db, "--manifest", m)
	if code != report.ExitThreat {
		t.Errorf("tampered: code=%d, want %d", code, report.ExitThreat)
	}
	if !strings.Contains(errOut, "TAMPER") {
		t.Errorf("expected a TAMPER line: %q", errOut)
	}
}

func TestCLISelftestSignedDefeatsRerecord(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("good\n"), 0o644)
	m := filepath.Join(work, "integrity.json")

	// Operator's signing keypair.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyDir := t.TempDir()
	privFile := filepath.Join(keyDir, "priv.hex")
	pubFile := filepath.Join(keyDir, "pub.hex")
	os.WriteFile(privFile, []byte(hex.EncodeToString(priv.Seed())), 0o600)
	os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)), 0o644)

	// Record a SIGNED baseline.
	if code, _, e := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m, "--sign-key", privFile); code != report.ExitOK {
		t.Fatalf("signed record: code=%d err=%s", code, e)
	}
	// Verify against the pinned public key → OK.
	if code, out, _ := runCLI(t, "selftest", "--db", db, "--manifest", m, "--pubkey", pubFile); code != report.ExitOK {
		t.Fatalf("signed verify: code=%d out=%s", code, out)
	}

	// Attacker edits the content AND re-records the (unsigned) manifest to match.
	os.WriteFile(db, []byte("evil\n"), 0o644)
	if code, _, _ := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m); code != report.ExitOK {
		t.Fatal("attacker re-record failed to run")
	}
	// Digest check alone would now pass — but verifying against the pinned key
	// catches it, because the attacker cannot produce a valid signature.
	code, _, errOut := runCLI(t, "selftest", "--db", db, "--manifest", m, "--pubkey", pubFile)
	if code != report.ExitThreat {
		t.Errorf("re-recorded manifest accepted: code=%d, want %d", code, report.ExitThreat)
	}
	if !strings.Contains(errOut, "signature") {
		t.Errorf("expected a signature failure: %q", errOut)
	}
}

func TestCLISelftestMissingManifest(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("x\n"), 0o644)
	code, _, _ := runCLI(t, "selftest", "--db", db, "--manifest", filepath.Join(work, "nope.json"))
	if code != report.ExitRunFailed {
		t.Errorf("missing manifest: code=%d, want %d", code, report.ExitRunFailed)
	}
}

func TestCLISelftestSignedManifestShape(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("x\n"), 0o644)
	m := filepath.Join(work, "integrity.json")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privFile := filepath.Join(work, "priv.hex")
	os.WriteFile(privFile, []byte(hex.EncodeToString(priv.Seed())), 0o600)
	runCLI(t, "selftest", "--record", "--db", db, "--manifest", m, "--sign-key", privFile)
	data, _ := os.ReadFile(m)
	var doc struct {
		Signature string `json:"signature"`
	}
	json.Unmarshal(data, &doc)
	if doc.Signature == "" {
		t.Error("signed manifest has no signature field")
	}
}

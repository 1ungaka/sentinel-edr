package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
)

// The override flags have to change what is verified: a resource that moved to a
// new path is checked there, not reported missing where it used to live.
func TestCLISelftestOverrideChangesWhatIsVerified(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("good\n"), 0o644)
	m := filepath.Join(work, "integrity.json")
	if code, _, e := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m); code != report.ExitOK {
		t.Fatalf("record: exit %d %s", code, e)
	}

	// The operator moves the database. Verification without the flag reports the
	// recorded path missing; with it, the new path is the one checked.
	moved := filepath.Join(work, "moved", "hashes.txt")
	if err := os.MkdirAll(filepath.Dir(moved), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(db, moved); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "selftest", "--db", db, "--manifest", m); code != report.ExitThreat {
		t.Errorf("no override: exit %d, want %d (resource missing at the old path)", code, report.ExitThreat)
	}
	if code, _, _ := runCLI(t, "selftest", "--db", moved, "--manifest", m); code != report.ExitOK {
		t.Errorf("override to a clean copy: exit %d, want %d", code, report.ExitOK)
	}

	// Tampering with the resource where it now lives is still drift.
	os.WriteFile(moved, []byte("evil\n"), 0o644)
	code, _, errOut := runCLI(t, "selftest", "--db", moved, "--manifest", m)
	if code != report.ExitThreat || !strings.Contains(errOut, "TAMPER") {
		t.Errorf("tampered at the overridden path: exit %d err=%q", code, errOut)
	}

	// An override the baseline does not cover is an error, not a silent skip.
	// The baseline is written directly here so the resource set is exact: an
	// auto-discovering record would pick up whatever this checkout happens to
	// have, and "rules" is exactly the resource that exists beside the tests.
	only := filepath.Join(work, "only-signatures.json")
	// The baseline is computed where the database now lives: it was moved to
	// moved above, and Compute digests a resource it can stat, so the pre-move
	// path (which no longer exists) is not one it can record.
	base, err := selftest.Compute([]selftest.Resource{{Name: "signatures", Path: moved}})
	if err != nil {
		t.Fatal(err)
	}
	if err := selftest.WriteManifest(only, base); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runCLI(t, "selftest", "--db", moved, "--rules", moved, "--manifest", only)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "rules") {
		t.Errorf("uncovered override: exit %d err=%q, want %d naming rules", code, errOut, report.ExitRunFailed)
	}
}

// A resource that is only discovered, never named by a flag, must not be
// silently redirected to a discovered path the baseline never recorded.
func TestCLISelftestNoOverrideUsesRecordedPaths(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("good\n"), 0o644)
	m := filepath.Join(work, "integrity.json")
	if code, _, e := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m); code != report.ExitOK {
		t.Fatalf("record: exit %d %s", code, e)
	}
	// A clean copy elsewhere, with no flag pointing at it: the baseline's own
	// path is what is checked, so the report is about that file.
	copy := filepath.Join(work, "other", "hashes.txt")
	if err := os.MkdirAll(filepath.Dir(copy), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(copy, []byte("good\n"), 0o644)
	if code, _, _ := runCLI(t, "selftest", "--db", db, "--manifest", m); code != report.ExitOK {
		t.Errorf("verify without an override: exit %d, want %d", code, report.ExitOK)
	}
}

// The signed baseline authenticates resource paths from schema 3 on, so a
// manifest whose entry was redirected at a clean copy no longer verifies.
func TestCLISelftestSignedPathRedirectFails(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("good\n"), 0o644)
	clean := filepath.Join(work, "clean-copy.txt")
	os.WriteFile(clean, []byte("good\n"), 0o644)
	m := filepath.Join(work, "integrity.json")

	// Sign with a throwaway key the attacker does not have.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDir := t.TempDir()
	privFile, pubFile := filepath.Join(keyDir, "priv.hex"), filepath.Join(keyDir, "pub.hex")
	os.WriteFile(privFile, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
	os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	if code, _, e := runCLI(t, "selftest", "--record", "--db", db, "--manifest", m, "--sign-key", privFile); code != report.ExitOK {
		t.Fatalf("signed record: exit %d %s", code, e)
	}
	if code, _, _ := runCLI(t, "selftest", "--db", db, "--manifest", m, "--pubkey", pubFile); code != report.ExitOK {
		t.Fatalf("signed verify: exit %d", code)
	}

	// Redirect the recorded entry at the clean copy: the digest still matches,
	// which is exactly why the path has to be signed.
	data, err := os.ReadFile(m)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"path": "`+db+`"`, `"path": "`+clean+`"`, 1)
	if edited == string(data) {
		t.Fatalf("manifest does not carry the recorded path: %s", data)
	}
	if err := os.WriteFile(m, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "selftest", "--db", db, "--manifest", m, "--pubkey", pubFile)
	if code != report.ExitThreat || !strings.Contains(errOut, "signature") {
		t.Errorf("path-redirected manifest accepted: exit %d err=%q", code, errOut)
	}
}

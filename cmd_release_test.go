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
)

// keypairFiles writes a hex ed25519 keypair and returns the file paths.
func keypairFiles(t *testing.T) (privFile, pubFile string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	privFile = filepath.Join(dir, "priv.hex")
	pubFile = filepath.Join(dir, "pub.hex")
	os.WriteFile(privFile, []byte(hex.EncodeToString(priv.Seed())), 0o600)
	os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)), 0o644)
	return privFile, pubFile, pub
}

func TestCLIBundleChecksumsAndVerify(t *testing.T) {
	work := t.TempDir()
	privFile, pubFile, _ := keypairFiles(t)

	// A "released" file.
	artifact := filepath.Join(work, "artifact.bin")
	os.WriteFile(artifact, []byte("the released bytes"), 0o644)

	// bundle checksums → signed SHA256SUMS over it.
	if code, _, e := runCLI(t, "bundle", "checksums", "--sign-key", privFile, "--out", work, artifact); code != report.ExitOK {
		t.Fatalf("bundle checksums: code=%d err=%s", code, e)
	}
	for _, n := range []string{"SHA256SUMS", "SHA256SUMS.sig"} {
		if _, err := os.Stat(filepath.Join(work, n)); err != nil {
			t.Fatalf("%s not written: %v", n, err)
		}
	}

	// Tamper SHA256SUMS → signature must fail (ExitThreat) on verify-self.
	// (verify-self checks the running test binary, which is not in SHA256SUMS,
	// but the signature is verified first, so a bad signature is caught before
	// the name lookup.)
	good, _ := os.ReadFile(filepath.Join(work, "SHA256SUMS"))
	os.WriteFile(filepath.Join(work, "SHA256SUMS"), append(good, byte(' ')), 0o644)
	code, _, errOut := runCLI(t, "verify-self", "--from", work, "--pubkey", pubFile, "--name", "artifact.bin")
	if code != report.ExitThreat {
		t.Errorf("tampered SHA256SUMS: code=%d, want %d", code, report.ExitThreat)
	}
	if !strings.Contains(errOut, "signature") {
		t.Errorf("expected a signature error: %q", errOut)
	}
}

func TestCLIBundleUpdateProducesVerifiableBundle(t *testing.T) {
	work := t.TempDir()
	privFile, _, _ := keypairFiles(t)
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("a", 64)+"|X\n"), 0o644)
	out := filepath.Join(work, "bundle")

	code, _, e := runCLI(t, "bundle", "update", "--db", db, "--sign-key", privFile, "--out", out, "--db-version", "2026.11.02", "--min-engine", "0.1.0")
	if code != report.ExitOK {
		t.Fatalf("bundle update: code=%d err=%s", code, e)
	}
	// The produced bundle must install via cau update with the matching pubkey.
	// (Reuse the pubkey the keypair wrote; set it via --pubkey on update.)
	for _, n := range []string{"hashes.txt", "manifest.json", "manifest.json.sig"} {
		if _, err := os.Stat(filepath.Join(out, n)); err != nil {
			t.Fatalf("bundle missing %s: %v", n, err)
		}
	}
}

func TestCLIVerifySelfUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "verify-self"); code != report.ExitUsage {
		t.Errorf("no source: code=%d", code)
	}
	if code, _, _ := runCLI(t, "verify-self", "--from", "x", "--url", "http://y"); code != report.ExitUsage {
		t.Errorf("both sources: code=%d", code)
	}
}

func TestCLIBundleUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "bundle"); code != report.ExitUsage {
		t.Errorf("no subcommand: code=%d", code)
	}
	if code, _, _ := runCLI(t, "bundle", "checksums", "--out", t.TempDir()); code != report.ExitUsage {
		t.Errorf("no sign-key: code=%d", code)
	}
}

// TestBundleUpdateRoundTripsThroughUpdater proves the producer and consumer
// agree: a bundle made by `cau bundle update` verifies and installs via
// `cau update` with the signer's public key.
func TestBundleUpdateRoundTripsThroughUpdater(t *testing.T) {
	work := t.TempDir()
	privFile, pubFile, _ := keypairFiles(t)
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("b", 64)+"|Fam\n"), 0o644)
	out := filepath.Join(work, "bundle")
	if code, _, _ := runCLI(t, "bundle", "update", "--db", db, "--sign-key", privFile, "--out", out, "--min-engine", "0.1.0"); code != report.ExitOK {
		t.Fatal("bundle update failed")
	}
	liveDB := filepath.Join(work, "live.txt")
	os.WriteFile(liveDB, []byte("SHA256|"+strings.Repeat("0", 64)+"|Old\n"), 0o644)
	code, out2, errOut := runCLI(t, "update", "--from", out, "--pubkey", pubFile, "--db", liveDB)
	if code != report.ExitOK {
		t.Fatalf("update from produced bundle: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out2, "installed") {
		t.Errorf("update output: %q", out2)
	}
	if got, _ := os.ReadFile(liveDB); !strings.Contains(string(got), "Fam") {
		t.Errorf("live DB not updated from the bundle: %q", got)
	}
}

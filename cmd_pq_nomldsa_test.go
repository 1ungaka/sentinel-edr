//go:build !go1.27 || nomldsa

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
)

// A binary built without ML-DSA (a Go toolchain older than 1.27, or the
// nomldsa tag) refuses every hybrid key loudly. Run with
//
//	go test -tags nomldsa -run PQ .
func TestPQWithoutMLDSAHybridKeysFailLoudly(t *testing.T) {
	t.Setenv(envUpdateKey, "")
	pub, priv := pqCompatKey()
	scratch := t.TempDir()
	hybridPub := pqWrite(t, filepath.Join(scratch, "hybrid.pub"),
		[]byte("cau-hybrid-v1 public-key\ned25519: "+hex.EncodeToString(pub)+"\nml-dsa-65: "+strings.Repeat("ab", release.PQPublicKeySize)+"\n"))
	hybridPriv := pqWrite(t, filepath.Join(scratch, "hybrid.key"),
		[]byte("cau-hybrid-v1 private-key\ned25519: "+hex.EncodeToString(priv.Seed())+"\nml-dsa-65: "+strings.Repeat("cd", release.PQSeedSize)+"\n"))

	// The bundle is a genuine Ed25519 release by the key's Ed25519 half: it
	// would install if the hybrid key were quietly read as Ed25519-only.
	legacy, edPub := pqLegacyBundle(t, []byte("payload"), "hex")
	db := pqLiveDB(t)
	code, out, errOut := runCLI(t, "update", "--from", legacy, "--pubkey", hybridPub, "--db", db)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "built without ML-DSA-65") || out != "" {
		t.Errorf("update with a hybrid key: code=%d out %q err %q", code, out, errOut)
	}
	if got, _ := os.ReadFile(db); !strings.Contains(string(got), "|Old") {
		t.Error("the database changed")
	}
	if code, _, _ := runCLI(t, "verify-self", "--from", legacy, "--pubkey", hybridPub); code != report.ExitRunFailed {
		t.Errorf("verify-self with a hybrid key: code=%d", code)
	}
	if code, _, errOut := runCLI(t, "bundle", "keygen", "--out", filepath.Join(scratch, "k"), "--hybrid"); code != report.ExitRunFailed || !strings.Contains(errOut, "built without") {
		t.Errorf("keygen --hybrid: code=%d err=%q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(scratch, "k", "cau-release.key")); err == nil {
		t.Error("keygen --hybrid left a key behind")
	}
	if code, _, _ := runCLI(t, "bundle", "update", "--db", db, "--sign-key", hybridPriv, "--out", filepath.Join(scratch, "b")); code != report.ExitRunFailed {
		t.Errorf("bundle update with a hybrid key: code=%d", code)
	}
	// The Ed25519 chain is untouched.
	if code, _, errOut := runCLI(t, "update", "--from", legacy, "--pubkey", edPub, "--db", db); code != report.ExitOK {
		t.Errorf("Ed25519 update: code=%d err=%s", code, errOut)
	}
}

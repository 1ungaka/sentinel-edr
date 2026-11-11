package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/release"
	"github.com/1ungaka/sentinel-edr/internal/report"
)

func testSignKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "priv.hex")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Two inputs sharing a basename would leave one of them out of the signed
// manifest while the success line counted both, so the run has to fail.
func TestCLIBundleChecksumsRefusesBasenameCollision(t *testing.T) {
	work := t.TempDir()
	first, second := filepath.Join(work, "a"), filepath.Join(work, "b")
	for _, d := range []string{first, second} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(first, "payload"), []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "payload"), []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "dist")
	key := testSignKey(t, work)
	code, _, errOut := runCLI(t, "bundle", "checksums", "--sign-key", key, "--out", out,
		filepath.Join(first, "payload"), filepath.Join(second, "payload"))
	if code != report.ExitRunFailed {
		t.Fatalf("collision: exit %d, want %d\n%s", code, report.ExitRunFailed, errOut)
	}
	if !strings.Contains(errOut, "payload") {
		t.Errorf("the failure does not name the colliding file: %q", errOut)
	}
	// Nothing may be written: a manifest missing an input is the bug.
	for _, name := range []string{release.SumsName, release.SigName} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Errorf("%s was written despite the collision", name)
		}
	}
}

// The control: distinct names produce a manifest that covers every input, and
// the count the success line prints is the number of entries in it.
func TestCLIBundleChecksumsCoversEveryInput(t *testing.T) {
	work := t.TempDir()
	out := filepath.Join(work, "dist")
	var inputs []string
	for _, name := range []string{"one", "two", "three"} {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, p)
	}
	key := testSignKey(t, work)
	code, stdout, errOut := runCLI(t, "bundle", "checksums", "--sign-key", key, "--out", out, inputs[0], inputs[1], inputs[2])
	if code != report.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitOK, errOut)
	}
	if !strings.Contains(stdout, "over 3 file(s)") {
		t.Errorf("success line: %q", stdout)
	}
	sums, err := os.ReadFile(filepath.Join(out, release.SumsName))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := release.Parse(sums)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		if _, ok := parsed.Digest(name); !ok {
			t.Errorf("%s is missing from the signed manifest:\n%s", name, sums)
		}
	}
}

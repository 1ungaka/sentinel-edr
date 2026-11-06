package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func bundleAt(t *testing.T, payload, created string) Verified {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := BuildManifest([]byte(payload), "1", "")
	m.Created = created
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(Bundle{Payload: []byte(payload), Manifest: raw, Signature: ed25519.Sign(priv, raw)}, pub, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

const (
	older = "2026-01-01T00:00:00Z"
	newer = "2026-06-01T00:00:00Z"
)

func installed(t *testing.T, payload, created string) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "hashes.txt")
	if _, err := Apply(db, bundleAt(t, payload, created), false); err != nil {
		t.Fatal(err)
	}
	return db
}

// A signature proves a bundle was released, not that it is current. Anyone who
// controls a mirror can serve last year's signed database, which verifies
// perfectly and drops every detection added since.
func TestApplyRefusesAnOlderSignedBundle(t *testing.T) {
	db := installed(t, "new data", newer)
	_, err := Apply(db, bundleAt(t, "old data", older), false)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback", err)
	}
	if got, _ := os.ReadFile(db); string(got) != "new data" {
		t.Fatalf("the database changed on a refused rollback: %q", got)
	}
}

func TestDowngradeNeedsToBeAskedFor(t *testing.T) {
	db := installed(t, "bad release", newer)
	if _, err := Apply(db, bundleAt(t, "known good", older), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(db); string(got) != "known good" {
		t.Fatalf("db = %q", got)
	}
	// The floor moves with it, or the next run would refuse a re-install.
	if err := CheckRollback(db, bundleAt(t, "known good", older).Manifest); err != nil {
		t.Fatalf("after a deliberate downgrade: %v", err)
	}
}

func TestNewerAndSameBundlesInstall(t *testing.T) {
	db := installed(t, "first", older)
	if _, err := Apply(db, bundleAt(t, "first", older), false); err != nil {
		t.Fatalf("re-installing the same bundle: %v", err)
	}
	if _, err := Apply(db, bundleAt(t, "second", newer), false); err != nil {
		t.Fatalf("a newer bundle: %v", err)
	}
}

// Otherwise stripping the field would be the way around the check, on a bundle
// old enough to predate it.
func TestABundleWithNoDateCannotReplaceADatedOne(t *testing.T) {
	db := installed(t, "dated", newer)
	if _, err := Apply(db, bundleAt(t, "undated", ""), false); !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback", err)
	}
}

func TestUnreadableInstallStateFailsClosed(t *testing.T) {
	db := installed(t, "data", older)
	if err := os.WriteFile(db+StateSuffix, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(db, bundleAt(t, "next", newer), false); err == nil {
		t.Fatal("a corrupt install record was ignored")
	}
}

func TestAFirstInstallHasNothingToCompare(t *testing.T) {
	db := filepath.Join(t.TempDir(), "hashes.txt")
	if err := CheckRollback(db, bundleAt(t, "x", older).Manifest); err != nil {
		t.Fatal(err)
	}
}

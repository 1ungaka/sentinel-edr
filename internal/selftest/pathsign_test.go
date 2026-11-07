package selftest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The signature covers each entry's path from schema 3 on: an editor without the
// key could otherwise redirect an entry to a clean copy of the resource while
// the digest and the signature both still verified.
func TestSigningBytesCoversPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Schema: ManifestSchema, Entries: []Entry{
		{Name: "signatures", Path: "/var/lib/cau/hashes.txt", SHA256: "abc"},
	}}
	m.Sign(priv)
	if err := m.VerifySignature(pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Redirect the entry at a clean copy: same digest, same name, new path.
	m.Entries[0].Path = "/tmp/clean-copy.txt"
	if err := m.VerifySignature(pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a path-redirected manifest still verified: %v", err)
	}
}

// A v2 signature is over bytes without the path, so an old manifest keeps
// verifying byte for byte — the documented legacy mode.
func TestLegacySchema2SignatureStillVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Schema: ManifestSchemaLegacy, Entries: []Entry{
		{Name: "signatures", Path: "/var/lib/cau/hashes.txt", SHA256: "abc"},
	}}
	m.Sign(priv)
	if err := m.VerifySignature(pub); err != nil {
		t.Fatalf("v2 signature no longer verifies: %v", err)
	}
	// Re-signing the same v2 manifest by hand over the old byte format must be
	// what Sign produces, or the compatibility is only half of it.
	want := "cau-selftest/v2\nsignatures|abc|false\n"
	if got := string(m.SigningBytes()); got != want {
		t.Errorf("v2 signing bytes = %q, want %q", got, want)
	}
	// The v3 format has the path in it, and a v3 signature is not a v2 one.
	v3 := Manifest{Schema: ManifestSchema, Entries: []Entry{{Name: "signatures", Path: "/p", SHA256: "abc"}}}
	if want3 := "cau-selftest/v3\nsignatures|/p|abc|false\n"; string(v3.SigningBytes()) != want3 {
		t.Errorf("v3 signing bytes = %q, want %q", string(v3.SigningBytes()), want3)
	}
}

func TestReadManifestAcceptsSchema2And3(t *testing.T) {
	work := t.TempDir()
	for _, schema := range []string{"2", "3"} {
		p := filepath.Join(work, "m"+schema+".json")
		if err := os.WriteFile(p, []byte(`{"schema":`+schema+`,"entries":[{"name":"signatures","path":"/p","sha256":"ab"}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadManifest(p); err != nil {
			t.Errorf("schema %s rejected: %v", schema, err)
		}
	}
	p := filepath.Join(work, "old.json")
	if err := os.WriteFile(p, []byte(`{"schema":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(p); err == nil {
		t.Error("accepted schema 1")
	}
}

// An override that says where a moved resource now lives has to make the check
// cover that path — that is what the flag promises.
func TestVerifyWithOverridesCoversMovedResource(t *testing.T) {
	work := t.TempDir()
	orig := filepath.Join(work, "hashes.txt")
	writeFile(t, orig, "good\n")
	moved := filepath.Join(work, "moved", "hashes.txt")
	writeFile(t, moved, "good\n")

	m, err := Compute([]Resource{{Name: "signatures", Path: orig}})
	if err != nil {
		t.Fatal(err)
	}
	// The old location is gone: without the override this is a missing resource.
	if err := os.Remove(orig); err != nil {
		t.Fatal(err)
	}
	drift, err := VerifyWithOverrides(m, map[string]string{"signatures": moved})
	if err != nil {
		t.Fatalf("verify with override: %v", err)
	}
	if len(drift) != 0 {
		t.Errorf("a clean copy at the overridden path reported drift: %v", drift)
	}
	// Now tamper with it where it lives: the override must not hide that.
	writeFile(t, moved, "evil\n")
	drift, err = VerifyWithOverrides(m, map[string]string{"signatures": moved})
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 1 || drift[0].Name != "signatures" {
		t.Fatalf("drift = %v, want the overridden resource", drift)
	}
}

// An override the baseline does not cover is an error, not a silent skip: the
// result would be about a file the signature says nothing about.
func TestVerifyWithOverridesRejectsUnknownName(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	writeFile(t, db, "x\n")
	m, _ := Compute([]Resource{{Name: "signatures", Path: db}})
	if _, err := VerifyWithOverrides(m, map[string]string{"rules": "/elsewhere"}); err == nil {
		t.Error("accepted an override naming no baseline entry")
	}
	// An empty path is "not given", not "given as nothing".
	if _, err := VerifyWithOverrides(m, map[string]string{"rules": ""}); err != nil {
		t.Errorf("an empty override path was an error: %v", err)
	}
	// The no-override path still works, for callers that have no overrides.
	if drift, err := Verify(m); err != nil || len(drift) != 0 {
		t.Errorf("Verify: drift=%v err=%v", drift, err)
	}
}

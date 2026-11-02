package selftest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestComputeAndVerifyClean(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	writeFile(t, db, "SHA256|abc|X\n")
	rules := filepath.Join(work, "rules")
	writeFile(t, filepath.Join(rules, "a.yar"), "rule A {condition: true}")
	writeFile(t, filepath.Join(rules, "b.yar"), "rule B {condition: true}")

	res := []Resource{{Name: "signatures", Path: db}, {Name: "rules", Path: rules}, {Name: "fuzzy", Path: ""}}
	m, err := Compute(res)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if len(m.Entries) != 2 { // empty fuzzy path skipped
		t.Fatalf("entries = %d, want 2", len(m.Entries))
	}
	drift, err := Verify(m)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(drift) != 0 {
		t.Errorf("clean verify reported drift: %v", drift)
	}
}

func TestVerifyDetectsFileAndDirDrift(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	writeFile(t, db, "original\n")
	rules := filepath.Join(work, "rules")
	writeFile(t, filepath.Join(rules, "a.yar"), "rule A {}")

	m, _ := Compute([]Resource{{Name: "signatures", Path: db}, {Name: "rules", Path: rules}})

	// Edit the DB and add a rule file → both drift.
	writeFile(t, db, "tampered\n")
	writeFile(t, filepath.Join(rules, "evil.yar"), "rule Evil {}")

	drift, err := Verify(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 2 {
		t.Fatalf("drift = %v, want 2 (signatures + rules)", drift)
	}
}

func TestVerifyDetectsMissingResource(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	writeFile(t, db, "x\n")
	m, _ := Compute([]Resource{{Name: "signatures", Path: db}})
	os.Remove(db)
	drift, err := Verify(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(drift) != 1 {
		t.Fatalf("drift = %v, want 1 (missing)", drift)
	}
}

func TestDigestTreeIsOrderIndependentButContentSensitive(t *testing.T) {
	work := t.TempDir()
	r1 := filepath.Join(work, "r1")
	writeFile(t, filepath.Join(r1, "z.yar"), "Z")
	writeFile(t, filepath.Join(r1, "a.yar"), "A")
	d1, n1, err := digestTree(r1)
	if err != nil || n1 != 2 {
		t.Fatalf("digestTree: %v n=%d", err, n1)
	}
	// Same files, created in a different order → same digest (sorted).
	r2 := filepath.Join(work, "r2")
	writeFile(t, filepath.Join(r2, "a.yar"), "A")
	writeFile(t, filepath.Join(r2, "z.yar"), "Z")
	d2, _, _ := digestTree(r2)
	if d1 != d2 {
		t.Errorf("digest depends on creation order: %s != %s", d1, d2)
	}
	// Changing content changes the digest.
	writeFile(t, filepath.Join(r2, "a.yar"), "A-modified")
	d3, _, _ := digestTree(r2)
	if d3 == d1 {
		t.Error("digest did not change after an edit")
	}
}

func TestSignAndVerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Schema: ManifestSchema, Entries: []Entry{{Name: "signatures", SHA256: "abc"}}}
	m.Sign(priv)
	if err := m.VerifySignature(pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Tamper an entry digest after signing → signature no longer verifies.
	m.Entries[0].SHA256 = "def"
	if err := m.VerifySignature(pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered manifest verified: %v", err)
	}
}

func TestVerifySignatureWrongKeyAndUnsigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Schema: ManifestSchema, Entries: []Entry{{Name: "x", SHA256: "y"}}}
	m.Sign(priv)
	if err := m.VerifySignature(other); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key accepted: %v", err)
	}
	unsigned := Manifest{Schema: ManifestSchema}
	if err := unsigned.VerifySignature(pub); !errors.Is(err, ErrUnsigned) {
		t.Errorf("unsigned manifest: err = %v, want ErrUnsigned", err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	writeFile(t, db, "x\n")
	m, _ := Compute([]Resource{{Name: "signatures", Path: db}})
	path := filepath.Join(work, "integrity.json")
	if err := WriteManifest(path, m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].SHA256 != m.Entries[0].SHA256 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestParseKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pk, err := ParsePublicKey([]byte(hexify(pub)))
	if err != nil || len(pk) != ed25519.PublicKeySize {
		t.Fatalf("pub parse: %v", err)
	}
	sk, err := ParsePrivateKey([]byte(hexify(priv.Seed())))
	if err != nil || len(sk) != ed25519.PrivateKeySize {
		t.Fatalf("priv (seed) parse: %v", err)
	}
	if _, err := ParsePublicKey([]byte("zz")); err == nil {
		t.Error("accepted a bad public key")
	}
}

func hexify(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

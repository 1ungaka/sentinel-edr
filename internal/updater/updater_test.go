package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// signedBundle builds a valid bundle for payload, signed by priv.
func signedBundle(t *testing.T, priv ed25519.PrivateKey, payload []byte, minEngine string) Bundle {
	t.Helper()
	m := BuildManifest(payload, "2026.11.02", minEngine)
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, mb)
	return Bundle{Payload: payload, Manifest: mb, Signature: sig}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyAcceptsValidBundle(t *testing.T) {
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("SHA256|abc|Test\n"), "0.1.0")
	v, err := Verify(b, pub, "0.4.0-dev")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(v.Payload) != "SHA256|abc|Test\n" {
		t.Error("payload not returned intact")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := keypair(t)
	other, _ := keypair(t)
	b := signedBundle(t, priv, []byte("x"), "")
	if _, err := Verify(b, other, "0.4.0"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("original"), "")
	b.Payload = []byte("tampered") // digest no longer matches the signed manifest
	if _, err := Verify(b, pub, "0.4.0"); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("err = %v, want ErrDigestMismatch", err)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("x"), "")
	b.Manifest = append(b.Manifest, ' ') // signature no longer matches
	if _, err := Verify(b, pub, "0.4.0"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyEngineTooOld(t *testing.T) {
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("x"), "9.9.9")
	if _, err := Verify(b, pub, "0.4.0"); !errors.Is(err, ErrEngineTooOld) {
		t.Errorf("err = %v, want ErrEngineTooOld", err)
	}
}

func TestVerifyNoKey(t *testing.T) {
	_, priv := keypair(t)
	b := signedBundle(t, priv, []byte("x"), "")
	if _, err := Verify(b, nil, "0.4.0"); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

func TestApplyAtomicWithRollback(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|old|Old\n"), 0o644)

	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("SHA256|new|New\n"), "")
	v, err := Verify(b, pub, "0.4.0")
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := Apply(db, v, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(db); string(got) != "SHA256|new|New\n" {
		t.Errorf("db not updated: %q", got)
	}
	if got, _ := os.ReadFile(rollback); string(got) != "SHA256|old|Old\n" {
		t.Errorf("rollback copy wrong: %q", got)
	}
}

func TestApplyToFreshPathNoRollback(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "new", "hashes.txt")
	os.MkdirAll(filepath.Dir(db), 0o755)
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("x"), "")
	v, _ := Verify(b, pub, "0.4.0")
	rollback, err := Apply(db, v, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if rollback != "" {
		t.Errorf("rollback created for a fresh install: %q", rollback)
	}
}

func TestLoadBundleDirAndParseKey(t *testing.T) {
	work := t.TempDir()
	pub, priv := keypair(t)
	b := signedBundle(t, priv, []byte("payload-bytes"), "")
	os.WriteFile(filepath.Join(work, PayloadName), b.Payload, 0o644)
	os.WriteFile(filepath.Join(work, ManifestName), b.Manifest, 0o644)
	// Write the signature as hex, to exercise decodeSig.
	os.WriteFile(filepath.Join(work, SignatureName), []byte(hex.EncodeToString(b.Signature)), 0o644)

	loaded, err := LoadBundleDir(work)
	if err != nil {
		t.Fatalf("LoadBundleDir: %v", err)
	}
	// Round-trip the key through its hex on-disk form.
	key, err := ParsePublicKey([]byte(hex.EncodeToString(pub)))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if _, err := Verify(loaded, key, "0.4.0"); err != nil {
		t.Errorf("verify loaded bundle: %v", err)
	}
}

func TestEngineAtLeast(t *testing.T) {
	cases := []struct {
		running, min string
		want         bool
	}{
		{"0.4.0", "0.1.0", true},
		{"0.4.0", "0.4.0", true},
		{"0.4.0", "0.5.0", false},
		{"1.0.0", "0.9.9", true},
		{"0.4.0-dev", "0.4.0", true},
		{"0.4.0", "", true},
		{"garbage", "0.4.0", true}, // unparseable running → not blocked
	}
	for _, c := range cases {
		if got := engineAtLeast(c.running, c.min); got != c.want {
			t.Errorf("engineAtLeast(%q,%q) = %v, want %v", c.running, c.min, got, c.want)
		}
	}
}

func TestParsePublicKeyBadLength(t *testing.T) {
	if _, err := ParsePublicKey([]byte("abcd")); err == nil {
		t.Error("accepted a too-short key")
	}
}

package updater

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/release"
)

// These run in every build, with or without ML-DSA, and pin that an
// Ed25519-signed bundle behaves through VerifyWithKey exactly as it does
// through Verify. The bundles are made with crypto/ed25519 directly, in the
// forms the release has always published.

func compatKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func compatManifest(t testing.TB, payload []byte, minEngine, created string) []byte {
	t.Helper()
	m := BuildManifest(payload, "2026.11.02", minEngine)
	if created != "" {
		m.Created = created
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return mb
}

func TestCompatEd25519BundleVerifiesTheSameThroughBothPaths(t *testing.T) {
	pub, priv := compatKeypair()
	otherPub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	payload := []byte("SHA256|" + strings.Repeat("1", 64) + "|New\n")
	mb := compatManifest(t, payload, "0.1.0", "")
	sig := ed25519.Sign(priv, mb)
	good := Bundle{Payload: payload, Manifest: mb, Signature: sig}

	tamperedManifest := good
	tamperedManifest.Manifest = append(append([]byte(nil), mb...), ' ')
	tamperedPayload := good
	tamperedPayload.Payload = []byte("evil")
	tooNew := Bundle{Payload: payload, Manifest: compatManifest(t, payload, "99.0.0", "")}
	tooNew.Signature = ed25519.Sign(priv, tooNew.Manifest)
	badSchema := Bundle{Payload: payload, Manifest: []byte(`{"schema":2}`)}
	badSchema.Signature = ed25519.Sign(priv, badSchema.Manifest)
	notJSON := Bundle{Payload: payload, Manifest: []byte(`not json`)}
	notJSON.Signature = ed25519.Sign(priv, notJSON.Manifest)

	cases := []struct {
		name string
		b    Bundle
		key  ed25519.PublicKey
		want error // nil = accepted
	}{
		{"valid", good, pub, nil},
		{"wrong key", good, otherPub, ErrBadSignature},
		{"tampered manifest", tamperedManifest, pub, ErrBadSignature},
		{"tampered payload", tamperedPayload, pub, ErrDigestMismatch},
		{"engine too old", tooNew, pub, ErrEngineTooOld},
		{"unsupported schema", badSchema, pub, ErrBadManifest},
		{"manifest is not JSON", notJSON, pub, ErrBadManifest},
		{"no key", good, nil, ErrNoKey},
		{"empty signature", Bundle{Payload: payload, Manifest: mb}, pub, ErrBadSignature},
	}
	for _, tc := range cases {
		oldV, oldErr := Verify(tc.b, tc.key, "0.4.0")
		newV, checked, newErr := VerifyWithKey(tc.b, release.VerifyKey{Ed25519: tc.key}, "0.4.0")
		if tc.want == nil {
			if oldErr != nil || newErr != nil {
				t.Errorf("%s: old err=%v new err=%v", tc.name, oldErr, newErr)
				continue
			}
			if !reflect.DeepEqual(oldV, newV) {
				t.Errorf("%s: the two paths verified different things", tc.name)
			}
			if checked != (release.Checked{Ed25519: true}) || checked.String() != "Ed25519" {
				t.Errorf("%s: checked = %+v", tc.name, checked)
			}
			continue
		}
		if !errors.Is(oldErr, tc.want) || !errors.Is(newErr, tc.want) {
			t.Errorf("%s: old err=%v new err=%v, want %v from both", tc.name, oldErr, newErr, tc.want)
		}
		if newV.Payload != nil || checked != (release.Checked{}) {
			t.Errorf("%s: a failure returned a payload or a check", tc.name)
		}
	}
}

// The signature file forms an Ed25519 release has always been able to publish
// load and verify as before, through LoadBundleDir and both verifiers.
func TestCompatEd25519SignatureFileForms(t *testing.T) {
	pub, priv := compatKeypair()
	payload := []byte("payload")
	mb := compatManifest(t, payload, "", "")
	raw := ed25519.Sign(priv, mb)
	for name, sigFile := range map[string][]byte{
		"hex":           []byte(hex.EncodeToString(raw)),
		"hex + newline": []byte(hex.EncodeToString(raw) + "\n"),
		"raw":           raw,
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, PayloadName), payload, 0o644)
		os.WriteFile(filepath.Join(dir, ManifestName), mb, 0o644)
		os.WriteFile(filepath.Join(dir, SignatureName), sigFile, 0o644)
		b, err := LoadBundleDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := Verify(b, pub, "0.4.0"); err != nil {
			t.Errorf("%s: Verify: %v", name, err)
		}
		if _, c, err := VerifyWithKey(b, release.VerifyKey{Ed25519: pub}, "0.4.0"); err != nil || c.PQUnchecked {
			t.Errorf("%s: VerifyWithKey: %+v, %v", name, c, err)
		}
		// VerifyWithKey also takes the file bytes as they are.
		b.Signature = sigFile
		if _, _, err := VerifyWithKey(b, release.VerifyKey{Ed25519: pub}, "0.4.0"); err != nil {
			t.Errorf("%s: VerifyWithKey on the unnormalised file: %v", name, err)
		}
		if got := NormalizeSignature(sigFile); string(got) != string(raw) {
			t.Errorf("%s: NormalizeSignature changed", name)
		}
	}
}

// An Ed25519-only key verifies a hybrid-signed bundle on its Ed25519 half and
// says the ML-DSA half was not checked. Verify, the original function, reads
// only the Ed25519 forms and refuses it. The ML-DSA component here is a
// well-formed fake: this verifier must not look at it.
func TestEd25519KeyVerifiesAHybridSignedBundle(t *testing.T) {
	pub, priv := compatKeypair()
	payload := []byte("payload")
	mb := compatManifest(t, payload, "", "")
	sigFile := []byte("cau-hybrid-v1 signature\ned25519: " + hex.EncodeToString(ed25519.Sign(priv, mb)) +
		"\nml-dsa-65: " + strings.Repeat("5a", release.PQSignatureSize) + "\n")

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, PayloadName), payload, 0o644)
	os.WriteFile(filepath.Join(dir, ManifestName), mb, 0o644)
	os.WriteFile(filepath.Join(dir, SignatureName), sigFile, 0o644)
	b, err := LoadBundleDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(NormalizeSignature(sigFile)) != string(sigFile) {
		t.Fatal("NormalizeSignature altered a hybrid signature")
	}
	v, c, err := VerifyWithKey(b, release.VerifyKey{Ed25519: pub}, "0.4.0")
	if err != nil {
		t.Fatalf("Ed25519-only key refused a hybrid-signed bundle: %v", err)
	}
	if c != (release.Checked{Ed25519: true, PQUnchecked: true}) || c.Note() == "" || string(v.Payload) != "payload" {
		t.Errorf("checked = %+v", c)
	}
	if _, err := Verify(b, pub, "0.4.0"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify on a hybrid signature: %v", err)
	}

	// A malformed hybrid signature is a bad signature with the reason.
	b.Signature = []byte("cau-hybrid-v2 signature\n")
	_, _, err = VerifyWithKey(b, release.VerifyKey{Ed25519: pub}, "0.4.0")
	if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "unsupported hybrid format version") {
		t.Errorf("unknown version: %v", err)
	}
}

// The rollback floor applies to what VerifyWithKey returns exactly as it does
// to what Verify returns.
func TestRollbackStillAppliesAfterVerifyWithKey(t *testing.T) {
	pub, priv := compatKeypair()
	key := release.VerifyKey{Ed25519: pub}
	verified := func(payload, created string) Verified {
		mb := compatManifest(t, []byte(payload), "", created)
		v, _, err := VerifyWithKey(Bundle{Payload: []byte(payload), Manifest: mb, Signature: ed25519.Sign(priv, mb)}, key, "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	db := filepath.Join(t.TempDir(), "hashes.txt")
	if _, err := Apply(db, verified("new", newer), false); err != nil {
		t.Fatal(err)
	}
	old := verified("old", older)
	if err := CheckRollback(db, old.Manifest); !errors.Is(err, ErrRollback) {
		t.Fatalf("CheckRollback: %v", err)
	}
	if _, err := Apply(db, old, false); !errors.Is(err, ErrRollback) {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(db); string(got) != "new" {
		t.Fatalf("db = %q", got)
	}
	if _, err := Apply(db, old, true); err != nil {
		t.Fatalf("--allow-downgrade: %v", err)
	}
}

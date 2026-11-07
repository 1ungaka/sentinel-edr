//go:build go1.27 && !nomldsa

package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/release"
)

func hybridKey(t testing.TB) release.SignKey {
	t.Helper()
	k, err := release.GenerateSignKey(true)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// hybridBundle signs a bundle the way `cau bundle update` does with a hybrid key.
func hybridBundle(t testing.TB, k release.SignKey, payload []byte, created string) Bundle {
	t.Helper()
	mb := compatManifest(t, payload, "0.1.0", created)
	sig, err := release.SignDetached(mb, k, release.DomainUpdateManifest)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Payload: payload, Manifest: mb, Signature: sig}
}

func sigHalves(t testing.TB, sig []byte) (edHex, pqHex string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("not a hybrid signature: %d lines", len(lines))
	}
	return strings.TrimPrefix(lines[1], "ed25519: "), strings.TrimPrefix(lines[2], "ml-dsa-65: ")
}

func flip(s string, i int) string {
	c := byte('0')
	if s[i] == '0' {
		c = '1'
	}
	return s[:i] + string(c) + s[i+1:]
}

func TestHybridBundleRoundTripsThroughADirectory(t *testing.T) {
	k := hybridKey(t)
	b := hybridBundle(t, k, []byte("SHA256|"+strings.Repeat("1", 64)+"|New\n"), "")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, PayloadName), b.Payload, 0o644)
	os.WriteFile(filepath.Join(dir, ManifestName), b.Manifest, 0o644)
	os.WriteFile(filepath.Join(dir, SignatureName), b.Signature, 0o644)

	loaded, err := LoadBundleDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, c, err := VerifyWithKey(loaded, k.Public(), "0.4.0")
	if err != nil {
		t.Fatalf("hybrid bundle: %v", err)
	}
	if c != (release.Checked{Ed25519: true, MLDSA: true}) || c.String() != "Ed25519 + ML-DSA-65" || !bytes.Equal(v.Payload, b.Payload) {
		t.Errorf("checked = %+v", c)
	}
	// The manifest checks still follow the signature.
	loaded.Payload = []byte("evil")
	if _, _, err := VerifyWithKey(loaded, k.Public(), "0.4.0"); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("tampered payload: %v", err)
	}
	if _, _, err := VerifyWithKey(b, k.Public(), "0.0.1"); !errors.Is(err, ErrEngineTooOld) {
		t.Errorf("engine too old: %v", err)
	}
}

func TestHybridKeyRequiresBothSignaturesOnABundle(t *testing.T) {
	k := hybridKey(t)
	other := hybridKey(t)
	pub := k.Public()
	b := hybridBundle(t, k, []byte("payload"), "")
	edHex, pqHex := sigHalves(t, b.Signature)
	edRaw, _ := hex.DecodeString(edHex)
	doc := func(ed, pq string) []byte {
		return []byte("cau-hybrid-v1 signature\ned25519: " + ed + "\nml-dsa-65: " + pq + "\n")
	}
	// The same manifest bytes signed as a SHA256SUMS: a genuine hybrid
	// signature by the right key, for the wrong artifact type.
	asChecksums, err := release.SignChecksums(b.Manifest, k)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sig  []byte
		key  release.VerifyKey
		want string
	}{
		{"ML-DSA half stripped, hex left", []byte(edHex), pub, "stripped"},
		{"ML-DSA half stripped, raw left", edRaw, pub, "stripped"},
		{"signed by the Ed25519 half alone", []byte(hex.EncodeToString(ed25519.Sign(k.Ed25519, b.Manifest))), pub, "stripped"},
		{"hybrid frame truncated", []byte("cau-hybrid-v1 signature\ned25519: " + edHex + "\n"), pub, "truncated"},
		{"Ed25519 half tampered", doc(flip(edHex, 5), pqHex), pub, "the Ed25519 signature is not valid"},
		{"ML-DSA half tampered", doc(edHex, flip(pqHex, 5)), pub, "the ML-DSA-65 signature is not valid"},
		{"a checksums signature presented for a manifest", asChecksums, pub, "the ML-DSA-65 signature is not valid"},
		{"wrong ML-DSA key", b.Signature, release.VerifyKey{Ed25519: pub.Ed25519, MLDSA: other.Public().MLDSA}, "the ML-DSA-65 signature is not valid"},
		{"wrong Ed25519 key", b.Signature, release.VerifyKey{Ed25519: other.Public().Ed25519, MLDSA: pub.MLDSA}, "the Ed25519 signature is not valid"},
		{"unknown algorithm", []byte("cau-hybrid-v1 signature\ned25519: " + edHex + "\nml-dsa-87: " + pqHex + "\n"), pub, "unknown algorithm tag"},
	}
	for _, tc := range cases {
		v, c, err := VerifyWithKey(Bundle{Payload: b.Payload, Manifest: b.Manifest, Signature: tc.sig}, tc.key, "0.4.0")
		if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want ErrBadSignature containing %q", tc.name, err, tc.want)
		}
		if v.Payload != nil || c != (release.Checked{}) {
			t.Errorf("%s: a failure returned a payload or a check", tc.name)
		}
	}

	// The stripped forms are genuine Ed25519 signatures: the Ed25519-only key
	// holder accepts them, which is why the hybrid key must not.
	edOnly := release.VerifyKey{Ed25519: pub.Ed25519}
	if _, c, err := VerifyWithKey(Bundle{Payload: b.Payload, Manifest: b.Manifest, Signature: []byte(edHex)}, edOnly, "0.4.0"); err != nil || c.PQUnchecked {
		t.Errorf("Ed25519-only key, stripped signature: %+v, %v", c, err)
	}
	if _, c, err := VerifyWithKey(b, edOnly, "0.4.0"); err != nil || !c.PQUnchecked {
		t.Errorf("Ed25519-only key, hybrid signature: %+v, %v", c, err)
	}
	// The original function reads only the Ed25519 forms.
	if _, err := Verify(b, pub.Ed25519, "0.4.0"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify on a hybrid signature: %v", err)
	}
}

func TestRollbackAppliesToAHybridBundle(t *testing.T) {
	k := hybridKey(t)
	verify := func(payload, created string) Verified {
		v, _, err := VerifyWithKey(hybridBundle(t, k, []byte(payload), created), k.Public(), "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	db := filepath.Join(t.TempDir(), "hashes.txt")
	if _, err := Apply(db, verify("new", newer), false); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(db, verify("old", older), false); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older hybrid-signed bundle installed: %v", err)
	}
	if got, _ := os.ReadFile(db); string(got) != "new" {
		t.Fatalf("db = %q", got)
	}
}

// FuzzVerifyWithKey mutates payload, manifest, signature file and which key is
// trusted around one genuine hybrid-signed bundle. Invariants: never panic,
// and never accept unless the manifest is the genuine one (nobody can forge a
// signature over another) and the payload is the one it names; with the
// hybrid key, the signature must also be the genuine hybrid signature, up to
// the whitespace the reader tolerates.
func FuzzVerifyWithKey(f *testing.F) {
	k := hybridKey(f)
	pub := k.Public()
	edOnly := release.VerifyKey{Ed25519: pub.Ed25519}
	b := hybridBundle(f, k, []byte("SHA256|abc|X\n"), "")
	edHex, pqHex := sigHalves(f, b.Signature)
	asChecksums, err := release.SignChecksums(b.Manifest, k)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(b.Payload, b.Manifest, b.Signature, true)
	f.Add(b.Payload, b.Manifest, b.Signature, false)
	f.Add(b.Payload, b.Manifest, []byte(edHex), true)
	f.Add(b.Payload, b.Manifest, []byte(edHex), false)
	f.Add(b.Payload, b.Manifest, asChecksums, true)
	f.Add(b.Payload, b.Manifest, []byte("cau-hybrid-v1 signature\ned25519: "+edHex+"\nml-dsa-65: "+flip(pqHex, 9)+"\n"), true)
	f.Add([]byte("x"), []byte("{}"), []byte("y"), true)
	f.Add([]byte{}, []byte{}, []byte{}, false)

	canonical := func(sig []byte) string {
		return strings.ReplaceAll(string(bytes.TrimSpace(sig)), "\r\n", "\n") + "\n"
	}
	f.Fuzz(func(t *testing.T, payload, manifest, sig []byte, hybrid bool) {
		key := edOnly
		if hybrid {
			key = pub
		}
		v, c, err := VerifyWithKey(Bundle{Payload: payload, Manifest: manifest, Signature: sig}, key, "0.4.0")
		if err != nil {
			if v.Payload != nil || c != (release.Checked{}) {
				t.Fatalf("a failure returned a payload or a check")
			}
			return
		}
		if !bytes.Equal(manifest, b.Manifest) || !bytes.Equal(payload, b.Payload) {
			t.Fatalf("accepted a bundle that is not the genuine one")
		}
		if hybrid && (canonical(sig) != string(b.Signature) || !c.MLDSA) {
			t.Fatalf("the hybrid key accepted something other than the genuine hybrid signature: %+v", c)
		}
		if !hybrid && c.MLDSA {
			t.Fatalf("the Ed25519-only key claims to have checked ML-DSA")
		}
	})
}

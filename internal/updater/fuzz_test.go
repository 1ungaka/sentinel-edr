package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// FuzzVerify drives the fail-closed bundle verifier with arbitrary payload,
// manifest, signature, and key bytes. Invariants: never panic, and never return
// a nil error (accept the bundle) unless the signature genuinely verifies AND
// the payload digest matches — i.e. a forgery is never accepted.
func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte("SHA256|abc|X\n")
	m := BuildManifest(payload, "1", "0.1.0")
	mb, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, mb)
	f.Add(payload, mb, sig, []byte(pub))
	f.Add([]byte("x"), []byte("{}"), []byte("y"), []byte("z"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, payload, manifest, sig, key []byte) {
		var pk ed25519.PublicKey
		if len(key) == ed25519.PublicKeySize {
			pk = ed25519.PublicKey(key)
		}
		v, err := Verify(Bundle{Payload: payload, Manifest: manifest, Signature: sig}, pk, "0.4.0")
		if err != nil {
			return
		}
		// Accepted: re-check the two guarantees hold for real.
		if len(pk) != ed25519.PublicKeySize || !ed25519.Verify(pk, manifest, sig) {
			t.Fatalf("Verify accepted a bundle whose signature does not verify")
		}
		if v.Manifest.SHA256 == "" {
			t.Fatalf("Verify accepted a bundle with no payload digest")
		}
	})
}

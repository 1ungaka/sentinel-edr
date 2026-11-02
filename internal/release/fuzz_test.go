package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzParse drives the SHA256SUMS parser with arbitrary bytes: never panic, and
// a successful parse must only hold valid 64-hex digests.
func FuzzParse(f *testing.F) {
	f.Add([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  cau\n"))
	f.Add([]byte("# comment\n\n*binary onlyname\n"))
	f.Add([]byte("nothex  x"))
	f.Add([]byte(""))
	f.Add([]byte("   \n\t\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			return
		}
		// Every recorded digest must be a 64-char lowercase hex string.
		for name := range c.sums {
			d, _ := c.Digest(name)
			if !isHex64(d) {
				t.Fatalf("parsed a non-digest %q for %q", d, name)
			}
		}
	})
}

// FuzzVerifySignature must never panic on arbitrary manifest/signature/key bytes.
func FuzzVerifySignature(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := Format(map[string]string{"cau": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	f.Add(data, Sign(data, priv), []byte(pub))
	f.Add([]byte("x"), []byte("y"), []byte("z"))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, sums, sig, key []byte) {
		var pk ed25519.PublicKey
		if len(key) == ed25519.PublicKeySize {
			pk = ed25519.PublicKey(key)
		}
		_ = VerifySignature(sums, sig, pk) // only asserting no panic
	})
}

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
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

// FuzzParseHybrid drives the three parsers that read key and signature files
// with arbitrary bytes. Invariants: never panic; nothing over the size bound
// is accepted as a hybrid object; every accepted component has exactly its
// algorithm's length; and an accepted hybrid object is the canonical encoding
// up to the framing the reader tolerates (surrounding whitespace, CRLF), which
// is what "strict" means: there is one way to write each object.
func FuzzParseHybrid(f *testing.F) {
	pub, priv := compatKey()
	edSig := hex.EncodeToString(ed25519.Sign(priv, compatSums))
	f.Add(hybridDoc("signature", edSig, fakePQSig))
	f.Add(hybridDoc("public-key", hex.EncodeToString(pub), strings.Repeat("ab", PQPublicKeySize)))
	f.Add(hybridDoc("private-key", hex.EncodeToString(priv.Seed()), strings.Repeat("cd", PQSeedSize)))
	f.Add(bytes.ReplaceAll(hybridDoc("signature", edSig, fakePQSig), []byte("\n"), []byte("\r\n")))
	f.Add([]byte("cau-hybrid-v2 signature\ned25519: 00\nml-dsa-65: 00\n"))
	f.Add([]byte("cau-hybrid-v1 signature\ned25519: " + edSig + "\n"))
	f.Add([]byte("cau-hybrid-v1 signature\nml-dsa-87: 00\n"))
	f.Add([]byte("cau-hybrid-"))
	f.Add([]byte(edSig))
	f.Add([]byte(hex.EncodeToString(pub)))
	f.Add([]byte(hex.EncodeToString(priv.Seed())))
	f.Add(ed25519.Sign(priv, compatSums))
	f.Add([]byte{})

	canonical := func(data []byte) string {
		return strings.ReplaceAll(string(bytes.TrimSpace(data)), "\r\n", "\n") + "\n"
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if s, err := ParseSignature(data); err == nil {
			if len(s.Ed25519) != ed25519.SignatureSize {
				t.Fatalf("accepted an Ed25519 component of %d bytes", len(s.Ed25519))
			}
			if s.MLDSA != nil {
				if len(s.MLDSA) != PQSignatureSize || len(data) > maxHybridBytes {
					t.Fatalf("accepted a %d-byte ML-DSA component from %d bytes of input", len(s.MLDSA), len(data))
				}
				if string(s.Encode()) != canonical(data) {
					t.Fatalf("accepted a hybrid signature that is not the canonical encoding")
				}
			}
		}
		if k, err := ParseVerifyKey(data); err == nil {
			if len(k.Ed25519) != ed25519.PublicKeySize {
				t.Fatalf("accepted an Ed25519 public key of %d bytes", len(k.Ed25519))
			}
			if k.MLDSA != nil {
				if len(k.MLDSA.Bytes()) != PQPublicKeySize || len(data) > maxHybridBytes || string(k.Encode()) != canonical(data) {
					t.Fatalf("accepted a hybrid public key that is not the canonical encoding")
				}
			}
		} else if !k.IsZero() {
			t.Fatalf("an error came with a usable public key")
		}
		if k, err := ParseSignKey(data); err == nil {
			if len(k.Ed25519) != ed25519.PrivateKeySize {
				t.Fatalf("accepted an Ed25519 private key of %d bytes", len(k.Ed25519))
			}
			if k.MLDSA != nil {
				if len(k.MLDSA.Bytes()) != PQSeedSize || len(data) > maxHybridBytes || string(k.Encode()) != canonical(data) {
					t.Fatalf("accepted a hybrid private key that is not the canonical encoding")
				}
			}
		} else if k.Ed25519 != nil || k.MLDSA != nil {
			t.Fatalf("an error came with a usable private key")
		}
	})
}

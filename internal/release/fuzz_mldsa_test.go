//go:build go1.27 && !nomldsa

package release

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzVerifyDetached mutates a message, a signature file and the artifact type
// around two genuine hybrid signatures, and holds both verifiers to what they
// may accept. Nobody can forge either scheme, so anything accepted has to be
// one of the two genuine signatures over the genuine message: for the hybrid
// key, that exact signature (up to the whitespace the reader tolerates) under
// the artifact type it was made for; for the Ed25519-only key, the genuine
// Ed25519 signature. Never panic, and never accept anything else.
func FuzzVerifyDetached(f *testing.F) {
	k := mustHybridKey(f)
	pub := k.Public()
	edOnly := VerifyKey{Ed25519: pub.Ed25519}
	msg := append([]byte(nil), compatSums...)
	domains := []Domain{DomainChecksums, DomainUpdateManifest}
	genuine := [][]byte{mustSign(f, msg, k, domains[0]), mustSign(f, msg, k, domains[1])}
	edHex, pqHex := sigParts(f, genuine[0])

	f.Add(msg, genuine[0], uint8(0))
	f.Add(msg, genuine[1], uint8(1))
	f.Add(msg, genuine[0], uint8(1))                                              // wrong artifact type
	f.Add(msg, []byte(edHex), uint8(0))                                           // stripped
	f.Add(msg, []byte("cau-hybrid-v1 signature\ned25519: "+edHex+"\n"), uint8(0)) // truncated
	f.Add(msg, hybridDoc("signature", edHex, fakePQSig), uint8(0))
	f.Add(msg, hybridDoc("signature", flipHex(edHex, 3), pqHex), uint8(0))
	f.Add(msg, bytes.ReplaceAll(genuine[0], []byte("\n"), []byte("\r\n")), uint8(0))
	f.Add([]byte{}, []byte{}, uint8(0))
	f.Add([]byte("x"), []byte("cau-hybrid-"), uint8(1))

	canonical := func(sig []byte) string {
		return strings.ReplaceAll(string(bytes.TrimSpace(sig)), "\r\n", "\n") + "\n"
	}
	f.Fuzz(func(t *testing.T, m, sig []byte, sel uint8) {
		i := int(sel) % len(domains)
		d := domains[i]

		c, err := VerifyDetached(m, sig, pub, d)
		if err == nil {
			if !bytes.Equal(m, msg) || canonical(sig) != string(genuine[i]) || c != (Checked{Ed25519: true, MLDSA: true}) {
				t.Fatalf("hybrid key accepted something other than the genuine %s signature: %+v", d, c)
			}
		} else if c != (Checked{}) {
			t.Fatalf("a failure reported checks: %+v", c)
		}

		c, err = VerifyDetached(m, sig, edOnly, d)
		if err == nil {
			s, perr := ParseSignature(sig)
			if perr != nil || !bytes.Equal(m, msg) || !c.Ed25519 || c.MLDSA {
				t.Fatalf("Ed25519-only key accepted: parse=%v checked=%+v", perr, c)
			}
			if got := string(Signature{Ed25519: s.Ed25519}.Encode()); got != edHex {
				t.Fatalf("Ed25519-only key accepted a signature that is not the genuine one")
			}
			if c.PQUnchecked != s.Hybrid() {
				t.Fatalf("PQUnchecked=%v for a signature with Hybrid()=%v", c.PQUnchecked, s.Hybrid())
			}
		}
	})
}

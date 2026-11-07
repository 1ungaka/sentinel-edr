//go:build go1.27 && !nomldsa

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Tests of the hybrid chain proper. What is under test is this package's own
// work: the encodings, the both-must-verify rule, the downgrade refusal and
// the domain separation. ML-DSA itself is the standard library's and is not
// re-tested with known-answer vectors here.

func mustHybridKey(t testing.TB) SignKey {
	t.Helper()
	k, err := GenerateSignKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Hybrid() || !k.Public().Hybrid() {
		t.Fatal("GenerateSignKey(true) did not make a hybrid key")
	}
	return k
}

func mustSign(t testing.TB, msg []byte, k SignKey, d Domain) []byte {
	t.Helper()
	sig, err := SignDetached(msg, k, d)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// sigParts splits a hybrid signature file into its two hex values by hand.
func sigParts(t testing.TB, sig []byte) (edHex, pqHex string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	if len(lines) != 3 || lines[0] != "cau-hybrid-v1 signature" {
		t.Fatalf("not a hybrid signature file: %d lines, header %q", len(lines), lines[0])
	}
	return strings.TrimPrefix(lines[1], "ed25519: "), strings.TrimPrefix(lines[2], "ml-dsa-65: ")
}

// flipHex changes one hex digit, keeping the value well formed.
func flipHex(s string, i int) string {
	c := byte('0')
	if s[i] == '0' {
		c = '1'
	}
	return s[:i] + string(c) + s[i+1:]
}

func TestPQParameterSetIsConsistent(t *testing.T) {
	p := pqParams()
	if p != mldsa.MLDSA65() || p.String() != PQName {
		t.Fatalf("parameter set %s, named %s", p, PQName)
	}
	if strings.ToLower(PQName) != labelMLDSA {
		t.Fatalf("label %q does not name %s", labelMLDSA, PQName)
	}
	if p.PublicKeySize() != PQPublicKeySize || p.SignatureSize() != PQSignatureSize || mldsa.PrivateKeySize != PQSeedSize {
		t.Fatalf("sizes: public %d signature %d seed %d", p.PublicKeySize(), p.SignatureSize(), mldsa.PrivateKeySize)
	}
	if !PQAvailable {
		t.Fatal("PQAvailable is false in a build with crypto/mldsa")
	}
}

// The on-disk forms are exactly what the package comment says, byte for byte.
func TestHybridEncodingsAreExact(t *testing.T) {
	k := mustHybridKey(t)
	pub := k.Public()

	wantPub := hybridDoc("public-key", hex.EncodeToString(pub.Ed25519), hex.EncodeToString(pub.MLDSA.Bytes()))
	if got := pub.Encode(); !bytes.Equal(got, wantPub) || len(got) != 4015 {
		t.Errorf("public key file: %d bytes, equal=%v", len(got), bytes.Equal(got, wantPub))
	}
	wantPriv := hybridDoc("private-key", hex.EncodeToString(k.Ed25519.Seed()), hex.EncodeToString(k.MLDSA.Bytes()))
	if got := k.Encode(); !bytes.Equal(got, wantPriv) || len(got) != 176 {
		t.Errorf("private key file: %d bytes, equal=%v", len(got), bytes.Equal(got, wantPriv))
	}
	sig := mustSign(t, compatSums, k, DomainChecksums)
	if len(sig) != 6792 {
		t.Errorf("signature file is %d bytes, want 6792", len(sig))
	}
	edHex, pqHex := sigParts(t, sig)
	if len(edHex) != 2*ed25519.SignatureSize || len(pqHex) != 2*PQSignatureSize {
		t.Errorf("components: %d and %d hex characters", len(edHex), len(pqHex))
	}
	// The Ed25519 half is plain Ed25519 over the same bytes: exactly what an
	// Ed25519-only release carries.
	if edHex != hex.EncodeToString(ed25519.Sign(k.Ed25519, compatSums)) {
		t.Error("the Ed25519 half is not plain Ed25519 over the artifact bytes")
	}
	// The ML-DSA half is over the same bytes with the domain as its context,
	// checked here against crypto/mldsa directly.
	pqRaw, _ := hex.DecodeString(pqHex)
	if err := mldsa.Verify(pub.MLDSA.pk, compatSums, pqRaw, &mldsa.Options{Context: "cau-v1-release-checksums"}); err != nil {
		t.Errorf("the ML-DSA half does not verify with the documented context: %v", err)
	}
	if err := mldsa.Verify(pub.MLDSA.pk, compatSums, pqRaw, nil); err == nil {
		t.Error("the ML-DSA half verifies with no context: the domain is not bound")
	}

	// Round trips.
	pub2, err := ParseVerifyKey(wantPub)
	if err != nil || !bytes.Equal(pub2.Encode(), wantPub) || pub2.Algorithms() != "Ed25519 + ML-DSA-65" {
		t.Errorf("public key round trip: %v", err)
	}
	k2, err := ParseSignKey(wantPriv)
	if err != nil || !bytes.Equal(k2.Encode(), wantPriv) || !bytes.Equal(k2.Public().Encode(), wantPub) {
		t.Errorf("private key round trip: %v", err)
	}
	s, err := ParseSignature(sig)
	if err != nil || !s.Hybrid() || !bytes.Equal(s.Encode(), sig) {
		t.Errorf("signature round trip: %v", err)
	}
	// A key read back from disk signs what the original public key verifies.
	if _, err := VerifyChecksums(compatSums, mustSign(t, compatSums, k2, DomainChecksums), pub); err != nil {
		t.Errorf("reloaded key: %v", err)
	}
}

func TestHybridRoundTripBothArtifactTypes(t *testing.T) {
	k := mustHybridKey(t)
	manifest := []byte(`{"schema":1,"db_version":"x","sha256":"00"}`)
	for _, tc := range []struct {
		d   Domain
		msg []byte
	}{{DomainChecksums, compatSums}, {DomainUpdateManifest, manifest}, {DomainChecksums, nil}} {
		sig := mustSign(t, tc.msg, k, tc.d)
		c, err := VerifyDetached(tc.msg, sig, k.Public(), tc.d)
		if err != nil {
			t.Fatalf("%s: %v", tc.d, err)
		}
		if c != (Checked{Ed25519: true, MLDSA: true}) || c.String() != "Ed25519 + ML-DSA-65" || c.Note() != "" {
			t.Errorf("%s: checked = %+v %q", tc.d, c, c)
		}
	}
	// Hedged signing: two signatures over the same bytes differ and both verify.
	a, b := mustSign(t, compatSums, k, DomainChecksums), mustSign(t, compatSums, k, DomainChecksums)
	if bytes.Equal(a, b) {
		t.Error("two hybrid signatures are identical; ML-DSA signing is expected to be hedged")
	}
	if _, err := VerifyChecksums(compatSums, b, k.Public()); err != nil {
		t.Error(err)
	}
}

// Hybrid means both: each half tampered on its own is a rejection, and the
// reason says which half.
func TestHybridRejectsEitherHalfTampered(t *testing.T) {
	k := mustHybridKey(t)
	pub := k.Public()
	sig := mustSign(t, compatSums, k, DomainChecksums)
	edHex, pqHex := sigParts(t, sig)

	cases := []struct {
		name string
		msg  []byte
		sig  []byte
		want string
	}{
		{"Ed25519 half tampered", compatSums, hybridDoc("signature", flipHex(edHex, 7), pqHex), "the Ed25519 signature is not valid"},
		{"ML-DSA half tampered", compatSums, hybridDoc("signature", edHex, flipHex(pqHex, 100)), "the ML-DSA-65 signature is not valid"},
		{"ML-DSA half tampered at its end", compatSums, hybridDoc("signature", edHex, flipHex(pqHex, len(pqHex)-1)), "the ML-DSA-65 signature is not valid"},
		{"ML-DSA half replaced with a well-formed fake", compatSums, hybridDoc("signature", edHex, fakePQSig), "the ML-DSA-65 signature is not valid"},
		{"content tampered", append([]byte("x"), compatSums...), sig, "neither the Ed25519 nor the ML-DSA-65 signature is valid"},
	}
	for _, tc := range cases {
		c, err := VerifyChecksums(tc.msg, tc.sig, pub)
		if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want ErrBadSignature containing %q", tc.name, err, tc.want)
		}
		if c != (Checked{}) {
			t.Errorf("%s: a failure reported checks: %+v", tc.name, c)
		}
	}
	if _, err := VerifyChecksums(compatSums, sig, pub); err != nil {
		t.Fatalf("the untampered signature: %v", err)
	}
}

// The downgrade: strip the post-quantum half and present what is left. A
// hybrid key refuses every way of doing it, although the Ed25519 half is
// genuine. An Ed25519-only key accepts the same artifact and says what it did
// not check.
func TestHybridKeyRefusesAStrippedSignature(t *testing.T) {
	k := mustHybridKey(t)
	pub := k.Public()
	edOnly := VerifyKey{Ed25519: pub.Ed25519}
	sig := mustSign(t, compatSums, k, DomainChecksums)
	edHex, _ := sigParts(t, sig)
	edRaw, _ := hex.DecodeString(edHex)

	stripped := map[string][]byte{
		"bare hex Ed25519 signature":     []byte(edHex),
		"raw Ed25519 signature":          edRaw,
		"what an Ed25519-only key signs": Sign(compatSums, k.Ed25519),
	}
	for name, s := range stripped {
		if err := VerifySignature(compatSums, s, pub.Ed25519); err != nil {
			t.Fatalf("%s: the Ed25519 half is not genuine, so this proves nothing: %v", name, err)
		}
		_, err := VerifyChecksums(compatSums, s, pub)
		if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "stripped") {
			t.Errorf("%s: hybrid key: err = %v, want a refusal naming the missing ML-DSA signature", name, err)
		}
		if c, err := VerifyChecksums(compatSums, s, edOnly); err != nil || c != (Checked{Ed25519: true}) {
			t.Errorf("%s: Ed25519-only key: %+v, %v", name, c, err)
		}
	}
	// The hybrid frame with its second field cut off is malformed for everyone.
	cut := []byte("cau-hybrid-v1 signature\ned25519: " + edHex + "\n")
	for name, key := range map[string]VerifyKey{"hybrid": pub, "Ed25519-only": edOnly} {
		if _, err := VerifyChecksums(compatSums, cut, key); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "truncated") {
			t.Errorf("%s key, truncated frame: %v", name, err)
		}
	}

	// The same hybrid-signed artifact, verified by the holder of the old key.
	c, err := VerifyChecksums(compatSums, sig, edOnly)
	if err != nil {
		t.Fatalf("Ed25519-only key refused a hybrid-signed artifact: %v", err)
	}
	if c != (Checked{Ed25519: true, PQUnchecked: true}) || !strings.Contains(c.Note(), "NOT checked") {
		t.Errorf("checked = %+v, note %q", c, c.Note())
	}
}

// A signature for one artifact type is not a signature for the other, even
// over identical bytes.
func TestHybridDomainSeparation(t *testing.T) {
	k := mustHybridKey(t)
	pub := k.Public()
	msg := []byte("the same bytes, signed as two different things")
	asChecksums := mustSign(t, msg, k, DomainChecksums)
	asManifest := mustSign(t, msg, k, DomainUpdateManifest)

	for _, tc := range []struct {
		name string
		sig  []byte
		d    Domain
	}{
		{"a checksums signature presented for an update manifest", asChecksums, DomainUpdateManifest},
		{"an update-manifest signature presented for checksums", asManifest, DomainChecksums},
	} {
		_, err := VerifyDetached(msg, tc.sig, pub, tc.d)
		if !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "the ML-DSA-65 signature is not valid") {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	if _, err := VerifyDetached(msg, asChecksums, pub, DomainChecksums); err != nil {
		t.Error(err)
	}
	if _, err := VerifyDetached(msg, asManifest, pub, DomainUpdateManifest); err != nil {
		t.Error(err)
	}
	// Stated, not hidden: the Ed25519 half carries no domain (it could not
	// without breaking every existing signature), so an Ed25519-only verifier
	// has only what it always had here, the two artifact types not parsing as
	// each other. The cryptographic separation is the hybrid key's.
	if _, err := VerifyDetached(msg, asChecksums, VerifyKey{Ed25519: pub.Ed25519}, DomainUpdateManifest); err != nil {
		t.Errorf("Ed25519-only verification is expected to be domain-blind: %v", err)
	}
}

func TestHybridRejectsAWrongKeyInEitherHalf(t *testing.T) {
	k := mustHybridKey(t)
	other := mustHybridKey(t)
	sig := mustSign(t, compatSums, k, DomainChecksums)

	wrongPQ := VerifyKey{Ed25519: k.Public().Ed25519, MLDSA: other.Public().MLDSA}
	if _, err := VerifyChecksums(compatSums, sig, wrongPQ); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "the ML-DSA-65 signature is not valid") {
		t.Errorf("wrong ML-DSA key: %v", err)
	}
	wrongEd := VerifyKey{Ed25519: other.Public().Ed25519, MLDSA: k.Public().MLDSA}
	if _, err := VerifyChecksums(compatSums, sig, wrongEd); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "the Ed25519 signature is not valid") {
		t.Errorf("wrong Ed25519 key: %v", err)
	}
	if _, err := VerifyChecksums(compatSums, sig, other.Public()); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "neither") {
		t.Errorf("wrong key entirely: %v", err)
	}
	// A key with a post-quantum half and no Ed25519 half is no key.
	if _, err := VerifyChecksums(compatSums, sig, VerifyKey{MLDSA: k.Public().MLDSA}); !errors.Is(err, ErrNoKey) {
		t.Errorf("ML-DSA-only key: %v", err)
	}
}

// Upgrading an Ed25519 key keeps its Ed25519 half, so nobody is orphaned.
func TestUpgradedKeyKeepsItsEd25519Half(t *testing.T) {
	oldPub, oldPriv := compatKey()
	up, err := SignKey{Ed25519: oldPriv}.WithNewMLDSA()
	if err != nil {
		t.Fatal(err)
	}
	if !up.Hybrid() || !bytes.Equal(up.Public().Ed25519, oldPub) {
		t.Fatal("the upgraded key does not keep the Ed25519 half")
	}
	sig := mustSign(t, compatSums, up, DomainChecksums)
	if c, err := VerifyChecksums(compatSums, sig, VerifyKey{Ed25519: oldPub}); err != nil || !c.PQUnchecked {
		t.Errorf("old key holder: %+v, %v", c, err)
	}
	if c, err := VerifyChecksums(compatSums, sig, up.Public()); err != nil || !c.MLDSA {
		t.Errorf("new key holder: %+v, %v", c, err)
	}
	if _, err := (SignKey{}).WithNewMLDSA(); err == nil {
		t.Error("upgraded an empty key")
	}
}

// A hybrid key file that is not exactly right is an error and yields no key:
// in particular it never yields its Ed25519 half as an Ed25519-only key.
func TestMalformedHybridKeysAreRejected(t *testing.T) {
	k := mustHybridKey(t)
	pub := k.Public()
	ed := hex.EncodeToString(pub.Ed25519)
	pq := hex.EncodeToString(pub.MLDSA.Bytes())
	edSeed := hex.EncodeToString(k.Ed25519.Seed())
	pqSeed := hex.EncodeToString(k.MLDSA.Bytes())
	line := func(parts ...string) []byte { return []byte(strings.Join(parts, "\n") + "\n") }
	const pubHdr, privHdr = "cau-hybrid-v1 public-key", "cau-hybrid-v1 private-key"

	pubCases := []struct {
		name string
		in   []byte
		want string
	}{
		{"unknown version", line("cau-hybrid-v2 public-key", "ed25519: "+ed, "ml-dsa-65: "+pq), "unsupported hybrid format version"},
		{"a private key offered as a public key", k.Encode(), "this is a hybrid private-key, not a hybrid public-key"},
		{"a signature offered as a public key", mustSign(t, compatSums, k, DomainChecksums), "this is a hybrid signature, not a hybrid public-key"},
		{"ML-DSA half missing", line(pubHdr, "ed25519: "+ed), "truncated: the ml-dsa-65 component is missing"},
		{"ML-DSA half truncated", line(pubHdr, "ed25519: "+ed, "ml-dsa-65: "+pq[:3000]), "the ml-dsa-65 component is 3000 hex characters, want exactly 3904"},
		{"ML-DSA-44 sized key", line(pubHdr, "ed25519: "+ed, "ml-dsa-65: "+strings.Repeat("ab", 1312)), "want exactly 3904"},
		{"unknown algorithm", line(pubHdr, "ed25519: "+ed, "slh-dsa: "+pq), "unknown algorithm tag \"slh-dsa\""},
		{"Ed25519 half the wrong length", line(pubHdr, "ed25519: "+ed[:60], "ml-dsa-65: "+pq), "the ed25519 component is 60 hex characters"},
		{"trailing line", line(pubHdr, "ed25519: "+ed, "ml-dsa-65: "+pq, "x"), "unexpected trailing data"},
		{"header only", line(pubHdr), "truncated"},
	}
	for _, tc := range pubCases {
		got, err := ParseVerifyKey(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("public, %s: err = %v, want %q", tc.name, err, tc.want)
		}
		if !got.IsZero() {
			t.Errorf("public, %s: an error came with a usable key", tc.name)
		}
	}

	privCases := []struct {
		name string
		in   []byte
		want string
	}{
		{"unknown version", line("cau-hybrid-v0 private-key", "ed25519: "+edSeed, "ml-dsa-65: "+pqSeed), "unsupported hybrid format version"},
		{"a public key offered as a private key", pub.Encode(), "this is a hybrid public-key, not a hybrid private-key"},
		{"ML-DSA seed missing", line(privHdr, "ed25519: "+edSeed), "truncated: the ml-dsa-65 component is missing"},
		{"ML-DSA seed short", line(privHdr, "ed25519: "+edSeed, "ml-dsa-65: "+pqSeed[:62]), "the ml-dsa-65 component is 62 hex characters, want exactly 64"},
		{"Ed25519 in its 64-byte form", line(privHdr, "ed25519: "+hex.EncodeToString(k.Ed25519), "ml-dsa-65: "+pqSeed), "the ed25519 component is 128 hex characters, want exactly 64"},
		{"trailing line", line(privHdr, "ed25519: "+edSeed, "ml-dsa-65: "+pqSeed, "ml-dsa-65: "+pqSeed), "unexpected trailing data"},
	}
	for _, tc := range privCases {
		got, err := ParseSignKey(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("private, %s: err = %v, want %q", tc.name, err, tc.want)
		}
		if got.Ed25519 != nil || got.MLDSA != nil {
			t.Errorf("private, %s: an error came with a usable key", tc.name)
		}
	}
}

// ── Measurements ─────────────────────────────────────────────────────────────
//
//	go test -run '^$' -bench 'Sign|Verify|Keygen' -benchtime 2s ./internal/release/

var benchMsg = Format(map[string]string{
	"cau-v1.2.3-linux-amd64":        strings.Repeat("1", 64),
	"cau-v1.2.3-linux-amd64.tar.gz": strings.Repeat("2", 64),
	"cau-mcp-v1.2.3-linux-amd64":    strings.Repeat("3", 64),
	"cau-1.2.3.tar.gz":              strings.Repeat("4", 64),
	"hashes.txt":                    strings.Repeat("5", 64),
	"manifest.json":                 strings.Repeat("6", 64),
	"manifest.json.sig":             strings.Repeat("7", 64),
	"integrity.json":                strings.Repeat("8", 64),
	"cau.cdx.json":                  strings.Repeat("9", 64),
	"cau-mcp.cdx.json":              strings.Repeat("a", 64),
})

func BenchmarkSignEd25519(b *testing.B) {
	_, priv := compatKey()
	k := SignKey{Ed25519: priv}
	for b.Loop() {
		if _, err := SignDetached(benchMsg, k, DomainChecksums); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignHybrid includes the verify-after-sign that SignDetached does.
func BenchmarkSignHybrid(b *testing.B) {
	k := mustHybridKey(b)
	for b.Loop() {
		if _, err := SignDetached(benchMsg, k, DomainChecksums); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEd25519(b *testing.B) {
	pub, priv := compatKey()
	sig := Sign(benchMsg, priv)
	key := VerifyKey{Ed25519: pub}
	for b.Loop() {
		if _, err := VerifyDetached(benchMsg, sig, key, DomainChecksums); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyHybrid is parse plus both verifications, from the file bytes.
func BenchmarkVerifyHybrid(b *testing.B) {
	k := mustHybridKey(b)
	sig := mustSign(b, benchMsg, k, DomainChecksums)
	key := k.Public()
	for b.Loop() {
		if _, err := VerifyDetached(benchMsg, sig, key, DomainChecksums); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadHybridPublicKey is what a verifier pays once per run to read
// the trusted key file.
func BenchmarkLoadHybridPublicKey(b *testing.B) {
	enc := mustHybridKey(b).Public().Encode()
	for b.Loop() {
		if _, err := ParseVerifyKey(enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygenHybrid(b *testing.B) {
	for b.Loop() {
		if _, err := GenerateSignKey(true); err != nil {
			b.Fatal(err)
		}
	}
}

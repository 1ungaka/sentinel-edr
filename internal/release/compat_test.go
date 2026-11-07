package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// These tests run in every build, with or without ML-DSA. They pin two things:
// the Ed25519-only chain behaves exactly as it did before hybrid keys existed,
// and the hybrid text form is parsed strictly. Nothing here goes through the
// hybrid signer: Ed25519 material is made with crypto/ed25519 directly, in the
// on-disk forms the release has always used, and hybrid objects are written
// out by hand so the encoder is not what checks the parser.

// compatKey is a fixed Ed25519 keypair, so a failure is reproducible.
func compatKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

var compatSums = Format(map[string]string{
	"cau-v1.2.3-linux-amd64": strings.Repeat("a", 64),
	"hashes.txt":             strings.Repeat("b", 64),
})

// hybridDoc writes a hybrid object by hand, independently of encodeHybrid.
func hybridDoc(kind, edHex, pqHex string) []byte {
	return []byte("cau-hybrid-v1 " + kind + "\ned25519: " + edHex + "\nml-dsa-65: " + pqHex + "\n")
}

// fakePQSig is a well-formed ML-DSA-65 signature component that verifies
// under no key. An Ed25519-only verifier must not care.
var fakePQSig = strings.Repeat("5a", PQSignatureSize)

func TestCompatEd25519SignaturesVerifyAsBefore(t *testing.T) {
	pub, priv := compatKey()
	raw := ed25519.Sign(priv, compatSums)
	hexSig := hex.EncodeToString(raw)

	sigForms := map[string][]byte{
		"raw 64 bytes":       raw,
		"hex":                []byte(hexSig),
		"hex + newline":      []byte(hexSig + "\n"),
		"hex, padded":        []byte("  " + hexSig + " \r\n"),
		"hex, upper case":    []byte(strings.ToUpper(hexSig)),
		"what Sign writes":   Sign(compatSums, priv),
		"what Encode writes": Signature{Ed25519: raw}.Encode(),
	}
	keyForms := map[string][]byte{
		"hex":             []byte(hex.EncodeToString(pub)),
		"hex + newline":   []byte(hex.EncodeToString(pub) + "\n"),
		"hex, upper case": []byte(strings.ToUpper(hex.EncodeToString(pub))),
		"what Encode writes": VerifyKey{
			Ed25519: pub,
		}.Encode(),
	}
	for kn, kf := range keyForms {
		oldKey, err := ParsePublicKey(kf)
		if err != nil {
			t.Fatalf("key %s: ParsePublicKey: %v", kn, err)
		}
		newKey, err := ParseVerifyKey(kf)
		if err != nil {
			t.Fatalf("key %s: ParseVerifyKey: %v", kn, err)
		}
		if newKey.Hybrid() || !bytes.Equal(newKey.Ed25519, oldKey) || newKey.Algorithms() != "Ed25519" {
			t.Fatalf("key %s: a bare-hex key did not parse as the same Ed25519-only key: %+v", kn, newKey)
		}
		for sn, sf := range sigForms {
			if err := VerifySignature(compatSums, sf, oldKey); err != nil {
				t.Errorf("key %s, sig %s: VerifySignature: %v", kn, sn, err)
			}
			for _, d := range []Domain{DomainChecksums, DomainUpdateManifest} {
				c, err := VerifyDetached(compatSums, sf, newKey, d)
				if err != nil {
					t.Errorf("key %s, sig %s, %s: VerifyDetached: %v", kn, sn, d, err)
					continue
				}
				if c != (Checked{Ed25519: true}) || c.String() != "Ed25519" || c.Note() != "" {
					t.Errorf("key %s, sig %s: checked = %+v %q note %q", kn, sn, c, c, c.Note())
				}
			}
			if _, err := VerifyChecksums(compatSums, sf, newKey); err != nil {
				t.Errorf("key %s, sig %s: VerifyChecksums: %v", kn, sn, err)
			}
		}
	}
}

// The old and new verifiers must agree on every input, the rejected ones
// included: same verdict, and ErrBadSignature either way.
func TestCompatOldAndNewVerifiersAgree(t *testing.T) {
	pub, priv := compatKey()
	otherPub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	raw := ed25519.Sign(priv, compatSums)
	hexSig := hex.EncodeToString(raw)
	flipped := append([]byte(nil), raw...)
	flipped[10] ^= 1

	cases := []struct {
		name string
		msg  []byte
		sig  []byte
		key  ed25519.PublicKey
		ok   bool
	}{
		{"valid raw", compatSums, raw, pub, true},
		{"valid hex", compatSums, []byte(hexSig), pub, true},
		{"tampered content", append(append([]byte(nil), compatSums...), ' '), raw, pub, false},
		{"wrong key", compatSums, raw, otherPub, false},
		{"one bit flipped", compatSums, flipped, pub, false},
		{"raw + newline is 65 bytes", compatSums, append(append([]byte(nil), raw...), '\n'), pub, false},
		{"truncated hex", compatSums, []byte(hexSig[:126]), pub, false},
		{"hex with a trailing byte", compatSums, []byte(hexSig + "00"), pub, false},
		{"not hex", compatSums, []byte(strings.Repeat("zz", 64)), pub, false},
		{"64 hex characters read as raw", compatSums, []byte(hexSig[:64]), pub, false},
		{"empty", compatSums, nil, pub, false},
		{"empty content, valid for it", nil, ed25519.Sign(priv, nil), pub, true},
	}
	for _, tc := range cases {
		oldErr := VerifySignature(tc.msg, tc.sig, tc.key)
		_, newErr := VerifyChecksums(tc.msg, tc.sig, VerifyKey{Ed25519: tc.key})
		if (oldErr == nil) != tc.ok || (newErr == nil) != tc.ok {
			t.Errorf("%s: old err=%v new err=%v, want ok=%v", tc.name, oldErr, newErr, tc.ok)
		}
		if !tc.ok && (!errors.Is(oldErr, ErrBadSignature) || !errors.Is(newErr, ErrBadSignature)) {
			t.Errorf("%s: want ErrBadSignature from both, got old=%v new=%v", tc.name, oldErr, newErr)
		}
	}

	// No key is ErrNoKey from both, not a bad signature.
	if err := VerifySignature(compatSums, raw, nil); !errors.Is(err, ErrNoKey) {
		t.Errorf("VerifySignature with no key: %v", err)
	}
	if _, err := VerifyChecksums(compatSums, raw, VerifyKey{}); !errors.Is(err, ErrNoKey) {
		t.Errorf("VerifyChecksums with no key: %v", err)
	}
}

func TestCompatKeyParsersAgree(t *testing.T) {
	pub, priv := compatKey()
	pubHex := hex.EncodeToString(pub)
	for _, in := range []string{pubHex, pubHex + "\n", pubHex[:62], pubHex + "00", "", "not hex", strings.Repeat("g", 64)} {
		oldKey, oldErr := ParsePublicKey([]byte(in))
		newKey, newErr := ParseVerifyKey([]byte(in))
		if (oldErr == nil) != (newErr == nil) || (oldErr != nil && oldErr.Error() != newErr.Error()) {
			t.Errorf("public %q: old err=%v, new err=%v", in, oldErr, newErr)
		}
		if oldErr == nil && (!bytes.Equal(oldKey, newKey.Ed25519) || newKey.MLDSA != nil) {
			t.Errorf("public %q: keys differ", in)
		}
		if newErr != nil && !newKey.IsZero() {
			t.Errorf("public %q: an error came with a usable key", in)
		}
	}
	seedHex := hex.EncodeToString(priv.Seed())
	fullHex := hex.EncodeToString(priv)
	for _, in := range []string{seedHex, seedHex + "\n", fullHex, seedHex[:60], "", "zz"} {
		oldKey, oldErr := ParsePrivateKey([]byte(in))
		newKey, newErr := ParseSignKey([]byte(in))
		if (oldErr == nil) != (newErr == nil) || (oldErr != nil && oldErr.Error() != newErr.Error()) {
			t.Errorf("private %q: old err=%v, new err=%v", in, oldErr, newErr)
		}
		if oldErr == nil && (!bytes.Equal(oldKey, newKey.Ed25519) || newKey.Hybrid()) {
			t.Errorf("private %q: keys differ", in)
		}
	}
}

// An Ed25519 key signs exactly the bytes it always has, through the new entry
// points too.
func TestCompatEd25519SigningIsByteIdentical(t *testing.T) {
	_, priv := compatKey()
	want := hex.EncodeToString(ed25519.Sign(priv, compatSums))
	for _, form := range []string{hex.EncodeToString(priv.Seed()), hex.EncodeToString(priv)} {
		key, err := ParseSignKey([]byte(form))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range []Domain{DomainChecksums, DomainUpdateManifest} {
			got, err := SignDetached(compatSums, key, d)
			if err != nil || string(got) != want {
				t.Errorf("SignDetached(%s) = %q, %v; want %q", d, got, err, want)
			}
		}
		if got, err := SignChecksums(compatSums, key); err != nil || string(got) != want {
			t.Errorf("SignChecksums = %q, %v", got, err)
		}
		if got := Sign(compatSums, key.Ed25519); string(got) != want {
			t.Errorf("Sign = %q", got)
		}
		if key.Algorithms() != "Ed25519" {
			t.Errorf("Algorithms = %q", key.Algorithms())
		}
	}
	if _, err := SignDetached(compatSums, SignKey{}, DomainChecksums); err == nil {
		t.Error("signed with no key")
	}
	key, _ := ParseSignKey([]byte(hex.EncodeToString(priv.Seed())))
	if _, err := SignDetached(compatSums, key, Domain("something-else")); err == nil {
		t.Error("signed for an unknown domain")
	}
	if _, err := VerifyDetached(compatSums, []byte(want), key.Public(), Domain("")); !errors.Is(err, ErrBadSignature) {
		t.Errorf("verified for an unknown domain: %v", err)
	}
}

// An Ed25519-only key holder can verify a hybrid-signed artifact: the Ed25519
// half is checked, the ML-DSA half is reported as present and not checked.
func TestEd25519KeyAcceptsHybridSignatureOnItsEd25519Half(t *testing.T) {
	pub, priv := compatKey()
	edHex := hex.EncodeToString(ed25519.Sign(priv, compatSums))
	sig := hybridDoc("signature", edHex, fakePQSig)

	c, err := VerifyChecksums(compatSums, sig, VerifyKey{Ed25519: pub})
	if err != nil {
		t.Fatalf("Ed25519-only key refused a hybrid signature: %v", err)
	}
	if c != (Checked{Ed25519: true, PQUnchecked: true}) || c.String() != "Ed25519" {
		t.Errorf("checked = %+v %q", c, c)
	}
	if !strings.Contains(c.Note(), "NOT checked") || !strings.Contains(c.Note(), PQName) {
		t.Errorf("note = %q", c.Note())
	}

	// Tolerated framing, and only this: surrounding whitespace, CRLF, no final newline.
	for name, form := range map[string][]byte{
		"CRLF":             bytes.ReplaceAll(sig, []byte("\n"), []byte("\r\n")),
		"padded":           append([]byte("\n  "), append(append([]byte(nil), sig...), " \n\n"...)...),
		"no final newline": bytes.TrimSuffix(sig, []byte("\n")),
	} {
		if _, err := VerifyChecksums(compatSums, form, VerifyKey{Ed25519: pub}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The Ed25519 half still has to be right.
	if _, err := VerifyChecksums(append([]byte("x"), compatSums...), sig, VerifyKey{Ed25519: pub}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered content verified: %v", err)
	}
	// The original Ed25519-only function reads only the bare forms.
	if err := VerifySignature(compatSums, sig, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifySignature on a hybrid signature: %v", err)
	}
}

// Every malformed hybrid signature is a verification failure with a specific
// message, including for a verifier that would not check the ML-DSA half.
func TestMalformedHybridSignaturesAreRejected(t *testing.T) {
	pub, priv := compatKey()
	ed := hex.EncodeToString(ed25519.Sign(priv, compatSums))
	pq := fakePQSig
	line := func(parts ...string) []byte { return []byte(strings.Join(parts, "\n") + "\n") }
	const hdr = "cau-hybrid-v1 signature"

	cases := []struct {
		name string
		sig  []byte
		want string // substring of the reason
	}{
		{"unknown version", line("cau-hybrid-v2 signature", "ed25519: "+ed, "ml-dsa-65: "+pq), "unsupported hybrid format version \"cau-hybrid-v2\""},
		{"version with a suffix", line("cau-hybrid-v10 signature", "ed25519: "+ed, "ml-dsa-65: "+pq), "unsupported hybrid format version"},
		{"magic only", []byte("cau-hybrid-"), "unsupported hybrid format version"},
		{"no kind", line("cau-hybrid-v1", "ed25519: "+ed, "ml-dsa-65: "+pq), "unknown hybrid object kind"},
		{"unknown kind", line("cau-hybrid-v1 certificate", "ed25519: "+ed, "ml-dsa-65: "+pq), "unknown hybrid object kind \"certificate\""},
		{"a public key where a signature belongs", line("cau-hybrid-v1 public-key", "ed25519: "+ed, "ml-dsa-65: "+pq), "this is a hybrid public-key, not a hybrid signature"},
		{"unknown algorithm, first field", line(hdr, "rsa: "+ed, "ml-dsa-65: "+pq), "unknown algorithm tag \"rsa\""},
		{"unknown algorithm, second field", line(hdr, "ed25519: "+ed, "ml-dsa-87: "+pq), "unknown algorithm tag \"ml-dsa-87\""},
		{"label in the wrong case", line(hdr, "Ed25519: "+ed, "ml-dsa-65: "+pq), "unknown algorithm tag"},
		{"fields swapped", line(hdr, "ml-dsa-65: "+pq, "ed25519: "+ed), "found the ml-dsa-65 component where ed25519 belongs"},
		{"Ed25519 twice", line(hdr, "ed25519: "+ed, "ed25519: "+ed), "found the ed25519 component where ml-dsa-65 belongs"},
		{"Ed25519 truncated", line(hdr, "ed25519: "+ed[:126], "ml-dsa-65: "+pq), "the ed25519 component is 126 hex characters, want exactly 128"},
		{"Ed25519 too long", line(hdr, "ed25519: "+ed+"00", "ml-dsa-65: "+pq), "the ed25519 component is 130 hex characters"},
		{"Ed25519 empty", line(hdr, "ed25519: ", "ml-dsa-65: "+pq), "the ed25519 component is 0 hex characters"},
		{"ML-DSA truncated", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq[:6000]), "the ml-dsa-65 component is 6000 hex characters, want exactly 6618"},
		{"ML-DSA odd length", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq[:6617]), "the ml-dsa-65 component is 6617 hex characters"},
		{"ML-DSA too long", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq+"ab"), "the ml-dsa-65 component is 6620 hex characters"},
		{"ML-DSA of another parameter set's length", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+strings.Repeat("ab", 2420)), "want exactly 6618"},
		{"trailing bytes on the last field", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq+" x"), "the ml-dsa-65 component is 6620 hex characters"},
		{"upper-case hex", line(hdr, "ed25519: "+strings.ToUpper(ed), "ml-dsa-65: "+pq), "not lowercase hexadecimal"},
		{"not hex", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq[:6616]+"zz"), "not lowercase hexadecimal"},
		{"ML-DSA line missing", line(hdr, "ed25519: "+ed), "truncated: the ml-dsa-65 component is missing"},
		{"header only", line(hdr), "truncated: the ed25519 and ml-dsa-65 components are missing"},
		{"a fourth line", line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq, "ml-dsa-87: "+pq), "unexpected trailing data"},
		{"trailing bytes after the object", append(line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq), "junk"...), "unexpected trailing data"},
		{"blank line inside", line(hdr, "", "ed25519: "+ed, "ml-dsa-65: "+pq), "expected a \"ed25519\" line"},
		{"no space after the colon", line(hdr, "ed25519:"+ed, "ml-dsa-65: "+pq), "expected a \"ed25519\" line"},
		{"two spaces after the colon", line(hdr, "ed25519:  "+ed, "ml-dsa-65: "+pq), "the ed25519 component is 129 hex characters"},
		{"over the size limit", append(line(hdr, "ed25519: "+ed, "ml-dsa-65: "+pq), bytes.Repeat([]byte(" "), maxHybridBytes)...), "over the 16384-byte limit"},
		{"bare hex of the wrong length", []byte(ed + pq), "is not a cau-hybrid-v1 object"},
	}
	for _, tc := range cases {
		_, err := VerifyChecksums(compatSums, tc.sig, VerifyKey{Ed25519: pub})
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v, want ErrBadSignature", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), "malformed signature") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: reason %q does not contain %q", tc.name, err, tc.want)
		}
		if _, perr := ParseSignature(tc.sig); perr == nil {
			t.Errorf("%s: ParseSignature accepted it", tc.name)
		}
	}
}

// A file-derived token in an error is bounded and quoted.
func TestHybridErrorsBoundWhatTheyQuote(t *testing.T) {
	long := "cau-hybrid-v" + strings.Repeat("9", 5000) + " signature\n"
	_, err := ParseSignature([]byte(long))
	if err == nil || len(err.Error()) > 300 {
		t.Fatalf("error is %d bytes: %v", len(err.Error()), err)
	}
	_, err = ParseSignature([]byte("cau-hybrid-v1 signature\n\x1b[2Jevil: 00\n"))
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("an escape byte reached the error text: %q", err)
	}
}

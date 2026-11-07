package release

// The hybrid (Ed25519 + ML-DSA) signature chain. The package comment in
// release.go specifies the on-disk forms; this file implements them. The
// ML-DSA primitive itself is behind pq_mldsa.go (Go 1.27 and later) and
// pq_none.go (older toolchains, where a hybrid key is an error).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The post-quantum half. The parameter set is ML-DSA-65, chosen in
// pq_mldsa.go's pqParams; the names and sizes that follow from it are here,
// and that file does not compile if a size disagrees with crypto/mldsa.
//
// ML-DSA-65 is FIPS 204's NIST security category 3 (roughly the cost of
// breaking AES-192). A release key is long-lived and is pinned on air-gapped
// machines that are re-keyed rarely, so the margin over category 2 (ML-DSA-44)
// is worth having, and the cost is paid once per update, not per file scanned:
// a 1952-byte public key and a 3309-byte signature (3904 and 6618 hex
// characters on disk) next to a signature database of megabytes. ML-DSA-87
// (category 5) would add another 640 and 1318 bytes for a margin this chain
// does not otherwise have: the classical half is Ed25519, about 128 bits.
const (
	// PQName is how the post-quantum algorithm is named in output.
	PQName = "ML-DSA-65"
	// PQPublicKeySize, PQSignatureSize and PQSeedSize are the raw component
	// sizes in bytes. The private key is stored as its 32-byte FIPS 204 seed.
	PQPublicKeySize = 1952
	PQSignatureSize = 3309
	PQSeedSize      = 32
)

// ErrPQUnavailable: this binary has no ML-DSA (see PQAvailable), so a hybrid
// key cannot be loaded, generated or used. It is always an error and never a
// reason to check less.
var ErrPQUnavailable = errors.New("release: this binary was built without " + PQName + " (crypto/mldsa needs Go 1.27 or later), so it cannot use a hybrid key")

// Field labels of the hybrid text form. The post-quantum label carries the
// parameter set, so a different set is a different, unknown label to this
// build and is rejected, never read as ML-DSA-65.
const (
	labelEd25519 = "ed25519"
	labelMLDSA   = "ml-dsa-65"
)

// The hybrid text form's header line is "<version> <kind>".
const (
	hybridMagic   = "cau-hybrid-"   // any hybrid object, any version
	hybridVersion = "cau-hybrid-v1" // the only version this build reads
	kindPublic    = "public-key"
	kindPrivate   = "private-key"
	kindSignature = "signature"
)

// maxHybridBytes bounds a hybrid object before anything is split or decoded.
// The largest valid one is a signature, 6792 bytes (6794 with CRLF line ends
// and no final newline, 6795 with one).
const maxHybridBytes = 16 << 10

// Domain names what a signature is over. The ML-DSA half is made and checked
// with the domain as its FIPS 204 context string (crypto/mldsa Options.Context),
// so a signature over one kind of artifact never verifies as a signature over
// another, whatever the bytes are. The Ed25519 half has no context: it stays
// plain Ed25519 over the artifact bytes, which is what keeps every existing
// signature and every Ed25519-only key holder working.
type Domain string

// The two signed artifact types. These strings are part of the signature
// format: changing one invalidates every hybrid signature made with it.
const (
	// DomainChecksums: the bytes of a release SHA256SUMS file.
	DomainChecksums Domain = "cau-v1-release-checksums"
	// DomainUpdateManifest: the bytes of an update bundle's manifest.json.
	DomainUpdateManifest Domain = "cau-v1-update-manifest"
)

func (d Domain) valid() bool { return d == DomainChecksums || d == DomainUpdateManifest }

// VerifyKey is a trusted public key. Ed25519 is always set; MLDSA is set for a
// hybrid key and nil for an Ed25519-only one. Which of the two it is decides
// what a signature must carry (see VerifyDetached); it is never negotiated
// with the artifact.
type VerifyKey struct {
	Ed25519 ed25519.PublicKey
	MLDSA   *PQPublicKey
}

// IsZero reports whether no key is configured at all.
func (k VerifyKey) IsZero() bool { return len(k.Ed25519) == 0 && k.MLDSA == nil }

// Hybrid reports whether the key has a post-quantum half.
func (k VerifyKey) Hybrid() bool { return k.MLDSA != nil }

// Algorithms names what a signature must carry to verify against this key.
func (k VerifyKey) Algorithms() string { return algorithms(k.Hybrid()) }

// Encode renders the key in its on-disk form: bare hex and a newline for an
// Ed25519-only key (what ParsePublicKey reads), the hybrid text form otherwise.
func (k VerifyKey) Encode() []byte {
	if k.MLDSA == nil {
		return []byte(hex.EncodeToString(k.Ed25519) + "\n")
	}
	return encodeHybrid(kindPublic, k.Ed25519, k.MLDSA.Bytes())
}

// SignKey is a release signing key: Ed25519 always, plus ML-DSA when hybrid.
type SignKey struct {
	Ed25519 ed25519.PrivateKey
	MLDSA   *PQPrivateKey
}

// Hybrid reports whether the key has a post-quantum half.
func (k SignKey) Hybrid() bool { return k.MLDSA != nil }

// Algorithms names the signatures this key produces.
func (k SignKey) Algorithms() string { return algorithms(k.Hybrid()) }

// Public returns the matching verification key.
func (k SignKey) Public() VerifyKey {
	var v VerifyKey
	if len(k.Ed25519) == ed25519.PrivateKeySize {
		v.Ed25519, _ = k.Ed25519.Public().(ed25519.PublicKey)
	}
	if k.MLDSA != nil {
		v.MLDSA = k.MLDSA.Public()
	}
	return v
}

// Encode renders the key in its on-disk form: the bare hex Ed25519 seed and a
// newline for an Ed25519-only key, the hybrid text form (two 32-byte seeds)
// otherwise. A key with no Ed25519 half encodes to nothing.
func (k SignKey) Encode() []byte {
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		return nil
	}
	if k.MLDSA == nil {
		return []byte(hex.EncodeToString(k.Ed25519.Seed()) + "\n")
	}
	return encodeHybrid(kindPrivate, k.Ed25519.Seed(), k.MLDSA.Bytes())
}

// Signature is a parsed detached signature. MLDSA is nil for an Ed25519-only
// signature. Both components, when present, have exactly their algorithm's
// signature length; ParseSignature returns nothing else.
type Signature struct {
	Ed25519 []byte
	MLDSA   []byte
}

// Hybrid reports whether the signature carries a post-quantum component.
func (s Signature) Hybrid() bool { return s.MLDSA != nil }

// Encode renders the signature in its on-disk form: bare hex with no newline
// for Ed25519-only (byte-for-byte what Sign has always written), the hybrid
// text form otherwise.
func (s Signature) Encode() []byte {
	if s.MLDSA == nil {
		return []byte(hex.EncodeToString(s.Ed25519))
	}
	return encodeHybrid(kindSignature, s.Ed25519, s.MLDSA)
}

// Checked says which signatures a successful verification actually checked.
type Checked struct {
	Ed25519 bool
	MLDSA   bool
	// PQUnchecked: the artifact carries an ML-DSA signature that was NOT
	// verified, because the trusted key is Ed25519-only. The result is exactly
	// as strong as an Ed25519-only signature.
	PQUnchecked bool
}

// String names the signatures checked: "Ed25519" or "Ed25519 + ML-DSA-65".
func (c Checked) String() string {
	switch {
	case c.Ed25519 && c.MLDSA:
		return algorithms(true)
	case c.Ed25519:
		return algorithms(false)
	}
	return "nothing"
}

// Note is a sentence for the operator when a post-quantum signature was
// present and not checked, and "" otherwise.
func (c Checked) Note() string {
	if !c.PQUnchecked {
		return ""
	}
	return "a post-quantum (" + PQName + ") signature is present but was NOT checked, because the trusted key is Ed25519-only; trust the hybrid public key to require it"
}

func algorithms(hybrid bool) string {
	if hybrid {
		return "Ed25519 + " + PQName
	}
	return "Ed25519"
}

// VerifyError is a signature that did not verify, with the specific reason.
// It matches ErrBadSignature under errors.Is.
type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return "release: signature does not verify: " + e.Reason }

// Is makes errors.Is(err, ErrBadSignature) true for every VerifyError.
func (e *VerifyError) Is(target error) bool { return target == ErrBadSignature }

// GenerateSignKey makes a new signing key from the system random source:
// Ed25519 alone, or Ed25519 plus ML-DSA-65 when hybrid is set.
func GenerateSignKey(hybrid bool) (SignKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SignKey{}, fmt.Errorf("release: generate Ed25519 key: %w", err)
	}
	k := SignKey{Ed25519: priv}
	if hybrid {
		return k.WithNewMLDSA()
	}
	return k, nil
}

// WithNewMLDSA returns the key with a freshly generated ML-DSA-65 half beside
// its existing Ed25519 half. This is how an Ed25519 release key becomes hybrid
// without orphaning anyone: the Ed25519 public key does not change, so a host
// that pins only it still verifies everything the upgraded key signs.
func (k SignKey) WithNewMLDSA() (SignKey, error) {
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		return SignKey{}, errors.New("release: no Ed25519 key to pair the " + PQName + " key with")
	}
	pq, err := pqGenerateKey()
	if err != nil {
		if errors.Is(err, ErrPQUnavailable) {
			return SignKey{}, err
		}
		return SignKey{}, fmt.Errorf("release: generate %s key: %w", PQName, err)
	}
	return SignKey{Ed25519: k.Ed25519, MLDSA: pq}, nil
}

// SignDetached signs msg for the given domain and returns the detached
// signature in its on-disk form. An Ed25519-only key writes exactly what Sign
// writes. A hybrid key writes the hybrid form with both signatures over the
// same msg: Ed25519 plain, ML-DSA-65 with the domain as its context string.
// The ML-DSA signature is the hedged (randomised) variant, FIPS 204's default,
// so signing the same bytes twice gives two different, equally valid files.
//
// A hybrid signature is verified against the key's own public half before it
// is returned, so a fault during signing is an error here and not a release
// that fails to verify on a machine nobody can reach.
func SignDetached(msg []byte, key SignKey, d Domain) ([]byte, error) {
	if len(key.Ed25519) != ed25519.PrivateKeySize {
		return nil, errors.New("release: no signing key")
	}
	if !d.valid() {
		return nil, fmt.Errorf("release: unknown signature domain %q", string(d))
	}
	s := Signature{Ed25519: ed25519.Sign(key.Ed25519, msg)}
	if key.MLDSA == nil {
		return s.Encode(), nil
	}
	pq, err := pqSign(key.MLDSA, msg, string(d))
	if err != nil {
		return nil, fmt.Errorf("release: %s sign: %w", PQName, err)
	}
	s.MLDSA = pq
	out := s.Encode()
	if _, err := VerifyDetached(msg, out, key.Public(), d); err != nil {
		return nil, fmt.Errorf("release: the signature just made does not verify, refusing to write it: %w", err)
	}
	return out, nil
}

// VerifyDetached verifies a detached signature (any on-disk form) over msg for
// the given domain. The trusted key alone decides what is required:
//
//   - An Ed25519-only key requires a valid Ed25519 signature. If the signature
//     is hybrid, its ML-DSA component must still be well formed but is not
//     verified, and Checked.PQUnchecked says so.
//   - A hybrid key requires BOTH a valid Ed25519 signature and a valid
//     ML-DSA-65 signature over the same msg. There is no either-one mode, and
//     a signature with no ML-DSA component is rejected even when its Ed25519
//     half is valid: stripping the post-quantum half is the downgrade a hybrid
//     key exists to stop.
//
// It returns ErrNoKey when the key has no Ed25519 half, and a *VerifyError
// (which matches ErrBadSignature) naming the reason for everything else,
// malformed encodings included.
func VerifyDetached(msg, sig []byte, key VerifyKey, d Domain) (Checked, error) {
	if len(key.Ed25519) != ed25519.PublicKeySize {
		return Checked{}, ErrNoKey
	}
	if !d.valid() {
		return Checked{}, &VerifyError{Reason: fmt.Sprintf("unknown signature domain %q", string(d))}
	}
	s, err := parseSignature(sig)
	if err != nil {
		return Checked{}, &VerifyError{Reason: "malformed signature: " + err.Error()}
	}
	edOK := ed25519.Verify(key.Ed25519, msg, s.Ed25519)
	if key.MLDSA == nil {
		if !edOK {
			return Checked{}, &VerifyError{Reason: "the Ed25519 signature is not valid for this key and content"}
		}
		return Checked{Ed25519: true, PQUnchecked: s.MLDSA != nil}, nil
	}
	if s.MLDSA == nil {
		return Checked{}, &VerifyError{Reason: "the trusted key is hybrid (" + algorithms(true) + ") but the signature is Ed25519-only; an artifact with its " + PQName + " signature missing or stripped is refused"}
	}
	pqErr := pqVerify(key.MLDSA, msg, s.MLDSA, string(d))
	switch {
	case !edOK && pqErr != nil:
		return Checked{}, &VerifyError{Reason: fmt.Sprintf("neither the Ed25519 nor the %s signature is valid for this key and content (%v)", PQName, pqErr)}
	case !edOK:
		return Checked{}, &VerifyError{Reason: "the Ed25519 signature is not valid for this key and content (the " + PQName + " signature is, but both are required)"}
	case pqErr != nil:
		return Checked{}, &VerifyError{Reason: fmt.Sprintf("the %s signature is not valid for this key, content and artifact type (%v; the Ed25519 signature is, but both are required)", PQName, pqErr)}
	}
	return Checked{Ed25519: true, MLDSA: true}, nil
}

// SignChecksums signs SHA256SUMS bytes with either kind of key and returns the
// SHA256SUMS.sig content. With an Ed25519-only key it equals Sign.
func SignChecksums(sumsData []byte, key SignKey) ([]byte, error) {
	return SignDetached(sumsData, key, DomainChecksums)
}

// VerifyChecksums verifies a SHA256SUMS.sig (any form) against either kind of
// key, under the rules of VerifyDetached. A signature that does not verify is
// ErrBadSignature with the reason appended.
func VerifyChecksums(sumsData, sig []byte, key VerifyKey) (Checked, error) {
	c, err := VerifyDetached(sumsData, sig, key, DomainChecksums)
	var ve *VerifyError
	if errors.As(err, &ve) {
		return Checked{}, fmt.Errorf("%w: %s", ErrBadSignature, ve.Reason)
	}
	return c, err
}

// ParseVerifyKey reads a public key in either on-disk form: bare hex is an
// Ed25519-only key (exactly ParsePublicKey), the hybrid text form is a hybrid
// key. A hybrid object of another version or kind is an error, never a
// fallback to the other form, and so is a hybrid key in a binary that has no
// ML-DSA (ErrPQUnavailable): its Ed25519 half is never used on its own.
func ParseVerifyKey(data []byte) (VerifyKey, error) {
	if !isHybrid(data) {
		pub, err := ParsePublicKey(data)
		if err != nil {
			return VerifyKey{}, err
		}
		return VerifyKey{Ed25519: pub}, nil
	}
	ed, pq, err := parseHybrid(data, kindPublic, ed25519.PublicKeySize, PQPublicKeySize)
	if err != nil {
		return VerifyKey{}, fmt.Errorf("release: hybrid public key: %w", err)
	}
	pk, err := pqNewPublicKey(pq)
	if err != nil {
		return VerifyKey{}, pqKeyError("public", err)
	}
	return VerifyKey{Ed25519: ed25519.PublicKey(ed), MLDSA: pk}, nil
}

// ParseSignKey reads a private key in either on-disk form: bare hex is an
// Ed25519-only key (exactly ParsePrivateKey: seed or full form), the hybrid
// text form holds the Ed25519 seed and the ML-DSA-65 seed.
func ParseSignKey(data []byte) (SignKey, error) {
	if !isHybrid(data) {
		priv, err := ParsePrivateKey(data)
		if err != nil {
			return SignKey{}, err
		}
		return SignKey{Ed25519: priv}, nil
	}
	ed, pq, err := parseHybrid(data, kindPrivate, ed25519.SeedSize, PQSeedSize)
	if err != nil {
		return SignKey{}, fmt.Errorf("release: hybrid private key: %w", err)
	}
	sk, err := pqNewPrivateKey(pq)
	if err != nil {
		return SignKey{}, pqKeyError("private", err)
	}
	return SignKey{Ed25519: ed25519.NewKeyFromSeed(ed), MLDSA: sk}, nil
}

func pqKeyError(which string, err error) error {
	if errors.Is(err, ErrPQUnavailable) {
		return err
	}
	return fmt.Errorf("release: hybrid %s key: %s component: %w", which, labelMLDSA, err)
}

// ParseSignature reads a detached signature in any on-disk form: 64 raw bytes
// or bare hex is an Ed25519-only signature, the hybrid text form carries both.
// Every component returned has exactly its algorithm's signature length.
func ParseSignature(data []byte) (Signature, error) {
	s, err := parseSignature(data)
	if err != nil {
		return Signature{}, fmt.Errorf("release: signature: %w", err)
	}
	return s, nil
}

func parseSignature(data []byte) (Signature, error) {
	// Raw first, exactly as the Ed25519-only readers always have: 64 bytes are
	// a raw signature whatever they contain. A hybrid object is never 64 bytes.
	if len(data) == ed25519.SignatureSize {
		return Signature{Ed25519: data}, nil
	}
	if isHybrid(data) {
		ed, pq, err := parseHybrid(data, kindSignature, ed25519.SignatureSize, PQSignatureSize)
		if err != nil {
			return Signature{}, err
		}
		return Signature{Ed25519: ed, MLDSA: pq}, nil
	}
	// The length check comes before the decode, so garbage of any size costs
	// one trim.
	text := bytes.TrimSpace(data)
	if len(text) != 2*ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("an Ed25519 signature is %d raw bytes or %d hex characters; this is %d bytes and is not a %s object",
			ed25519.SignatureSize, 2*ed25519.SignatureSize, len(text), hybridVersion)
	}
	raw, err := hex.DecodeString(string(text))
	if err != nil {
		return Signature{}, errors.New("not hexadecimal")
	}
	return Signature{Ed25519: raw}, nil
}

// isHybrid reports whether data claims to be a hybrid object of any version.
// The magic contains letters that are not hex digits, so no bare-hex key or
// signature can be mistaken for one, and nothing that starts with it is ever
// read as bare hex.
func isHybrid(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte(hybridMagic))
}

// encodeHybrid writes the one canonical hybrid text form.
func encodeHybrid(kind string, ed, pq []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(hybridVersion) + len(kind) + 2*(len(ed)+len(pq)) + 32)
	b.WriteString(hybridVersion + " " + kind + "\n")
	b.WriteString(labelEd25519 + ": " + hex.EncodeToString(ed) + "\n")
	b.WriteString(labelMLDSA + ": " + hex.EncodeToString(pq) + "\n")
	return b.Bytes()
}

// parseHybrid reads a hybrid object of the wanted kind and returns its two
// components, each exactly edLen and pqLen bytes. Everything is bounded and
// positional: the object is at most maxHybridBytes, has exactly three lines
// (header, ed25519, ml-dsa-65, in that order), and each value is exactly the
// expected number of lowercase hex characters. Surrounding whitespace and CRLF
// line ends are tolerated, as they are for the bare-hex forms; nothing else is.
func parseHybrid(data []byte, wantKind string, edLen, pqLen int) (ed, pq []byte, err error) {
	if len(data) > maxHybridBytes {
		return nil, nil, fmt.Errorf("%d bytes, over the %d-byte limit for a hybrid object", len(data), maxHybridBytes)
	}
	lines := strings.SplitN(string(bytes.TrimSpace(data)), "\n", 4)
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}

	version, kind, _ := strings.Cut(lines[0], " ")
	if version != hybridVersion {
		return nil, nil, fmt.Errorf("unsupported hybrid format version %q (this build reads %s only)", clip(version), hybridVersion)
	}
	switch kind {
	case kindPublic, kindPrivate, kindSignature:
	default:
		return nil, nil, fmt.Errorf("unknown hybrid object kind %q", clip(kind))
	}
	if kind != wantKind {
		return nil, nil, fmt.Errorf("this is a hybrid %s, not a hybrid %s", kind, wantKind)
	}

	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("truncated: the %s and %s components are missing", labelEd25519, labelMLDSA)
	}
	if ed, err = hybridField(lines[1], labelEd25519, edLen); err != nil {
		return nil, nil, err
	}
	if len(lines) < 3 {
		return nil, nil, fmt.Errorf("truncated: the %s component is missing", labelMLDSA)
	}
	if pq, err = hybridField(lines[2], labelMLDSA, pqLen); err != nil {
		return nil, nil, err
	}
	if len(lines) > 3 {
		return nil, nil, fmt.Errorf("unexpected trailing data after the %s component", labelMLDSA)
	}
	return ed, pq, nil
}

// hybridField reads one "<label>: <hex>" line whose value must decode to
// exactly size bytes.
func hybridField(line, wantLabel string, size int) ([]byte, error) {
	label, value, ok := strings.Cut(line, ": ")
	if !ok {
		return nil, fmt.Errorf("expected a %q line of the form \"<algorithm>: <hex>\"", wantLabel)
	}
	if label != wantLabel {
		if label == labelEd25519 || label == labelMLDSA {
			return nil, fmt.Errorf("found the %s component where %s belongs (each appears once, %s then %s)", label, wantLabel, labelEd25519, labelMLDSA)
		}
		return nil, fmt.Errorf("unknown algorithm tag %q where %s belongs", clip(label), wantLabel)
	}
	if len(value) != 2*size {
		return nil, fmt.Errorf("the %s component is %d hex characters, want exactly %d (%d bytes)", wantLabel, len(value), 2*size, size)
	}
	if !isLowerHex(value) {
		return nil, fmt.Errorf("the %s component is not lowercase hexadecimal", wantLabel)
	}
	raw, err := hex.DecodeString(value)
	if err != nil { // unreachable after isLowerHex and the even length; kept fail-closed
		return nil, fmt.Errorf("the %s component is not hexadecimal", wantLabel)
	}
	return raw, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// clip bounds a file-derived token before it goes into an error message.
func clip(s string) string {
	const max = 40
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

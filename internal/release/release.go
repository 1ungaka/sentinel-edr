// Package release handles signed release artifacts: a SHA256SUMS manifest over
// the released files, a detached signature over it, and the ability for a
// running binary to verify *itself* against that signed manifest.
//
// This is the secure channel for "what is the authoritative hash of this
// build, and does my binary match it": the manifest is fetched over HTTPS (or
// read from a local/air-gapped copy), its signature is verified against a
// pinned key, and only then is the binary's own SHA-256 compared. An attacker
// who can MITM the download still cannot forge the signature, so a tampered
// binary (or a tampered manifest) fails closed. It reuses the same trust
// anchor as `cau update`; the signing key lives off the host in CI (a GitHub
// Actions secret).
//
// # Two kinds of key
//
// A key is either Ed25519-only (the original form) or hybrid: Ed25519 plus
// ML-DSA-65, the FIPS 204 post-quantum signature scheme, from the standard
// library's crypto/mldsa. The package also holds the signing and verifying
// primitives for `cau update` bundles (package updater calls VerifyDetached),
// so both artifact types share one implementation of the rules below.
//
// The trusted public key decides what a signature must carry. Nothing is
// negotiated with the artifact:
//
//   - Ed25519-only key: a valid Ed25519 signature is required. A hybrid
//     signature is accepted on its Ed25519 half (so the holder of an old key
//     can verify a new release); its ML-DSA half must be well formed but is
//     not verified, and the result says so (Checked.PQUnchecked).
//   - Hybrid key: a valid Ed25519 signature AND a valid ML-DSA-65 signature
//     over the same bytes are both required. There is no either-one mode. A
//     signature with no ML-DSA component is refused even when its Ed25519
//     half is valid, because stripping the post-quantum half is the downgrade
//     a hybrid key exists to stop.
//
// The Ed25519 half is plain Ed25519 over the artifact bytes, unchanged from
// the Ed25519-only chain. The ML-DSA half is over the same bytes with a FIPS
// 204 context string fixed per artifact type (Domain): "cau-v1-release-checksums"
// for SHA256SUMS and "cau-v1-update-manifest" for an update bundle's
// manifest.json, so an ML-DSA signature over one never verifies as the other.
// ML-DSA signing is the hedged (randomised) variant.
//
// # On-disk forms
//
// The bare forms mean Ed25519-only, as they always have. Surrounding
// whitespace is ignored and hex may be either case:
//
//	public key    64 hex characters (32 bytes)
//	private key   64 hex characters (the 32-byte seed) or 128 (seed || public)
//	signature     128 hex characters, or the 64 raw bytes
//
// The hybrid forms are a three-line text object, "cau-hybrid-v1":
//
//	cau-hybrid-v1 <kind>
//	ed25519: <hex>
//	ml-dsa-65: <hex>
//
// where <kind> and the two values are
//
//	public-key    ed25519: 64 hex (32 bytes)   ml-dsa-65: 3904 hex (1952 bytes)
//	private-key   ed25519: 64 hex (seed)       ml-dsa-65: 64 hex (32-byte seed)
//	signature     ed25519: 128 hex (64 bytes)  ml-dsa-65: 6618 hex (3309 bytes)
//
// A text form with labelled fields was chosen over a tagged binary blob
// because an operator can tell what a file is, and which algorithms it holds,
// by looking at it; because there is no length arithmetic to get wrong (each
// value's length is fixed by its label and kind); and because the header
// contains letters that are not hex digits, so a hybrid object can never be
// read as a bare-hex one or the reverse.
//
// The writer emits exactly that: one space between the version and the kind
// and one after each colon, lowercase hex, "\n" line ends, a final newline. The reader is
// strict and bounded. It accepts surrounding whitespace and "\r\n" line ends
// and nothing else: the object is at most 16 KiB; anything that starts with
// "cau-hybrid-" must be version "cau-hybrid-v1" (another version is an error,
// never a fallback to bare hex) and of the kind the caller wants (a private
// key offered as a public key is an error); the two fields appear once each,
// in that order; an unknown label is an unknown algorithm and is rejected; a
// value that is not exactly the stated number of lowercase hex characters is
// rejected; a missing line is a truncation and a fourth line is trailing
// data, and both are rejected.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Errors a caller can branch on.
var (
	// ErrBadSignature: the SHA256SUMS signature did not verify against the key.
	ErrBadSignature = errors.New("release: SHA256SUMS signature does not verify")
	// ErrNotListed: the file being verified is not in the manifest.
	ErrNotListed = errors.New("release: file is not listed in SHA256SUMS")
	// ErrMismatch: the file's digest does not match the signed manifest.
	ErrMismatch = errors.New("release: file digest does not match the signed manifest")
	// ErrNoKey: no usable public key was provided.
	ErrNoKey = errors.New("release: no public key configured")
)

// SumsName / SigName are the conventional artifact filenames.
const (
	SumsName = "SHA256SUMS"
	SigName  = "SHA256SUMS.sig"
)

// Checksums maps a release filename to its lowercase-hex SHA-256.
type Checksums struct {
	sums map[string]string
}

// Parse reads a SHA256SUMS file (coreutils style: "<hex>  <name>", one or more
// spaces, an optional "*" binary marker before the name). Blank lines and
// '#' comments are ignored.
func Parse(data []byte) (*Checksums, error) {
	c := &Checksums{sums: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("release: malformed SHA256SUMS line %q", line)
		}
		sum := strings.ToLower(fields[0])
		if !isHex64(sum) {
			return nil, fmt.Errorf("release: not a SHA-256 digest: %q", fields[0])
		}
		name := strings.TrimPrefix(strings.Join(fields[1:], " "), "*")
		c.sums[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("release: read SHA256SUMS: %w", err)
	}
	return c, nil
}

// Format renders checksums as a canonical, sorted SHA256SUMS file.
func Format(sums map[string]string) []byte {
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[n], n)
	}
	return b.Bytes()
}

// Digest returns the recorded digest for a filename, or ok=false.
func (c *Checksums) Digest(name string) (string, bool) {
	d, ok := c.sums[name]
	return d, ok
}

// VerifyFile checks that name is listed and that gotDigest matches it.
func (c *Checksums) VerifyFile(name, gotDigest string) error {
	want, ok := c.sums[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotListed, name)
	}
	if !strings.EqualFold(want, gotDigest) {
		return fmt.Errorf("%w: %s", ErrMismatch, name)
	}
	return nil
}

// VerifySignature verifies a detached Ed25519 signature (raw or hex) over the
// exact SHA256SUMS bytes. It is the Ed25519-only check and reads only the bare
// forms; VerifyChecksums takes either kind of key and either signature form.
func VerifySignature(sumsData, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrNoKey
	}
	raw := normalizeSig(sig)
	if len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, sumsData, raw) {
		return ErrBadSignature
	}
	return nil
}

// Sign produces a detached hex Ed25519 signature over sumsData (producer side,
// used by `cau bundle` in CI). SignChecksums takes either kind of key and
// writes exactly this for an Ed25519-only one.
func Sign(sumsData []byte, priv ed25519.PrivateKey) []byte {
	return []byte(hex.EncodeToString(ed25519.Sign(priv, sumsData)))
}

// SelfDigest returns the SHA-256 (hex) and resolved name of the running
// executable, following symlinks so a symlinked invocation hashes the real
// binary.
func SelfDigest() (digest, name string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("release: locate self: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	d, err := DigestFile(exe)
	if err != nil {
		return "", "", err
	}
	return d, filepath.Base(exe), nil
}

// ParsePublicKey reads a hex Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("release: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release: public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a hex Ed25519 private key (seed or full form).
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("release: decode private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("release: private key is %d bytes, want %d or %d", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// DigestFile returns the SHA-256 hex of a file, read in a bounded stream.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("release: open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("release: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func normalizeSig(data []byte) []byte {
	if len(data) == ed25519.SignatureSize {
		return data
	}
	if raw, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil {
		return raw
	}
	return data
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

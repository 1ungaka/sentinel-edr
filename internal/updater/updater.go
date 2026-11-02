// Package updater applies a signed signature-database bundle, fail-closed.
//
// The engine never phones home on its own: an update is always an explicit
// command (or an opt-in periodic job the operator configures). This package is
// the verify-and-apply core. Trust is anchored in a pinned Ed25519 public key;
// a bundle whose detached signature does not verify against that key, or whose
// payload digest does not match the signed manifest, or whose declared
// min-engine-version is newer than the running engine, is rejected and nothing
// on disk changes. A successful apply replaces the live database atomically and
// leaves a rollback copy.
//
// The bundle is three files produced by the release job:
//
//	hashes.txt         the signature database payload
//	manifest.json      {schema, db_version, min_engine_version, sha256, created}
//	manifest.json.sig  a detached Ed25519 signature over manifest.json's bytes
//
// One signature over the manifest covers everything, because the manifest
// carries the SHA-256 of hashes.txt: verify the manifest, then verify the
// payload against the manifest's digest.
package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ManifestSchema is the manifest format version this updater understands.
const ManifestSchema = 1

// Bundle filenames within an update directory.
const (
	PayloadName   = "hashes.txt"
	ManifestName  = "manifest.json"
	SignatureName = "manifest.json.sig"
)

// Errors a caller can branch on. Every one leaves the live database untouched.
var (
	ErrBadSignature   = errors.New("updater: manifest signature does not verify against the pinned key")
	ErrDigestMismatch = errors.New("updater: payload digest does not match the signed manifest")
	ErrEngineTooOld   = errors.New("updater: bundle requires a newer engine")
	ErrBadManifest    = errors.New("updater: manifest is malformed or an unsupported schema")
	ErrNoKey          = errors.New("updater: no pinned public key configured")
)

// Manifest is the signed metadata for a bundle.
type Manifest struct {
	Schema           int    `json:"schema"`
	DBVersion        string `json:"db_version"`
	MinEngineVersion string `json:"min_engine_version"`
	SHA256           string `json:"sha256"` // lowercase hex of the payload
	Created          string `json:"created,omitempty"`
}

// Bundle is the raw bytes of the three files, however the caller obtained them
// (a local directory or an explicit fetch).
type Bundle struct {
	Payload   []byte
	Manifest  []byte
	Signature []byte
}

// Verified is the result of a successful Verify: the parsed manifest and the
// payload bytes that are safe to install.
type Verified struct {
	Manifest Manifest
	Payload  []byte
}

// Verify checks a bundle fail-closed against pubKey and the running
// engineVersion. It returns the verified payload, or an error and no payload.
// It touches no files.
func Verify(b Bundle, pubKey ed25519.PublicKey, engineVersion string) (Verified, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return Verified{}, ErrNoKey
	}
	if !ed25519.Verify(pubKey, b.Manifest, b.Signature) {
		return Verified{}, ErrBadSignature
	}
	var m Manifest
	if err := json.Unmarshal(b.Manifest, &m); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if m.Schema != ManifestSchema {
		return Verified{}, fmt.Errorf("%w: schema %d (want %d)", ErrBadManifest, m.Schema, ManifestSchema)
	}
	sum := sha256.Sum256(b.Payload)
	if !strings.EqualFold(m.SHA256, hex.EncodeToString(sum[:])) {
		return Verified{}, ErrDigestMismatch
	}
	if !engineAtLeast(engineVersion, m.MinEngineVersion) {
		return Verified{}, fmt.Errorf("%w: needs >= %s, running %s", ErrEngineTooOld, m.MinEngineVersion, engineVersion)
	}
	return Verified{Manifest: m, Payload: b.Payload}, nil
}

// Apply writes the verified payload to dbPath atomically, after copying the
// current database (if any) to dbPath+".bak" as a rollback. It is only ever
// called with the result of a successful Verify.
func Apply(dbPath string, v Verified) (rollback string, err error) {
	if existing, rerr := os.ReadFile(dbPath); rerr == nil {
		rollback = dbPath + ".bak"
		if werr := writeFileAtomic(rollback, existing, 0o644); werr != nil {
			return "", fmt.Errorf("updater: write rollback copy: %w", werr)
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return "", fmt.Errorf("updater: read current database: %w", rerr)
	}
	if err := writeFileAtomic(dbPath, v.Payload, 0o644); err != nil {
		return "", fmt.Errorf("updater: install payload: %w", err)
	}
	return rollback, nil
}

// LoadBundleDir reads the three bundle files from a directory.
func LoadBundleDir(dir string) (Bundle, error) {
	var b Bundle
	var err error
	if b.Payload, err = os.ReadFile(filepath.Join(dir, PayloadName)); err != nil {
		return Bundle{}, fmt.Errorf("updater: read payload: %w", err)
	}
	if b.Manifest, err = os.ReadFile(filepath.Join(dir, ManifestName)); err != nil {
		return Bundle{}, fmt.Errorf("updater: read manifest: %w", err)
	}
	if b.Signature, err = os.ReadFile(filepath.Join(dir, SignatureName)); err != nil {
		return Bundle{}, fmt.Errorf("updater: read signature: %w", err)
	}
	b.Signature = decodeSig(b.Signature)
	return b, nil
}

// ParsePublicKey reads an Ed25519 public key from hex (with surrounding
// whitespace tolerated), the on-disk form the release documents.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("updater: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("updater: public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// NormalizeSignature accepts a detached signature as raw bytes or as hex text
// and returns the raw signature bytes. The CLI uses it when assembling a bundle
// from separately fetched files.
func NormalizeSignature(data []byte) []byte { return decodeSig(data) }

// decodeSig accepts a signature as raw bytes or as hex text, so the release can
// publish whichever is convenient.
func decodeSig(data []byte) []byte {
	if len(data) == ed25519.SignatureSize {
		return data
	}
	if raw, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil && len(raw) == ed25519.SignatureSize {
		return raw
	}
	return data
}

// engineAtLeast reports whether running >= minimum under a lenient dotted
// numeric comparison. A blank minimum means "no floor". A running version the
// updater cannot parse (e.g. a dev string) is treated as satisfying the floor,
// because a local build should not be blocked from installing a release DB; the
// signature is the real gate.
func engineAtLeast(running, minimum string) bool {
	minimum = strings.TrimSpace(minimum)
	if minimum == "" {
		return true
	}
	rp, rok := parseVersion(running)
	mp, _ := parseVersion(minimum)
	if !rok {
		return true
	}
	for i := 0; i < len(mp); i++ {
		var r int
		if i < len(rp) {
			r = rp[i]
		}
		if r != mp[i] {
			return r > mp[i]
		}
	}
	return true
}

// parseVersion extracts the leading dotted-numeric core of a version string
// ("0.4.0-dev" → [0 4 0]). ok is false when there is no numeric core.
func parseVersion(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return out, len(out) > 0
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// BuildManifest produces a manifest for a payload, for the release/signing side
// and for tests. Created is set to now (UTC, RFC 3339).
func BuildManifest(payload []byte, dbVersion, minEngineVersion string) Manifest {
	sum := sha256.Sum256(payload)
	return Manifest{
		Schema:           ManifestSchema,
		DBVersion:        dbVersion,
		MinEngineVersion: minEngineVersion,
		SHA256:           hex.EncodeToString(sum[:]),
		Created:          time.Now().UTC().Format(time.RFC3339),
	}
}

// writeFileAtomic writes via a temp file in the same directory and a rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	// fsync before rename: a signed DB that installs half-written would fail its
	// own next verification, but a durable install is the honest contract.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

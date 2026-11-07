// Package updater applies a signed signature-database bundle, fail-closed.
//
// The engine never phones home on its own: an update is always an explicit
// command (or an opt-in periodic job the operator configures). This package is
// the verify-and-apply core. Trust is anchored in a pinned public key, either
// Ed25519-only or hybrid (Ed25519 + ML-DSA-65; see package release for the
// key and signature forms and for the rule that a hybrid key requires both);
// a bundle whose detached signature does not verify against that key, or whose
// payload digest does not match the signed manifest, or whose declared
// min-engine-version is newer than the running engine, is rejected and nothing
// on disk changes. So is a bundle older than the one installed: a signature proves
// a bundle was released, not that it is current, and a mirror can replay any
// release it has seen. A successful apply replaces the live database atomically,
// leaves a rollback copy, and records what it installed.
//
// The bundle is three files produced by the release job:
//
//	hashes.txt         the signature database payload
//	manifest.json      {schema, db_version, min_engine_version, sha256, created}
//	manifest.json.sig  a detached signature over manifest.json's bytes: Ed25519
//	                   (hex or raw), or the hybrid cau-hybrid-v1 form carrying
//	                   an Ed25519 and an ML-DSA-65 signature over those bytes
//
// One signature file over the manifest covers everything, because the manifest
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

	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/safefs"
)

// ManifestSchema is the manifest format version this updater understands.
const ManifestSchema = 1

// Bundle filenames within an update directory.
const (
	PayloadName   = "hashes.txt"
	ManifestName  = "manifest.json"
	SignatureName = "manifest.json.sig"
)

// StateSuffix names the record of the installed bundle, kept beside the database.
const StateSuffix = ".manifest"

// Errors a caller can branch on. Every one leaves the live database untouched.
var (
	ErrBadSignature   = errors.New("updater: manifest signature does not verify against the pinned key")
	ErrDigestMismatch = errors.New("updater: payload digest does not match the signed manifest")
	ErrEngineTooOld   = errors.New("updater: bundle requires a newer engine")
	ErrBadManifest    = errors.New("updater: manifest is malformed or an unsupported schema")
	ErrNoKey          = errors.New("updater: no pinned public key configured")
	ErrRollback       = errors.New("updater: bundle is older than the installed database")
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
//
// This is the original Ed25519-only check, kept as it was: b.Signature must be
// the 64 raw signature bytes (what LoadBundleDir and NormalizeSignature leave
// for an Ed25519 signature file), and a hybrid signature is refused.
// VerifyWithKey is the general form: either kind of key, either signature form.
func Verify(b Bundle, pubKey ed25519.PublicKey, engineVersion string) (Verified, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return Verified{}, ErrNoKey
	}
	if !ed25519.Verify(pubKey, b.Manifest, b.Signature) {
		return Verified{}, ErrBadSignature
	}
	return checkManifest(b, engineVersion)
}

// VerifyWithKey is Verify for a trusted key that may be hybrid. The signature
// rules are release.VerifyDetached's, with the update-manifest domain: an
// Ed25519-only key needs a valid Ed25519 signature (and accepts a hybrid
// signature on its Ed25519 half, reporting the ML-DSA half as present and
// unchecked); a hybrid key needs a valid Ed25519 signature AND a valid
// ML-DSA-65 signature, and refuses a bundle whose signature is Ed25519-only.
// b.Signature may be the raw Ed25519 bytes, hex, or the hybrid text form.
//
// Everything after the signature is the same as Verify: schema, payload
// digest, minimum engine version. The rollback check is Apply's and
// CheckRollback's, unchanged, and is applied to what this returns exactly as
// it is to what Verify returns. It touches no files.
func VerifyWithKey(b Bundle, key release.VerifyKey, engineVersion string) (Verified, release.Checked, error) {
	checked, err := release.VerifyDetached(b.Manifest, b.Signature, key, release.DomainUpdateManifest)
	if err != nil {
		if errors.Is(err, release.ErrNoKey) {
			return Verified{}, release.Checked{}, ErrNoKey
		}
		var ve *release.VerifyError
		if errors.As(err, &ve) {
			return Verified{}, release.Checked{}, fmt.Errorf("%w: %s", ErrBadSignature, ve.Reason)
		}
		return Verified{}, release.Checked{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	v, err := checkManifest(b, engineVersion)
	if err != nil {
		return Verified{}, release.Checked{}, err
	}
	return v, checked, nil
}

// checkManifest is everything Verify checks once the signature over b.Manifest
// has been verified. It is only called after that.
func checkManifest(b Bundle, engineVersion string) (Verified, error) {
	var m Manifest
	if err := json.Unmarshal(b.Manifest, &m); err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrBadManifest, err)
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

// CheckRollback returns ErrRollback when m is older than the bundle recorded as
// installed at dbPath. With no record there is nothing to compare, so the first
// install takes what it is given. Re-installing the same bundle is fine. A bundle
// with no date cannot replace a dated one, or dropping the field would be the way
// around this. A record that cannot be read fails closed.
func CheckRollback(dbPath string, m Manifest) error {
	raw, err := os.ReadFile(dbPath + StateSuffix)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("updater: read install record: %w", err)
	}
	var cur Manifest
	if err := json.Unmarshal(raw, &cur); err != nil {
		return fmt.Errorf("updater: install record %s%s is corrupt: %w", dbPath, StateSuffix, err)
	}
	if strings.EqualFold(cur.SHA256, m.SHA256) {
		return nil
	}
	installed, err := time.Parse(time.RFC3339, cur.Created)
	if err != nil {
		return nil // the installed bundle carries no date to hold a floor at
	}
	if created, err := time.Parse(time.RFC3339, m.Created); err != nil || created.Before(installed) {
		return fmt.Errorf("%w: installed db_version %s (%s), bundle db_version %s (%s)",
			ErrRollback, cur.DBVersion, cur.Created, m.DBVersion, m.Created)
	}
	return nil
}

// Apply writes the verified payload to dbPath atomically, after copying the
// current database (if any) to dbPath+".bak" as a rollback, and records the
// manifest beside it. It refuses a rollback unless allowDowngrade is set, which
// is for an operator backing out a bad release. It is only ever called with the
// result of a successful Verify.
func Apply(dbPath string, v Verified, allowDowngrade bool) (rollback string, err error) {
	if !allowDowngrade {
		if err := CheckRollback(dbPath, v.Manifest); err != nil {
			return "", err
		}
	}
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
	state, err := json.MarshalIndent(v.Manifest, "", "  ")
	if err != nil {
		return rollback, fmt.Errorf("updater: encode install record: %w", err)
	}
	if err := writeFileAtomic(dbPath+StateSuffix, state, 0o644); err != nil {
		return rollback, fmt.Errorf("updater: installed, but could not record it, so the rollback check is out of date: %w", err)
	}
	return rollback, nil
}

// Bundle size limits. --from is the air-gap path, so these files can be whatever
// was on the media, and they are read before anything about them is verified.
// The payload limit matches what `cau update --url` accepts.
const (
	maxPayloadBytes  = 256 << 20
	maxManifestBytes = 1 << 20
)

// LoadBundleDir reads the three bundle files from a directory.
func LoadBundleDir(dir string) (Bundle, error) {
	var b Bundle
	var err error
	if b.Payload, err = safefs.ReadFile(filepath.Join(dir, PayloadName), maxPayloadBytes); err != nil {
		return Bundle{}, fmt.Errorf("updater: read payload: %w", err)
	}
	if b.Manifest, err = safefs.ReadFile(filepath.Join(dir, ManifestName), maxManifestBytes); err != nil {
		return Bundle{}, fmt.Errorf("updater: read manifest: %w", err)
	}
	if b.Signature, err = safefs.ReadFile(filepath.Join(dir, SignatureName), maxManifestBytes); err != nil {
		return Bundle{}, fmt.Errorf("updater: read signature: %w", err)
	}
	b.Signature = decodeSig(b.Signature)
	return b, nil
}

// ParsePublicKey reads an Ed25519 public key from hex (with surrounding
// whitespace tolerated), the on-disk form the release documents. It reads the
// Ed25519-only form; release.ParseVerifyKey reads that and the hybrid form.
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
// from separately fetched files. Anything that is not a 64-byte Ed25519
// signature in one of those two forms, a hybrid signature included, is
// returned unchanged for VerifyWithKey to parse (or for Verify to refuse).
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

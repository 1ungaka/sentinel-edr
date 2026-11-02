// Package selftest verifies the integrity of the engine's detection content so
// tampering is caught rather than silently disabling the scanner. Gutting the
// signature database or neutering a YARA rule is the classic "impair defenses"
// move (ATT&CK T1562.001); this package records a baseline digest of each
// resource and detects any later drift.
//
// Two strengths:
//
//   - A plain digest baseline catches accidental corruption and tampering by a
//     process that cannot also rewrite the manifest.
//   - An Ed25519-signed manifest, verified against a pinned/operator-supplied
//     public key, catches an attacker who rewrites both the content and the
//     manifest — the only thing they cannot forge is the signature. This is the
//     tamper-resistant mode; the signing key lives off the host.
//
// A directory resource (the YARA rules) is reduced to one canonical digest over
// its regular files in sorted order, so adding, removing, or editing any rule
// file changes the digest.
package selftest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestSchema guards the on-disk format.
const ManifestSchema = 1

// Errors a caller can branch on.
var (
	// ErrDrift is returned by Verify when one or more resources changed.
	ErrDrift = errors.New("selftest: detection content has drifted from the baseline")
	// ErrBadSignature is returned when a signed manifest fails verification.
	ErrBadSignature = errors.New("selftest: manifest signature does not verify")
	// ErrUnsigned is returned when a signature was required but the manifest has none.
	ErrUnsigned = errors.New("selftest: manifest is not signed")
)

// Resource is one thing to baseline: a file or a directory.
type Resource struct {
	Name string // stable label, e.g. "signatures", "rules", "fuzzy"
	Path string // filesystem path (file or dir)
}

// Entry is one resource's recorded digest.
type Entry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	IsDir  bool   `json:"is_dir,omitempty"`
	Files  int    `json:"files,omitempty"` // for a directory: regular files counted
}

// Manifest is the recorded baseline.
type Manifest struct {
	Schema    int     `json:"schema"`
	CreatedAt string  `json:"created_at,omitempty"`
	Entries   []Entry `json:"entries"`
	// Signature is the hex Ed25519 signature over SigningBytes(), or "" when the
	// manifest is unsigned.
	Signature string `json:"signature,omitempty"`
}

// Compute digests every resource and returns a manifest (unsigned). A resource
// whose path is empty is skipped (an optional resource that is not deployed).
func Compute(resources []Resource) (Manifest, error) {
	m := Manifest{Schema: ManifestSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, r := range resources {
		if r.Path == "" {
			continue
		}
		info, err := os.Stat(r.Path)
		if err != nil {
			return Manifest{}, fmt.Errorf("selftest: stat %s: %w", r.Path, err)
		}
		e := Entry{Name: r.Name, Path: r.Path, IsDir: info.IsDir()}
		if info.IsDir() {
			digest, n, derr := digestTree(r.Path)
			if derr != nil {
				return Manifest{}, derr
			}
			e.SHA256 = digest
			e.Files = n
		} else {
			digest, derr := digestFile(r.Path)
			if derr != nil {
				return Manifest{}, derr
			}
			e.SHA256 = digest
		}
		m.Entries = append(m.Entries, e)
	}
	sort.SliceStable(m.Entries, func(i, j int) bool { return m.Entries[i].Name < m.Entries[j].Name })
	return m, nil
}

// digestFile returns the SHA-256 hex of a file.
func digestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("selftest: read %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// digestTree reduces a directory to one canonical digest over its regular files
// in sorted relative-path order, binding each file's path and content, so any
// add / remove / edit / rename changes the result. Returns the digest and the
// count of regular files.
func digestTree(root string) (string, int, error) {
	type fileDigest struct{ rel, sum string }
	var files []fileDigest
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		files = append(files, fileDigest{rel: filepath.ToSlash(rel), sum: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return "", 0, fmt.Errorf("selftest: walk %s: %w", root, err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%s\n", f.rel, f.sum)
	}
	return hex.EncodeToString(h.Sum(nil)), len(files), nil
}

// SigningBytes is the canonical, signature-free serialization the Ed25519
// signature covers: the schema and every entry's name|sha256|isdir, sorted.
// It deliberately excludes CreatedAt and the Signature field so re-recording the
// timestamp does not invalidate a signature and the signature cannot cover
// itself.
func (m Manifest) SigningBytes() []byte {
	entries := append([]Entry(nil), m.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "cau-selftest/v%d\n", m.Schema)
	for _, e := range entries {
		fmt.Fprintf(&b, "%s|%s|%t\n", e.Name, e.SHA256, e.IsDir)
	}
	return []byte(b.String())
}

// Sign attaches an Ed25519 signature over SigningBytes().
func (m *Manifest) Sign(priv ed25519.PrivateKey) {
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, m.SigningBytes()))
}

// VerifySignature checks the manifest's signature against pub. It returns
// ErrUnsigned when there is no signature, ErrBadSignature when it does not
// verify, and nil when it does.
func (m Manifest) VerifySignature(pub ed25519.PublicKey) error {
	if m.Signature == "" {
		return ErrUnsigned
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return ErrBadSignature
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, m.SigningBytes(), sig) {
		return ErrBadSignature
	}
	return nil
}

// Drift is one resource that no longer matches the baseline.
type Drift struct {
	Name   string
	Reason string // "modified", "missing from baseline", "missing on disk"
}

// Verify recomputes digests for the baseline's resources and returns the drift.
// A nil slice means every resource matches. Resources are matched by name.
func Verify(baseline Manifest) ([]Drift, error) {
	var drift []Drift
	for _, want := range baseline.Entries {
		info, err := os.Stat(want.Path)
		if errors.Is(err, os.ErrNotExist) {
			drift = append(drift, Drift{Name: want.Name, Reason: "resource missing on disk: " + want.Path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("selftest: stat %s: %w", want.Path, err)
		}
		var got string
		if info.IsDir() {
			got, _, err = digestTree(want.Path)
		} else {
			got, err = digestFile(want.Path)
		}
		if err != nil {
			return nil, err
		}
		if got != want.SHA256 {
			drift = append(drift, Drift{Name: want.Name, Reason: "content changed since the baseline"})
		}
	}
	return drift, nil
}

// WriteManifest persists a manifest as indented JSON (0644 — it is public
// integrity metadata, not a secret).
func WriteManifest(path string, m Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("selftest: encode manifest: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("selftest: create manifest dir: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("selftest: write manifest: %w", err)
	}
	return nil
}

// ReadManifest loads a manifest.
func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("selftest: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("selftest: parse manifest: %w", err)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("selftest: manifest schema %d is not supported (want %d)", m.Schema, ManifestSchema)
	}
	return m, nil
}

// ParsePublicKey reads a hex Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("selftest: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("selftest: public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a hex Ed25519 private key (seed or full).
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("selftest: decode private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("selftest: private key is %d bytes, want %d or %d", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
}

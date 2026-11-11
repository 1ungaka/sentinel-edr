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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// ManifestSchema guards the on-disk format.
// ManifestSchema 2 added Pins. A manifest read from disk keeps the schema it
// was written with, and SigningBytes emits pins only when there are any, so a
// signature made over a v1 manifest still verifies byte for byte.
// ManifestSchema 3 also signs each entry's Path, which v2 left out: an editor
// without the key could redirect an entry to a clean copy of a resource while
// keeping the signature valid. SigningBytes emits the path only from v3 on, so
// a v2 signature still verifies byte for byte — and a v2 manifest keeps its
// documented weakness, which is why ReadManifest accepts it only as legacy.
//
// Adding a resource to record (the canary manifest, say) needs no new schema:
// entries are signed as data, so a baseline recorded before that resource
// existed simply does not cover it, and a build that predates it verifies the
// entries it knows and ignores the rest.
const ManifestSchema = 3

// ManifestSchemaLegacy is the oldest schema still readable. Its signatures do
// not cover the resource paths, so a caller that needs a path to be
// authenticated has to re-record the baseline with the current schema (or
// refuse the manifest); Verify still checks the digest at the recorded path.
const ManifestSchemaLegacy = 2

// Pin names. A pin is signed configuration that is not a file digest.
const (
	// PinSIEM is the address incidents are forwarded to. It is pinned because
	// the file that configures it is the one an attacker would rewrite to do
	// two things at once: stop the real SIEM hearing about the intrusion, and
	// have the agent deliver its findings to them instead. With the address
	// signed, editing the config on disk can no longer redirect the stream.
	PinSIEM = "siem"
	// PinSIEMCert is the manager's public-key pin. Signing it matters for
	// the same reason as the address: an attacker who could edit it on disk
	// would simply replace it with the pin of their own collector.
	PinSIEMCert = "siem-cert"
)

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
	// Pins are signed values that are not file digests: settings an attacker
	// could change on disk to redirect or silence the agent without touching
	// any detection content. A pin says what the value was when the baseline
	// was recorded, so a caller can both detect the edit and keep working from
	// the authentic value instead of the one now on disk.
	Pins map[string]string `json:"pins,omitempty"`
	// Signature is the hex Ed25519 signature over SigningBytes(), or "" when the
	// manifest is unsigned.
	Signature string `json:"signature,omitempty"`
}

// Pin returns a pinned value and whether it was recorded.
func (m Manifest) Pin(name string) (string, bool) {
	v, ok := m.Pins[name]
	return v, ok
}

// Lookup returns the baseline entry for a resource name.
func (m Manifest) Lookup(name string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Digest computes a resource's digest the same way Compute does, so a caller
// can check one resource without re-reading every other one. A directory is
// reduced to a single canonical digest over its contents.
func Digest(path string) (sum string, isDir bool, files int, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false, 0, err
	}
	if info.IsDir() {
		sum, files, err = digestTree(path)
		return sum, true, files, err
	}
	sum, err = digestFile(path)
	return sum, false, 1, err
}

// VerifyOne checks a single named resource against the baseline. It reports the
// drift, if any, and whether the baseline covers that name at all — a resource
// the baseline never recorded cannot be said to have drifted, and the caller
// decides whether that absence is itself a problem.
func VerifyOne(baseline Manifest, name string) (drift Drift, covered bool, err error) {
	want, ok := baseline.Lookup(name)
	if !ok {
		return Drift{}, false, nil
	}
	got, _, _, err := Digest(want.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Drift{Name: name, Reason: "resource missing on disk: " + want.Path}, true, nil
	}
	if err != nil {
		return Drift{}, true, err
	}
	if got != want.SHA256 {
		return Drift{Name: name, Reason: "content changed since the baseline"}, true, nil
	}
	return Drift{}, true, nil
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
//
// It reads through safefs because this runs before the daemon does, as
// ExecStartPre, and a FIFO planted at a baselined path would otherwise hold that
// step until systemd gave up on the unit. A timeout is not an exit code, so the
// "-" that forgives a failed selftest does not forgive it.
func digestFile(path string) (string, error) {
	f, _, err := safefs.Open(path)
	if err != nil {
		return "", fmt.Errorf("selftest: read %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("selftest: read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// digestTree reduces a directory to one canonical digest over its regular files
// in sorted relative-path order, binding each file's path and content, so any
// add / remove / edit / rename changes the result. A symlink is bound by its
// target: the rule loader follows one, so skipping it would let a link to an
// attacker's rule file through unnoticed. Returns the digest and the count of
// entries bound.
func digestTree(root string) (string, int, error) {
	type fileDigest struct{ rel, sum string }
	var files []fileDigest
	err := filepath.WalkDir(safefs.WalkRoot(root), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return rerr
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			sum := sha256.Sum256([]byte("symlink\x00" + target))
			files = append(files, fileDigest{rel: filepath.ToSlash(rel), sum: hex.EncodeToString(sum[:])})
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		sum, rerr := digestFile(p)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		files = append(files, fileDigest{rel: filepath.ToSlash(rel), sum: sum})
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
// signature covers: the schema and every entry's name|path|sha256|isdir, sorted.
// It deliberately excludes CreatedAt and the Signature field so re-recording the
// timestamp does not invalidate a signature and the signature cannot cover
// itself.
//
// The path has been signed since schema 3. Leaving it out meant a manifest
// editor without the signing key could point an entry at a clean copy of a
// resource — the digest still matched, the signature still verified, and the
// active resource drifted unnoticed. A schema-2 manifest is serialized without
// the path so an existing signature keeps verifying byte for byte; that is the
// documented legacy mode, not a choice to keep making.
func (m Manifest) SigningBytes() []byte {
	entries := append([]Entry(nil), m.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "cau-selftest/v%d\n", m.Schema)
	for _, e := range entries {
		if m.Schema >= ManifestSchema {
			fmt.Fprintf(&b, "%s|%s|%s|%t\n", e.Name, e.Path, e.SHA256, e.IsDir)
			continue
		}
		fmt.Fprintf(&b, "%s|%s|%t\n", e.Name, e.SHA256, e.IsDir)
	}
	// Pins are emitted only when present, so the bytes signed for a manifest
	// without any are exactly what they were before pins existed and an older
	// signature still verifies.
	if len(m.Pins) > 0 {
		names := make([]string, 0, len(m.Pins))
		for k := range m.Pins {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(&b, "pin|%s|%s\n", k, m.Pins[k])
		}
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
//
// It verifies the paths the manifest recorded: for a caller that has overrides
// of its own (an operator who moved a resource, and says where to), use
// VerifyWithOverrides.
func Verify(baseline Manifest) ([]Drift, error) { return VerifyWithOverrides(baseline, nil) }

// VerifyWithOverrides is Verify with per-resource path overrides, keyed by the
// resource's name (its role in the baseline). An override replaces the recorded
// path for that resource only, so a resource an operator moved is verified where
// it now lives instead of being reported missing where it used to.
//
// An override that names no entry in the baseline is an error rather than a
// silent skip: the caller asked for a resource the baseline does not cover, and
// checking something else in its place would report a result about a file the
// signature says nothing about. A resource absent on disk (empty path) is fine —
// the baseline's own path is used, or the entry is reported as usual.
func VerifyWithOverrides(baseline Manifest, overrides map[string]string) ([]Drift, error) {
	for name, path := range overrides {
		if path == "" {
			continue // not given, so nothing to override
		}
		if _, ok := baseline.Lookup(name); !ok {
			return nil, fmt.Errorf("selftest: no baseline entry named %q to override; re-record the baseline to cover it", name)
		}
	}
	var drift []Drift
	for _, want := range baseline.Entries {
		path := want.Path
		if p, ok := overrides[want.Name]; ok && p != "" {
			path = p
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			drift = append(drift, Drift{Name: want.Name, Reason: "resource missing on disk: " + path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("selftest: stat %s: %w", path, err)
		}
		var got string
		if info.IsDir() {
			got, _, err = digestTree(path)
		} else {
			got, err = digestFile(path)
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

// maxManifestBytes bounds a manifest. It holds a few digests and pins; a tree of
// rules is one entry however many files are in it.
const maxManifestBytes = 16 << 20

// ReadManifest loads a manifest.
//
// A schema-2 manifest is accepted for backward compatibility and verified as
// the legacy mode it is: its signature does not cover the resource paths, so a
// caller that needs the path authenticated must re-record with this build (or
// refuse the manifest) rather than trusting what it reads.
func ReadManifest(path string) (Manifest, error) {
	data, err := safefs.ReadFile(path, maxManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("selftest: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("selftest: parse manifest: %w", err)
	}
	if m.Schema != ManifestSchema && m.Schema != ManifestSchemaLegacy {
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

// Package canary plants decoy files and later reports which of them were
// touched. It is the OSS engine's cheap ground truth: a canary that changed,
// moved, or vanished is a high-signal, near-zero-false-positive event, because
// nothing legitimate has any reason to open a decoy the operator planted and
// never advertised.
//
// The engine itself does not watch files at runtime — that is the sensor's job
// in the proprietary console. What the engine provides, and what this package
// is, are the two halves a watcher needs: a generator that writes plausible
// decoys and records their baseline, and a checker that diffs the live files
// against that baseline. A cron job, a pre/post-task hook, or the behavior
// engine can call Check and act on a tripped canary; the primitive stays
// honest about being a point-in-time comparison, not a live monitor.
//
// Baselines are recorded by content digest, size, mode, and modification time,
// so Check distinguishes a rewrite (ransomware's signature) from a pure
// permission or timestamp change, and reports a deletion separately from both.
//
// A baseline that records no canary at all is refused rather than accepted: the
// manifest lives beside what it describes, so one that validates but says
// nothing is planted is how a set is silenced without any alert. See
// ReadManifest.
package canary

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/parallel"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// manifestVersion guards the on-disk format against silent misparsing.
const manifestVersion = 1

// decoyNames are the lure filenames a planted set draws from, in order. They
// are deliberately the things an intruder or ransomware worker opens first:
// credentials, finance, keys, backups. The content is random filler of a
// plausible size; the value is entirely in the baseline, never in the bytes.
var decoyNames = []string{
	"passwords.xlsx",
	"backup_codes.txt",
	"id_rsa",
	"Q4_Financials.xlsx",
	"customer_export.csv",
	"vpn_config.ovpn",
	"wallet.dat",
	"domain_admins.csv",
	"aws_credentials.csv",
	"payroll_2025.xlsx",
}

// Canary is one planted decoy's baseline record.
type Canary struct {
	// Path is the absolute path of the planted file.
	Path string `json:"path"`
	// Size is the baseline size in bytes.
	Size int64 `json:"size"`
	// Mode is the baseline permission bits.
	Mode os.FileMode `json:"mode"`
	// SHA256 is the lowercase-hex digest of the baseline content.
	SHA256 string `json:"sha256"`
	// ModTime is the baseline modification time (UTC).
	ModTime time.Time `json:"mod_time"`
}

// Manifest is the baseline for a planted set, persisted as JSON.
type Manifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Canaries  []Canary  `json:"canaries"`
}

// Status classifies a canary at check time.
type Status string

const (
	// StatusIntact: content, size, mode and modification time all match the
	// baseline.
	StatusIntact Status = "intact"
	// StatusModified: the content digest changed — the file was rewritten.
	// This is the ransomware/exfil-staging signal.
	StatusModified Status = "modified"
	// StatusDeleted: the file is gone.
	StatusDeleted Status = "deleted"
	// StatusMetaChanged: content is identical but mode changed. Lower signal
	// than a rewrite, reported separately so it is never conflated with one.
	StatusMetaChanged Status = "meta-changed"
	// StatusTimestampChanged: content and mode are identical but the
	// modification time moved. A decoy nobody legitimately opens has no reason
	// to be restamped, so touching it is its own signal — and one that a
	// digest-only check reports as intact.
	StatusTimestampChanged Status = "timestamp-changed"
	// StatusError: the file could not be read to judge it.
	StatusError Status = "error"
)

// Result pairs a canary with the verdict Check reached for it.
type Result struct {
	Canary Canary
	Status Status
	// Detail is a human-readable note for non-intact statuses ("" when intact).
	Detail string
}

// Tripped reports whether the status is anything other than intact.
func (r Result) Tripped() bool { return r.Status != StatusIntact }

// Plant writes count decoy files into dir and returns their baseline manifest.
// dir is created if missing. Files are written 0600 (a planted secret an
// attacker reads is still just filler, but world-readability would be an odd
// smell on a real secret). count is clamped to the number of distinct decoy
// names available. Plant refuses to overwrite an existing file, so a second
// Plant into the same directory does not silently clobber a live set.
func Plant(dir string, count int) (*Manifest, error) {
	if count <= 0 {
		return nil, errors.New("canary: count must be positive")
	}
	if count > len(decoyNames) {
		count = len(decoyNames)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("canary: create dir: %w", err)
	}
	m := &Manifest{Version: manifestVersion, CreatedAt: time.Now().UTC()}
	for i := 0; i < count; i++ {
		name := decoyNames[i]
		path, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("canary: resolve path: %w", err)
		}
		content, err := filler(name)
		if err != nil {
			return nil, err
		}
		if err := writeNew(path, content); errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("canary: %s already exists; refusing to overwrite", path)
		} else if err != nil {
			return nil, fmt.Errorf("canary: write %s: %w", path, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("canary: stat planted %s: %w", path, err)
		}
		sum := sha256.Sum256(content)
		m.Canaries = append(m.Canaries, Canary{
			Path:    path,
			Size:    info.Size(),
			Mode:    info.Mode().Perm(),
			SHA256:  hex.EncodeToString(sum[:]),
			ModTime: info.ModTime().UTC(),
		})
	}
	return m, nil
}

// writeNew creates path, failing if anything is there. O_EXCL makes that atomic
// and refuses a symlink too: decoys go where an attacker can reach, and a link
// planted first would have this write through it.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Check compares each canary in the manifest against the file on disk now and
// returns one Result per canary, in manifest order. It reads file content to
// judge modification, so it is a point-in-time check, not a live watch.
func Check(m *Manifest) []Result {
	out := make([]Result, len(m.Canaries))
	parallel.For(len(m.Canaries), 0, func(i int) { out[i] = checkOne(m.Canaries[i]) })
	return out
}

// Tripped filters a Check result down to the canaries that are not intact.
func Tripped(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if r.Tripped() {
			out = append(out, r)
		}
	}
	return out
}

// maxDecoyRead bounds the read of a decoy: an attacker may have replaced it with
// anything, and anything this big is not the decoy.
const maxDecoyRead = 64 << 20

func checkOne(c Canary) Result {
	data, info, err := safefs.ReadFileNoFollow(c.Path, maxDecoyRead)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Result{Canary: c, Status: StatusDeleted, Detail: "file no longer exists"}
	case errors.Is(err, safefs.ErrNotRegular):
		return Result{Canary: c, Status: StatusModified, Detail: "replaced by a non-regular file"}
	case errors.Is(err, safefs.ErrTooLarge):
		return Result{Canary: c, Status: StatusModified, Detail: fmt.Sprintf("content changed (%d bytes, now over %d)", c.Size, maxDecoyRead)}
	case err != nil:
		return Result{Canary: c, Status: StatusError, Detail: err.Error()}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != c.SHA256 {
		return Result{Canary: c, Status: StatusModified, Detail: fmt.Sprintf("content changed (%d → %d bytes)", c.Size, len(data))}
	}
	if info.Mode().Perm() != c.Mode {
		return Result{Canary: c, Status: StatusMetaChanged, Detail: fmt.Sprintf("mode changed (%o → %o)", c.Mode, info.Mode().Perm())}
	}
	// A timestamp-only change leaves digest and mode alone, so without this
	// comparison the package's own documentation ("and modification time")
	// would be a promise Check did not keep.
	if !info.ModTime().UTC().Equal(c.ModTime.UTC()) {
		return Result{Canary: c, Status: StatusTimestampChanged,
			Detail: fmt.Sprintf("modification time changed (%s → %s)", c.ModTime.UTC().Format(time.RFC3339Nano), info.ModTime().UTC().Format(time.RFC3339Nano))}
	}
	return Result{Canary: c, Status: StatusIntact}
}

// WriteManifest persists a manifest to path as indented JSON (0600).
//
// The manifest sits next to what it describes and is written by a privileged
// `cau canary plant`, so a write that follows a symlink would let whoever
// planted the link truncate their own target instead. The destination is
// therefore lstat'd first — a symlink is refused rather than followed — and the
// content is written to a temporary file beside it and renamed over the path,
// which never follows a link and replaces the manifest whole or not at all. The
// mode argument of a plain write only applies when the file is created, so an
// existing manifest keeps whatever permissions it already had; the 0600
// contract is enforced by chmod on the file that is renamed into place.
func WriteManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("canary: encode manifest: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("canary: create manifest dir: %w", err)
		}
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("canary: refusing to write the manifest through a symlink: %s", path)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("canary: manifest path %s is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("canary: stat manifest: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".canary-manifest-*")
	if err != nil {
		return fmt.Errorf("canary: create manifest: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op once the rename has succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("canary: write manifest: %w", err)
	}
	// An existing manifest may be broader than 0600: the rename would otherwise
	// carry the temporary file's umask-narrowed mode over a file that was fine
	// with 0644, and this function's contract is 0600 either way.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("canary: set manifest mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("canary: write manifest: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("canary: write manifest: %w", err)
	}
	return nil
}

// maxManifestBytes bounds a manifest. A host has a handful of canaries.
const maxManifestBytes = 16 << 20

// ReadManifest loads a manifest written by WriteManifest.
//
// A version-1 manifest with an empty canaries list parses cleanly and, accepted,
// would leave nothing that can trip: the same UID that owns the decoys owns this
// file, so replacing it with an empty one silences every canary on the host with
// no alert anywhere. Plant always records at least one canary, so a baseline
// that records none is not a state a recording ever produced and is refused
// rather than trusted.
//
// The same reasoning covers the baseline's identity. Plant always stamps a
// manifest with the moment it was taken, an absolute path and a content digest
// per canary, a non-negative size, and each path exactly once. A baseline
// missing any of that is an edit rather than the recording it is standing in
// for, and accepting one lets the same UID rewrite the baseline — dropping an
// entry, pointing one elsewhere — while every caller keeps treating it as the
// manifest that was planted. ReadManifest therefore refuses a manifest it can
// tell was not recorded by Plant.
//
// What that can prove is bounded by the format: these checks are all internal
// to the file, so a fully rewritten baseline with fabricated digests still
// passes. Cryptographic authentication of a baseline is what the selftest
// manifest's Ed25519 signature is for; a caller who needs that guarantee for
// canaries should hold the manifest's signing under the same scheme.
func ReadManifest(path string) (*Manifest, error) {
	data, err := safefs.ReadFile(path, maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("canary: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("canary: parse manifest: %w", err)
	}
	if m.Version != manifestVersion {
		return nil, fmt.Errorf("canary: manifest version %d is not supported (want %d)", m.Version, manifestVersion)
	}
	if len(m.Canaries) == 0 {
		return nil, errors.New("canary: manifest baselines no canary, so nothing on this host can trip; refusing to trust it as a clean baseline")
	}
	if err := validateBaseline(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// validateBaseline rejects a manifest no Plant could have written. Each entry
// must carry an absolute path and the digest of the content planted there, a
// non-negative size, and no path may be recorded twice — Plant writes each
// decoy once into a set of distinct names, so a repeat is a splice. The
// manifest must also say when it was taken. Together these are the identity of
// the recorded baseline: not proof against a from-scratch forgery, which needs
// a signature, but enough that a gutted, truncated or hand-patched manifest
// never passes for the one that was planted.
func validateBaseline(m *Manifest) error {
	if m.CreatedAt.IsZero() {
		return errors.New("canary: manifest records no time it was taken, so it is not the baseline Plant wrote; refusing to trust it")
	}
	seen := make(map[string]struct{}, len(m.Canaries))
	for i, c := range m.Canaries {
		if !filepath.IsAbs(c.Path) {
			return fmt.Errorf("canary: canary %d records %q, which is not an absolute path; a planted decoy always has one", i, c.Path)
		}
		if c.SHA256 == "" {
			return fmt.Errorf("canary: canary %d (%s) records no digest, so it could never match anything", i, c.Path)
		}
		if _, err := hex.DecodeString(c.SHA256); err != nil {
			return fmt.Errorf("canary: canary %d (%s) records %q, which is not a hex digest", i, c.Path, c.SHA256)
		}
		if c.Size < 0 {
			return fmt.Errorf("canary: canary %d (%s) records a negative size %d", i, c.Path, c.Size)
		}
		if _, dup := seen[c.Path]; dup {
			return fmt.Errorf("canary: %s is recorded more than once; a baseline Plant wrote lists each decoy once", c.Path)
		}
		seen[c.Path] = struct{}{}
	}
	return nil
}

// filler produces deterministic-length but random-content bytes for a decoy.
// The size is name-dependent so a directory listing looks like a real mix of
// documents, not a row of identical files. Content is cryptographically random
// so two plants never collide and a digest match on check is meaningful.
func filler(name string) ([]byte, error) {
	// A small per-name size table keeps listings plausible without pretending
	// to generate valid file formats (which would be payload work, not decoy
	// work). Sizes are in bytes.
	sizes := map[string]int{
		"id_rsa":           2602,
		"backup_codes.txt": 512,
		"vpn_config.ovpn":  3400,
		"wallet.dat":       16384,
	}
	size := sizes[name]
	if size == 0 {
		// Spreadsheets/CSVs: a few KiB, varied per name via its length so the
		// set is not uniform.
		size = 4096 + len(name)*97
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("canary: generate filler: %w", err)
	}
	return b, nil
}

// SortByPath returns the results sorted by path, for stable reporting.
func SortByPath(results []Result) []Result {
	out := append([]Result(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Canary.Path < out[j].Canary.Path
	})
	return out
}

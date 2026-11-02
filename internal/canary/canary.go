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
	// StatusIntact: content, size, and mode all match the baseline.
	StatusIntact Status = "intact"
	// StatusModified: the content digest changed — the file was rewritten.
	// This is the ransomware/exfil-staging signal.
	StatusModified Status = "modified"
	// StatusDeleted: the file is gone.
	StatusDeleted Status = "deleted"
	// StatusMetaChanged: content is identical but mode changed. Lower signal
	// than a rewrite, reported separately so it is never conflated with one.
	StatusMetaChanged Status = "meta-changed"
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
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("canary: %s already exists; refusing to overwrite", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("canary: stat %s: %w", path, err)
		}
		content, err := filler(name)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
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

// Check compares each canary in the manifest against the file on disk now and
// returns one Result per canary, in manifest order. It reads file content to
// judge modification, so it is a point-in-time check, not a live watch.
func Check(m *Manifest) []Result {
	out := make([]Result, 0, len(m.Canaries))
	for _, c := range m.Canaries {
		out = append(out, checkOne(c))
	}
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

func checkOne(c Canary) Result {
	info, err := os.Lstat(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Canary: c, Status: StatusDeleted, Detail: "file no longer exists"}
	}
	if err != nil {
		return Result{Canary: c, Status: StatusError, Detail: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return Result{Canary: c, Status: StatusModified, Detail: "replaced by a non-regular file"}
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		return Result{Canary: c, Status: StatusError, Detail: err.Error()}
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != c.SHA256 {
		return Result{Canary: c, Status: StatusModified, Detail: fmt.Sprintf("content changed (%d → %d bytes)", c.Size, len(data))}
	}
	if info.Mode().Perm() != c.Mode {
		return Result{Canary: c, Status: StatusMetaChanged, Detail: fmt.Sprintf("mode changed (%o → %o)", c.Mode, info.Mode().Perm())}
	}
	return Result{Canary: c, Status: StatusIntact}
}

// WriteManifest persists a manifest to path as indented JSON (0600).
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
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("canary: write manifest: %w", err)
	}
	return nil
}

// ReadManifest loads a manifest written by WriteManifest.
func ReadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
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
	return &m, nil
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

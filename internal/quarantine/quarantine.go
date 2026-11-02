// Package quarantine is the OSS engine's honest vault for files a scan flags.
//
// The console ships full response (kill, isolate, roll back) by design; the
// OSS analyst still needs somewhere to put a found file so it is off the live
// path but not destroyed. This package is that somewhere: a directory-backed
// store with an integrity-checked restore.
//
// Two properties matter and are enforced here:
//
//   - Neutralization. A stored file is XOR-masked with a per-entry random key.
//     The vault therefore never holds a runnable PE/ELF on disk, and a scanner
//     pointed at the vault (including this one) does not re-flag its own
//     quarantine. The mask is reversible and its key lives in the index, so
//     this is obfuscation for safety, never encryption for secrecy — the
//     doc.go comment says so plainly.
//
//   - Integrity-checked restore. Every entry records the SHA-256 of the
//     original bytes and of the masked blob. Restore verifies the blob digest
//     before unmasking and the unmasked digest before writing, so a vault that
//     was corrupted or tampered with fails closed instead of writing wrong
//     bytes back onto the live path.
//
// The store is single-process: the CLI opens it, does one operation, and
// exits. Index writes are atomic (temp file + rename) so a crash mid-write
// leaves the previous index intact.
package quarantine

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

// indexName is the JSON index at the root of the store; blobSubdir holds the
// masked file bodies, one per entry, named by entry ID.
const (
	indexName  = "index.json"
	blobSubdir = "blobs"

	// indexVersion lets a future format change be detected rather than
	// mis-parsed. Bumped only on an incompatible layout change.
	indexVersion = 1

	// maxEntrySize caps a single quarantined file at 2 GiB. The vault holds
	// samples, not disk images; an unbounded read here would be a memory
	// liability with the same shape the scanner's own caps guard against.
	maxEntrySize = 2 << 30
)

// Errors a caller can branch on.
var (
	// ErrNotFound is returned when no entry has the requested ID.
	ErrNotFound = errors.New("quarantine: entry not found")
	// ErrIntegrity is returned when a stored blob's digest does not match what
	// the index recorded, or an unmasked restore does not reproduce the
	// original digest. The operation is abandoned; nothing is written back.
	ErrIntegrity = errors.New("quarantine: integrity check failed")
	// ErrExists is returned by Restore when the destination already exists and
	// overwrite was not requested, so a restore never clobbers a live file.
	ErrExists = errors.New("quarantine: destination already exists")
	// ErrTooLarge is returned when a file exceeds maxEntrySize.
	ErrTooLarge = errors.New("quarantine: file exceeds the entry size cap")
)

// Entry is one quarantined file's record. It is the public, JSON-serialized
// shape of a vault row; the mask Key is included because the vault's threat
// model is "off the live path, not runnable", not "secret from the operator".
type Entry struct {
	// ID is the vault-unique identifier (also the blob filename): 32 hex chars
	// of randomness, so it never collides and never leaks the original name.
	ID string `json:"id"`
	// OriginalPath is the absolute path the file was quarantined from.
	OriginalPath string `json:"original_path"`
	// ThreatName is the detection label that led to quarantine (free-form;
	// "manual" when an operator quarantined without a verdict).
	ThreatName string `json:"threat_name"`
	// Size is the original file size in bytes.
	Size int64 `json:"size"`
	// Mode is the original file's permission bits, restored with the file.
	Mode os.FileMode `json:"mode"`
	// SHA256 is the lowercase-hex digest of the original bytes.
	SHA256 string `json:"sha256"`
	// StoredSHA256 is the digest of the masked blob as written to the vault;
	// Verify recomputes it to detect at-rest corruption or tampering.
	StoredSHA256 string `json:"stored_sha256"`
	// Key is the XOR mask (lowercase hex). Its length is the mask period.
	Key string `json:"key"`
	// QuarantinedAt is when the entry was written (UTC, RFC 3339).
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// index is the on-disk document.
type index struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Store is a directory-backed quarantine vault. Open it, operate, done.
type Store struct {
	dir string
}

// Open opens (creating if necessary) the vault rooted at dir. The directory
// and its blob subdirectory are created 0700; a fresh vault gets an empty
// index. Open fails if dir exists as a non-directory, or if an existing index
// is unreadable or from an incompatible version.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("quarantine: empty store directory")
	}
	if err := os.MkdirAll(filepath.Join(dir, blobSubdir), 0o700); err != nil {
		return nil, fmt.Errorf("quarantine: create store: %w", err)
	}
	s := &Store{dir: dir}
	// Touch the index so a fresh vault is well-formed on disk and subsequent
	// reads do not have to special-case "no index yet".
	if _, err := os.Stat(s.indexPath()); errors.Is(err, os.ErrNotExist) {
		if err := s.writeIndex(&index{Version: indexVersion}); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("quarantine: stat index: %w", err)
	} else {
		// Validate the existing index eagerly so Open is the single place a
		// corrupt or future-version vault is reported.
		if _, err := s.readIndex(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) indexPath() string         { return filepath.Join(s.dir, indexName) }
func (s *Store) blobPath(id string) string { return filepath.Join(s.dir, blobSubdir, id) }

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Quarantine moves the file at path into the vault and returns its entry. The
// original bytes are read, masked, and written to the vault; on success the
// original is removed unless keepOriginal is set. A failure at any step leaves
// the original in place and writes nothing to the index.
func (s *Store) Quarantine(path, threatName string, keepOriginal bool) (Entry, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Entry{}, fmt.Errorf("quarantine: resolve path: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Entry{}, fmt.Errorf("quarantine: stat %s: %w", abs, err)
	}
	if !info.Mode().IsRegular() {
		return Entry{}, fmt.Errorf("quarantine: %s is not a regular file", abs)
	}
	if info.Size() > maxEntrySize {
		return Entry{}, ErrTooLarge
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return Entry{}, fmt.Errorf("quarantine: read %s: %w", abs, err)
	}

	id, err := randomHex(16)
	if err != nil {
		return Entry{}, err
	}
	key, err := randomBytes(32)
	if err != nil {
		return Entry{}, err
	}

	orig := sha256.Sum256(data)
	masked := xorMask(data, key)
	stored := sha256.Sum256(masked)

	if err := writeFileAtomic(s.blobPath(id), masked, 0o600); err != nil {
		return Entry{}, fmt.Errorf("quarantine: write blob: %w", err)
	}

	e := Entry{
		ID:            id,
		OriginalPath:  abs,
		ThreatName:    threatName,
		Size:          info.Size(),
		Mode:          info.Mode().Perm(),
		SHA256:        hex.EncodeToString(orig[:]),
		StoredSHA256:  hex.EncodeToString(stored[:]),
		Key:           hex.EncodeToString(key),
		QuarantinedAt: time.Now().UTC(),
	}

	if err := s.appendEntry(e); err != nil {
		// Roll back the orphaned blob so a failed index write leaves no litter.
		_ = os.Remove(s.blobPath(id))
		return Entry{}, err
	}

	if !keepOriginal {
		if err := os.Remove(abs); err != nil {
			// The vault copy is committed; report the removal failure so the
			// operator knows the live copy is still there, but do not unwind
			// the vault entry (that would lose the only integrity-checked copy).
			return e, fmt.Errorf("quarantine: stored %s but could not remove original: %w", id, err)
		}
	}
	return e, nil
}

// Restore writes entry id back to dest. The masked blob's digest is verified
// before unmasking and the unmasked digest before writing, so a corrupted
// vault fails with ErrIntegrity rather than writing wrong bytes. dest is
// written with the entry's recorded mode. If dest exists, Restore returns
// ErrExists unless overwrite is set. An empty dest restores to OriginalPath.
func (s *Store) Restore(id, dest string, overwrite bool) (string, error) {
	e, err := s.find(id)
	if err != nil {
		return "", err
	}
	if dest == "" {
		dest = e.OriginalPath
	}
	data, err := s.loadVerified(e)
	if err != nil {
		return "", err
	}
	if !overwrite {
		if _, err := os.Lstat(dest); err == nil {
			return "", ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("quarantine: stat dest: %w", err)
		}
	}
	if dir := filepath.Dir(dest); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("quarantine: create dest dir: %w", err)
		}
	}
	if err := writeFileAtomic(dest, data, e.Mode); err != nil {
		return "", fmt.Errorf("quarantine: write restored file: %w", err)
	}
	return dest, nil
}

// Verify recomputes the stored blob digest for entry id and confirms it
// matches the index. It detects at-rest corruption and tampering without
// restoring. A missing blob is reported as ErrIntegrity.
func (s *Store) Verify(id string) error {
	e, err := s.find(id)
	if err != nil {
		return err
	}
	_, err = s.loadVerified(e)
	return err
}

// VerifyAll verifies every entry and returns the IDs that failed, in index
// order. A nil error with an empty slice means the whole vault is intact.
func (s *Store) VerifyAll() (failed []string, err error) {
	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	for _, e := range idx.Entries {
		if _, err := s.loadVerified(e); err != nil {
			failed = append(failed, e.ID)
		}
	}
	return failed, nil
}

// List returns every entry, newest first.
func (s *Store) List() ([]Entry, error) {
	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	out := append([]Entry(nil), idx.Entries...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].QuarantinedAt.After(out[j].QuarantinedAt)
	})
	return out, nil
}

// Get returns a single entry by ID.
func (s *Store) Get(id string) (Entry, error) { return s.find(id) }

// Delete permanently purges entry id: its blob and its index row. Use it to
// expire a vault entry the operator has decided on. Deleting a non-existent ID
// returns ErrNotFound.
func (s *Store) Delete(id string) error {
	idx, err := s.readIndex()
	if err != nil {
		return err
	}
	kept := idx.Entries[:0:0]
	found := false
	for _, e := range idx.Entries {
		if e.ID == id {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return ErrNotFound
	}
	if err := os.Remove(s.blobPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("quarantine: remove blob: %w", err)
	}
	idx.Entries = kept
	return s.writeIndex(idx)
}

// ── internals ────────────────────────────────────────────────────────────────

// loadVerified reads the masked blob, checks both digests, and returns the
// original bytes. It is the one place the integrity contract is enforced, so
// Restore and Verify share exactly the same checks.
func (s *Store) loadVerified(e Entry) ([]byte, error) {
	masked, err := os.ReadFile(s.blobPath(e.ID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: blob for %s is missing", ErrIntegrity, e.ID)
		}
		return nil, fmt.Errorf("quarantine: read blob: %w", err)
	}
	if got := sha256.Sum256(masked); hex.EncodeToString(got[:]) != e.StoredSHA256 {
		return nil, fmt.Errorf("%w: stored blob for %s does not match recorded digest", ErrIntegrity, e.ID)
	}
	key, err := hex.DecodeString(e.Key)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("%w: mask key for %s is unusable", ErrIntegrity, e.ID)
	}
	data := xorMask(masked, key)
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != e.SHA256 {
		return nil, fmt.Errorf("%w: unmasked bytes for %s do not reproduce the original digest", ErrIntegrity, e.ID)
	}
	return data, nil
}

func (s *Store) find(id string) (Entry, error) {
	idx, err := s.readIndex()
	if err != nil {
		return Entry{}, err
	}
	for _, e := range idx.Entries {
		if e.ID == id {
			return e, nil
		}
	}
	return Entry{}, ErrNotFound
}

func (s *Store) appendEntry(e Entry) error {
	idx, err := s.readIndex()
	if err != nil {
		return err
	}
	idx.Entries = append(idx.Entries, e)
	return s.writeIndex(idx)
}

func (s *Store) readIndex() (*index, error) {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return nil, fmt.Errorf("quarantine: read index: %w", err)
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("quarantine: parse index: %w", err)
	}
	if idx.Version != indexVersion {
		return nil, fmt.Errorf("quarantine: index version %d is not supported (want %d)", idx.Version, indexVersion)
	}
	return &idx, nil
}

func (s *Store) writeIndex(idx *index) error {
	idx.Version = indexVersion
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("quarantine: encode index: %w", err)
	}
	return writeFileAtomic(s.indexPath(), data, 0o600)
}

// writeFileAtomic writes data to path via a temp file in the same directory
// and a rename, so a reader never sees a half-written file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	// fsync the data before the rename so a crash can never leave a renamed-in
	// file with unflushed (zero or torn) contents — the vault's integrity seal
	// is only meaningful if the bytes it covers actually reached disk.
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
	// Best-effort fsync of the directory so the rename itself is durable.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// xorMask returns data XOR-masked with key repeated to length. It is its own
// inverse, which is why one function serves both store and restore.
func xorMask(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("quarantine: read randomness: %w", err)
	}
	return b, nil
}

func randomHex(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

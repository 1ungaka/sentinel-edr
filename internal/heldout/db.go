// Package heldout stores the identities of the held-out recall corpus — the
// SHA-256 of every real malware sample the detectors are measured against but
// were not authored from — in an authenticated, encrypted database.
//
// The hash list is sensitive: it reveals which families and samples are
// tracked, and a plaintext list in the repository is both a disclosure and a
// temptation to tune rules against it. The database is therefore encrypted at
// rest with AES-256-GCM under a key derived from a passphrase with PBKDF2, so
// the ciphertext is safe to commit while the hashes never are. GCM's
// authentication tag means a wrong passphrase or a tampered file fails to
// decrypt rather than returning garbage.
package heldout

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

// magic identifies an encrypted held-out database and versions its on-disk
// layout: magic(8) ‖ salt(16) ‖ nonce(12) ‖ AES-256-GCM(ciphertext ‖ tag).
var magic = [8]byte{'C', 'A', 'U', 'H', 'D', 'B', 0x00, 0x01}

const (
	saltLen = 16
	keyLen  = 32      // AES-256
	iters   = 600_000 // PBKDF2-HMAC-SHA256 rounds
)

// ErrWrongKey is returned when decryption fails its authentication check,
// which a wrong passphrase and a corrupt or tampered file are alike.
var ErrWrongKey = errors.New("heldout: wrong passphrase or corrupt database")

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Record is one held-out sample's identity and the threat intel that travels
// with it. The bytes are never stored here; the SHA-256 is the handle used to
// re-fetch and verify them.
type Record struct {
	SHA256 string `json:"sha256"`
	Family string `json:"family"`
	Label  string `json:"label,omitempty"` // defaults to Family

	// Intel, as carried by the feed (MalwareBazaar full export).
	Signature string   `json:"signature,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	FileType  string   `json:"file_type,omitempty"`
	FirstSeen string   `json:"first_seen,omitempty"`
	Reporter  string   `json:"reporter,omitempty"`
	Imphash   string   `json:"imphash,omitempty"`

	URL     string `json:"url,omitempty"`
	License string `json:"license,omitempty"`
	Added   string `json:"added,omitempty"` // RFC3339
	Notes   string `json:"notes,omitempty"`
}

func (r Record) label() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Family
}

// DB is the decrypted database. Records are kept unsorted in memory for O(1)
// amortised insertion through idx and sorted only when encrypted, so a pull of
// millions of rows is linear rather than quadratic.
type DB struct {
	Records []Record `json:"records"`

	idx map[string]int // sha256 -> index into Records; built lazily
}

// ensureIndex builds the hash index from Records on first use (e.g. after a
// Decrypt, which populates Records but not idx).
func (d *DB) ensureIndex() {
	if d.idx != nil {
		return
	}
	d.idx = make(map[string]int, len(d.Records))
	for i, r := range d.Records {
		d.idx[r.SHA256] = i
	}
}

// Len reports how many records the database holds.
func (d *DB) Len() int { return len(d.Records) }

// Has reports whether a (already-normalised) hash is present.
func (d *DB) Has(sha string) bool {
	d.ensureIndex()
	_, ok := d.idx[sha]
	return ok
}

// normSHA lower-cases and validates a hash as 64 hex characters.
func normSHA(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !hex64.MatchString(s) {
		return "", fmt.Errorf("heldout: %q is not a 64-hex-char sha256", s)
	}
	return s, nil
}

// Add inserts a record, rejecting a malformed hash or empty family and
// replacing any existing record with the same hash. Insertion is O(1)
// amortised; the file is sorted by hash at encryption time, not here, so a
// bulk pull stays linear.
func (d *DB) Add(r Record) error {
	sha, err := normSHA(r.SHA256)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r.Family) == "" {
		return errors.New("heldout: family is required")
	}
	r.SHA256 = sha
	if r.Added == "" {
		r.Added = time.Now().UTC().Format(time.RFC3339)
	}
	d.ensureIndex()
	if i, ok := d.idx[sha]; ok {
		d.Records[i] = r
		return nil
	}
	d.idx[sha] = len(d.Records)
	d.Records = append(d.Records, r)
	return nil
}

// Remove drops the record with the given hash, reporting whether it existed.
func (d *DB) Remove(sha string) (bool, error) {
	sha, err := normSHA(sha)
	if err != nil {
		return false, err
	}
	d.ensureIndex()
	i, ok := d.idx[sha]
	if !ok {
		return false, nil
	}
	d.Records = append(d.Records[:i], d.Records[i+1:]...)
	d.idx = nil // indices shifted; rebuild lazily
	return true, nil
}

// Encrypt serialises and encrypts the database under the passphrase.
func Encrypt(db *DB, pass []byte) ([]byte, error) {
	if len(pass) == 0 {
		return nil, errors.New("heldout: empty passphrase")
	}
	// Sort by hash so the plaintext (and thus a diff of two decrypted dumps)
	// is stable regardless of insertion order.
	sort.Slice(db.Records, func(i, j int) bool { return db.Records[i].SHA256 < db.Records[j].SHA256 })
	db.idx = nil // order changed; rebuild lazily
	plain, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, string(pass), salt, iters, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Bind the header as additional data so a tampered magic/salt/nonce fails.
	out := make([]byte, 0, len(magic)+saltLen+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, magic[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	ct := gcm.Seal(nil, nonce, plain, out[:len(magic)+saltLen+len(nonce)])
	return append(out, ct...), nil
}

// Decrypt authenticates and decrypts a database blob.
func Decrypt(blob, pass []byte) (*DB, error) {
	hdr := len(magic) + saltLen + 12
	if len(blob) < hdr {
		return nil, ErrWrongKey
	}
	if [8]byte(blob[:8]) != magic {
		return nil, errors.New("heldout: not a held-out database (bad magic)")
	}
	salt := blob[len(magic) : len(magic)+saltLen]
	nonce := blob[len(magic)+saltLen : hdr]
	ct := blob[hdr:]
	key, err := pbkdf2.Key(sha256.New, string(pass), salt, iters, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, blob[:hdr])
	if err != nil {
		return nil, ErrWrongKey
	}
	var db DB
	if err := json.Unmarshal(plain, &db); err != nil {
		return nil, fmt.Errorf("heldout: decode: %w", err)
	}
	return &db, nil
}

// Save writes the encrypted database to path atomically (temp file + rename)
// with owner-only permissions, so a crash mid-write never leaves a truncated,
// undecryptable database — the previous checkpoint survives intact.
func Save(path string, db *DB, pass []byte) error {
	blob, err := Encrypt(db, pass)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	// Without this the rename can reach the disk before the data does, and a
	// crash replaces the last good checkpoint with an empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load reads and decrypts the database at path.
func Load(path string, pass []byte) (*DB, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Decrypt(blob, pass)
}

// Manifest renders the database as an eval corpus manifest (schema_version 1)
// whose samples live under root, one file per hash named "<sha256>.bin". It is
// the source manifest the fetch script consumes: no hash ever lands in a
// plaintext file on disk, the manifest is produced on demand from the
// decrypted database.
func (d *DB) Manifest(root string) ([]byte, error) {
	type prov struct {
		Source  string `json:"source"`
		URL     string `json:"url,omitempty"`
		License string `json:"license,omitempty"`
	}
	type sample struct {
		ID         string `json:"id"`
		Path       string `json:"path"`
		Label      string `json:"label"`
		Family     string `json:"family"`
		SHA256     string `json:"sha256"`
		Notes      string `json:"notes,omitempty"`
		Provenance prov   `json:"provenance"`
	}
	type manifest struct {
		SchemaVersion string            `json:"schema_version"`
		Name          string            `json:"name"`
		Description   string            `json:"description"`
		Root          string            `json:"root"`
		Defaults      map[string]string `json:"defaults"`
		Samples       []sample          `json:"samples"`
	}
	m := manifest{
		SchemaVersion: "1",
		Name:          "heldout",
		Description:   "Held-out recall corpus (live). Generated from the encrypted hash database; not committed.",
		Root:          root,
		Defaults:      map[string]string{"source": "malwarebazaar"},
		Samples:       make([]sample, 0, len(d.Records)),
	}
	for _, r := range d.Records {
		id := r.Family + "-" + r.SHA256[:12]
		m.Samples = append(m.Samples, sample{
			ID:         id,
			Path:       r.SHA256 + ".bin",
			Label:      r.label(),
			Family:     r.Family,
			SHA256:     r.SHA256,
			Notes:      r.Notes,
			Provenance: prov{Source: "malwarebazaar", URL: r.URL, License: r.License},
		})
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// A passphrase file is read whole. It may be a pipe, and a pipe may be slow
// while a secrets manager asks for a passphrase of its own, but not forever.
const (
	maxKeyFileBytes = 64 << 10
	keyPipeWait     = 2 * time.Minute
)

// ReadKey resolves the passphrase from a key file (preferred) or the
// CAU_HELDOUT_KEY environment variable, trimming a trailing newline from a
// file so `echo pass > key` behaves. It never echoes the key.
func ReadKey(keyFile string) ([]byte, error) {
	if keyFile != "" {
		b, err := safefs.ReadOperatorFile(keyFile, maxKeyFileBytes, keyPipeWait)
		if err != nil {
			return nil, fmt.Errorf("heldout: read key file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	if v := os.Getenv("CAU_HELDOUT_KEY"); v != "" {
		return []byte(v), nil
	}
	return nil, errors.New("heldout: no passphrase (set CAU_HELDOUT_KEY or pass --key-file)")
}

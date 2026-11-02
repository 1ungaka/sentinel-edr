package scanner

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/fusion"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// Verdict represents the outcome of a file scan.
type Verdict string

const (
	VerdictMalicious Verdict = "MALICIOUS"
	VerdictClean     Verdict = "CLEAN"
	VerdictError     Verdict = "ERROR"
)

// ScanResult holds the full result of scanning a single file with the hash
// and YARA detectors. Heuristics are reported separately (HeuristicResult)
// because they produce a score, not a verdict.
type ScanResult struct {
	FilePath string
	// Size is the file size in bytes. 0 when the file could not be stat-ed.
	Size   int64
	MD5    string
	SHA1   string
	SHA256 string

	// Hash detection fields
	Detected   bool
	MatchType  string // e.g. "SHA256", "MD5", "SHA1"
	MatchHash  string // the specific hash that matched
	ThreatName string

	// YARA detection fields
	YaraMatches []YaraMatch

	// Warnings records non-fatal problems (a YARA scan that timed out after
	// collecting some matches, for example). They never change the verdict.
	Warnings []string

	// Static is the structural analysis (entropy, fuzzy hashes, PE anatomy,
	// anomalies), nil when the engine ran without it. Like heuristics it
	// produces a score against a threshold, not a verdict: a breach is the
	// SUSPICIOUS tier, never MALICIOUS.
	Static *static.Result

	// Stego is the invisible-codepoint analysis of text and code artifacts
	// (zero-width steganography, Trojan Source bidi controls), nil when the
	// engine ran without it. A breach is the SUSPICIOUS tier.
	Stego *stego.Result

	// EncChain is the encoded-executable analysis (base64/hex layers that
	// decode to a PE/ELF header). nil when the detector did not run.
	EncChain *encchain.Result

	// LNK is the Windows Shell Link (.lnk) analysis (malicious-shortcut
	// delivery: interpreter arguments, obfuscation, lures). nil when the
	// detector did not run. A breach is the SUSPICIOUS tier.
	LNK *lnk.Result

	// OLE is the OLE compound-file analysis (VBA macro tradecraft: auto-exec
	// entry points, suspicious calls, embedded-object lures). nil when the
	// detector did not run. A breach is the SUSPICIOUS tier.
	OLE *ole.Result

	// PDF is the PDF malicious-document analysis (auto-run actions, embedded
	// JavaScript, Launch, embedded files, name obfuscation). nil when the
	// detector did not run. A breach is the SUSPICIOUS tier.
	PDF *pdf.Result

	// ISO is the ISO 9660 malicious-container analysis (the .lnk+hidden-payload
	// email-smuggling shape, autorun.inf). nil when the detector did not run.
	// A breach is the SUSPICIOUS tier.
	ISO *iso.Result

	// Fusion is the lattice's view over every detector that ran: which
	// sources agreed, how strongly, and what techniques the agreeing evidence
	// carries. nil when no detector was configured. It can be SUSPICIOUS when
	// no single detector crossed its own threshold (Fusion.Corroborated).
	Fusion *fusion.Verdict

	Verdict  Verdict
	ScanTime time.Duration
	Error    error
}

// ── Signature database ───────────────────────────────────────────────────────

// Signature represents a single entry in the hash database.
type Signature struct {
	HashType   string // "MD5", "SHA1", "SHA256"
	Hash       string // lowercase hex
	ThreatName string
	// Line is the 1-based line in the source file the entry came from
	// (0 for entries added programmatically).
	Line int
}

// hashLengths maps every supported hash type to the exact hex length it must
// have. A hash of the wrong length can never match anything, so storing it only
// inflates the signature count while detecting nothing.
var hashLengths = map[string]int{
	"MD5":    32,
	"SHA1":   40,
	"SHA256": 64,
}

// HashTypes returns the supported hash types in canonical order.
func HashTypes() []string { return []string{"MD5", "SHA1", "SHA256"} }

// NormalizeHashType canonicalises the spellings people actually type
// ("sha-256", "Sha1", "md5") onto the canonical "MD5" / "SHA1" / "SHA256".
func NormalizeHashType(t string) (string, error) {
	n := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(t), "-", ""))
	if _, ok := hashLengths[n]; !ok {
		return "", fmt.Errorf("unsupported hash type %q (want MD5, SHA1 or SHA256)", t)
	}
	return n, nil
}

// HashTypeFor infers the hash type from the length of a hex digest.
func HashTypeFor(hash string) (string, bool) {
	for _, t := range HashTypes() {
		if hashLengths[t] == len(strings.TrimSpace(hash)) {
			return t, true
		}
	}
	return "", false
}

// ValidateHash checks a (type, digest) pair and returns the canonical form. It
// rejects non-hex digests, digests of the wrong length for the declared type
// (naming the type the length *does* fit, which is the usual copy-paste
// mistake), and unknown types.
func ValidateHash(hashType, digest string) (normType, normHash string, err error) {
	normType, err = NormalizeHashType(hashType)
	if err != nil {
		return "", "", err
	}
	normHash = strings.ToLower(strings.TrimSpace(digest))
	if normHash == "" {
		return "", "", fmt.Errorf("empty %s hash", normType)
	}
	for i := 0; i < len(normHash); i++ {
		c := normHash[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", "", fmt.Errorf("%s hash %q is not hexadecimal (offending character %q at position %d)",
				normType, normHash, c, i+1)
		}
	}
	if want := hashLengths[normType]; len(normHash) != want {
		if fits, ok := HashTypeFor(normHash); ok {
			return "", "", fmt.Errorf("%s hash %q has %d hex characters, want %d (the length matches %s)",
				normType, normHash, len(normHash), want, fits)
		}
		return "", "", fmt.Errorf("%s hash %q has %d hex characters, want %d",
			normType, normHash, len(normHash), want)
	}
	return normType, normHash, nil
}

// SignatureDB holds all loaded signatures, indexed by hash value for fast lookup.
//
// Every entry has been validated (known type, hex, exact length) and is unique:
// a duplicate hash is reported as a warning instead of silently overwriting the
// earlier entry, so Count() is the number of hashes that can actually match.
type SignatureDB struct {
	entries  map[string]Signature // key: lowercase hash value
	byType   map[string]int
	warnings []string
	source   string
	skipped  int
}

// NewSignatureDB returns an empty database.
func NewSignatureDB() *SignatureDB {
	return &SignatureDB{entries: make(map[string]Signature), byType: make(map[string]int)}
}

// LoadSignatures reads the pipe-delimited hashes.txt file into a SignatureDB.
// Lines starting with '#' or that are blank are skipped.
// Expected format: HASH_TYPE|HASH|THREAT_NAME
//
// Malformed, invalid and duplicate lines are skipped and recorded in
// Warnings(); they are not fatal because one bad line must not disable hash
// detection entirely. An unreadable file is fatal.
func LoadSignatures(path string) (*SignatureDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open signature database: %w", err)
	}
	defer f.Close()
	return ParseSignatures(f, path)
}

// ParseSignatures is LoadSignatures over an io.Reader. source labels warnings.
func ParseSignatures(r io.Reader, source string) (*SignatureDB, error) {
	db := NewSignatureDB()
	db.source = source

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			db.skip(lineNum, "malformed line (want HASH_TYPE|HASH|THREAT_NAME)")
			continue
		}

		sig := Signature{
			HashType:   parts[0],
			Hash:       parts[1],
			ThreatName: strings.TrimSpace(parts[2]),
			Line:       lineNum,
		}
		if err := db.Add(sig); err != nil {
			db.skip(lineNum, err.Error())
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading signature database: %w", err)
	}
	return db, nil
}

func (db *SignatureDB) skip(line int, why string) {
	db.skipped++
	db.warnings = append(db.warnings, fmt.Sprintf("%s:%d: skipped: %s", db.label(), line, why))
}

func (db *SignatureDB) label() string {
	if db.source == "" {
		return "<signatures>"
	}
	return db.source
}

// Add validates sig and inserts it. It returns an error for an invalid hash,
// an empty or pipe-containing threat name, and for a hash that is already in
// the database (the error says which threat name the existing entry carries,
// so a conflicting re-labelling is visible rather than silently applied).
func (db *SignatureDB) Add(sig Signature) error {
	if db.entries == nil {
		db.entries = make(map[string]Signature)
	}
	if db.byType == nil {
		db.byType = make(map[string]int)
	}

	t, h, err := ValidateHash(sig.HashType, sig.Hash)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(sig.ThreatName)
	switch {
	case name == "":
		return fmt.Errorf("empty threat name for %s %s", t, h)
	case strings.ContainsAny(name, "|\r\n"):
		return fmt.Errorf("threat name %q must not contain '|' or line breaks", name)
	}

	if prev, dup := db.entries[h]; dup {
		if prev.ThreatName == name {
			return fmt.Errorf("duplicate %s %s (already listed as %q at line %d)", t, h, prev.ThreatName, prev.Line)
		}
		return fmt.Errorf("conflicting %s %s: already listed as %q at line %d, keeping the first entry",
			t, h, prev.ThreatName, prev.Line)
	}

	db.entries[h] = Signature{HashType: t, Hash: h, ThreatName: name, Line: sig.Line}
	db.byType[t]++
	return nil
}

// Lookup checks whether a given hash (any type) is in the database.
func (db *SignatureDB) Lookup(hashValue string) (Signature, bool) {
	if db == nil {
		return Signature{}, false
	}
	sig, found := db.entries[strings.ToLower(strings.TrimSpace(hashValue))]
	return sig, found
}

// Count returns the number of unique, valid signatures loaded.
func (db *SignatureDB) Count() int {
	if db == nil {
		return 0
	}
	return len(db.entries)
}

// CountByType returns the number of signatures per hash type.
func (db *SignatureDB) CountByType() map[string]int {
	out := make(map[string]int, len(db.byType))
	for k, v := range db.byType {
		out[k] = v
	}
	return out
}

// Skipped returns how many lines were rejected while loading.
func (db *SignatureDB) Skipped() int { return db.skipped }

// Warnings returns one message per rejected line, in file order.
func (db *SignatureDB) Warnings() []string {
	return append([]string(nil), db.warnings...)
}

// Source returns the path the database was loaded from, if any.
func (db *SignatureDB) Source() string { return db.source }

// Signatures returns every entry sorted by hash type, then hash.
func (db *SignatureDB) Signatures() []Signature {
	out := make([]Signature, 0, len(db.entries))
	for _, s := range db.entries {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HashType != out[j].HashType {
			return out[i].HashType < out[j].HashType
		}
		return out[i].Hash < out[j].Hash
	})
	return out
}

// AddSignature validates a new signature against the existing database file
// and appends it. It refuses duplicates and conflicting re-labellings instead of
// appending a line that LoadSignatures would then reject anyway.
func AddSignature(dbPath, hashType, hashValue, threatName string) error {
	t, h, err := ValidateHash(hashType, hashValue)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(threatName)
	if name == "" {
		return fmt.Errorf("threat name must not be empty")
	}
	if strings.ContainsAny(name, "|\r\n") {
		return fmt.Errorf("threat name %q must not contain '|' or line breaks", name)
	}

	existing, err := LoadSignatures(dbPath)
	switch {
	case err == nil:
		if prev, dup := existing.Lookup(h); dup {
			if prev.ThreatName == name {
				return fmt.Errorf("%s %s is already in %s (line %d)", t, h, dbPath, prev.Line)
			}
			return fmt.Errorf("%s %s is already in %s as %q (line %d); remove that line first to re-label it",
				t, h, dbPath, prev.ThreatName, prev.Line)
		}
	case errors.Is(err, fs.ErrNotExist):
		// A brand new database: nothing to collide with.
	default:
		return err
	}

	f, err := os.OpenFile(dbPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("could not open signature database for writing: %w", err)
	}
	defer f.Close()

	// Make sure the new entry starts on its own line even if the file does not
	// end with a newline.
	prefix := ""
	if fi, serr := f.Stat(); serr == nil && fi.Size() > 0 {
		if r, rerr := os.Open(dbPath); rerr == nil {
			buf := make([]byte, 1)
			if _, rerr = r.ReadAt(buf, fi.Size()-1); rerr == nil && buf[0] != '\n' {
				prefix = "\n"
			}
			r.Close()
		}
	}

	_, err = fmt.Fprintf(f, "%s%s|%s|%s\n", prefix, t, h, name)
	return err
}

// ── Hashing ──────────────────────────────────────────────────────────────────

type digests struct{ md5, sha1, sha256 string }

// hashFile computes MD5, SHA-1, and SHA-256 of a file in a single streaming pass.
func hashFile(path string) (digests, error) {
	f, err := os.Open(path)
	if err != nil {
		return digests{}, fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) (digests, error) {
	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256), r); err != nil {
		return digests{}, fmt.Errorf("could not hash file: %w", err)
	}
	return digests{hashHex(hMD5), hashHex(hSHA1), hashHex(hSHA256)}, nil
}

// hashBytes computes the three digests of an in-memory buffer.
func hashBytes(data []byte) digests {
	m, s1, s2 := md5.Sum(data), sha1.Sum(data), sha256.Sum256(data)
	return digests{hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s2[:])}
}

func hashHex(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

// ── Compatibility entry points ───────────────────────────────────────────────

// ScanFile scans a single file against the hash signature database and,
// optionally, a compiled YARA ruleset. Pass nil for ys to skip YARA scanning.
// It is a thin wrapper over Engine for callers that do not need heuristics.
func ScanFile(path string, db *SignatureDB, ys *YaraScanner) ScanResult {
	res, _ := (&Engine{DB: db, Yara: ys}).ScanFile(path)
	return res
}

// ScanDirectory recursively scans all regular files in a directory, in walk
// order, using a single worker. See Engine.ScanDirectory for concurrency.
func ScanDirectory(root string, db *SignatureDB, ys *YaraScanner) []ScanResult {
	results, _ := (&Engine{DB: db, Yara: ys, Jobs: 1}).ScanDirectory(root, nil)
	return results
}

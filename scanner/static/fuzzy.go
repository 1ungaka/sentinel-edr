package static

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"

	"github.com/s-b-repo/cau/internal/safefs"
)

// FuzzyHashes are the similarity digests computed for a file.
type FuzzyHashes struct {
	// TLSH is the 70-hex-character TLSH digest, "" when the input is too
	// short or too uniform for TLSH (under 50 bytes, or no byte variety).
	TLSH string `json:"tlsh,omitempty"`
	// TLSHNote explains an empty TLSH.
	TLSHNote string `json:"tlsh_note,omitempty"`
	// SSDeep is the context-triggered piecewise hash, "" for inputs under
	// ssdeep's 4096-byte minimum.
	SSDeep string `json:"ssdeep,omitempty"`
	// SSDeepNote explains an empty SSDeep.
	SSDeepNote string `json:"ssdeep_note,omitempty"`
}

// ComputeFuzzy hashes data with TLSH and ssdeep. Neither failure is an error:
// small files simply have no meaningful fuzzy hash, and the result says why.
func ComputeFuzzy(data []byte) FuzzyHashes {
	var out FuzzyHashes
	if t, err := tlsh.HashBytes(data); err == nil {
		out.TLSH = strings.ToUpper(t.String())
	} else {
		out.TLSHNote = "tlsh: " + err.Error()
	}
	if s, err := ssdeep.FuzzyBytes(data); err == nil {
		out.SSDeep = s
	} else if errors.Is(err, ssdeep.ErrFileTooSmall) {
		out.SSDeepNote = "ssdeep: input below the 4096-byte minimum"
	} else {
		out.SSDeepNote = "ssdeep: " + err.Error()
	}
	return out
}

// TLSHDistance returns the TLSH difference score between two digests (0 is
// identical; typical same-family matches are under 30-60). An error means a
// digest was malformed.
func TLSHDistance(a, b string) (int, error) {
	ta, err := parseTLSH(a)
	if err != nil {
		return 0, err
	}
	tb, err := parseTLSH(b)
	if err != nil {
		return 0, err
	}
	return ta.Diff(tb), nil
}

var tlshHex = regexp.MustCompile(`^[0-9A-Fa-f]{70}$`)

// parseTLSH validates and parses a TLSH digest. It accepts the "T1" versioned
// prefix emitted by the reference implementation. The length check matters:
// the underlying library indexes the decoded bytes without checking them.
func parseTLSH(s string) (*tlsh.TLSH, error) {
	s = strings.TrimSpace(s)
	if len(s) == 72 && (strings.HasPrefix(s, "T1") || strings.HasPrefix(s, "t1")) {
		s = s[2:]
	}
	if !tlshHex.MatchString(s) {
		return nil, fmt.Errorf("TLSH digest must be 70 hex characters (optionally prefixed T1), got %d", len(s))
	}
	return tlsh.ParseStringToTlsh(strings.ToLower(s))
}

// SSDeepScore returns the ssdeep match score (0..100) between two digests.
func SSDeepScore(a, b string) (int, error) {
	if !validSSDeep(a) || !validSSDeep(b) {
		return 0, fmt.Errorf("ssdeep digest must look like blocksize:hash1:hash2")
	}
	return ssdeep.Distance(a, b)
}

func validSSDeep(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) <= 256
}

// ── Fuzzy signature database ─────────────────────────────────────────────────

// Fuzzy database defaults. These are the published thresholds: a TLSH
// distance at or below TLSHMaxDistance, or an ssdeep score at or above
// SSDeepMinScore, counts as a match. TLSH's own guidance puts same-family
// variants under ~30-60 and unrelated files well above 100; ssdeep scores
// above 70 are rarely coincidental for inputs over a few kilobytes.
const (
	DefaultTLSHMaxDistance = 30
	DefaultSSDeepMinScore  = 70
)

// Fuzzy entry types.
const (
	FuzzyTLSH    = "TLSH"
	FuzzySSDeep  = "SSDEEP"
	FuzzyImphash = "IMPHASH"
)

// FuzzyEntry is one line of the fuzzy signature database.
type FuzzyEntry struct {
	Type       string
	Hash       string
	ThreatName string
	Line       int
	parsed     *tlsh.TLSH
}

// FuzzyMatch is a database entry that matched a scanned file.
type FuzzyMatch struct {
	Type       string `json:"type"`
	Hash       string `json:"hash"`
	ThreatName string `json:"threat"`
	// Distance is the TLSH difference (TLSH entries only; lower is closer).
	Distance int `json:"distance,omitempty"`
	// Score is the ssdeep match score (SSDEEP entries only; higher is closer).
	Score int `json:"score,omitempty"`
	Line  int `json:"-"`
}

// FuzzyDB is a validated set of fuzzy signatures. File format, one entry per
// line, '#' comments:
//
//	TLSH|<70 hex>|<threat name>
//	SSDEEP|<blocksize:hash:hash>|<threat name>
//	IMPHASH|<32 hex>|<threat name>
type FuzzyDB struct {
	entries  []FuzzyEntry
	byImp    map[string]int
	byTLSH   map[byte][]int
	bySSDeep map[int][]int
	warnings []string
	source   string
	skipped  int

	// TLSHMaxDistance and SSDeepMinScore override the defaults when non-zero.
	TLSHMaxDistance int
	SSDeepMinScore  int
}

// NewFuzzyDB returns an empty database.
func NewFuzzyDB() *FuzzyDB {
	return &FuzzyDB{
		byImp:    map[string]int{},
		byTLSH:   map[byte][]int{},
		bySSDeep: map[int][]int{},
	}
}

// LoadFuzzyDB reads a database file. Malformed lines are skipped and recorded
// as warnings; an unreadable file is an error.
func LoadFuzzyDB(path string) (*FuzzyDB, error) {
	f, _, err := safefs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open fuzzy database: %w", err)
	}
	defer f.Close()
	return ParseFuzzyDB(f, path)
}

// ParseFuzzyDB is LoadFuzzyDB over a reader.
func ParseFuzzyDB(r io.Reader, source string) (*FuzzyDB, error) {
	db := NewFuzzyDB()
	db.source = source
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			db.skip(n, "malformed line (want TYPE|HASH|THREAT_NAME)")
			continue
		}
		if err := db.Add(FuzzyEntry{Type: parts[0], Hash: parts[1], ThreatName: parts[2], Line: n}); err != nil {
			db.skip(n, err.Error())
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading fuzzy database: %w", err)
	}
	return db, nil
}

func (db *FuzzyDB) skip(line int, why string) {
	db.skipped++
	src := db.source
	if src == "" {
		src = "<fuzzy>"
	}
	db.warnings = append(db.warnings, fmt.Sprintf("%s:%d: skipped: %s", src, line, why))
}

// ValidateFuzzy normalises and checks one (type, digest) pair.
func ValidateFuzzy(typ, digest string) (string, string, error) {
	t := strings.ToUpper(strings.TrimSpace(typ))
	h := strings.TrimSpace(digest)
	switch t {
	case FuzzyTLSH:
		if _, err := parseTLSH(h); err != nil {
			return "", "", err
		}
		if len(h) == 72 {
			h = h[2:]
		}
		return t, strings.ToUpper(h), nil
	case FuzzySSDeep:
		if !validSSDeep(h) {
			return "", "", fmt.Errorf("ssdeep digest %q must look like blocksize:hash1:hash2", h)
		}
		return t, h, nil
	case FuzzyImphash:
		h = strings.ToLower(h)
		if len(h) != 32 {
			return "", "", fmt.Errorf("imphash %q must be 32 hex characters", h)
		}
		for i := 0; i < len(h); i++ {
			c := h[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return "", "", fmt.Errorf("imphash %q is not hexadecimal", h)
			}
		}
		return t, h, nil
	}
	return "", "", fmt.Errorf("unsupported fuzzy type %q (want TLSH, SSDEEP or IMPHASH)", typ)
}

// Add validates and inserts an entry. Duplicate digests are rejected with the
// existing threat name in the error so a re-labelling is visible.
func (db *FuzzyDB) Add(e FuzzyEntry) error {
	if db.byImp == nil {
		db.byImp = map[string]int{}
	}
	if db.byTLSH == nil {
		db.byTLSH = map[byte][]int{}
	}
	if db.bySSDeep == nil {
		db.bySSDeep = map[int][]int{}
	}
	t, h, err := ValidateFuzzy(e.Type, e.Hash)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(e.ThreatName)
	if name == "" {
		return fmt.Errorf("empty threat name for %s %s", t, h)
	}
	if strings.ContainsAny(name, "|\r\n") {
		return fmt.Errorf("threat name %q must not contain '|' or line breaks", name)
	}
	for _, x := range db.entries {
		if x.Type == t && x.Hash == h {
			return fmt.Errorf("duplicate %s %s (already listed as %q at line %d)", t, h, x.ThreatName, x.Line)
		}
	}
	entry := FuzzyEntry{Type: t, Hash: h, ThreatName: name, Line: e.Line}
	if t == FuzzyTLSH {
		// h passed ValidateFuzzy above, so this parse cannot fail; guard it
		// anyway so a future change to normalisation cannot silently store a
		// nil digest that would never match.
		p, perr := parseTLSH(h)
		if perr != nil {
			return fmt.Errorf("internal: validated TLSH %q failed to parse: %w", h, perr)
		}
		entry.parsed = p
	}
	if t == FuzzyImphash {
		db.byImp[h] = len(db.entries)
	} else if t == FuzzyTLSH {
		key := tlshLength(h)
		db.byTLSH[key] = append(db.byTLSH[key], len(db.entries))
	} else if t == FuzzySSDeep {
		key := ssdeepBlockSize(h)
		db.bySSDeep[key] = append(db.bySSDeep[key], len(db.entries))
	}
	db.entries = append(db.entries, entry)
	return nil
}

// Count returns the number of valid entries.
func (db *FuzzyDB) Count() int {
	if db == nil {
		return 0
	}
	return len(db.entries)
}

// CountByType returns entries per type.
func (db *FuzzyDB) CountByType() map[string]int {
	out := map[string]int{}
	if db == nil {
		return out
	}
	for _, e := range db.entries {
		out[e.Type]++
	}
	return out
}

// Warnings returns one message per rejected line.
func (db *FuzzyDB) Warnings() []string {
	if db == nil {
		return nil
	}
	return append([]string(nil), db.warnings...)
}

// Source returns the path the database was loaded from.
func (db *FuzzyDB) Source() string {
	if db == nil {
		return ""
	}
	return db.source
}

func (db *FuzzyDB) tlshMax() int {
	if db.TLSHMaxDistance > 0 {
		return db.TLSHMaxDistance
	}
	return DefaultTLSHMaxDistance
}

func (db *FuzzyDB) ssdeepMin() int {
	if db.SSDeepMinScore > 0 {
		return db.SSDeepMinScore
	}
	return DefaultSSDeepMinScore
}

// Lookup returns every entry within threshold of the given digests, closest
// first. An empty digest of a given type simply skips that type. The database
// is indexed by the one bound that decides whether a distance is scoreable at
// all — the TLSH length quantile and the ssdeep block size — so a lookup
// touches only the buckets a digest can match instead of every entry.
func (db *FuzzyDB) Lookup(h FuzzyHashes, imphash string) []FuzzyMatch {
	if db == nil || len(db.entries) == 0 {
		return nil
	}
	var out []FuzzyMatch
	// Imphash is an exact match, so one map hit settles it.
	if imphash != "" {
		if i, ok := db.byImp[strings.ToLower(imphash)]; ok {
			e := db.entries[i]
			out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Line: e.Line})
		}
	}
	// TLSH: the length difference alone is scored 12 per step, so only the
	// length buckets within threshold/12 of the query can reach the
	// threshold. The length is measured on a circular scale, so the
	// neighbours are taken modulo 256.
	if h.TLSH != "" {
		if query, err := parseTLSH(h.TLSH); err == nil && query != nil {
			radius := db.tlshMax() / 12
			if radius < 1 {
				radius = 1
			}
			if radius > 128 {
				radius = 128
			}
			length := tlshLength(h.TLSH)
			var seen [256]bool
			for d := -radius; d <= radius; d++ {
				key := byte(int(length) + d)
				if seen[key] {
					continue
				}
				seen[key] = true
				for _, i := range db.byTLSH[key] {
					e := &db.entries[i]
					if e.parsed == nil {
						continue
					}
					if dist := query.Diff(e.parsed); dist <= db.tlshMax() {
						out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Distance: dist, Line: e.Line})
					}
				}
			}
		}
	}
	// ssdeep: only digests whose block sizes are equal or exactly double are
	// scored at all, so those buckets hold every candidate.
	if h.SSDeep != "" {
		bs := ssdeepBlockSize(h.SSDeep)
		keys := [3]int{bs, bs * 2, bs / 2}
		nkeys := 3
		switch {
		case bs == 0:
			nkeys = 1 // every candidate key is 0
		case bs%2 != 0:
			nkeys = 2 // a halved block size is not the entry's double
		}
		for _, key := range keys[:nkeys] {
			for _, i := range db.bySSDeep[key] {
				e := &db.entries[i]
				if s, err := ssdeep.Distance(h.SSDeep, e.Hash); err == nil && s >= db.ssdeepMin() {
					out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Score: s, Line: e.Line})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Closest first: exact imphash, then low TLSH distance, then high ssdeep score.
		ri, rj := out[i].rank(), out[j].rank()
		if ri != rj {
			return ri < rj
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// tlshLength returns the length quantile (the "L value") of a normalised
// 70-hex TLSH digest: the second header byte, whose nibbles the digest swaps.
// The library scores a length difference of n as 12n, so digests within a
// match threshold sit in the same or a neighbouring length bucket.
func tlshLength(digest string) byte {
	if len(digest) < 4 {
		return 0
	}
	hi, okHi := hexNibble(digest[2])
	lo, okLo := hexNibble(digest[3])
	if !okHi || !okLo {
		return 0
	}
	return hi | lo<<4 // swap the nibbles back
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ssdeepBlockSize returns the block size of a "blocksize:hash1:hash2"
// digest. The library scores only equal or exactly double block sizes, so
// the block size is the index key.
func ssdeepBlockSize(digest string) int {
	i := strings.IndexByte(digest, ':')
	if i <= 0 {
		return 0
	}
	n := 0
	for j := 0; j < i; j++ {
		c := digest[j]
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// rank orders matches by closeness on a common scale (lower is closer).
func (m FuzzyMatch) rank() int {
	switch m.Type {
	case FuzzyImphash:
		return 0
	case FuzzyTLSH:
		return 1 + m.Distance
	case FuzzySSDeep:
		return 1 + (100 - m.Score)
	}
	return 1000
}

// AddFuzzySignature validates a new entry against the existing database file
// and appends it, creating the file when absent.
func AddFuzzySignature(dbPath, typ, digest, threatName string) error {
	t, h, err := ValidateFuzzy(typ, digest)
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
	existing, err := LoadFuzzyDB(dbPath)
	switch {
	case err == nil:
		for _, e := range existing.entries {
			if e.Type == t && e.Hash == h {
				if e.ThreatName == name {
					return fmt.Errorf("%s %s is already in %s (line %d)", t, h, dbPath, e.Line)
				}
				return fmt.Errorf("%s %s is already in %s as %q (line %d); remove that line first to re-label it", t, h, dbPath, e.ThreatName, e.Line)
			}
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return err
	}
	f, err := os.OpenFile(dbPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("could not open fuzzy database for writing: %w", err)
	}
	defer f.Close()
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
	if _, err = fmt.Fprintf(f, "%s%s|%s|%s\n", prefix, t, h, name); err != nil {
		return err
	}
	return f.Close() // the deferred one is then a no-op; this one reports the flush
}

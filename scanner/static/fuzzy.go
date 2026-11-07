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
	warnings []string
	source   string
	skipped  int

	// TLSHMaxDistance and SSDeepMinScore override the defaults when non-zero.
	TLSHMaxDistance int
	SSDeepMinScore  int
}

// NewFuzzyDB returns an empty database.
func NewFuzzyDB() *FuzzyDB { return &FuzzyDB{byImp: map[string]int{}} }

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
// first. An empty digest of a given type simply skips that type. TLSH and
// ssdeep lookups are linear over the database; at the sizes a hand-curated
// fuzzy database reaches that is microseconds, and the design note in PLAN.md
// records that an indexed structure replaces it before the feed-driven
// databases of Phase 4 arrive.
func (db *FuzzyDB) Lookup(h FuzzyHashes, imphash string) []FuzzyMatch {
	if db == nil || len(db.entries) == 0 {
		return nil
	}
	var out []FuzzyMatch
	var query *tlsh.TLSH
	if h.TLSH != "" {
		query, _ = parseTLSH(h.TLSH)
	}
	for _, e := range db.entries {
		switch e.Type {
		case FuzzyTLSH:
			if query == nil || e.parsed == nil {
				continue
			}
			if d := query.Diff(e.parsed); d <= db.tlshMax() {
				out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Distance: d, Line: e.Line})
			}
		case FuzzySSDeep:
			if h.SSDeep == "" {
				continue
			}
			if s, err := ssdeep.Distance(h.SSDeep, e.Hash); err == nil && s >= db.ssdeepMin() {
				out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Score: s, Line: e.Line})
			}
		case FuzzyImphash:
			if imphash != "" && strings.EqualFold(imphash, e.Hash) {
				out = append(out, FuzzyMatch{Type: e.Type, Hash: e.Hash, ThreatName: e.ThreatName, Line: e.Line})
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

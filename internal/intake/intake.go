// Package intake parses threat-intelligence feeds into hash signatures, so the
// signature database is fed from machine-readable sources instead of being
// hand-typed. It is the parser half of Phase 4 intake; fetching is a thin,
// explicit step (see Fetch) and scheduling is an ops concern — the engine never
// phones home on its own.
//
// Four source formats ship, chosen because they are the canonical,
// machine-readable hash feeds named in the plan:
//
//   - STIX 2.1 bundles (indicator SDOs with a file:hashes pattern) — the
//     interoperable standard most TAXII servers speak.
//   - MISP event JSON (CIRCL, Luxembourg) — the canonical EU sync format.
//   - MalwareBazaar (abuse.ch) query/dump JSON — family-labelled samples.
//   - LOLDrivers — known-malicious driver hashes, the first real corpus to
//     replace the synthetic hashes.txt filler.
//
// Every parser returns normalized IOCs; validation, hash-type inference and the
// signature-database format live in the scanner package, so an IOC that the
// scanner would reject here is dropped with a reason rather than written.
package intake

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/s-b-repo/cau/scanner"
)

// maxFetchBytes caps a fetched feed so a hostile or runaway endpoint cannot
// exhaust memory. Intake feeds are hash lists, not disk images.
const maxFetchBytes = 256 << 20

// Fetch retrieves a feed over HTTP(S). It is only ever called from an explicit
// command — the engine never fetches on its own — and the response is bounded
// by maxFetchBytes. The caller passes the bytes to Parse.
func Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("intake: build request: %w", err)
	}
	req.Header.Set("User-Agent", "cau-intake")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intake: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intake: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return nil, fmt.Errorf("intake: read %s: %w", url, err)
	}
	if int64(len(data)) > maxFetchBytes {
		return nil, fmt.Errorf("intake: feed from %s exceeds the %d-byte cap", url, maxFetchBytes)
	}
	return data, nil
}

// IOC is one hash indicator extracted from a feed.
type IOC struct {
	// HashType is "MD5", "SHA1" or "SHA256" (scanner's canonical spelling).
	HashType string
	// Hash is lowercase hex.
	Hash string
	// ThreatName is the label written to the database. Feed labels that carry
	// '|' or line breaks are sanitized (the database format is pipe-delimited).
	ThreatName string
	// Source is the feed the IOC came from, for provenance in the label.
	Source string
}

// Format identifiers accepted by Parse.
const (
	FormatSTIX          = "stix"
	FormatMISP          = "misp"
	FormatMalwareBazaar = "malwarebazaar"
	FormatLOLDrivers    = "loldrivers"
)

// Formats lists the supported format ids, for help text and validation.
func Formats() []string {
	return []string{FormatSTIX, FormatMISP, FormatMalwareBazaar, FormatLOLDrivers}
}

// Parse dispatches to the parser for format. An unknown format is an error.
func Parse(format string, data []byte) ([]IOC, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case FormatSTIX:
		return ParseSTIX(data)
	case FormatMISP:
		return ParseMISP(data)
	case FormatMalwareBazaar:
		return ParseMalwareBazaar(data)
	case FormatLOLDrivers:
		return ParseLOLDrivers(data)
	default:
		return nil, fmt.Errorf("intake: unknown format %q (want one of %s)", format, strings.Join(Formats(), ", "))
	}
}

// ── STIX 2.1 ─────────────────────────────────────────────────────────────────

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	Labels      []string `json:"labels"`
}

// stixHashPattern matches a file:hashes comparison in a STIX pattern, e.g.
// [file:hashes.'SHA-256' = 'abc...'] or [file:hashes.MD5='...']. The hash name
// may be quoted or bare; the value is hex.
var stixHashPattern = regexp.MustCompile(`(?i)file:hashes\.'?([a-z0-9\-]+)'?\s*=\s*'([0-9a-f]+)'`)

// ParseSTIX extracts hash IOCs from a STIX 2.1 bundle. A bare list of SDOs (no
// bundle wrapper) is also accepted.
func ParseSTIX(data []byte) ([]IOC, error) {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		// Maybe it is a bare array of objects.
		var objs []stixObject
		if err2 := json.Unmarshal(data, &objs); err2 != nil {
			return nil, fmt.Errorf("intake: STIX parse: %w", err)
		}
		bundle.Objects = objs
	}
	var out []IOC
	for _, o := range bundle.Objects {
		if !strings.EqualFold(o.Type, "indicator") || o.Pattern == "" {
			continue
		}
		name := firstNonEmpty(o.Name, o.Description, strings.Join(o.Labels, ","), "STIX indicator")
		for _, m := range stixHashPattern.FindAllStringSubmatch(o.Pattern, -1) {
			if ioc, ok := newIOC(m[1], m[2], name, "stix"); ok {
				out = append(out, ioc)
			}
		}
	}
	return dedupe(out), nil
}

// ── MISP event JSON ──────────────────────────────────────────────────────────

type mispDoc struct {
	Event   *mispEvent  `json:"Event"`
	Events  []mispEvent `json:"Events"`
	Objects []mispObj   `json:"Object"` // a bare object list
	Attrs   []mispAttr  `json:"Attribute"`
}

type mispEvent struct {
	Info      string     `json:"info"`
	Attribute []mispAttr `json:"Attribute"`
	Object    []mispObj  `json:"Object"`
}

type mispObj struct {
	Attribute []mispAttr `json:"Attribute"`
}

type mispAttr struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ParseMISP extracts hash attributes from a MISP event (or event list). Hash
// attribute types md5/sha1/sha256 are taken directly; composite "filename|hash"
// types (e.g. "filename|sha256") take the hash half.
func ParseMISP(data []byte) ([]IOC, error) {
	var doc mispDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("intake: MISP parse: %w", err)
	}
	var out []IOC
	collect := func(ev mispEvent) {
		label := firstNonEmpty(ev.Info, "MISP event")
		add := func(attrs []mispAttr) {
			for _, a := range attrs {
				if ioc, ok := mispAttrToIOC(a, label); ok {
					out = append(out, ioc)
				}
			}
		}
		add(ev.Attribute)
		for _, o := range ev.Object {
			add(o.Attribute)
		}
	}
	if doc.Event != nil {
		collect(*doc.Event)
	}
	for _, ev := range doc.Events {
		collect(ev)
	}
	// A bare attribute/object list (some exports omit the Event wrapper).
	collect(mispEvent{Info: "MISP export", Attribute: doc.Attrs, Object: doc.Objects})
	return dedupe(out), nil
}

func mispAttrToIOC(a mispAttr, label string) (IOC, bool) {
	typ := strings.ToLower(strings.TrimSpace(a.Type))
	val := strings.TrimSpace(a.Value)
	// Composite types: "filename|sha256" with value "name|hash".
	if i := strings.IndexByte(typ, '|'); i >= 0 {
		typ = typ[i+1:]
		if j := strings.LastIndexByte(val, '|'); j >= 0 {
			val = val[j+1:]
		}
	}
	switch typ {
	case "md5", "sha1", "sha256":
		return newIOC(typ, val, label, "misp")
	}
	return IOC{}, false
}

// ── MalwareBazaar ──────────────────────────────────────────────────────────

type mbDoc struct {
	QueryStatus string     `json:"query_status"`
	Data        []mbSample `json:"data"`
}

type mbSample struct {
	SHA256    string `json:"sha256_hash"`
	SHA1      string `json:"sha1_hash"`
	MD5       string `json:"md5_hash"`
	Signature string `json:"signature"`
	FileName  string `json:"file_name"`
	FileType  string `json:"file_type"`
}

// ParseMalwareBazaar extracts samples from a MalwareBazaar query/dump JSON
// response. Each sample contributes every hash it carries, labelled with its
// malware family signature when present.
func ParseMalwareBazaar(data []byte) ([]IOC, error) {
	var doc mbDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("intake: MalwareBazaar parse: %w", err)
	}
	if doc.QueryStatus != "" && doc.QueryStatus != "ok" {
		return nil, fmt.Errorf("intake: MalwareBazaar query_status %q", doc.QueryStatus)
	}
	var out []IOC
	for _, s := range doc.Data {
		label := firstNonEmpty(s.Signature, s.FileName, "MalwareBazaar")
		for typ, val := range map[string]string{"sha256": s.SHA256, "sha1": s.SHA1, "md5": s.MD5} {
			if ioc, ok := newIOC(typ, val, label, "malwarebazaar"); ok {
				out = append(out, ioc)
			}
		}
	}
	return dedupe(out), nil
}

// ── LOLDrivers ─────────────────────────────────────────────────────────────

type lolDriver struct {
	ID                     string         `json:"Id"`
	Category               string         `json:"Category"`
	Tags                   []string       `json:"Tags"`
	KnownVulnerableSamples []lolDriverSmp `json:"KnownVulnerableSamples"`
}

type lolDriverSmp struct {
	SHA256   string `json:"SHA256"`
	SHA1     string `json:"SHA1"`
	MD5      string `json:"MD5"`
	FileName string `json:"Filename"`
}

// ParseLOLDrivers extracts the known-vulnerable driver sample hashes from the
// LOLDrivers catalog (a JSON array of driver records).
func ParseLOLDrivers(data []byte) ([]IOC, error) {
	var drivers []lolDriver
	if err := json.Unmarshal(data, &drivers); err != nil {
		return nil, fmt.Errorf("intake: LOLDrivers parse: %w", err)
	}
	var out []IOC
	for _, d := range drivers {
		for _, s := range d.KnownVulnerableSamples {
			label := "LOLDriver: " + firstNonEmpty(s.FileName, firstNonEmpty(d.Tags...), d.Category, d.ID, "unknown")
			for typ, val := range map[string]string{"sha256": s.SHA256, "sha1": s.SHA1, "md5": s.MD5} {
				if ioc, ok := newIOC(typ, val, label, "loldrivers"); ok {
					out = append(out, ioc)
				}
			}
		}
	}
	return dedupe(out), nil
}

// ── normalization / application ──────────────────────────────────────────────

// newIOC validates a raw (type, value) pair against the scanner's rules and
// returns a normalized IOC, or ok=false when it is unusable (empty, wrong
// length, non-hex). The hash type is inferred from length when typ is blank or
// unrecognized, so a feed that mislabels a digest is still ingested correctly.
func newIOC(typ, val, name, source string) (IOC, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return IOC{}, false
	}
	t := canonicalType(typ)
	if t == "" {
		inferred, ok := scanner.HashTypeFor(val)
		if !ok {
			return IOC{}, false
		}
		t = inferred
	}
	nt, nh, err := scanner.ValidateHash(t, val)
	if err != nil {
		return IOC{}, false
	}
	return IOC{HashType: nt, Hash: nh, ThreatName: sanitizeName(name), Source: source}, true
}

func canonicalType(typ string) string {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(typ), "-", "")) {
	case "MD5":
		return "MD5"
	case "SHA1":
		return "SHA1"
	case "SHA256":
		return "SHA256"
	}
	return ""
}

// sanitizeName makes a feed label safe for the pipe-delimited database format
// and bounds its length so a pathological description cannot bloat a line.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer("|", "/", "\r", " ", "\n", " ", "\t", " ").Replace(name)
	name = strings.Join(strings.Fields(name), " ")
	const max = 120
	if len(name) > max {
		name = strings.TrimSpace(name[:max])
	}
	if name == "" {
		name = "intel-feed"
	}
	return name
}

// dedupe collapses IOCs with the same hash (first label wins), and returns them
// in a stable order (by hash) so output and tests are deterministic.
func dedupe(in []IOC) []IOC {
	seen := make(map[string]struct{}, len(in))
	var out []IOC
	for _, i := range in {
		if _, dup := seen[i.Hash]; dup {
			continue
		}
		seen[i.Hash] = struct{}{}
		out = append(out, i)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Hash < out[b].Hash })
	return out
}

// ApplyResult reports what Apply did.
type ApplyResult struct {
	Added      int
	Skipped    int // already present with the same (or a conflicting) label
	Signatures []scanner.Signature
}

// Apply filters iocs against an existing database: an IOC whose hash is already
// present is skipped (the database is the source of truth and never re-labels
// on intake), and the rest are returned as the signatures to add. It does not
// mutate db or touch disk — the caller writes them.
func Apply(db *scanner.SignatureDB, iocs []IOC) ApplyResult {
	var res ApplyResult
	for _, i := range iocs {
		if db != nil {
			if _, dup := db.Lookup(i.Hash); dup {
				res.Skipped++
				continue
			}
		}
		res.Added++
		res.Signatures = append(res.Signatures, scanner.Signature{HashType: i.HashType, Hash: i.Hash, ThreatName: i.ThreatName})
	}
	return res
}

// Render writes signatures in the database's `TYPE|hash|name` line format. It
// is the exact format LoadSignatures reads, so an intake run can be appended to
// hashes.txt verbatim.
func Render(sigs []scanner.Signature) []byte {
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	for _, s := range sigs {
		fmt.Fprintf(w, "%s|%s|%s\n", s.HashType, s.Hash, s.ThreatName)
	}
	w.Flush()
	return b.Bytes()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ParseMalwareBazaarCSV is a convenience for the abuse.ch full CSV dump, whose
// columns are documented with a comment header. It reads the sha256_hash and
// signature columns. Kept separate from the JSON path because the dump is a
// different shape than the API response.
func ParseMalwareBazaarCSV(data []byte) ([]IOC, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("intake: MalwareBazaar CSV parse: %w", err)
	}
	var out []IOC
	// The abuse.ch dump column order: first_seen, sha256_hash, md5_hash,
	// sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, ...
	for _, rec := range records {
		if len(rec) < 9 {
			continue
		}
		label := firstNonEmpty(strings.Trim(rec[8], `" `), strings.Trim(rec[5], `" `), "MalwareBazaar")
		for _, idx := range []struct {
			col int
			typ string
		}{{1, "sha256"}, {2, "md5"}, {3, "sha1"}} {
			if ioc, ok := newIOC(idx.typ, strings.Trim(rec[idx.col], `" `), label, "malwarebazaar"); ok {
				out = append(out, ioc)
			}
		}
	}
	return dedupe(out), nil
}

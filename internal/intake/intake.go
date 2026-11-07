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
	// Confidence is what the source itself states about the indicator, never
	// an engine guess: for STIX the indicator's confidence property on the
	// specification's None/Low/Med/High scale ("none", "low", "medium",
	// "high"); ConfidenceUnstated for a source that states nothing, which is
	// every other format today.
	Confidence string
	// RetrievedAt is when the feed was read. The parsers leave it zero; the
	// caller that read the bytes stamps it (see Stamp).
	RetrievedAt time.Time
	// Origin is where the bytes came from: a URL, a TAXII collection, a file
	// path or "stdin". Set by Stamp.
	Origin string
	// MISPClusters are the MISP galaxy-cluster tags the source attached to
	// the indicator or its event (`misp-galaxy:<galaxy>="<value>"`), kept
	// verbatim: actor, tool and family tagging in the CIRCL vocabulary.
	MISPClusters []string
	// MalpediaFamily is the Malpedia family name, when the source tagged one
	// (`misp-galaxy:malpedia="<family>"`). Empty otherwise: the engine does
	// not map a feed's own free-text label onto a Malpedia name.
	MalpediaFamily string
}

// maxClusterTags and maxTagLen bound what a feed can attach to one indicator.
const (
	maxClusterTags = 16
	maxTagLen      = 160
)

// galaxyTag matches a MISP galaxy-cluster tag and captures the galaxy and the
// cluster value.
var galaxyTag = regexp.MustCompile(`^misp-galaxy:([a-z0-9\-]+)="([^"]{1,140})"$`)

// applyTags records the galaxy-cluster tags among names on the IOC. Tags that
// are not galaxy clusters (TLP markings, workflow state, free text) are not
// kept: they are not a naming scheme a consumer can pivot on.
func (i *IOC) applyTags(names []string) {
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if len(name) > maxTagLen || strings.ContainsAny(name, "\r\n\t|") {
			continue
		}
		m := galaxyTag.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		dup := false
		for _, have := range i.MISPClusters {
			if have == name {
				dup = true
				break
			}
		}
		if !dup && len(i.MISPClusters) < maxClusterTags {
			i.MISPClusters = append(i.MISPClusters, name)
		}
		if m[1] == "malpedia" && i.MalpediaFamily == "" {
			i.MalpediaFamily = m[2]
		}
	}
}

// ConfidenceUnstated marks an IOC whose source states no confidence.
const ConfidenceUnstated = "unstated"

// Stamp records when and from where a parsed feed was read on every IOC.
func Stamp(iocs []IOC, origin string, retrieved time.Time) {
	for i := range iocs {
		iocs[i].Origin = origin
		iocs[i].RetrievedAt = retrieved.UTC()
	}
}

// ProvenanceRecord is the audit record of one consumed indicator: what it is,
// which feed and origin it came from, when it was retrieved and how confident
// the source said it was. One JSON object per line; the signature database
// itself stays the three-field format it has always been.
type ProvenanceRecord struct {
	HashType    string `json:"hash_type"`
	Hash        string `json:"hash"`
	ThreatName  string `json:"threat_name"`
	Source      string `json:"source"`
	Origin      string `json:"origin,omitempty"`
	RetrievedAt string `json:"retrieved_at,omitempty"`
	Confidence  string `json:"confidence"`
	// MISPClusters and MalpediaFamily carry the source's own galaxy-cluster
	// tagging, so a consumer can name the family or actor in the CIRCL and
	// Fraunhofer FKIE vocabularies instead of this engine's label.
	MISPClusters   []string `json:"misp_clusters,omitempty"`
	MalpediaFamily string   `json:"malpedia_family,omitempty"`
}

// Provenance renders the provenance records of iocs as JSON lines.
func Provenance(iocs []IOC) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, i := range iocs {
		rec := ProvenanceRecord{
			HashType: i.HashType, Hash: i.Hash, ThreatName: i.ThreatName,
			Source: i.Source, Origin: i.Origin, Confidence: i.Confidence,
			MISPClusters: i.MISPClusters, MalpediaFamily: i.MalpediaFamily,
		}
		if rec.Confidence == "" {
			rec.Confidence = ConfidenceUnstated
		}
		if !i.RetrievedAt.IsZero() {
			rec.RetrievedAt = i.RetrievedAt.UTC().Format(time.RFC3339)
		}
		if err := enc.Encode(rec); err != nil {
			return nil, fmt.Errorf("intake: encode provenance: %w", err)
		}
	}
	return b.Bytes(), nil
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
	Revoked     bool     `json:"revoked"`
	ValidUntil  string   `json:"valid_until"`
	Confidence  *int     `json:"confidence"`
	// IndicatorTypes is the STIX open vocabulary saying what the indicator
	// indicates ("malicious-activity", "anomalous-activity", "benign", ...).
	IndicatorTypes []string `json:"indicator_types"`
}

// stixIndicatesMalice reports whether an indicator's declared types make it
// fit to become a hash signature. An indicator that declares no type is taken
// as before. One that declares types is taken only if it says the thing is
// malicious or compromised: "benign" is the producer saying it is not a
// threat, and "anomalous-activity" alone is a suspicion, which is what this
// engine's own STIX export uses for a file that only crossed a heuristic. A
// hash signature is the engine's most confident tier, so a suspicion must
// not be promoted into one by a round trip through a feed.
func stixIndicatesMalice(types []string) bool {
	if len(types) == 0 {
		return true
	}
	malicious := false
	for _, t := range types {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "benign":
			return false
		case "malicious-activity", "compromised":
			malicious = true
		}
	}
	return malicious
}

// stixConfidence maps a STIX confidence value (0-100) onto the None/Low/Med/
// High scale of STIX 2.1 Appendix A. An absent property is unstated.
func stixConfidence(c *int) string {
	switch {
	case c == nil:
		return ConfidenceUnstated
	case *c <= 0:
		return "none"
	case *c < 30:
		return "low"
	case *c < 70:
		return "medium"
	default:
		return "high"
	}
}

// stixNow is the clock valid_until is compared against (a variable for tests).
var stixNow = time.Now

// stixHashPattern matches a file:hashes comparison in a STIX pattern, e.g.
// [file:hashes.'SHA-256' = 'abc...'] or [file:hashes.MD5='...']. The hash name
// may be quoted or bare; the value is hex.
var stixHashPattern = regexp.MustCompile(`(?i)file:hashes\.'?([a-z0-9\-]+)'?\s*=\s*'([0-9a-f]+)'`)

// ParseSTIX extracts hash IOCs from a STIX 2.1 bundle. A bare list of SDOs (no
// bundle wrapper) is also accepted. An indicator its producer has withdrawn
// (revoked) or that has expired (valid_until in the past) is not ingested:
// the producer has said it no longer identifies a threat, and a signature
// database that keeps it is a false-positive source. So is an indicator whose
// declared indicator_types do not say "malicious" (see stixIndicatesMalice).
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
		if !strings.EqualFold(o.Type, "indicator") || o.Pattern == "" || o.Revoked || !stixIndicatesMalice(o.IndicatorTypes) {
			continue
		}
		if o.ValidUntil != "" {
			if until, err := time.Parse(time.RFC3339Nano, o.ValidUntil); err == nil && until.Before(stixNow()) {
				continue
			}
		}
		name := firstNonEmpty(o.Name, o.Description, strings.Join(o.Labels, ","), "STIX indicator")
		for _, m := range stixHashPattern.FindAllStringSubmatch(o.Pattern, -1) {
			if ioc, ok := newIOC(m[1], m[2], name, "stix"); ok {
				ioc.Confidence = stixConfidence(o.Confidence)
				ioc.applyTags(o.Labels)
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
	Tag       []mispTag  `json:"Tag"`
}

type mispTag struct {
	Name string `json:"name"`
}

func tagNames(tags []mispTag) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, t.Name)
	}
	return out
}

type mispObj struct {
	Attribute []mispAttr `json:"Attribute"`
}

type mispAttr struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	// ToIDS is MISP's "use this for detection" flag. An attribute exported
	// with to_ids false is context (a legitimate file seen in the incident, a
	// decoy), which its producer has said must not become a signature. A
	// document that omits the flag is taken as before.
	ToIDS *bool `json:"to_ids"`
	// Tag carries attribute-level tags; event-level tags apply to every
	// attribute of the event.
	Tag []mispTag `json:"Tag"`
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
		eventTags := tagNames(ev.Tag)
		add := func(attrs []mispAttr) {
			for _, a := range attrs {
				if ioc, ok := mispAttrToIOC(a, label); ok {
					// The attribute's own tags first: they are the more
					// specific statement when the two disagree.
					ioc.applyTags(tagNames(a.Tag))
					ioc.applyTags(eventTags)
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
	if a.ToIDS != nil && !*a.ToIDS {
		return IOC{}, false
	}
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
	return IOC{HashType: nt, Hash: nh, ThreatName: sanitizeName(name), Source: source, Confidence: ConfidenceUnstated}, true
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
	// Accepted are the IOCs behind Signatures, index-aligned, with their
	// provenance (source, origin, retrieved-at, confidence).
	Accepted []IOC
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
		res.Accepted = append(res.Accepted, i)
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

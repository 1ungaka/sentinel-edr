package report

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/attack"
)

// STIX 2.1 output: one bundle per run, so a threat-intelligence platform
// (Security Onion, OpenCTI, MISP, anything that reads STIX) can consume a
// scan's findings as indicators. The finding set is the OCSF one: the files
// the engine reports as suspicious or malicious. Per finding the bundle holds
//
//   - an indicator whose pattern is the file's digests and nothing else;
//   - a relationship "indicates" to an attack-pattern per ATT&CK technique;
//   - a relationship "indicates" to a malware object per threat the finding
//     names: a hash-signature threat (is_family false) or a family a YARA
//     rule's author declared (is_family true);
//
// and one identity for the producer that every object is created_by_ref.
//
// What is deliberately not there:
//
//   - A file name or path in a pattern. Both are chosen by whoever dropped the
//     file; a pattern is something a consumer executes. The path is carried in
//     the indicator's description, as a JSON string, and nowhere else.
//   - An indicator for a finding with no digest. Without one the only thing
//     left to match on is the name, so the finding is not expressible as an
//     indicator and is left out (the OCSF and JSON formats carry it).
//   - A malware object for a fuzzy-hash similarity. "Resembles a known
//     sample" is not "is that sample", and STIX has no weaker way to say it.
//   - A confidence the engine did not state, a malware type, or a family
//     nobody named.
//
// Ids are UUIDv5 over a fixed namespace, so the same finding is the same
// object in every run and a platform updates rather than duplicates. The
// reference objects (identity, attack-pattern, malware) also carry a fixed
// created/modified: their content is a function of their key, and STIX
// forbids two versions of one id that differ in created. An indicator and its
// relationships are stamped with the reporter's clock; rescanning the same
// file therefore re-issues the indicator under the same id with a new
// created, which a strict version check would flag and which is the price of
// a scanner that keeps no state between runs.
//
// The document is one line unless indented, like the otlp format.
const (
	// STIXVersion is the specification version of every object written.
	STIXVersion = "2.1"

	// stixNamespaceName is hashed (UUIDv5, URL namespace) into the namespace
	// every object id is derived under. STIX reserves its own namespace for
	// cyber-observables and requires a producer's deterministic SDO ids to use
	// a different one. Changing this string renames every object this
	// producer has ever published; a test pins the resulting UUID.
	stixNamespaceName = "https://github.com/s-b-repo/cau#stix-2.1"

	// stixDefinitionTime is created/modified of the reference objects. It is
	// the date their definitions were written, not a clock reading: an object
	// whose id and content are both derived from a key must not change
	// between runs.
	stixDefinitionTime = "2026-11-06T00:00:00.000Z"

	stixTimeLayout = "2006-01-02T15:04:05.000Z"

	// The None/Low/Med/High confidence scale of STIX 2.1 Appendix A.
	stixConfidenceLow    = 15
	stixConfidenceMedium = 50
	stixConfidenceHigh   = 85
)

// uuidNamespaceURL is the RFC 4122 namespace for names that are URLs.
var uuidNamespaceURL = [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}

var stixNamespace = uuidV5(uuidNamespaceURL, stixNamespaceName)

// uuidV5 is the RFC 4122 name-based UUID (SHA-1).
func uuidV5(namespace [16]byte, name string) [16]byte {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))
	var u [16]byte
	copy(u[:], h.Sum(nil))
	u[6] = u[6]&0x0f | 0x50 // version 5
	u[8] = u[8]&0x3f | 0x80 // RFC 4122 variant
	return u
}

func uuidString(u [16]byte) string {
	s := hex.EncodeToString(u[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// stixID derives an object id from its type and a key. The parts are joined
// with NUL, which no key contains, so two different (type, parts) tuples
// cannot collide by concatenation.
func stixID(typ string, parts ...string) string {
	return typ + "--" + uuidString(uuidV5(stixNamespace, typ+"\x00"+strings.Join(parts, "\x00")))
}

// STIXReporter renders a run's findings as a STIX 2.1 bundle.
type STIXReporter struct {
	cfg config
}

// NewSTIXReporter builds a reporter from the shared options.
func NewSTIXReporter(opts ...Option) *STIXReporter {
	return &STIXReporter{cfg: buildConfig(opts)}
}

type stixBundle struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Objects []any  `json:"objects"`
}

// stixCommon is the properties every SDO and SRO written here carries.
type stixCommon struct {
	Type         string `json:"type"`
	SpecVersion  string `json:"spec_version"`
	ID           string `json:"id"`
	CreatedByRef string `json:"created_by_ref,omitempty"`
	Created      string `json:"created"`
	Modified     string `json:"modified"`
}

type stixIdentity struct {
	stixCommon
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
}

type stixExternalReference struct {
	SourceName string `json:"source_name"`
	URL        string `json:"url,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

type stixIndicator struct {
	stixCommon
	Name               string                  `json:"name"`
	Description        string                  `json:"description,omitempty"`
	IndicatorTypes     []string                `json:"indicator_types"`
	Pattern            string                  `json:"pattern"`
	PatternType        string                  `json:"pattern_type"`
	PatternVersion     string                  `json:"pattern_version"`
	ValidFrom          string                  `json:"valid_from"`
	Confidence         *int                    `json:"confidence,omitempty"`
	Labels             []string                `json:"labels,omitempty"`
	ExternalReferences []stixExternalReference `json:"external_references,omitempty"`
}

type stixAttackPattern struct {
	stixCommon
	Name               string                  `json:"name"`
	ExternalReferences []stixExternalReference `json:"external_references"`
}

type stixMalware struct {
	stixCommon
	Name     string `json:"name"`
	IsFamily bool   `json:"is_family"`
}

type stixRelationship struct {
	stixCommon
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

// Write encodes the bundle to w.
func (r *STIXReporter) Write(w io.Writer, in Input) error {
	if err := writeJSONLine(w, r.Build(in), r.cfg.indent); err != nil {
		return fmt.Errorf("report: encode stix: %w", err)
	}
	return nil
}

// stixNamedThreat is one malware object a finding points at.
type stixNamedThreat struct {
	name     string
	isFamily bool
}

// Build assembles the bundle without encoding it. Objects are ordered
// identity, attack-patterns (by technique id), malware (by name), indicators
// (in scan order), relationships (in scan order). STIX gives the order no
// meaning; it is fixed so the document is reproducible.
//
// A run with no finding yields a bundle holding the identity alone. STIX
// forbids an empty list, so the alternative is a bundle with no objects
// property at all: a second document shape for consumers to handle, saying
// nothing more. The identity keeps the shape constant and tells a consumer
// whose (empty) feed it just read.
func (r *STIXReporter) Build(in Input) stixBundle {
	c := r.cfg
	doc := c.buildDocument(in)
	now := c.now().UTC()
	stamp := now.Format(stixTimeLayout)

	identity := stixIdentity{
		stixCommon: stixCommon{
			Type: "identity", SpecVersion: STIXVersion, ID: stixID("identity", c.toolName),
			Created: stixDefinitionTime, Modified: stixDefinitionTime,
		},
		Name:          c.toolName,
		IdentityClass: "system",
	}
	reference := func(typ string, key ...string) stixCommon {
		return stixCommon{
			Type: typ, SpecVersion: STIXVersion, ID: stixID(typ, key...), CreatedByRef: identity.ID,
			Created: stixDefinitionTime, Modified: stixDefinitionTime,
		}
	}

	techniques := map[string]stixAttackPattern{}
	threats := map[string]stixMalware{}
	var indicators, relationships []any
	seenIndicator := map[string]bool{}
	seenRelationship := map[string]bool{}
	indicates := func(indicatorID, targetID string) {
		id := stixID("relationship", indicatorID, "indicates", targetID)
		if seenRelationship[id] {
			return
		}
		seenRelationship[id] = true
		relationships = append(relationships, stixRelationship{
			stixCommon: stixCommon{
				Type: "relationship", SpecVersion: STIXVersion, ID: id, CreatedByRef: identity.ID,
				Created: stamp, Modified: stamp,
			},
			RelationshipType: "indicates", SourceRef: indicatorID, TargetRef: targetID,
		})
	}

	for _, f := range doc.Files {
		if f.Verdict != JSONVerdictSuspicious && f.Verdict != JSONVerdictMalicious {
			continue
		}
		pattern := stixFilePattern(f.Hashes)
		if pattern == "" {
			continue // no digest: nothing but a name to match on
		}
		fi := c.ocsfFinding(doc, f, now.UnixMilli())
		ind := stixIndicator{
			stixCommon: stixCommon{
				Type: "indicator", SpecVersion: STIXVersion, ID: stixID("indicator", fi.FindingInfo.UID),
				CreatedByRef: identity.ID, Created: stamp, Modified: stamp,
			},
			Name:           c.boundedMessage(fi.FindingInfo.Title),
			Description:    fi.FindingInfo.Desc,
			IndicatorTypes: []string{"anomalous-activity"},
			Pattern:        pattern,
			PatternType:    "stix",
			PatternVersion: STIXVersion,
			ValidFrom:      stamp,
			ExternalReferences: []stixExternalReference{
				{SourceName: sinkSlug, ExternalID: fi.FindingInfo.UID},
			},
		}
		if seenIndicator[ind.ID] {
			continue // the same content at the same path, listed twice
		}
		seenIndicator[ind.ID] = true
		if f.Verdict == JSONVerdictMalicious {
			ind.IndicatorTypes = []string{"malicious-activity"}
		}
		switch fi.ConfidenceID {
		case 1:
			ind.Confidence = intPtr(stixConfidenceLow)
		case 2:
			ind.Confidence = intPtr(stixConfidenceMedium)
		case 3:
			ind.Confidence = intPtr(stixConfidenceHigh)
		}
		for _, d := range fi.FindingInfo.Types {
			ind.Labels = append(ind.Labels, "detector:"+d)
		}
		indicators = append(indicators, ind)

		for _, a := range fi.FindingInfo.Attacks {
			id := strings.TrimSpace(a.Technique.UID)
			// A rule's meta block can put anything in its technique field;
			// only something shaped like a technique id is attributed to
			// MITRE ATT&CK.
			if !attack.ValidID(id) {
				continue
			}
			ap, ok := techniques[id]
			if !ok {
				name := attack.Name(id)
				if name == "" {
					name = id // attack-pattern requires a name; the id is the honest one
				}
				ap = stixAttackPattern{
					stixCommon: reference("attack-pattern", id),
					Name:       name,
					ExternalReferences: []stixExternalReference{{
						SourceName: "mitre-attack",
						URL:        "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/",
						ExternalID: id,
					}},
				}
				techniques[id] = ap
			}
			indicates(ind.ID, ap.ID)
		}
		for _, t := range stixThreats(f) {
			kind := "sample"
			if t.isFamily {
				kind = "family"
			}
			key := kind + "\x00" + t.name
			mw, ok := threats[key]
			if !ok {
				mw = stixMalware{stixCommon: reference("malware", kind, t.name), Name: t.name, IsFamily: t.isFamily}
				threats[key] = mw
			}
			indicates(ind.ID, mw.ID)
		}
	}

	objects := []any{identity}
	ids := []string{identity.ID}
	for _, k := range sortedMapKeys(techniques) {
		objects, ids = append(objects, techniques[k]), append(ids, techniques[k].ID)
	}
	for _, k := range sortedMapKeys(threats) {
		objects, ids = append(objects, threats[k]), append(ids, threats[k].ID)
	}
	for _, o := range indicators {
		objects, ids = append(objects, o), append(ids, o.(stixIndicator).ID)
	}
	for _, o := range relationships {
		objects, ids = append(objects, o), append(ids, o.(stixRelationship).ID)
	}
	// The bundle id names this set of objects: the same findings give the same
	// bundle, a different set a different one.
	return stixBundle{Type: "bundle", ID: stixID("bundle", ids...), Objects: objects}
}

func intPtr(n int) *int { return &n }

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// stixThreats lists what a finding names: the hash-signature threat, which
// labels one known sample (is_family false), and each family a matched YARA
// rule's author declared in its meta block (is_family true). Nothing is
// inferred: a rule without a family meta names no family.
func stixThreats(f File) []stixNamedThreat {
	var out []stixNamedThreat
	seen := map[stixNamedThreat]bool{}
	add := func(name string, isFamily bool) {
		t := stixNamedThreat{name: strings.TrimSpace(name), isFamily: isFamily}
		if t.name != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if f.HashMatch != nil {
		add(f.HashMatch.Threat, false)
	}
	for _, h := range f.Yara {
		for _, m := range h.Meta {
			if m.Key == "family" {
				add(m.Value, true)
			}
		}
	}
	return out
}

// stixFilePattern builds the indicator pattern from the digests a file has:
//
//	[file:hashes.'SHA-256' = '...' OR file:hashes.MD5 = '...' OR file:hashes.'SHA-1' = '...']
//
// Only a digest that is exactly the lowercase hex of its algorithm's length is
// used, so a digest the configuration truncated can never become an
// indicator for some other file. "" means the file has no usable digest.
func stixFilePattern(h *Hashes) string {
	if h == nil {
		return ""
	}
	var terms []string
	add := func(key, digest string, hexLen int) {
		if isLowerHex(digest, hexLen) {
			terms = append(terms, "file:hashes."+key+" = "+stixQuote(digest))
		}
	}
	// A hash name with a hyphen must be quoted in a STIX object path.
	add("'SHA-256'", h.SHA256, 64)
	add("MD5", h.MD5, 32)
	add("'SHA-1'", h.SHA1, 40)
	if len(terms) == 0 {
		return ""
	}
	return "[" + strings.Join(terms, " OR ") + "]"
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// stixQuote renders a STIX pattern string literal: single-quoted, with
// backslash and single quote escaped by a backslash. Every value that reaches
// a pattern today is validated hex and needs no escaping; the literal is still
// built here so that no pattern is ever assembled by bare concatenation.
func stixQuote(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 2)
	sb.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' || s[i] == '\'' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('\'')
	return sb.String()
}

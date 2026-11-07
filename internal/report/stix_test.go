package report

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/intake"
	"github.com/s-b-repo/cau/scanner"
)

// ── an independent STIX 2.1 reader ───────────────────────────────────────────
//
// Written against the specification's required properties, not against the
// encoder's structs: it decodes into plain maps and checks what section 3
// (common properties), section 4 (SDOs), section 5 (SROs) and section 8
// (bundle) require of each object type this producer emits.

var stixIDShape = regexp.MustCompile(`^([a-z][a-z0-9-]*)--[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type stixDoc struct {
	id      string
	objects []map[string]any
	byID    map[string]map[string]any
}

func (d stixDoc) ofType(typ string) []map[string]any {
	var out []map[string]any
	for _, o := range d.objects {
		if o["type"] == typ {
			out = append(out, o)
		}
	}
	return out
}

func stixTimestamp(t *testing.T, o map[string]any, key string) time.Time {
	t.Helper()
	s, ok := o[key].(string)
	if !ok {
		t.Fatalf("%v: %s is required and must be a string", o["id"], key)
	}
	if !strings.HasSuffix(s, "Z") {
		t.Errorf("%v: %s = %q is not in UTC with a Z suffix", o["id"], key, s)
	}
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("%v: %s = %q is not an RFC 3339 timestamp: %v", o["id"], key, s, err)
	}
	return ts
}

func stixString(t *testing.T, o map[string]any, key string) string {
	t.Helper()
	s, ok := o[key].(string)
	if !ok || s == "" {
		t.Fatalf("%v (%v): %s is required and must be a non-empty string, got %v", o["id"], o["type"], key, o[key])
	}
	return s
}

// noEmptyValues enforces two rules that hold everywhere in STIX: an empty
// list is prohibited, and a property is omitted rather than null.
func noEmptyValues(t *testing.T, where string, v any) {
	t.Helper()
	switch x := v.(type) {
	case nil:
		t.Errorf("%s is null", where)
	case []any:
		if len(x) == 0 {
			t.Errorf("%s is an empty list, which STIX prohibits", where)
		}
		for _, e := range x {
			noEmptyValues(t, where+"[]", e)
		}
	case map[string]any:
		for k, e := range x {
			noEmptyValues(t, where+"."+k, e)
		}
	}
}

var stixIndicatorTypes = map[string]bool{
	"anomalous-activity": true, "anonymization": true, "benign": true, "compromised": true,
	"malicious-activity": true, "attribution": true, "unknown": true,
}

func readSTIX(t *testing.T, raw []byte) stixDoc {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	noEmptyValues(t, "bundle", bundle)
	if bundle["type"] != "bundle" {
		t.Fatalf("top-level type = %v, want bundle", bundle["type"])
	}
	for k := range bundle {
		if k != "type" && k != "id" && k != "objects" {
			t.Errorf("a 2.1 bundle has only type, id and objects; found %q", k)
		}
	}
	d := stixDoc{byID: map[string]map[string]any{}}
	d.id = stixString(t, bundle, "id")
	if m := stixIDShape.FindStringSubmatch(d.id); m == nil || m[1] != "bundle" {
		t.Errorf("bundle id %q is not bundle--<uuid>", d.id)
	}
	list, ok := bundle["objects"].([]any)
	if !ok {
		t.Fatalf("objects is not a list: %v", bundle["objects"])
	}
	for _, e := range list {
		o, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("an object is not a JSON object: %v", e)
		}
		typ := stixString(t, o, "type")
		id := stixString(t, o, "id")
		if m := stixIDShape.FindStringSubmatch(id); m == nil || m[1] != typ {
			t.Errorf("id %q is not %s--<uuid>", id, typ)
		}
		if d.byID[id] != nil {
			t.Errorf("id %s appears twice in the bundle", id)
		}
		if o["spec_version"] != "2.1" {
			t.Errorf("%s: spec_version = %v, want 2.1", id, o["spec_version"])
		}
		created, modified := stixTimestamp(t, o, "created"), stixTimestamp(t, o, "modified")
		if modified.Before(created) {
			t.Errorf("%s: modified %v is before created %v", id, modified, created)
		}
		d.objects = append(d.objects, o)
		d.byID[id] = o
	}

	identities := d.ofType("identity")
	if len(identities) != 1 {
		t.Fatalf("want exactly one identity, got %d", len(identities))
	}
	producer := identities[0]["id"]
	for _, o := range d.objects {
		id := o["id"]
		if o["type"] != "identity" && o["created_by_ref"] != producer {
			t.Errorf("%v: created_by_ref = %v, want the producer identity %v", id, o["created_by_ref"], producer)
		}
		if refs, ok := o["external_references"].([]any); ok {
			for _, r := range refs {
				ref, _ := r.(map[string]any)
				if s, _ := ref["source_name"].(string); s == "" {
					t.Errorf("%v: an external reference has no source_name", id)
				}
				if ref["url"] == nil && ref["external_id"] == nil && ref["description"] == nil {
					t.Errorf("%v: an external reference needs a url, an external_id or a description", id)
				}
			}
		}
		if c, ok := o["confidence"]; ok {
			if n, isNum := c.(float64); !isNum || n != float64(int(n)) || n < 0 || n > 100 {
				t.Errorf("%v: confidence = %v, want an integer 0-100", id, c)
			}
		}
		switch o["type"] {
		case "identity":
			stixString(t, o, "name")
		case "indicator":
			stixString(t, o, "pattern")
			if o["pattern_type"] != "stix" {
				t.Errorf("%v: pattern_type = %v", id, o["pattern_type"])
			}
			validFrom := stixTimestamp(t, o, "valid_from")
			if validFrom.Before(stixTimestamp(t, o, "created")) {
				t.Errorf("%v: valid_from precedes created", id)
			}
			for _, it := range o["indicator_types"].([]any) {
				if !stixIndicatorTypes[it.(string)] {
					t.Errorf("%v: indicator type %v is not in indicator-type-ov", id, it)
				}
			}
			stixPatternHashes(t, o["pattern"].(string))
		case "attack-pattern":
			stixString(t, o, "name")
		case "malware":
			if _, ok := o["is_family"].(bool); !ok {
				t.Errorf("%v: is_family is required and must be a boolean", id)
			}
		case "relationship":
			stixString(t, o, "relationship_type")
			src, dst := d.byID[stixString(t, o, "source_ref")], d.byID[stixString(t, o, "target_ref")]
			if src == nil || dst == nil {
				t.Fatalf("%v: a ref does not resolve inside the bundle", id)
			}
			// The only relationship written is "indicates", which the
			// specification defines from an indicator to (among others) an
			// attack-pattern or a malware.
			if o["relationship_type"] != "indicates" || src["type"] != "indicator" ||
				(dst["type"] != "attack-pattern" && dst["type"] != "malware") {
				t.Errorf("%v: %v %v %v is not a relationship this producer should write", id, src["type"], o["relationship_type"], dst["type"])
			}
		default:
			t.Errorf("unexpected object type %v", o["type"])
		}
	}
	return d
}

var stixHashTerm = regexp.MustCompile(`^file:hashes\.('SHA-256'|MD5|'SHA-1') = '([0-9a-f]+)'$`)

// stixPatternHashes reads the one pattern shape this producer may write: a
// single observation expression of hash comparisons joined by OR. Anything
// else in a pattern, in particular anything that is not hex inside a string
// literal, fails the test.
func stixPatternHashes(t *testing.T, pattern string) map[string]string {
	t.Helper()
	if !strings.HasPrefix(pattern, "[") || !strings.HasSuffix(pattern, "]") {
		t.Fatalf("pattern is not one observation expression: %q", pattern)
	}
	want := map[string]int{"'SHA-256'": 64, "MD5": 32, "'SHA-1'": 40}
	out := map[string]string{}
	for _, term := range strings.Split(pattern[1:len(pattern)-1], " OR ") {
		m := stixHashTerm.FindStringSubmatch(term)
		if m == nil {
			t.Fatalf("pattern term %q is not a file hash comparison (pattern %q)", term, pattern)
		}
		if len(m[2]) != want[m[1]] {
			t.Fatalf("pattern term %q: digest has %d hex characters, want %d", term, len(m[2]), want[m[1]])
		}
		if _, dup := out[m[1]]; dup {
			t.Fatalf("pattern repeats %s: %q", m[1], pattern)
		}
		out[m[1]] = m[2]
	}
	return out
}

func stixRun(t *testing.T, in Input, extra ...Option) stixDoc {
	t.Helper()
	return readSTIX(t, renderFormat(t, "stix", in, extra...))
}

// indicated lists the names of the objects of a type an indicator indicates.
func (d stixDoc) indicated(indicator map[string]any, typ string) []string {
	var out []string
	for _, r := range d.ofType("relationship") {
		if r["source_ref"] == indicator["id"] {
			if target := d.byID[r["target_ref"].(string)]; target["type"] == typ {
				out = append(out, target["name"].(string))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ── the conformance fixture ──────────────────────────────────────────────────

func checkSTIXFixture(t *testing.T, raw []byte) {
	oneLine(t, raw)
	d := readSTIX(t, raw)
	count := map[string]int{}
	for _, o := range d.objects {
		count[o["type"].(string)]++
	}
	want := map[string]int{"identity": 1, "attack-pattern": 2, "malware": 1, "indicator": 1, "relationship": 3}
	if !reflect.DeepEqual(count, want) {
		t.Fatalf("objects by type = %v, want %v", count, want)
	}
	ind := d.ofType("indicator")[0]
	hashes := stixPatternHashes(t, ind["pattern"].(string))
	if hashes["'SHA-256'"] != fixtureSHA256 || hashes["MD5"] != "d41d8cd98f00b204e9800998ecf8427e" || hashes["'SHA-1'"] != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("pattern hashes: %v", hashes)
	}
	if types := ind["indicator_types"].([]any); len(types) != 1 || types[0] != "malicious-activity" {
		t.Errorf("indicator_types: %v", types)
	}
	if ts := stixTimestamp(t, ind, "valid_from"); !ts.Equal(fixedTime) {
		t.Errorf("valid_from %v, want the reporter's clock %v", ts, fixedTime)
	}
	if _, has := ind["confidence"]; has {
		t.Errorf("the fixture's finding states no confidence, the indicator claims %v", ind["confidence"])
	}
	if !strings.Contains(ind["name"].(string), "wannacry_ransomware") {
		t.Errorf("name: %v", ind["name"])
	}
	labels := map[string]bool{}
	for _, l := range ind["labels"].([]any) {
		labels[l.(string)] = true
	}
	if !labels["detector:yara"] || !labels["detector:heuristic"] {
		t.Errorf("labels: %v", ind["labels"])
	}
	techniques := map[string]string{}
	for _, ap := range d.ofType("attack-pattern") {
		ref := ap["external_references"].([]any)[0].(map[string]any)
		if ref["source_name"] != "mitre-attack" {
			t.Errorf("attack-pattern reference: %v", ref)
		}
		techniques[ref["external_id"].(string)] = ref["url"].(string)
	}
	if techniques["T1055"] != "https://attack.mitre.org/techniques/T1055/" || techniques["T1486"] != "https://attack.mitre.org/techniques/T1486/" || len(techniques) != 2 {
		t.Errorf("techniques: %v", techniques)
	}
	if mw := d.ofType("malware")[0]; mw["name"] != "wannacry" || mw["is_family"] != true {
		t.Errorf("malware: %v", mw)
	}
	if got := d.indicated(ind, "attack-pattern"); len(got) != 2 {
		t.Errorf("indicator indicates %d attack-patterns, want 2", len(got))
	}
	if got := d.indicated(ind, "malware"); len(got) != 1 || got[0] != "wannacry" {
		t.Errorf("indicator indicates malware %v", got)
	}
}

// ── round trip through the project's own STIX consumer ───────────────────────

// digestsOf gives a file its own synthetic digests, so a round trip can tell
// the findings apart (the shared fixtures all carry the empty file's hashes).
func digestsOf(r scanner.ScanResult, seed string) scanner.ScanResult {
	m, s1, s256 := md5.Sum([]byte(seed)), sha1.Sum([]byte(seed)), sha256.Sum256([]byte(seed))
	r.MD5, r.SHA1, r.SHA256 = hex.EncodeToString(m[:]), hex.EncodeToString(s1[:]), hex.EncodeToString(s256[:])
	if r.MatchHash != "" {
		r.MatchHash = r.SHA256
	}
	return r
}

func roundTripInput() Input {
	sha256Only := digestsOf(yaraResult("samples/dropper.bin"), "dropper")
	sha256Only.MD5, sha256Only.SHA1 = "", ""
	return Input{
		Results: []scanner.ScanResult{
			digestsOf(hashResult("samples/wannacry.exe"), "wannacry"),
			sha256Only,
			digestsOf(fusionCorroboratedResult("samples/fused.exe"), "fused"),
			digestsOf(cleanResult("samples/notepad.exe"), "notepad"),
			errorResult("samples/locked.bin"),
			digestsOf(cleanResult("samples/heuristic.exe"), "heuristic"),
		},
		Heuristics: []scanner.HeuristicResult{
			heuristicLow("samples/notepad.exe"),
			heuristicBreach("samples/heuristic.exe"),
			// A finding with no scan result has no digest at all.
			heuristicBreach("samples/no-digest.exe"),
		},
	}
}

func TestSTIXRoundTripsThroughIntake(t *testing.T) {
	in := roundTripInput()
	raw := renderFormat(t, "stix", in)
	readSTIX(t, raw)

	// What the findings hold, read from the OCSF view of the same run: every
	// digest of every suspicious or malicious file.
	type digest struct{ typ, hash string }
	want := map[digest]string{}       // digest -> the finding's confidence, every finding
	wantIngest := map[digest]string{} // the subset intake may turn into signatures
	findings := ocsfRun(t, in, WithHostname("edr-host-01"), WithHeuristicThreshold(7))
	if len(findings) != 5 {
		t.Fatalf("the input should hold 5 findings (one of them without a digest), has %d", len(findings))
	}
	names := map[int]string{1: "MD5", 2: "SHA1", 3: "SHA256"}
	for _, f := range findings {
		conf, _ := f["confidence"].(string)
		if conf == "" {
			conf = intake.ConfidenceUnstated
		}
		file := f["evidences"].([]any)[0].(map[string]any)["file"].(map[string]any)
		hashes, _ := file["hashes"].([]any)
		for _, h := range hashes {
			hm := h.(map[string]any)
			d := digest{names[int(hm["algorithm_id"].(float64))], hm["value"].(string)}
			want[d] = strings.ToLower(conf)
			// Intake takes an indicator only when it says "malicious": a
			// suspicious file is exported as anomalous-activity and must not
			// come back as a hash signature, the engine's most confident tier.
			if f["severity_id"].(float64) >= 4 {
				wantIngest[d] = strings.ToLower(conf)
			}
		}
	}
	// 3 + 1 + 3 + 3 digests; the no-digest finding contributes none.
	if len(want) != 10 {
		t.Fatalf("expected 10 distinct digests across the findings, have %d", len(want))
	}

	iocs, err := intake.ParseSTIX(raw)
	if err != nil {
		t.Fatalf("intake rejected the bundle: %v", err)
	}
	got := map[digest]string{}
	for _, ioc := range iocs {
		got[digest{ioc.HashType, ioc.Hash}] = ioc.Confidence
		if ioc.Source != "stix" || ioc.ThreatName == "" {
			t.Errorf("ioc %+v", ioc)
		}
		if strings.Contains(ioc.ThreatName, "samples/") {
			t.Errorf("a file path became a threat label: %q", ioc.ThreatName)
		}
	}
	if !reflect.DeepEqual(got, wantIngest) {
		t.Errorf("intake read back\n %v\nwant exactly the malicious findings' digests\n %v", got, wantIngest)
	}
	if len(wantIngest) == 0 || len(wantIngest) == len(want) {
		t.Fatalf("the input must hold both malicious and suspicious findings with digests (%d of %d ingestible)", len(wantIngest), len(want))
	}
	// Every finding's digests are in the bundle, suspicious ones included:
	// the export is complete, it is the ingestion that is selective.
	stated := 0
	for d, c := range want {
		if !bytes.Contains(raw, []byte(d.hash)) {
			t.Errorf("digest %s of a finding is missing from the bundle", d.hash)
		}
		if c != intake.ConfidenceUnstated {
			stated++
		}
	}
	if stated != 3 {
		t.Errorf("%d digests carry a stated confidence, want the 3 of the one finding whose verdict has one", stated)
	}
	clean := digestsOf(cleanResult(""), "notepad")
	for _, h := range []string{clean.MD5, clean.SHA1, clean.SHA256} {
		if bytes.Contains(raw, []byte(h)) {
			t.Errorf("a clean file's digest %s is in the bundle", h)
		}
	}
}

// ── behaviour ────────────────────────────────────────────────────────────────

func TestSTIXIsReproducible(t *testing.T) {
	in := roundTripInput()
	a, b := renderFormat(t, "stix", in), renderFormat(t, "stix", in)
	if !bytes.Equal(a, b) {
		t.Fatal("two runs over the same input and clock differ")
	}

	// A later run changes the clock-stamped properties and nothing else.
	later := fixedTime.Add(36 * time.Hour)
	c := renderFormat(t, "stix", in, WithClock(func() time.Time { return later }))
	if bytes.Equal(a, c) {
		t.Fatal("the clock is not reaching the bundle")
	}
	strip := func(raw []byte) (stripped []map[string]any, reference []map[string]any) {
		d := readSTIX(t, raw)
		for _, o := range d.objects {
			switch o["type"] {
			case "indicator", "relationship":
				delete(o, "created")
				delete(o, "modified")
				delete(o, "valid_from")
			default:
				reference = append(reference, o)
			}
			stripped = append(stripped, o)
		}
		return stripped, reference
	}
	first, refs := strip(a)
	second, _ := strip(c)
	if !reflect.DeepEqual(first, second) {
		t.Error("a later run differs in more than indicator and relationship timestamps")
	}
	if readSTIX(t, a).id != readSTIX(t, c).id {
		t.Error("the same findings gave two bundle ids")
	}
	// Reference objects are a function of their key: fixed timestamps.
	for _, o := range refs {
		if o["created"] != stixDefinitionTime || o["modified"] != stixDefinitionTime {
			t.Errorf("%v: reference object stamped %v/%v", o["id"], o["created"], o["modified"])
		}
	}
	if len(refs) < 4 {
		t.Errorf("only %d reference objects in the round-trip input", len(refs))
	}

	// A different finding set is a different bundle.
	other := in
	other.Results = other.Results[1:]
	if readSTIX(t, renderFormat(t, "stix", other)).id == readSTIX(t, a).id {
		t.Error("a different finding set kept the bundle id")
	}
}

// An empty run is a bundle holding the producer identity alone (see Build).
func TestSTIXEmptyRun(t *testing.T) {
	for name, in := range map[string]Input{
		"nothing scanned": {},
		"nothing found":   {Results: []scanner.ScanResult{cleanResult("samples/notepad.exe"), errorResult("samples/locked.bin")}},
	} {
		raw := renderFormat(t, "stix", in)
		d := readSTIX(t, raw)
		if len(d.objects) != 1 || d.objects[0]["type"] != "identity" || d.objects[0]["name"] != DefaultToolName {
			t.Errorf("%s: objects = %v", name, d.objects)
		}
		if iocs, err := intake.ParseSTIX(raw); err != nil || len(iocs) != 0 {
			t.Errorf("%s: intake read %d indicators (err %v) from an empty bundle", name, len(iocs), err)
		}
	}
	if a, b := renderFormat(t, "stix", Input{}), renderFormat(t, "stix", Input{}, WithClock(time.Now)); !bytes.Equal(a, b) {
		t.Error("an empty bundle depends on the clock")
	}
}

// The path is attacker-chosen: it is data in the description and is in no
// pattern, whatever it contains.
func TestSTIXHostilePathStaysOutOfPatterns(t *testing.T) {
	// A name that tries to close the string literal and the observation
	// expression and append its own comparison.
	injection := "x' OR file:name = 'y'] OR [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e"
	for _, path := range []string{hostilePath, injection, `back\slash'quote`} {
		raw := renderFormat(t, "stix", Input{Results: []scanner.ScanResult{digestsOf(hashResult(path), "hostile")}})
		if strings.ContainsAny(string(raw), "\x1b\u202e\r") || strings.Count(string(raw), "\n") != 1 {
			t.Errorf("%q: a raw control character or a second line reached the document", path)
		}
		d := readSTIX(t, raw)
		inds := d.ofType("indicator")
		if len(inds) != 1 {
			t.Fatalf("%q: %d indicators for one finding", path, len(inds))
		}
		pattern := inds[0]["pattern"].(string)
		hashes := stixPatternHashes(t, pattern) // fails on anything but hash comparisons
		want := digestsOf(cleanResult(""), "hostile")
		if len(hashes) != 3 || hashes["'SHA-256'"] != want.SHA256 {
			t.Errorf("%q: pattern %q", path, pattern)
		}
		if !strings.Contains(inds[0]["description"].(string), path) {
			t.Errorf("%q: the description does not carry the path as data: %q", path, inds[0]["description"])
		}
		// Nowhere but the description.
		for _, o := range d.objects {
			for k, v := range o {
				if s, ok := v.(string); ok && k != "description" && strings.Contains(s, path) {
					t.Errorf("%q: the path is in %v.%s", path, o["type"], k)
				}
			}
		}
		if iocs, err := intake.ParseSTIX(raw); err != nil || len(iocs) != 3 {
			t.Errorf("%q: intake read %d indicators (err %v), want the file's 3 digests", path, len(iocs), err)
		}
	}
}

func TestSTIXQuote(t *testing.T) {
	for in, want := range map[string]string{
		"abc":    `'abc'`,
		`a'b`:    `'a\'b'`,
		`a\b`:    `'a\\b'`,
		`\'`:     `'\\\''`,
		"":       `''`,
		`a' OR `: `'a\' OR '`,
	} {
		if got := stixQuote(in); got != want {
			t.Errorf("stixQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// A digest that is not the full lowercase hex of its algorithm never becomes
// an indicator: a truncated hash would match some other file.
func TestSTIXOnlyWholeDigestsReachAPattern(t *testing.T) {
	good := strings.Repeat("ab", 32)
	cases := []struct {
		h    *Hashes
		want string
	}{
		{nil, ""},
		{&Hashes{}, ""},
		{&Hashes{SHA256: good[:40]}, ""},
		{&Hashes{SHA256: strings.ToUpper(good)}, ""},
		{&Hashes{SHA256: good[:63] + "'"}, ""},
		{&Hashes{SHA256: good[:63] + "g"}, ""},
		{&Hashes{SHA256: good}, "[file:hashes.'SHA-256' = '" + good + "']"},
		{&Hashes{MD5: good[:32], SHA1: good[:40]}, "[file:hashes.MD5 = '" + good[:32] + "' OR file:hashes.'SHA-1' = '" + good[:40] + "']"},
		{&Hashes{SHA256: good[:12], MD5: good[:32]}, "[file:hashes.MD5 = '" + good[:32] + "']"},
	}
	for _, tc := range cases {
		if got := stixFilePattern(tc.h); got != tc.want {
			t.Errorf("stixFilePattern(%+v) = %q, want %q", tc.h, got, tc.want)
		}
	}

	// End to end: a configuration that truncates digests yields no indicator,
	// and a finding without a scan result (no digest) yields none either.
	in := Input{Results: []scanner.ScanResult{hashResult("samples/wannacry.exe")}}
	if d := stixRun(t, in, WithMaxHashChars(16)); len(d.ofType("indicator")) != 0 || len(d.objects) != 1 {
		t.Errorf("truncated digests produced %d objects", len(d.objects))
	}
	noDigest := Input{Heuristics: []scanner.HeuristicResult{heuristicBreach("samples/no-digest.exe")}}
	if len(ocsfRun(t, noDigest, WithHeuristicThreshold(7))) != 1 {
		t.Fatal("the no-digest input should still be an OCSF finding")
	}
	if d := stixRun(t, noDigest); len(d.objects) != 1 {
		t.Errorf("a finding without a digest produced %d objects", len(d.objects))
	}
}

func TestSTIXMalwareOnlyWhenNamed(t *testing.T) {
	plainYara := digestsOf(yaraResult("samples/plain.bin"), "plain") // the rule declares no family
	withFamily := digestsOf(yaraResult("samples/family.bin"), "family")
	withFamily.YaraMatches[0].Metas = append(append([]scanner.YaraMatchMeta(nil), withFamily.YaraMatches[0].Metas...),
		scanner.YaraMatchMeta{Identifier: "family", Value: "wannacry"})
	sameFamily := digestsOf(yaraResult("samples/family2.bin"), "family2")
	sameFamily.YaraMatches[0].Metas = withFamily.YaraMatches[0].Metas
	in := Input{Results: []scanner.ScanResult{
		digestsOf(hashResult("samples/wannacry.exe"), "wannacry"),
		plainYara, withFamily, sameFamily,
	}}
	d := stixRun(t, in)
	byPath := map[string]map[string]any{}
	for _, ind := range d.ofType("indicator") {
		for _, p := range []string{"wannacry.exe", "plain.bin", "family.bin", "family2.bin"} {
			if strings.Contains(ind["description"].(string), "samples/"+p+":") {
				byPath[p] = ind
			}
		}
	}
	if len(byPath) != 4 {
		t.Fatalf("indicators: %d", len(byPath))
	}
	malware := map[string]bool{}
	for _, mw := range d.ofType("malware") {
		malware[mw["name"].(string)] = mw["is_family"].(bool)
	}
	// One sample label from the signature database, one family from the rule
	// author, shared by the two files that matched it.
	if want := map[string]bool{"WannaCry Ransomware": false, "wannacry": true}; !reflect.DeepEqual(malware, want) {
		t.Errorf("malware objects (name -> is_family) = %v, want %v", malware, want)
	}
	if got := d.indicated(byPath["wannacry.exe"], "malware"); len(got) != 1 || got[0] != "WannaCry Ransomware" {
		t.Errorf("hash finding indicates %v", got)
	}
	if got := d.indicated(byPath["plain.bin"], "malware"); len(got) != 0 {
		t.Errorf("a YARA rule with no family meta was given a malware object: %v", got)
	}
	for _, p := range []string{"family.bin", "family2.bin"} {
		if got := d.indicated(byPath[p], "malware"); len(got) != 1 || got[0] != "wannacry" {
			t.Errorf("%s indicates %v", p, got)
		}
	}
}

func TestSTIXConfidenceOnlyWhenStated(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{
		digestsOf(hashResult("samples/wannacry.exe"), "wannacry"),
		digestsOf(fusionCorroboratedResult("samples/fused.exe"), "fused"),
	}}
	stated := map[string]string{}
	for _, f := range ocsfRun(t, in) {
		conf, _ := f["confidence"].(string)
		stated[f["finding_info"].(map[string]any)["uid"].(string)] = conf
	}
	scale := map[string]float64{"Low": 15, "Medium": 50, "High": 85}
	withConfidence := 0
	d := stixRun(t, in)
	for _, ind := range d.ofType("indicator") {
		uid := ind["external_references"].([]any)[0].(map[string]any)["external_id"].(string)
		conf, known := stated[uid]
		if !known {
			t.Fatalf("indicator %v does not reference an OCSF finding uid (%q)", ind["id"], uid)
		}
		got, has := ind["confidence"]
		switch {
		case conf == "" && has:
			t.Errorf("%s: the engine stated no confidence, the indicator claims %v", uid, got)
		case conf != "" && got != scale[conf]:
			t.Errorf("%s: confidence %v for the engine's %q, want %v", uid, got, conf, scale[conf])
		}
		if has {
			withConfidence++
		}
		// The hash-signature finding is malicious; the corroborated one is
		// suspicious.
		wantType := "anomalous-activity"
		if strings.Contains(ind["name"].(string), "hash signature") {
			wantType = "malicious-activity"
		}
		if types := ind["indicator_types"].([]any); len(types) != 1 || types[0] != wantType {
			t.Errorf("%s: indicator_types %v, want %s", uid, types, wantType)
		}
	}
	if withConfidence != 1 || len(d.ofType("indicator")) != 2 {
		t.Errorf("%d of %d indicators carry a confidence, want 1 of 2", withConfidence, len(d.ofType("indicator")))
	}
}

// Techniques are one attack-pattern each however many findings share them,
// and only something shaped like a technique id is attributed to ATT&CK.
func TestSTIXAttackPatterns(t *testing.T) {
	mk := func(path, seed, technique string) scanner.ScanResult {
		r := digestsOf(yaraResult(path), seed)
		r.YaraMatches[0].Metas = append(append([]scanner.YaraMatchMeta(nil), r.YaraMatches[0].Metas...),
			scanner.YaraMatchMeta{Identifier: "mitre_attack", Value: technique})
		return r
	}
	d := stixRun(t, Input{Results: []scanner.ScanResult{
		mk("a.bin", "a", "T1486, T1027.002"),
		mk("b.bin", "b", "T1486 not-a-technique T9999"),
	}})
	got := map[string]string{}
	for _, ap := range d.ofType("attack-pattern") {
		ref := ap["external_references"].([]any)[0].(map[string]any)
		got[ref["external_id"].(string)] = ref["url"].(string) + " " + ap["name"].(string)
	}
	if len(got) != 3 {
		t.Fatalf("attack-patterns: %v", got)
	}
	if _, bad := got["not-a-technique"]; bad {
		t.Error("free text from a rule's meta block was attributed to MITRE ATT&CK")
	}
	if !strings.HasPrefix(got["T1027.002"], "https://attack.mitre.org/techniques/T1027/002/ ") {
		t.Errorf("sub-technique: %q", got["T1027.002"])
	}
	// An id the bundled catalogue does not know is named by its id, not given
	// an invented name.
	if got["T9999"] != "https://attack.mitre.org/techniques/T9999/ T9999" {
		t.Errorf("unknown technique: %q", got["T9999"])
	}
	if n := len(d.ofType("relationship")); n != 4 {
		t.Errorf("%d relationships, want 2 + 2", n)
	}
}

// The id scheme is a published contract: pin the namespace and the algorithm.
func TestSTIXIDsArePinned(t *testing.T) {
	// RFC 4122 test vector: uuid5(NAMESPACE_DNS, "python.org").
	dns := [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	if got := uuidString(uuidV5(dns, "python.org")); got != "886313e1-3b8a-5372-9b90-0c9aee199e5d" {
		t.Fatalf("uuidV5 is not RFC 4122 version 5: %s", got)
	}
	if got := uuidString(stixNamespace); got != "92c2a859-cf6d-5826-a0f3-b8bca359f51e" {
		t.Errorf("the id namespace changed to %s: every published object id changes with it", got)
	}
	// STIX reserves this namespace for cyber-observables; SDO ids must not use it.
	if uuidString(stixNamespace) == "00abedb4-aa42-466c-9c01-fed23315a9b7" {
		t.Error("SDO ids are derived under the STIX SCO namespace")
	}
	if a, b := stixID("malware", "sample", "ab"), stixID("malware", "sample\x00a", "b"); a == b {
		t.Error("id keys collide by concatenation")
	}
	if a, b := stixID("malware", "sample", "x"), stixID("malware", "family", "x"); a == b {
		t.Error("a sample label and a family of the same name share an id")
	}
}

func TestSTIXIndentedIsTheSameDocument(t *testing.T) {
	compact := renderFormat(t, "stix", conformanceInput())
	pretty := renderFormat(t, "stix", conformanceInput(), WithIndent(true))
	if bytes.Count(pretty, []byte("\n")) < 10 {
		t.Fatalf("WithIndent did not indent: %s", pretty)
	}
	var a, b any
	if json.Unmarshal(compact, &a) != nil || json.Unmarshal(pretty, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Error("the indented bundle is not the compact bundle")
	}
}

// STIX is a document for a TAXII server, not an event stream: it is a report
// format and not one --sink-url can carry.
func TestSTIXIsNotASinkFormat(t *testing.T) {
	for _, f := range SinkFormats() {
		if f == "stix" {
			t.Fatal("stix is listed as a sink format")
		}
	}
	if _, err := NewSinkReporter("stix"); err == nil {
		t.Error("NewSinkReporter accepted stix")
	}
	if _, _, err := RenderSinkEvents("stix", nil); err == nil {
		t.Error("RenderSinkEvents accepted stix")
	}
	found := false
	for _, f := range Formats {
		found = found || f == "stix"
	}
	if !found {
		t.Error("stix is not in Formats")
	}
}

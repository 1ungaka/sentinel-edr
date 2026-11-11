package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/scanner"
)

// The conformance fixtures: one committed artifact per standard, each
// regenerated and compared on every run and then parsed back by an
// independent reader written against the standard rather than against the
// encoder. A sink change that alters the wire shape fails here first.
//
//	go test ./internal/report -run TestSinkConformanceFixtures -update
//
// rewrites the fixtures; the diff is then the review artifact.
var updateFixtures = flag.Bool("update", false, "rewrite the sink conformance fixtures")

// conformanceInput is the one finding every fixture carries: a YARA hit with
// a family and two ATT&CK techniques on a file that also breached heuristics.
func conformanceInput() Input {
	r := yaraResult("samples/dropper.bin")
	r.YaraMatches[0].Metas = append(r.YaraMatches[0].Metas,
		scanner.YaraMatchMeta{Identifier: "mitre_attack", Value: "T1486"},
		scanner.YaraMatchMeta{Identifier: "family", Value: "wannacry"})
	h := heuristicBreach("samples/dropper.bin")
	h.Categories = []scanner.CategoryScore{
		{Category: "Process Injection", Applied: 5, Cap: 8, Technique: "T1055"},
	}
	return Input{Results: []scanner.ScanResult{r}, Heuristics: []scanner.HeuristicResult{h}}
}

func sinkOpts(extra ...Option) []Option {
	return testOpts(append([]Option{WithHostname("edr-host-01"), WithHeuristicThreshold(7)}, extra...)...)
}

func renderFormat(t *testing.T, format string, in Input, extra ...Option) []byte {
	t.Helper()
	rep, err := NewReporter(format, sinkOpts(extra...)...)
	if err != nil {
		t.Fatalf("NewReporter(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := rep.Write(&buf, in); err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	return buf.Bytes()
}

var conformanceFixtures = []struct {
	format string
	file   string
	check  func(t *testing.T, raw []byte)
}{
	{"syslog", "rfc5424.log", checkSyslogFixture},
	{"cef", "cef.log", checkCEFFixture},
	{"leef", "leef.log", checkLEEFFixture},
	{"gelf", "gelf.json", checkGELFFixture},
	{"ecs", "ecs.json", checkECSFixture},
	{"ocsf", "ocsf.json", checkOCSFFixture},
	{"otlp", "otlp.json", checkOTLPFixture},
	{"stix", "stix.json", checkSTIXFixture},
}

func TestSinkConformanceFixtures(t *testing.T) {
	for _, fx := range conformanceFixtures {
		t.Run(fx.format, func(t *testing.T) {
			got := renderFormat(t, fx.format, conformanceInput())
			path := filepath.Join("testdata", "conformance", fx.file)
			if *updateFixtures {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("fixture missing (run with -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s drifted from its conformance fixture %s\n got: %s\nwant: %s", fx.format, path, got, want)
			}
			fx.check(t, want)
		})
	}
}

// ── independent readers ──────────────────────────────────────────────────────

type syslogMsg struct {
	pri, version                   int
	ts                             time.Time
	host, app, procid, msgid, sdID string
	params                         map[string]string
	msg                            string
}

// parseSyslog reads one RFC 5424 frame.
func parseSyslog(t *testing.T, line string) syslogMsg {
	t.Helper()
	var m syslogMsg
	m.params = map[string]string{}
	if !strings.HasPrefix(line, "<") {
		t.Fatalf("no PRI: %q", line)
	}
	end := strings.IndexByte(line, '>')
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri < 0 || pri > 191 {
		t.Fatalf("bad PRI in %q", line)
	}
	m.pri = pri
	rest := line[end+1:]
	fields := strings.SplitN(rest, " ", 7)
	if len(fields) != 7 {
		t.Fatalf("want 7 header fields, got %d: %q", len(fields), rest)
	}
	if m.version, err = strconv.Atoi(fields[0]); err != nil {
		t.Fatalf("version: %v", err)
	}
	if m.ts, err = time.Parse(time.RFC3339Nano, fields[1]); err != nil {
		t.Fatalf("timestamp %q: %v", fields[1], err)
	}
	m.host, m.app, m.procid, m.msgid = fields[2], fields[3], fields[4], fields[5]
	for _, hf := range fields[2:6] {
		for i := 0; i < len(hf); i++ {
			if hf[i] <= 32 || hf[i] >= 127 {
				t.Fatalf("header field %q is not PRINTUSASCII", hf)
			}
		}
	}
	tail := fields[6]
	if strings.HasPrefix(tail, "-") {
		m.msg = strings.TrimPrefix(strings.TrimPrefix(tail, "-"), " ")
		return m
	}
	if tail[0] != '[' {
		t.Fatalf("structured data must be - or [: %q", tail)
	}
	i := 1
	for i < len(tail) && tail[i] != ' ' && tail[i] != ']' {
		i++
	}
	m.sdID = tail[1:i]
	for i < len(tail) && tail[i] != ']' {
		if tail[i] != ' ' {
			t.Fatalf("expected space before SD-PARAM at %d in %q", i, tail)
		}
		i++
		eq := strings.IndexByte(tail[i:], '=')
		name := tail[i : i+eq]
		if len(name) == 0 || len(name) > 32 || strings.ContainsAny(name, ` ]"`) {
			t.Fatalf("bad SD-NAME %q", name)
		}
		i += eq + 1
		if tail[i] != '"' {
			t.Fatalf("PARAM-VALUE must be quoted: %q", tail[i:])
		}
		i++
		var val strings.Builder
		for ; tail[i] != '"'; i++ {
			if tail[i] == ']' {
				t.Fatalf("unescaped ] inside PARAM-VALUE of %s", name)
			}
			if tail[i] == '\\' && (tail[i+1] == '"' || tail[i+1] == '\\' || tail[i+1] == ']') {
				i++
			}
			val.WriteByte(tail[i])
		}
		i++ // closing quote
		m.params[name] = val.String()
	}
	m.msg = strings.TrimPrefix(tail[i+1:], " ")
	return m
}

// splitUnescaped splits s on sep where sep is not preceded by a backslash
// escape, up to n parts (n <= 0: unlimited).
func splitUnescaped(s string, sep byte, n int) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == sep && (n <= 0 || len(parts) < n-1) {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func cefUnescape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			default:
				sb.WriteByte(s[i])
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

var cefKey = regexp.MustCompile(`[A-Za-z0-9]+$`)

// parseCEF reads one CEF event into its seven header fields and extension map.
func parseCEF(t *testing.T, line string) ([]string, map[string]string) {
	t.Helper()
	parts := splitUnescaped(line, '|', 8)
	if len(parts) != 8 {
		t.Fatalf("CEF needs 7 header fields and an extension, got %d parts: %q", len(parts), line)
	}
	header := make([]string, 7)
	for i := range header {
		header[i] = cefUnescape(parts[i])
	}
	ext := map[string]string{}
	body := parts[7]
	// Every unescaped '=' ends a key; the value runs to the next key.
	var eqs []int
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' {
			i++
			continue
		}
		if body[i] == '=' {
			eqs = append(eqs, i)
		}
	}
	keyStart := func(eq int) int { return eq - len(cefKey.FindString(body[:eq])) }
	for n, eq := range eqs {
		ks := keyStart(eq)
		if ks == eq {
			t.Fatalf("extension '=' at %d has no key: %q", eq, body)
		}
		end := len(body)
		if n+1 < len(eqs) {
			end = keyStart(eqs[n+1]) - 1 // the separating space
		}
		ext[body[ks:eq]] = cefUnescape(body[eq+1 : end])
	}
	return header, ext
}

// parseLEEF reads one LEEF 2.0 event into its header fields and attributes.
func parseLEEF(t *testing.T, line string) ([]string, map[string]string) {
	t.Helper()
	parts := strings.SplitN(line, "|", 7)
	if len(parts) != 7 {
		t.Fatalf("LEEF 2.0 needs 6 header fields and attributes, got %d parts: %q", len(parts), line)
	}
	if parts[5] != "0x09" {
		t.Fatalf("delimiter field = %q, want 0x09", parts[5])
	}
	attrs := map[string]string{}
	for _, kv := range strings.Split(parts[6], "\t") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			t.Fatalf("attribute %q is not key=value", kv)
		}
		attrs[k] = v
	}
	return parts[:6], attrs
}

func decodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, raw)
	}
	return m
}

func oneLine(t *testing.T, raw []byte) string {
	t.Helper()
	s := strings.TrimSuffix(string(raw), "\n")
	if s == "" || strings.Contains(s, "\n") {
		t.Fatalf("want exactly one line, got %q", raw)
	}
	return s
}

const fixtureSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func checkSyslogFixture(t *testing.T, raw []byte) {
	m := parseSyslog(t, oneLine(t, raw))
	if m.pri != 10*8+3 || m.version != 1 {
		t.Errorf("pri/version = %d/%d, want 83/1 (authpriv.err)", m.pri, m.version)
	}
	if !m.ts.Equal(fixedTime) {
		t.Errorf("timestamp %v, want %v", m.ts, fixedTime)
	}
	if m.host != "edr-host-01" || m.app != "cau" || m.procid != "-" || m.msgid != "finding" {
		t.Errorf("header: %+v", m)
	}
	if m.sdID != "cau@32473" {
		t.Errorf("SD-ID %q", m.sdID)
	}
	want := map[string]string{
		"verdict": "malicious", "filePath": "samples/dropper.bin", "fileName": "dropper.bin",
		"sha256": fixtureSHA256, "attackTechniques": "T1055,T1486", "malware": "wannacry",
	}
	for k, v := range want {
		if m.params[k] != v {
			t.Errorf("SD %s = %q, want %q", k, m.params[k], v)
		}
	}
	if !strings.Contains(m.msg, "wannacry_ransomware") {
		t.Errorf("MSG %q", m.msg)
	}
}

func checkCEFFixture(t *testing.T, raw []byte) {
	h, ext := parseCEF(t, oneLine(t, raw))
	if h[0] != "CEF:0" || h[1] != "CAU" || h[2] != "cau" || h[3] != "9.9.9-test" {
		t.Errorf("header: %q", h)
	}
	if h[4] != "yara/default/wannacry_ransomware" || h[6] != "8" {
		t.Errorf("signature/severity: %q / %q", h[4], h[6])
	}
	if sev, err := strconv.Atoi(h[6]); err != nil || sev < 0 || sev > 10 {
		t.Errorf("severity %q outside 0-10", h[6])
	}
	want := map[string]string{
		"rt": strconv.FormatInt(fixedTime.UnixMilli(), 10), "dvchost": "edr-host-01", "cat": "malicious",
		"filePath": "samples/dropper.bin", "fname": "dropper.bin", "fileHash": fixtureSHA256,
		"cs1": "T1055,T1486", "cs1Label": "attackTechniques", "cs3": "wannacry", "cs3Label": "malware",
	}
	for k, v := range want {
		if ext[k] != v {
			t.Errorf("extension %s = %q, want %q", k, ext[k], v)
		}
	}
	for k := range ext {
		if strings.HasPrefix(k, "cs") && !strings.HasSuffix(k, "Label") && ext[k+"Label"] == "" {
			t.Errorf("custom string %s has no label", k)
		}
	}
}

func checkLEEFFixture(t *testing.T, raw []byte) {
	h, attrs := parseLEEF(t, oneLine(t, raw))
	if h[0] != "LEEF:2.0" || h[1] != "CAU" || h[2] != "cau" || h[3] != "9.9.9-test" || h[4] != "yara/default/wannacry_ransomware" {
		t.Errorf("header: %q", h)
	}
	want := map[string]string{
		"devTime": strconv.FormatInt(fixedTime.UnixMilli(), 10), "sev": "8", "cat": "malicious",
		"filePath": "samples/dropper.bin", "fileHash": fixtureSHA256, "attackTechniques": "T1055,T1486",
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, attrs[k], v)
		}
	}
}

var gelfField = regexp.MustCompile(`^_[\w.\-]+$`)

func checkGELFFixture(t *testing.T, raw []byte) {
	m := decodeObject(t, []byte(oneLine(t, raw)))
	if m["version"] != "1.1" || m["host"] != "edr-host-01" || m["short_message"] == "" {
		t.Errorf("required fields: %v", m)
	}
	if ts, ok := m["timestamp"].(float64); !ok || ts != float64(fixedTime.UnixMilli())/1000 {
		t.Errorf("timestamp %v", m["timestamp"])
	}
	if lvl, ok := m["level"].(float64); !ok || lvl != 3 {
		t.Errorf("level %v, want 3", m["level"])
	}
	std := map[string]bool{"version": true, "host": true, "short_message": true, "full_message": true, "timestamp": true, "level": true}
	for k, v := range m {
		if std[k] {
			continue
		}
		if !gelfField.MatchString(k) || k == "_id" {
			t.Errorf("additional field %q is not a legal GELF field name", k)
		}
		switch v.(type) {
		case string, float64:
		default:
			t.Errorf("additional field %s must be a string or number, is %T", k, v)
		}
	}
	if m["_file_sha256"] != fixtureSHA256 || m["_attack_techniques"] != "T1055,T1486" || m["_verdict"] != "malicious" {
		t.Errorf("additional fields: %v", m)
	}
}

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q is not an object", path, p)
		}
		cur = obj[p]
	}
	return cur
}

func checkECSFixture(t *testing.T, raw []byte) {
	m := decodeObject(t, []byte(oneLine(t, raw)))
	ts, err := time.Parse(time.RFC3339Nano, m["@timestamp"].(string))
	if err != nil || !ts.Equal(fixedTime) {
		t.Errorf("@timestamp %v (%v)", m["@timestamp"], err)
	}
	if dig(t, m, "ecs", "version") != ECSVersion {
		t.Errorf("ecs.version %v", dig(t, m, "ecs", "version"))
	}
	// The allowed values of the ECS categorization fields this profile uses.
	if dig(t, m, "event", "kind") != "alert" {
		t.Errorf("event.kind %v", dig(t, m, "event", "kind"))
	}
	if cat := dig(t, m, "event", "category").([]any); len(cat) != 1 || cat[0] != "malware" {
		t.Errorf("event.category %v", cat)
	}
	if typ := dig(t, m, "event", "type").([]any); len(typ) != 1 || typ[0] != "info" {
		t.Errorf("event.type %v", typ)
	}
	if dig(t, m, "file", "path") != "samples/dropper.bin" || dig(t, m, "file", "hash", "sha256") != fixtureSHA256 {
		t.Errorf("file: %v", m["file"])
	}
	if dig(t, m, "rule", "id") != "yara/default/wannacry_ransomware" {
		t.Errorf("rule: %v", m["rule"])
	}
	ids := dig(t, m, "threat", "technique", "id").([]any)
	names := dig(t, m, "threat", "technique", "name").([]any)
	if len(ids) != 2 || ids[0] != "T1055" || ids[1] != "T1486" || len(names) != len(ids) {
		t.Errorf("threat.technique: %v / %v", ids, names)
	}
	if dig(t, m, "threat", "framework") != "MITRE ATT&CK" || dig(t, m, "host", "name") != "edr-host-01" {
		t.Errorf("threat/host: %v %v", m["threat"], m["host"])
	}
	if dig(t, m, "cau", "verdict") != "malicious" {
		t.Errorf("cau: %v", m["cau"])
	}
}

func checkOCSFFixture(t *testing.T, raw []byte) {
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) != 1 {
		t.Fatalf("want one OCSF object: %v", err)
	}
	f := arr[0]
	if f["class_uid"].(float64) != 2004 || f["category_uid"].(float64) != 2 || f["type_uid"].(float64) != 200401 {
		t.Errorf("class: %v", f)
	}
	if dig(t, f, "metadata", "version") != OCSFVersion || f["severity_id"].(float64) != 4 {
		t.Errorf("metadata/severity: %v", f)
	}
}

func otlpAttrs(t *testing.T, list any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for _, a := range list.([]any) {
		kv := a.(map[string]any)
		key, ok := kv["key"].(string)
		val, ok2 := kv["value"].(map[string]any)
		if !ok || !ok2 || len(val) != 1 {
			t.Fatalf("attribute is not {key, value:{oneof}}: %v", a)
		}
		for kind, v := range val {
			switch kind {
			case "stringValue":
				out[key] = v
			case "intValue":
				if _, err := strconv.ParseInt(v.(string), 10, 64); err != nil {
					t.Fatalf("intValue of %s must be a decimal string: %v", key, v)
				}
				out[key] = v
			case "arrayValue":
				var items []string
				for _, it := range v.(map[string]any)["values"].([]any) {
					item := it.(map[string]any)
					if s, ok := item["stringValue"].(string); ok {
						items = append(items, s)
						continue
					}
					n, ok := item["intValue"].(string)
					if _, err := strconv.ParseInt(n, 10, 64); !ok || err != nil {
						t.Fatalf("array item of %s is neither a stringValue nor a decimal intValue: %v", key, it)
					}
					items = append(items, n)
				}
				out[key] = strings.Join(items, ",")
			default:
				t.Fatalf("unexpected AnyValue kind %q", kind)
			}
		}
	}
	return out
}

func checkOTLPFixture(t *testing.T, raw []byte) {
	m := decodeObject(t, raw)
	rl := m["resourceLogs"].([]any)
	if len(rl) != 1 {
		t.Fatalf("resourceLogs: %v", rl)
	}
	res := otlpAttrs(t, dig(t, rl[0].(map[string]any), "resource", "attributes"))
	if res["service.name"] != "cau" || res["service.version"] != "9.9.9-test" || res["host.name"] != "edr-host-01" {
		t.Errorf("resource: %v", res)
	}
	sl := rl[0].(map[string]any)["scopeLogs"].([]any)
	recs := sl[0].(map[string]any)["logRecords"].([]any)
	if len(recs) != 1 {
		t.Fatalf("logRecords: %d", len(recs))
	}
	rec := recs[0].(map[string]any)
	ns, err := strconv.ParseInt(rec["timeUnixNano"].(string), 10, 64)
	if err != nil || ns != fixedTime.UnixNano() {
		t.Errorf("timeUnixNano %v (%v)", rec["timeUnixNano"], err)
	}
	if rec["severityNumber"].(float64) != 17 || rec["severityText"] != "ERROR" {
		t.Errorf("severity: %v %v", rec["severityNumber"], rec["severityText"])
	}
	if body := rec["body"].(map[string]any)["stringValue"]; body == "" {
		t.Errorf("body empty")
	}
	attrs := otlpAttrs(t, rec["attributes"])
	if attrs["file.path"] != "samples/dropper.bin" || attrs["file.hash.sha256"] != fixtureSHA256 ||
		attrs["threat.technique.id"] != "T1055,T1486" || attrs["cau.verdict"] != "malicious" {
		t.Errorf("attributes: %v", attrs)
	}
}

// ── behaviour ────────────────────────────────────────────────────────────────

// Every profile must emit exactly the findings OCSF emits: the same count and
// the same uid, since they are one event model with different spellings.
func TestSinkProfilesAgreeWithOCSF(t *testing.T) {
	in := fullInput()
	ocsf := ocsfRun(t, in)
	var uids []string
	for _, f := range ocsf {
		uids = append(uids, f["finding_info"].(map[string]any)["uid"].(string))
	}
	if len(uids) != 3 {
		t.Fatalf("fixture should hold 3 findings, has %d", len(uids))
	}
	for _, format := range SinkFormats() {
		out := string(renderFormat(t, format, in))
		if format != "otlp" {
			if n := strings.Count(out, "\n"); n != len(uids) {
				t.Errorf("%s: %d lines for %d findings", format, n, len(uids))
			}
		}
		for _, uid := range uids {
			if !strings.Contains(out, uid) {
				t.Errorf("%s: finding %s missing", format, uid)
			}
		}
	}
}

func TestSinkEmptyRun(t *testing.T) {
	for _, format := range SinkFormats() {
		out := renderFormat(t, format, Input{})
		if format == "otlp" {
			if m := decodeObject(t, out); len(m["resourceLogs"].([]any)) != 0 {
				t.Errorf("otlp empty run: %s", out)
			}
			continue
		}
		if len(out) != 0 {
			t.Errorf("%s: empty run wrote %q", format, out)
		}
	}
}

func TestSinkSuspiciousSeverity(t *testing.T) {
	in := Input{
		Results:    []scanner.ScanResult{cleanResult("samples/heuristic-only.exe")},
		Heuristics: []scanner.HeuristicResult{heuristicBreach("samples/heuristic-only.exe")},
	}
	if _, ext := parseCEF(t, oneLine(t, renderFormat(t, "cef", in, WithHeuristicThreshold(3)))); ext["cat"] != "suspicious" {
		t.Errorf("cef cat = %q", ext["cat"])
	}
	h, _ := parseCEF(t, oneLine(t, renderFormat(t, "cef", in, WithHeuristicThreshold(3))))
	if h[6] != "5" {
		t.Errorf("cef severity = %q, want 5", h[6])
	}
	if m := parseSyslog(t, oneLine(t, renderFormat(t, "syslog", in, WithHeuristicThreshold(3)))); m.pri != 10*8+4 {
		t.Errorf("syslog pri = %d, want 84 (authpriv.warning)", m.pri)
	}
	g := decodeObject(t, renderFormat(t, "gelf", in, WithHeuristicThreshold(3)))
	if g["level"].(float64) != 4 {
		t.Errorf("gelf level = %v, want 4", g["level"])
	}
	o := decodeObject(t, renderFormat(t, "otlp", in, WithHeuristicThreshold(3)))
	rec := o["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	if rec["severityNumber"].(float64) != 13 || rec["severityText"] != "WARN" {
		t.Errorf("otlp severity: %v", rec)
	}
}

// hostilePath is a file name chosen to break every line format at once: the
// separators of CEF, LEEF and RFC 5424, a newline followed by a forged frame,
// a tab, an escape sequence and a bidi override.
const hostilePath = "drop/ev|il=1 x=2]\"q\\\n<83>1 2026-01-01T00:00:00Z h cau - finding - forged\tt\x1b[2K\u202egpj.exe"

func hostileInput() Input {
	return Input{Results: []scanner.ScanResult{hashResult(hostilePath)}}
}

// A hostile file name must never forge a second event, and the structured
// formats must carry it byte-exact.
func TestSinkHostileFilename(t *testing.T) {
	visible := TermSafe(hostilePath)

	for _, format := range SinkFormats() {
		out := string(renderFormat(t, format, hostileInput()))
		if format != "otlp" && strings.Count(out, "\n") != 1 {
			t.Errorf("%s: hostile name produced %d lines, want 1:\n%s", format, strings.Count(out, "\n"), out)
		}
		if strings.ContainsAny(strings.TrimSuffix(out, "\n"), "\x1b\u202e\r") {
			t.Errorf("%s: raw control or bidi character reached the output", format)
		}
	}

	// JSON profiles: exact bytes.
	ecs := decodeObject(t, renderFormat(t, "ecs", hostileInput()))
	if got := dig(t, ecs, "file", "path"); got != hostilePath {
		t.Errorf("ecs file.path = %q", got)
	}
	gelf := decodeObject(t, renderFormat(t, "gelf", hostileInput()))
	if gelf["_file_path"] != hostilePath {
		t.Errorf("gelf _file_path = %q", gelf["_file_path"])
	}
	otlp := decodeObject(t, renderFormat(t, "otlp", hostileInput()))
	rec := otlp["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	if got := otlpAttrs(t, rec["attributes"])["file.path"]; got != hostilePath {
		t.Errorf("otlp file.path = %q", got)
	}

	// CEF: the standard's own escapes round-trip the separators and the
	// newline exactly; only the non-line-breaking controls become visible.
	_, ext := parseCEF(t, oneLine(t, renderFormat(t, "cef", hostileInput())))
	wantCEF := strings.NewReplacer("\t", `\t`, "\x1b", `\x1b`, "\u202e", `\u202e`).Replace(hostilePath)
	if ext["filePath"] != wantCEF {
		t.Errorf("cef filePath\n got %q\nwant %q", ext["filePath"], wantCEF)
	}
	if ext["cat"] != "malicious" || ext["fileHash"] != fixtureSHA256 {
		t.Errorf("cef: the hostile name displaced other extension fields: %v", ext)
	}

	// RFC 5424: the SD parameter unescapes to the visible form, and the
	// fields after it are still where they belong.
	m := parseSyslog(t, oneLine(t, renderFormat(t, "syslog", hostileInput())))
	if m.params["filePath"] != visible {
		t.Errorf("syslog filePath\n got %q\nwant %q", m.params["filePath"], visible)
	}
	if m.params["sha256"] != fixtureSHA256 || m.params["verdict"] != "malicious" {
		t.Errorf("syslog: the hostile name displaced other parameters: %v", m.params)
	}

	// LEEF: no escape exists, so the value is the visible form and the
	// attribute count is unchanged by the tab in the name.
	_, attrs := parseLEEF(t, oneLine(t, renderFormat(t, "leef", hostileInput())))
	if attrs["filePath"] != visible {
		t.Errorf("leef filePath\n got %q\nwant %q", attrs["filePath"], visible)
	}
	if attrs["fileHash"] != fixtureSHA256 || attrs["cat"] != "malicious" {
		t.Errorf("leef: the hostile name displaced other attributes: %v", attrs)
	}
}

// The wrapped syslog profiles carry the inner format unchanged as MSG.
func TestSyslogWrappedProfiles(t *testing.T) {
	in := conformanceInput()
	for inner, wrapped := range map[string]string{"ecs": "syslog-ecs", "cef": "syslog-cef", "leef": "syslog-leef"} {
		want := oneLine(t, renderFormat(t, inner, in))
		m := parseSyslog(t, oneLine(t, renderFormat(t, wrapped, in)))
		if m.msg != want {
			t.Errorf("%s MSG is not the %s payload\n got %q\nwant %q", wrapped, inner, m.msg, want)
		}
		if m.sdID != "" || m.pri != 83 {
			t.Errorf("%s: sd %q pri %d", wrapped, m.sdID, m.pri)
		}
	}
}

func TestNewReporterKnowsEverySinkFormat(t *testing.T) {
	for _, f := range Formats {
		if _, err := NewReporter(f); err != nil {
			t.Errorf("NewReporter(%q): %v", f, err)
		}
	}
	if _, err := NewReporter("splunk"); err == nil || !strings.Contains(err.Error(), "syslog-cef") {
		t.Errorf("unknown format should list the sink formats, got %v", err)
	}
}

// ── OCSF maps in (RenderSinkBatch) ───────────────────────────────────────────

// viaJSON is what a finding looks like after it crossed a JSON boundary: the
// shape a queue or another process hands back.
func viaJSON(t *testing.T, v any) []map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The contract that keeps the two entry points one format: for a scan's
// findings, rendering the OCSF maps is byte-identical to SinkReporter.
func TestRenderSinkEventsMatchesSinkReporter(t *testing.T) {
	inputs := map[string]Input{
		"full":        fullInput(),
		"conformance": conformanceInput(),
		"hostile":     hostileInput(),
		"empty":       {},
		"round-trip":  roundTripInput(),
		"fusion": {Results: []scanner.ScanResult{stegoBreach("c"), fusionCorroboratedResult("f"), fusionRestated("g")},
			Heuristics: []scanner.HeuristicResult{heuristicBreach("g")}},
	}
	for name, in := range inputs {
		findings := NewOCSFReporter(sinkOpts()...).Build(in)
		maps := viaJSON(t, findings)
		if len(maps) != len(findings) {
			t.Fatalf("%s: %d maps for %d findings", name, len(maps), len(findings))
		}
		for _, format := range SinkFormats() {
			for _, indent := range []bool{false, true} {
				want := renderFormat(t, format, in, WithIndent(indent))
				got, n, err := RenderSinkEvents(format, maps, sinkOpts(WithIndent(indent))...)
				if err != nil {
					t.Fatalf("%s/%s: %v", name, format, err)
				}
				if n != len(findings) {
					t.Errorf("%s/%s: rendered %d of %d", name, format, n, len(findings))
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s/%s (indent %v): the map path and the scan path disagree\n got: %s\nwant: %s", name, format, indent, got, want)
				}
			}
		}
	}
	if n := len(NewOCSFReporter(sinkOpts()...).Build(inputs["full"])); n != 3 {
		t.Fatalf("the full input should hold 3 findings, has %d", n)
	}
	if _, _, err := RenderSinkEvents("splunk", nil); err == nil || !strings.Contains(err.Error(), "syslog-cef") {
		t.Errorf("an unknown format should list the sink formats, got %v", err)
	}
}

// incidentMap builds a correlated incident the way forward.OCSFIncident does:
// Go-typed values, file, process and dst_endpoint evidences, the reporting
// host in unmapped. (This package cannot import forward: forward imports it.)
func incidentMap(uid string, confirmed bool, files []string, pids []int, peers []string) map[string]any {
	severityID, severity := 3, "Medium"
	if confirmed {
		severityID, severity = 4, "High"
	}
	var evidences []map[string]any
	for _, f := range files {
		evidences = append(evidences, map[string]any{"file": map[string]any{"name": baseName(f), "path": f, "type_id": 1, "type": "Regular File"}})
	}
	for _, pid := range pids {
		evidences = append(evidences, map[string]any{"process": map[string]any{"pid": pid}})
	}
	for _, p := range peers {
		evidences = append(evidences, map[string]any{"dst_endpoint": map[string]any{"ip": p}})
	}
	ev := map[string]any{
		"activity_id": OCSFActivityID, "activity_name": OCSFActivityName,
		"category_uid": OCSFCategoryUID, "category_name": OCSFCategoryName,
		"class_uid": OCSFClassUID, "class_name": OCSFClassName,
		"type_uid": OCSFTypeUID, "type_name": OCSFTypeName,
		"time":        fixedTime.UnixMilli(),
		"severity_id": severityID, "severity": severity,
		"status_id": OCSFStatusNew, "status": "New", "is_alert": confirmed,
		"message": "CONFIRMED incident (file+network) reverse shell",
		"metadata": map[string]any{
			"version":     OCSFVersion,
			"product":     map[string]any{"name": "CAU EDR", "version": "9.9.9-test", "vendor_name": "CAU"},
			"logged_time": fixedTime.UnixMilli(),
		},
		"finding_info": map[string]any{
			"title": "CONFIRMED incident (file+network) reverse shell",
			"uid":   uid,
			"desc":  "a shell script opened a socket to a peer",
			"analytic": map[string]any{
				"name": "cau defend correlation", "type_id": 4, "type": "Behavioral", "uid": "inc-0001", "desc": "why",
			},
			"attacks": []map[string]any{{
				"technique": map[string]any{"uid": "T1059.004", "name": "Unix Shell"},
				"version":   "v15",
				"tactics":   []map[string]any{{"name": "Execution"}},
			}},
			"data_sources": []string{"file", "network"},
		},
		"unmapped": map[string]any{"agent_host": "edr-agent-7", "confirmed": confirmed, "score": 9, "layers": []string{"file", "network"}},
	}
	if len(evidences) > 0 {
		ev["evidences"] = evidences
	}
	if len(peers) == 1 {
		ev["dst_endpoint"] = map[string]any{"ip": peers[0]}
	}
	return ev
}

func renderIncident(t *testing.T, format string, m map[string]any) []byte {
	t.Helper()
	b, err := RenderSinkBatch(format, []map[string]any{m}, sinkOpts()...)
	if err != nil || b.Rendered != 1 || len(b.Skipped) != 0 {
		t.Fatalf("%s: rendered %d, skipped %v, err %v", format, b.Rendered, b.Skipped, err)
	}
	// A map that crossed JSON must render to the same bytes as the Go-typed one.
	again, err := RenderSinkBatch(format, viaJSON(t, []map[string]any{m}), sinkOpts()...)
	if err != nil || !bytes.Equal(again.Payload, b.Payload) {
		t.Fatalf("%s: the JSON round-trip of an incident renders differently (err %v)\n native: %s\n json:   %s", format, err, b.Payload, again.Payload)
	}
	return b.Payload
}

func otlpRecordAttrs(t *testing.T, raw []byte) (resource, record map[string]any) {
	t.Helper()
	rl := decodeObject(t, raw)["resourceLogs"].([]any)[0].(map[string]any)
	rec := rl["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	return otlpAttrs(t, dig(t, rl, "resource", "attributes")), otlpAttrs(t, rec["attributes"])
}

// What an incident names and a file finding does not (the peer, the process,
// a second file) reaches every format that has a place for it.
func TestRenderSinkBatchCarriesIncidentFields(t *testing.T) {
	const peer = "203.0.113.7"
	one := incidentMap("fp-one", true, []string{"/tmp/a.sh", "/tmp/b.sh"}, []int{4242}, []string{peer})

	ecs := decodeObject(t, []byte(oneLine(t, renderIncident(t, "ecs", one))))
	if dig(t, ecs, "destination", "ip") != peer || dig(t, ecs, "destination", "address") != peer {
		t.Errorf("ecs destination: %v", ecs["destination"])
	}
	if ips := dig(t, ecs, "related", "ip").([]any); len(ips) != 1 || ips[0] != peer {
		t.Errorf("ecs related.ip: %v", ips)
	}
	if dig(t, ecs, "process", "pid") != float64(4242) {
		t.Errorf("ecs process: %v", ecs["process"])
	}
	if files := dig(t, ecs, "cau", "files").([]any); len(files) != 2 || files[0] != "/tmp/a.sh" || files[1] != "/tmp/b.sh" {
		t.Errorf("ecs cau.files: %v", files)
	}
	if dig(t, ecs, "file", "path") != "/tmp/a.sh" || dig(t, ecs, "host", "name") != "edr-agent-7" {
		t.Errorf("ecs file/host: %v %v", ecs["file"], ecs["host"])
	}
	if dig(t, ecs, "event", "id") != "fp-one" || dig(t, ecs, "event", "severity") != float64(8) || dig(t, ecs, "rule", "id") != "inc-0001" {
		t.Errorf("ecs event/rule: %v %v", ecs["event"], ecs["rule"])
	}
	if ids := dig(t, ecs, "threat", "technique", "id").([]any); len(ids) != 1 || ids[0] != "T1059.004" {
		t.Errorf("ecs threat: %v", ecs["threat"])
	}
	if cat := dig(t, ecs, "event", "category").([]any); cat[0] != "malware" {
		t.Errorf("ecs category with a file: %v", cat)
	}

	_, ext := parseCEF(t, oneLine(t, renderIncident(t, "cef", one)))
	if ext["dst"] != peer || ext["spid"] != "4242" || ext["filePath"] != "/tmp/a.sh" || ext["dvchost"] != "edr-agent-7" {
		t.Errorf("cef: %v", ext)
	}
	_, attrs := parseLEEF(t, oneLine(t, renderIncident(t, "leef", one)))
	if attrs["dst"] != peer || attrs["pids"] != "4242" || attrs["files"] != "/tmp/a.sh,/tmp/b.sh" {
		t.Errorf("leef: %v", attrs)
	}
	sys := parseSyslog(t, oneLine(t, renderIncident(t, "syslog", one)))
	if sys.params["dst"] != peer || sys.params["pids"] != "4242" || sys.params["files"] != "/tmp/a.sh,/tmp/b.sh" || sys.host != "edr-agent-7" || sys.pri != 83 {
		t.Errorf("syslog: %+v", sys)
	}
	gelf := decodeObject(t, []byte(oneLine(t, renderIncident(t, "gelf", one))))
	if gelf["_destination_ip"] != peer || gelf["_pids"] != "4242" || gelf["_files"] != "/tmp/a.sh,/tmp/b.sh" || gelf["host"] != "edr-agent-7" {
		t.Errorf("gelf: %v", gelf)
	}
	checkGELFAdditionalFields(t, gelf)
	res, rec := otlpRecordAttrs(t, renderIncident(t, "otlp", one))
	if rec["destination.ip"] != peer || rec["related.ip"] != peer || rec["process.pid"] != "4242" ||
		rec["cau.files"] != "/tmp/a.sh,/tmp/b.sh" || res["host.name"] != "edr-agent-7" {
		t.Errorf("otlp: %v / %v", res, rec)
	}
	// The wrapped profiles carry the same payloads.
	if m := parseSyslog(t, oneLine(t, renderIncident(t, "syslog-ecs", one))); m.msg != oneLine(t, renderIncident(t, "ecs", one)) {
		t.Errorf("syslog-ecs MSG is not the ecs document")
	}

	// Several peers and processes, no file: no single "destination" is named.
	many := incidentMap("fp-many", false, nil, []int{10, 11}, []string{"198.51.100.9", "2001:db8::5"})
	ecs = decodeObject(t, []byte(oneLine(t, renderIncident(t, "ecs", many))))
	if _, has := ecs["destination"]; has {
		t.Errorf("ecs named one of two peers as the destination: %v", ecs["destination"])
	}
	if _, has := ecs["file"]; has {
		t.Errorf("ecs wrote a file object for an incident without one: %v", ecs["file"])
	}
	if ips := dig(t, ecs, "related", "ip").([]any); len(ips) != 2 || ips[1] != "2001:db8::5" {
		t.Errorf("ecs related.ip: %v", ips)
	}
	if pids := dig(t, ecs, "cau", "pids").([]any); len(pids) != 2 || pids[0] != float64(10) || pids[1] != float64(11) {
		t.Errorf("ecs cau.pids: %v", pids)
	}
	if cat := dig(t, ecs, "event", "category").([]any); cat[0] != "intrusion_detection" {
		t.Errorf("ecs category without a file: %v", cat)
	}
	if dig(t, ecs, "event", "severity") != float64(5) {
		t.Errorf("ecs severity for an unconfirmed incident: %v", dig(t, ecs, "event", "severity"))
	}
	_, ext = parseCEF(t, oneLine(t, renderIncident(t, "cef", many)))
	if ext["flexString1"] != "198.51.100.9,2001:db8::5" || ext["flexString1Label"] != "destinationAddresses" ||
		ext["flexString2"] != "10,11" || ext["flexString2Label"] != "processIds" || ext["dst"] != "" || ext["spid"] != "" || ext["filePath"] != "" {
		t.Errorf("cef: %v", ext)
	}
	_, attrs = parseLEEF(t, oneLine(t, renderIncident(t, "leef", many)))
	if attrs["peers"] != "198.51.100.9,2001:db8::5" || attrs["pids"] != "10,11" || attrs["dst"] != "" {
		t.Errorf("leef: %v", attrs)
	}
	gelf = decodeObject(t, []byte(oneLine(t, renderIncident(t, "gelf", many))))
	if gelf["_peers"] != "198.51.100.9,2001:db8::5" || gelf["_pids"] != "10,11" || gelf["level"] != float64(4) {
		t.Errorf("gelf: %v", gelf)
	}
	if _, has := gelf["_file_path"]; has {
		t.Errorf("gelf wrote a file path for an incident without one")
	}
	checkGELFAdditionalFields(t, gelf)
	_, rec = otlpRecordAttrs(t, renderIncident(t, "otlp", many))
	if rec["related.ip"] != "198.51.100.9,2001:db8::5" || rec["cau.pids"] != "10,11" || rec["destination.ip"] != nil || rec["file.path"] != nil {
		t.Errorf("otlp: %v", rec)
	}

	// One IPv6 peer, and one peer that is a name: typed address fields only
	// ever receive an address of their type.
	v6 := incidentMap("fp-v6", true, nil, nil, []string{"2001:db8::5"})
	_, ext = parseCEF(t, oneLine(t, renderIncident(t, "cef", v6)))
	if ext["c6a3"] != "2001:db8::5" || ext["c6a3Label"] != "Destination IPv6 Address" || ext["dst"] != "" {
		t.Errorf("cef ipv6: %v", ext)
	}
	named := incidentMap("fp-name", true, nil, nil, []string{"c2.example.net"})
	ecs = decodeObject(t, []byte(oneLine(t, renderIncident(t, "ecs", named))))
	if dig(t, ecs, "destination", "address") != "c2.example.net" || dig(t, ecs, "destination", "ip") != nil {
		t.Errorf("ecs put a name in destination.ip: %v", ecs["destination"])
	}
	if hosts := dig(t, ecs, "related", "hosts").([]any); len(hosts) != 1 || hosts[0] != "c2.example.net" || dig(t, ecs, "related", "ip") != nil {
		t.Errorf("ecs related: %v", ecs["related"])
	}
	_, ext = parseCEF(t, oneLine(t, renderIncident(t, "cef", named)))
	if ext["dhost"] != "c2.example.net" || ext["dst"] != "" {
		t.Errorf("cef name: %v", ext)
	}
	gelf = decodeObject(t, []byte(oneLine(t, renderIncident(t, "gelf", named))))
	if gelf["_peers"] != "c2.example.net" || gelf["_destination_ip"] != nil {
		t.Errorf("gelf name: %v", gelf)
	}
}

func checkGELFAdditionalFields(t *testing.T, m map[string]any) {
	t.Helper()
	std := map[string]bool{"version": true, "host": true, "short_message": true, "full_message": true, "timestamp": true, "level": true}
	for k, v := range m {
		if std[k] {
			continue
		}
		if !gelfField.MatchString(k) || k == "_id" {
			t.Errorf("additional field %q is not a legal GELF field name", k)
		}
		switch v.(type) {
		case string, float64:
		default:
			t.Errorf("additional field %s must be a string or number, is %T", k, v)
		}
	}
}

// An incident's own strings are as attacker-reachable as a file name: a peer
// or a second path with a newline must not forge an event either.
func TestRenderSinkBatchHostileIncident(t *testing.T) {
	m := incidentMap("fp-hostile", true, []string{"/tmp/ok.sh", hostilePath}, []int{7}, []string{hostilePath})
	for _, format := range SinkFormats() {
		out := string(renderIncident(t, format, m))
		if format != "otlp" && strings.Count(out, "\n") != 1 {
			t.Errorf("%s: %d lines for one incident:\n%s", format, strings.Count(out, "\n"), out)
		}
		if strings.ContainsAny(strings.TrimSuffix(out, "\n"), "\x1b\u202e\r") {
			t.Errorf("%s: a raw control or bidi character reached the output", format)
		}
	}
	ecs := decodeObject(t, renderIncident(t, "ecs", m))
	if files := dig(t, ecs, "cau", "files").([]any); files[1] != hostilePath {
		t.Errorf("ecs does not carry the second path byte for byte: %q", files[1])
	}
	if dig(t, ecs, "destination", "address") != hostilePath || dig(t, ecs, "destination", "ip") != nil {
		t.Errorf("ecs destination: %v", ecs["destination"])
	}
	sys := parseSyslog(t, oneLine(t, renderIncident(t, "syslog", m)))
	if sys.params["pids"] != "7" || sys.params["product"] != "CAU EDR" {
		t.Errorf("syslog: the hostile strings displaced other parameters: %v", sys.params)
	}
}

// A map that is not a finding is skipped and reported by index; a finding
// with fields of the wrong type renders with what could be read. Nothing
// panics.
func TestRenderSinkBatchMalformedMaps(t *testing.T) {
	good := incidentMap("fp-good", true, []string{"/tmp/a.sh"}, []int{1}, []string{"203.0.113.7"})
	noUID := incidentMap("", true, nil, nil, nil)
	wrongClass := incidentMap("fp-net", true, nil, nil, nil)
	wrongClass["class_uid"] = 4001
	classAsText := incidentMap("fp-text", true, nil, nil, nil)
	classAsText["class_uid"] = "2004"
	// Every field present and of the wrong type, around a valid class and uid.
	garbled := map[string]any{
		"class_uid":   float64(2004),
		"time":        "yesterday",
		"severity_id": 99,
		"severity":    []string{"High"},
		"confidence":  7,
		"metadata":    "none",
		"finding_info": map[string]any{
			"uid": "fp-garbled", "title": 12, "desc": nil, "analytic": []any{"x"},
			"types":   []any{"file", 3, nil, map[string]any{}},
			"attacks": []any{"T1059", map[string]any{"technique": "T1059"}, map[string]any{"technique": map[string]any{"uid": 5}}, map[string]any{"technique": map[string]any{"uid": "T1105"}, "tactics": "Execution"}},
		},
		"evidences": []any{
			nil, "file", map[string]any{"file": "a"}, map[string]any{"process": map[string]any{"pid": "12"}},
			map[string]any{"process": map[string]any{"pid": 12.5}}, map[string]any{"process": map[string]any{"pid": float64(12)}},
			map[string]any{"file": map[string]any{"path": 9, "size": -1.5, "hashes": []any{1, map[string]any{"algorithm_id": "3", "value": "x"}, map[string]any{"algorithm_id": 3, "value": fixtureSHA256}}}},
			map[string]any{"dst_endpoint": map[string]any{"ip": 16}},
		},
		"dst_endpoint": []string{"203.0.113.7"},
		"malware":      map[string]any{"name": "x"},
		"unmapped":     []any{},
	}
	batch := []map[string]any{nil, good, {}, noUID, garbled, wrongClass, classAsText, {"finding_info": "x", "class_uid": 2004}}
	for _, format := range SinkFormats() {
		b, err := RenderSinkBatch(format, batch, sinkOpts()...)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if want := []int{0, 2, 3, 5, 6, 7}; b.Rendered != 2 || !reflect.DeepEqual(b.Skipped, want) {
			t.Errorf("%s: rendered %d, skipped %v; want 2 and %v", format, b.Rendered, b.Skipped, want)
		}
		out := string(b.Payload)
		if format != "otlp" && strings.Count(out, "\n") != 2 {
			t.Errorf("%s: %d lines for 2 events", format, strings.Count(out, "\n"))
		}
		if !strings.Contains(out, "fp-good") || !strings.Contains(out, "fp-garbled") || strings.Contains(out, "fp-net") {
			t.Errorf("%s: wrong events rendered:\n%s", format, out)
		}
	}

	// What the garbled finding still says.
	b, _ := RenderSinkBatch("ecs", []map[string]any{garbled}, sinkOpts()...)
	doc := decodeObject(t, b.Payload)
	if ts, err := time.Parse(time.RFC3339Nano, doc["@timestamp"].(string)); err != nil || !ts.Equal(fixedTime) {
		t.Errorf("an unreadable time should be the reporter's clock, got %v", doc["@timestamp"])
	}
	if dig(t, doc, "host", "name") != "edr-host-01" {
		t.Errorf("host should fall back to the configured name: %v", doc["host"])
	}
	if dig(t, doc, "file", "hash", "sha256") != fixtureSHA256 || dig(t, doc, "file", "size") != nil || dig(t, doc, "file", "path") != "" {
		t.Errorf("file: %v", doc["file"])
	}
	if dig(t, doc, "process", "pid") != float64(12) {
		t.Errorf("only the one whole-number pid should be read: %v", doc["process"])
	}
	if ids := dig(t, doc, "threat", "technique", "id").([]any); len(ids) != 1 || ids[0] != "T1105" {
		t.Errorf("techniques: %v", ids)
	}
	if det := dig(t, doc, "cau", "detectors").([]any); len(det) != 1 || det[0] != "file" {
		t.Errorf("detectors: %v", det)
	}
	if _, has := doc["destination"]; has {
		t.Errorf("a dst_endpoint of the wrong type became a destination: %v", doc["destination"])
	}
	// severity_id 99 ("Other") names no tier: it must not read as high.
	if dig(t, doc, "event", "severity") != float64(5) {
		t.Errorf("severity: %v", dig(t, doc, "event", "severity"))
	}
}

func TestMapIntAcceptsOnlyWholeNumbers(t *testing.T) {
	for _, v := range []any{int(5), int8(5), int16(5), int32(5), int64(5), uint(5), uint8(5), uint16(5), uint32(5), uint64(5), float32(5), float64(5), json.Number("5")} {
		if n, ok := mapInt(v); !ok || n != 5 {
			t.Errorf("mapInt(%T) = %d, %v", v, n, ok)
		}
	}
	nan := 0.0
	for _, v := range []any{nil, "5", true, 5.5, 1e19, -1e19, nan / nan, uint64(1 << 63), json.Number("5.5"), json.Number("x"), []int{5}} {
		if n, ok := mapInt(v); ok {
			t.Errorf("mapInt(%v) accepted as %d", v, n)
		}
	}
	if n, ok := mapInt(float64(-1 << 63)); !ok || n != -1<<63 {
		t.Errorf("the smallest int64 is a whole number: %d %v", n, ok)
	}
	big := make([]string, maxSinkListItems+50)
	if got := len(mapList(big)); got != maxSinkListItems {
		t.Errorf("mapList read %d items, cap is %d", got, maxSinkListItems)
	}
	if got := len(mapList(make([]any, maxSinkListItems+50))); got != maxSinkListItems {
		t.Errorf("mapList read %d items, cap is %d", got, maxSinkListItems)
	}
}

// FuzzRenderSinkBatch: any JSON whatsoever, in every format. Invariants: no
// panic, every finding is either rendered or listed as skipped, a line format
// has exactly one line per rendered event, and no output holds a raw escape.
func FuzzRenderSinkBatch(f *testing.F) {
	seed := func(v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	seed([]map[string]any{incidentMap("fp-seed", true, []string{"/tmp/a.sh", "/tmp/b.sh"}, []int{1, 2}, []string{"203.0.113.7"})})
	seed(NewOCSFReporter(sinkOpts()...).Build(fullInput()))
	seed(NewOCSFReporter(sinkOpts()...).Build(hostileInput()))
	f.Add([]byte(`[{"class_uid":2004,"finding_info":{"uid":"u","attacks":[{"technique":{"uid":"T1"},"tactics":[{"name":"\u001b[2K"}]}]},"evidences":[{"file":{"path":"a\nb","hashes":[{"algorithm_id":3,"value":"\u202e"}]}},{"process":{"pid":1e300}},{"dst_endpoint":{"hostname":"x\ty"}}],"time":1e30,"severity_id":-4}]`))
	f.Add([]byte(`[null,{},{"class_uid":"2004"},{"class_uid":2004,"finding_info":[]}]`))
	f.Add([]byte(`{"class_uid":2004,"finding_info":{"uid":"single object, not a list"}}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		var findings []map[string]any
		if json.Unmarshal(raw, &findings) != nil {
			var one map[string]any
			if json.Unmarshal(raw, &one) != nil {
				return
			}
			findings = []map[string]any{one}
		}
		for _, format := range SinkFormats() {
			b, err := RenderSinkBatch(format, findings, sinkOpts()...)
			if err != nil {
				t.Fatalf("%s: %v", format, err)
			}
			if b.Rendered+len(b.Skipped) != len(findings) {
				t.Fatalf("%s: %d rendered + %d skipped != %d findings", format, b.Rendered, len(b.Skipped), len(findings))
			}
			if bytes.IndexByte(b.Payload, 0x1b) >= 0 {
				t.Fatalf("%s: a raw escape byte reached the output", format)
			}
			if format == "otlp" {
				var doc map[string]any
				if err := json.Unmarshal(b.Payload, &doc); err != nil {
					t.Fatalf("otlp is not JSON: %v", err)
				}
				continue
			}
			if n := bytes.Count(b.Payload, []byte{'\n'}); n != b.Rendered {
				t.Fatalf("%s: %d lines for %d events:\n%s", format, n, b.Rendered, b.Payload)
			}
		}
	})
}

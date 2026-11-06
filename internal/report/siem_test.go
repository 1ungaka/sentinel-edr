package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/scanner"
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
					items = append(items, it.(map[string]any)["stringValue"].(string))
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

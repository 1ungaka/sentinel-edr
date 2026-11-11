package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/1ungaka/sentinel-edr/scanner"
)

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func get(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, k := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %q is not an object", path, k)
		}
		cur, ok = obj[k]
		if !ok {
			t.Fatalf("path %v: key %q missing", path, k)
		}
	}
	return cur
}

func fullInput() Input {
	return Input{
		Results: []scanner.ScanResult{
			hashResult("samples/wannacry.exe"),
			yaraResult("samples/dropper.bin"),
			cleanResult("samples/notepad.exe"),
			errorResult("samples/locked.bin"),
		},
		Heuristics: []scanner.HeuristicResult{
			heuristic("samples/wannacry.exe", 0),
			heuristicBreach("samples/dropper.bin"),
			heuristicLow("samples/notepad.exe"),
			heuristicError("samples/locked.bin"),
			heuristicBreach("samples/heuristic-only.exe"),
		},
		Elapsed: 1234 * time.Millisecond,
	}
}

func TestJSONDocumentShape(t *testing.T) {
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts(WithFailOn(FailOnHeuristic), WithRoot("/srv"))...).Write(&buf, fullInput()); err != nil {
		t.Fatal(err)
	}
	m := decodeJSON(t, buf.Bytes())

	if got := get(t, m, "schema_version"); got != JSONSchemaVersion {
		t.Errorf("schema_version = %v", got)
	}
	if got := get(t, m, "tool", "name"); got != DefaultToolName {
		t.Errorf("tool.name = %v", got)
	}
	if got := get(t, m, "tool", "version"); got != "9.9.9-test" {
		t.Errorf("tool.version = %v", got)
	}
	if got := get(t, m, "tool", "tagline"); got != DefaultToolTagline {
		t.Errorf("tool.tagline = %v", got)
	}
	if got := get(t, m, "generated_at"); got != "2026-10-24T12:00:00Z" {
		t.Errorf("generated_at = %v", got)
	}
	if got := get(t, m, "root"); got != "/srv" {
		t.Errorf("root = %v", got)
	}

	sum := get(t, m, "summary").(map[string]any)
	wantSum := map[string]any{
		"files_scanned":        5.0,
		"hash_detections":      1.0,
		"yara_detections":      1.0,
		"heuristic_detections": 2.0,
		"errors":               2.0,
		"elapsed_ms":           1234.0,
		"heuristic_threshold":  3.0,
		"verdict":              "malicious",
		"fail_on":              "heuristic",
		"exit_code":            float64(ExitScanFailed),
	}
	for k, v := range wantSum {
		if sum[k] != v {
			t.Errorf("summary.%s = %v, want %v", k, sum[k], v)
		}
	}
	if _, ok := sum["exit_reason"].(string); !ok {
		t.Error("summary.exit_reason missing")
	}
	if _, ok := m["run_error"]; ok {
		t.Error("run_error must be omitted when nil")
	}

	files := get(t, m, "files").([]any)
	if len(files) != 5 {
		t.Fatalf("files has %d entries, want 5", len(files))
	}
	byPath := map[string]map[string]any{}
	for _, f := range files {
		fm := f.(map[string]any)
		byPath[fm["path"].(string)] = fm
	}
	// Scan order first, heuristic-only tail last.
	if files[4].(map[string]any)["path"] != "samples/heuristic-only.exe" {
		t.Errorf("heuristic-only path should be last, got %v", files[4].(map[string]any)["path"])
	}

	// Hash hit.
	wc := byPath["samples/wannacry.exe"]
	if wc["verdict"] != "malicious" {
		t.Errorf("wannacry verdict = %v", wc["verdict"])
	}
	if got := get(t, wc, "hash_match", "threat"); got != "WannaCry Ransomware" {
		t.Errorf("hash_match.threat = %v", got)
	}
	if got := get(t, wc, "hash_match", "type"); got != "SHA256" {
		t.Errorf("hash_match.type = %v", got)
	}
	if got := get(t, wc, "hashes", "sha256"); got != hashResult("x").SHA256 {
		t.Errorf("hashes.sha256 = %v", got)
	}
	if got := wc["size"]; got != float64(1000+len("samples/wannacry.exe")) {
		t.Errorf("size = %v (StatFunc not used)", got)
	}
	if got := wc["scan_time_ms"]; got != 12.0 {
		t.Errorf("scan_time_ms = %v", got)
	}
	if got := get(t, wc, "heuristics", "detected"); got != false {
		t.Errorf("wannacry heuristics.detected = %v", got)
	}

	// YARA hit.
	dr := byPath["samples/dropper.bin"]
	if dr["verdict"] != "malicious" {
		t.Errorf("dropper verdict = %v", dr["verdict"])
	}
	if _, ok := dr["hash_match"]; ok {
		t.Error("dropper must not carry hash_match")
	}
	yara := dr["yara"].([]any)
	if len(yara) != 1 {
		t.Fatalf("dropper yara has %d hits", len(yara))
	}
	hit := yara[0].(map[string]any)
	if hit["rule"] != "wannacry_ransomware" || hit["namespace"] != "default" {
		t.Errorf("yara hit = %v", hit)
	}
	if tags := hit["tags"].([]any); len(tags) != 2 || tags[0] != "apt" || tags[1] != "ransomware" {
		t.Errorf("tags not sorted: %v", tags)
	}
	meta := hit["meta"].([]any)
	if len(meta) != 4 {
		t.Fatalf("meta has %d pairs, want 4", len(meta))
	}
	if p := meta[2].(map[string]any); p["key"] != "threat_level" || p["value"] != "3" {
		t.Errorf("meta[2] = %v", p)
	}
	if p := meta[3].(map[string]any); p["key"] != "in_the_wild" || p["value"] != "false" {
		t.Errorf("meta[3] = %v", p)
	}
	strs := hit["strings"].([]any)
	s0 := strs[0].(map[string]any)
	if s0["name"] != "$c" || s0["offset"] != float64(0x3a20) || s0["data_hex"] != "574e6372794032303137" ||
		s0["preview"] != "WNcry@2017" || s0["truncated"] != false || s0["length"] != 10.0 {
		t.Errorf("string[0] = %v", s0)
	}
	// Heuristic breach on the same file.
	if got := get(t, dr, "heuristics", "score"); got != 7.0 {
		t.Errorf("dropper heuristics.score = %v", got)
	}
	if got := get(t, dr, "heuristics", "detected"); got != true {
		t.Errorf("dropper heuristics.detected = %v", got)
	}
	hm := get(t, dr, "heuristics", "matches").([]any)
	if len(hm) != 3 || hm[0].(map[string]any)["indicator"] != "WriteProcessMemory" {
		t.Errorf("heuristic matches = %v", hm)
	}

	// Clean file with low heuristics.
	np := byPath["samples/notepad.exe"]
	if np["verdict"] != "clean" {
		t.Errorf("notepad verdict = %v", np["verdict"])
	}
	if got := get(t, np, "heuristics", "threshold"); got != 3.0 {
		t.Errorf("threshold = %v", got)
	}

	// Errored file.
	lk := byPath["samples/locked.bin"]
	if lk["verdict"] != "error" {
		t.Errorf("locked verdict = %v", lk["verdict"])
	}
	if !strings.Contains(lk["error"].(string), "permission denied") {
		t.Errorf("error string = %v", lk["error"])
	}
	if !strings.Contains(get(t, lk, "heuristics", "error").(string), "EIO") {
		t.Errorf("heuristics.error = %v", get(t, lk, "heuristics", "error"))
	}
	if _, ok := lk["hashes"]; ok {
		t.Error("errored file must not carry hashes")
	}

	// Heuristic-only path.
	ho := byPath["samples/heuristic-only.exe"]
	if ho["verdict"] != "suspicious" {
		t.Errorf("heuristic-only verdict = %v", ho["verdict"])
	}
	if _, ok := ho["hashes"]; ok {
		t.Error("heuristic-only file must not carry hashes")
	}
}

func TestJSONVerdictAndExitAgree(t *testing.T) {
	cases := []struct {
		name    string
		in      Input
		verdict string
		exit    int
	}{
		{"empty", Input{}, "clean", ExitOK},
		{"clean", Input{Results: []scanner.ScanResult{cleanResult("a")}}, "clean", ExitOK},
		{"suspicious", Input{Heuristics: []scanner.HeuristicResult{heuristicBreach("a")}}, "suspicious", ExitOK},
		{"malicious", Input{Results: []scanner.ScanResult{yaraResult("a")}}, "malicious", ExitThreat},
		{"error", Input{RunError: errors.New("no db")}, "error", ExitRunFailed},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		if err := NewJSONReporter(testOpts()...).Write(&buf, tc.in); err != nil {
			t.Fatal(err)
		}
		m := decodeJSON(t, buf.Bytes())
		if got := get(t, m, "summary", "verdict"); got != tc.verdict {
			t.Errorf("%s: verdict = %v, want %s", tc.name, got, tc.verdict)
		}
		if got := get(t, m, "summary", "exit_code"); got != float64(tc.exit) {
			t.Errorf("%s: exit_code = %v, want %d", tc.name, got, tc.exit)
		}
		if tc.in.RunError != nil {
			if got := get(t, m, "run_error"); got != "no db" {
				t.Errorf("run_error = %v", got)
			}
		}
		if files := get(t, m, "files"); files == nil {
			t.Errorf("%s: files must be [] not null", tc.name)
		}
	}
}

func TestJSONTruncatesHugeMatch(t *testing.T) {
	r := cleanResult("a")
	m := yaraMatch()
	m.Strings = []scanner.YaraMatchString{bigMatch(10 * 1024)}
	r.YaraMatches = []scanner.YaraMatch{m}

	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 8*1024 {
		t.Errorf("document is %d bytes for a 10 KB match; truncation did not bite", buf.Len())
	}
	doc := decodeJSON(t, buf.Bytes())
	s := get(t, doc, "files").([]any)[0].(map[string]any)["yara"].([]any)[0].(map[string]any)["strings"].([]any)[0].(map[string]any)
	if s["truncated"] != true {
		t.Error("truncated flag not set")
	}
	if s["length"] != 10240.0 {
		t.Errorf("length = %v, want 10240", s["length"])
	}
	if len(s["data_hex"].(string)) != 2*DefaultMaxMatchStringBytes {
		t.Errorf("data_hex is %d chars, want %d", len(s["data_hex"].(string)), 2*DefaultMaxMatchStringBytes)
	}
	if len(s["preview"].(string)) != DefaultMaxPreviewBytes {
		t.Errorf("preview is %d chars, want %d", len(s["preview"].(string)), DefaultMaxPreviewBytes)
	}
}

func TestJSONSurvivesHostileStrings(t *testing.T) {
	r := hashResult("samples/\xff\xfe<script>alert(1)</script>.exe")
	r.ThreatName = strings.Repeat("A", 5000) + "\x00<b>"
	r.YaraMatches = []scanner.YaraMatch{{
		RuleName:  "r",
		Namespace: "n",
		Strings:   []scanner.YaraMatchString{{Name: "$a", Data: []byte{0x00, 0xff, '<', '>'}}},
	}}
	h := heuristicBreach(r.FilePath)
	h.Matches[0].Indicator = "\xc0\xafbad"

	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}, Heuristics: []scanner.HeuristicResult{h}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !utf8.ValidString(out) {
		t.Fatal("output is not valid UTF-8")
	}
	if strings.Contains(out, "<script>") || strings.Contains(out, "<b>") {
		t.Error("HTML was not escaped")
	}
	m := decodeJSON(t, buf.Bytes())
	f := get(t, m, "files").([]any)[0].(map[string]any)
	if !strings.Contains(f["path"].(string), "�") {
		t.Errorf("invalid UTF-8 in path was not replaced: %q", f["path"])
	}
	threat := get(t, f, "hash_match", "threat").(string)
	if !strings.HasSuffix(threat, TruncationMarker) || utf8.RuneCountInString(threat) > DefaultMaxMessageRunes+utf8.RuneCountInString(TruncationMarker) {
		t.Errorf("threat name not bounded: len %d", utf8.RuneCountInString(threat))
	}
	// The hostile heuristic path has no ScanResult of its own? It does (same path), so it correlates.
	if got := get(t, f, "heuristics", "score"); got != 7.0 {
		t.Errorf("heuristics did not correlate by path: %v", got)
	}
}

func TestJSONIndentAndDeterminism(t *testing.T) {
	in := fullInput()
	var a, b bytes.Buffer
	if err := NewJSONReporter(testOpts(WithIndent(true))...).Write(&a, in); err != nil {
		t.Fatal(err)
	}
	if err := NewJSONReporter(testOpts(WithIndent(true))...).Write(&b, in); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Error("two renders of the same input differ")
	}
	if !strings.Contains(a.String(), "\n  \"schema_version\"") {
		t.Error("WithIndent(true) did not indent")
	}
	var c bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&c, in); err != nil {
		t.Fatal(err)
	}
	if strings.Count(c.String(), "\n") != 1 {
		t.Error("compact output should be a single line")
	}
}

func TestJSONMissingFileSizeIsNull(t *testing.T) {
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{errorResult("samples/missing.bin")}}); err != nil {
		t.Fatal(err)
	}
	m := decodeJSON(t, buf.Bytes())
	f := get(t, m, "files").([]any)[0].(map[string]any)
	if v, ok := f["size"]; !ok || v != nil {
		t.Errorf("size = %v (present=%v), want null", v, ok)
	}
}

func TestNewReporter(t *testing.T) {
	for _, f := range []string{"text", "JSON", " sarif ", ""} {
		if _, err := NewReporter(f, testOpts()...); err != nil {
			t.Errorf("NewReporter(%q): %v", f, err)
		}
	}
	if _, err := NewReporter("xml"); err == nil || !strings.Contains(err.Error(), "text, json, sarif") {
		t.Errorf("NewReporter(xml) err = %v", err)
	}
	var _ Reporter = NewJSONReporter()
	var _ Reporter = NewSARIFReporter()
	var _ Reporter = NewTextReporter()
}

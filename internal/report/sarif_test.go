package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner"
)

func renderSARIF(t *testing.T, in Input, opts ...Option) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := NewSARIFReporter(testOpts(opts...)...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	return decodeJSON(t, buf.Bytes())
}

// checkSARIFStructure verifies the invariants every SARIF log must hold.
func checkSARIFStructure(t *testing.T, m map[string]any) (rules []any, results []any) {
	t.Helper()
	if m["$schema"] != SARIFSchema || m["version"] != SARIFVersion {
		t.Errorf("header = %v / %v", m["$schema"], m["version"])
	}
	runs := m["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	run := runs[0].(map[string]any)
	driver := get(t, run, "tool", "driver").(map[string]any)
	for _, k := range []string{"name", "version", "informationUri", "rules"} {
		if _, ok := driver[k]; !ok {
			t.Errorf("driver.%s missing", k)
		}
	}
	rules = driver["rules"].([]any)
	results = run["results"].([]any)
	inv := run["invocations"].([]any)
	if len(inv) != 1 {
		t.Fatalf("invocations = %d", len(inv))
	}
	if _, ok := inv[0].(map[string]any)["executionSuccessful"]; !ok {
		t.Error("invocation.executionSuccessful missing")
	}

	ids := map[string]int{}
	for i, r := range rules {
		rm := r.(map[string]any)
		id := rm["id"].(string)
		if _, dup := ids[id]; dup {
			t.Errorf("duplicate rule id %s", id)
		}
		ids[id] = i
		if i > 0 && rules[i-1].(map[string]any)["id"].(string) > id {
			t.Errorf("rules not sorted at %d: %s", i, id)
		}
		if _, ok := rm["shortDescription"]; !ok {
			t.Errorf("rule %s has no shortDescription", id)
		}
	}
	for i, r := range results {
		rm := r.(map[string]any)
		id, _ := rm["ruleId"].(string)
		idx := int(rm["ruleIndex"].(float64))
		want, ok := ids[id]
		if !ok {
			t.Errorf("result %d references unknown rule %q", i, id)
		} else if idx != want {
			t.Errorf("result %d ruleIndex %d does not point at %s (index %d)", i, idx, id, want)
		}
		switch rm["level"] {
		case LevelError, LevelWarning, LevelNote, LevelNone:
		default:
			t.Errorf("result %d has invalid level %v", i, rm["level"])
		}
		if txt := get(t, rm, "message", "text").(string); txt == "" {
			t.Errorf("result %d has empty message", i)
		}
		locs := rm["locations"].([]any)
		if len(locs) == 0 {
			t.Errorf("result %d has no locations", i)
		}
		for _, l := range locs {
			art := get(t, l.(map[string]any), "physicalLocation", "artifactLocation").(map[string]any)
			uri := art["uri"].(string)
			if uri == "" || strings.Contains(uri, `\`) || strings.Contains(uri, " ") {
				t.Errorf("result %d has bad uri %q", i, uri)
			}
			if _, rel := art["uriBaseId"]; rel && strings.HasPrefix(uri, "file:") {
				t.Errorf("result %d: absolute uri with uriBaseId", i)
			}
		}
	}
	return rules, results
}

func TestSARIFFullRun(t *testing.T) {
	m := renderSARIF(t, fullInput(), WithRoot("/srv"), WithFailOn(FailOnHeuristic))
	rules, results := checkSARIFStructure(t, m)

	wantRules := []string{
		"hash/wannacry-ransomware",
		"heuristic/score",
		"scan/error",
		"yara/default/wannacry_ransomware",
	}
	if len(rules) != len(wantRules) {
		t.Fatalf("rules = %d, want %d", len(rules), len(wantRules))
	}
	for i, want := range wantRules {
		if got := rules[i].(map[string]any)["id"]; got != want {
			t.Errorf("rules[%d] = %v, want %s", i, got, want)
		}
	}
	yr := rules[3].(map[string]any)
	if got := get(t, yr, "shortDescription", "text"); got != "Detects WannaCry strings" {
		t.Errorf("yara rule shortDescription = %v", got)
	}
	if got := get(t, yr, "properties", "threat_level"); got != 3.0 {
		t.Errorf("yara rule threat_level = %v", got)
	}
	if tags := get(t, yr, "properties", "tags").([]any); len(tags) != 2 || tags[0] != "apt" {
		t.Errorf("yara rule tags = %v", tags)
	}
	if got := get(t, yr, "defaultConfiguration", "level"); got != LevelError {
		t.Errorf("yara default level = %v", got)
	}

	// hash, yara, heuristic(dropper), scan error (locked) ×2 (scan + heuristics), heuristic-only.
	if len(results) != 6 {
		for _, r := range results {
			t.Logf("  %v", r.(map[string]any)["ruleId"])
		}
		t.Fatalf("results = %d, want 6", len(results))
	}
	counts := map[string]int{}
	for _, r := range results {
		counts[r.(map[string]any)["ruleId"].(string)]++
	}
	if counts["hash/wannacry-ransomware"] != 1 || counts["yara/default/wannacry_ransomware"] != 1 ||
		counts["heuristic/score"] != 2 || counts["scan/error"] != 2 {
		t.Errorf("result counts by rule = %v", counts)
	}

	// Hash result.
	hr := results[0].(map[string]any)
	if hr["level"] != LevelError {
		t.Errorf("hash level = %v", hr["level"])
	}
	if got := get(t, hr, "partialFingerprints", "sha256/v1"); got != hashResult("x").SHA256 {
		t.Errorf("fingerprint = %v", got)
	}
	// Paths are not under /srv (they are relative), so the URI stays relative and bare.
	art := get(t, hr["locations"].([]any)[0].(map[string]any), "physicalLocation", "artifactLocation").(map[string]any)
	if art["uri"] != "samples/wannacry.exe" {
		t.Errorf("hash uri = %v", art["uri"])
	}

	// YARA result: one location per string with byte regions.
	yres := results[1].(map[string]any)
	locs := yres["locations"].([]any)
	if len(locs) != 2 {
		t.Fatalf("yara locations = %d, want 2", len(locs))
	}
	reg := get(t, locs[0].(map[string]any), "physicalLocation", "region").(map[string]any)
	if reg["byteOffset"] != float64(0x3a20) || reg["byteLength"] != 10.0 {
		t.Errorf("region[0] = %v", reg)
	}
	if got := get(t, reg, "snippet", "binary"); got != "574e6372794032303137" {
		t.Errorf("snippet.binary = %v", got)
	}
	if got := get(t, reg, "snippet", "text"); got != "WNcry@2017" {
		t.Errorf("snippet.text = %v", got)
	}
	reg1 := get(t, locs[1].(map[string]any), "physicalLocation", "region").(map[string]any)
	if reg1["byteOffset"] != float64(0x5c10) || reg1["byteLength"] != 20.0 {
		t.Errorf("region[1] = %v", reg1)
	}
	if !strings.Contains(get(t, yres, "message", "text").(string), "Detects WannaCry strings") {
		t.Errorf("yara message = %v", get(t, yres, "message", "text"))
	}

	// Heuristic result follows its file's scan results.
	hres := results[2].(map[string]any)
	if hres["ruleId"] != "heuristic/score" || hres["level"] != LevelNote {
		t.Errorf("results[2] = %v / %v", hres["ruleId"], hres["level"])
	}
	if got := get(t, hres, "properties", "score"); got != 7.0 {
		t.Errorf("heuristic score = %v", got)
	}
	if !strings.Contains(get(t, hres, "message", "text").(string), "Process Injection, Shell Execution") {
		t.Errorf("heuristic message = %v", get(t, hres, "message", "text"))
	}

	// Invocation.
	inv := m["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != true {
		t.Error("executionSuccessful should be true without a RunError")
	}
	if inv["exitCode"] != float64(ExitScanFailed) {
		t.Errorf("exitCode = %v, want %d", inv["exitCode"], ExitScanFailed)
	}
	if inv["endTimeUtc"] != "2026-10-24T12:00:00Z" {
		t.Errorf("endTimeUtc = %v", inv["endTimeUtc"])
	}
	base := get(t, m["runs"].([]any)[0].(map[string]any), "originalUriBaseIds", SARIFSrcRoot, "uri")
	if base != "file:///srv/" {
		t.Errorf("originalUriBaseIds = %v", base)
	}
}

func TestSARIFRelativeToRoot(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{yaraResult("/repo/bin/a.exe"), hashResult("/elsewhere/b.exe")}}
	m := renderSARIF(t, in, WithRoot("/repo"))
	_, results := checkSARIFStructure(t, m)

	// results are sorted by scan order: yara on a.exe first.
	art := get(t, results[0].(map[string]any)["locations"].([]any)[0].(map[string]any), "physicalLocation", "artifactLocation").(map[string]any)
	if art["uri"] != "bin/a.exe" || art["uriBaseId"] != SARIFSrcRoot {
		t.Errorf("inside-root artifact = %v", art)
	}
	art = get(t, results[1].(map[string]any)["locations"].([]any)[0].(map[string]any), "physicalLocation", "artifactLocation").(map[string]any)
	if art["uri"] != "file:///elsewhere/b.exe" {
		t.Errorf("outside-root artifact = %v", art)
	}
	if _, ok := art["uriBaseId"]; ok {
		t.Error("outside-root artifact must not carry uriBaseId")
	}
}

func TestSARIFRunError(t *testing.T) {
	m := renderSARIF(t, Input{RunError: errors.New("signature database unreadable")})
	rules, results := checkSARIFStructure(t, m)
	if len(rules) != 0 || len(results) != 0 {
		t.Errorf("rules/results = %d/%d, want 0/0", len(rules), len(results))
	}
	inv := m["runs"].([]any)[0].(map[string]any)["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false || inv["exitCode"] != float64(ExitRunFailed) {
		t.Errorf("invocation = %v", inv)
	}
	n := inv["toolExecutionNotifications"].([]any)
	if len(n) != 1 || n[0].(map[string]any)["level"] != LevelError ||
		get(t, n[0].(map[string]any), "message", "text") != "signature database unreadable" {
		t.Errorf("notifications = %v", n)
	}
}

func TestSARIFLevelOverridesAndFilters(t *testing.T) {
	in := fullInput()
	m := renderSARIF(t, in,
		WithSARIFLevels(LevelWarning, LevelNote, LevelNone, "bogus"),
		WithSARIFHeuristics(false),
		WithSARIFScanErrors(false),
	)
	rules, results := checkSARIFStructure(t, m)
	if len(rules) != 2 {
		t.Errorf("rules = %d, want 2 (heuristic and scan/error filtered)", len(rules))
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].(map[string]any)["level"] != LevelWarning {
		t.Errorf("hash level override ignored: %v", results[0].(map[string]any)["level"])
	}
	if results[1].(map[string]any)["level"] != LevelNote {
		t.Errorf("yara level override ignored: %v", results[1].(map[string]any)["level"])
	}

	// Scan errors back on with a bogus level: falls back to warning.
	m = renderSARIF(t, in, WithSARIFLevels("", "", "", "bogus"), WithSARIFHeuristics(false))
	_, results = checkSARIFStructure(t, m)
	for _, r := range results {
		rm := r.(map[string]any)
		if rm["ruleId"] == SARIFRuleScanError && rm["level"] != LevelWarning {
			t.Errorf("bogus scan-error level did not fall back: %v", rm["level"])
		}
	}
}

func TestSARIFYaraWithoutStringsStillHasLocation(t *testing.T) {
	r := cleanResult("a.bin")
	r.YaraMatches = []scanner.YaraMatch{{RuleName: "no_strings", Namespace: ""}}
	m := renderSARIF(t, Input{Results: []scanner.ScanResult{r}})
	rules, results := checkSARIFStructure(t, m)
	if rules[0].(map[string]any)["id"] != "yara/default/no_strings" {
		t.Errorf("empty namespace should map to default: %v", rules[0].(map[string]any)["id"])
	}
	loc := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)
	if _, hasRegion := get(t, loc, "physicalLocation").(map[string]any)["region"]; hasRegion {
		t.Error("no strings: there must be no region")
	}
}

func TestSARIFDeterministicAcrossScanOrder(t *testing.T) {
	a := Input{Results: []scanner.ScanResult{hashResult("x"), yaraResult("y")}}
	b := Input{Results: []scanner.ScanResult{yaraResult("y"), hashResult("x")}}
	ra, _ := checkSARIFStructure(t, renderSARIF(t, a))
	rb, _ := checkSARIFStructure(t, renderSARIF(t, b))
	for i := range ra {
		if ra[i].(map[string]any)["id"] != rb[i].(map[string]any)["id"] {
			t.Errorf("rule table depends on scan order: %v vs %v", ra[i].(map[string]any)["id"], rb[i].(map[string]any)["id"])
		}
	}
}

func TestSARIFHugeMatchIsBounded(t *testing.T) {
	r := cleanResult("a")
	m := yaraMatch()
	m.Strings = []scanner.YaraMatchString{bigMatch(10 * 1024)}
	r.YaraMatches = []scanner.YaraMatch{m}
	var buf bytes.Buffer
	if err := NewSARIFReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 8*1024 {
		t.Errorf("SARIF is %d bytes for a 10 KB match", buf.Len())
	}
	doc := decodeJSON(t, buf.Bytes())
	_, results := checkSARIFStructure(t, doc)
	reg := get(t, results[0].(map[string]any)["locations"].([]any)[0].(map[string]any), "physicalLocation", "region").(map[string]any)
	if reg["byteLength"] != 10240.0 {
		t.Errorf("byteLength must be the true length, got %v", reg["byteLength"])
	}
}

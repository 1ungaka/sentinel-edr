package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner"
)

// Tests for the scanner fields that carry per-result context: the threshold a
// result was scored against, the size the scanner saw, skipped heuristics and
// scan warnings.

func TestPerResultThresholdWins(t *testing.T) {
	// Score 7; config threshold 3 would breach, the result says it was scored
	// against 10, so it must not.
	h := heuristicBreach("a")
	h.Threshold = 10
	in := Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{h}}

	if n := len(in.HeuristicBreach(3)); n != 0 {
		t.Errorf("HeuristicBreach ignored the result's own threshold: %d breaches", n)
	}
	if got := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic))...).Code(in); got != ExitOK {
		t.Errorf("exit code %d, want %d", got, ExitOK)
	}

	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	m := decodeJSON(t, buf.Bytes())
	f := get(t, m, "files").([]any)[0].(map[string]any)
	if got := get(t, f, "heuristics", "threshold"); got != 10.0 {
		t.Errorf("json threshold = %v, want 10", got)
	}
	if got := get(t, f, "heuristics", "detected"); got != false {
		t.Errorf("json detected = %v, want false", got)
	}
	if f["verdict"] != "clean" {
		t.Errorf("verdict = %v, want clean", f["verdict"])
	}

	buf.Reset()
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "DETECTED (Heuristics)") || !strings.Contains(buf.String(), "LOW SUSPICION — a (score: 7)") {
		t.Errorf("text ignored the per-result threshold:\n%s", buf.String())
	}

	// And the other way round: config says 10, result says 5, score 7 breaches.
	h.Threshold = 5
	in.Heuristics = []scanner.HeuristicResult{h}
	if n := len(in.HeuristicBreach(10)); n != 1 {
		t.Errorf("result threshold 5 vs score 7: %d breaches, want 1", n)
	}
	sm := renderSARIF(t, in, WithHeuristicThreshold(10))
	_, results := checkSARIFStructure(t, sm)
	if len(results) != 1 || get(t, results[0].(map[string]any), "properties", "threshold") != 5.0 {
		t.Errorf("sarif heuristic result = %v", results)
	}
	if !strings.Contains(get(t, results[0].(map[string]any), "message", "text").(string), "threshold 5") {
		t.Errorf("sarif message does not name the real threshold: %v", get(t, results[0].(map[string]any), "message", "text"))
	}
}

func TestSkippedHeuristicsAreNeitherBreachNorError(t *testing.T) {
	h := scanner.HeuristicResult{FilePath: "huge.bin", Score: 99, Skipped: "file is 5.0 GiB, over the heuristic size limit"}
	in := Input{Results: []scanner.ScanResult{cleanResult("huge.bin")}, Heuristics: []scanner.HeuristicResult{h}}

	if len(in.HeuristicBreach(3)) != 0 {
		t.Error("a skipped result must not breach, whatever its score")
	}
	if in.FileErrorCount() != 0 {
		t.Error("a skipped result is not an error")
	}
	if got := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic))...).Code(in); got != ExitOK {
		t.Errorf("exit code %d, want %d", got, ExitOK)
	}

	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	f := get(t, decodeJSON(t, buf.Bytes()), "files").([]any)[0].(map[string]any)
	if got := get(t, f, "heuristics", "skipped"); got != h.Skipped {
		t.Errorf("json skipped = %v", got)
	}
	if got := get(t, f, "heuristics", "detected"); got != false {
		t.Error("json detected must be false for a skipped result")
	}

	buf.Reset()
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), " [~] SKIPPED heuristics on huge.bin: file is 5.0 GiB") {
		t.Errorf("text does not report the skip:\n%s", buf.String())
	}

	_, results := checkSARIFStructure(t, renderSARIF(t, in))
	if len(results) != 0 {
		t.Errorf("sarif emitted %d results for a skipped result", len(results))
	}
}

func TestScannerSizeBeatsStat(t *testing.T) {
	r := cleanResult("sized.bin")
	r.Size = 777
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	f := get(t, decodeJSON(t, buf.Bytes()), "files").([]any)[0].(map[string]any)
	if f["size"] != 777.0 {
		t.Errorf("size = %v, want 777 (ScanResult.Size must win over StatFunc)", f["size"])
	}
}

func TestWarningsAndMatchDetailSurface(t *testing.T) {
	r := yaraResult("a")
	r.Warnings = []string{"YARA scan timed out after 30s, results are partial"}
	h := heuristicBreach("a")
	h.Matches[2].Score = 2
	h.Matches[2].Hits = 5
	h.Matches[2].Pattern = "cmd.exe /c"
	h.Matches[2].Examples = []string{"cmd.exe /c whoami", "cmd.exe /c net user"}
	h.Categories = []scanner.CategoryScore{{Category: "Process Injection", Raw: 6, Applied: 5, Cap: 5}, {Category: "Shell Execution", Raw: 2, Applied: 2}}
	in := Input{Results: []scanner.ScanResult{r}, Heuristics: []scanner.HeuristicResult{h}}

	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	f := get(t, decodeJSON(t, buf.Bytes()), "files").([]any)[0].(map[string]any)
	if w := f["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "timed out") {
		t.Errorf("warnings = %v", f["warnings"])
	}
	cats := get(t, f, "heuristics", "categories").([]any)
	if len(cats) != 2 || cats[0].(map[string]any)["applied"] != 5.0 || cats[0].(map[string]any)["cap"] != 5.0 {
		t.Errorf("categories = %v", cats)
	}
	hm := get(t, f, "heuristics", "matches").([]any)[2].(map[string]any)
	if hm["score"] != 2.0 || hm["hits"] != 5.0 || hm["pattern"] != "cmd.exe /c" || len(hm["examples"].([]any)) != 2 {
		t.Errorf("match detail = %v", hm)
	}
	if _, ok := get(t, f, "heuristics", "matches").([]any)[0].(map[string]any)["pattern"]; ok {
		t.Error("pattern equal to indicator must be omitted")
	}

	buf.Reset()
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "     [WARN] YARA scan timed out") {
		t.Errorf("text misses the warning:\n%s", out)
	}
	if !strings.Contains(out, "cmd.exe /c whoami  (x5)") {
		t.Errorf("text misses the hit count:\n%s", out)
	}

	_, results := checkSARIFStructure(t, renderSARIF(t, in))
	var heur map[string]any
	for _, res := range results {
		if res.(map[string]any)["ruleId"] == SARIFRuleHeuristic {
			heur = res.(map[string]any)
		}
	}
	if heur == nil {
		t.Fatal("no heuristic result in sarif")
	}
	ind := get(t, heur, "properties", "indicators").([]any)[2].(map[string]any)
	if ind["score"] != 2.0 || ind["hits"] != 5.0 {
		t.Errorf("sarif indicator = %v", ind)
	}
}

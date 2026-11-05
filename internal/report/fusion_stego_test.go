package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/fusion"
	"github.com/s-b-repo/cau/scanner/stego"
)

// Hermetic stego and fusion fixtures: hand-built results, no scanning.

func stegoClean(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Stego = &stego.Result{FilePath: path, Size: 120, IsText: true, Encoding: "utf-8", Lines: 4}
	return r
}

func stegoExcused(path string) scanner.ScanResult {
	r := stegoClean(path)
	r.Stego.Benign = 3
	r.Stego.Codepoints = []stego.Codepoint{{Rune: 0x200D, Code: "U+200D", Name: "ZERO WIDTH JOINER", Class: stego.ClassZeroWidth, Count: 3, Benign: 3, FirstLine: 2, Excuses: map[string]int{"emoji sequence": 3}}}
	return r
}

func stegoBreach(path string) scanner.ScanResult {
	r := stegoClean(path)
	r.Stego.Suspicious, r.Stego.LongestRun, r.Stego.ASCIICarrier = 8, 8, 8
	r.Stego.Codepoints = []stego.Codepoint{
		{Rune: 0x200B, Code: "U+200B", Name: "ZERO WIDTH SPACE", Class: stego.ClassZeroWidth, Count: 4, FirstOffset: 27, FirstLine: 3, Examples: []string{"line 3: installer<U+200B><U+200C> and <script>"}},
		{Rune: 0x200C, Code: "U+200C", Name: "ZERO WIDTH NON-JOINER", Class: stego.ClassZeroWidth, Count: 4, FirstOffset: 30, FirstLine: 3},
	}
	r.Stego.Findings = []stego.Finding{
		{Class: "stego.zero-width", Score: 6, Detail: "4× U+200B ZERO WIDTH SPACE, 4× U+200C ZERO WIDTH NON-JOINER; first at line 3", Technique: "T1027", Novel: "NOVEL-001"},
		{Class: "stego.payload-run", Score: 2, Detail: "8 consecutive invisible codepoints", Technique: "T1027"},
		{Class: "stego.ascii-carrier", Score: 2, Detail: "8 of 8 scored codepoints sit between ASCII text", Technique: "T1027"},
	}
	r.Stego.Score = 10
	return r
}

func stegoSkipped(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Stego = &stego.Result{FilePath: path, Size: 5000, Score: 99, Skipped: "not a text artifact: contains NUL bytes"}
	return r
}

func stegoError(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Stego = &stego.Result{FilePath: path, Error: errors.New("could not read file: EIO")}
	return r
}

func fusionCorroboratedResult(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Fusion = fusion.Fuse([]fusion.Source{
		{Name: "hash", Definitive: true},
		{Name: "heuristic", Score: 5, Threshold: 7, Evidence: []fusion.Evidence{{Label: "heuristic/process-injection", Detail: "Process Injection 5/8", Technique: "T1055", Weight: 5}}},
		{Name: "static", Score: 6, Threshold: 8, Evidence: []fusion.Evidence{{Label: "static/packer.upx", Detail: "packed with UPX", Technique: "T1027.002", Weight: 2}, {Label: "static/section.rwx", Detail: "writable+executable section(s): UPX1", Technique: "T1027.009", Weight: 3}}},
		{Name: "stego", Skipped: "not a text artifact: contains NUL bytes", Threshold: 4},
	})
	return r
}

func fusionRestated(path string) scanner.ScanResult {
	// One detector crossed on its own; the lattice adds nothing new.
	r := cleanResult(path)
	r.Fusion = fusion.Fuse([]fusion.Source{{Name: "heuristic", Score: 9, Threshold: 7}})
	return r
}

func fusionObserved(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Fusion = fusion.Fuse([]fusion.Source{{Name: "heuristic", Score: 2, Threshold: 7}, {Name: "static", Score: 1, Threshold: 8}})
	return r
}

func TestStegoAndFusionBreachSemantics(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{stegoClean("a"), stegoExcused("b"), stegoBreach("c"), stegoSkipped("d"), stegoError("e"),
		fusionCorroboratedResult("f"), fusionRestated("g"), fusionObserved("h")}}
	if got := in.StegoBreach(DefaultStegoThreshold); len(got) != 1 || got[0].FilePath != "c" {
		t.Errorf("stego breach = %v", got)
	}
	if got := in.FusionCorroborated(); len(got) != 1 || got[0].FilePath != "f" {
		t.Errorf("fusion corroborated = %v", got)
	}
	if in.ErrorCount() != 1 || in.FileErrorCount() != 1 {
		t.Errorf("errors = %d/%d", in.ErrorCount(), in.FileErrorCount())
	}
	// A per-result threshold overrides the fallback.
	r := stegoBreach("x")
	r.Stego.Threshold = 11
	if got := (Input{Results: []scanner.ScanResult{r}}).StegoBreach(1); len(got) != 0 {
		t.Error("per-result threshold ignored")
	}
}

func TestExitPolicyStegoAndFusionTiers(t *testing.T) {
	steg := Input{Results: []scanner.ScanResult{stegoBreach("c")}}
	excused := Input{Results: []scanner.ScanResult{stegoExcused("b")}}
	fused := Input{Results: []scanner.ScanResult{fusionCorroboratedResult("f")}}
	observed := Input{Results: []scanner.ScanResult{fusionObserved("h")}}
	cases := []struct {
		name string
		in   Input
		fail FailOn
		want int
	}{
		{"stego/malicious", steg, FailOnMalicious, ExitOK},
		{"stego/heuristic", steg, FailOnHeuristic, ExitThreat},
		{"stego/clean", steg, FailOnClean, ExitThreat},
		{"stego/none", steg, FailOnNone, ExitOK},
		{"excused/heuristic", excused, FailOnHeuristic, ExitOK},
		{"excused/clean", excused, FailOnClean, ExitOK},
		{"fused/malicious", fused, FailOnMalicious, ExitOK},
		{"fused/heuristic", fused, FailOnHeuristic, ExitThreat},
		{"fused/clean", fused, FailOnClean, ExitThreat},
		{"observed/heuristic", observed, FailOnHeuristic, ExitOK},
		{"observed/clean", observed, FailOnClean, ExitOK},
	}
	for _, tc := range cases {
		p := NewExitPolicy(testOpts(WithFailOn(tc.fail))...)
		if got := p.Code(tc.in); got != tc.want {
			t.Errorf("%s: exit %d want %d (%s)", tc.name, got, tc.want, p.Explain(tc.in))
		}
	}
	p := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic))...)
	if why := p.Explain(steg); !strings.Contains(why, "stego") {
		t.Errorf("explanation does not name the stego tier: %s", why)
	}
	if why := p.Explain(fused); !strings.Contains(why, "fusion") {
		t.Errorf("explanation does not name fusion: %s", why)
	}
	if NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic), WithStegoThreshold(100))...).Code(steg) != ExitOK {
		t.Error("WithStegoThreshold ignored")
	}
}

func TestJSONStegoAndFusion(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{stegoClean("clean.md"), stegoExcused("emoji.md"), stegoBreach("bad.md"), stegoSkipped("blob.bin"), stegoError("err.md"),
		fusionCorroboratedResult("fused.exe"), fusionRestated("heur.exe"), fusionObserved("low.exe")}}
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("HTML escaping is off: hostile example rendered raw")
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != JSONSchemaVersion {
		t.Errorf("schema = %s", doc.SchemaVersion)
	}
	if doc.Summary.StegoDetections != 1 || doc.Summary.FusionDetections != 1 || doc.Summary.StegoThreshold != DefaultStegoThreshold || doc.Summary.Verdict != JSONVerdictSuspicious {
		t.Errorf("summary = %+v", doc.Summary)
	}
	files := map[string]File{}
	for _, f := range doc.Files {
		files[f.Path] = f
	}
	if c := files["clean.md"]; c.Stego == nil || c.Stego.Detected || !c.Stego.IsText || c.Verdict != JSONVerdictClean {
		t.Errorf("clean = %+v", c.Stego)
	}
	if e := files["emoji.md"]; e.Stego == nil || e.Stego.Detected || e.Stego.Benign != 3 || e.Stego.Codepoints[0].Excuses["emoji sequence"] != 3 || e.Verdict != JSONVerdictClean {
		t.Errorf("excused = %+v", e.Stego)
	}
	b := files["bad.md"]
	if b.Stego == nil || !b.Stego.Detected || b.Stego.Score != 10 || b.Stego.Threshold != DefaultStegoThreshold || b.Verdict != JSONVerdictSuspicious {
		t.Errorf("breach = %+v verdict %s", b.Stego, b.Verdict)
	}
	if len(b.Stego.Findings) != 3 || b.Stego.Findings[0].Novel != "NOVEL-001" || len(b.Stego.Codepoints) != 2 || b.Stego.Codepoints[0].FirstLine != 3 {
		t.Errorf("breach detail = %+v", b.Stego)
	}
	if s := files["blob.bin"]; s.Stego == nil || s.Stego.Skipped == "" || s.Stego.Detected || s.Verdict != JSONVerdictClean {
		t.Errorf("skipped = %+v", s)
	}
	if e := files["err.md"]; e.Stego == nil || e.Stego.Error == "" || e.Verdict != JSONVerdictError {
		t.Errorf("error = %+v", e)
	}
	f := files["fused.exe"]
	if f.Fusion == nil || f.Fusion.Tier != "suspicious" || !f.Fusion.Corroborated || f.Verdict != JSONVerdictSuspicious {
		t.Fatalf("fused = %+v verdict %s", f.Fusion, f.Verdict)
	}
	if len(f.Fusion.Agreed) != 2 || f.Fusion.Agreed[0] != "static" || len(f.Fusion.Techniques) != 3 || len(f.Fusion.Sources) != 4 {
		t.Errorf("fused detail = %+v", f.Fusion)
	}
	if f.Fusion.Sources[0].Role != "primary" || f.Fusion.Sources[0].Ratio != 0.75 || f.Fusion.Sources[3].Role != "skipped" {
		t.Errorf("sources = %+v", f.Fusion.Sources)
	}
	if h := files["heur.exe"]; h.Fusion == nil || h.Fusion.Corroborated || h.Verdict != JSONVerdictClean {
		// The heuristic result itself is not in this Input; the lattice restating
		// it must not invent a verdict the heuristics stream would carry.
		t.Errorf("restated = %+v verdict %s", h.Fusion, h.Verdict)
	}
	if l := files["low.exe"]; l.Fusion == nil || l.Fusion.Tier != "observed" || l.Verdict != JSONVerdictClean {
		t.Errorf("observed = %+v", l.Fusion)
	}
	// Malicious + fused stays malicious.
	m := hashResult("mal.bin")
	m.Fusion = fusion.Fuse([]fusion.Source{{Name: "hash", Definitive: true, Hit: true}, {Name: "heuristic", Score: 9, Threshold: 7}})
	doc = NewJSONReporter(testOpts()...).Build(Input{Results: []scanner.ScanResult{m}})
	if doc.Files[0].Verdict != JSONVerdictMalicious || doc.Files[0].Fusion.Tier != "malicious" || doc.Summary.FusionDetections != 0 {
		t.Errorf("malicious + fusion = %+v", doc.Files[0])
	}
}

func TestTextStegoAndFusion(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{stegoClean("clean.md"), stegoExcused("emoji.md"), stegoBreach("bad.md"), stegoError("err.md"),
		fusionCorroboratedResult("fused.exe"), fusionRestated("heur.exe"), fusionObserved("low.exe")}}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"[CLEAN] clean.md",
		"[CLEAN] emoji.md",
		"[!] DETECTED (Stego) — bad.md",
		"10 / 4 threshold",
		"[stego.zero-width] 6",
		"(T1027 NOVEL-001)",
		"U+200B line 3: installer<U+200B><U+200C>",
		"[ERR] Stego analysis on err.md",
		"[!] DETECTED (Fusion) — fused.exe",
		"SUSPICIOUS (fused 1.11 / 1.00, medium confidence)",
		"Agreed    : static, heuristic",
		"Techniques: T1027.002, T1027.009, T1055",
		"[static] 6/8, ratio 0.75, primary",
		"[heuristic] 5/7, ratio 0.71, corroborating",
		"static/packer.upx",
		"Stego detections      : 1",
		"Fused-only detections : 1",
		"THREATS DETECTED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Fusion — heur.exe", "Fusion — low.exe", "emoji sequence"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("text output should not contain %q\n%s", unwanted, out)
		}
	}
}

func TestSARIFStegoAndFusion(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{stegoExcused("emoji.md"), stegoBreach("bad.md"), stegoError("err.md"), fusionCorroboratedResult("fused.exe"), fusionRestated("heur.exe")}}
	m := renderSARIF(t, in)
	rules, results := checkSARIFStructure(t, m)
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.(map[string]any)["id"].(string)] = true
	}
	if !ids["stego/zero-width"] || !ids[SARIFRuleFusion] || !ids[SARIFRuleScanError] || ids["stego/payload-run"] {
		t.Errorf("rules = %v", ids)
	}
	var stegoN, fusionN int
	for _, r := range results {
		rm := r.(map[string]any)
		switch rm["ruleId"] {
		case "stego/zero-width":
			stegoN++
			region := get(t, rm, "locations").([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
			if region["byteOffset"] != 27.0 || region["startLine"] != 3.0 || region["byteLength"] != 3.0 {
				t.Errorf("region = %v", region)
			}
			props := rm["properties"].(map[string]any)
			if props["novel"] != "NOVEL-001" || len(props["codepoints"].([]any)) != 2 || len(props["modifiers"].([]any)) != 2 {
				t.Errorf("props = %v", props)
			}
		case SARIFRuleFusion:
			fusionN++
			props := rm["properties"].(map[string]any)
			if props["score"] != 1.107 || len(props["agreed"].([]any)) != 2 || len(props["sources"].([]any)) != 2 {
				t.Errorf("fusion props = %v", props)
			}
			if !strings.Contains(get(t, rm, "message", "text").(string), "by corroboration") {
				t.Errorf("message = %v", rm["message"])
			}
		}
	}
	if stegoN != 1 || fusionN != 1 {
		t.Errorf("stego results %d fusion results %d", stegoN, fusionN)
	}
	run := m["runs"].([]any)[0].(map[string]any)
	if run["properties"].(map[string]any)["stegoDetections"] != 1.0 || run["properties"].(map[string]any)["fusionDetections"] != 1.0 {
		t.Errorf("run properties = %v", run["properties"])
	}
	// Opting out of heuristic-tier results drops both.
	var buf bytes.Buffer
	_ = NewSARIFReporter(testOpts(WithSARIFHeuristics(false))...).Write(&buf, in)
	if strings.Contains(buf.String(), "stego/") || strings.Contains(buf.String(), SARIFRuleFusion) {
		t.Error("stego/fusion results emitted with heuristics disabled")
	}
}

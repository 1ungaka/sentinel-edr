package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
)

func ocsfRun(t *testing.T, in Input, extra ...Option) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := NewOCSFReporter(testOpts(extra...)...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	return out
}

func TestOCSFEmitsOnlyFindings(t *testing.T) {
	out := ocsfRun(t, fullInput())
	// wannacry (hash), dropper (yara+heuristic), heuristic-only: 3. notepad clean, locked error.
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	for _, f := range out {
		if f["class_uid"].(float64) != 2004 || f["type_uid"].(float64) != 200401 || f["category_uid"].(float64) != 2 {
			t.Errorf("class/type/category wrong: %v", f)
		}
		meta := f["metadata"].(map[string]any)
		if meta["version"] != OCSFVersion || meta["product"].(map[string]any)["version"] != "9.9.9-test" {
			t.Errorf("metadata: %v", meta)
		}
		if f["time"].(float64) != float64(fixedTime.UnixMilli()) {
			t.Errorf("time %v", f["time"])
		}
		ev := f["evidences"].([]any)[0].(map[string]any)["file"].(map[string]any)
		if ev["path"] == "" || ev["name"] == "" || ev["type_id"].(float64) != 1 {
			t.Errorf("evidence: %v", ev)
		}
	}
	empty := ocsfRun(t, Input{})
	if empty == nil || len(empty) != 0 {
		t.Errorf("empty run should encode as [], got %v", empty)
	}
}

func TestOCSFHashFinding(t *testing.T) {
	out := ocsfRun(t, Input{Results: []scanner.ScanResult{hashResult("samples/wannacry.exe")}})
	f := out[0]
	if f["severity_id"].(float64) != 4 || f["is_alert"] != true {
		t.Errorf("malicious should be High and an alert: %v", f)
	}
	info := f["finding_info"].(map[string]any)
	an := info["analytic"].(map[string]any)
	if an["type_id"].(float64) != 5 || an["uid"] != "hash/wannacry-ransomware" || !strings.HasSuffix(an["name"].(string), "/hash") {
		t.Errorf("analytic: %v", an)
	}
	if mw := f["malware"].([]any); len(mw) != 1 || mw[0].(map[string]any)["name"] != "WannaCry Ransomware" {
		t.Errorf("malware: %v", f["malware"])
	}
	hashes := f["evidences"].([]any)[0].(map[string]any)["file"].(map[string]any)["hashes"].([]any)
	if len(hashes) != 3 || hashes[2].(map[string]any)["algorithm_id"].(float64) != 3 {
		t.Errorf("hashes: %v", hashes)
	}
	if !strings.HasPrefix(info["uid"].(string), "cau:") || len(info["uid"].(string)) != 36 {
		t.Errorf("uid: %v", info["uid"])
	}
}

func TestOCSFYaraAndHeuristicAttacks(t *testing.T) {
	r := yaraResult("samples/dropper.bin")
	r.YaraMatches[0].Metas = append(r.YaraMatches[0].Metas,
		scanner.YaraMatchMeta{Identifier: "mitre_attack", Value: "T1486"},
		scanner.YaraMatchMeta{Identifier: "family", Value: "wannacry"})
	h := heuristicBreach("samples/dropper.bin")
	h.Categories = []scanner.CategoryScore{
		{Category: "Process Injection", Applied: 5, Cap: 8, Technique: "T1055"},
		{Category: "Shell Execution", Applied: 2, Cap: 2, Technique: "T1059.003"},
		{Category: "Suspicious Paths", Applied: 0, Cap: 4},
	}
	out := ocsfRun(t, Input{Results: []scanner.ScanResult{r}, Heuristics: []scanner.HeuristicResult{h}}, WithHeuristicThreshold(7))
	f := out[0]
	info := f["finding_info"].(map[string]any)
	var ids []string
	for _, a := range info["attacks"].([]any) {
		tq := a.(map[string]any)["technique"].(map[string]any)
		ids = append(ids, tq["uid"].(string))
		if tq["uid"] == "T1486" && tq["name"] != "Data Encrypted for Impact" {
			t.Errorf("technique name missing: %v", tq)
		}
	}
	if strings.Join(ids, ",") != "T1055,T1059.003,T1486" {
		t.Errorf("attacks = %v", ids)
	}
	an := info["analytic"].(map[string]any)
	if an["uid"] != "yara/default/wannacry_ransomware" || an["type_id"].(float64) != 1 || an["desc"] != "Detects WannaCry strings" {
		t.Errorf("analytic: %v", an)
	}
	if types := info["types"].([]any); len(types) != 2 || types[0] != "yara" || types[1] != "heuristic" {
		t.Errorf("types: %v", types)
	}
	names := map[string]bool{}
	for _, m := range f["malware"].([]any) {
		names[m.(map[string]any)["name"].(string)] = true
	}
	if !names["wannacry"] {
		t.Errorf("family should be malware: %v", f["malware"])
	}
	un := f["unmapped"].(map[string]any)
	if un["verdict"] != "malicious" || un["heuristics"].(map[string]any)["score"].(float64) != 7 {
		t.Errorf("unmapped: %v", un)
	}
	if cats := un["heuristics"].(map[string]any)["categories"].([]any); len(cats) != 2 {
		t.Errorf("only applied categories belong in unmapped: %v", cats)
	}
}

func TestOCSFStaticStegoAndFusion(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{
		staticBreach("s"), stegoBreach("t"), fusionCorroboratedResult("f"), fusionObserved("o"), staticLow("low"),
	}}
	out := ocsfRun(t, in)
	byPath := map[string]map[string]any{}
	for _, f := range out {
		byPath[f["evidences"].([]any)[0].(map[string]any)["file"].(map[string]any)["path"].(string)] = f
	}
	if len(out) != 3 || byPath["o"] != nil || byPath["low"] != nil {
		t.Fatalf("got %d findings (%v): observed and sub-threshold files are not findings", len(out), byPath)
	}
	s := byPath["s"]
	if s["severity_id"].(float64) != 3 || s["is_alert"] != false {
		t.Errorf("suspicious should be Medium: %v", s)
	}
	sinfo := s["finding_info"].(map[string]any)
	if sinfo["analytic"].(map[string]any)["uid"] != "static/score" {
		t.Errorf("static analytic: %v", sinfo["analytic"])
	}
	var ids []string
	for _, a := range sinfo["attacks"].([]any) {
		ids = append(ids, a.(map[string]any)["technique"].(map[string]any)["uid"].(string))
	}
	if strings.Join(ids, ",") != "T1027.002,T1027.007,T1027.009" {
		t.Errorf("static attacks = %v", ids)
	}
	if mw := s["malware"].([]any); len(mw) != 1 || mw[0].(map[string]any)["name"] != "Example Family" {
		t.Errorf("fuzzy match should be malware: %v", s["malware"])
	}
	classes := s["unmapped"].(map[string]any)["static"].(map[string]any)["classes"].([]any)
	if len(classes) != 4 {
		t.Errorf("scored classes only (authenticode.unverified is weight 0): %v", classes)
	}

	st := byPath["t"]["finding_info"].(map[string]any)
	if st["analytic"].(map[string]any)["uid"] != "stego/score" || len(st["attacks"].([]any)) != 1 {
		t.Errorf("stego: %v", st)
	}

	fu := byPath["f"]
	finfo := fu["finding_info"].(map[string]any)
	an := finfo["analytic"].(map[string]any)
	if an["uid"] != "fusion/corroborated" || an["type_id"].(float64) != 99 {
		t.Errorf("fusion analytic: %v", an)
	}
	if fu["confidence_id"].(float64) == 0 {
		t.Errorf("fusion confidence should map: %v", fu["confidence_id"])
	}
	ids = nil
	for _, a := range finfo["attacks"].([]any) {
		ids = append(ids, a.(map[string]any)["technique"].(map[string]any)["uid"].(string))
	}
	if strings.Join(ids, ",") != "T1027.002,T1027.009,T1055" {
		t.Errorf("fusion attacks = %v", ids)
	}
	if desc := finfo["desc"].(string); desc == "" {
		t.Error("fusion explanation should be the description")
	}
}

func TestOCSFEscapesAndBounds(t *testing.T) {
	r := hashResult("samples/<script>alert(1)</script>.exe")
	r.ThreatName = strings.Repeat("x", 5000)
	var buf bytes.Buffer
	if err := NewOCSFReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("HTML must be escaped")
	}
	if strings.Contains(buf.String(), strings.Repeat("x", 2000)) {
		t.Error("threat name must be bounded")
	}
}

func TestOCSFIsAFormat(t *testing.T) {
	if _, err := NewReporter("ocsf"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range Formats {
		if f == "ocsf" {
			found = true
		}
	}
	if !found {
		t.Error("Formats must list ocsf")
	}
}

package coverage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner"
)

func rules() []scanner.RuleInfo {
	return []scanner.RuleInfo{
		{Name: "mimikatz_strings", Namespace: "default", Meta: map[string]string{"description": "Mimikatz strings", "threat_level": "5", "mitre_attack": "T1003"}},
		{Name: "two_techs", Namespace: "pack", Meta: map[string]string{"mitre_attack": "T1486, T1490"}},
		{Name: "no_meta", Namespace: "default"},
		{Name: "hidden", Namespace: "default", Private: true, Meta: map[string]string{"mitre_attack": "T1999"}},
	}
}

func build(t *testing.T) *Matrix {
	t.Helper()
	return Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51, FuzzyCount: 0})
}

func find(m *Matrix, id string) *Technique {
	for i := range m.Techniques {
		if m.Techniques[i].ID == id {
			return &m.Techniques[i]
		}
	}
	return nil
}

func TestBuildGroupsContentByTechnique(t *testing.T) {
	m := build(t)
	cred := find(m, "T1003")
	if cred == nil {
		t.Fatal("T1003 missing")
	}
	if strings.Join(cred.Sources, ",") != "heuristic,tradecraft,yara" || cred.Tier != TierMalicious || cred.Name != "OS Credential Dumping" {
		t.Errorf("T1003 = %+v", cred)
	}
	if find(m, "T1490") == nil || find(m, "T1486") == nil {
		t.Error("comma-separated rule meta should yield one entry per technique")
	}
	if find(m, "T1999") != nil {
		t.Error("private rules must not count")
	}
	// Static classes land under static or similarity, never both.
	if st := find(m, "T1027.002"); st == nil || st.Sources[0] != SourceStatic {
		t.Errorf("T1027.002 = %+v", st)
	}
	if zw := find(m, "T1027"); zw == nil || !contains(zw.Sources, SourceStego) || !contains(zw.Sources, SourceStatic) {
		t.Errorf("T1027 = %+v", zw)
	}
	// Unmapped: Suspicious Paths, the fuzzy classes, unmapped static classes, the rule without meta.
	var labels []string
	for _, e := range m.Unmapped {
		labels = append(labels, e.Label)
	}
	for _, want := range []string{"heuristic/suspicious-paths", "static/fuzzy.tlsh", "static/entrypoint.zero", "yara/default/no_meta"} {
		if !contains(labels, want) {
			t.Errorf("unmapped lacks %s: %v", want, labels)
		}
	}
	for _, e := range m.Unmapped {
		if strings.HasSuffix(e.Label, "clr.present") {
			t.Error("informational classes must be hidden unless IncludeInfo")
		}
	}
	// Informational classes appear on request.
	mi := Build(Inputs{Rules: rules(), IncludeInfo: true})
	found := false
	for _, e := range mi.Unmapped {
		if e.Label == "static/clr.present" {
			found = true
		}
	}
	if !found {
		t.Error("IncludeInfo should list weight-0 classes")
	}
	// Sorted output.
	for i := 1; i < len(m.Techniques); i++ {
		if m.Techniques[i-1].ID >= m.Techniques[i].ID {
			t.Fatalf("techniques unsorted at %d", i)
		}
	}
}

func TestSourceSummaries(t *testing.T) {
	m := build(t)
	byName := map[string]SourceSummary{}
	for _, s := range m.Sources {
		byName[s.Name] = s
	}
	if h := byName[SourceHash]; h.Content != 51 || h.Pyramid != PyramidHash || h.Tier != TierMalicious || h.Entries != 0 {
		t.Errorf("hash = %+v", h)
	}
	if y := byName[SourceYara]; y.Content != 4 || y.Entries != 4 || y.Mapped != 3 || !strings.Contains(y.Note, "unmapped") {
		t.Errorf("yara = %+v", y)
	}
	if st := byName[SourceStego]; st.Entries != 6 || st.Mapped != 6 || st.Pyramid != PyramidTTPs {
		t.Errorf("stego = %+v", st)
	}
	if sim := byName[SourceSimilarity]; sim.Entries != 3 || sim.Mapped != 0 {
		t.Errorf("similarity = %+v", sim)
	}
	off := Build(Inputs{HashCount: -1, FuzzyCount: -1})
	for _, s := range off.Sources {
		if (s.Name == SourceHash || s.Name == SourceYara || s.Name == SourceSimilarity) && !strings.Contains(s.Note, "no ") {
			t.Errorf("%s should say nothing is loaded: %+v", s.Name, s)
		}
	}
}

func TestExpectParseCompareRecord(t *testing.T) {
	m := build(t)
	src := "# comment\nT1003 covered heuristic, yara\nT1542   gap   no decode analytic\nT1486 covered\n"
	e, err := ParseExpect(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Rows) != 3 || e.Rows[1].Note != "no decode analytic" || e.Rows[1].Line != 3 {
		t.Fatalf("rows = %+v", e.Rows)
	}
	for _, bad := range []string{"T1003\n", "T10 covered\n", "T1003 maybe\n", "T1003 covered\nT1003 gap\n"} {
		if _, err := ParseExpect(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	problems := Compare(m, e)
	kinds := map[string]int{}
	for _, p := range problems {
		kinds[p.Kind]++
	}
	// Many covered techniques are undeclared in this tiny expectation.
	if kinds["undeclared"] == 0 || kinds["regression"] != 0 || kinds["gap-closed"] != 0 {
		t.Errorf("problems = %+v", problems)
	}
	if len(m.Gaps) != 1 || m.Gaps[0].ID != "T1542" || m.Gaps[0].Name == "" {
		t.Errorf("gaps = %+v", m.Gaps)
	}

	// Record, then compare again: clean.
	rec := Record(m, e)
	e2, err := ParseExpect(bytes.NewReader(rec))
	if err != nil {
		t.Fatalf("recorded file does not parse: %v\n%s", err, rec)
	}
	m2 := build(t)
	if p := Compare(m2, e2); len(p) != 0 {
		t.Errorf("recorded expectation disagrees: %+v", p)
	}
	if !strings.Contains(string(rec), "T1542       gap       no decode analytic") {
		t.Errorf("gap row not preserved:\n%s", rec)
	}

	// A regression and a closed gap are both reported.
	e3, _ := ParseExpect(strings.NewReader("T1003 covered\nT1027 gap\nT1999 covered\n"))
	m3 := build(t)
	p := Compare(m3, e3)
	if !hasKind(p, "regression", "T1999") || !hasKind(p, "gap-closed", "T1027") {
		t.Errorf("problems = %+v", p)
	}
}

func TestRenderers(t *testing.T) {
	m := build(t)
	e, _ := ParseExpect(strings.NewReader("T1542 gap planned\n"))
	Compare(m, e)

	var text bytes.Buffer
	if err := WriteText(&text, m); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Pyramid of Pain", "T1003", "OS Credential Dumping", "no engine content", "T1542", "planned", "no ATT&CK technique", "heuristic/suspicious-paths"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, text.String())
		}
	}

	var js bytes.Buffer
	if err := WriteJSON(&js, m, true); err != nil {
		t.Fatal(err)
	}
	var back Matrix
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Techniques) != len(m.Techniques) || len(back.Gaps) != 1 {
		t.Error("JSON round trip lost rows")
	}

	var nav bytes.Buffer
	if err := WriteNavigator(&nav, m, false); err != nil {
		t.Fatal(err)
	}
	var layer map[string]interface{}
	if err := json.Unmarshal(nav.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer["domain"] != NavigatorDomain || layer["versions"].(map[string]interface{})["layer"] != NavigatorLayerVersion {
		t.Errorf("layer header = %v", layer)
	}
	techs := layer["techniques"].([]interface{})
	if len(techs) != len(m.Techniques)+1 {
		t.Errorf("layer has %d techniques, want %d + 1 gap", len(techs), len(m.Techniques))
	}
	var gapSeen, credSeen bool
	for _, raw := range techs {
		tq := raw.(map[string]interface{})
		switch tq["techniqueID"] {
		case "T1542":
			gapSeen = tq["score"].(float64) == 0 && tq["color"] == "#d9d9d9"
		case "T1003":
			credSeen = tq["score"].(float64) == 3 && strings.Contains(tq["comment"].(string), "mimikatz_strings")
		}
	}
	if !gapSeen || !credSeen {
		t.Errorf("gap=%v cred=%v", gapSeen, credSeen)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasKind(p []Problem, kind, id string) bool {
	for _, x := range p {
		if x.Kind == kind && x.ID == id {
			return true
		}
	}
	return false
}

package coverage

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func buildWithExpect(t *testing.T, expect string) *Matrix {
	t.Helper()
	m := Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51})
	e, err := ParseExpect(strings.NewReader(expect))
	if err != nil {
		t.Fatal(err)
	}
	if p := Compare(m, e); len(p) != 0 {
		t.Fatalf("expectation disagrees with matrix: %+v", p)
	}
	return m
}

// recordExpectCovering records the full matrix so every covered technique is
// declared, then overlays the caller's partial/gap/none rows.
func recordExpectCovering(t *testing.T, m *Matrix, overlay string) *Expect {
	t.Helper()
	full := Record(m, nil)
	lines := strings.Split(string(full), "\n")
	override := map[string]string{}
	for _, l := range strings.Split(overlay, "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			override[f[0]] = l
		}
	}
	var out []string
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 2 && override[f[0]] != "" {
			out = append(out, override[f[0]])
			delete(override, f[0])
			continue
		}
		out = append(out, l)
	}
	for _, l := range override {
		out = append(out, l)
	}
	e, err := ParseExpect(strings.NewReader(strings.Join(out, "\n")))
	if err != nil {
		t.Fatalf("overlay expectation: %v", err)
	}
	return e
}

func TestExpectFourStates(t *testing.T) {
	// A fresh matrix with the four states exercised.
	m := Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51})
	e := recordExpectCovering(t, m, "T1003 partial only strings\nT1542 gap planned decode\nT1046 none sensor owns it")
	m2 := Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51})
	problems := Compare(m2, e)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %+v", problems)
	}
	// T1003 is covered-but-partial.
	if tq := find(m2, "T1003"); tq == nil || !tq.Partial || tq.State() != StatePartialS {
		t.Errorf("T1003 should be partial: %+v", tq)
	}
	// T1542 (planned) and T1046 (none) are gaps with the right state.
	gapState := map[string]string{}
	for _, g := range m2.Gaps {
		gapState[g.ID] = g.State
	}
	if gapState["T1542"] != StatePlanned || gapState["T1046"] != StateNoneS {
		t.Errorf("gap states = %v", gapState)
	}

	// partial declared where nothing maps is a regression; none/gap where
	// content maps is gap-closed.
	bad, _ := ParseExpect(strings.NewReader("T1003 none\nT1999 partial"))
	p := Compare(Build(Inputs{Rules: rules()}), bad)
	kinds := map[string]string{}
	for _, x := range p {
		kinds[x.ID] = x.Kind
	}
	if kinds["T1003"] != "gap-closed" || kinds["T1999"] != "regression" {
		t.Errorf("problems = %+v", p)
	}

	if _, err := ParseExpect(strings.NewReader("T1003 sideways")); err == nil {
		t.Error("unknown state should be rejected")
	}
}

func TestRecordPreservesPartialAndNone(t *testing.T) {
	m := Build(Inputs{Rules: rules(), YaraLoaded: true})
	prev := recordExpectCovering(t, m, "T1003 partial acknowledged incomplete\nT1542 gap planned\nT1046 none sensor")
	Compare(m, prev)
	rec := Record(m, prev)
	text := string(rec)
	if !strings.Contains(text, "T1003       partial   acknowledged incomplete") {
		t.Errorf("partial row not preserved:\n%s", text)
	}
	if !strings.Contains(text, "T1542       gap       planned") || !strings.Contains(text, "T1046       none      sensor") {
		t.Errorf("gap/none rows not preserved:\n%s", text)
	}
	// Re-parsing the recorded file and comparing is clean.
	e2, err := ParseExpect(bytes.NewReader(rec))
	if err != nil {
		t.Fatal(err)
	}
	m2 := Build(Inputs{Rules: rules(), YaraLoaded: true})
	if p := Compare(m2, e2); len(p) != 0 {
		t.Errorf("recorded expectation disagrees: %+v", p)
	}
	if tq := find(m2, "T1003"); tq == nil || !tq.Partial {
		t.Error("partial state lost through a record round trip")
	}
}

func TestWriteSARIF(t *testing.T) {
	m := Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51})
	e := recordExpectCovering(t, m, "T1003 partial strings only\nT1542 gap planned decode\nT1046 none sensor owns it")
	m2 := Build(Inputs{Tool: "CAU EDR", Version: "test", Rules: rules(), YaraLoaded: true, HashCount: 51})
	Compare(m2, e)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, m2, true); err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" || !strings.Contains(log["$schema"].(string), "sarif-2.1.0") {
		t.Errorf("header: %v", log)
	}
	run := log["runs"].([]any)[0].(map[string]any)
	props := run["properties"].(map[string]any)
	if props["partial"].(float64) != 1 || props["planned"].(float64) != 1 || props["none"].(float64) != 1 {
		t.Errorf("state counts: %v", props)
	}
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	results := run["results"].([]any)
	if len(rules) != len(results) {
		t.Errorf("%d rules, %d results: one of each per technique", len(rules), len(results))
	}
	byID := map[string]map[string]any{}
	for _, raw := range results {
		r := raw.(map[string]any)
		byID[r["ruleId"].(string)] = r
	}
	// detected → note/pass; partial → note; planned → warning/open; none → note.
	cases := []struct{ id, level, kind, state string }{
		{"coverage/T1003", "note", "informational", "partial"},
		{"coverage/T1486", "note", "pass", "detected"},
		{"coverage/T1542", "warning", "open", "planned"},
		{"coverage/T1046", "note", "informational", "none"},
	}
	for _, c := range cases {
		r := byID[c.id]
		if r == nil {
			t.Errorf("%s missing from results", c.id)
			continue
		}
		if r["level"] != c.level || r["kind"] != c.kind || r["properties"].(map[string]any)["state"] != c.state {
			t.Errorf("%s = level %v kind %v state %v, want %v %v %v", c.id, r["level"], r["kind"],
				r["properties"].(map[string]any)["state"], c.level, c.kind, c.state)
		}
		loc := r["locations"].([]any)[0].(map[string]any)["logicalLocations"].([]any)[0].(map[string]any)
		if loc["fullyQualifiedName"] != "attack/"+strings.TrimPrefix(c.id, "coverage/") {
			t.Errorf("%s logical location: %v", c.id, loc)
		}
	}
	// The planned gap's message carries its note; a detected one names its content.
	if msg := byID["coverage/T1542"]["message"].(map[string]any)["text"].(string); !strings.Contains(msg, "roadmap") || !strings.Contains(msg, "decode") {
		t.Errorf("planned message: %q", msg)
	}
	if msg := byID["coverage/T1003"]["message"].(map[string]any)["text"].(string); !strings.Contains(msg, "partially covered") {
		t.Errorf("partial message: %q", msg)
	}
	// Help URIs point at attack.mitre.org, sub-techniques nested.
	for _, raw := range rules {
		rl := raw.(map[string]any)
		if !strings.HasPrefix(rl["helpUri"].(string), "https://attack.mitre.org/techniques/") {
			t.Errorf("helpUri: %v", rl["helpUri"])
		}
	}
	sub := byID["coverage/T1055.012"]
	if sub != nil {
		var found string
		for _, raw := range rules {
			rl := raw.(map[string]any)
			if rl["id"] == "coverage/T1055.012" {
				found = rl["helpUri"].(string)
			}
		}
		if !strings.Contains(found, "/T1055/012/") {
			t.Errorf("sub-technique helpUri: %q", found)
		}
	}
}

func TestSARIFIsAFormat(t *testing.T) {
	found := false
	for _, f := range Formats {
		if f == "sarif" {
			found = true
		}
	}
	if !found {
		t.Errorf("Formats missing sarif: %v", Formats)
	}
}

// failWriter fails after acceptN successful writes, to prove the renderers
// surface a write error instead of swallowing it.
type failWriter struct {
	n, acceptN int
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.n >= f.acceptN {
		return 0, errBrokenPipe
	}
	f.n++
	return len(p), nil
}

var errBrokenPipe = &writeErr{}

type writeErr struct{}

func (*writeErr) Error() string { return "broken pipe" }

func TestRenderersSurfaceWriteErrors(t *testing.T) {
	m := build(t)
	// WriteText fans out across many writes; a failure partway must surface.
	if err := WriteText(&failWriter{acceptN: 3}, m); err == nil {
		t.Error("WriteText swallowed a write error")
	}
	// A writer that accepts everything succeeds.
	if err := WriteText(&failWriter{acceptN: 1 << 20}, m); err != nil {
		t.Errorf("WriteText on a good writer: %v", err)
	}
	for _, w := range []func(io.Writer) error{
		func(w io.Writer) error { return WriteJSON(w, m, false) },
		func(w io.Writer) error { return WriteNavigator(w, m, false) },
		func(w io.Writer) error { return WriteSARIF(w, m, false) },
	} {
		if err := w(&failWriter{acceptN: 0}); err == nil {
			t.Error("a renderer swallowed a write error")
		}
	}
}

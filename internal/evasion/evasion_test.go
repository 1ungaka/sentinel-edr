package evasion

import (
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
)

// A rule that fires on one string is one byte away from silence: that is the
// number a detection author needs to see.
func TestYaraDistanceForASingleStringRule(t *testing.T) {
	src := map[string]RuleSource{
		"one_string": {Condition: "$a", Strings: map[string]StringSpec{"a": {LiteralLen: 8}}},
	}
	m := scanner.YaraMatch{RuleName: "one_string", Strings: []scanner.YaraMatchString{{Name: "$a"}}}
	d, ok := yaraDetector(m, src)
	if !ok {
		t.Fatal("no detector produced")
	}
	if !d.Derivable {
		t.Fatalf("distance not derived: %+v", d)
	}
	if d.Distance != 1 {
		t.Errorf("distance = %d, want 1", d.Distance)
	}
}

// In "a or b" both sides have to go: one byte each.
func TestYaraDistanceForADisjunction(t *testing.T) {
	src := map[string]RuleSource{
		"either": {Condition: "$a or $b", Strings: map[string]StringSpec{"a": {LiteralLen: 8}, "b": {LiteralLen: 8}}},
	}
	m := scanner.YaraMatch{RuleName: "either", Strings: []scanner.YaraMatchString{{Name: "$a"}, {Name: "$b"}}}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 2 {
		t.Errorf("distance = %d (derivable %v), want 2", d.Distance, d.Derivable)
	}
}

// In "a and b" one side is enough: the cheapest way out.
func TestYaraDistanceForAConjunction(t *testing.T) {
	src := map[string]RuleSource{
		"both": {Condition: "$a and $b", Strings: map[string]StringSpec{"a": {LiteralLen: 8}, "b": {LiteralLen: 8}}},
	}
	m := scanner.YaraMatch{RuleName: "both", Strings: []scanner.YaraMatchString{{Name: "$a"}, {Name: "$b"}}}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 1 {
		t.Errorf("distance = %d (derivable %v), want 1", d.Distance, d.Derivable)
	}
}

// "not $a" means the rule fires because the string is absent: breaking it
// means writing the string, which costs its length.
func TestYaraDistanceForANegatedString(t *testing.T) {
	src := map[string]RuleSource{
		"absent": {Condition: "not $a", Strings: map[string]StringSpec{"a": {LiteralLen: 12}}},
	}
	m := scanner.YaraMatch{RuleName: "absent"}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 12 {
		t.Errorf("distance = %d (derivable %v), want 12", d.Distance, d.Derivable)
	}
}

// A condition the analysis cannot cost is reported as not derivable, never
// guessed at.
func TestYaraDistanceIsNotGuessedForAnUnmodelledCondition(t *testing.T) {
	src := map[string]RuleSource{
		"pe": {Condition: `pe.sections[0].name == ".text"`, Strings: map[string]StringSpec{}},
	}
	m := scanner.YaraMatch{RuleName: "pe", Strings: []scanner.YaraMatchString{{Name: "$a"}}}
	d, _ := yaraDetector(m, src)
	if d.Derivable {
		t.Errorf("an unmodelled condition produced a distance: %+v", d)
	}
	if d.Edit == "" {
		t.Error("a not-derivable detector said nothing about why")
	}
}

// Without the rule source there is no condition to cost.
func TestYaraDistanceWithoutTheRuleSource(t *testing.T) {
	m := scanner.YaraMatch{RuleName: "unknown_rule", Strings: []scanner.YaraMatchString{{Name: "$a"}}}
	d, _ := yaraDetector(m, nil)
	if d.Derivable {
		t.Errorf("a rule with no source produced a distance: %+v", d)
	}
}

// The hash detection is one byte from silence, exactly.
func TestHashDistanceIsOneByte(t *testing.T) {
	res := &scanner.ScanResult{
		FilePath:   "/tmp/x",
		Size:       100,
		Detected:   true,
		MatchType:  "SHA256",
		MatchHash:  "00112233445566778899aabbccddeeff",
		ThreatName: "test.threat",
		Verdict:    scanner.VerdictMalicious,
	}
	r := Analyze(res, Options{})
	if len(r.Detectors) != 1 {
		t.Fatalf("detectors = %+v", r.Detectors)
	}
	d := r.Detectors[0]
	if d.Name != "hash" || !d.Derivable || d.Distance != 1 {
		t.Errorf("hash detector = %+v", d)
	}
	if r.Lower != 1 || r.Upper != 1 {
		t.Errorf("bounds = %d..%d, want 1..1", r.Lower, r.Upper)
	}
}

// Two detectors that both fire: one edit could break both (the lower bound),
// and breaking them one at a time always works (the upper bound).
func TestBoundsSpanOneEditToMany(t *testing.T) {
	res := &scanner.ScanResult{
		Detected:  true,
		MatchType: "SHA256",
		MatchHash: "abc",
		YaraMatches: []scanner.YaraMatch{{
			RuleName: "r",
			Strings:  []scanner.YaraMatchString{{Name: "$a"}},
		}},
	}
	sources := map[string]RuleSource{"r": {Condition: "$a", Strings: map[string]StringSpec{"a": {LiteralLen: 4}}}}
	r := Analyze(res, Options{Sources: sources})
	if r.Lower != 1 {
		t.Errorf("lower bound = %d, want 1", r.Lower)
	}
	if r.Upper != 2 {
		t.Errorf("upper bound = %d, want 2", r.Upper)
	}
}

// The report says which change is needed without carrying a patch: no offset,
// no byte value.
func TestReportDescribesTheChangeWithoutAPatch(t *testing.T) {
	res := &scanner.ScanResult{
		Detected:  true,
		MatchType: "SHA256",
		MatchHash: "00112233445566778899aabbccddeeff",
		YaraMatches: []scanner.YaraMatch{{
			RuleName: "r",
			Strings:  []scanner.YaraMatchString{{Name: "$a", Offset: 4096, Data: []byte("secret")}},
		}},
	}
	sources := map[string]RuleSource{"r": {Condition: "$a", Strings: map[string]StringSpec{"a": {LiteralLen: 6}}}}
	r := Analyze(res, Options{Sources: sources})
	text := r.String()
	for _, leak := range []string{"4096", "secret"} {
		if strings.Contains(text, leak) {
			t.Errorf("the report leaks %q:\n%s", leak, text)
		}
	}
}

package evasion

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner"
)

// "3 of them" with four matches: the rule falls when three stop matching, so
// two have to break.
func TestYaraDistanceForAnOfThemCondition(t *testing.T) {
	src := map[string]RuleSource{
		"three": {Condition: "3 of them", Strings: map[string]StringSpec{
			"a": {LiteralLen: 4}, "b": {LiteralLen: 4}, "c": {LiteralLen: 4}, "d": {LiteralLen: 4},
		}},
	}
	m := scanner.YaraMatch{RuleName: "three", Strings: []scanner.YaraMatchString{
		{Name: "$a"}, {Name: "$b"}, {Name: "$c"}, {Name: "$d"},
	}}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 2 {
		t.Errorf("distance = %d (derivable %v), want 2", d.Distance, d.Derivable)
	}
}

// "all of them" with a string that did not match: the term is already false,
// so the rule does not need it broken.
func TestYaraDistanceForAllOfThemWithAnUnmatchedString(t *testing.T) {
	src := map[string]RuleSource{
		"all": {Condition: "all of them", Strings: map[string]StringSpec{
			"a": {LiteralLen: 4}, "b": {LiteralLen: 4},
		}},
	}
	m := scanner.YaraMatch{RuleName: "all", Strings: []scanner.YaraMatchString{{Name: "$a"}}}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 0 {
		t.Errorf("distance = %d (derivable %v), want 0", d.Distance, d.Derivable)
	}
}

// "2 of ($ext*)" is a string set with a wildcard: only the identifiers in the
// set count.
func TestYaraDistanceForAStringSet(t *testing.T) {
	src := map[string]RuleSource{
		"exts": {Condition: "2 of ($ext*)", Strings: map[string]StringSpec{
			"ext1": {LiteralLen: 4}, "ext2": {LiteralLen: 4}, "other": {LiteralLen: 4},
		}},
	}
	m := scanner.YaraMatch{RuleName: "exts", Strings: []scanner.YaraMatchString{
		{Name: "$ext1"}, {Name: "$ext2"}, {Name: "$other"},
	}}
	d, _ := yaraDetector(m, src)
	if !d.Derivable || d.Distance != 1 {
		t.Errorf("distance = %d (derivable %v), want 1", d.Distance, d.Derivable)
	}
}

// The rule source reader finds the condition and the shape of the strings.
func TestReadRuleSources(t *testing.T) {
	dir := t.TempDir()
	src := `rule sample_rule
{
    meta:
        description = "a rule"
    strings:
        $a = "literal text" ascii wide
        $b = { 4D 5A 90 00 }
        $c = /regex[0-9]+/
    condition:
        2 of them and $a
}
`
	if err := os.WriteFile(filepath.Join(dir, "r.yar"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := ReadRuleSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	rs, ok := sources["sample_rule"]
	if !ok {
		t.Fatalf("the rule was not found: %+v", sources)
	}
	if rs.Condition != "2 of them and $a" {
		t.Errorf("condition = %q", rs.Condition)
	}
	if got := rs.Strings["a"].LiteralLen; got != len("literal text") {
		t.Errorf("literal length = %d, want %d", got, len("literal text"))
	}
	if got := rs.Strings["b"].LiteralLen; got != 4 {
		t.Errorf("hex string length = %d, want 4", got)
	}
	if !rs.Strings["c"].Regex {
		t.Error("the regular expression was not recognised")
	}
}

// A rule whose condition is on several lines is read whole.
func TestReadRuleSourcesWithAMultiLineCondition(t *testing.T) {
	dir := t.TempDir()
	src := "rule multi\n{\n    strings:\n        $a = \"x\"\n    condition:\n        $a and\n        $b\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yar"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := ReadRuleSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := sources["multi"].Condition; got != "$a and $b" {
		t.Errorf("condition = %q, want %q", got, "$a and $b")
	}
}

// Two rules in one file are both read, and a comment with a '#' inside a
// string literal is not a comment.
func TestReadRuleSourcesReadsEveryRule(t *testing.T) {
	dir := t.TempDir()
	src := "rule one\n{\n    strings:\n        $a = \"has # inside\"\n    condition:\n        $a\n}\n" +
		"rule two\n{\n    strings:\n        $b = \"x\"\n    condition:\n        $b # a trailing comment\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yar"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := ReadRuleSources(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("read %d rules, want 2", len(sources))
	}
	if got := sources["one"].Strings["a"].LiteralLen; got != len("has # inside") {
		t.Errorf("the '#' inside the literal was taken for a comment: length %d", got)
	}
	if got := sources["two"].Condition; got != "$b" {
		t.Errorf("condition = %q, want %q", got, "$b")
	}
}

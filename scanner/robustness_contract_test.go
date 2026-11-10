package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The per-rule robustness contract.
//
// The detection-robustness harness measures how much benign perturbation each
// *sampled family* survives. This is the same measurement for every rule the
// repository ships, so the contract is enforced per rule and a new rule is
// covered the moment it lands: a rule that declares `nocase` must still fire
// when the sample is upper-cased, and a rule that declares `wide` must still
// fire when the sample is UTF-16LE.
//
// The samples are synthetic and built from the rule's own literals: no real
// malware is involved, and nothing here is a bypass — the transformations are
// the benign ones the harness already uses.

var (
	// reRuleHead finds a rule declaration.
	reRuleHead = regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)`)
	// reRuleString finds a text string definition and its modifiers.
	reRuleString = regexp.MustCompile(`(?m)^\s*(\$[A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"([^\n]*)$`)
)

// ruleFixture is one bundled rule, as far as the contract needs it.
type ruleFixture struct {
	name string
	// literals are the rule's text strings, unescaped.
	literals []string
	// nocase and wide say whether the rule declares the modifier.
	nocase bool
	wide   bool
	// condition is the rule's condition text, for the report.
	condition string
}

// bundledRules reads the rules the repository ships.
func bundledRules(t *testing.T) []ruleFixture {
	t.Helper()
	var out []ruleFixture
	err := filepath.WalkDir(repoRules, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext != ".yar" && ext != ".yara" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		out = append(out, parseRuleFixtures(string(data))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", repoRules, err)
	}
	if len(out) == 0 {
		t.Fatalf("no rules found under %s", repoRules)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// parseRuleFixtures reads the rules out of one file's text.
func parseRuleFixtures(text string) []ruleFixture {
	var out []ruleFixture
	lines := strings.Split(text, "\n")
	var cur *ruleFixture
	section := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if m := reRuleHead.FindStringSubmatch(line); m != nil {
			out = append(out, ruleFixture{name: m[1]})
			cur = &out[len(out)-1]
			section = ""
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(line, "strings:"):
			section = "strings"
			continue
		case strings.HasPrefix(line, "condition:"):
			section = "condition"
			rest := strings.TrimSpace(strings.TrimPrefix(line, "condition:"))
			if rest != "" {
				cur.condition = rest
			}
			continue
		case line == "}":
			cur = nil
			section = ""
			continue
		}
		if section == "condition" && cur.condition == "" {
			// The condition usually sits on the line after "condition:".
			cur.condition = line
			continue
		}
		if section == "strings" {
			m := reRuleString.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			cur.literals = append(cur.literals, unescapeYaraLiteral(m[2]))
			mods := strings.Fields(m[3])
			for _, mod := range mods {
				switch mod {
				case "nocase":
					cur.nocase = true
				case "wide":
					cur.wide = true
				}
			}
		}
	}
	return out
}

// unescapeYaraLiteral resolves the escapes a YARA text string may carry.
func unescapeYaraLiteral(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// sample builds the synthetic content that trips a rule: its own literals.
func (r ruleFixture) sample() []byte {
	var b bytes.Buffer
	for _, lit := range r.literals {
		b.WriteString(lit)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// TestEveryBundledRuleSurvivesBenignPerturbation is the per-rule contract.
//
// A rule that declares `nocase` must still fire when the sample is
// upper-cased or lower-cased, and a rule that declares `wide` must still fire
// when the sample is UTF-16LE. A rule that declares neither is expected to
// lose those, and the report says which — that is the measurement, not a
// failure.
//
// The harness covers every rule the repository ships, so a rule added later is
// covered the moment it lands.
func TestEveryBundledRuleSurvivesBenignPerturbation(t *testing.T) {
	ys := loadRepoYara(t)
	rules := bundledRules(t)

	// The transformations that must not break a rule which declares the
	// matching modifier, plus the ones that break every rule (junk is
	// harmless to a string match).
	type check struct {
		transform string
		// needs says the rule must declare this modifier to survive it.
		needs string
		apply func([]byte) []byte
	}
	junk := bytes.Repeat([]byte("the quick brown fox. "), 200)
	checks := []check{
		{"upper", "nocase", bytes.ToUpper},
		{"lower", "nocase", bytes.ToLower},
		{"wide-utf16", "wide", toUTF16LE},
		{"prefix-junk", "", func(b []byte) []byte { return append(append([]byte{}, junk...), b...) }},
		{"suffix-junk", "", func(b []byte) []byte { return append(append([]byte{}, b...), junk...) }},
	}

	for _, rule := range rules {
		if len(rule.literals) == 0 {
			// A rule with no text string (an exotic one) cannot be sampled
			// this way; it is named rather than silently passed over.
			t.Logf("  %-28s no text string: not sampled", rule.name)
			continue
		}
		sample := rule.sample()

		if structural(rule.condition) {
			// The rule keys on the file's structure (a PE header, a size), so
			// a text sample built from its literals cannot trip it. It is
			// named rather than passed over in silence.
			t.Logf("  %-28s keys on the file's structure: not sampled", rule.name)
			continue
		}
		matches, err := ys.ScanMemYaraStrict(sample)
		if err != nil {
			t.Errorf("%s: the synthetic sample did not scan: %v", rule.name, err)
			continue
		}
		if !hasRule(matches, rule.name) {
			t.Errorf("%s: the synthetic sample built from the rule's own literals does not trip it; the rule cannot be sampled", rule.name)
			continue
		}

		for _, c := range checks {
			transformed := c.apply(sample)
			m, err := ys.ScanMemYaraStrict(transformed)
			if err != nil {
				t.Errorf("%s under %s: the sample did not scan: %v", rule.name, c.transform, err)
				continue
			}
			fired := hasRule(m, rule.name)
			switch {
			case fired:
				continue
			case c.needs == "":
				t.Errorf("BRITTLE: %s stops firing under the benign %s perturbation, which every rule must survive", rule.name, c.transform)
			case c.needs == "nocase" && rule.nocase:
				t.Errorf("BRITTLE: %s declares nocase and stops firing under the %s perturbation", rule.name, c.transform)
			case c.needs == "wide" && rule.wide:
				t.Errorf("BRITTLE: %s declares wide and stops firing under the %s perturbation", rule.name, c.transform)
			default:
				// Expected: the rule does not declare the modifier, so the
				// perturbation does break it. That is the measurement.
				t.Logf("  %-28s loses the %s perturbation (no %s modifier)", rule.name, c.transform, c.needs)
			}
		}
	}
	t.Logf("robustness contract checked on %d bundled rule(s)", len(rules))
}

// structural reports whether a condition reads the file's structure rather
// than its content: a header field, a size, a parsed image.
func structural(condition string) bool {
	for _, term := range []string{"uint8(", "uint16(", "uint32(", "filesize", "pe.", "elf.", "math."} {
		if strings.Contains(condition, term) {
			return true
		}
	}
	return false
}

// hasRule reports whether the rule is among the matches.
func hasRule(matches []YaraMatch, name string) bool {
	for _, m := range matches {
		if m.RuleName == name {
			return true
		}
	}
	return false
}

// The fixtures the contract is built on must be honest: a rule with no
// literals is reported, not passed over in silence.
func TestTheBundledRulesAreAllSampled(t *testing.T) {
	rules := bundledRules(t)
	var unsampled []string
	for _, r := range rules {
		if len(r.literals) == 0 {
			unsampled = append(unsampled, r.name)
		}
	}
	if len(unsampled) > 0 {
		t.Logf("rules with no text string (not sampled by the contract): %s", strings.Join(unsampled, ", "))
	}
	for _, r := range rules {
		if r.name == "" {
			t.Fatal("a rule was read without a name")
		}
		if r.condition == "" {
			t.Errorf("%s: the rule was read without a condition", r.name)
		}
	}
	_ = fmt.Sprint
}

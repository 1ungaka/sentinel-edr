package evasion

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// maxRuleFileBytes bounds a rule file. A rule file is content, not a
// sample, but it is still a file on disk: the bounded reader is the one that
// refuses a FIFO and a device instead of hanging on them.
const maxRuleFileBytes = 8 << 20

// The rule sources are read back so the analysis can cost a rule: which of its
// strings have to break for the condition to go false, and how long a string
// is when the condition needs it to appear instead of disappear.

var (
	reRuleDecl  = regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)`)
	reStringDef = regexp.MustCompile(`^\s*(\$[A-Za-z0-9_]*)\s*=\s*(.*)$`)
	reTextLit   = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"`)
	reHexLit    = regexp.MustCompile(`^\{([^}]*)\}`)
	reRegexLit  = regexp.MustCompile(`^/`)
)

// ReadRuleSources reads the YARA rule files under dir and returns what the
// analysis needs to know about each rule: its condition and the shape of the
// strings it matches on.
//
// The files are read, never executed: a rule file is content, and the analysis
// only looks at the condition's shape.
func ReadRuleSources(dir string) (map[string]RuleSource, error) {
	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]RuleSource{}
	for _, f := range files {
		data, err := safefs.ReadFile(f, maxRuleFileBytes)
		if err != nil {
			return nil, fmt.Errorf("evasion: read rule file %s: %w", f, err)
		}
		for name, src := range parseRuleSources(string(data)) {
			out[name] = src
		}
	}
	return out, nil
}

// ruleFiles lists the rule files under dir, sorted, so two runs read the same
// rules in the same order.
func ruleFiles(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("evasion: rules path: %w", err)
	}
	if !info.IsDir() {
		return []string{dir}, nil
	}
	// safefs.WalkRoot resolves a symlinked root: the rules directory is
	// often a symlink (/usr/share/cau/rules -> /etc/cau/rules), and a walk
	// that refuses to follow it would find no rules at all.
	var out []string
	err = filepath.WalkDir(safefs.WalkRoot(dir), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yar", ".yara":
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("evasion: walk rules: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// parseRuleSources extracts every rule in one file's text.
func parseRuleSources(text string) map[string]RuleSource {
	out := map[string]RuleSource{}
	lines := strings.Split(text, "\n")

	name := ""
	section := ""
	depth := 0
	var cond []string
	var strings_ map[string]StringSpec

	flush := func() {
		if name != "" {
			out[name] = RuleSource{
				Condition: strings.TrimSpace(strings.Join(cond, " ")),
				Strings:   strings_,
			}
		}
		name, section, depth, cond, strings_ = "", "", 0, nil, nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(stripYaraComment(raw))
		if line == "" {
			continue
		}
		if m := reRuleDecl.FindStringSubmatch(line); m != nil {
			flush()
			name = m[1]
			section = ""
			depth = 1
			cond = nil
			strings_ = map[string]StringSpec{}
			continue
		}
		if name == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "strings:"):
			section = "strings"
			continue
		case strings.HasPrefix(line, "condition:"):
			section = "condition"
			if rest := strings.TrimSpace(strings.TrimPrefix(line, "condition:")); rest != "" {
				cond = append(cond, rest)
			}
			continue
		}
		switch section {
		case "strings":
			if spec, id, ok := parseStringDef(line); ok {
				strings_[id] = spec
			}
		case "condition":
			cond = append(cond, strings.TrimSuffix(line, "}"))
		}
		// A rule ends when its braces balance. A hex string may span lines
		// and close one of them, so the depth is what ends the rule, not a
		// lone brace.
		depth += braceDelta(line)
		if depth <= 0 {
			flush()
		}
	}
	flush()
	return out
}

// braceDelta counts the braces a line opens and closes, ignoring the ones
// inside a string literal.
func braceDelta(line string) int {
	delta := 0
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// nothing
		case c == '{':
			delta++
		case c == '}':
			delta--
		}
	}
	return delta
}

// parseStringDef reads one string definition.
func parseStringDef(line string) (StringSpec, string, bool) {
	m := reStringDef.FindStringSubmatch(line)
	if m == nil {
		return StringSpec{}, "", false
	}
	id := strings.TrimPrefix(m[1], "$")
	rest := strings.TrimSpace(m[2])
	switch {
	case strings.HasPrefix(rest, `"`):
		tm := reTextLit.FindStringSubmatch(rest)
		if tm == nil {
			return StringSpec{}, "", false
		}
		return StringSpec{LiteralLen: len(unescapeYara(tm[1]))}, id, true
	case strings.HasPrefix(rest, "{"):
		hm := reHexLit.FindStringSubmatch(rest)
		if hm == nil {
			return StringSpec{}, "", false
		}
		// A hex string has a fixed length: the bytes it matches are known, so
		// writing it to satisfy a "not" condition costs its length.
		n := 0
		for _, f := range strings.Fields(hm[1]) {
			if len(f) == 2 {
				n++
			}
		}
		return StringSpec{LiteralLen: n}, id, true
	case reRegexLit.MatchString(rest):
		return StringSpec{Regex: true}, id, true
	}
	return StringSpec{}, "", false
}

// stripYaraComment removes a trailing comment from a rule line. A '#' inside a
// string literal is not a comment, so the literal is skipped over.
func stripYaraComment(line string) string {
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case c == '#' && !inString:
			return line[:i]
		}
	}
	return line
}

// unescapeYara resolves the escapes a YARA text string may carry, so its
// length is the length of the bytes it matches.
func unescapeYara(s string) string {
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
		case 'x':
			// \xNN: two hex digits.
			if i+2 < len(s) {
				if v, err := hexVal(s[i+1], s[i+2]); err == nil {
					b.WriteByte(v)
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hexVal reads two hex digits.
func hexVal(a, b byte) (byte, error) {
	var v byte
	for _, c := range []byte{a, b} {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= c - '0'
		case c >= 'a' && c <= 'f':
			v |= c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v |= c - 'A' + 10
		default:
			return 0, fmt.Errorf("not a hex digit")
		}
	}
	return v, nil
}

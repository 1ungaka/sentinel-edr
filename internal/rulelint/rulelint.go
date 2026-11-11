// Package rulelint checks YARA rule files against the conventions the
// engine's reports and coverage matrix rely on, and against the general
// hygiene a detection rule needs before it ships (the "Zen of Security
// Rules" distilled to what a file scanner can check):
//
//   - it compiles, and the compiler had nothing to warn about;
//   - it says what it detects (description), who wrote it (author), how bad
//     a hit is (threat_level 1-5), which family (family) and which ATT&CK
//     technique (mitre_attack) it is evidence for;
//   - its strings can actually match bytes: hex written as the text
//     "0x89,0x00" never fires, strings under four bytes fire everywhere, and
//     narrow-only text misses UTF-16 carriers (Windows binaries);
//   - its condition is not trivially true.
//
// Two profiles: "cau" enforces the bundled-content conventions (family,
// threat_level and `wide` are required); "generic" lints third-party rule
// sets for the checks every ruleset should pass (compile, description,
// technique id shape, dead strings, trivial conditions).
package rulelint

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/1ungaka/sentinel-edr/internal/attack"
	"github.com/1ungaka/sentinel-edr/scanner"
)

// Severities.
const (
	Error   = "error"
	Warning = "warning"
	Info    = "info"
)

// Profiles.
const (
	ProfileCAU     = "cau"
	ProfileGeneric = "generic"
)

// Finding is one lint result.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Message  string `json:"message"`
}

func (f Finding) String() string {
	var b strings.Builder
	b.WriteString(f.File)
	if f.Line > 0 {
		fmt.Fprintf(&b, ":%d", f.Line)
	}
	fmt.Fprintf(&b, ": %s [%s]", f.Severity, f.Code)
	if f.Rule != "" {
		fmt.Fprintf(&b, " rule %s", f.Rule)
	}
	b.WriteString(": ")
	b.WriteString(f.Message)
	return b.String()
}

// Options configure a lint run.
type Options struct {
	// Profile is "cau" (default) or "generic".
	Profile string
}

// Report is the result of linting one rules path.
type Report struct {
	Path     string    `json:"path"`
	Profile  string    `json:"profile"`
	Files    int       `json:"files"`
	Rules    int       `json:"rules"`
	Findings []Finding `json:"findings"`
	Errors   int       `json:"errors"`
	Warnings int       `json:"warnings"`
	Infos    int       `json:"infos"`
}

// Failed reports whether the run found errors (or, when strict, warnings).
func (r *Report) Failed(strict bool) bool {
	return r.Errors > 0 || (strict && r.Warnings > 0)
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case Error:
		r.Errors++
	case Warning:
		r.Warnings++
	default:
		r.Infos++
	}
}

var (
	techniqueKeys = []string{"mitre_attack", "attack", "technique"}
	reRuleStart   = regexp.MustCompile(`(?m)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)`)
	reStringDef   = regexp.MustCompile(`^\s*\$([A-Za-z0-9_]*)\s*=\s*(.*)$`)
	reTextLit     = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"(.*)$`)
	reRegexLit    = regexp.MustCompile(`^/((?:[^/\\]|\\.)*)/(.*)$`)
	reHexLit      = regexp.MustCompile(`^\{([^}]*)\}(.*)$`)
	reHexAsText   = regexp.MustCompile(`^\s*(?:\\?0x[0-9A-Fa-f]{2}\s*,?\s*){2,}$`)
	reHexByte     = regexp.MustCompile(`[0-9A-Fa-f?]{2}`)
	reSnakeCase   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	reTrivialCond = regexp.MustCompile(`^(true|1|filesize\s*[<>]=?\s*\d+[KM]?B?)$`)
)

// Lint checks every rule file at path (a file or a directory).
func Lint(path string, opts Options) (*Report, error) {
	profile := opts.Profile
	if profile == "" {
		profile = ProfileCAU
	}
	if profile != ProfileCAU && profile != ProfileGeneric {
		return nil, fmt.Errorf("unknown lint profile %q (want %s or %s)", profile, ProfileCAU, ProfileGeneric)
	}
	files, err := scanner.RuleFiles(path)
	if err != nil {
		return nil, err
	}
	rep := &Report{Path: path, Profile: profile, Files: len(files)}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .yar/.yara files at %s", path)
	}

	// Compile. Dropped sources are errors; the compiler's own warnings are
	// warnings. A ruleset where nothing compiles is still a report, not a
	// failure of the linter.
	ys, _, err := scanner.LoadYaraRules(path, scanner.WithWarnFunc(func(string, ...interface{}) {}))
	kept := map[string]bool{}
	if err == nil {
		defer ys.Close()
		for _, s := range ys.Sources() {
			kept[s.Path] = true
		}
		for _, w := range ys.Warnings() {
			sev := Warning
			if !kept[w.Source] {
				sev = Error
			}
			msg := "failed to compile"
			if w.Err != nil {
				msg = w.Err.Error()
			}
			rep.add(Finding{Code: "compile", Severity: sev, File: w.Source, Line: w.Line, Rule: w.Rule, Message: msg})
		}
		rep.Rules = ys.RuleCount()
		for _, r := range ys.RuleInfos() {
			lintMeta(rep, r, profile, ruleFile(files, kept, r))
		}
	} else {
		rep.add(Finding{Code: "compile", Severity: Error, File: path, Message: err.Error()})
	}

	// Source-level checks that the compiled form cannot answer.
	for _, f := range files {
		src, rerr := os.ReadFile(f)
		if rerr != nil {
			rep.add(Finding{Code: "read", Severity: Error, File: f, Message: rerr.Error()})
			continue
		}
		lintSource(rep, f, string(src), profile)
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Code < b.Code
	})
	return rep, nil
}

// ruleFile returns the file a compiled rule most likely came from: with one
// kept file that is it; otherwise the compiled form does not say, and the
// path is used.
func ruleFile(files []string, kept map[string]bool, r scanner.RuleInfo) string {
	var only string
	n := 0
	for _, f := range files {
		if kept[f] {
			only = f
			n++
		}
	}
	if n == 1 {
		return only
	}
	return ""
}

func lintMeta(rep *Report, r scanner.RuleInfo, profile, file string) {
	if r.Private {
		return
	}
	add := func(code, sev, msg string) {
		rep.add(Finding{Code: code, Severity: sev, File: file, Rule: r.Name, Message: msg})
	}
	if strings.TrimSpace(r.Meta["description"]) == "" {
		add("meta-description", Error, "no description: a hit nobody can read is a hit nobody can triage")
	}
	if strings.TrimSpace(r.Meta["author"]) == "" {
		add("meta-author", Warning, "no author")
	}
	if tl, ok := r.Meta["threat_level"]; ok {
		if n, err := strconv.Atoi(tl); err != nil || n < 1 || n > 5 {
			add("meta-threat-level", Error, fmt.Sprintf("threat_level %q is not an integer 1-5", tl))
		}
	} else if profile == ProfileCAU {
		add("meta-threat-level", Error, "no threat_level (1-5): reports and SARIF rank hits by it")
	}
	if profile == ProfileCAU && strings.TrimSpace(r.Meta["family"]) == "" {
		add("meta-family", Warning, "no family: per-family recall in the evaluation harness needs it")
	}
	techs := r.MetaTechnique()
	if len(techs) == 0 {
		add("meta-technique", Warning, "no mitre_attack meta: the rule is listed as unmapped in the coverage matrix")
	}
	for _, t := range techs {
		if !attack.ValidID(t) {
			add("meta-technique", Error, fmt.Sprintf("%q is not an ATT&CK technique id (T1234 or T1234.001)", t))
		}
	}
	if profile == ProfileCAU && !reSnakeCase.MatchString(r.Name) {
		add("name-style", Warning, "rule names are lower_snake_case in the bundled content")
	}
	if r.Strings == 0 {
		add("no-strings", Info, "condition-only rule (no strings): make sure the condition is specific")
	}
}

// lintSource parses the rule text just far enough to see each string
// definition with its modifiers and the condition.
func lintSource(rep *Report, file, src, profile string) {
	starts := reRuleStart.FindAllStringSubmatchIndex(src, -1)
	for i, loc := range starts {
		end := len(src)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		name := src[loc[2]:loc[3]]
		body := src[loc[0]:end]
		baseLine := 1 + strings.Count(src[:loc[0]], "\n")
		lintRuleBody(rep, file, name, body, baseLine, profile)
	}
}

func lintRuleBody(rep *Report, file, name, body string, baseLine int, profile string) {
	add := func(line int, code, sev, msg string) {
		rep.add(Finding{Code: code, Severity: sev, File: file, Line: line, Rule: name, Message: msg})
	}
	section := ""
	var cond []string
	condLine := 0
	for n, raw := range strings.Split(body, "\n") {
		line := baseLine + n
		text := strings.TrimSpace(stripComment(raw))
		switch {
		case text == "":
			continue
		case strings.HasPrefix(text, "meta:"):
			section = "meta"
			continue
		case strings.HasPrefix(text, "strings:"):
			section = "strings"
			continue
		case strings.HasPrefix(text, "condition:"):
			section = "condition"
			condLine = line
			if rest := strings.TrimSpace(strings.TrimPrefix(text, "condition:")); rest != "" {
				cond = append(cond, rest)
			}
			continue
		}
		switch section {
		case "strings":
			m := reStringDef.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			id := "$" + m[1]
			lit := strings.TrimSpace(m[2])
			switch {
			case strings.HasPrefix(lit, `"`):
				tm := reTextLit.FindStringSubmatch(lit)
				if tm == nil {
					continue
				}
				content, mods := tm[1], strings.Fields(strings.TrimSpace(tm[2]))
				if reHexAsText.MatchString(content) {
					add(line, "string-hex-as-text", Error, fmt.Sprintf("%s is the text %q, not bytes: write a hex string { .. } or the rule can never fire", id, content))
				}
				if unescapedLen(content) < 4 && !hasMod(mods, "fullword") {
					add(line, "string-short", Warning, fmt.Sprintf("%s is under four bytes: it matches almost everything and slows every scan", id))
				}
				if profile == ProfileCAU && !hasMod(mods, "wide") {
					add(line, "string-narrow", Warning, fmt.Sprintf("%s has no `wide` modifier: UTF-16LE carriers (Windows binaries) will not match", id))
				}
			case strings.HasPrefix(lit, "{"):
				hm := reHexLit.FindStringSubmatch(lit)
				if hm == nil {
					continue
				}
				bytesN := len(reHexByte.FindAllString(hm[1], -1))
				if bytesN > 0 && bytesN < 4 && !strings.Contains(hm[1], "[") {
					add(line, "string-short", Warning, fmt.Sprintf("%s is %d byte(s) of hex: it matches almost everything", id, bytesN))
				}
			case strings.HasPrefix(lit, "/"):
				rm := reRegexLit.FindStringSubmatch(lit)
				if rm != nil && len(rm[1]) < 4 {
					add(line, "string-short", Warning, fmt.Sprintf("%s is a very short regular expression", id))
				}
			}
		case "condition":
			if text == "}" {
				continue
			}
			cond = append(cond, strings.TrimSuffix(text, "}"))
		}
	}
	joined := strings.TrimSpace(strings.Join(cond, " "))
	if joined != "" && reTrivialCond.MatchString(joined) {
		add(condLine, "condition-trivial", Error, fmt.Sprintf("condition %q matches every file (or every file of a size)", joined))
	}
}

func stripComment(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inStr {
				i++
			}
		case '"':
			inStr = !inStr
		case '/':
			if !inStr && i+1 < len(line) && line[i+1] == '/' {
				return line[:i]
			}
		}
	}
	return line
}

func hasMod(mods []string, want string) bool {
	for _, m := range mods {
		if m == want {
			return true
		}
	}
	return false
}

// unescapedLen counts the bytes a YARA text literal matches: every escape
// sequence (\n, \t, \", \\, \xNN) is one byte.
func unescapedLen(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == 'x' && i+3 < len(s) {
				i += 3
			} else {
				i++
			}
		}
		n++
	}
	return n
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer) error {
	for _, f := range r.Findings {
		fmt.Fprintln(w, f.String())
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "files\t%d\nrules\t%d\nprofile\t%s\nerrors\t%d\nwarnings\t%d\ninfo\t%d\n", r.Files, r.Rules, r.Profile, r.Errors, r.Warnings, r.Infos)
	return tw.Flush()
}

// WriteJSON renders the report as JSON.
func (r *Report) WriteJSON(w io.Writer, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(r)
}

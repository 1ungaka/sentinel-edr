package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	yara "github.com/hillu/go-yara/v4"

	"github.com/s-b-repo/cau/internal/safefs"
)

// RuleSource is a single unit of YARA source that can be compiled into a
// ruleset. Most callers use Path; Text exists so that rules can be embedded
// (tests, plugins, rules fetched from a feed, ...).
type RuleSource struct {
	// Path points at a .yar/.yara file. Ignored when Text is set.
	Path string
	// Text holds inline YARA source. When set, Path is only used to label
	// diagnostics (see Name).
	Text string
	// Namespace forces every rule of this source into the given namespace.
	// An empty string keeps the namespace declared by the rules themselves,
	// which is what CAU EDR does by default: the reported namespace is then
	// the real one ("default" when the rule declares none).
	Namespace string
	// Name is the human readable label used in warnings. Defaults to Path.
	Name string
}

// label returns the name used to refer to the source in diagnostics.
func (s RuleSource) label() string {
	if s.Name != "" {
		return s.Name
	}
	if s.Path != "" {
		return s.Path
	}
	return "<inline rules>"
}

// RuleCompileWarning records a rule source that could not be compiled. A
// broken rule file never aborts loading: it is downgraded to a warning and the
// remaining rules are still compiled, because losing one bad file must never
// turn a malicious sample into a clean verdict.
type RuleCompileWarning struct {
	// Source is the label of the offending rule source (usually a path).
	Source string
	// Namespace is the namespace the source was compiled into, if forced.
	Namespace string
	// Line is the 1-based line number reported by the YARA compiler, or 0.
	Line int
	// Column is the 1-based column, derived from the offending line when the
	// compiler message names a token. 0 means "unknown".
	Column int
	// Rule is the rule identifier the compiler blamed, if any.
	Rule string
	// Err is the underlying YARA compiler error.
	Err error
}

// Error renders the warning as "file:line:col: message (rule ns.name)".
func (w RuleCompileWarning) Error() string {
	var b strings.Builder
	b.WriteString(w.Source)
	if w.Line > 0 {
		fmt.Fprintf(&b, ":%d", w.Line)
		if w.Column > 0 {
			fmt.Fprintf(&b, ":%d", w.Column)
		}
	}
	b.WriteString(": ")
	if w.Err != nil {
		b.WriteString(w.Err.Error())
	} else {
		b.WriteString("failed to compile")
	}
	if w.Rule != "" {
		fmt.Fprintf(&b, " (rule %s)", w.Rule)
	}
	return b.String()
}

// Unwrap exposes the underlying YARA error for errors.Is/errors.As.
func (w RuleCompileWarning) Unwrap() error { return w.Err }

// compileRuleSources compiles every source into ONE *yara.Rules, isolating
// failures: a source that does not compile (by itself, or because it collides
// with a rule that was already added) is dropped with a warning and the rest of
// the ruleset is still produced.
//
// It returns the ruleset, the sources that made it into it (in compile order),
// every diagnostic collected, and an error if nothing usable is left.
func compileRuleSources(sources []RuleSource, onWarn func(RuleCompileWarning)) (*yara.Rules, []RuleSource, []RuleCompileWarning, error) {
	if len(sources) == 0 {
		return nil, nil, nil, fmt.Errorf("no YARA rules to compile")
	}

	var dropped []RuleCompileWarning
	record := func(w RuleCompileWarning) {
		dropped = append(dropped, w)
		if onWarn != nil {
			onWarn(w)
		}
	}

	pass := compileSourcesIsolated(sources, record)
	if pass.err != nil {
		return nil, nil, dropped, noUsableRulesError(len(sources), dropped, pass.err)
	}
	return pass.rules, pass.kept, append(dropped, pass.warns...), nil
}

// noUsableRulesError folds every dropped source into a single actionable
// error: a ruleset that ends up empty is fatal, and the operator needs to know
// which files to fix.
func noUsableRulesError(total int, dropped []RuleCompileWarning, cause error) error {
	if len(dropped) == 0 {
		return cause
	}
	const maxShown = 5
	shown := dropped
	extra := ""
	if len(shown) > maxShown {
		shown = shown[:maxShown]
		extra = fmt.Sprintf(" (+%d more)", len(dropped)-maxShown)
	}
	msgs := make([]string, 0, len(shown))
	for _, w := range shown {
		msgs = append(msgs, w.Error())
	}
	return fmt.Errorf("no usable YARA rules: all %d rule source(s) failed to compile%s: %s (%w)",
		total, extra, strings.Join(msgs, "; "), cause)
}

// compileSourcesIsolated performs a single pass over sources and, on failure,
// narrows the problem down to the exact source that has to be dropped.
//
// compileOnce fails at the first source that cannot be added to the compiler
// (a YARA compiler is unusable once it has reported a parse error, so the pass
// cannot simply be resumed). We therefore narrow the search instead:
//
//   - source compiles alone            -> it clashes with an earlier source, so
//     the earlier prefix is compiled on its own; if the prefix is also broken
//     recurse into it, otherwise the newcomer is the one to drop.
//   - source does not compile alone    -> it is intrinsically broken, drop it.
//
// Every branch drops exactly one source, so this terminates.
func compileSourcesIsolated(sources []RuleSource, onWarn func(RuleCompileWarning)) compilePass {
	pass := compileOnce(sources)
	if pass.err == nil {
		return pass
	}

	badIdx := pass.failed
	if badIdx < 0 || badIdx >= len(sources) {
		badIdx = len(sources) - 1
	}

	if len(sources) == 1 {
		onWarn(pass.diag)
		return compilePass{failed: badIdx, diag: pass.diag, err: pass.err}
	}

	if badIdx == 0 {
		// The very first source failed: it is broken on its own.
		onWarn(pass.diag)
		return compileSourcesIsolated(dropSource(sources, 0), onWarn)
	}

	// Does the failing source compile on its own?
	solo := compileOnce(sources[badIdx : badIdx+1])
	if solo.err == nil {
		// It is valid, so it collides with a rule compiled earlier. Narrow the
		// search down to the prefix: if the prefix is broken too, the culprit
		// is in there, otherwise the newcomer is the one to drop.
		prefix := compileOnce(sources[:badIdx])
		if prefix.err != nil && prefix.failed >= 0 {
			onWarn(pass.diag)
			return compileSourcesIsolated(sources[:badIdx], onWarn)
		}
		onWarn(conflictWarning(pass.diag))
		return compileSourcesIsolated(dropSource(sources, badIdx), onWarn)
	}

	onWarn(solo.diag)
	return compileSourcesIsolated(dropSource(sources, badIdx), onWarn)
}

// dropSource returns sources without the entry at idx without mutating the
// caller's slice (the 3-index slice forces a copy on append).
func dropSource(sources []RuleSource, idx int) []RuleSource {
	out := make([]RuleSource, 0, len(sources)-1)
	out = append(out, sources[:idx]...)
	out = append(out, sources[idx+1:]...)
	return out
}

// compilePass is the outcome of one attempt at compiling a set of sources.
type compilePass struct {
	rules  *yara.Rules          // nil when err != nil
	kept   []RuleSource         // the sources that made it into rules
	warns  []RuleCompileWarning // non-fatal compiler warnings of this pass
	failed int                  // index of the source that could not be added, -1 if none
	diag   RuleCompileWarning   // diagnostic for the failing source
	err    error
}

// compileOnce adds every source to a fresh compiler and returns the resulting
// ruleset. On failure the returned pass carries the index of the source that
// could not be added plus a locatable diagnostic for it.
func compileOnce(sources []RuleSource) compilePass {
	compiler, cerr := yara.NewCompiler()
	if cerr != nil {
		return compilePass{failed: -1, err: fmt.Errorf("could not create YARA compiler: %w", cerr)}
	}
	defer compiler.Destroy()

	// Inline text comes from an MCP client, not the operator's rules directory.
	// include would read any file this process can, past the path sandbox.
	for i := range sources {
		if sources[i].Text != "" {
			compiler.DisableIncludes()
			break
		}
	}

	for i := range sources {
		if aerr := addRuleSource(compiler, sources[i]); aerr != nil {
			return compilePass{
				failed: i,
				diag:   describeCompilerFailure(compiler, sources[i], aerr),
				err:    aerr,
			}
		}
	}

	rules, gerr := compiler.GetRules()
	if gerr != nil {
		return compilePass{failed: -1, err: fmt.Errorf("could not finalise YARA ruleset: %w", gerr)}
	}

	return compilePass{rules: rules, kept: sources, warns: compilerWarnings(compiler), failed: -1}
}

// addRuleSource feeds one source to the compiler.
func addRuleSource(compiler *yara.Compiler, src RuleSource) error {
	if src.Text != "" {
		return compiler.AddString(src.Text, src.Namespace)
	}
	f, _, err := safefs.Open(src.Path)
	if err != nil {
		return fmt.Errorf("could not open rule file: %w", err)
	}
	defer f.Close()
	return compiler.AddFile(f, src.Namespace)
}

// warnFor turns a compiler failure into a warning, pulling the line number
// reported by the YARA compiler callback and deriving a column when the
// message names a token that can be located in the source.
func warnFor(src RuleSource, err error, line int) RuleCompileWarning {
	w := RuleCompileWarning{
		Source:    src.label(),
		Namespace: src.Namespace,
		Line:      line,
		Err:       err,
	}
	if w.Err == nil {
		w.Err = fmt.Errorf("failed to compile")
	}
	return w
}

func conflictWarning(diag RuleCompileWarning) RuleCompileWarning {
	diag.Err = fmt.Errorf("%w (it collides with a rule compiled earlier)", diag.Err)
	return diag
}

// describeCompilerFailure turns a compiler failure into a locatable warning:
// the YARA compiler callback knows the line (and, via the message, often the
// offending token, which yields the column).
func describeCompilerFailure(compiler *yara.Compiler, src RuleSource, addErr error) RuleCompileWarning {
	w := warnFor(src, addErr, 0)
	if msgs := compiler.Errors; len(msgs) > 0 {
		// yr_compiler_get_error_message reports the LAST error, so align with
		// the last callback message.
		last := msgs[len(msgs)-1]
		w.Line = last.Line
		w.Rule = last.Rule
		w.Column = locateColumn(src, last.Line, last.Text)
		if last.Filename != "" && last.Filename != src.Path {
			w.Source = last.Filename
		}
	}
	return w
}

// compilerWarnings converts YARA's non-fatal compiler warnings (slow strings,
// unreferenced modifiers, ...) into RuleCompileWarnings.
func compilerWarnings(compiler *yara.Compiler) []RuleCompileWarning {
	if len(compiler.Warnings) == 0 {
		return nil
	}
	out := make([]RuleCompileWarning, 0, len(compiler.Warnings))
	for _, m := range compiler.Warnings {
		out = append(out, RuleCompileWarning{
			Source: m.Filename,
			Line:   m.Line,
			Rule:   m.Rule,
			Err:    fmt.Errorf("%s", m.Text),
		})
	}
	return out
}

var (
	// syntax errors look like: syntax error, unexpected <condition>, expecting ...
	reUnexpectedTag = regexp.MustCompile(`unexpected <([^>]+)>`)
	// semantic errors quote the offending token: undefined identifier "foo"
	reQuotedToken = regexp.MustCompile(`"([^"]+)"`)
)

// locateColumn returns the 1-based column of the token blamed by the compiler
// message, or 0 when the token cannot be found. The YARA C API only reports a
// line number, so the column is recovered from the source text.
func locateColumn(src RuleSource, line int, message string) int {
	if line <= 0 {
		return 0
	}
	token := blamedToken(message)
	if token == "" {
		return 0
	}
	text, ok := sourceLine(src, line)
	if !ok {
		return 0
	}
	if idx := strings.Index(text, token); idx >= 0 {
		return idx + 1
	}
	return 0
}

// blamedToken extracts the token the YARA compiler complained about.
func blamedToken(message string) string {
	if m := reUnexpectedTag.FindStringSubmatch(message); m != nil {
		return m[1]
	}
	if m := reQuotedToken.FindStringSubmatch(message); m != nil {
		return m[1]
	}
	return ""
}

// sourceLine returns the given 1-based line of a rule source.
func sourceLine(src RuleSource, line int) (string, bool) {
	if src.Text != "" {
		lines := strings.Split(src.Text, "\n")
		if line-1 < 0 || line-1 >= len(lines) {
			return "", false
		}
		return lines[line-1], true
	}
	if src.Path == "" {
		return "", false
	}
	f, _, err := safefs.Open(src.Path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for i := 1; sc.Scan(); i++ {
		if i == line {
			return sc.Text(), true
		}
	}
	return "", false
}

// collectRuleFiles returns all .yar/.yara files at the given path. If path is a
// file, it returns just that file; if it is a directory, it walks it
// recursively. The rules directory is walked exactly once, at load time.
func collectRuleFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("could not access rules path %s: %w", path, err)
	}

	if !info.IsDir() {
		if !isRuleFile(path) {
			return nil, fmt.Errorf("rules file must have .yar or .yara extension: %s", path)
		}
		return []string{path}, nil
	}

	var files []string
	err = filepath.Walk(safefs.WalkRoot(path), func(p string, fi os.FileInfo, werr error) error {
		if werr != nil {
			// An unreadable sub-directory must not abort the whole load.
			if fi != nil && fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		if isRuleFile(p) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not walk rules path %s: %w", path, err)
	}

	// Deterministic compile order keeps rule numbering stable between runs.
	sort.Strings(files)
	return files, nil
}

func isRuleFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yar" || ext == ".yara"
}

var reInvalidNamespaceChars = regexp.MustCompile(`[^A-Za-z0-9_.]`)

// namespaceFromFileName derives a namespace from a rule file name, keeping the
// historical behaviour available through WithNamespaceFromFileName. Characters
// YARA does not accept in an identifier are replaced.
func namespaceFromFileName(path string) string {
	base := filepath.Base(path)
	return reInvalidNamespaceChars.ReplaceAllString(strings.TrimSuffix(base, filepath.Ext(base)), "_")
}

// RuleFiles returns every .yar/.yara file at path (a file, or a directory
// walked recursively), in the deterministic order the compiler loads them.
func RuleFiles(path string) ([]string, error) { return collectRuleFiles(path) }

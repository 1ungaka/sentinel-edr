package main

import (
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Doc-as-code, the engine-side slice of it: every `cau ...` command line shown
// in a fenced code block of the documentation must name a command that exists
// and use only flags that command defines. The flag sets live inside the cmdX
// functions, so they are read back from the CLI itself, in-process:
//
//   - `cau <path> --help` lists the flags (the flag package's defaults listing,
//     or a command's hand-written usage);
//   - `cau <path> --<name>=x --help` asks the flag package directly: it answers
//     "flag provided but not defined: -<name>" for an unknown flag, and either
//     the usage or an invalid-value error for a known one.
//
// Both forms stop inside fs.Parse, before a command does any work. That holds
// because every command defines its flags and then parses them as its first
// action, returning on any parse error (flag.ErrHelp included). A command that
// did real work before parsing would have to be excluded here.

const (
	// docsNoSuchSub and docsNoSuchFlag are names no command will ever define.
	// They calibrate the probes: how a command answers an unknown word.
	docsNoSuchSub  = "zz-docs-test-no-such-subcommand"
	docsNoSuchFlag = "zz-docs-test-no-such-flag"

	// Vacuity floors. The documentation held 159 checked example lines, 49
	// distinct subcommand paths and 273 flag uses when these were chosen; an
	// extraction that silently finds little or nothing must fail, not pass.
	docsMinExamples = 100
	docsMinPaths    = 30
	docsMinFlags    = 150
)

var (
	docsWord         = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	docsHelpFlag     = regexp.MustCompile(`^-{1,2}([a-z0-9][a-z0-9-]*)`)
	docsHelpAlias    = regexp.MustCompile(`^(?:, ?| ?\| ?|/)-{1,2}([a-z0-9][a-z0-9-]*)`)
	docsHelpColumns  = regexp.MustCompile(`\t| {2,}`)
	docsSynopsisWord = regexp.MustCompile(`(?i)^<?(flags?|options?|opts)(\.\.\.|…)?>?$`)
	docsFlagHole     = regexp.MustCompile(`^-{1,2}[<{]`)
)

// docsTok is one shell word of a documented command line.
type docsTok struct {
	text   string
	pos    int  // byte offset in the joined command text
	line   int  // 1-based line in the file (set by docsExtract)
	quoted bool // the word began with a quote: a value, never a flag
	opt    bool // the word sits inside synopsis brackets, [..] or (..)
}

// docsExample is one `cau ...` command line found in a fenced code block.
type docsExample struct {
	file     string
	line     int       // 1-based line of the `cau` word
	toks     []docsTok // the words after `cau`, up to the first shell operator
	synopsis bool      // a usage synopsis whose flags are placeholders
}

type docsFlag struct {
	name string
	line int
}

// docsTokenize splits the text after `cau` into shell words and stops at the
// first shell operator outside quotes (a pipe, a redirect, &&, ;, a comment).
//
// Documentation mixes runnable lines with synopses, so three notations that
// are not shell are understood rather than tripped over:
//
//   - [..] and (..) group optional or alternative arguments; the brackets are
//     dropped and the words inside are kept, so `[--format json]` still has
//     its flag checked;
//   - <placeholder> is one word, even with a space in it (`<path ...>`);
//   - a | is an alternative, not a pipe, inside brackets, between the values
//     of one word (text|json), and whenever what follows it starts with a
//     dash, because no command in a pipeline does (--from <dir> | --url <u>).
//
// A pipe written without spaces after a plain word (x|jq) is therefore read as
// alternatives; write pipes with spaces around them.
func docsTokenize(s string) []docsTok {
	var (
		toks   []docsTok
		cur    strings.Builder
		inTok  bool
		start  int
		quoted bool
		depth  int
	)
	flush := func() {
		if inTok {
			toks = append(toks, docsTok{text: cur.String(), pos: start, quoted: quoted, opt: depth > 0})
		}
		cur.Reset()
		inTok, quoted = false, false
	}
	open := func(i int, q bool) {
		if !inTok {
			inTok, start, quoted = true, i, q
		}
	}
	// flagName reports whether the word being built is still a flag's name.
	flagName := func() bool {
		w := cur.String()
		return inTok && !quoted && strings.HasPrefix(w, "-") && !strings.Contains(w, "=")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
		case '\\':
			if i+1 == len(s) {
				continue
			}
			i++
			if s[i] == '\n' {
				continue // a line continuation
			}
			open(i-1, false)
			cur.WriteByte(s[i])
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 { // an apostrophe in prose, not a quote
				open(i, false)
				cur.WriteByte(c)
				continue
			}
			open(i, true)
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case '"':
			end := docsClosingQuote(s, i+1)
			if end < 0 {
				open(i, false)
				cur.WriteByte(c)
				continue
			}
			open(i, true)
			for j := i + 1; j < end; j++ {
				if s[j] == '\\' && j+1 < end {
					j++
				}
				cur.WriteByte(s[j])
			}
			i = end
		case '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				open(i, false)
				cur.WriteByte(c)
				continue
			}
			open(i, false)
			cur.WriteString(s[i : i+end+2]) // a command substitution is one opaque word
			i += end + 1
		case '$':
			open(i, false)
			if i+1 < len(s) && s[i+1] == '(' {
				if end := docsMatchParen(s, i+1); end > 0 {
					cur.WriteString(s[i : end+1]) // $(find . -name x): its flags are not cau's
					i = end
					continue
				}
			}
			cur.WriteByte(c)
		case '#':
			if !inTok {
				return toks // a comment
			}
			cur.WriteByte(c)
		case ';', '>':
			flush()
			return toks
		case '&':
			if !inTok || (i+1 < len(s) && s[i+1] == '&') {
				flush()
				return toks
			}
			cur.WriteByte(c)
		case '<':
			end := docsPlaceholderEnd(s, i)
			if end < 0 { // a redirect
				flush()
				return toks
			}
			open(i, false)
			cur.WriteString(s[i : end+1])
			i = end
		case '|':
			if i+1 < len(s) && s[i+1] == '|' {
				flush()
				return toks
			}
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			dashNext := j+1 < len(s) && s[j] == '-' && (s[j+1] == '-' || docsLetter(s[j+1]))
			switch {
			case depth > 0 || dashNext:
				flush() // alternatives
			case inTok && !flagName() && j == i+1 && j < len(s) && s[j] != '\n':
				cur.WriteByte(c) // text|json
			default:
				flush()
				return toks
			}
		case '[':
			if inTok && !flagName() {
				cur.WriteByte(c)
				continue
			}
			flush()
			depth++
		case '(':
			if inTok {
				cur.WriteByte(c)
				continue
			}
			depth++
		case ']', ')':
			if depth == 0 {
				open(i, false)
				cur.WriteByte(c)
				continue
			}
			flush()
			depth--
		default:
			open(i, false)
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

func docsLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// docsClosingQuote returns the index of the double quote closing the string
// that starts at from, or -1.
func docsClosingQuote(s string, from int) int {
	for j := from; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j
		}
	}
	return -1
}

// docsMatchParen returns the index of the parenthesis closing the one at open,
// or -1.
func docsMatchParen(s string, open int) int {
	depth := 0
	for j := open; j < len(s); j++ {
		switch s[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// docsPlaceholderEnd returns the index of the > closing a <placeholder> that
// starts at i, or -1 when the < is a shell redirect.
func docsPlaceholderEnd(s string, i int) int {
	if i+1 >= len(s) || !(docsLetter(s[i+1]) || (s[i+1] >= '0' && s[i+1] <= '9')) {
		return -1
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '>':
			return j
		case '<', '\n':
			return -1
		}
	}
	return -1
}

// docsCommand strips a shell prompt and sudo from a code-block line and
// returns what follows the `cau` word, when the line is a cau command.
func docsCommand(line string) (rest string, ok bool) {
	s := strings.TrimLeft(line, " \t")
	for stripped := true; stripped; {
		stripped = false
		for _, prefix := range []string{"$ ", "# ", "sudo "} {
			if after, found := strings.CutPrefix(s, prefix); found {
				s, stripped = strings.TrimLeft(after, " \t"), true
			}
		}
	}
	s = strings.TrimPrefix(s, "./")
	after, found := strings.CutPrefix(s, "cau")
	if !found || after == "" || (after[0] != ' ' && after[0] != '\t') {
		return "", false
	}
	return after, true
}

// docsFenceRun returns the run of backticks or tildes that opens or closes a
// fenced code block on this line, or "".
func docsFenceRun(line string) string {
	s := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(s, "```") && !strings.HasPrefix(s, "~~~") {
		return ""
	}
	n := 0
	for n < len(s) && s[n] == s[0] {
		n++
	}
	return s[:n]
}

// docsExtract returns the cau command lines in the fenced code blocks of one
// Markdown document. A line ending in a backslash continues on the next; so
// does a synopsis whose next line is indented and opens with a bracketed flag.
func docsExtract(file, content string) []docsExample {
	lines := strings.Split(content, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	var out []docsExample
	fence := "" // the opening run while inside a block
	for i := 0; i < len(lines); i++ {
		if run := docsFenceRun(lines[i]); run != "" {
			trimmed := strings.TrimSpace(lines[i])
			switch {
			case fence == "":
				if !strings.Contains(trimmed[len(run):], run) { // not a one-line code span
					fence = run
				}
			case run[0] == fence[0] && len(run) >= len(fence) && trimmed == run:
				fence = ""
			}
			continue
		}
		if fence == "" {
			continue
		}
		text, ok := docsCommand(lines[i])
		if !ok {
			continue
		}
		first := i + 1
		for i+1 < len(lines) && docsFenceRun(lines[i+1]) == "" {
			next := lines[i+1]
			if head := strings.TrimRight(text, " \t"); strings.HasSuffix(head, `\`) {
				text = strings.TrimSuffix(head, `\`) + "\n" + next
				i++
				continue
			}
			body := strings.TrimLeft(next, " \t")
			if body != next && (strings.HasPrefix(body, "[-") || strings.HasPrefix(body, "(-")) {
				text += "\n" + next
				i++
				continue
			}
			break
		}
		toks := docsTokenize(text)
		if len(toks) == 0 {
			continue
		}
		ex := docsExample{file: file, line: first, toks: toks}
		for k := range toks {
			tk := &toks[k]
			tk.line = first + strings.Count(text[:tk.pos], "\n")
			if tk.quoted {
				continue
			}
			placeholder := tk.opt || strings.HasPrefix(tk.text, "<")
			if (placeholder && docsSynopsisWord.MatchString(tk.text)) || docsFlagHole.MatchString(tk.text) {
				ex.synopsis = true
			}
		}
		out = append(out, ex)
	}
	return out
}

// docsFlagName returns the flag a word names: one dash or two, then a letter,
// up to an optional =value. Negative numbers, a bare - and -- are not flags.
func docsFlagName(word string) (string, bool) {
	rest, ok := strings.CutPrefix(word, "-")
	if !ok {
		return "", false
	}
	rest = strings.TrimPrefix(rest, "-")
	if rest == "" || !docsLetter(rest[0]) {
		return "", false
	}
	name, _, _ := strings.Cut(rest, "=")
	return name, true
}

// docsFlags returns the flags among the words of a command, stopping at the
// -- that ends flag parsing. A quoted word is a value even when it starts
// with a dash.
func docsFlags(toks []docsTok) []docsFlag {
	var out []docsFlag
	for _, tk := range toks {
		if tk.quoted {
			continue
		}
		if tk.text == "--" {
			break
		}
		if name, ok := docsFlagName(tk.text); ok {
			out = append(out, docsFlag{name: name, line: tk.line})
		}
	}
	return out
}

func docsEditDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		row := make([]int, len(b)+1)
		row[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			row[j] = min(prev[j]+1, row[j-1]+1, prev[j-1]+cost)
		}
		prev = row
	}
	return prev[len(b)]
}

// docsClosest returns the candidate nearest to name, or "" when nothing is
// near enough to be a plausible slip. A candidate that extends name (or the
// reverse) counts as near: --out for --output.
func docsClosest(name string, candidates []string) string {
	best, bestDist := "", (len(name)+1)/2+1
	for _, c := range slices.Sorted(slices.Values(candidates)) {
		d := docsEditDistance(name, c)
		if strings.HasPrefix(c, name) || strings.HasPrefix(name, c) {
			d = min(d, 1)
		}
		if d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

func docsDidYouMean(prefix, name string, candidates []string) string {
	if c := docsClosest(name, candidates); c != "" {
		return " (did you mean " + prefix + c + "?)"
	}
	return ""
}

// docsHelpFlags returns the flags a --help text lists: the flag package's
// defaults listing ("  -name value") or a hand-written one ("  --name <arg>",
// "  -q, --quiet", "  --db <path>  --rules <path>   detection content"). Only
// the flag columns of an indented line count; a flag mentioned in a
// description does not.
func docsHelpFlags(help string) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(help, "\n") {
		body := strings.TrimLeft(line, " \t")
		if body == line {
			continue
		}
		for _, column := range docsHelpColumns.Split(body, -1) {
			m := docsHelpFlag.FindStringSubmatch(column)
			if m == nil {
				break // the description column
			}
			for m != nil {
				set[m[1]] = true
				column = column[len(m[0]):]
				m = docsHelpAlias.FindStringSubmatch(column)
			}
		}
	}
	return set
}

// docsCLI reads the CLI's own surface back, in-process. Every invocation it
// makes ends in --help, so it only ever reaches a command's flag parser.
type docsCLI struct {
	t    *testing.T
	outs map[string]string
	sets map[string]*docsFlagSet
}

type docsFlagSet struct {
	help  map[string]bool // flags the --help text lists
	probe bool            // the flag package answers for this path (see defined)
}

func newDocsCLI(t *testing.T) *docsCLI {
	return &docsCLI{t: t, outs: map[string]string{}, sets: map[string]*docsFlagSet{}}
}

func (c *docsCLI) help(args ...string) string {
	args = append(slices.Clone(args), "--help")
	key := strings.Join(args, "\x00")
	if out, ok := c.outs[key]; ok {
		return out
	}
	code, stdout, stderr := runCLI(c.t, args...)
	out := fmt.Sprintf("exit %d\n%s\n%s", code, stdout, stderr)
	c.outs[key] = out
	return out
}

// dispatches reports whether cmd treats its first bare word as a nested
// subcommand: a command with one flag set ignores a positional word in front
// of --help, a dispatcher does not.
func (c *docsCLI) dispatches(cmd string) bool {
	return c.help(cmd) != c.help(cmd, docsNoSuchSub)
}

// unknownSub reports whether cmd answers sub exactly as it answers a word
// that is certainly not one of its subcommands.
func (c *docsCLI) unknownSub(cmd, sub string) bool {
	return c.help(cmd, sub) == strings.ReplaceAll(c.help(cmd, docsNoSuchSub), docsNoSuchSub, sub)
}

func (c *docsCLI) flagSet(path []string) *docsFlagSet {
	key := strings.Join(path, " ")
	if set, ok := c.sets[key]; ok {
		return set
	}
	set := &docsFlagSet{help: docsHelpFlags(c.help(path...))}
	set.probe = !c.defined(path, docsNoSuchFlag)
	c.sets[key] = set
	return set
}

// defined asks the flag package whether the path's flag set has this flag.
// --name=x is rejected as "provided but not defined" when it does not; when it
// does, parsing goes on to --help (or stops at an invalid value). Only
// meaningful when the path's set.probe is true: a path with no flag set at
// all never says "not defined".
func (c *docsCLI) defined(path []string, name string) bool {
	out := c.help(append(slices.Clone(path), "--"+name+"=x")...)
	return !strings.Contains(out, "flag provided but not defined: -"+name+"\n")
}

// docsFiles lists the documentation the examples are collected from.
func docsFiles(t *testing.T) []string {
	t.Helper()
	files := []string{"README.md"}
	err := filepath.WalkDir("docs", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking docs/: %v", err)
	}
	wiki, err := filepath.Glob(filepath.Join("wiki", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, wiki...)
	slices.Sort(files)
	return files
}

// docsReport is what checking a set of examples against the CLI found.
type docsReport struct {
	violations []string          // file:line: message, sorted by file and line
	paths      map[string]bool   // distinct subcommand paths whose flags were looked up
	blind      map[string]bool   // paths whose flags cannot be read back at all
	unchecked  map[string]string // "path --flag" used on a blind path -> where
	helpGaps   map[string]string // "path --flag" defined but not listed by --help -> where
	examples   int               // example lines checked
	synopses   int               // synopsis lines: command name checked, flags skipped
	flags      int               // flag uses looked up
}

// docsCheck holds every example against the real CLI: the command must exist,
// a nested subcommand must exist, and every flag must be one the subcommand's
// flag set defines.
func docsCheck(t *testing.T, examples []docsExample) *docsReport {
	t.Helper()
	commands := map[string]bool{"help": true, "version": true, "completion": true}
	for _, c := range commandsFromUsage(t) {
		commands[c] = true
	}
	commandNames := make([]string, 0, len(commands))
	for c := range commands {
		commandNames = append(commandNames, c)
	}

	type finding struct {
		file string
		line int
		msg  string
	}
	var findings []finding
	fail := func(file string, line int, format string, a ...any) {
		findings = append(findings, finding{file, line, fmt.Sprintf(format, a...)})
	}
	note := func(m map[string]string, key, where string) {
		if _, seen := m[key]; !seen {
			m[key] = where
		}
	}

	cli := newDocsCLI(t)
	rep := &docsReport{
		paths: map[string]bool{}, blind: map[string]bool{},
		unchecked: map[string]string{}, helpGaps: map[string]string{},
	}
	for _, ex := range examples {
		cmd := ex.toks[0]
		switch {
		case cmd.quoted || strings.HasPrefix(cmd.text, "<"):
			rep.synopses++ // cau <command> ...
			continue
		case strings.HasPrefix(cmd.text, "-"):
			if !slices.Contains([]string{"-h", "--help", "-v", "--version"}, cmd.text) {
				fail(ex.file, ex.line, "cau %s: not a top-level flag (cau takes -h, --help, -v and --version)", cmd.text)
			}
			rep.examples++
			continue
		case !commands[cmd.text]:
			fail(ex.file, ex.line, "cau %s: command does not exist%s", cmd.text, docsDidYouMean("cau ", cmd.text, commandNames))
			continue
		}
		if ex.synopsis {
			rep.synopses++ // the command name was checked; its flags are placeholders
			continue
		}
		rep.examples++

		path, rest := []string{cmd.text}, ex.toks[1:]
		if len(rest) > 0 && !rest[0].quoted && docsWord.MatchString(rest[0].text) && cli.dispatches(cmd.text) {
			sub := rest[0].text
			if cli.unknownSub(cmd.text, sub) {
				fail(ex.file, rest[0].line, "cau %s: subcommand %q does not exist", cmd.text, sub)
				continue
			}
			path, rest = append(path, sub), rest[1:]
		}
		key := strings.Join(path, " ")
		rep.paths[key] = true
		set := cli.flagSet(path)
		if !set.probe && len(set.help) == 0 {
			rep.blind[key] = true
		}
		known := make([]string, 0, len(set.help))
		for name := range set.help {
			known = append(known, name)
		}

		for _, fl := range docsFlags(rest) {
			rep.flags++
			where := fmt.Sprintf("%s:%d", ex.file, fl.line)
			listed := set.help[fl.name] || fl.name == "h" || fl.name == "help"
			undefined := func(why string) {
				fail(ex.file, fl.line, "cau %s: flag --%s is not defined%s%s", key, fl.name, why, docsDidYouMean("--", fl.name, known))
			}
			switch {
			case rep.blind[key]:
				note(rep.unchecked, key+" --"+fl.name, where)
			case !set.probe: // only the --help text to go by
				if !listed {
					undefined("")
				}
			case !cli.defined(path, fl.name) && listed:
				undefined(" (the --help text lists it, this subcommand's flag set does not have it)")
			case !cli.defined(path, fl.name):
				undefined("")
			case !listed:
				note(rep.helpGaps, key+" --"+fl.name, where)
			}
		}
	}

	slices.SortFunc(findings, func(a, b finding) int {
		return cmp.Or(cmp.Compare(a.file, b.file), cmp.Compare(a.line, b.line), cmp.Compare(a.msg, b.msg))
	})
	for _, f := range findings {
		rep.violations = append(rep.violations, fmt.Sprintf("%s:%d: %s", f.file, f.line, f.msg))
	}
	return rep
}

func docsSortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestDocsExamplesUseRealFlags(t *testing.T) {
	var examples []docsExample
	for _, file := range docsFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		examples = append(examples, docsExtract(filepath.ToSlash(file), string(data))...)
	}

	rep := docsCheck(t, examples)
	for _, v := range rep.violations {
		t.Error(v)
	}

	t.Logf("checked %d example lines (%d more are synopses: command name only), %d distinct subcommand paths, %d flag uses",
		rep.examples, rep.synopses, len(rep.paths), rep.flags)
	t.Logf("could not introspect (no flags in --help, no flag set to probe): %q", docsSortedKeys(rep.blind))
	for _, k := range docsSortedKeys(rep.unchecked) {
		t.Logf("not checked, the path cannot be introspected: cau %s (first used at %s)", k, rep.unchecked[k])
	}
	for _, k := range docsSortedKeys(rep.helpGaps) {
		t.Logf("help text incomplete: cau %s is defined, but `--help` does not list it (first used at %s)", k, rep.helpGaps[k])
	}

	if rep.examples < docsMinExamples || len(rep.paths) < docsMinPaths || rep.flags < docsMinFlags {
		t.Errorf("found %d example lines, %d subcommand paths and %d flag uses; want at least %d, %d and %d: the extraction is broken or the documentation lost its examples",
			rep.examples, len(rep.paths), rep.flags, docsMinExamples, docsMinPaths, docsMinFlags)
	}
}

// TestDocsCheckerCatchesDrift holds the checker itself against the real CLI
// with examples whose answers are known, so a change to how commands answer
// --help cannot turn the documentation check into one that passes everything.
func TestDocsCheckerCatchesDrift(t *testing.T) {
	const fence = "```"
	md := strings.Join([]string{
		/* 1 */ fence,
		/* 2 */ "cau scan --dir ./x --format json --fail-on none --quiet",
		/* 3 */ "cau scan ./x --outpt report.json",
		/* 4 */ "cau frobnicate --fast",
		/* 5 */ "cau eval run --corpus m.json --no-such-eval-flag",
		/* 6 */ "cau eval bogus --corpus m.json",
		/* 7 */ `sudo cau net block 203.0.113.9 --reason "phishing kit C2"`,
		/* 8 */ "cau net --reason why",
		/* 9 */ "cau quarantine restore <id> --to ./out.bin \\",
		/* 10 */ "    --overwrite",
		/* 11 */ "cau hash --format json a.exe | jq -r .sha256",
		/* 12 */ "cau completion bash --shell zsh",
		/* 13 */ "cau version --verbose",
		/* 14 */ "cau update (--from <dir> | --url <base>) [--pubkey <file>] [--no-such-update-flag]",
		/* 15 */ "cau scan -h",
		/* 16 */ "cau persist [flags] --never-checked",
		/* 17 */ fence,
	}, "\n")
	rep := docsCheck(t, docsExtract("drift.md", md))

	want := []string{
		"drift.md:3: cau scan: flag --outpt is not defined (did you mean --output?)",
		"drift.md:4: cau frobnicate: command does not exist",
		"drift.md:5: cau eval run: flag --no-such-eval-flag is not defined",
		`drift.md:6: cau eval: subcommand "bogus" does not exist`,
		"drift.md:8: cau net: flag --reason is not defined",
		"drift.md:10: cau quarantine restore: flag --overwrite is not defined",
		"drift.md:12: cau completion: flag --shell is not defined",
		"drift.md:14: cau update: flag --no-such-update-flag is not defined",
	}
	// A violation may carry a note or a suggestion after the stated text.
	for i := 0; i < max(len(want), len(rep.violations)); i++ {
		switch {
		case i >= len(rep.violations):
			t.Errorf("missing violation: %s", want[i])
		case i >= len(want):
			t.Errorf("unexpected violation: %s", rep.violations[i])
		case !strings.HasPrefix(rep.violations[i], want[i]):
			t.Errorf("violation %d:\n got %s\nwant %s", i, rep.violations[i], want[i])
		}
	}

	// `cau version` has no flag set: its flags cannot be checked, and that is
	// said rather than passed over.
	if got := docsSortedKeys(rep.blind); !slices.Equal(got, []string{"version"}) {
		t.Errorf("could not introspect %q, want only version", got)
	}
	if got := docsSortedKeys(rep.unchecked); !slices.Equal(got, []string{"version --verbose"}) {
		t.Errorf("unchecked flags %q, want only version --verbose", got)
	}
	// Line 4 names no command, so it is a violation and not an example.
	if rep.examples != 12 || rep.synopses != 1 {
		t.Errorf("checked %d examples and skipped %d synopses, want 12 and 1", rep.examples, rep.synopses)
	}
	wantPaths := []string{"completion", "eval run", "hash", "net", "net block", "quarantine restore", "scan", "update", "version"}
	if got := docsSortedKeys(rep.paths); !slices.Equal(got, wantPaths) {
		t.Errorf("paths\n got %q\nwant %q", got, wantPaths)
	}
}

func TestDocsExampleParser(t *testing.T) {
	const fence = "```"
	md := strings.Join([]string{
		/* 1 */ "Prose: cau scan --not-in-a-block",
		/* 2 */ "cau scan --not-in-a-block-either",
		/* 3 */ fence + "sh",
		/* 4 */ "$ cau scan --dir ./x --format json",
		/* 5 */ "sudo cau ps --respond stop   # freeze them; --not-a-flag",
		/* 6 */ `# sudo ./cau net block 203.0.113.9 --reason "phishing -kit --c2"`,
		/* 7 */ `cau defend --respond stop \`,
		/* 8 */ `     --ingest /var/lib/cau/telemetry \`,
		/* 9 */ "     --sever",
		/* 10 */ "cau scan ./x --format json | jq -r '.results[]'",
		/* 11 */ "cau completion bash > /etc/bash_completion.d/cau --nope",
		/* 12 */ "cau scan ./x --quiet && rm -rf ./y; ls -la",
		/* 13 */ "cau scan --fail-on=none --output=$(mktemp -d)/r.json -quiet $(find . -name x)",
		/* 14 */ "cau intake --format stix --input - -- -not-a-flag",
		/* 15 */ "cau persist --threshold -5",
		/* 16 */ "cau scan      [flags] [path ...]     scan files and directories",
		/* 17 */ "cau frob --<name> value",
		/* 18 */ "cau update (--from <dir> | --url <base>) [--pubkey <file>] [--dry-run]",
		/* 19 */ "           [--allow-downgrade]",
		/* 20 */ "cau rules lint [--profile cau|generic] [--format text|json] [--strict]",
		/* 21 */ "cau verify-self --from|--url <x>",
		/* 22 */ `cau add-hash --name "-weird name" --hash 'abc -def'`,
		/* 23 */ "cau quarantine restore <id> --to ./recovered.bin",
		/* 24 */ "cau-mcp serve --not-cau",
		/* 25 */ "the cau binary --not-a-command-line",
		/* 26 */ "cau version    print the binary's version",
		/* 27 */ "cau",
		/* 28 */ fence,
		/* 29 */ "cau scan --after-the-block",
		/* 30 */ "~~~",
		/* 31 */ "cau hash --format json a.exe",
		/* 32 */ fence, // does not close a tilde block
		/* 33 */ "cau cluster --imphashes a b",
		/* 34 */ "~~~",
		/* 35 */ "cau scan --after-the-tilde-block",
		/* 36 */ fence + "cau scan --a-code-span-on-one-line" + fence,
		/* 37 */ "cau scan --still-outside",
	}, "\n")

	type want struct {
		line     int
		words    string // the words up to the first flag
		flags    string // name@line, in order
		synopsis bool
	}
	wants := []want{
		{4, "scan", "dir@4 format@4", false},
		{5, "ps", "respond@5", false},
		{6, "net block 203.0.113.9", "reason@6", false},
		{7, "defend", "respond@7 ingest@8 sever@9", false},
		{10, "scan ./x", "format@10", false},
		{11, "completion bash", "", false},
		{12, "scan ./x", "quiet@12", false},
		{13, "scan", "fail-on@13 output@13 quiet@13", false},
		{14, "intake", "format@14 input@14", false},
		{15, "persist", "threshold@15", false},
		{16, "scan flags path ... scan files and directories", "", true},
		{17, "frob --<name> value", "", true},
		{18, "update", "from@18 url@18 pubkey@18 dry-run@18 allow-downgrade@19", false},
		{20, "rules lint", "profile@20 format@20 strict@20", false},
		{21, "verify-self", "from@21 url@21", false},
		{22, "add-hash", "name@22 hash@22", false},
		{23, "quarantine restore <id>", "to@23", false},
		{26, "version print the binary's version", "", false},
		{31, "hash", "format@31", false},
		{33, "cluster", "imphashes@33", false},
	}

	got := docsExtract("inline.md", md)
	for i, ex := range got {
		var words, flags []string
		for _, tk := range ex.toks {
			if _, isFlag := docsFlagName(tk.text); isFlag && !tk.quoted {
				break
			}
			words = append(words, tk.text)
		}
		for _, fl := range docsFlags(ex.toks) {
			flags = append(flags, fmt.Sprintf("%s@%d", fl.name, fl.line))
		}
		g := want{ex.line, strings.Join(words, " "), strings.Join(flags, " "), ex.synopsis}
		if ex.synopsis {
			g.flags = "" // a synopsis's flags are never checked
		}
		if i >= len(wants) {
			t.Errorf("unexpected example %+v", g)
			continue
		}
		if g != wants[i] {
			t.Errorf("example %d:\n got %+v\nwant %+v", i, g, wants[i])
		}
	}
	if len(got) < len(wants) {
		t.Errorf("extracted %d examples, want %d; missing from %+v", len(got), len(wants), wants[len(got):])
	}

	// The words themselves: quoting, substitutions and synopsis notation.
	tokenCases := []struct{ in, want string }{
		{`--name "foo -bar" x`, `--name|"foo -bar"|x`},
		{`--name="foo -bar" x`, `--name=foo -bar|x`},
		{`a\ b 'c d' "e \"f\""`, `a b|"c d"|"e "f""`},
		{"--out `mktemp -d` $(ls -a) $HOME", "--out|`mktemp -d`|$(ls -a)|$HOME"},
		{`x # --comment`, `x`},
		{`https://h/p#frag --quiet`, `https://h/p#frag|--quiet`},
		{`x 2>/dev/null --lost`, `x|2`},
		{`x < in.txt --lost`, `x`},
		{`x || echo --lost`, `x`},
		{`--quiet|grep -v x`, `--quiet`},
		{`[--format text|json] <path ...> [id]`, `(--format)|(text)|(json)|<path ...>|(id)`},
		{`--color[=when] file[0-9].bin`, `--color|(=when)|file[0-9].bin`},
	}
	for _, tc := range tokenCases {
		var parts []string
		for _, tk := range docsTokenize(tc.in) {
			switch {
			case tk.quoted:
				parts = append(parts, `"`+tk.text+`"`)
			case tk.opt:
				parts = append(parts, "("+tk.text+")")
			default:
				parts = append(parts, tk.text)
			}
		}
		if got := strings.Join(parts, "|"); got != tc.want {
			t.Errorf("docsTokenize(%q)\n got %s\nwant %s", tc.in, got, tc.want)
		}
	}

	flagCases := map[string]string{
		"--quiet": "quiet", "-quiet": "quiet", "--fail-on=none": "fail-on", "-o=x": "o",
		"-": "", "--": "", "-5": "", "--5": "", "---x": "", "x": "", "": "",
	}
	for word, want := range flagCases {
		if got, _ := docsFlagName(word); got != want {
			t.Errorf("docsFlagName(%q) = %q, want %q", word, got, want)
		}
	}

	candidates := []string{"output", "format", "fail-on", "quiet"}
	for name, want := range map[string]string{"out": "output", "formt": "format", "failon": "fail-on", "wazuh-url": ""} {
		if got := docsClosest(name, candidates); got != want {
			t.Errorf("docsClosest(%q) = %q, want %q", name, got, want)
		}
	}

	// The --help listing parser accepts the flag package's form and the
	// hand-written ones, and leaves flags named in a description alone.
	help := strings.Join([]string{
		"Usage of x:",
		"  -db string",
		"    \tsignature database (see --not-this-one)",
		"  -no-yara",
		"    \tdisable",
		"Flags:",
		"  --format <fmt>      text or json; --nor-this",
		"  -q, --quiet         say less",
		"  --kernel-events <f> correlate with --not-here either",
		"  --rules <path>  --fuzzy-db <path>   detection content",
		"  --no-process  --no-network   disable a layer",
		"  - a bullet, not a flag",
		"--at-column-zero is prose",
	}, "\n")
	const wantHelp = "db format fuzzy-db kernel-events no-network no-process no-yara q quiet rules"
	if got := strings.Join(docsSortedKeys(docsHelpFlags(help)), " "); got != wantHelp {
		t.Errorf("flags parsed from help\n got %s\nwant %s", got, wantHelp)
	}
}

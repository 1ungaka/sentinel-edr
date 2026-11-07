package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	docsCodeSpan     = regexp.MustCompile("(`+)([^`]+)(`+)")
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

// docsCommand strips a shell prompt, sudo and a CI step's `run:` key from a
// code-block line and returns what follows the binary's name, when the line
// invokes that binary (cau, or cau-mcp).
func docsCommand(line, binary string) (rest string, ok bool) {
	s := strings.TrimLeft(line, " \t")
	for stripped := true; stripped; {
		stripped = false
		for _, prefix := range []string{"$ ", "# ", "sudo ", "- run: ", "run: "} {
			if after, found := strings.CutPrefix(s, prefix); found {
				s, stripped = strings.TrimLeft(after, " \t"), true
			}
		}
	}
	s = strings.TrimPrefix(s, "./")
	after, found := strings.CutPrefix(s, binary)
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
	return docsExtractBinary(file, content, "cau")
}

// docsExtractBinary is docsExtract for the command lines of one binary.
func docsExtractBinary(file, content, binary string) []docsExample {
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
		text, ok := docsCommand(lines[i], binary)
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
		if ex, ok := docsNewExample(file, first, text); ok {
			out = append(out, ex)
		}
	}
	return out
}

// docsNewExample tokenizes the text that follows the binary's name. first is
// the line that text starts on.
func docsNewExample(file string, first int, text string) (docsExample, bool) {
	toks := docsTokenize(text)
	if len(toks) == 0 {
		return docsExample{}, false
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
	return ex, true
}

// docsExtractSpans returns the inline code spans of a Markdown document that
// invoke cau: `cau scan --format ocsf`. Spans inside fenced blocks are left to
// docsExtract; a span such as `cau-kernel` or `./cau.sarif` is not a command.
func docsExtractSpans(file, content string) []docsExample {
	var out []docsExample
	fence := ""
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if run := docsFenceRun(line); run != "" {
			trimmed := strings.TrimSpace(line)
			switch {
			case fence == "":
				if !strings.Contains(trimmed[len(run):], run) {
					fence = run
					continue
				}
			case run[0] == fence[0] && len(run) >= len(fence) && trimmed == run:
				fence = ""
				continue
			}
		}
		if fence != "" {
			continue
		}
		for _, m := range docsCodeSpan.FindAllStringSubmatch(line, -1) {
			text, ok := docsCommand(m[2], "cau")
			if !ok {
				continue
			}
			if ex, ok := docsNewExample(file, i+1, text); ok {
				out = append(out, ex)
			}
		}
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

// newDocsCLI refuses to probe anything unless every command in the package
// parses its flags before it does anything else: that is what makes --help
// free of side effects.
func newDocsCLI(t *testing.T) *docsCLI {
	t.Helper()
	if src := docsRootSource(); len(src.unsafe) > 0 {
		t.Fatalf("the documentation tests run every command with --help, which is only safe when a command defines its flags and parses them before doing any work; these do not:\n  %s",
			strings.Join(src.unsafe, "\n  "))
	}
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

// ── the flag sets, read back from the source ────────────────────────────────
//
// --help cannot say which flags a command defines when its usage text is
// hand-written, so the flag sets are also read from the source: every
// flag.NewFlagSet call, and the flag definitions made on its variable in the
// same function or in a helper the variable is handed to.

// docsFlagMethods maps a flag-defining method to the position of the flag's
// name among its arguments.
var docsFlagMethods = map[string]int{
	"Bool": 0, "Int": 0, "Int64": 0, "Uint": 0, "Uint64": 0, "String": 0, "Float64": 0, "Duration": 0, "Func": 0, "BoolFunc": 0,
	"BoolVar": 1, "IntVar": 1, "Int64Var": 1, "UintVar": 1, "Uint64Var": 1, "StringVar": 1, "Float64Var": 1, "DurationVar": 1, "Var": 1, "TextVar": 1,
}

type docsSrcFlagSet struct {
	name    string            // the flag.NewFlagSet name: "scan", "eval run"
	dynamic bool              // the name is a literal prefix and a computed word: "net "+sub
	fn      string            // the function that builds it
	pos     string            // file:line of the flag.NewFlagSet call
	flags   map[string]string // flag -> file:line of its definition
	custom  bool              // fs.Usage is hand-written
}

type docsSource struct {
	sets   []docsSrcFlagSet
	words  []string // case labels of the cmd* functions: candidate subcommand names
	unsafe []string // functions that do more than define flags before parsing them
	errs   []string // what could not be read or attributed
}

var docsRootSource = sync.OnceValue(func() *docsSource { return docsParseSource(".") })

func docsStringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func docsIsIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// docsIsSelector reports whether e is x.sel.
func docsIsSelector(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	return ok && docsIsIdent(s.X, x) && s.Sel.Name == sel
}

// docsFlagSetParam returns the name of fn's i-th parameter when it is a
// *flag.FlagSet, or "".
func docsFlagSetParam(fn *ast.FuncDecl, i int) string {
	n := 0
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if n == i {
				star, ok := field.Type.(*ast.StarExpr)
				if ok && docsIsSelector(star.X, "flag", "FlagSet") {
					return name.Name
				}
				return ""
			}
			n++
		}
	}
	return ""
}

// docsUsesFlagSet reports whether call is a method call on the flag set, or
// hands the flag set to a helper.
func docsUsesFlagSet(call *ast.CallExpr, ident string) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && docsIsIdent(sel.X, ident) {
		return true
	}
	return slices.ContainsFunc(call.Args, func(arg ast.Expr) bool { return docsIsIdent(arg, ident) })
}

// docsParsesFirst checks the shape that makes `cau <command> --help` free of
// side effects: after flag.NewFlagSet the function only defines flags, then
// parses them and returns when that fails. It returns what is wrong, or "".
// Statements in front of flag.NewFlagSet (cau net picks a subcommand there)
// and commands with no flag set at all are outside what it can see.
func docsParsesFirst(fn *ast.FuncDecl, ident string) string {
	start := -1
	for i, stmt := range fn.Body.List {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !docsIsIdent(as.Lhs[0], ident) {
			continue
		}
		if call, ok := as.Rhs[0].(*ast.CallExpr); ok && docsIsSelector(call.Fun, "flag", "NewFlagSet") {
			start = i
			break
		}
	}
	if start < 0 {
		return "builds its flag set inside a nested block"
	}
	for _, stmt := range fn.Body.List[start+1:] {
		if ifs, ok := stmt.(*ast.IfStmt); ok {
			init, _ := ifs.Init.(*ast.AssignStmt)
			if init != nil && len(init.Rhs) == 1 {
				if call, ok := init.Rhs[0].(*ast.CallExpr); ok && docsIsSelector(call.Fun, ident, "Parse") {
					if n := len(ifs.Body.List); n > 0 {
						if _, returns := ifs.Body.List[n-1].(*ast.ReturnStmt); returns {
							return ""
						}
					}
					return "does not return when parsing its flags fails"
				}
			}
		}
		switch stmt.(type) {
		case *ast.ExprStmt, *ast.AssignStmt, *ast.DeclStmt:
		default:
			return "does something other than define flags before it parses them"
		}
		defines := true
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false // fs.Usage = func() {...}: not run here
			case *ast.CallExpr:
				if !docsUsesFlagSet(n, ident) {
					defines = false
				}
				return false // a default value's expression is the definition's business
			}
			return true
		})
		if !defines {
			return "calls something other than a flag definition before it parses its flags"
		}
	}
	return "never parses its flags with `if err := " + ident + ".Parse(...); err != nil { return ... }`"
}

// docsParseSource reads the non-test Go files of one package directory.
func docsParseSource(dir string) *docsSource {
	src := &docsSource{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		src.errs = append(src.errs, err.Error())
		return src
	}
	var (
		fset   = token.NewFileSet()
		funcs  = map[string][]*ast.FuncDecl{}
		consts = map[string]string{}
		words  = map[string]bool{}
		decls  []*ast.FuncDecl
	)
	at := func(p token.Pos) string {
		pos := fset.Position(p)
		return fmt.Sprintf("%s:%d", filepath.ToSlash(pos.Filename), pos.Line)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			src.errs = append(src.errs, err.Error())
			continue
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				funcs[d.Name.Name] = append(funcs[d.Name.Name], d)
				decls = append(decls, d)
				if !strings.HasPrefix(d.Name.Name, "cmd") {
					continue
				}
				ast.Inspect(d.Body, func(n ast.Node) bool {
					if cc, ok := n.(*ast.CaseClause); ok {
						for _, label := range cc.List {
							if v, ok := docsStringLit(label); ok && docsWord.MatchString(v) {
								words[v] = true
							}
						}
					}
					return true
				})
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if v, ok := docsStringLit(vs.Values[i]); ok {
								consts[n.Name] = v
							}
						}
					}
				}
			}
		}
	}
	src.words = docsSortedKeys(words)

	// collect adds the flags defined on ident in fn, and in every helper of
	// the package that ident is handed to.
	var collect func(fn *ast.FuncDecl, ident string, set *docsSrcFlagSet, seen map[*ast.FuncDecl]bool)
	collect = func(fn *ast.FuncDecl, ident string, set *docsSrcFlagSet, seen map[*ast.FuncDecl]bool) {
		if seen[fn] {
			return
		}
		seen[fn] = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if docsIsSelector(lhs, ident, "Usage") {
						set.custom = true
					}
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && docsIsIdent(sel.X, ident) {
					idx, defines := docsFlagMethods[sel.Sel.Name]
					if !defines {
						return true
					}
					if idx >= len(n.Args) {
						src.errs = append(src.errs, at(n.Pos())+": a flag definition with too few arguments")
						return true
					}
					name, ok := docsStringLit(n.Args[idx])
					if id, isIdent := n.Args[idx].(*ast.Ident); !ok && isIdent {
						name, ok = consts[id.Name]
					}
					if !ok {
						src.errs = append(src.errs, at(n.Args[idx].Pos())+": a flag whose name is not a string literal or constant")
						return true
					}
					set.flags[name] = at(n.Args[idx].Pos())
					return true
				}
				for i, arg := range n.Args {
					if !docsIsIdent(arg, ident) {
						continue
					}
					callee := ""
					switch f := n.Fun.(type) {
					case *ast.Ident:
						callee = f.Name
					case *ast.SelectorExpr:
						callee = f.Sel.Name
					}
					for _, decl := range funcs[callee] {
						if param := docsFlagSetParam(decl, i); param != "" {
							collect(decl, param, set, seen)
						}
					}
				}
			}
			return true
		})
	}

	for _, fn := range decls {
		idents := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok || !docsIsSelector(call.Fun, "flag", "NewFlagSet") || len(call.Args) == 0 {
				return true
			}
			set := docsSrcFlagSet{fn: fn.Name.Name, pos: at(call.Pos()), flags: map[string]string{}}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok || idents[id.Name] {
				src.errs = append(src.errs, set.pos+": cannot tell this flag set's definitions from another's in "+fn.Name.Name)
				return true
			}
			idents[id.Name] = true
			named := false
			switch arg := call.Args[0].(type) {
			case *ast.BasicLit:
				set.name, named = docsStringLit(arg)
			case *ast.Ident:
				set.name, named = consts[arg.Name]
			case *ast.BinaryExpr:
				set.name, named = docsStringLit(arg.X)
				set.name, set.dynamic = strings.TrimSpace(set.name), true
				named = named && arg.Op == token.ADD
			}
			if !named || set.name == "" {
				src.errs = append(src.errs, set.pos+": cannot read this flag set's name")
				return true
			}
			collect(fn, id.Name, &set, map[*ast.FuncDecl]bool{})
			if why := docsParsesFirst(fn, id.Name); why != "" {
				src.unsafe = append(src.unsafe, fmt.Sprintf("%s: %s %s", set.pos, fn.Name.Name, why))
			}
			src.sets = append(src.sets, set)
			return true
		})
	}
	slices.SortFunc(src.sets, func(a, b docsSrcFlagSet) int { return cmp.Compare(a.pos, b.pos) })
	return src
}

// subcommands lists the nested subcommands of cmd, aliases and help included,
// by offering it every case label of the cmd* functions.
func (c *docsCLI) subcommands(cmd string) []string {
	if !c.dispatches(cmd) {
		return nil
	}
	var subs []string
	for _, w := range docsRootSource().words {
		if !c.unknownSub(cmd, w) {
			subs = append(subs, w)
		}
	}
	return subs
}

// docsPath is one subcommand path and the flags its flag set defines.
type docsPath struct {
	path   []string
	flags  map[string]string // flag -> file:line of its definition
	custom bool              // the usage text is hand-written
	pos    string            // file:line of the flag.NewFlagSet call
}

// docsUniverse maps every flag set in the source to the subcommand path that
// reaches it, and holds the two readings against each other: the flag package
// must answer on that path, and must accept every flag the source defines.
func docsUniverse(t *testing.T, cli *docsCLI) map[string]*docsPath {
	t.Helper()
	src := docsRootSource()
	if len(src.errs) > 0 {
		t.Fatalf("cannot read the flag sets from the source:\n  %s", strings.Join(src.errs, "\n  "))
	}
	static := map[string]bool{}
	for _, set := range src.sets {
		static[set.name] = static[set.name] || !set.dynamic
	}
	universe := map[string]*docsPath{}
	add := func(set docsSrcFlagSet, path []string) {
		key := strings.Join(path, " ")
		if other, dup := universe[key]; dup {
			t.Errorf("%s: a second flag set claims `cau %s` (the first is at %s)", set.pos, key, other.pos)
			return
		}
		if !cli.flagSet(path).probe {
			t.Errorf("%s: flag set %q is not what `cau %s --help` reaches", set.pos, set.name, key)
			return
		}
		for _, name := range docsSortedKeys(set.flags) {
			if !cli.defined(path, name) {
				t.Errorf("%s: the source defines --%s on flag set %q, but `cau %s` rejects it: the source reader and the CLI disagree",
					set.flags[name], name, set.name, key)
			}
		}
		universe[key] = &docsPath{path: path, flags: set.flags, custom: set.custom, pos: set.pos}
	}
	for _, set := range src.sets {
		if !set.dynamic {
			add(set, strings.Fields(set.name))
			continue
		}
		reached := 0
		for _, sub := range cli.subcommands(set.name) {
			if path := []string{set.name, sub}; !static[set.name+" "+sub] && cli.flagSet(path).probe {
				add(set, path)
				reached++
			}
		}
		if reached == 0 {
			t.Errorf("%s: no `cau %s <subcommand>` reaches the flag set named %q+...", set.pos, set.name, set.name+" ")
		}
	}
	return universe
}

// docsCommandFlags returns the flags defined on any path of a top-level
// command (cau eval: validate, run, ...), and whether it has a flag set.
func docsCommandFlags(universe map[string]*docsPath, cmd string) (map[string]bool, bool) {
	flags, found := map[string]bool{}, false
	for _, p := range universe {
		if p.path[0] != cmd {
			continue
		}
		found = true
		for name := range p.flags {
			flags[name] = true
		}
	}
	return flags, found
}

func docsCommandSet(t *testing.T) map[string]bool {
	t.Helper()
	commands := map[string]bool{"help": true, "version": true, "completion": true}
	for _, c := range commandsFromUsage(t) {
		commands[c] = true
	}
	return commands
}

func docsMentionsFlag(text, name string) bool {
	return regexp.MustCompile(`(^|[^A-Za-z0-9-])--?` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9-])`).MatchString(text)
}

func docsLineAt(content string, offset int) int { return 1 + strings.Count(content[:offset], "\n") }

func docsRead(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ── usage text against the flag set ─────────────────────────────────────────

// docsUndocumentedFlags are flags a command defines and deliberately leaves
// out of its --help: "path --flag" -> why. Only a test-only override of a
// filesystem root belongs here.
var docsUndocumentedFlags = map[string]string{}

const (
	// 51 paths, 13 of them with hand-written usage, and 393 flags when chosen.
	docsMinUniversePaths = 40
	docsMinCustomUsages  = 7
	docsMinDefinedFlags  = 300
)

// TestDocsHelpListsEveryFlag: every flag a subcommand defines must appear in
// that subcommand's --help. The flag package's own listing cannot omit one; a
// hand-written usage text can.
func TestDocsHelpListsEveryFlag(t *testing.T) {
	cli := newDocsCLI(t)
	universe := docsUniverse(t, cli)
	flags, custom := 0, 0
	for _, key := range docsSortedKeys(universe) {
		p := universe[key]
		help := cli.help(p.path...)
		listed := docsHelpFlags(help)
		if p.custom {
			custom++
		}
		for _, name := range docsSortedKeys(p.flags) {
			flags++
			id := key + " --" + name
			mentioned := docsMentionsFlag(help, name)
			switch _, allowed := docsUndocumentedFlags[id]; {
			case allowed && mentioned:
				t.Errorf("docsUndocumentedFlags[%q] is stale: `cau %s --help` mentions the flag", id, key)
			case allowed:
			case !mentioned:
				t.Errorf("%s: cau %s: flag --%s is defined, but `cau %s --help` does not mention it", p.flags[name], key, name, key)
			case !listed[name]:
				t.Logf("mentioned in prose only: `cau %s --help` names --%s but has no entry for it in its flag list", key, name)
			}
		}
		if !p.custom {
			continue
		}
		for _, name := range docsSortedKeys(listed) {
			if _, defined := p.flags[name]; !defined && name != "h" && name != "help" {
				t.Logf("listed but not defined: `cau %s --help` lists --%s, which `cau %s` rejects", key, name, key)
			}
		}
	}
	for _, id := range docsSortedKeys(docsUndocumentedFlags) {
		path, name, _ := strings.Cut(id, " --")
		if p := universe[path]; p == nil || p.flags[name] == "" {
			t.Errorf("docsUndocumentedFlags[%q] is stale: no such flag", id)
		}
	}
	t.Logf("checked %d defined flags on %d subcommand paths (%d with hand-written usage) against --help", flags, len(universe), custom)
	if len(universe) < docsMinUniversePaths || custom < docsMinCustomUsages || flags < docsMinDefinedFlags {
		t.Errorf("read %d subcommand paths, %d hand-written usages and %d flags from the source; want at least %d, %d and %d: the source reader is broken",
			len(universe), custom, flags, docsMinUniversePaths, docsMinCustomUsages, docsMinDefinedFlags)
	}
}

// ── inline code spans ───────────────────────────────────────────────────────

const (
	// 212 spans, 32 flag uses when chosen.
	docsMinSpans     = 110
	docsMinSpanFlags = 15
)

// TestDocsInlineSpansUseRealFlags: an inline code span that invokes cau is
// held to the same standard as a fenced example. `cau scan` has its command
// checked, `cau net clear` its subcommand, `cau scan --format ocsf` its flags.
// A span whose first word is not a plain word is not treated as a command.
func TestDocsInlineSpansUseRealFlags(t *testing.T) {
	var spans []docsExample
	for _, file := range docsFiles(t) {
		for _, ex := range docsExtractSpans(filepath.ToSlash(file), docsRead(t, file)) {
			if first := ex.toks[0]; !first.quoted && (docsWord.MatchString(first.text) || strings.HasPrefix(first.text, "<")) {
				spans = append(spans, ex)
				continue
			}
			t.Logf("%s:%d: not read as a command: `cau %s ...`", ex.file, ex.line, ex.toks[0].text)
		}
	}
	rep := docsCheck(t, spans)
	for _, v := range rep.violations {
		t.Error(v)
	}
	t.Logf("checked %d inline spans (%d more are synopses), %d distinct subcommand paths, %d flag uses",
		rep.examples, rep.synopses, len(rep.paths), rep.flags)
	for _, k := range docsSortedKeys(rep.unchecked) {
		t.Logf("not checked, the path cannot be introspected: cau %s (first used at %s)", k, rep.unchecked[k])
	}
	if rep.examples < docsMinSpans || rep.flags < docsMinSpanFlags {
		t.Errorf("found %d inline spans and %d flag uses; want at least %d and %d", rep.examples, rep.flags, docsMinSpans, docsMinSpanFlags)
	}
}

// ── man pages ───────────────────────────────────────────────────────────────

// docsRoffArgs splits the arguments of a roff request: words, or "quoted
// strings" in which "" is a quote.
func docsRoffArgs(s string) []string {
	var args []string
	for i := 0; i < len(s); {
		if s[i] == ' ' {
			i++
			continue
		}
		if s[i] != '"' {
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			args = append(args, s[i:j])
			i = j
			continue
		}
		var arg strings.Builder
		j := i + 1
		for ; j < len(s); j++ {
			if s[j] == '"' {
				if j+1 < len(s) && s[j+1] == '"' {
					j++
				} else {
					break
				}
			}
			arg.WriteByte(s[j])
		}
		args = append(args, arg.String())
		i = j + 1
	}
	return args
}

// docsRoffInline rewrites a font macro line (.B, .BR, .RI, ...) as the text it
// sets with inline font escapes. A text line is returned as it is; any other
// request reports false.
func docsRoffInline(line string) (string, bool) {
	if !strings.HasPrefix(line, ".") {
		return line, true
	}
	macro, rest, _ := strings.Cut(line[1:], " ")
	args := docsRoffArgs(rest)
	switch macro {
	case "B", "I":
		return `\f` + macro + strings.Join(args, " ") + `\fR`, true
	case "BR", "BI", "RB", "RI", "IB", "IR":
		var b strings.Builder
		for i, arg := range args {
			b.WriteString(`\f`)
			b.WriteByte(macro[i%2])
			b.WriteString(arg)
		}
		b.WriteString(`\fR`)
		return b.String(), true
	}
	return "", false
}

// docsRoffRuns renders a line of roff with inline escapes: the plain text,
// and each run of it that is set in bold.
func docsRoffRuns(s string) (plain string, bold []string) {
	var text, run strings.Builder
	cur, prev := byte('R'), byte('R')
	endRun := func() {
		if r := strings.TrimSpace(run.String()); r != "" {
			bold = append(bold, r)
		}
		run.Reset()
	}
	emit := func(str string) {
		text.WriteString(str)
		if cur == 'B' {
			run.WriteString(str)
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			emit(s[i : i+1])
			continue
		}
		i++
		switch s[i] {
		case 'f':
			if i+1 == len(s) {
				continue
			}
			i++
			next := s[i]
			if next == 'P' {
				next = prev
			}
			if cur == 'B' && next != 'B' {
				endRun()
			}
			prev, cur = cur, next
		case '-':
			emit("-")
		case '&':
		case 'e':
			emit(`\`)
		case '(':
			name := s[i+1 : min(i+3, len(s))]
			i += len(name)
			switch name {
			case "em":
				emit("—")
			case "aq":
				emit("'")
			case "dq":
				emit(`"`)
			default:
				emit("?")
			}
		default:
			emit(s[i : i+1])
		}
	}
	endRun()
	return text.String(), bold
}

// docsManFlag is a flag a man page names in bold.
type docsManFlag struct {
	line  int
	name  string
	scope string // the command whose entry or section it stands in; "" for none
}

// docsManSubs is a `cau eval <validate|run|...>` list of alternatives.
type docsManSubs struct {
	line int
	cmd  string
	alts []string
}

type docsManPage struct {
	entries  []docsExample // `.B cau <command> ...` synopsis entries
	examples []docsExample // command lines in .nf/.EX blocks, and bold `cau ...` runs
	flags    []docsManFlag
	subs     []docsManSubs
	unclosed []int // lines whose synopsis opens a < it never closes
	unscoped []int // OPTIONS flags with no command named in front of them
}

var docsManAlternatives = regexp.MustCompile(`<([a-z][a-z0-9-]*(?:\|[a-z][a-z0-9-]*)*)`)

// docsParseMan reads a man page for one binary. Scoping follows the page:
// a bold flag in a COMMANDS entry belongs to that entry's command, one in
// OPTIONS to the command the section's opening sentence names in bold, and
// one anywhere else to no command in particular.
func docsParseMan(file, content, binary string) *docsManPage {
	page := &docsManPage{}
	section, entryCmd, optionsCmd := "", "", ""
	inBlock, afterTP := false, false
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		ln := i + 1
		if inBlock {
			if strings.HasPrefix(line, ".fi") || strings.HasPrefix(line, ".EE") {
				inBlock = false
				continue
			}
			plain, _ := docsRoffRuns(line)
			if text, ok := docsCommand(plain, binary); ok {
				if ex, ok := docsNewExample(file, ln, text); ok {
					page.examples = append(page.examples, ex)
				}
			}
			continue
		}
		if strings.HasPrefix(line, ".") {
			request, rest, _ := strings.Cut(line[1:], " ")
			switch request {
			case "SH":
				section, entryCmd, optionsCmd, afterTP = strings.Trim(strings.TrimSpace(rest), `"`), "", "", false
				continue
			case "nf", "EX":
				inBlock = true
				continue
			case "TP":
				afterTP = true
				if section == "COMMANDS" {
					entryCmd = ""
				}
				continue
			}
		}
		inline, ok := docsRoffInline(line)
		if !ok {
			continue
		}
		tag := afterTP
		afterTP = false
		plain, bold := docsRoffRuns(inline)
		if strings.HasPrefix(line, ".") && binary == "cau" {
			if text, ok := docsCommand(plain, "cau"); ok {
				ex, ok := docsNewExample(file, ln, text)
				if !ok {
					continue
				}
				page.entries = append(page.entries, ex)
				cmd := ex.toks[0].text
				if tag && section == "COMMANDS" {
					entryCmd = cmd
				}
				if m := docsManAlternatives.FindStringSubmatch(text); m != nil {
					page.subs = append(page.subs, docsManSubs{line: ln, cmd: cmd, alts: strings.Split(m[1], "|")})
				}
				if strings.Count(text, "<") != strings.Count(text, ">") {
					page.unclosed = append(page.unclosed, ln)
				}
				continue
			}
		}
		for _, run := range bold {
			if text, ok := docsCommand(run, "cau"); ok && binary == "cau" {
				ex, ok := docsNewExample(file, ln, text)
				if !ok {
					continue
				}
				if section == "OPTIONS" && optionsCmd == "" {
					optionsCmd = ex.toks[0].text
				}
				page.examples = append(page.examples, ex)
				continue
			}
			word, _, _ := strings.Cut(run, " ")
			name, ok := docsFlagName(strings.TrimRight(word, ",.;:)"))
			if !ok {
				continue
			}
			scope := ""
			switch section {
			case "COMMANDS":
				scope = entryCmd
			case "OPTIONS":
				if scope = optionsCmd; scope == "" && binary == "cau" {
					page.unscoped = append(page.unscoped, ln)
				}
			}
			page.flags = append(page.flags, docsManFlag{line: ln, name: name, scope: scope})
		}
	}
	return page
}

const (
	// docs/cau.1 held 31 synopsis entries, 8 subcommand lists, 37 bold flags
	// and 5 command lines when these were chosen.
	docsMinManEntries  = 22
	docsMinManSubLists = 6
	docsMinManFlags    = 22
	docsMinManExamples = 2
)

// TestDocsManPageUsesRealFlags holds docs/cau.1 against the CLI: every
// synopsis entry names a real command and real subcommands, every flag set in
// bold is defined on the command it is written under, and the command lines
// in the example blocks pass the same check as the Markdown ones.
func TestDocsManPageUsesRealFlags(t *testing.T) {
	const file = "docs/cau.1"
	cli := newDocsCLI(t)
	universe := docsUniverse(t, cli)
	commands := docsCommandSet(t)
	page := docsParseMan(file, docsRead(t, file), "cau")

	undefined := func(line int, cmd, name string, flags map[string]bool) {
		t.Errorf("%s:%d: cau %s: flag --%s is not defined%s", file, line, cmd, name, docsDidYouMean("--", name, docsSortedKeys(flags)))
	}
	entered := map[string]bool{}
	for _, ex := range page.entries {
		cmd := ex.toks[0].text
		if !commands[cmd] {
			t.Errorf("%s:%d: cau %s: command does not exist%s", file, ex.line, cmd, docsDidYouMean("cau ", cmd, docsSortedKeys(commands)))
			continue
		}
		entered[cmd] = true
		flags, _ := docsCommandFlags(universe, cmd)
		for _, fl := range docsFlags(ex.toks[1:]) {
			if !flags[fl.name] {
				undefined(fl.line, cmd, fl.name, flags)
			}
		}
	}
	lists := 0
	for _, list := range page.subs {
		real := cli.subcommands(list.cmd)
		if !commands[list.cmd] || len(real) == 0 {
			continue // <path ...>, <shell>: a placeholder, not a list of subcommands
		}
		lists++
		for _, alt := range list.alts {
			if !slices.Contains(real, alt) {
				t.Errorf("%s:%d: cau %s: subcommand %q does not exist", file, list.line, list.cmd, alt)
			}
		}
		var omitted []string
		for _, sub := range real {
			if sub != "help" && !slices.Contains(list.alts, sub) {
				omitted = append(omitted, sub)
			}
		}
		if len(omitted) > 0 {
			t.Logf("%s:%d: the synopsis of cau %s omits the subcommand(s) %q", file, list.line, list.cmd, omitted)
		}
	}
	for _, fl := range page.flags {
		if fl.scope != "" {
			if flags, _ := docsCommandFlags(universe, fl.scope); !flags[fl.name] {
				undefined(fl.line, fl.scope, fl.name, flags)
			}
			continue
		}
		anywhere := slices.ContainsFunc(docsSortedKeys(universe), func(key string) bool { return universe[key].flags[fl.name] != "" })
		if !anywhere {
			t.Errorf("%s:%d: flag --%s is not defined by any cau command", file, fl.line, fl.name)
		}
	}
	for _, ln := range page.unscoped {
		t.Errorf("%s:%d: a flag under OPTIONS, but the section does not say in bold which command its options belong to", file, ln)
	}
	rep := docsCheck(t, page.examples)
	for _, v := range rep.violations {
		t.Error(v)
	}

	for _, ln := range page.unclosed {
		t.Logf("%s:%d: the synopsis opens a < that it never closes", file, ln)
	}
	var missing []string
	for _, cmd := range docsSortedKeys(commands) {
		if !entered[cmd] && cmd != "help" {
			missing = append(missing, cmd)
		}
	}
	if len(missing) > 0 {
		t.Logf("%s has no synopsis entry for the command(s) %q", file, missing)
	}
	t.Logf("checked %d synopsis entries, %d subcommand lists, %d bold flags and %d command lines (%d flag uses)",
		len(page.entries), lists, len(page.flags), rep.examples, rep.flags)
	if len(page.entries) < docsMinManEntries || lists < docsMinManSubLists || len(page.flags) < docsMinManFlags || rep.examples < docsMinManExamples {
		t.Errorf("found %d synopsis entries, %d subcommand lists, %d bold flags and %d command lines; want at least %d, %d, %d and %d: the roff reader is broken or the page lost its content",
			len(page.entries), lists, len(page.flags), rep.examples, docsMinManEntries, docsMinManSubLists, docsMinManFlags, docsMinManExamples)
	}
}

const (
	// docs/cau-mcp.1 held 25 bold flags and 1 command line, the Markdown 2
	// cau-mcp command lines, when these were chosen.
	docsMinMCPManFlags = 18
	docsMinMCPExamples = 2
)

// TestDocsMCPDocsUseRealFlags checks what is written about cau-mcp against
// the flags its source defines. cau-mcp is another binary (cmd/cau-mcp), so
// its flag set is read from the source only: nothing here runs it, and its
// own --help text is not checked.
func TestDocsMCPDocsUseRealFlags(t *testing.T) {
	src := docsParseSource(filepath.Join("cmd", "cau-mcp"))
	if len(src.errs) > 0 || len(src.sets) != 1 {
		t.Fatalf("want exactly one flag set in cmd/cau-mcp, read %d (errors: %q)", len(src.sets), src.errs)
	}
	defined := src.sets[0].flags
	check := func(file string, line int, name string) {
		if defined[name] == "" && name != "h" && name != "help" {
			t.Errorf("%s:%d: cau-mcp: flag --%s is not defined%s", file, line, name, docsDidYouMean("--", name, docsSortedKeys(defined)))
		}
	}

	const man = "docs/cau-mcp.1"
	page := docsParseMan(man, docsRead(t, man), "cau-mcp")
	named := map[string]bool{}
	for _, fl := range page.flags {
		named[fl.name] = true
		check(man, fl.line, fl.name)
	}
	examples := page.examples
	for _, file := range docsFiles(t) {
		examples = append(examples, docsExtractBinary(filepath.ToSlash(file), docsRead(t, file), "cau-mcp")...)
	}
	uses := 0
	for _, ex := range examples {
		for _, fl := range docsFlags(ex.toks) {
			uses++
			check(ex.file, fl.line, fl.name)
		}
	}
	var omitted []string
	for _, name := range docsSortedKeys(defined) {
		if !named[name] {
			omitted = append(omitted, "--"+name)
		}
	}
	if len(omitted) > 0 {
		t.Logf("%s does not name these flags that cau-mcp defines: %q", man, omitted)
	}
	t.Logf("checked %d bold flags in the man page and %d command lines (%d flag uses) against the %d flags cmd/cau-mcp defines",
		len(page.flags), len(examples), uses, len(defined))
	if len(page.flags) < docsMinMCPManFlags || len(examples) < docsMinMCPExamples {
		t.Errorf("found %d bold flags and %d command lines; want at least %d and %d", len(page.flags), len(examples), docsMinMCPManFlags, docsMinMCPExamples)
	}
}

// ── shell completions ───────────────────────────────────────────────────────

// docsCompBlock is one table of a completion script: the commands it is
// offered for and the words offered.
type docsCompBlock struct {
	line  int
	cmds  []string
	words []string
}

var (
	docsBashFlags = regexp.MustCompile(`(?m)^[ \t]*([a-z][a-z0-9|-]*)\)[ \t]*\n[ \t]*flags="([^"]*)"`)
	docsBashSubs  = regexp.MustCompile(`(?m)^[ \t]*([a-z][a-z0-9-]*)\)[ \t]+sub="([^"]*)"`)
	docsBashTop   = regexp.MustCompile(`(?m)^[ \t]*top="([^"]*)"`)
	docsZshSubs   = regexp.MustCompile(`(?m)^[ \t]*([a-z][a-z0-9-]*)\)[ \t]*\n[ \t]*sub=\(([^)]*)\)`)
	docsZshTop    = regexp.MustCompile(`(?m)^[ \t]*top=\(([^)]*)\)`)
	docsFishTop   = regexp.MustCompile(`(?m)^complete -c cau -n __fish_use_subcommand -a (\S+)`)
	docsFishSeen  = regexp.MustCompile(`(?m)^complete -c cau -n '__fish_seen_subcommand_from ([^']+)'(.*)$`)
	docsFishLong  = regexp.MustCompile(` -l ([a-z0-9][a-z0-9-]*)`)
	docsFishArgs  = regexp.MustCompile(` -a '([^']*)'`)
)

// docsCompBlocks reads the tables a pattern matches: group 1 names the
// commands (separated by sep), group 2 lists the words.
func docsCompBlocks(content string, re *regexp.Regexp, sep string) []docsCompBlock {
	var out []docsCompBlock
	for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
		cmds := strings.FieldsFunc(content[m[2]:m[3]], func(r rune) bool { return strings.ContainsRune(sep, r) })
		out = append(out, docsCompBlock{line: docsLineAt(content, m[2]), cmds: cmds, words: strings.Fields(content[m[4]:m[5]])})
	}
	return out
}

// docsFishBlocks reads fish's per-command lines: the flags (-l name) and the
// subcommand lists (-a '...') offered once a command has been typed.
func docsFishBlocks(content string) (flags, subs []docsCompBlock) {
	for _, m := range docsFishSeen.FindAllStringSubmatchIndex(content, -1) {
		block := docsCompBlock{line: docsLineAt(content, m[0]), cmds: strings.Fields(content[m[2]:m[3]])}
		rest := content[m[4]:m[5]]
		if long := docsFishLong.FindStringSubmatch(rest); long != nil {
			block.words = []string{long[1]}
			flags = append(flags, block)
		} else if args := docsFishArgs.FindStringSubmatch(rest); args != nil {
			block.words = strings.Fields(args[1])
			subs = append(subs, block)
		}
	}
	return flags, subs
}

const (
	// bash: 30 command labels and 314 flag offers; fish: 24 flag offers; and
	// 7, 8 and 8 subcommand lists in bash, zsh and fish, when chosen.
	docsMinBashLabels = 20
	docsMinBashFlags  = 200
	docsMinFishFlags  = 10
	docsMinCompSubs   = 5
)

// TestDocsCompletionsUseRealFlags: a completion script must not offer a
// command, a subcommand or a flag the CLI would reject. What the CLI has and
// a script does not offer is logged, not failed: a completion may be partial,
// it may not be wrong. zsh completes commands and subcommands only.
func TestDocsCompletionsUseRealFlags(t *testing.T) {
	cli := newDocsCLI(t)
	universe := docsUniverse(t, cli)
	commands := docsCommandSet(t)

	checkTop := func(file string, words []string) {
		for _, w := range words {
			if !commands[w] {
				t.Errorf("%s: offers the command %q, which does not exist", file, w)
			}
		}
	}
	// checkFlags returns the commands the script has flags for and how many
	// flag offers it checked.
	checkFlags := func(file string, blocks []docsCompBlock) (map[string]map[string]bool, int) {
		offered, n := map[string]map[string]bool{}, 0
		for _, b := range blocks {
			for _, cmd := range b.cmds {
				if !commands[cmd] {
					t.Errorf("%s:%d: offers flags for the command %q, which does not exist", file, b.line, cmd)
					continue
				}
				if offered[cmd] == nil {
					offered[cmd] = map[string]bool{}
				}
				flags, _ := docsCommandFlags(universe, cmd)
				for _, w := range b.words {
					n++
					name := strings.TrimLeft(w, "-")
					offered[cmd][name] = true
					if !flags[name] && name != "h" && name != "help" {
						t.Errorf("%s:%d: cau %s: the completion offers --%s, which no `cau %s` flag set defines%s",
							file, b.line, cmd, name, cmd, docsDidYouMean("--", name, docsSortedKeys(flags)))
					}
				}
			}
		}
		return offered, n
	}
	logOmittedFlags := func(file string, offered map[string]map[string]bool, all bool) {
		var silent []string
		for _, cmd := range docsSortedKeys(commands) {
			flags, _ := docsCommandFlags(universe, cmd)
			if offered[cmd] == nil {
				if len(flags) > 0 {
					silent = append(silent, cmd)
				}
				continue
			}
			var omitted []string
			for _, name := range docsSortedKeys(flags) {
				if !offered[cmd][name] {
					omitted = append(omitted, "--"+name)
				}
			}
			if len(omitted) > 0 {
				t.Logf("%s omits %d flag(s) that cau %s defines: %s", file, len(omitted), cmd, strings.Join(omitted, " "))
			}
		}
		if len(silent) > 0 && all {
			t.Logf("%s offers no flags at all for: %s", file, strings.Join(silent, " "))
		} else if len(silent) > 0 {
			t.Logf("%s offers no flags at all for %d commands that define some", file, len(silent))
		}
	}
	checkSubs := func(file string, blocks []docsCompBlock) int {
		listed, n := map[string]bool{}, 0
		for _, b := range blocks {
			for _, cmd := range b.cmds {
				real := cli.subcommands(cmd)
				if len(real) == 0 {
					continue // completion <shell>, help <command>: not subcommands
				}
				n++
				listed[cmd] = true
				for _, w := range b.words {
					if !slices.Contains(real, w) {
						t.Errorf("%s:%d: cau %s: the completion offers the subcommand %q, which does not exist", file, b.line, cmd, w)
					}
				}
				var omitted []string
				for _, sub := range real {
					if !slices.Contains(b.words, sub) {
						omitted = append(omitted, sub)
					}
				}
				if len(omitted) > 0 {
					t.Logf("%s:%d: omits the cau %s subcommand(s) %q", file, b.line, cmd, omitted)
				}
			}
		}
		for _, cmd := range docsSortedKeys(commands) {
			if real := cli.subcommands(cmd); len(real) > 0 && !listed[cmd] {
				t.Logf("%s: offers no subcommands for cau %s, which has %q", file, cmd, real)
			}
		}
		return n
	}

	const bashFile, zshFile, fishFile = "completions/cau.bash", "completions/cau.zsh", "completions/cau.fish"
	bash, zsh, fish := docsRead(t, bashFile), docsRead(t, zshFile), docsRead(t, fishFile)

	for _, m := range docsBashTop.FindAllStringSubmatch(bash, -1) {
		checkTop(bashFile, strings.Fields(m[1]))
	}
	bashBlocks := docsCompBlocks(bash, docsBashFlags, "|")
	bashOffered, bashFlags := checkFlags(bashFile, bashBlocks)
	logOmittedFlags(bashFile, bashOffered, true)
	bashSubs := checkSubs(bashFile, docsCompBlocks(bash, docsBashSubs, "|"))

	for _, m := range docsZshTop.FindAllStringSubmatch(zsh, -1) {
		checkTop(zshFile, strings.Fields(m[1]))
	}
	zshSubs := checkSubs(zshFile, docsCompBlocks(zsh, docsZshSubs, "|"))

	for _, m := range docsFishTop.FindAllStringSubmatch(fish, -1) {
		checkTop(fishFile, []string{m[1]})
	}
	fishFlagBlocks, fishSubBlocks := docsFishBlocks(fish)
	fishOffered, fishFlags := checkFlags(fishFile, fishFlagBlocks)
	logOmittedFlags(fishFile, fishOffered, false)
	fishSubs := checkSubs(fishFile, fishSubBlocks)

	labels := 0
	for _, b := range bashBlocks {
		labels += len(b.cmds)
	}
	t.Logf("bash: %d command labels, %d flag offers, %d subcommand lists; zsh: %d subcommand lists and no flags; fish: %d flag offers, %d subcommand lists",
		labels, bashFlags, bashSubs, zshSubs, fishFlags, fishSubs)
	if labels < docsMinBashLabels || bashFlags < docsMinBashFlags || fishFlags < docsMinFishFlags ||
		bashSubs < docsMinCompSubs || zshSubs < docsMinCompSubs || fishSubs < docsMinCompSubs {
		t.Errorf("the completion readers found too little (floors: %d bash labels, %d bash flags, %d fish flags, %d subcommand lists per shell)",
			docsMinBashLabels, docsMinBashFlags, docsMinFishFlags, docsMinCompSubs)
	}
}

// ── documented outputs ──────────────────────────────────────────────────────

// docsBlock is one fenced code block and the last line of prose before it.
type docsBlock struct {
	line  int // of the opening fence
	intro string
	body  []string
}

func docsBlocks(content string) []docsBlock {
	var (
		out   []docsBlock
		cur   *docsBlock
		fence string
		last  string
	)
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		run := docsFenceRun(line)
		switch {
		case cur == nil && run != "" && !strings.Contains(trimmed[len(run):], run):
			cur, fence = &docsBlock{line: i + 1, intro: last}, run
		case cur == nil:
			if trimmed != "" {
				last = trimmed
			}
		case run != "" && run[0] == fence[0] && len(run) >= len(fence) && trimmed == run:
			out = append(out, *cur)
			cur = nil
		default:
			cur.body = append(cur.body, line)
		}
	}
	return out
}

// TestDocsDocumentedOutputs regenerates the documented outputs that are fully
// determined by the binary and compares them with what the page shows:
//
//   - the built-in regression policy in docs/evaluation.md (`cau eval policy`),
//     compared as JSON so layout is free;
//   - the command table that opens docs/cli.md, which presents itself as the
//     text of `cau help`: it must name every command `cau help` names.
//
// Scan reports, gate verdicts and the annotated JSON shapes are not
// regenerated here: they need a scan, or are not verbatim output.
func TestDocsDocumentedOutputs(t *testing.T) {
	t.Run("eval policy", func(t *testing.T) {
		const file = "docs/evaluation.md"
		code, stdout, stderr := runCLI(t, "eval", "policy")
		var want any
		if err := json.Unmarshal([]byte(stdout), &want); code != 0 || err != nil {
			t.Fatalf("cau eval policy: exit %d, %v\n%s", code, err, stderr)
		}
		found := 0
		for _, b := range docsBlocks(docsRead(t, file)) {
			if !strings.Contains(b.intro, "`cau eval policy`") {
				continue
			}
			found++
			var got any
			if err := json.Unmarshal([]byte(strings.Join(b.body, "\n")), &got); err != nil {
				t.Errorf("%s:%d: the block introduced as `cau eval policy` is not JSON: %v", file, b.line, err)
			} else if !reflect.DeepEqual(got, want) {
				t.Errorf("%s:%d: the documented policy is not what `cau eval policy` prints:\n%s", file, b.line, stdout)
			}
		}
		if found == 0 {
			t.Errorf("%s: no code block is introduced by a line naming `cau eval policy`; the documented policy moved or the test must follow it", file)
		}
	})

	t.Run("cau help", func(t *testing.T) {
		const file = "docs/cli.md"
		commands := docsCommandSet(t)
		found := 0
		for _, b := range docsBlocks(docsRead(t, file)) {
			listed := map[string]bool{}
			for _, line := range b.body {
				if text, ok := docsCommand(line, "cau"); ok {
					listed[strings.Fields(text)[0]] = true
				}
			}
			if !listed["help"] || len(listed) < 5 {
				continue // not the command table
			}
			found++
			var missing []string
			for _, cmd := range docsSortedKeys(commands) {
				if !listed[cmd] {
					missing = append(missing, cmd)
				}
			}
			if len(missing) > 0 {
				t.Errorf("%s:%d: the command table lists %d of the %d commands; `cau help` also has: %s",
					file, b.line, len(listed), len(commands), strings.Join(missing, " "))
			}
		}
		if found != 1 {
			t.Errorf("%s: found %d command tables (a block of `cau <command>` lines with a `cau help` line), want 1", file, found)
		}
	})
}

// ── the readers, held against inputs whose answers are known ────────────────

// TestDocsReaders checks the source, roff, completion and inline-span readers
// on synthetic inputs, so the checks built on them cannot pass by reading
// nothing.
func TestDocsReaders(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		dir := t.TempDir()
		source := `package main

import "flag"

const toolName = "tool"

type shared struct{ format string }

func (s *shared) bind(fs *flag.FlagSet) { fs.StringVar(&s.format, "format", "text", "") }

func common(fs *flag.FlagSet) *string { return fs.String("db", "", "") }

func cmdOne(args []string) int {
	fs := flag.NewFlagSet("one", flag.ContinueOnError)
	fs.Usage = func() { println("usage") }
	var s shared
	s.bind(fs)
	db := common(fs)
	quiet := fs.Bool("quiet", false, "say "+join("less"))
	var n int
	fs.IntVar(&n, "jobs", 0, "")
	if err := fs.Parse(args); err != nil {
		return 4
	}
	_, _ = db, quiet
	return 0
}

func cmdTwo(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "add", "remove":
			return twoSub(args[0], args[1:])
		}
	}
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 4
	}
	return 0
}

func twoSub(sub string, args []string) int {
	fs := flag.NewFlagSet("two "+sub, flag.ContinueOnError)
	fs.Duration("ttl", 0, "")
	if err := fs.Parse(args); err != nil {
		return 4
	}
	return 0
}

func cmdEager(args []string) int {
	fs := flag.NewFlagSet("eager", flag.ContinueOnError)
	out := fs.String("out", "", "")
	touch(*out)
	if err := fs.Parse(args); err != nil {
		return 4
	}
	return 0
}

func cmdLoose(args []string) int {
	fs := flag.NewFlagSet("loose", flag.ContinueOnError)
	fs.Bool("x", false, "")
	_ = fs.Parse(args)
	return 0
}

func join(s string) string { return s }
func touch(string)         {}
`
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "skipped_test.go"), []byte("package main\nfunc init() { flag.NewFlagSet(\"never\", 0) }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := docsParseSource(dir)
		if len(src.errs) > 0 {
			t.Fatalf("errors: %q", src.errs)
		}
		var got []string
		for _, set := range src.sets {
			got = append(got, fmt.Sprintf("%s dynamic=%v custom=%v fn=%s flags=%s",
				set.name, set.dynamic, set.custom, set.fn, strings.Join(docsSortedKeys(set.flags), ",")))
		}
		want := []string{
			"one dynamic=false custom=true fn=cmdOne flags=db,format,jobs,quiet",
			"tool dynamic=false custom=false fn=cmdTwo flags=",
			"two dynamic=true custom=false fn=twoSub flags=ttl",
			"eager dynamic=false custom=false fn=cmdEager flags=out",
			"loose dynamic=false custom=false fn=cmdLoose flags=x",
		}
		if !slices.Equal(got, want) {
			t.Errorf("flag sets\n got %q\nwant %q", got, want)
		}
		if !slices.Equal(src.words, []string{"add", "remove"}) {
			t.Errorf("candidate subcommands %q, want add and remove", src.words)
		}
		// cmdEager works before it parses; cmdLoose does not stop on a parse
		// error. Both would make --help unsafe to probe.
		if len(src.unsafe) != 2 || !strings.Contains(src.unsafe[0], "cmdEager calls something other than a flag definition") ||
			!strings.Contains(src.unsafe[1], "cmdLoose does something other than define flags") {
			t.Errorf("unsafe = %q, want cmdEager and cmdLoose", src.unsafe)
		}
		if set := src.sets[0]; !strings.HasSuffix(set.flags["quiet"], "main.go:19") || !strings.HasSuffix(set.flags["format"], "main.go:9") {
			t.Errorf("definition sites: quiet at %s, format at %s", set.flags["quiet"], set.flags["format"])
		}
	})

	t.Run("roff", func(t *testing.T) {
		render := func(line string) string {
			inline, ok := docsRoffInline(line)
			if !ok {
				return "(request)"
			}
			plain, bold := docsRoffRuns(inline)
			return plain + " | " + strings.Join(bold, " ; ")
		}
		cases := map[string]string{
			`.B cau intake \fB\-\-format \fP<\fPfmt\fP>\fP \fR[\fPflags\fR]`:  "cau intake --format <fmt> [flags] | cau intake --format <fmt> ; flags",
			`.BR \-file " " \fIfile\fR`:                                       "-file file | -file",
			`.BR \-pretty\fR, \fB\-quiet\fR`:                                  "-pretty,-quiet | -pretty ; -quiet",
			`.B \-no\-yara\fR, \fB\-no\-heur\fR`:                              "-no-yara, -no-heur | -no-yara ; -no-heur",
			`.BR \-fail\-on " " "\fBclean\fP|\fBnone\fR`:                      "-fail-on clean|none | -fail-on ; clean|none",
			`peers; \fB\-\-respond block\fR drops (\fB\-\-block\-ttl\fR, 1h)`: "peers; --respond block drops (--block-ttl, 1h) | --respond block ; --block-ttl",
			`called \(em web shells, \fBsyslog\-ecs\fR`:                       "called — web shells, syslog-ecs | syslog-ecs",
			`.RB ( CAU_RULES ,`:                                               "(CAU_RULES, | CAU_RULES",
			`.TP`:                                                             "(request)",
		}
		for line, want := range cases {
			if got := render(line); got != want {
				t.Errorf("roff %q\n got %s\nwant %s", line, got, want)
			}
		}

		page := docsParseMan("x.1", strings.Join([]string{
			/* 1 */ `.TH X 1`,
			/* 2 */ `.SH SYNOPSIS`,
			/* 3 */ `.B cau`,
			/* 4 */ `.I command`,
			/* 5 */ `.B cau version`,
			/* 6 */ `.SH COMMANDS`,
			/* 7 */ `.TP`,
			/* 8 */ `.B cau eval \fR<\fBvalidate\fP|\fBrun\fP\fR>`,
			/* 9 */ `Gate a run; \fB\-\-baseline\fR names the reference.`,
			/* 10 */ `.TP`,
			/* 11 */ `.B cau rules \fR<\fBlint\fP|\fBlist\fR\fP\fR`,
			/* 12 */ `.TP`,
			/* 13 */ `.B cau update \fB\-\-from\fP|\fB\-\-url\fP \fR[\fPflags\fR]`,
			/* 14 */ `Install it; \fBclear\fR is not a flag.`,
			/* 15 */ `.SH OPTIONS`,
			/* 16 */ `The options of \fBcau scan\fP:`,
			/* 17 */ `.TP`,
			/* 18 */ `.BR \-dir " " \fIdirectory\fR`,
			/* 19 */ `Recursive. \fBcau scan \-h\fR lists the rest.`,
			/* 20 */ `.SH "EXIT STATUS"`,
			/* 21 */ `Nothing at or above \fB\-\-fail\-on\fR.`,
			/* 22 */ `.SH EXAMPLES`,
			/* 23 */ `.nf`,
			/* 24 */ `cau scan \-\-file x.exe`,
			/* 25 */ `sudo systemctl enable --now cau-scan.timer`,
			/* 26 */ `.fi`,
		}, "\n"), "cau")
		var got []string
		for _, ex := range page.entries {
			var names []string
			for _, fl := range docsFlags(ex.toks[1:]) {
				names = append(names, fl.name)
			}
			got = append(got, fmt.Sprintf("entry %d %s %v", ex.line, ex.toks[0].text, names))
		}
		for _, list := range page.subs {
			got = append(got, fmt.Sprintf("subs %d %s %v", list.line, list.cmd, list.alts))
		}
		for _, fl := range page.flags {
			got = append(got, fmt.Sprintf("flag %d --%s scope=%q", fl.line, fl.name, fl.scope))
		}
		for _, ex := range page.examples {
			var names []string
			for _, fl := range docsFlags(ex.toks[1:]) {
				names = append(names, fl.name)
			}
			got = append(got, fmt.Sprintf("example %d %s %v", ex.line, ex.toks[0].text, names))
		}
		got = append(got, fmt.Sprintf("unclosed %v unscoped %v", page.unclosed, page.unscoped))
		want := []string{
			"entry 5 version []",
			"entry 8 eval []",
			"entry 11 rules []",
			"entry 13 update [from url]",
			"subs 8 eval [validate run]",
			"subs 11 rules [lint list]",
			`flag 9 --baseline scope="eval"`,
			`flag 18 --dir scope="scan"`,
			`flag 21 --fail-on scope=""`,
			"example 16 scan []",
			"example 19 scan [h]",
			"example 24 scan [file]",
			"unclosed [11] unscoped []",
		}
		if !slices.Equal(got, want) {
			t.Errorf("man page\n got %q\nwant %q", got, want)
		}
	})

	t.Run("completions", func(t *testing.T) {
		show := func(blocks []docsCompBlock) string {
			var out []string
			for _, b := range blocks {
				out = append(out, fmt.Sprintf("%d %v %v", b.line, b.cmds, b.words))
			}
			return strings.Join(out, " / ")
		}
		bash := strings.Join([]string{
			/* 1 */ `    top="scan hash`,
			/* 2 */ `eval"`,
			/* 3 */ `                case "${COMP_WORDS[1]}" in`,
			/* 4 */ `                    scan)`,
			/* 5 */ `                        flags="-dir -file`,
			/* 6 */ `-quiet"`,
			/* 7 */ `                        ;;`,
			/* 8 */ `                    hash|cluster)`,
			/* 9 */ `                        flags="-format"`,
			/* 10 */ `                        ;;`,
			/* 11 */ `                    version|help)`,
			/* 12 */ `                        flags=""`,
			/* 13 */ `            eval)        sub="validate run help" ;;`,
		}, "\n")
		if got, want := show(docsCompBlocks(bash, docsBashFlags, "|")), "4 [scan] [-dir -file -quiet] / 8 [hash cluster] [-format] / 11 [version help] []"; got != want {
			t.Errorf("bash flags\n got %s\nwant %s", got, want)
		}
		if got, want := show(docsCompBlocks(bash, docsBashSubs, "|")), "13 [eval] [validate run help]"; got != want {
			t.Errorf("bash subcommands\n got %s\nwant %s", got, want)
		}
		if m := docsBashTop.FindStringSubmatch(bash); m == nil || !slices.Equal(strings.Fields(m[1]), []string{"scan", "hash", "eval"}) {
			t.Errorf("bash top = %q", m)
		}

		zsh := "    top=(\n        scan hash\n        eval\n    )\n            case ${words[2]} in\n                eval)\n                    sub=(validate run help)\n                    ;;\n"
		if got, want := show(docsCompBlocks(zsh, docsZshSubs, "|")), "6 [eval] [validate run help]"; got != want {
			t.Errorf("zsh subcommands\n got %s\nwant %s", got, want)
		}
		if m := docsZshTop.FindStringSubmatch(zsh); m == nil || !slices.Equal(strings.Fields(m[1]), []string{"scan", "hash", "eval"}) {
			t.Errorf("zsh top = %q", m)
		}

		fish := strings.Join([]string{
			/* 1 */ `complete -c cau -f`,
			/* 2 */ `complete -c cau -n __fish_use_subcommand -a scan -d 'scan files'`,
			/* 3 */ `complete -c cau -n '__fish_seen_subcommand_from eval' -a 'validate run help'`,
			/* 4 */ `complete -c cau -n '__fish_seen_subcommand_from scan hash' -l format -d 'output format' -r -f -a 'text json'`,
			/* 5 */ `complete -c cau -f -l help -d 'print help'`,
		}, "\n")
		flags, subs := docsFishBlocks(fish)
		if got, want := show(flags), "4 [scan hash] [format]"; got != want {
			t.Errorf("fish flags\n got %s\nwant %s", got, want)
		}
		if got, want := show(subs), "3 [eval] [validate run help]"; got != want {
			t.Errorf("fish subcommands\n got %s\nwant %s", got, want)
		}
		if m := docsFishTop.FindAllStringSubmatch(fish, -1); len(m) != 1 || m[0][1] != "scan" {
			t.Errorf("fish top = %q", m)
		}
	})

	t.Run("spans and blocks", func(t *testing.T) {
		const fence = "```"
		md := strings.Join([]string{
			/* 1 */ "Run `cau scan --format ocsf` or `cau net clear`; `cau-kernel` and `./cau.sarif` are not commands.",
			/* 2 */ "| `--format text\\|json` | `cau eval run --out` |",
			/* 3 */ "The policy (`cau eval policy`):",
			/* 4 */ "",
			/* 5 */ fence + "json",
			/* 6 */ "{}",
			/* 7 */ "`cau scan --inside-a-block`",
			/* 8 */ fence,
			/* 9 */ "``cau <command> --help`` and `$ sudo cau ps`",
		}, "\n")
		var got []string
		for _, ex := range docsExtractSpans("x.md", md) {
			var names []string
			for _, fl := range docsFlags(ex.toks[1:]) {
				names = append(names, fl.name)
			}
			got = append(got, fmt.Sprintf("%d %s %v", ex.line, ex.toks[0].text, names))
		}
		want := []string{"1 scan [format]", "1 net []", "2 eval [out]", "3 eval []", "9 <command> [help]", "9 ps []"}
		if !slices.Equal(got, want) {
			t.Errorf("spans\n got %q\nwant %q", got, want)
		}
		blocks := docsBlocks(md)
		if len(blocks) != 1 || blocks[0].line != 5 || blocks[0].intro != "The policy (`cau eval policy`):" || len(blocks[0].body) != 2 {
			t.Errorf("blocks = %+v", blocks)
		}
	})

	for text, want := range map[string]bool{
		"  --feed <path>   the feed": true, "  -feed string": true, "see --feed.": true,
		"--feed-reload <d>": false, "cau-feed": false, "--no-feed": false, "feed": false,
	} {
		if got := docsMentionsFlag(text, "feed"); got != want {
			t.Errorf("docsMentionsFlag(%q, feed) = %v, want %v", text, got, want)
		}
	}
}

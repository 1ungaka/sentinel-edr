#!/usr/bin/env python3
"""regex-audit.py — sweep the tree for known bug shapes with regexes.

Usage:
  regex-audit.py [--root DIR] [--family NAME] [--rule ID] [--tests]
                 [--summary] [--all] [--write-baseline] [--list] [--self-test]

Hits are candidates, not verdicts: a regex sees the shape of a bug, not whether
the code around it already handles the case, so every hit needs reading. Mark a
line that has been read and is fine with a trailing `audit:ok` comment, or record
everything currently reported with --write-baseline.

scripts/regex-audit.baseline holds the hits that have been read. A hit is matched
by rule, file and line text, so moving code does not resurrect it and editing the
line does. The exit status is 1 when a hit is not in the baseline, which makes the
sweep a gate; --all reports everything, baseline or not, and exits 0.

Families: errors (swallowed failures), memory (unbounded reads, retained or
leaked resources, integer wrap), logic (conditions that cannot do what they say),
badcode (things that work but should not stay), fs (races on attacker-reachable
paths), injection (attacker text reaching a shell, terminal or workflow).

A rule's `bad` sample must match and its `good` sample must not, which --self-test
checks, so a broken regex fails loudly instead of reporting a clean tree. It also
has three scopes, because the worst shapes do not fit on a line:

  line     one line at a time
  file     across lines, on the file with comments blanked
  raw      one line at a time, comments included
  func     per Go function: the function has `has` but not `lacks`
  loop     lines inside a for loop
"""
import argparse
import collections
import hashlib
import os
import re
import sys

SKIP_DIRS = {".git", "vendor", "corpus", "eval-out", "node_modules", "wiki", "signatures", "testdata"}
LANGS = {".go": "go", ".c": "c", ".h": "c", ".py": "py", ".sh": "sh", ".yml": "yaml", ".yaml": "yaml"}
SHELL_NAMES = {"postinst", "postrm", "preinst", "prerm", "PKGBUILD"}

Rule = collections.namedtuple("Rule", "id family lang scope pattern why bad good lacks")


def rule(id, family, lang, pattern, why, bad, good="", scope="line", lacks=None):
    return Rule(id, family, lang, scope, pattern, why, bad, good, lacks)


RULES = [
    # ── errors: a failure that disappears ─────────────────────────────────────
    rule("go-err-empty", "errors", "go", r"if\s+[^\n{]*err\s*!=\s*nil\s*\{\s*\}",
         "an error branch with nothing in it", "if err != nil {\n}\n", "if err != nil {\n\treturn err\n}\n", "file"),
    rule("go-err-continue", "errors", "go", r"if\s+[^\n{]*err\s*!=\s*nil\s*\{\s*continue\s*\}",
         "a failed item is skipped with no record of it", "if err != nil {\n\tcontinue\n}\n",
         "if err != nil {\n\tcontinue // logged\n\tx()\n}\n", "file"),
    rule("go-err-return-nil", "errors", "go", r"if\s+[^\n{]*err\s*!=\s*nil\s*\{\s*return\s+(nil|false|\"\"|0)\s*\}",
         "an error turns into a zero value the caller cannot tell from success",
         "if err != nil {\n\treturn nil\n}\n", "if err != nil {\n\treturn err\n}\n", "file"),
    rule("go-err-discard", "errors", "go",
         r"^\s*(\w+,\s*)?_\s*(,\s*_)?\s*:?=\s*(os|io|json|strconv|filepath|fmt|binary|hex|base64|exec)\.\w+\(",
         "an error from a call that can really fail is thrown away",
         "\tv, _ := strconv.Atoi(s)", "\tv, err := strconv.Atoi(s)"),
    rule("go-err-verb", "errors", "go", r"fmt\.Errorf\(\"(?![^\"]*%w)[^\"]*%[vs][^\"]*\"[^\n]*,\s*\w*[eE]rr\w*\)",
         "the chain is cut: errors.Is and errors.As cannot see through %v",
         'fmt.Errorf("read: %v", err)', 'fmt.Errorf("read: %w", err)'),
    rule("go-err-compare", "errors", "go", r"\b\w*err\w*\s*[!=]=\s*(io\.E\w+|[a-z]+\.Err\w+|Err[A-Z]\w+|err[A-Z]\w+)\b",
         "== misses a wrapped error; use errors.Is", "if err == io.EOF {", "if errors.Is(err, io.EOF) {"),
    rule("go-err-string", "errors", "go", r"\.Error\(\)\s*[!=]=|strings\.\w+\(\w*[eE]rr\w*\.Error\(\)",
         "branching on an error's text breaks when the text changes",
         'if err.Error() == "x" {', 'return err.Error()'),
    rule("go-recover-drop", "errors", "go", r"(^\s*|_\s*=\s*)recover\(\)\s*$",
         "a panic is caught and dropped", "\t_ = recover()", "\tif r := recover(); r != nil {"),
    rule("go-close-write", "errors", "go",
         r"(os\.Create\(|O_WRONLY|O_RDWR)[^\n]*\n(?:[^\n]*\n){0,8}?\s*defer\s+\w+\.Close\(\)",
         "deferring Close on a file being written loses the write error",
         'f, _ := os.Create(p)\nif err != nil {\n}\ndefer f.Close()\n', 'f, _ := os.Open(p)\ndefer f.Close()\n', "file"),
    rule("go-scanner-err", "errors", "go", r"bufio\.NewScanner\(",
         "the read error is never checked, so a failure reads as end of input",
         "func f() {\n\ts := bufio.NewScanner(r)\n}\n", "func f() {\n\ts := bufio.NewScanner(r)\n\ts.Err()\n}\n",
         "func", r"\.Err\(\)"),
    rule("go-scanner-limit", "errors", "go", r"bufio\.NewScanner\(",
         "a line over 64 KiB stops the scan; without .Buffer that is reachable by input",
         "func f() {\n\ts := bufio.NewScanner(r)\n}\n", "func f() {\n\ts := bufio.NewScanner(r)\n\ts.Buffer(b, n)\n}\n",
         "func", r"\.Buffer\("),
    rule("go-walk-ignored", "errors", "go", r"^\s*(_\s*=\s*)?filepath\.Walk(Dir)?\(",
         "the walk's error is dropped, so a failed walk reads as an empty tree",
         "\tfilepath.Walk(p, f)", "\terr := filepath.Walk(p, f)"),
    rule("go-exit-lib", "errors", "go", r"\b(os\.Exit|log\.Fatal\w*)\(",
         "a library ends the process instead of returning the error", "\tos.Exit(1)", "\treturn err"),

    # ── memory: what is held, leaked, or sized by input ───────────────────────
    rule("go-readall", "memory", "go", r"\bio(util)?\.ReadAll\((?!io\.LimitReader|http\.MaxBytesReader)",
         "reads until the source stops, however much that is", "io.ReadAll(r)", "io.ReadAll(io.LimitReader(r, n))"),
    rule("go-readfile", "memory", "go", r"\bos\.ReadFile\(",
         "no size limit, and it blocks on a FIFO; internal/safefs is the bounded form", "os.ReadFile(p)", "safefs.ReadFile(p, n)"),
    rule("go-make-sized", "memory", "go",
         r"\bmake\(\[\][\w.]+,\s*(?!len\(|cap\(|\d|0x)[\w.]*(n|size|count|num|length|total|Len|Size|Count)\b",
         "an allocation sized by a variable: is it bounded before this line?",
         "make([]byte, size)", "make([]byte, len(b))"),
    rule("go-open-close", "memory", "go", r"\bos\.(Open|Create|OpenFile)\(",
         "opened and never closed in this function", "func f() {\n\tf, _ := os.Open(p)\n}\n",
         "func f() {\n\tf, _ := os.Open(p)\n\tdefer f.Close()\n}\n", "func", r"\.Close\(\)|return\s+\w*f\b|return\s+f,"),
    rule("go-body-close", "memory", "go", r"\.(Do|Get|Post)\(.*\breq\b|http\.(Get|Post)\(",
         "a response body that is never closed leaks the connection",
         "func f() {\n\tr, _ := http.Get(u)\n}\n", "func f() {\n\tr, _ := http.Get(u)\n\tr.Body.Close()\n}\n", "func", r"Body\.Close\(\)"),
    rule("go-ticker", "memory", "go", r"time\.NewTicker\(",
         "a ticker that is never stopped runs forever", "func f() {\n\tt := time.NewTicker(d)\n}\n",
         "func f() {\n\tt := time.NewTicker(d)\n\tt.Stop()\n}\n", "func", r"\.Stop\(\)"),
    rule("go-time-tick", "memory", "go", r"\btime\.Tick\(", "cannot be stopped, so it leaks", "time.Tick(d)", "time.NewTicker(d)"),
    rule("go-cancel", "memory", "go", r"context\.With(Timeout|Cancel|Deadline)\(",
         "the cancel function is dropped, which leaks the context's timer",
         "func f() {\n\tc, _ := context.WithCancel(x)\n}\n", "func f() {\n\tc, cancel := context.WithCancel(x)\n\tdefer cancel()\n}\n",
         "func", r"\bcancel\b|\bstop\b"),
    rule("go-wrap-add", "memory", "go", r"\b[\w.]+\s*\+\s*[\w.()]+\s*(>|>=|<=)\s*uint64\(",
         "a uint64 sum as a bound can wrap back inside the buffer; subtract instead",
         "if off+size > uint64(len(b)) {", "if size > uint64(len(b))-off {"),
    rule("go-wrap-int", "memory", "go", r"\bint\(\s*\w*\.?\w*\.?Uint(32|64)\(",
         "a wire value as int: negative on 32-bit, and wraps in arithmetic", "n := int(r.Uint32(b))", "n := r.Uint32(b)"),
    rule("go-int-compare", "memory", "go", r"\bint\([\w.]+\)\s*(>=|<|>|<=)\s*(len\(|ss\b)",
         "int() of an unsigned value can go negative and pass this check",
         "if int(n) >= len(b) {", "if uint64(n) >= uint64(len(b)) {"),
    rule("go-last-index", "memory", "go", r"\[len\([\w.]+\)\s*-\s*\d+\s*\]",
         "panics on an empty slice unless the length is checked first", "x[len(x)-1]", "x[0]"),
    rule("go-split-index", "memory", "go", r"strings\.(Split|SplitN|Fields)\([^)]*\)\[\d+\]",
         "panics when the separator is absent", 's := strings.Fields(x)[0]', "s := strings.Fields(x)"),
    rule("go-short-read", "memory", "go", r"\b\w+,\s*(_|err)\s*:?=\s*\w+\.Read\(\w+\)",
         "one Read may return less than the buffer; a seq_file returns a page", "n, _ := f.Read(buf)",
         "func f() {\n\tfor {\n\t\tn, err := r.Read(buf)\n\t}\n}\n", "noloop"),
    rule("go-unsafe", "memory", "go", r"\bunsafe\.(Pointer|Slice|String|StringData|Add)\(",
         "outside the type system: check the bounds by hand", "unsafe.Slice(p, n)", "x"),
    rule("go-retained-slice", "memory", "go", r"^\s*\w+\.\w+\s*=\s*\w+\[[^\]\n:]*:[^\]\n]*\]\s*$",
         "a sub-slice in a struct pins the whole buffer behind it", "\tm.body = data[4:n]", "\tbody := data[4:n]"),
    rule("go-loop-defer", "memory", "go", r"^\s*defer\b",
         "runs at function end, not each iteration, so resources pile up", "\tdefer f.Close()", "\tf.Close()", "loop"),
    rule("go-loop-after", "memory", "go", r"time\.After\(",
         "allocates a timer every iteration", "\tcase <-time.After(d):", "\tcase <-t.C:", "loop"),
    rule("go-regexp-call", "memory", "go", r"\bregexp\.(MustCompile|Compile)\(",
         "compiled on every call rather than once", 'func f() {\n\tre := regexp.MustCompile("x")\n}\n',
         'func f() func() *regexp.Regexp {\n\treturn sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile("x") })\n}\n',
         "func", r"sync\.Once"),

    # ── logic: conditions that cannot do what they say ────────────────────────
    rule("go-same-operands", "logic", "go",
         r"(?<![\w.\"])([A-Za-z_][\w.]*)\s*(==|!=|<=|>=)\s*\1(?![\w.(\[\"])",
         "both sides are the same expression", "if a.b == a.b {", "if a.b == a.c {"),
    rule("go-or-ne", "logic", "go", r"\b([\w.]+)\s*!=\s*[^\s|&()]+\s*\|\|\s*\1\s*!=",
         "always true: a value cannot equal both, so one side always holds", "if x != 1 || x != 2 {", "if x != 1 && x != 2 {"),
    rule("go-and-eq", "logic", "go", r"\b([\w.]+)\s*==\s*[^\s|&()]+\s*&&\s*\1\s*==",
         "always false: a value cannot equal two things", "if x == 1 && x == 2 {", "if x == 1 || x == 2 {"),
    rule("go-len-negative", "logic", "go", r"len\([^)]*\)\s*(<\s*0|>=\s*0)\b", "a length is never negative", "if len(x) < 0 {", "if len(x) == 0 {"),
    rule("go-unsigned-neg", "logic", "go", r"\buint\d*\([^)]*\)\s*(<\s*0|>=\s*0)\b", "an unsigned value is never negative", "if uint32(x) < 0 {", "if x < 0 {"),
    rule("go-index-gt-zero", "logic", "go", r"\.(Index|IndexByte|IndexAny|LastIndex|LastIndexByte)\([^)]*\)\s*>\s*0\b",
         "misses a match at position 0; found means >= 0", "if strings.Index(s, x) > 0 {", "if strings.Index(s, x) >= 0 {"),
    rule("go-nil-deref", "logic", "go", r"\b(\w+)\s*==\s*nil\s*&&\s*\1\.|\b(\w+)\s*!=\s*nil\s*\|\|\s*\2\.",
         "dereferences on exactly the path where it is nil", "if x == nil && x.y {", "if x != nil && x.y {"),
    rule("go-inverted-err", "logic", "go", r"if\s+err\s*==\s*nil\s*\{\s*return\s+([\w\"]+,\s*)*err\s*\}",
         "returns the error on the success path", "if err == nil {\n\treturn err\n}\n", "if err != nil {\n\treturn err\n}\n", "file"),
    rule("go-err-overwrite", "logic", "go",
         r"^[ \t]*[\w, ]*\berr\s*:?=\s*[^\n{]+\n[ \t]*[\w, ]*\berr\s*:?=\s",
         "the first error is overwritten before anyone looks at it", "\t_, err = a()\n\t_, err = b()\n", "\t_, err = a()\n\tif err != nil {\n", "file"),
    rule("go-defer-before-check", "logic", "go", r"(\w+),\s*err\s*:?=\s*[^\n]+\n\s*defer\s+\1\.",
         "the defer runs on a nil value when the call failed", "f, err := open()\ndefer f.Close()\n",
         "f, err := open()\nif err != nil {\n", "file"),
    rule("go-range-copy", "logic", "go", r"for\s+_,\s*(\w+)\s*:=\s*range\s+[^\n]+\{\n\s*\1\.\w+\s*(=|\+=|\+\+)",
         "writes to the loop's copy; the slice is unchanged", "for _, v := range xs {\n\tv.n = 1\n}\n", "for i := range xs {\n\txs[i].n = 1\n}\n", "file"),
    rule("go-sort-lte", "logic", "go", r"return\s+[^\n]*\[i\][\w.]*\s*(<=|>=)\s*[^\n]*\[j\]",
         "a Less that is true for equal items breaks the sort's contract", "return a[i].n <= a[j].n", "return a[i].n < a[j].n"),
    rule("go-trim-cutset", "logic", "go", r"strings\.Trim(Left|Right)?\([^,\n()]+,\s*\"[a-zA-Z][^\"]{2,}\"\)",
         "the second argument is a set of characters, not a string; use TrimPrefix",
         'strings.TrimLeft(s, "http://")', 'strings.TrimPrefix(s, "http://")'),
    rule("go-int-div-float", "logic", "go", r"float(32|64)\(\w+\s*/\s*\w+\)", "integer division happens first and truncates", "float64(a / b)", "float64(a) / float64(b)"),
    rule("go-float-eq", "logic", "go", r"\b\w+\s*[!=]=\s*\d+\.\d+\b", "floats rarely compare equal", "if x == 0.5 {", "if x > 0.5 {"),
    rule("go-select-break", "logic", "go", r"^\s*break\s*$", "breaks out of the select, not the for around it", "\tbreak", "\tbreak outer", "loop-select"),
    rule("go-wg-add", "logic", "go", r"go\s+func\([^)]*\)\s*\{\s*\n\s*\w+\.Add\(",
         "Add inside the goroutine races with Wait", "go func() {\n\twg.Add(1)\n}()\n", "wg.Add(1)\ngo func() {\n}()\n", "file"),
    rule("go-lock", "logic", "go", r"\.(R)?Lock\(\)", "locked and never unlocked in this function",
         "func f() {\n\tm.Lock()\n}\n", "func f() {\n\tm.Lock()\n\tm.Unlock()\n}\n", "func", r"Unlock\(\)"),
    rule("go-unreachable", "logic", "go",
         r"^(\t+)(return\b[^\n]*|continue|panic\([^\n]*\))\n\1(?!case\b|default\b|//|\})\S",
         "code after a return in the same block never runs", "\treturn\n\tx()\n", "\treturn\n}\n", "file"),
    rule("go-dup-branch", "logic", "go", r"(?m)^(\t*)if ([^\n{]+) \{\n(?:\1\t[^\n]*\n|\n){1,12}\1\} else if \2 \{",
         "the else-if repeats the condition, so it can never run", "if a {\n\tx()\n} else if a {\n", "if a {\n\tx()\n} else if b {\n", "file"),

    # ── badcode: works, but should not stay ───────────────────────────────────
    rule("go-todo", "badcode", "go", r"\b(TODO|FIXME|XXX|HACK)\b", "unfinished work", "// TODO: fix", "// done", "raw"),
    rule("go-empty-if", "badcode", "go", r"\bif [^\n{]+\{\s*\}\s*$", "a branch with nothing in it", "if x {\n}\n", "if x {\n\ty()\n}\n", "file"),
    rule("go-bool-compare", "badcode", "go", r"[!=]=\s*(true|false)\b", "compare the value, not its truth", "if x == true {", "if x {"),
    rule("go-sleep", "badcode", "go", r"\btime\.Sleep\(", "a sleep in production code is usually a race or a poll", "time.Sleep(d)", "<-t.C"),
    rule("go-panic-lib", "badcode", "go", r"^\s*panic\(", "library code should return an error", '\tpanic("x")', "\treturn err"),
    rule("go-context-bg", "badcode", "go", r"context\.(Background|TODO)\(\)", "the caller cannot cancel this", "context.Background()", "ctx"),

    # ── fs: attacker-reachable paths ──────────────────────────────────────────
    rule("go-walk-root", "fs", "go", r"filepath\.Walk(Dir)?\((?!safefs\.WalkRoot)",
         "a symlinked root is visited as nothing: `cau scan /bin` scanned 0 files", "filepath.Walk(p, f)", "filepath.Walk(safefs.WalkRoot(p), f)"),
    rule("go-create-excl", "fs", "go", r"os\.O_CREATE(?!.*O_EXCL)", "follows a planted symlink; add O_EXCL or write via temp and rename",
         "os.O_CREATE|os.O_WRONLY", "os.O_CREATE|os.O_EXCL"),
    rule("go-world-write", "fs", "go", r"\b0o?(666|777|775|664)\b", "group- or world-writable", "os.Chmod(p, 0o777)", "os.Chmod(p, 0o700)"),
    rule("go-exec-path", "fs", "go", r"exec\.Command(Context)?\(\s*(?:ctx,\s*)?\"[^/\"]", "resolved through PATH, which an attacker may control", 'exec.Command("sh")', 'exec.Command("/bin/sh")'),

    # ── injection ─────────────────────────────────────────────────────────────
    rule("go-exec-shell", "injection", "go", r"exec\.Command(Context)?\([^,\n]*,?\s*\"(/bin/)?(ba|z|da)?sh\"", "a shell around an argument is an injection point", 'exec.Command("sh", "-c", s)', 'exec.Command("/bin/ls", s)'),
    rule("go-print-raw", "injection", "go", r"^(?!.*TermSafe).*Fprint(f|ln)?\([^\n]*(\.OriginalPath|\.Comm|\.Cmdline|\.Evidence|\.FilePath)\b",
         "attacker text reaching a terminal raw; use report.TermSafe", "fmt.Fprintf(w, s, p.Comm)", "fmt.Fprintf(w, s, report.TermSafe(p.Comm))"),

    # ── C and BPF ─────────────────────────────────────────────────────────────
    rule("c-unsafe-fn", "memory", "c", r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(", "no bound on the destination", "strcpy(a, b);", "strscpy(a, b, n);"),
    rule("c-alloc-check", "memory", "c", r"\b(kmalloc|kzalloc|malloc|calloc)\s*\([^;]*;\s*\n(?!\s*if)", "an allocation that is not checked", "p = kmalloc(n, G);\n*p = 1;\n", "p = kmalloc(n, G);\nif (!p)\n", "file"),
    rule("c-assign-if", "logic", "c", r"\bif\s*\([^=!<>()]*[^=!<>()]=[^=][^)]*\)", "an assignment where a comparison was meant", "if (a = b) {", "if (a == b) {"),
    rule("c-sizeof-ptr", "memory", "c", r"sizeof\s*\(\s*\w+\s*\*\s*\)", "the size of a pointer, not of what it points at", "sizeof(foo *)", "sizeof(foo)"),
    rule("c-probe-result", "errors", "c", r"^\s*bpf_probe_read\w*\(", "a failed read leaves the destination zeroed, and that reads as a value", "\tbpf_probe_read_kernel(&a, 4, b);", "\tif (bpf_probe_read_kernel(&a, 4, b))"),

    # ── Python ────────────────────────────────────────────────────────────────
    rule("py-except-bare", "errors", "py", r"^\s*except\s*:", "catches everything, KeyboardInterrupt included", "except:", "except OSError:"),
    rule("py-except-pass", "errors", "py", r"except[^\n]*:\s*\n\s*(pass|continue)\s*$", "a failure disappears", "except OSError:\n    pass\n", "except OSError:\n    log()\n", "file"),
    rule("py-open-leak", "memory", "py", r"(?<!with )\b(json\.load\(open\(|=\s*open\(|\.read\(\)\s*$)", "a file left to the garbage collector; use with", "json.load(open(p))", "with open(p) as f:"),
    rule("py-mutable-default", "logic", "py", r"def\s+\w+\([^)]*=\s*(\[\]|\{\})", "the default is shared between calls", "def f(a=[]):", "def f(a=None):"),
    rule("py-is-literal", "logic", "py", r"\bis\s+(not\s+)?(['\"\d])", "compares identity, not value", "if a is 'x':", "if a == 'x':"),
    rule("py-none-eq", "badcode", "py", r"[!=]=\s*None\b", "use `is None`", "if a == None:", "if a is None:"),
    rule("py-shell", "injection", "py", r"shell\s*=\s*True|\bos\.system\(|\beval\(|\bexec\(", "a string reaches an interpreter", "run(c, shell=True)", "run([c])"),
    rule("py-extractall", "fs", "py", r"\.extractall\(", "an archive can write outside the target", "t.extractall(d)", "t.extract(m, d)"),

    # ── shell ─────────────────────────────────────────────────────────────────
    rule("sh-or-true", "errors", "sh", r"\|\|\s*(true|:)\s*($|;|#)", "a failure is forced to success", "rm x || true", "rm x"),
    rule("sh-devnull", "errors", "sh", r"\b2>\s*/dev/null", "stderr is thrown away, and with it the reason", "ls 2>/dev/null", "ls"),
    rule("sh-cd", "errors", "sh", r"^\s*cd\s+[^|&;]+$", "a failed cd runs the rest in the wrong directory", "cd build", "cd build || exit 1"),
    rule("sh-rm-var", "fs", "sh", r"\brm\s+-[rf]+\s+[^\"'\n]*\$", "an unquoted variable in rm -rf", "rm -rf $d", 'rm -rf "$d"'),
    rule("sh-curl-pipe", "injection", "sh", r"(curl|wget)[^|\n]*\|\s*(ba|z|da)?sh\b", "runs whatever the network returns", "curl u | sh", "curl -o f u"),
    rule("sh-tmp", "fs", "sh", r"(?<![\w$}/])/tmp/[\w.-]+", "a fixed name in a shared directory; use mktemp", "cp a /tmp/x", 'cp a "$tmp/x"'),
    rule("sh-eval", "injection", "sh", r"^\s*eval\b", "a string reaches the shell again", 'eval "$x"', 'x'),

    # ── workflows ─────────────────────────────────────────────────────────────
    rule("yaml-expr-run", "injection", "yaml", r"^\s*(run:|-)?.*\$\{\{\s*(github\.event\.|github\.head_ref|inputs\.)",
         "attacker-controlled text pasted into a shell step; pass it through env", "run: echo ${{ github.event.issue.title }}", "run: echo $TITLE"),
    rule("yaml-target", "injection", "yaml", r"\bpull_request_target\b", "runs a fork's PR with this repository's secrets", "on: pull_request_target", "on: pull_request"),
    rule("yaml-unpinned", "fs", "yaml", r"uses:\s*[\w./-]+@(?![0-9a-f]{40}\b)", "a tag can be moved; a commit hash cannot", "uses: a/b@v4", "uses: a/b@" + "0" * 40),
]

SUPPRESS = "audit:ok"
BASELINE = os.path.join("scripts", "regex-audit.baseline")


def fingerprint(r, path, line):
    return f"{r.id}\t{path}\t{hashlib.sha256(line.encode()).hexdigest()[:16]}"


def load_baseline(root, path=None):
    """Reads the hits somebody read. A missing baseline is an empty one, which
    makes every hit a new candidate: the sweep then says what it sees."""
    try:
        with open(path or os.path.join(root, BASELINE)) as f:
            return {line.rstrip("\n") for line in f if line.strip() and not line.startswith("#")}
    except FileNotFoundError:
        return set()


def blank_comments(text, lang):
    """Blanks comments and keeps line numbers, so prose cannot match a code rule."""
    if lang in ("go", "c"):
        def repl(m):
            s = m.group(0)
            if s.startswith(("//", "/*")):
                return re.sub(r"[^\n]", " ", s)
            return s
        return re.sub(r'"(?:\\.|[^"\\\n])*"|`[^`]*`|//[^\n]*|/\*.*?\*/', repl, text, flags=re.S)
    return re.sub(r"(?m)^[ \t]*#[^\n]*$", "", text)


def go_functions(text):
    """Yields (start line, body) for each top-level Go function."""
    matches = list(re.finditer(r"(?m)^func\b[^\n]*$", text))
    for i, m in enumerate(matches):
        end = text.find("\n}\n", m.start())
        limit = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        yield text.count("\n", 0, m.start()) + 1, text[m.start():(end + 2 if 0 <= end < limit else limit)]


def block_stack(lines):
    """Yields each line with the kinds of block open around it, innermost last."""
    stack = []
    for n, line in enumerate(lines, 1):
        body = line.strip()
        indent = len(line) - len(line.lstrip("\t"))
        while stack and (indent < stack[-1][1] or (indent == stack[-1][1] and body.startswith("}"))):
            stack.pop()
        yield n, line, [kind for kind, _ in stack]
        if body.endswith("{"):
            head = body.split(None, 1)[0] if body else ""
            is_closure = "func(" in body or body.startswith("func ")
            kind = "closure" if is_closure else {"for": "for", "select": "select", "switch": "switch"}.get(head, "block")
            stack.append((kind, indent))


def in_loop(kinds):
    """True when no closure sits between this line and the nearest for."""
    for kind in reversed(kinds):
        if kind == "for":
            return True
        if kind == "closure":
            return False
    return False


def break_leaves_select(kinds):
    """True when a bare break would stop at a select or switch inside a for."""
    seen = False
    for kind in reversed(kinds):
        if kind == "closure":
            return False
        if kind == "for":
            return seen
        if kind in ("select", "switch"):
            seen = True
    return False


def check(r, regex, text, raw_lines, report):
    if r.scope == "raw":
        for n, line in enumerate(raw_lines, 1):
            if regex.search(line):
                report(r, n, raw_lines)
    elif r.scope == "line":
        for n, line in enumerate(text.split("\n"), 1):
            if regex.search(line):
                report(r, n, raw_lines)
    elif r.scope == "file":
        for m in regex.finditer(text):
            report(r, text.count("\n", 0, m.start()) + 1, raw_lines)
    elif r.scope == "func":
        lacks = re.compile(r.lacks)
        for start, body in go_functions(text):
            m = regex.search(body)
            if m and not lacks.search(body):
                report(r, start + body.count("\n", 0, m.start()), raw_lines)
    else:
        test = {"loop": in_loop, "noloop": lambda kinds: not in_loop(kinds)}.get(r.scope, break_leaves_select)
        for n, line, kinds in block_stack(text.split("\n")):
            if regex.search(line) and test(kinds):
                report(r, n, raw_lines)


def compile_rule(r):
    return re.compile(r.pattern, re.M)


def self_test():
    """Every rule must catch its bad sample and pass its good one."""
    failed = 0
    for r in RULES:
        regex = compile_rule(r)
        for sample, want in ((r.bad, True), (r.good, False)):
            if not sample:
                continue
            hits = []
            check(r, regex, blank_comments(wrap(r, sample), r.lang), sample.split("\n"),
                  lambda _r, n, _l: hits.append(n))
            if bool(hits) != want:
                failed += 1
                print(f"FAIL {r.id}: {'missed' if want else 'matched'} {sample!r}")
    print(f"{len(RULES) - failed}/{len(RULES)} rules correct" if not failed else f"{failed} sample(s) wrong")
    return 1 if failed else 0


def wrap(r, sample):
    if r.scope == "loop":
        return "func f() {\n\tfor x {\n\t" + sample.strip() + "\n\t}\n}\n"
    if r.scope == "loop-select":
        return "func f() {\n\tfor x {\n\t\tselect {\n\t\tcase y:\n\t\t\t" + sample.strip() + "\n\t\t}\n\t}\n}\n"
    return sample


def scan(root, opts):
    hits = []
    compiled = [(r, compile_rule(r)) for r in RULES
                if (not opts.family or r.family == opts.family) and (not opts.rule or r.id == opts.rule)]

    def report(r, n, raw_lines):
        line = raw_lines[n - 1] if n <= len(raw_lines) else ""
        if SUPPRESS not in line:
            hits.append((r, path, n, line.strip()))

    for dirpath, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            lang = LANGS.get(os.path.splitext(name)[1]) or ("sh" if name in SHELL_NAMES else None)
            if not lang or name == "regex-audit.py":  # its samples are the bugs
                continue
            full = os.path.join(dirpath, name)
            path = os.path.relpath(full, root)
            if opts.prefix:
                path = os.path.join(opts.prefix, path)
            if not opts.tests and (name.endswith("_test.go") or "/vmtest/" in full):
                continue
            with open(full, errors="replace") as f:
                raw = f.read()
            text = blank_comments(raw, lang)
            raw_lines = raw.split("\n")
            is_main = lang == "go" and re.search(r"(?m)^package main\b", raw)
            strict = lang == "sh" and (name in SHELL_NAMES or re.search(r"(?m)^set -\w*e", raw))
            for r, regex in compiled:
                if r.lang != lang or (r.id == "go-exit-lib" and is_main) or (r.id == "sh-cd" and strict):
                    continue
                check(r, regex, text, raw_lines, report)
            wants_strict = not opts.rule and opts.family in (None, "errors")
            if wants_strict and lang == "sh" and not strict and SUPPRESS not in "".join(raw_lines[:3]):
                hits.append((Rule("sh-no-strict", "errors", "sh", "line", "", "a failed step does not stop the script", "", "", None),
                             path, 1, raw_lines[0]))
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".")
    ap.add_argument("--baseline", help="the baseline file to read (default: <root>/scripts/regex-audit.baseline). A tree that is not this repository reads its baseline from here, so one sweep covers both.")
    ap.add_argument("--prefix", default="", help="prefix for the reported paths, so a sibling tree produces the paths the baseline names (the baseline records them relative to this repository's root)")
    ap.add_argument("--family", choices=sorted({r.family for r in RULES}))
    ap.add_argument("--rule", help="run one rule by id")
    ap.add_argument("--tests", action="store_true", help="include test code")
    ap.add_argument("--summary", action="store_true", help="counts per rule, no hits")
    ap.add_argument("--all", action="store_true", help="ignore the baseline and exit 0")
    ap.add_argument("--write-baseline", action="store_true", help="record every current hit as read")
    ap.add_argument("--list", action="store_true", help="print the rules and exit")
    ap.add_argument("--self-test", action="store_true", help="check every rule against its samples")
    opts = ap.parse_args()

    if opts.self_test:
        return self_test()
    if opts.list:
        for r in sorted(RULES, key=lambda r: (r.family, r.id)):
            print(f"{r.family:10} {r.lang:5} {r.id:22} {r.why}")
        return 0

    hits = scan(opts.root, opts)
    if opts.write_baseline:
        entries = sorted({fingerprint(r, path, line) for r, path, _, line in hits})
        with open(os.path.join(opts.root, BASELINE), "w") as f:
            f.write("# Hits that have been read and left alone. See scripts/regex-audit.py.\n")
            f.write("# Rewrite with: scripts/regex-audit.py --write-baseline\n")
            f.write("".join(e + "\n" for e in entries))
        print(f"recorded {len(entries)} hit(s) in {BASELINE}")
        return 0
    known = set() if opts.all else load_baseline(opts.root, opts.baseline)
    total = len(hits)
    hits = [h for h in hits if fingerprint(h[0], h[1], h[3]) not in known]
    counts = collections.Counter(r.id for r, *_ in hits)
    if opts.summary:
        families = {r.id: r.family for r in RULES}
        for rid, n in sorted(counts.items(), key=lambda kv: (families.get(kv[0], "errors"), -kv[1])):
            print(f"{families.get(rid, 'errors'):10} {n:6}  {rid}")
    else:
        for r, path, n, line in sorted(hits, key=lambda h: (h[0].family, h[0].id, h[1], h[2])):
            print(f"{path}:{n}: [{r.family}/{r.id}] {r.why}\n    {line[:140]}")
    print(f"{len(hits)} new candidate(s) from {len(counts)} rule(s), {total - len(hits)} already read", file=sys.stderr)
    return 1 if hits and not opts.all else 0


if __name__ == "__main__":
    sys.exit(main())

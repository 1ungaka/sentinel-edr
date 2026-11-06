package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// All tests in this file belong to the YARA migration; they are prefixed with
// TestYara so they can be run (and attributed) independently of the rest of the
// scanner test suite.

// repoRules is the rule set shipped with CAU EDR.
const repoRules = "../rules/rule_list.yar"

// wannacrySample is a synthetic buffer that trips wannacry_ransomware in
// rules/rule_list.yar (3 of its 4 strings are enough).
var wannacrySample = strings.Join([]string{
	"MZ\x90\x00\x03",
	"C:\\%s\\qeriuwjhrf",
	"WNcry@2017",
	"msg/m_bulgarian.wnry",
	"WanaCryptor0banner",
}, "\n")

func loadRepoYara(t *testing.T, opts ...YaraOption) *YaraScanner {
	t.Helper()
	ys, files, err := LoadYaraRules(repoRules, opts...)
	if err != nil {
		t.Fatalf("LoadYaraRules(%s): %v", repoRules, err)
	}
	if files != 1 {
		t.Fatalf("LoadYaraRules(%s) = %d files, want 1", repoRules, files)
	}
	t.Cleanup(func() { _ = ys.Close() })
	return ys
}

// findMatch returns the match for the named rule.
func findMatch(t *testing.T, matches []YaraMatch, rule string) YaraMatch {
	t.Helper()
	for _, m := range matches {
		if m.RuleName == rule {
			return m
		}
	}
	t.Fatalf("rule %q did not match; got %v", rule, ruleNames(matches))
	return YaraMatch{}
}

func ruleNames(matches []YaraMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.RuleName)
	}
	return names
}

func findString(t *testing.T, m YaraMatch, name string) YaraMatchString {
	t.Helper()
	for _, s := range m.Strings {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("string %s not found in rule %s (got %d strings)", name, m.RuleName, len(m.Strings))
	return YaraMatchString{}
}

// TestYaraLoadCompilesRepoRules proves the ruleset is compiled in-process at
// load time (no yara binary, no per-file process spawn).
func TestYaraLoadCompilesRepoRules(t *testing.T) {
	ys := loadRepoYara(t)

	if got := ys.RuleCount(); got != 8 {
		t.Errorf("RuleCount() = %d, want 8", got)
	}
	if got := len(ys.RuleFiles()); got != 1 {
		t.Errorf("RuleFiles() = %d entries, want 1", got)
	}
	if w := ys.Warnings(); len(w) != 0 {
		t.Errorf("Warnings() = %v, want none", w)
	}
	if ys.Timeout() != DefaultScanTimeout {
		t.Errorf("Timeout() = %s, want %s", ys.Timeout(), DefaultScanTimeout)
	}
	if ys.Rules() == nil {
		t.Fatal("Rules() = nil, want a compiled ruleset")
	}
}

// TestYaraScanMemMatchesRepoRule is the end-to-end proof of the migration: a
// synthetic buffer is matched against the repo ruleset, with tags, the real
// namespace and the rule's meta: block all populated.
func TestYaraScanMemMatchesRepoRule(t *testing.T) {
	ys := loadRepoYara(t)

	matches, err := ys.ScanMemYara([]byte(wannacrySample))
	if err != nil {
		t.Fatalf("ScanMemYara: %v", err)
	}

	m := findMatch(t, matches, "wannacry_ransomware")

	// Namespace must be the one YARA reports, not one guessed from the file
	// name (the old CLI implementation reported "rule_list").
	if m.Namespace != "default" {
		t.Errorf("Namespace = %q, want %q (the real YARA namespace)", m.Namespace, "default")
	}
	if m.Namespace == filepath.Base(repoRules) {
		t.Errorf("Namespace %q was faked from the file name", m.Namespace)
	}

	// meta: block used to be parsed by YARA and then thrown away.
	if got := m.MetaString("author"); got != "CAU" {
		t.Errorf("meta author = %q, want %q", got, "CAU")
	}
	if got, ok := m.MetaInt("threat_level"); !ok || got != 5 {
		t.Errorf("meta threat_level = %d (ok=%v), want 5", got, ok)
	}
	if meta, ok := m.Meta("in_the_wild"); !ok || meta.Value != true {
		t.Errorf("meta in_the_wild = %v (ok=%v), want true", meta.Value, ok)
	}
	if meta, ok := m.Meta("description"); !ok || !strings.Contains(meta.String(), "WannaCry") {
		t.Errorf("meta description = %q, want it to mention WannaCry", meta.String())
	}
	if len(m.Metas) < 4 {
		t.Errorf("Metas has %d entries, want at least 4: %+v", len(m.Metas), m.Metas)
	}

	// Matched strings and their offsets must point into the sample.
	s := findString(t, m, "$c") // "WNcry@2017"
	if !bytes.Equal(s.Data, []byte("WNcry@2017")) {
		t.Errorf("$c data = %q, want %q", s.Data, "WNcry@2017")
	}
	idx := strings.Index(wannacrySample, "WNcry@2017")
	if int(s.Offset) != idx {
		t.Errorf("$c offset = %d, want %d (absolute offset in the sample)", s.Offset, idx)
	}
	if len(m.Strings) < 3 {
		t.Errorf("only %d strings reported, want >= 3", len(m.Strings))
	}
}

// TestYaraStringOffsetsAreAbsolute pins the Base/Offset contract: Offset is the
// absolute offset into the scanned buffer, Base is the block base (0 here).
func TestYaraStringOffsetsAreAbsolute(t *testing.T) {
	const needle = "CAU_ABSOLUTE_OFFSET_PROBE"

	ys, _, err := LoadYaraRuleFiles([]RuleSource{{
		Text: "rule offset_probe {\n\tstrings:\n\t\t$n = \"" + needle + "\"\n\tcondition:\n\t\t$n\n}\n",
	}})
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys.Close()

	// Place the needle at several offsets, including deep into the buffer, so
	// an implementation that reported only the in-block offset would fail.
	for _, want := range []int{0, 1, 0x1234, 1 << 20, (3 << 20) + 4096} {
		buf := bytes.Repeat([]byte{0x90}, (3<<20)+8192)
		copy(buf[want:], needle)

		matches, err := ys.ScanMemYara(buf)
		if err != nil {
			t.Fatalf("ScanMemYara: %v", err)
		}

		m := findMatch(t, matches, "offset_probe")
		s := findString(t, m, "$n")
		if s.Offset != uint64(want) {
			t.Errorf("offset for needle at %d reported as %d (base=%d)", want, s.Offset, s.Base)
		}
		if s.Base != 0 {
			t.Errorf("Base = %d for a single-buffer scan, want 0", s.Base)
		}
		if !bytes.Equal(buf[s.Offset:s.Offset+uint64(len(needle))], []byte(needle)) {
			t.Errorf("data at reported offset %d is %q, want %q",
				s.Offset, buf[s.Offset:s.Offset+uint64(len(needle))], needle)
		}
	}
}

// TestYaraFileScanOffsetsAreAbsolute repeats the offset check through
// ScanFileYara, on a file large enough to catch block-relative reporting.
func TestYaraFileScanOffsetsAreAbsolute(t *testing.T) {
	const needle = "CAU_FILE_OFFSET_PROBE"

	ys, _, err := LoadYaraRuleFiles([]RuleSource{{
		Text: "rule file_offset_probe {\n\tstrings:\n\t\t$n = \"" + needle + "\"\n\tcondition:\n\t\t$n\n}\n",
	}})
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys.Close()

	// 5 MiB of filler so the match sits far past any block boundary.
	const want = (5 << 20) + 1234
	buf := bytes.Repeat([]byte{0x41}, want+len(needle)+64)
	copy(buf[want:], needle)

	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	matches, err := ys.ScanFileYara(path)
	if err != nil {
		t.Fatalf("ScanFileYara: %v", err)
	}
	s := findString(t, findMatch(t, matches, "file_offset_probe"), "$n")
	if s.Offset != want {
		t.Errorf("file offset = %d, want %d", s.Offset, want)
	}
}

// TestYaraLargeFileScannedInPlace covers the memory-map fallback used for files
// bigger than the in-memory scan limit.
func TestYaraLargeFileScannedInPlace(t *testing.T) {
	const needle = "CAU_MMAP_PROBE"

	ys, _, err := LoadYaraRuleFiles(
		[]RuleSource{{Text: "rule mmap_probe {\n\tstrings:\n\t\t$n = \"" + needle + "\"\n\tcondition:\n\t\t$n\n}\n"}},
		WithMaxScanSize(4096),
		WithWarnFunc(func(string, ...interface{}) {}),
	)
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys.Close()

	const want = 64 * 1024
	buf := bytes.Repeat([]byte{0x42}, want+len(needle)+1)
	copy(buf[want:], needle)

	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	matches, err := ys.ScanFileYara(path)
	if err != nil {
		t.Fatalf("ScanFileYara: %v", err)
	}
	s := findString(t, findMatch(t, matches, "mmap_probe"), "$n")
	if s.Offset != want {
		t.Errorf("mmap-ed file offset = %d, want %d", s.Offset, want)
	}
}

// TestYaraNamespaceIsRealOrDerived checks both namespace modes: the real one by
// default, the historical file-name one when explicitly requested.
func TestYaraNamespaceIsRealOrDerived(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "cau_derived.yar")
	if err := os.WriteFile(src, []byte("rule ns_probe { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	real, _, err := LoadYaraRules(dir, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatalf("LoadYaraRules: %v", err)
	}
	defer real.Close()

	matches, err := real.ScanMemYara([]byte("nothing to see here"))
	if err != nil {
		t.Fatalf("ScanMemYara: %v", err)
	}
	if ns := findMatch(t, matches, "ns_probe").Namespace; ns != "default" {
		t.Errorf("default namespace = %q, want %q", ns, "default")
	}

	derived, _, err := LoadYaraRules(dir,
		WithNamespaceFromFileName(),
		WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatalf("LoadYaraRules with namespaces: %v", err)
	}
	defer derived.Close()

	matches, err = derived.ScanMemYara([]byte("nothing to see here"))
	if err != nil {
		t.Fatalf("ScanMemYara: %v", err)
	}
	if ns := findMatch(t, matches, "ns_probe").Namespace; ns != "cau_derived" {
		t.Errorf("derived namespace = %q, want %q", ns, "cau_derived")
	}
}

// TestYaraErrorIsolation is the regression test for the bug where one broken
// rule file discarded every match collected so far: a ruleset with good and
// broken files must still scan, and must still detect.
func TestYaraErrorIsolation(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("01_good_detect.yar", `rule isolation_detect
{
	meta:
		author = "CAU"
		threat_level = 5
	strings:
		$a = "CAU_ISOLATION_CANARY"
	condition:
		$a
}
`)
	// Syntax error: $b has no value.
	write("02_broken_syntax.yar", `rule isolation_broken
{
	strings:
		$a =
	condition:
		$a
}
`)
	write("03_good_detect2.yar", `rule isolation_detect2
{
	strings:
		$a = "CAU_ISOLATION_CANARY2"
	condition:
		$a
}
`)
	// Duplicate rule identifier: only broken in combination with 01.
	write("04_duplicate.yar", `rule isolation_detect
{
	strings:
		$a = "duplicate"
	condition:
		$a
}
`)
	write("05_semantic_error.yar", `rule isolation_semantic
{
	condition:
		no_such_function(1)
}
`)
	// Not a rule file at all: ignored entirely.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("not rules"), 0o600); err != nil {
		t.Fatal(err)
	}

	var warnings []string
	ys, files, err := LoadYaraRules(dir, WithWarnFunc(func(format string, args ...interface{}) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}))
	if err != nil {
		t.Fatalf("LoadYaraRules must survive broken rule files: %v", err)
	}
	defer ys.Close()

	// 5 rule files were found, 3 of them are dropped (syntax error, duplicate
	// identifier, undefined identifier): the two healthy ones still compile.
	if files != 2 {
		t.Errorf("LoadYaraRules reported %d usable files, want 2 (warnings: %v)", files, warnings)
	}
	if got := ys.RuleCount(); got != 2 {
		t.Errorf("RuleCount() = %d, want 2", got)
	}

	// Each dropped file must be named in a warning.
	dropped := ys.Warnings()
	joined := warningText(dropped)
	for _, want := range []string{
		"02_broken_syntax.yar",
		"04_duplicate.yar",
		"05_semantic_error.yar",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning list does not mention %s:\n%s", want, joined)
		}
	}
	for _, w := range dropped {
		if w.Line <= 0 {
			t.Errorf("warning for %s has no line number: %s", w.Source, w)
		}
	}
	if len(warnings) != len(dropped) {
		t.Errorf("got %d warnings on stderr, want %d", len(warnings), len(dropped))
	}

	// The good rules still detect.
	matches, err := ys.ScanMemYara([]byte("prefix CAU_ISOLATION_CANARY suffix"))
	if err != nil {
		t.Fatalf("ScanMemYara: %v", err)
	}
	m := findMatch(t, matches, "isolation_detect")
	if got := m.MetaString("author"); got != "CAU" {
		t.Errorf("meta author = %q, want CAU", got)
	}
}

func warningText(ws []RuleCompileWarning) string {
	var b strings.Builder
	for _, w := range ws {
		b.WriteString(w.Error())
		b.WriteString("\n")
	}
	return b.String()
}

// TestYaraBrokenRuleIsNotFatalToTheScan guards the original defect directly: a
// ruleset that also contains a broken file must still report its detections.
func TestYaraBrokenRuleIsNotFatalToTheScan(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a_good.yar"),
		[]byte("rule still_detects { strings: $a = \"CAU_STILL_DETECTS\" condition: $a }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b_broken.yar"),
		[]byte("rule broken { condition: undefined_identifier }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ys, files, err := LoadYaraRules(dir, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatalf("LoadYaraRules: %v", err)
	}
	defer ys.Close()
	if files != 1 {
		t.Fatalf("usable files = %d, want 1", files)
	}

	matches, err := ys.ScanFileYara(writeTempFile(t, "payload.bin", []byte("CAU_STILL_DETECTS")))
	if err != nil {
		t.Fatalf("ScanFileYara: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no matches: a broken rule file must not make the sample look clean")
	}
	findMatch(t, matches, "still_detects")
}

// TestYaraAllRulesBrokenIsHardError: a ruleset with zero usable rules is an
// error, not a silently empty scanner.
func TestYaraAllRulesBrokenIsHardError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yar"),
		[]byte("rule broken {\n\tstrings:\n\t\t$a =\n\tcondition:\n\t\t$a\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ys, _, err := LoadYaraRules(dir, WithWarnFunc(func(string, ...interface{}) {}))
	if err == nil {
		t.Fatal("LoadYaraRules succeeded with only broken rules")
	}
	if ys != nil {
		_ = ys.Close()
		t.Error("a failed LoadYaraRules must not return a scanner")
	}
	if !strings.Contains(err.Error(), "broken.yar") {
		t.Errorf("error does not name the offending file: %v", err)
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("error does not carry the YARA message: %v", err)
	}
}

// TestYaraCompileErrorHasFileLineColumn checks the actionable-ness of a compile
// failure for a hand written file.
func TestYaraCompileErrorHasFileLineColumn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_syntax.yar")
	body := strings.Join([]string{
		`rule bad_syntax`,        // 1
		`{`,                      // 2
		`    meta:`,              // 3
		`        author = "CAU"`, // 4
		`    strings:`,           // 5
		`        $a =`,           // 6
		`        condition:`,     // 7
		`        $a`,             // 8
		`}`,                      // 9
	}, "\n")
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ys, _, err := LoadYaraRules(dir, WithWarnFunc(func(string, ...interface{}) {}))
	if err == nil {
		t.Fatal("expected an error: every rule file is broken")
	}
	if ys != nil {
		t.Error("a failed LoadYaraRules must not return a scanner")
	}

	// The error must name the file, the line, the column and the YARA message.
	// Line 7 is indented with 8 spaces, so "condition" starts at column 9.
	if !strings.Contains(err.Error(), "bad_syntax.yar:7:9:") {
		t.Errorf("error does not point at bad_syntax.yar:7:9: %v", err)
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("error does not carry the YARA message: %v", err)
	}
	if !strings.Contains(err.Error(), "no usable YARA rules") {
		t.Errorf("error does not explain that nothing was loaded: %v", err)
	}

	// Column recovery is a pure function of (source, line, message).
	if got := locateColumn(RuleSource{Path: path}, 7, `rule "bad_syntax": syntax error, unexpected <condition>, expecting text string`); got != 9 {
		t.Errorf("column of the blamed token = %d, want 9", got)
	}
	// ... and it degrades gracefully when the token is not on that line.
	if got := locateColumn(RuleSource{Path: path}, 4, `syntax error, unexpected <condition>`); got != 0 {
		t.Errorf("column for a token that is not on the line = %d, want 0", got)
	}
	if got := locateColumn(RuleSource{Text: "rule x { condition: true }"}, 1, `undefined identifier "nope"`); got != 0 {
		t.Errorf("column for a missing token = %d, want 0", got)
	}
	if got := blamedToken(`duplicated identifier "foo"`); got != "foo" {
		t.Errorf("blamedToken = %q, want %q", got, "foo")
	}
	if got := blamedToken(`syntax error, unexpected <condition>, expecting text string`); got != "condition" {
		t.Errorf("blamedToken = %q, want %q", got, "condition")
	}
}

// TestYaraScanTimeout proves an adversarial sample cannot hang the scanner: the
// scan returns an error instead of running forever.
func TestYaraScanTimeout(t *testing.T) {
	// The YARA VM only checks the timeout every 100 instruction cycles, so the
	// rule has to burn time in its *condition* (a nested for-loop), not in a
	// regex: regex evaluation is not interruptible.
	slow := `
rule cau_timeout_bait
{
	strings:
		$a = "a"
	condition:
		for all i in (1..#a) : ( for all j in (1..#a) : ( true ) )
}`

	ys, _, err := LoadYaraRuleFiles([]RuleSource{{Text: slow}},
		WithTimeout(time.Second),
		WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys.Close()

	if ys.Timeout() != time.Second {
		t.Errorf("Timeout() = %s, want 1s", ys.Timeout())
	}

	payload := bytes.Repeat([]byte("a"), 64*1024)

	start := time.Now()
	_, err = ys.ScanMemYaraStrict(payload)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("scan of a rule-bomb sample returned no error")
	}
	if !IsScanTimeout(err) {
		t.Errorf("error is not a scan timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "scan timeout") {
		t.Errorf("error message is not actionable: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("scan took %s, timeout was not enforced", elapsed)
	}
	t.Logf("timeout enforced after %s: %v", elapsed, err)

	// The non-strict entry point reports the failure too when nothing matched.
	if _, err := ys.ScanMemYara(payload); err == nil {
		t.Error("ScanMemYara swallowed the timeout error")
	}
}

// TestYaraTimeoutValidation: a zero timeout would disable the limit entirely
// (libyara reads 0 as "no timeout"), so it must be rejected, and sub-second
// values must be rounded up rather than truncated away.
func TestYaraTimeoutValidation(t *testing.T) {
	rule := []RuleSource{{Text: "rule t { condition: true }"}}

	if _, _, err := LoadYaraRuleFiles(rule, WithTimeout(0)); err == nil {
		t.Error("WithTimeout(0) was accepted: it disables the timeout entirely")
	}
	if _, _, err := LoadYaraRuleFiles(rule, WithTimeout(-time.Second)); err == nil {
		t.Error("WithTimeout(-1s) was accepted")
	}

	ys, _, err := LoadYaraRuleFiles(rule, WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys.Close()
	if ys.Timeout() != time.Second {
		t.Errorf("Timeout() = %s, want 1s (rounded up, never truncated to 0)", ys.Timeout())
	}

	ys2, _, err := LoadYaraRuleFiles(rule, WithTimeout(2500*time.Millisecond))
	if err != nil {
		t.Fatalf("LoadYaraRuleFiles: %v", err)
	}
	defer ys2.Close()
	if ys2.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %s, want 3s (rounded up to whole seconds)", ys2.Timeout())
	}
}

// TestYaraLoadErrors covers the argument validation of the loaders.
func TestYaraLoadErrors(t *testing.T) {
	if _, _, err := LoadYaraRules(""); err == nil {
		t.Error("LoadYaraRules(\"\") was accepted")
	}
	if _, _, err := LoadYaraRules(filepath.Join(t.TempDir(), "nope.yar")); err == nil {
		t.Error("LoadYaraRules accepted a missing path")
	}
	if _, _, err := LoadYaraRules(t.TempDir()); err == nil {
		t.Error("LoadYaraRules accepted an empty directory")
	}

	notRules := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(notRules, []byte("rule x { condition: true }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadYaraRules(notRules); err == nil {
		t.Error("LoadYaraRules accepted a file without a .yar/.yara extension")
	}
	if _, _, err := LoadYaraRuleFiles(nil); err == nil {
		t.Error("LoadYaraRuleFiles(nil) was accepted")
	}
}

// TestYaraClosedScanner: after Close the scanner reports an error instead of
// touching freed libyara memory.
func TestYaraClosedScanner(t *testing.T) {
	ys := loadRepoYara(t)
	if err := ys.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ys.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := ys.ScanMemYara([]byte(wannacrySample)); err == nil {
		t.Error("ScanMemYara on a closed scanner returned no error")
	}
	if _, err := ys.ScanFileYara("whatever"); err == nil {
		t.Error("ScanFileYara on a closed scanner returned no error")
	}
}

// TestYaraConcurrentScans: a *YaraScanner must be usable from several
// goroutines at once (one YARA scanner object per scan).
func TestYaraConcurrentScans(t *testing.T) {
	ys := loadRepoYara(t)

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	counts := make(chan int, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			buf := append([]byte(fmt.Sprintf("sample-%d\n", i)), []byte(wannacrySample)...)
			matches, err := ys.ScanMemYara(buf)
			if err != nil {
				errs <- err
				return
			}
			counts <- len(matches)
		}(i)
	}
	wg.Wait()
	close(errs)
	close(counts)

	for err := range errs {
		t.Errorf("concurrent scan: %v", err)
	}
	for n := range counts {
		if n == 0 {
			t.Error("concurrent scan found no match")
		}
	}
}

// TestYaraScanMissingFile: a missing sample is an error, not a silent clean.
func TestYaraScanMissingFile(t *testing.T) {
	ys := loadRepoYara(t)
	if _, err := ys.ScanFileYara(filepath.Join(t.TempDir(), "missing.bin")); err == nil {
		t.Error("ScanFileYara accepted a missing file")
	}
}

// TestYaraCleanSample: the negative case - no matches, no error.
func TestYaraCleanSample(t *testing.T) {
	ys := loadRepoYara(t)
	matches, err := ys.ScanMemYara(bytes.Repeat([]byte("harmless filler "), 1024))
	if err != nil {
		t.Fatalf("ScanMemYara: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("clean sample matched %v", ruleNames(matches))
	}
}

// TestYaraRuleFileWalk: the rules directory is walked recursively and sorted.
func TestYaraRuleFileWalk(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "deeper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(dir, "b.yar"),
		filepath.Join(dir, "a.YARA"),
		filepath.Join(nested, "c.yara"),
		filepath.Join(dir, "ignored.txt"),
	} {
		if err := os.WriteFile(p, []byte("rule r_"+filepath.Base(p)+" { condition: true }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	files, err := collectRuleFiles(dir)
	if err != nil {
		t.Fatalf("collectRuleFiles: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("collectRuleFiles returned %d files (%v), want 3", len(files), files)
	}
	for i := 1; i < len(files); i++ {
		if files[i-1] > files[i] {
			t.Errorf("rule files are not sorted: %v", files)
		}
	}
}

func writeTempFile(tb testing.TB, name string, body []byte) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// BenchmarkYaraLoadRepoRules measures the one-off cost that used to be paid
// again for every single scanned sample (the old implementation re-walked the
// rules directory and spawned the yara binary per rule file, per sample).
func BenchmarkYaraLoadRepoRules(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ys, _, err := LoadYaraRules(repoRules, WithWarnFunc(func(string, ...interface{}) {}))
		if err != nil {
			b.Fatal(err)
		}
		_ = ys.Close()
	}
}

// BenchmarkYaraScanMem is the cost of scanning one sample in memory.
func BenchmarkYaraScanMem(b *testing.B) {
	ys, _, err := LoadYaraRules(repoRules, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		b.Fatal(err)
	}
	defer ys.Close()

	buf := []byte(wannacrySample)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ys.ScanMemYara(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkYaraScanFile is the cost of scanning one sample from disk.
func BenchmarkYaraScanFile(b *testing.B) {
	ys, _, err := LoadYaraRules(repoRules, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		b.Fatal(err)
	}
	defer ys.Close()

	path := writeTempFile(b, "sample.bin", []byte(wannacrySample))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ys.ScanFileYara(path); err != nil {
			b.Fatal(err)
		}
	}
}

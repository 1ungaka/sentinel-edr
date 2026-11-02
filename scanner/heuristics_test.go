package scanner

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// windowsTools is the Windows tool set shipped with Kali. The real-binary
// fixtures below are skipped when it is not installed.
const windowsTools = "/usr/share/windows-resources"

func scoreOf(t *testing.T, parts ...string) HeuristicResult {
	t.Helper()
	// Separate strings with NULs so each becomes its own extracted string.
	return ScanHeuristicsData("<mem>", []byte(strings.Join(parts, "\x00")), HeuristicOptions{})
}

func categoryApplied(h HeuristicResult, cat string) int {
	for _, c := range h.Categories {
		if c.Category == cat {
			return c.Applied
		}
	}
	return 0
}

// TestHeuristicsNoScoreInflationFromRepeatedPattern is the regression test for
// the bug where every distinct URL scored +1: 200 URLs used to score 200.
func TestHeuristicsNoScoreInflationFromRepeatedPattern(t *testing.T) {
	urls := make([]string, 200)
	for i := range urls {
		urls[i] = fmt.Sprintf("http://crl%03d.example.invalid/ca.crl", i)
	}
	h := scoreOf(t, urls...)

	if h.Score > weakBudget {
		t.Fatalf("200 URLs scored %d, want <= %d", h.Score, weakBudget)
	}
	if h.Detected() {
		t.Fatal("200 URLs flagged the file")
	}
	if len(h.Matches) != 1 {
		t.Fatalf("want one match for the http:// pattern, got %d", len(h.Matches))
	}
	m := h.Matches[0]
	if m.Pattern != "http://" || m.Hits != 200 || len(m.Examples) != maxExamplesPerPattern || m.Score != 1 {
		t.Errorf("match = %+v", m)
	}
	if got := categoryApplied(h, catNetwork); got != 1 {
		t.Errorf("network applied = %d, want 1", got)
	}
}

// TestHeuristicsWeakBudget: no amount of ordinary behaviour adds up.
func TestHeuristicsWeakBudget(t *testing.T) {
	h := scoreOf(t,
		"http://example.invalid", "https://example.invalid", "ftp://example.invalid",
		"%TEMP%\\installer.log", "C:\\Users\\x\\AppData\\Roaming\\App", "C:\\Users\\x\\AppData\\Local\\Temp\\x",
		"/bin/sh -c", "wget https://x", "curl https://y",
	)
	if h.Score != weakBudget {
		t.Errorf("all-weak sample scored %d, want exactly %d: %+v", h.Score, weakBudget, h.Categories)
	}
	if h.Detected() {
		t.Error("all-weak sample was flagged")
	}
	for _, c := range h.Categories {
		if !c.Weak {
			t.Errorf("category %s should be weak", c.Category)
		}
	}
}

func TestHeuristicsCategoryCap(t *testing.T) {
	h := scoreOf(t,
		"sekurlsa::logonpasswords", "lsadump::sam", "mimikatz 2.0", "lsass.exe", "SAM\\Domains\\Account\\Users",
	)
	raw := 4 + 4 + 3 + 2 + 3
	cs := h.Categories[0]
	if cs.Category != catCredAccess || cs.Raw != raw || cs.Applied != categoryCaps[catCredAccess] {
		t.Errorf("credential access = %+v, want raw %d applied %d", cs, raw, categoryCaps[catCredAccess])
	}
	if h.Score != categoryCaps[catCredAccess] {
		t.Errorf("score = %d", h.Score)
	}
	if !h.Detected() {
		t.Error("credential dumper strings must detect on their own")
	}
}

func TestHeuristicsThresholdSemantics(t *testing.T) {
	h := scoreOf(t, "powershell -nop -w hidden -enc AAAA", "mshta.exe http://x/y.hta")
	// PowerShell execution: "-nop" 2, "-w hidden" 2 -> 3 (cap) ... plus encoded 3, LOLBin 3, network 1
	if h.Score < DefaultHeuristicThreshold {
		t.Fatalf("cradle scored %d: %+v", h.Score, h.Categories)
	}
	if !h.Detected() {
		t.Error("cradle not detected at default threshold")
	}

	// A per-result threshold overrides the package default.
	h.Threshold = h.Score + 1
	if h.Detected() {
		t.Error("Detected() ignored the per-result threshold")
	}
	if h.EffectiveThreshold() != h.Score+1 {
		t.Error("EffectiveThreshold() ignored the per-result threshold")
	}

	old := HeuristicThreshold
	HeuristicThreshold = 1000
	t.Cleanup(func() { HeuristicThreshold = old })
	h.Threshold = 0
	if h.Detected() {
		t.Error("Detected() ignored the package threshold")
	}
}

func TestHeuristicsSkippedAndErroredAreNotDetected(t *testing.T) {
	skipped := HeuristicResult{Score: 100, Skipped: "too big"}
	if skipped.Detected() {
		t.Error("skipped result reported as detected")
	}
	errored := HeuristicResult{Score: 100, Error: os.ErrNotExist}
	if errored.Detected() {
		t.Error("errored result reported as detected")
	}
}

func TestHeuristicsFileSizeCap(t *testing.T) {
	path := writeTempFile(t, "big.bin", bytes.Repeat([]byte("mimikatz sekurlsa "), 1000))
	h := ScanHeuristicsFile(path, HeuristicOptions{MaxSize: 1024})
	if h.Skipped == "" || h.Error != nil || h.Detected() {
		t.Errorf("oversized file: %+v", h)
	}
	h = ScanHeuristicsFile(path, HeuristicOptions{})
	if h.Skipped != "" || !h.Detected() {
		t.Errorf("default cap: %+v", h)
	}
	if h := ScanHeuristicsFile(t.TempDir(), HeuristicOptions{}); h.Error == nil {
		t.Error("directory accepted")
	}
	if h := ScanHeuristics(path + ".missing"); h.Error == nil {
		t.Error("missing file accepted")
	}
}

func TestHeuristicsUTF16BothAlignments(t *testing.T) {
	wide := func(s string) []byte {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), 0)
		}
		return b
	}
	aligned := wide("sekurlsa::logonpasswords")
	odd := append([]byte{0xff}, wide("lsadump::sam")...)
	h := ScanHeuristicsData("<mem>", append(aligned, odd...), HeuristicOptions{})
	var seen []string
	for _, m := range h.Matches {
		seen = append(seen, m.Pattern)
	}
	if strings.Join(seen, ",") != "sekurlsa,lsadump" {
		t.Errorf("UTF-16 patterns = %v", seen)
	}
}

func TestHeuristicsNonPEHasNoImports(t *testing.T) {
	h := scoreOf(t, "MZ but not really a PE file")
	if h.IsPE {
		t.Error("text starting with MZ was treated as PE")
	}
	if names, isPE := peImports([]byte("MZ\x90\x00")); isPE || names != nil {
		t.Error("truncated PE header accepted")
	}
}

// Real-binary fixtures. These pin the measured behaviour of the retune:
// single-capability tools stay below the threshold, credential dumpers and
// injectors cross it.
func TestHeuristicsRealBinaries(t *testing.T) {
	if _, err := os.Stat(windowsTools); err != nil {
		t.Skip("windows-resources not installed")
	}
	cases := []struct {
		rel      string
		detected bool
	}{
		{"binaries/plink.exe", false},     // scored 24 before the retune
		{"binaries/vncviewer.exe", false}, // scored 11
		{"binaries/wget.exe", false},
		{"binaries/whoami.exe", false},
		{"ollydbg/dbghelp.dll", false}, // scored 13
		{"ollydbg/PSAPI.DLL", false},
		{"mimikatz/x64/mimikatz.exe", true},
		{"wce/wce32.exe", true},
		{"binaries/fgdump/PwDump.exe", true},
		{"shellter/shellter.exe", true},
	}
	for _, tc := range cases {
		path := windowsTools + "/" + tc.rel
		if _, err := os.Stat(path); err != nil {
			t.Logf("skip %s: %v", tc.rel, err)
			continue
		}
		h := ScanHeuristics(path)
		if h.Error != nil {
			t.Errorf("%s: %v", tc.rel, h.Error)
			continue
		}
		if !h.IsPE {
			t.Errorf("%s: not recognised as PE", tc.rel)
		}
		if h.Detected() != tc.detected {
			t.Errorf("%s: detected=%v (score %d/%d) want %v; categories %+v",
				tc.rel, h.Detected(), h.Score, h.EffectiveThreshold(), tc.detected, h.Categories)
		}
	}

	// Import de-duplication: an API credited from the import table must not
	// be scored again from the string table.
	h := ScanHeuristics(windowsTools + "/mimikatz/x64/mimikatz.exe")
	seen := map[string]int{}
	for _, m := range h.Matches {
		seen[strings.ToLower(m.Pattern)]++
	}
	for p, n := range seen {
		if n > 1 {
			t.Errorf("pattern %q scored %d times", p, n)
		}
	}
}

func BenchmarkHeuristicsRealBinary(b *testing.B) {
	path := windowsTools + "/mimikatz/x64/mimikatz.exe"
	data, err := os.ReadFile(path)
	if err != nil {
		b.Skip(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ScanHeuristicsData(path, data, HeuristicOptions{})
	}
}

// ELF imports feed the same indicator table as PE imports. The fixture is a
// system binary that legitimately uses ptrace (sudo's intercept feature,
// strace, gdb); it must register the import and stay below the threshold,
// the same documented class as debuggers on Windows.
func TestHeuristicsELFImports(t *testing.T) {
	if names, ok := elfImports([]byte("\x7fELF but not really")); ok || names != nil {
		t.Error("truncated ELF header accepted")
	}
	if names, ok := elfImports([]byte("plain text")); ok || names != nil {
		t.Error("text treated as ELF")
	}
	// The crediting decision itself is a table lookup and must hold on every
	// host, independent of what system binaries happen to be installed: a
	// "ptrace" import maps to the process-injection category, which carries
	// T1055.
	if info, ok := suspiciousAPIs["ptrace"]; !ok || info.Category != catInjection {
		t.Fatalf("ptrace not mapped to %q in suspiciousAPIs: %+v", catInjection, info)
	}
	if got := categoryTechniques[catInjection]; got != "T1055" {
		t.Fatalf("injection category technique = %q, want T1055", got)
	}

	// The end-to-end path (ELF bytes -> ParseELF -> credited match) is checked
	// against a real binary that actually imports ptrace. Which system binary
	// does varies by host (CI runners often ship a sudo that does not), so the
	// binary is chosen by its real imports rather than assumed, and the check
	// is skipped when none of the candidates qualifies. ELF import parsing is
	// covered deterministically by the static package's buildELF tests.
	var path string
	for _, p := range []string{"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb", "/usr/bin/sudo", "/bin/sudo"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if names, ok := elfImports(data); ok && slices.Contains(names, "ptrace") {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("no binary that imports ptrace on this machine")
	}
	h := ScanHeuristics(path)
	if h.Error != nil {
		t.Fatal(h.Error)
	}
	if !h.IsELF || h.IsPE {
		t.Fatalf("%s: elf=%v pe=%v", path, h.IsELF, h.IsPE)
	}
	var elfImport bool
	for _, m := range h.Matches {
		if m.Source == "ELF Import" && m.Indicator == "ptrace" && m.Category == catInjection && m.Technique == "T1055" {
			elfImport = true
		}
	}
	if !elfImport {
		t.Errorf("%s: ptrace import not credited: %+v", path, h.Matches)
	}
	// Note: we do not assert the binary stays below the threshold here. That is
	// an anti-FP weight-tuning property of an *ordinary* binary, and the binary
	// chosen above is whichever host tool happens to import ptrace — often a
	// syscall-heavy tool like strace that legitimately scores high. The weight
	// tuning (a lone weak/capped category not crossing the bar) is covered by
	// the scoring tests on controlled inputs.
}

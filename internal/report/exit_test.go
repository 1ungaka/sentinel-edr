package report

import (
	"errors"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
)

// scenario is one shape of scan run the exit policy must classify.
type scenario struct {
	name string
	in   Input
}

func scenarios() []scenario {
	return []scenario{
		{"empty", Input{}},
		{"clean", Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{heuristic("a", 0)}}},
		{"heuristic-low", Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{heuristicLow("a")}}},
		{"heuristic-breach", Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{heuristicBreach("a")}}},
		{"yara", Input{Results: []scanner.ScanResult{yaraResult("a")}}},
		{"hash", Input{Results: []scanner.ScanResult{hashResult("a")}}},
		{"file-error", Input{Results: []scanner.ScanResult{errorResult("a")}}},
		{"heuristic-error", Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{heuristicError("a")}}},
		{"run-error", Input{RunError: errors.New("rules did not compile")}},
		{"run-error-with-hash", Input{RunError: errors.New("boom"), Results: []scanner.ScanResult{hashResult("a")}}},
		{"hash-and-file-error", Input{Results: []scanner.ScanResult{hashResult("a"), errorResult("b")}}},
	}
}

func TestExitPolicyMatrix(t *testing.T) {
	// want[level][scenario] with fail-on-scan-error ON (the default).
	want := map[FailOn]map[string]int{
		FailOnNone: {
			"empty": ExitOK, "clean": ExitOK, "heuristic-low": ExitOK, "heuristic-breach": ExitOK,
			"yara": ExitOK, "hash": ExitOK, "file-error": ExitScanFailed, "heuristic-error": ExitScanFailed,
			"run-error": ExitRunFailed, "run-error-with-hash": ExitRunFailed, "hash-and-file-error": ExitScanFailed,
		},
		FailOnMalicious: {
			"empty": ExitOK, "clean": ExitOK, "heuristic-low": ExitOK, "heuristic-breach": ExitOK,
			"yara": ExitThreat, "hash": ExitThreat, "file-error": ExitScanFailed, "heuristic-error": ExitScanFailed,
			"run-error": ExitRunFailed, "run-error-with-hash": ExitRunFailed, "hash-and-file-error": ExitScanFailed,
		},
		FailOnHeuristic: {
			"empty": ExitOK, "clean": ExitOK, "heuristic-low": ExitOK, "heuristic-breach": ExitThreat,
			"yara": ExitThreat, "hash": ExitThreat, "file-error": ExitScanFailed, "heuristic-error": ExitScanFailed,
			"run-error": ExitRunFailed, "run-error-with-hash": ExitRunFailed, "hash-and-file-error": ExitScanFailed,
		},
		FailOnClean: {
			"empty": ExitOK, "clean": ExitOK, "heuristic-low": ExitThreat, "heuristic-breach": ExitThreat,
			"yara": ExitThreat, "hash": ExitThreat, "file-error": ExitScanFailed, "heuristic-error": ExitScanFailed,
			"run-error": ExitRunFailed, "run-error-with-hash": ExitRunFailed, "hash-and-file-error": ExitScanFailed,
		},
	}

	for level, table := range want {
		for _, sc := range scenarios() {
			exp, ok := table[sc.name]
			if !ok {
				t.Fatalf("matrix is missing %s/%s", level, sc.name)
			}
			p := NewExitPolicy(testOpts(WithFailOn(level))...)
			if got := p.Code(sc.in); got != exp {
				t.Errorf("fail-on=%s scenario=%s: code %d, want %d (%s)", level, sc.name, got, exp, p.Explain(sc.in))
			}
			if why := p.Explain(sc.in); !strings.HasPrefix(why, "exit ") || strings.Contains(why, "\n") {
				t.Errorf("fail-on=%s scenario=%s: Explain is not a single 'exit N: ...' line: %q", level, sc.name, why)
			}
		}
	}
}

func TestExitPolicyScanErrorOptOut(t *testing.T) {
	cases := []struct {
		level FailOn
		name  string
		want  int
	}{
		{FailOnMalicious, "file-error", ExitOK},
		{FailOnMalicious, "hash-and-file-error", ExitThreat},
		{FailOnHeuristic, "heuristic-error", ExitOK},
		// A failed heuristic read is still an observation: the run is not spotless.
		{FailOnClean, "heuristic-error", ExitThreat},
		{FailOnNone, "run-error", ExitRunFailed},
	}
	byName := map[string]Input{}
	for _, sc := range scenarios() {
		byName[sc.name] = sc.in
	}
	for _, tc := range cases {
		p := NewExitPolicy(testOpts(WithFailOn(tc.level), WithFailOnScanError(false))...)
		if got := p.Code(byName[tc.name]); got != tc.want {
			t.Errorf("fail-on=%s scan-error-off scenario=%s: code %d, want %d", tc.level, tc.name, got, tc.want)
		}
	}
}

func TestExitPolicyThresholdIsHonoured(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{cleanResult("a")}, Heuristics: []scanner.HeuristicResult{heuristicBreach("a")}} // score 7
	if got := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic), WithHeuristicThreshold(8))...).Code(in); got != ExitOK {
		t.Errorf("threshold 8 vs score 7: code %d, want %d", got, ExitOK)
	}
	if got := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic), WithHeuristicThreshold(7))...).Code(in); got != ExitThreat {
		t.Errorf("threshold 7 vs score 7: code %d, want %d", got, ExitThreat)
	}
}

func TestParseFailOn(t *testing.T) {
	cases := []struct {
		in      string
		want    FailOn
		wantErr bool
	}{
		{"", FailOnMalicious, false},
		{"none", FailOnNone, false},
		{"NONE", FailOnNone, false},
		{" Malicious ", FailOnMalicious, false},
		{"heuristic", FailOnHeuristic, false},
		{"Clean", FailOnClean, false},
		{"strict", FailOnMalicious, true},
		{"mal", FailOnMalicious, true},
	}
	for _, tc := range cases {
		got, err := ParseFailOn(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseFailOn(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseFailOn(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.wantErr && !strings.Contains(err.Error(), "none, malicious, heuristic, clean") {
			t.Errorf("ParseFailOn(%q) error does not list the levels: %v", tc.in, err)
		}
	}
	if FailOn("").String() != "malicious" {
		t.Errorf("zero FailOn should print as malicious, got %q", FailOn("").String())
	}
}

func TestUnknownFailOnFallsBackToMalicious(t *testing.T) {
	p := NewExitPolicy(testOpts(WithFailOn(FailOn("bogus")))...)
	if p.FailOn() != FailOnMalicious {
		t.Fatalf("unknown level normalised to %q, want malicious", p.FailOn())
	}
	if got := p.Code(Input{Results: []scanner.ScanResult{hashResult("a")}}); got != ExitThreat {
		t.Errorf("typo in fail-on silently disabled failure: code %d", got)
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	codes := []int{ExitOK, ExitThreat, ExitScanFailed, ExitRunFailed, ExitUsage}
	seen := map[int]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("exit code %d is used twice", c)
		}
		seen[c] = true
	}
	if ExitOK != 0 {
		t.Error("ExitOK must be 0")
	}
}

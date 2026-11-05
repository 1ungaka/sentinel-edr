package report

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/s-b-repo/cau/scanner"
)

// Shared hermetic fixtures. No test in this package touches the filesystem:
// sizes come from fakeStat and the clock from fixedClock.

var fixedTime = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

func fakeStat(path string) (int64, error) {
	switch {
	case strings.HasSuffix(path, "missing.bin"):
		return 0, errors.New("stat: no such file")
	default:
		return int64(1000 + len(path)), nil
	}
}

// testOpts are the options every reporter in the tests is built with.
func testOpts(extra ...Option) []Option {
	base := []Option{
		WithToolVersion("9.9.9-test"),
		WithClock(fixedClock),
		WithStatFunc(fakeStat),
		WithHeuristicThreshold(3),
	}
	return append(base, extra...)
}

func cleanResult(path string) scanner.ScanResult {
	return scanner.ScanResult{
		FilePath: path,
		MD5:      "d41d8cd98f00b204e9800998ecf8427e",
		SHA1:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		SHA256:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Verdict:  scanner.VerdictClean,
		ScanTime: 12 * time.Millisecond,
	}
}

func hashResult(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Detected = true
	r.MatchType = "SHA256"
	r.MatchHash = r.SHA256
	r.ThreatName = "WannaCry Ransomware"
	r.Verdict = scanner.VerdictMalicious
	return r
}

func yaraMatch() scanner.YaraMatch {
	return scanner.YaraMatch{
		RuleName:  "wannacry_ransomware",
		Namespace: "default",
		Tags:      []string{"ransomware", "apt"},
		Metas: []scanner.YaraMatchMeta{
			{Identifier: "author", Value: "CAU"},
			{Identifier: "description", Value: "Detects WannaCry strings"},
			{Identifier: "threat_level", Value: 3},
			{Identifier: "in_the_wild", Value: false},
		},
		Strings: []scanner.YaraMatchString{
			{Name: "$c", Offset: 0x3a20, Data: []byte("WNcry@2017")},
			{Name: "$d", Offset: 0x5c10, Data: []byte("msg/m_bulgarian.wnry")},
		},
	}
}

func yaraResult(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.YaraMatches = []scanner.YaraMatch{yaraMatch()}
	r.Verdict = scanner.VerdictMalicious
	return r
}

func errorResult(path string) scanner.ScanResult {
	return scanner.ScanResult{
		FilePath: path,
		Verdict:  scanner.VerdictError,
		Error:    errors.New("could not open file: permission denied"),
	}
}

func heuristic(path string, score int, matches ...scanner.HeuristicMatch) scanner.HeuristicResult {
	return scanner.HeuristicResult{FilePath: path, Score: score, Matches: matches}
}

func heuristicLow(path string) scanner.HeuristicResult {
	return heuristic(path, 1, scanner.HeuristicMatch{Indicator: "Sleep", Category: "Timing / Sandbox Evasion", Source: "PE Import"})
}

func heuristicBreach(path string) scanner.HeuristicResult {
	return heuristic(path, 7,
		scanner.HeuristicMatch{Indicator: "WriteProcessMemory", Category: "Process Injection", Source: "PE Import"},
		scanner.HeuristicMatch{Indicator: "CreateRemoteThread", Category: "Process Injection", Source: "PE Import"},
		scanner.HeuristicMatch{Indicator: "cmd.exe /c whoami", Category: "Shell Execution", Source: "String"},
	)
}

func heuristicError(path string) scanner.HeuristicResult {
	return scanner.HeuristicResult{FilePath: path, Error: errors.New("could not read file: EIO")}
}

func bigMatch(n int) scanner.YaraMatchString {
	return scanner.YaraMatchString{Name: "$big", Offset: 42, Data: bytes.Repeat([]byte{0x41}, n)}
}

package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cau-edr/cau/scanner"
)

const textGolden = ` [!] DETECTED (Hash) — samples/wannacry.exe
     SHA256    : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     Match     : WannaCry Ransomware
     Verdict   : MALICIOUS
     Scan time : 12ms

     Also matched 1 YARA rule(s):
     [YARA] default::wannacry_ransomware [apt, ransomware]
            author=CAU threat_level=3 in_the_wild=false desc="Detects WannaCry strings"
            $c @ 0x3a20 : "WNcry@2017"
            $d @ 0x5c10 : "msg/m_bulgarian.wnry"
     Scan time : 12ms

 [!] DETECTED (Heuristics) — samples/wannacry.exe
     Verdict   : SUSPICIOUS
     Score     : 7 / 3 threshold

     [Process Injection]  (T1055)
       [PE Import]    WriteProcessMemory
       [PE Import]    CreateRemoteThread
     [Shell Execution]  (T1059.003)
       [String]       cmd.exe /c whoami

 [CLEAN] samples/notepad.exe
 [~] LOW SUSPICION — samples/notepad.exe (score: 1)

------------------------------------------------------------
 Scan complete         : 1.234s
 Files scanned         : 2
 Hash detections       : 1
 YARA detections       : 1
 Heuristic detections  : 1
 Static detections     : 0
 Stego detections      : 0
 Encoded-exe detections: 0
 Shell-link detections : 0
 OLE-macro detections  : 0
 PDF detections        : 0
 ISO detections        : 0
 Fused-only detections : 0
 Errors                : 0
 Exit code             : 1 (exit 1: 1 file(s) matched a hash signature or YARA rule)
------------------------------------------------------------

 *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***
`

func TestTextGolden(t *testing.T) {
	r := hashResult("samples/wannacry.exe")
	r.YaraMatches = []scanner.YaraMatch{yaraMatch()}
	in := Input{
		Results:    []scanner.ScanResult{r, cleanResult("samples/notepad.exe")},
		Heuristics: []scanner.HeuristicResult{heuristicBreach("samples/wannacry.exe"), heuristicLow("samples/notepad.exe")},
		Elapsed:    1234 * time.Millisecond,
	}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if buf.String() != textGolden {
		t.Errorf("text output differs from golden.\n--- got ---\n%s\n--- want ---\n%s", buf.String(), textGolden)
	}
}

func TestTextCleanRun(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{cleanResult("a.exe")}, Heuristics: []scanner.HeuristicResult{heuristic("a.exe", 0)}}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "[CLEAN] a.exe") != 1 {
		t.Errorf("clean file should be printed exactly once:\n%s", out)
	}
	if !strings.Contains(out, "No threats detected.") || !strings.Contains(out, "Exit code             : 0") {
		t.Errorf("clean summary missing:\n%s", out)
	}
}

func TestTextErrorsAndRunError(t *testing.T) {
	in := Input{
		RunError:   errors.New("rules did not compile"),
		Results:    []scanner.ScanResult{errorResult("locked.bin")},
		Heuristics: []scanner.HeuristicResult{heuristicError("locked.bin"), heuristic("only-heur.bin", 0)},
	}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		" [ERR] rules did not compile",
		" [ERR] locked.bin\n      could not open file: permission denied",
		" [ERR] Heuristics on locked.bin: could not read file: EIO",
		" [CLEAN] only-heur.bin",
		" Errors                : 3",
		" Exit code             : 3",
		" Scan did not run.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestTextTruncatesLongMatchData(t *testing.T) {
	r := cleanResult("a")
	m := yaraMatch()
	m.Strings = []scanner.YaraMatchString{bigMatch(100)}
	r.YaraMatches = []scanner.YaraMatch{m}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"`+strings.Repeat("A", 32)+`"...`) {
		t.Errorf("match data not cut at 32 bytes:\n%s", buf.String())
	}
}

func TestTextHostileNamesStayPrintable(t *testing.T) {
	r := hashResult("evil\x1b[31m\xff.exe")
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\xff") {
		t.Error("invalid UTF-8 leaked into text output")
	}
}

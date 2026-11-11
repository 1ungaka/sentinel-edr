package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner"
)

func textFor(t *testing.T, r scanner.ScanResult) string {
	t.Helper()
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{r}}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// A file name is whatever the attacker wants it to be. Written raw, it can erase
// its own report line, print a forged verdict, or hide everything after it.
func TestTextOutputCannotBeRewrittenByAFileName(t *testing.T) {
	for name, path := range map[string]string{
		"escape":    "evil\x1b[2K\r [CLEAN] harmless.txt\x1b[8m",
		"newline":   "evil\n [CLEAN] forged-line",
		"c1-csi":    "evil\u009b2Kx",
		"raw-c1":    "evil\x9b2Kx",
		"osc52":     "evil\x1b]52;c;aGk=\x07",
		"backspace": "evil\x08\x08\x08\x08good",
		"bidi":      "evil\u202etxt.exe",
	} {
		t.Run(name, func(t *testing.T) {
			out := textFor(t, hashResult(path))
			if strings.ContainsAny(out, "\x1b\r\x07\x08\u009b\u202e") || strings.Contains(out, "\x9b") {
				t.Fatalf("control character reached the terminal: %q", out)
			}
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, " [CLEAN]") {
					t.Fatalf("forged a report line: %q", line)
				}
			}
		})
	}
}

// Errors embed the path, so they carry the same control characters.
func TestTextErrorsAreEscapedToo(t *testing.T) {
	out := textFor(t, scanner.ScanResult{
		FilePath: "plain",
		Verdict:  scanner.VerdictError,
		Error:    errors.New("open evil\x1b[2K: permission denied"),
	})
	if strings.Contains(out, "\x1b") {
		t.Fatalf("control character reached the terminal: %q", out)
	}
}

func TestTermSafeKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{"/usr/bin/ls", "Überprüfung – 文件.txt", `C:\Windows\System32\cmd.exe`, "bad\ufffdbyte", ""} {
		if got := TermSafe(s); got != s {
			t.Errorf("TermSafe(%q) = %q", s, got)
		}
	}
}

// The escape must stay readable: an analyst has to be able to tell two names
// apart and find the file.
func TestTermSafeShowsWhatItEscaped(t *testing.T) {
	for in, want := range map[string]string{
		"a\x1bb":   `a\x1bb`,
		"a\nb":     `a\nb`,
		"a\xffb":   `a\xffb`,
		"a\u202eb": `a\u202eb`,
	} {
		if got := TermSafe(in); got != want {
			t.Errorf("TermSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

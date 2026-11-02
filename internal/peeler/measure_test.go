package peeler

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestMeasureRealPeel measures the peeler's false-positive rate on a real
// benign population: every file under the configured roots is peeled, and any
// outcome other than "clean" is a false positive (these trees ship no malware).
// A "revealed-executable"/"revealed-script" on a benign file is the serious FP;
// "peel-exhausted" is a soft FP (the budget was hit on legitimate nesting). The
// test prints the offenders so the gates can be tuned, and is skipped when the
// trees are absent, like the other measurement tests.
func TestMeasureRealPeel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-population measurement in -short mode")
	}
	roots := []string{
		"/usr/bin",
		"/usr/share/doc",
		"/usr/lib/python3/dist-packages",
		"/usr/share/nmap",
	}
	const maxFile = 8 << 20

	p := New()
	scanned := 0
	byOutcome := map[Outcome]int{}
	var hardFP []string
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxFile {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			scanned++
			r := p.Peel(context.Background(), data)
			if r.Outcome != OutcomeClean {
				byOutcome[r.Outcome]++
				if (r.Outcome == OutcomeRevealedExecutable || r.Outcome == OutcomeRevealedScript) && len(hardFP) < 50 {
					hardFP = append(hardFP, path+"  sig="+r.PrimarySignature)
				}
			}
			return nil
		})
	}
	if scanned == 0 {
		t.Skip("no benign population to measure")
	}
	hard := byOutcome[OutcomeRevealedExecutable] + byOutcome[OutcomeRevealedScript]
	t.Logf("peeler over %d benign files:", scanned)
	for _, o := range []Outcome{OutcomeRevealedExecutable, OutcomeRevealedScript, OutcomePeelExhausted} {
		t.Logf("  %-22s %d", o, byOutcome[o])
	}
	t.Logf("hard FP (revealed payload on benign): %d / %d (%.4f%%)", hard, scanned, 100*float64(hard)/float64(scanned))
	for _, o := range hardFP {
		t.Logf("  hard-FP: %s", o)
	}
}

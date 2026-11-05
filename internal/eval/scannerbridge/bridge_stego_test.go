package scannerbridge

import (
	"path/filepath"
	"testing"

	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/scanner"
)

func TestStegoDetector(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "README.md")
	hidden := filepath.Join(dir, "NOTES.md")
	blob := filepath.Join(dir, "blob.bin")
	if err := writeFile(clean, "# Title\n\nPlain prose.\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(hidden, "Plain\u200b prose\u200b with\u200b stray\u200b codepoints.\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(blob, "MZ\x00\x00\u200b"); err != nil {
		t.Fatal(err)
	}
	d := StegoDetector(0)
	if d.Name() != eval.DetectorStego {
		t.Errorf("name = %s", d.Name())
	}
	for _, path := range []string{clean, blob} {
		f, err := d.ScanFile(path)
		if err != nil || f.Detected() || f.Verdict != eval.VerdictClean {
			t.Errorf("%s: %+v %v", path, f, err)
		}
	}
	f, err := d.ScanFile(hidden)
	if err != nil || !f.Detected() || f.Verdict != eval.VerdictSuspicious {
		t.Fatalf("hidden: %+v %v", f, err)
	}
	rules := map[string]bool{}
	for _, s := range f.Signals {
		rules[s.Rule] = true
		if s.Detector != eval.DetectorStego {
			t.Errorf("signal detector = %s", s.Detector)
		}
	}
	if !rules["stego/score"] || !rules["stego/zero-width"] || !rules["stego/ascii-carrier"] {
		t.Errorf("rules = %v", rules)
	}
	// A raised threshold turns presence into "needs a modifier".
	if f, _ := StegoDetector(9).ScanFile(hidden); f.Detected() {
		t.Error("threshold 9 should not fire on four stray codepoints without a payload run")
	}
	if _, err := d.ScanFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file should be an error")
	}
}

func TestFusionDetectorReportsOnlyCorroboration(t *testing.T) {
	dir := t.TempDir()
	// Heuristic evidence below its threshold (3 + 3 = 6 < 7) plus one stray
	// zero-width codepoint below a raised stego threshold: neither fires
	// alone, the lattice does.
	fused := filepath.Join(dir, "loader.txt")
	alone := filepath.Join(dir, "alone.txt")
	clean := filepath.Join(dir, "clean.txt")
	if err := writeFile(fused, "powershell -enc AAAA mshta.exe\u200b\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(alone, "powershell -enc AAAA mshta.exe http://x\n"); err != nil { // 7/7 alone
		t.Fatal(err)
	}
	if err := writeFile(clean, "nothing here\n"); err != nil {
		t.Fatal(err)
	}
	e := &scanner.Engine{DB: scanner.NewSignatureDB(), Heuristics: true, Stego: true, StegoThreshold: 10}
	d := FusionDetector(e)
	if d.Name() != eval.DetectorFusion {
		t.Errorf("name = %s", d.Name())
	}
	f, err := d.ScanFile(fused)
	if err != nil || !f.Detected() || f.Verdict != eval.VerdictSuspicious {
		t.Fatalf("fused: %+v %v", f, err)
	}
	rules := map[string]bool{}
	for _, s := range f.Signals {
		rules[s.Rule] = true
	}
	if !rules["fusion/corroborated"] || !rules["fusion/agreed/heuristic"] || !rules["fusion/agreed/stego"] {
		t.Errorf("rules = %v", rules)
	}
	// A detector that fires on its own is that detector's recall, not fusion's.
	if f, _ := d.ScanFile(alone); f.Detected() {
		t.Errorf("fusion claimed a heuristic-only breach: %+v", f)
	}
	if f, _ := d.ScanFile(clean); f.Detected() {
		t.Errorf("fusion fired on clean: %+v", f)
	}
	if _, err := FusionDetector(nil).ScanFile(clean); err == nil {
		t.Error("nil engine must be a configuration error")
	}
}

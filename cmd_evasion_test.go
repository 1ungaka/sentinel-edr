package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// The report measures the shipped detections on one file: the bytes that must
// change for each detector to stop firing, and never a patched sample.
func TestEvasionReportMeasuresOneFile(t *testing.T) {
	code, out, errOut := runCLI(t, "evasion", "report", "--file", smokeHashHit,
		"--db", smokeDB, "--rules", "rules")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "evasion report") {
		t.Errorf("the report says nothing about itself:\n%s", out)
	}
	if !strings.Contains(out, "hash") {
		t.Errorf("the hash detection is missing from the report:\n%s", out)
	}
	if !strings.Contains(out, "byte") {
		t.Errorf("the report does not state a distance:\n%s", out)
	}
}

// The JSON form carries the same numbers.
func TestEvasionReportJSON(t *testing.T) {
	code, out, errOut := runCLI(t, "evasion", "report", "--file", smokeHashHit,
		"--db", smokeDB, "--rules", "rules", "--format", "json")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	var rep struct {
		Path      string `json:"path"`
		Verdict   string `json:"verdict"`
		Lower     int    `json:"lower_bound_bytes"`
		Upper     int    `json:"upper_bound_bytes"`
		Detectors []struct {
			Name      string `json:"name"`
			Distance  int    `json:"distance_bytes"`
			Derivable bool   `json:"distance_derivable"`
		} `json:"detectors"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, out)
	}
	if len(rep.Detectors) == 0 {
		t.Fatalf("no detector was measured:\n%s", out)
	}
	if rep.Lower < 1 {
		t.Errorf("the lower bound is %d, want at least 1", rep.Lower)
	}
	found := false
	for _, d := range rep.Detectors {
		if d.Name == "hash" && d.Derivable && d.Distance == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("the hash detection was not measured as one byte:\n%s", out)
	}
}

// The report never carries a patch: no offset, no matched bytes.
func TestEvasionReportCarriesNoPatch(t *testing.T) {
	code, out, errOut := runCLI(t, "evasion", "report", "--file", smokeHashHit,
		"--db", smokeDB, "--rules", "rules", "--format", "json")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	for _, leak := range []string{"offset", "\"data\""} {
		if strings.Contains(out, leak) {
			t.Errorf("the report carries %q:\n%s", leak, out)
		}
	}
}

// The bench measures a corpus per detector.
func TestEvasionBenchMeasuresACorpus(t *testing.T) {
	code, out, errOut := runCLI(t, "evasion", "bench", "--corpus", "corpus/smoke/manifest.json",
		"--db", smokeDB, "--rules", "rules")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "evasion bench") {
		t.Errorf("the bench says nothing about itself:\n%s", out)
	}
	if !strings.Contains(out, "samples") {
		t.Errorf("the bench does not count the samples:\n%s", out)
	}
}

// The bench refuses a corpus it cannot read, rather than reporting nothing.
func TestEvasionBenchNeedsACorpus(t *testing.T) {
	code, _, errOut := runCLI(t, "evasion", "bench")
	if code != report.ExitUsage {
		t.Errorf("code=%d, want a usage error", code)
	}
	if !strings.Contains(errOut, "corpus") {
		t.Errorf("the error does not say what is missing: %s", errOut)
	}
}

// The report needs a file.
func TestEvasionReportNeedsAFile(t *testing.T) {
	code, _, errOut := runCLI(t, "evasion", "report")
	if code != report.ExitUsage {
		t.Errorf("code=%d, want a usage error", code)
	}
	if !strings.Contains(errOut, "file") {
		t.Errorf("the error does not say what is missing: %s", errOut)
	}
}

// A file that does not exist is an error, not an empty report.
func TestEvasionReportOnAMissingFile(t *testing.T) {
	code, _, errOut := runCLI(t, "evasion", "report", "--file", filepath.Join(t.TempDir(), "nope.bin"))
	if code != report.ExitRunFailed {
		t.Errorf("code=%d, want a run failure", code)
	}
	if errOut == "" {
		t.Error("the failure said nothing")
	}
}

// The bench works on a corpus the operator supplies: the manifest is the
// evaluation harness's own format, so the numbers come from the same corpus
// the recall figures are published from.
func TestEvasionBenchAcceptsAnOperatorCorpus(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(sample, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":"1","name":"t","samples":[{"id":"s1","path":"sample.bin","label":"clean"}]}`
	mp := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mp, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "evasion", "bench", "--corpus", mp, "--db", smokeDB, "--rules", "rules")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "samples  : 1") {
		t.Errorf("the bench did not measure the sample:\n%s", out)
	}
}

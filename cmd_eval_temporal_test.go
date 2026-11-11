package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// The temporal gate measures the shipped content on both sides of a period
// boundary and fails when the recall drops across it.
func TestCLIEvalTemporal(t *testing.T) {
	code, out, errOut := runCLI(t, "eval", "temporal", "--corpus", "corpus/smoke/manifest.json",
		"--db", smokeDB, "--rules", "rules", "--quiet")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "temporal generalization") {
		t.Errorf("the measurement says nothing about itself:\n%s", out)
	}
	if !strings.Contains(out, "temporal gate:") {
		t.Errorf("the gate said nothing:\n%s", out)
	}
	if !strings.Contains(out, "recall drop across the boundary") {
		t.Errorf("the drop was not stated:\n%s", out)
	}
}

// The JSON form carries the measurement and the decision.
func TestCLIEvalTemporalJSON(t *testing.T) {
	code, out, errOut := runCLI(t, "eval", "temporal", "--corpus", "corpus/smoke/manifest.json",
		"--db", smokeDB, "--rules", "rules", "--quiet", "--format", "json")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	var payload struct {
		Measurement struct {
			Split   string   `json:"split"`
			Periods []string `json:"periods"`
		} `json:"measurement"`
		Decision struct {
			Pass bool `json:"pass"`
		} `json:"decision"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, out)
	}
	if len(payload.Measurement.Periods) < 2 {
		t.Errorf("the corpus declares %d period(s):\n%s", len(payload.Measurement.Periods), out)
	}
	if !payload.Decision.Pass {
		t.Errorf("the gate failed on the committed corpus:\n%s", out)
	}
}

// A corpus with one period has no boundary: the gate says so instead of
// measuring nothing.
func TestCLIEvalTemporalNeedsTwoPeriods(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(sample, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":"1","name":"t","samples":[{"id":"s1","path":"s.bin","label":"clean","period":"2026-01"}]}`
	mp := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mp, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "eval", "temporal", "--corpus", mp, "--db", smokeDB, "--rules", "rules", "--quiet")
	if code != report.ExitRunFailed {
		t.Errorf("code=%d, want a run failure", code)
	}
	if !strings.Contains(errOut, "period") {
		t.Errorf("the error does not say what is missing: %s", errOut)
	}
}

// The gate fails when the content loses recall across the boundary, and the
// failure is the exit status a CI lane reads.
func TestCLIEvalTemporalFailsOnADrop(t *testing.T) {
	dir := t.TempDir()
	// The early period holds a sample the signature database knows; the later
	// one holds a malware sample nothing catches. The recall drops across
	// the boundary.
	known, err := os.ReadFile(smokeHashHit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known.bin"), known, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unknown.bin"), []byte("nothing to see here"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":"1","name":"t","samples":[` +
		`{"id":"known","path":"known.bin","label":"smoke_hash","period":"2026-01"},` +
		`{"id":"unknown","path":"unknown.bin","label":"undetected","period":"2026-02"}]}`
	mp := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mp, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "eval", "temporal", "--corpus", mp, "--db", smokeDB, "--rules", "rules", "--quiet")
	if code != report.ExitThreat {
		t.Fatalf("code=%d, want the gate to fail (exit %d)\n%s\n%s", code, report.ExitThreat, out, errOut)
	}
	if !strings.Contains(out, "temporal gate: FAIL") {
		t.Errorf("the failure was not stated:\n%s", out)
	}
}

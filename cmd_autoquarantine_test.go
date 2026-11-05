package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/fusion"
)

// TestCLIScanAutoQuarantine confirms the free-prevention path: a scan with
// --quarantine moves a confirmed-malicious file into the vault, and leaves a
// clean file untouched.
func TestCLIScanAutoQuarantine(t *testing.T) {
	work := t.TempDir()
	vault := filepath.Join(work, "vault")

	// A file whose SHA-256 is in the smoke DB (copy of the committed sample).
	malData, err := os.ReadFile(smokeHashHit)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	mal := filepath.Join(work, "evil.bin")
	os.WriteFile(mal, malData, 0o644)
	clean := filepath.Join(work, "clean.txt")
	os.WriteFile(clean, []byte("totally benign text\n"), 0o644)

	code, _, errOut := runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara",
		"--quarantine", "--quarantine-store", vault, mal, clean)
	// hash hit → ExitThreat; the quarantine action runs regardless of exit code.
	if code != report.ExitThreat {
		t.Fatalf("scan: code=%d (want %d) err=%s", code, report.ExitThreat, errOut)
	}
	// The malicious file was moved out.
	if _, err := os.Stat(mal); !os.IsNotExist(err) {
		t.Errorf("malicious file was not moved: %v", err)
	}
	// The clean file is untouched.
	if _, err := os.Stat(clean); err != nil {
		t.Errorf("clean file was disturbed: %v", err)
	}
	// Exactly one vault entry, pointing at the malicious file.
	_, out, _ := runCLI(t, "quarantine", "list", "--store", vault, "--format", "json")
	var entries []struct {
		OriginalPath string `json:"original_path"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("list json: %v (%s)", err, out)
	}
	if len(entries) != 1 || entries[0].OriginalPath != mal {
		t.Fatalf("unexpected vault contents: %+v", entries)
	}
}

// TestQuarantineReasonScoreBased pins the auto-block decision: the hard
// MALICIOUS verdict always blocks, but a file that only reached the fused
// SUSPICIOUS tier (multi-indicator score, no single definitive hit) blocks
// solely under --quarantine-level suspicious, and the recorded label carries
// the score and the indicators that drove it.
func TestQuarantineReasonScoreBased(t *testing.T) {
	// A fused-suspicious result: no hash/YARA hit, verdict stays CLEAN, but the
	// lattice crossed its threshold on corroborating indicators.
	suspicious := scanner.ScanResult{
		FilePath: "sample.bin",
		Verdict:  scanner.VerdictClean,
		Fusion: &fusion.Verdict{
			Tier:       fusion.TierSuspicious,
			Score:      1.20,
			Threshold:  1.00,
			Agreed:     []string{"static", "encchain"},
			Techniques: []string{"T1027"},
		},
	}
	// A hard hit: hash signature fired, verdict MALICIOUS.
	malicious := scanner.ScanResult{
		FilePath:   "evil.bin",
		Verdict:    scanner.VerdictMalicious,
		ThreatName: "Win.Trojan.Agent",
	}
	// Evidence below the bar: observed, never blocked.
	observed := scanner.ScanResult{
		FilePath: "noisy.bin",
		Verdict:  scanner.VerdictClean,
		Fusion:   &fusion.Verdict{Tier: fusion.TierObserved, Score: 0.4, Threshold: 1.0},
	}

	// MALICIOUS blocks at either level.
	for _, level := range []string{"malicious", "suspicious"} {
		if label, hit := quarantineReason(malicious, level); !hit || label != "Win.Trojan.Agent" {
			t.Errorf("malicious at level %q: hit=%v label=%q, want true/Win.Trojan.Agent", level, hit, label)
		}
	}

	// A fused-suspicious file is left alone at the default (malicious) level...
	if label, hit := quarantineReason(suspicious, "malicious"); hit {
		t.Errorf("suspicious at level malicious: blocked (label=%q), want skipped", label)
	}
	// ...and blocked at the suspicious level, with an evidence-bearing label.
	label, hit := quarantineReason(suspicious, "suspicious")
	if !hit {
		t.Fatalf("suspicious at level suspicious: not blocked, want blocked")
	}
	for _, want := range []string{"1.20", "1.00", "static+encchain", "T1027"} {
		if !strings.Contains(label, want) {
			t.Errorf("label %q missing %q", label, want)
		}
	}

	// Observed never blocks, even at the suspicious level.
	if label, hit := quarantineReason(observed, "suspicious"); hit {
		t.Errorf("observed at level suspicious: blocked (label=%q), want skipped", label)
	}
}

func TestCLIScanNoQuarantineByDefault(t *testing.T) {
	work := t.TempDir()
	malData, _ := os.ReadFile(smokeHashHit)
	mal := filepath.Join(work, "evil.bin")
	os.WriteFile(mal, malData, 0o644)

	// Without --quarantine, a malicious file must NOT be moved.
	runCLI(t, "scan", "--quiet", "--db", smokeDB, "--no-yara", mal)
	if _, err := os.Stat(mal); err != nil {
		t.Errorf("file was moved without --quarantine: %v", err)
	}
}

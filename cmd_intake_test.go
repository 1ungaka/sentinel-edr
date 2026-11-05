package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

const (
	testSHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
	testSHA1   = "2222222222222222222222222222222222222222"
)

func TestCLIIntakeDryRun(t *testing.T) {
	work := t.TempDir()
	feed := filepath.Join(work, "drivers.json")
	os.WriteFile(feed, []byte(`[{"Id":"x","KnownVulnerableSamples":[{"SHA256":"`+testSHA256+`","Filename":"evil.sys"}]}]`), 0o644)

	code, out, errOut := runCLI(t, "intake", "--format", "loldrivers", "--input", feed, "--dry-run")
	if code != report.ExitOK {
		t.Fatalf("intake dry-run: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "SHA256|"+testSHA256+"|") {
		t.Errorf("dry-run output missing signature line:\n%s", out)
	}
	if !strings.Contains(out, "evil.sys") {
		t.Errorf("dry-run output missing driver label:\n%s", out)
	}
}

func TestCLIIntakeAppendsToDB(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("9", 64)+"|Seed\n"), 0o644)
	feed := filepath.Join(work, "mb.json")
	os.WriteFile(feed, []byte(`{"query_status":"ok","data":[{"sha256_hash":"`+testSHA256+`","signature":"AgentTesla"}]}`), 0o644)

	code, out, errOut := runCLI(t, "intake", "--format", "malwarebazaar", "--input", feed, "--db", db)
	if code != report.ExitOK {
		t.Fatalf("intake append: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "appended 1") {
		t.Errorf("unexpected output: %q", out)
	}
	content, _ := os.ReadFile(db)
	if !strings.Contains(string(content), "SHA256|"+testSHA256+"|AgentTesla") {
		t.Errorf("db not appended:\n%s", content)
	}
	// Second run is a no-op (already present).
	code, out, _ = runCLI(t, "intake", "--format", "malwarebazaar", "--input", feed, "--db", db)
	if code != report.ExitOK || !strings.Contains(out, "nothing new") {
		t.Errorf("second run should be a no-op: code=%d out=%q", code, out)
	}
}

func TestCLIIntakeOutputFile(t *testing.T) {
	work := t.TempDir()
	feed := filepath.Join(work, "stix.json")
	os.WriteFile(feed, []byte(`{"type":"bundle","objects":[{"type":"indicator","name":"X","pattern":"[file:hashes.'SHA-1'='`+testSHA1+`']"}]}`), 0o644)
	out := filepath.Join(work, "new.txt")

	code, _, errOut := runCLI(t, "intake", "--format", "stix", "--input", feed, "--output", out)
	if code != report.ExitOK {
		t.Fatalf("intake --output: code=%d err=%s", code, errOut)
	}
	content, _ := os.ReadFile(out)
	if !strings.Contains(string(content), "SHA1|"+testSHA1+"|X") {
		t.Errorf("output file wrong:\n%s", content)
	}
}

func TestCLIIntakeUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "intake"); code != report.ExitUsage {
		t.Errorf("no format: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "stix"); code != report.ExitUsage {
		t.Errorf("no input/url: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "stix", "--input", "a", "--url", "http://x"); code != report.ExitUsage {
		t.Errorf("both input and url: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "bogus", "--input", "/dev/null"); code != report.ExitRunFailed && code != report.ExitUsage {
		t.Errorf("bad format: code=%d", code)
	}
}

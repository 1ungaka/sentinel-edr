package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

const (
	smokeManifest = "corpus/smoke/manifest.json"
	smokeDB       = "corpus/smoke/hashes.txt"
	smokeHashHit  = "corpus/smoke/malicious/hash_only.bin"
	smokeYaraHit  = "corpus/smoke/malicious/wannacry_strings.bin"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, report.ExitUsage},
		{"unknown command", []string{"bogus"}, report.ExitUsage},
		{"version", []string{"version"}, report.ExitOK},
		{"scan nothing", []string{"scan", "--quiet"}, report.ExitUsage},
		{"scan bad format", []string{"scan", "--quiet", "--format", "yaml", "LICENSE"}, report.ExitUsage},
		{"scan bad fail-on", []string{"scan", "--quiet", "--fail-on", "sometimes", "LICENSE"}, report.ExitUsage},
		{"scan clean", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "rules", "LICENSE"}, report.ExitOK},
		{"scan hash hit", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "rules", smokeHashHit}, report.ExitThreat},
		{"scan yara hit", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "rules", smokeYaraHit}, report.ExitThreat},
		{"scan hit fail-on none", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "rules", "--fail-on", "none", smokeHashHit}, report.ExitOK},
		{"scan missing file", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "/definitely/not/here"}, report.ExitScanFailed},
		{"scan missing file tolerated", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--no-fail-on-scan-error", "/definitely/not/here"}, report.ExitOK},
		{"scan bad rules", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "/no/rules/here", "LICENSE"}, report.ExitRunFailed},
		{"scan bad db", []string{"scan", "--quiet", "--db", "/no/db/here", "LICENSE"}, report.ExitRunFailed},
		{"eval no sub", []string{"eval"}, report.ExitUsage},
		{"eval validate", []string{"eval", "validate", "--corpus", smokeManifest, "--verify-hashes"}, report.ExitOK},
		{"eval validate missing", []string{"eval", "validate", "--corpus", "/no/manifest.json"}, report.ExitRunFailed},
		{"eval policy", []string{"eval", "policy"}, report.ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, out, errOut)
			}
		})
	}
}

func TestCLIJSONReportOnRunFailure(t *testing.T) {
	code, out, _ := runCLI(t, "scan", "--quiet", "--format", "json", "--db", "/no/db", "LICENSE")
	if code != report.ExitRunFailed {
		t.Fatalf("exit %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if doc["run_error"] == nil {
		t.Errorf("run_error missing from %v", doc)
	}
}

func TestCLIStdoutIsCleanForMachineFormats(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		// Without --quiet the banner must still go to stderr, never stdout.
		code, out, errOut := runCLI(t, "scan", "--format", format, "--db", smokeDB, "--rules", "rules", smokeHashHit)
		if code != report.ExitThreat {
			t.Errorf("%s: exit %d", format, code)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), "{") {
			t.Errorf("%s: stdout does not start with a JSON document:\n%s", format, out)
		}
		if !strings.Contains(errOut, toolName) {
			t.Errorf("%s: banner not on stderr", format)
		}
	}
}

func TestCLIEvalRunGateAndDiff(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	cand := filepath.Join(dir, "cand.json")

	if code, out, errOut := runCLI(t, "eval", "run", "--corpus", smokeManifest, "--rules", "rules", "--out", base, "--quiet"); code != 0 {
		t.Fatalf("eval run: exit %d\n%s\n%s", code, out, errOut)
	}
	if code, out, errOut := runCLI(t, "eval", "run", "--corpus", smokeManifest, "--rules", "rules", "--no-yara", "--out", cand, "--quiet"); code != 0 {
		t.Fatalf("eval run (no yara): exit %d\n%s\n%s", code, out, errOut)
	}

	code, out, _ := runCLI(t, "eval", "gate", "--baseline", base, "--candidate", base)
	if code != 0 || !strings.Contains(out, "PASS") {
		t.Errorf("self-gate: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "eval", "gate", "--baseline", base, "--candidate", cand)
	if code != report.ExitThreat || !strings.Contains(out, "max_recall_drop") {
		t.Errorf("regression gate: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "eval", "diff", base, cand)
	if code != 0 || !strings.Contains(out, "recall -") {
		t.Errorf("diff: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "eval", "report", base)
	if code != 0 || !strings.Contains(out, "confusion matrix") {
		t.Errorf("report: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "eval", "gate", "--baseline", base, "--candidate", cand, "--format", "json")
	var doc map[string]any
	if code != report.ExitThreat || json.Unmarshal([]byte(out), &doc) != nil || doc["decision"] == nil {
		t.Errorf("gate json: exit %d\n%s", code, out)
	}
}

func TestResourceDiscovery(t *testing.T) {
	// Explicit wins over everything.
	if p, _ := findResource("/x/y", envRules, relRules); p != "/x/y" {
		t.Errorf("explicit: %q", p)
	}
	// Environment wins over the search path.
	t.Setenv(envRules, "/from/env")
	if p, _ := findResource("", envRules, relRules); p != "/from/env" {
		t.Errorf("env: %q", p)
	}
	t.Setenv(envRules, "")
	// The working directory (this repo) holds rules/ and signatures/hashes.txt.
	if p, searched := findResource("", envRules, relRules); p == "" {
		t.Errorf("rules not found in cwd; searched %v", searched)
	}
	if p, _ := findResource("", envSignatures, relSignatures); p == "" || !strings.HasSuffix(p, filepath.FromSlash(relSignatures)) {
		t.Errorf("signatures: %q", p)
	}
	if _, searched := findResource("", envRules, "does/not/exist"); len(searched) == 0 {
		t.Error("search list empty for a missing resource")
	}
	if _, err := os.Stat("rules"); err != nil {
		t.Fatal("tests must run from the repository root")
	}
}

func TestCLIStaticCommands(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.bin")
	data := make([]byte, 20000)
	for i := range data {
		data[i] = byte(i*31 + i/7)
	}
	if err := os.WriteFile(sample, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fuzzy := filepath.Join(dir, "fuzzy.txt")

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"hash no args", []string{"hash"}, report.ExitUsage},
		{"hash bad format", []string{"hash", "--format", "yaml", sample}, report.ExitUsage},
		{"hash ok", []string{"hash", sample}, report.ExitOK},
		{"hash json", []string{"hash", "--format", "json", sample}, report.ExitOK},
		{"hash missing", []string{"hash", "/no/such/file"}, report.ExitScanFailed},
		{"add-fuzzy no name", []string{"add-fuzzy", "--db", fuzzy, "--file", sample}, report.ExitUsage},
		{"add-fuzzy file", []string{"add-fuzzy", "--db", fuzzy, "--file", sample, "--name", "Synthetic Family"}, report.ExitOK},
		{"add-fuzzy duplicate", []string{"add-fuzzy", "--db", fuzzy, "--file", sample, "--name", "Synthetic Family"}, report.ExitRunFailed},
		{"add-fuzzy bad digest", []string{"add-fuzzy", "--db", fuzzy, "--type", "TLSH", "--hash", "nope", "--name", "x"}, report.ExitRunFailed},
		{"add-fuzzy missing file", []string{"add-fuzzy", "--db", fuzzy, "--file", "/no/such", "--name", "x"}, report.ExitRunFailed},
		{"cluster no args", []string{"cluster"}, report.ExitUsage},
		{"cluster bad sim", []string{"cluster", "--min-similarity", "2", dir}, report.ExitUsage},
		{"cluster dir", []string{"cluster", dir}, report.ExitOK},
		{"cluster json", []string{"cluster", "--format", "json", "--imphashes", dir}, report.ExitOK},
		{"cluster missing", []string{"cluster", "/no/such/dir"}, report.ExitRunFailed},
		{"scan bad static threshold", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--static-threshold", "0", "LICENSE"}, report.ExitUsage},
		{"scan bad fuzzy db", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--fuzzy-db", "/no/fuzzy.txt", "LICENSE"}, report.ExitRunFailed},
		{"scan no static", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--no-static", "LICENSE"}, report.ExitOK},
		// The sample is in the fuzzy db now: a similarity hit is the heuristic tier.
		{"scan fuzzy hit malicious", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--fuzzy-db", fuzzy, sample}, report.ExitOK},
		{"scan fuzzy hit heuristic", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--fuzzy-db", fuzzy, "--fail-on", "heuristic", sample}, report.ExitThreat},
		{"scan fuzzy hit no-fuzzy", []string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--fuzzy-db", fuzzy, "--no-fuzzy", "--fail-on", "heuristic", sample}, report.ExitOK},
		{"eval run static", []string{"eval", "run", "--corpus", smokeManifest, "--rules", "rules", "--quiet"}, report.ExitOK},
		{"eval run no static", []string{"eval", "run", "--corpus", smokeManifest, "--rules", "rules", "--no-static", "--quiet"}, report.ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, out, errOut)
			}
		})
	}

	// hash output carries every digest.
	_, out, _ := runCLI(t, "hash", "--format", "json", sample)
	var recs []map[string]any
	if err := json.Unmarshal([]byte(out), &recs); err != nil || len(recs) != 1 {
		t.Fatalf("hash json: %v\n%s", err, out)
	}
	for _, k := range []string{"sha256", "tlsh", "ssdeep"} {
		if s, _ := recs[0][k].(string); s == "" {
			t.Errorf("hash json missing %s: %v", k, recs[0])
		}
	}

	// scan JSON carries the static object and the similarity match.
	_, out, _ = runCLI(t, "scan", "--quiet", "--format", "json", "--db", smokeDB, "--no-yara", "--fuzzy-db", fuzzy, sample)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("scan json: %v\n%s", err, out)
	}
	if doc["schema_version"] != report.JSONSchemaVersion {
		t.Errorf("schema = %v", doc["schema_version"])
	}
	files := doc["files"].([]any)
	st, _ := files[0].(map[string]any)["static"].(map[string]any)
	if st == nil || st["detected"] != true || st["fuzzy_matches"] == nil {
		t.Errorf("static object = %v", st)
	}
	if doc["summary"].(map[string]any)["static_detections"] != float64(1) {
		t.Errorf("summary = %v", doc["summary"])
	}
}

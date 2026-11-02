package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cau-edr/cau/internal/report"
)

func TestCLICoverageAndRules(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
		out  string
	}{
		{"coverage text", []string{"coverage", "--quiet", "--rules", "rules", "--db", smokeDB}, report.ExitOK, "T1003"},
		{"coverage json", []string{"coverage", "--quiet", "--rules", "rules", "--format", "json"}, report.ExitOK, `"techniques"`},
		{"coverage navigator", []string{"coverage", "--quiet", "--rules", "rules", "--format", "navigator"}, report.ExitOK, `"enterprise-attack"`},
		{"coverage sarif", []string{"coverage", "--quiet", "--rules", "rules", "--format", "sarif"}, report.ExitOK, `sarif-2.1.0`},
		{"coverage no yara", []string{"coverage", "--quiet", "--no-yara", "--db", smokeDB}, report.ExitOK, "no ruleset loaded"},
		{"coverage gate ok", []string{"coverage", "--quiet", "--rules", "rules", "--expect", "baselines/attack-coverage.txt"}, report.ExitOK, "technique(s) with detection content"},
		{"coverage bad format", []string{"coverage", "--quiet", "--format", "xml"}, report.ExitUsage, ""},
		{"coverage positional", []string{"coverage", "--quiet", "extra"}, report.ExitUsage, ""},
		{"coverage record needs expect", []string{"coverage", "--quiet", "--record"}, report.ExitUsage, ""},
		{"coverage missing rules", []string{"coverage", "--quiet", "--rules", "/no/rules"}, report.ExitRunFailed, ""},
		{"coverage missing expect", []string{"coverage", "--quiet", "--rules", "rules", "--expect", "/no/expect.txt"}, report.ExitRunFailed, ""},
		{"rules no sub", []string{"rules"}, report.ExitUsage, ""},
		{"rules help", []string{"rules", "help"}, report.ExitOK, ""},
		{"rules lint", []string{"rules", "lint", "--rules", "rules"}, report.ExitOK, "errors"},
		{"rules lint strict", []string{"rules", "lint", "--rules", "rules", "--strict"}, report.ExitThreat, "warning"},
		{"rules lint json", []string{"rules", "lint", "--rules", "rules", "--format", "json"}, report.ExitOK, `"profile": "cau"`},
		{"rules lint generic", []string{"rules", "lint", "--rules", "rules", "--profile", "generic", "--strict"}, report.ExitThreat, "string-short"},
		{"rules lint bad profile", []string{"rules", "lint", "--rules", "rules", "--profile", "x"}, report.ExitRunFailed, ""},
		{"rules lint bad format", []string{"rules", "lint", "--rules", "rules", "--format", "x"}, report.ExitUsage, ""},
		{"rules lint missing", []string{"rules", "lint", "--rules", "/no/rules"}, report.ExitRunFailed, ""},
		{"rules list", []string{"rules", "list", "--rules", "rules"}, report.ExitOK, "mimikatz_strings"},
		{"rules list json", []string{"rules", "list", "--rules", "rules", "--format", "json"}, report.ExitOK, `"technique"`},
		{"scan ocsf", []string{"scan", "--quiet", "--db", smokeDB, "--rules", "rules", "--format", "ocsf", "--fail-on", "none", smokeHashHit}, report.ExitOK, `"class_uid":2004`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, out, errOut)
			}
			if tc.out != "" && !strings.Contains(out, tc.out) {
				t.Errorf("stdout lacks %q:\n%s\nstderr:\n%s", tc.out, out, errOut)
			}
		})
	}
}

func TestCLICoverageGateAndRecord(t *testing.T) {
	dir := t.TempDir()
	expect := filepath.Join(dir, "expect.txt")

	// A wrong expectation fails the gate in both directions and still writes the matrix.
	if err := os.WriteFile(expect, []byte("T1003 covered\nT1027 gap planned\nT1999 covered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "coverage", "--quiet", "--rules", "rules", "--expect", expect, "--format", "json")
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitThreat, errOut)
	}
	for _, want := range []string{"regression: T1999", "gap-closed: T1027", "undeclared: T1486", "[GATE] FAIL"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("matrix not written on gate failure: %v", err)
	}

	// Record, then the gate passes and the matrix is unchanged.
	code, _, errOut = runCLI(t, "coverage", "--quiet", "--rules", "rules", "--expect", expect, "--record")
	if code != report.ExitOK {
		t.Fatalf("record exit %d: %s", code, errOut)
	}
	rec, _ := os.ReadFile(expect)
	if !strings.Contains(string(rec), "T1003       covered") || strings.Contains(string(rec), "T1999") {
		t.Errorf("recorded expectation:\n%s", rec)
	}
	code, _, errOut = runCLI(t, "coverage", "--quiet", "--rules", "rules", "--expect", expect)
	if code != report.ExitOK {
		t.Fatalf("gate after record exit %d: %s", code, errOut)
	}

	// --record creates a missing file.
	fresh := filepath.Join(dir, "fresh.txt")
	if code, _, errOut = runCLI(t, "coverage", "--quiet", "--rules", "rules", "--expect", fresh, "--record"); code != report.ExitOK {
		t.Fatalf("record to new file exit %d: %s", code, errOut)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("record should create the file")
	}

	// --output writes the document.
	outFile := filepath.Join(dir, "layer.json")
	if code, _, errOut = runCLI(t, "coverage", "--quiet", "--rules", "rules", "--format", "navigator", "--output", outFile); code != report.ExitOK {
		t.Fatalf("output exit %d: %s", code, errOut)
	}
	if b, err := os.ReadFile(outFile); err != nil || !strings.Contains(string(b), "techniqueID") {
		t.Errorf("layer file: %v %s", err, b)
	}
}

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// An evaluation recipe must propagate every failure, including failures before
// the final reporting command. Otherwise a stale report can turn a failed scan
// or corpus validation into an apparently successful measurement.
func TestMakeEvaluationsPropagateFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Makefile recipes require a POSIX shell")
	}
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is not installed")
	}
	makefile, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target, fail, last string
	}{
		{"recall validation", "eval-recall", "eval validate", "eval report"},
		{"recall scan", "eval-recall", "eval run", "eval report"},
		{"specificity manifest", "eval-specificity", "manifest", "eval report"},
		{"specificity scan", "eval-specificity", "eval run", "eval report"},
		{"lab scan", "eval-lab", "eval run", "summary"},
		{"recall success", "eval-recall", "", "eval report"},
		{"specificity success", "eval-specificity", "", "eval report"},
		{"lab success", "eval-lab", "", "summary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, content string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			// Replace only the build prerequisite: exercise the real recipes
			// against deterministic commands without building another binary.
			write("Makefile", string(makefile)+"\nbuild: ; @:\n", 0644)
			stub := `printf '%s\n' "$*" >> "$CALLS"
if [ -n "$FAIL_STAGE" ]; then
    case "$*" in "$FAIL_STAGE"*) exit 23 ;; esac
fi
`
			write("cau", "#!/bin/sh\n"+stub, 0755)
			write("scripts/clean-manifest.sh", "#!/bin/sh\nset -- manifest \"$@\"\n"+stub, 0755)
			write("scripts/lab-summary.py", "#!/bin/sh\nset -- summary \"$@\"\n"+stub, 0755)
			write("heldout.json", "{}", 0644)
			write("lab/manifest-dev.json", "{}", 0644)
			write("lab/manifest-heldout.json", "{}", 0644)
			calls := filepath.Join(dir, "calls")
			cmd := exec.Command(makeBin, "--no-print-directory", tc.target,
				"BINARY=cau", "HELDOUT_MANIFEST=heldout.json", "CLEAN_ROOT=/clean", "LAB=lab")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "CALLS="+calls, "FAIL_STAGE="+tc.fail, "MAKEFLAGS=")
			out, err := cmd.CombinedOutput()
			if (err != nil) != (tc.fail != "") {
				t.Fatalf("make error = %v, failure stage = %q\n%s", err, tc.fail, out)
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(data), tc.last); got != (tc.fail == "") {
				t.Fatalf("report/summary ran = %v, failure stage = %q; calls:\n%s", got, tc.fail, data)
			}
		})
	}
}

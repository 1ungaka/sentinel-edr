package main

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

func argsFS() (*flag.FlagSet, *bool, *string) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, fs.Bool("no-yara", false, ""), fs.String("format", "text", "")
}

func TestFlagsAfterArgumentsAreFlags(t *testing.T) {
	for _, args := range [][]string{
		{"/bin", "--no-yara", "--format", "json"},
		{"--no-yara", "/bin", "--format=json"},
		{"--format", "json", "--no-yara", "/bin"},
		{"-no-yara", "/bin", "-format", "json"},
	} {
		fs, noYara, format := argsFS()
		if err := fs.Parse(interspersed(fs, args)); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !*noYara || *format != "json" {
			t.Errorf("%v: no-yara=%v format=%q", args, *noYara, *format)
		}
		if got := fs.Args(); !reflect.DeepEqual(got, []string{"/bin"}) {
			t.Errorf("%v: args = %q", args, got)
		}
	}
}

func TestDoubleDashStillEndsFlags(t *testing.T) {
	fs, noYara, _ := argsFS()
	if err := fs.Parse(interspersed(fs, []string{"/bin", "--", "--no-yara", "-x"})); err != nil {
		t.Fatal(err)
	}
	if *noYara {
		t.Error("a path after -- was read as a flag")
	}
	if got := fs.Args(); !reflect.DeepEqual(got, []string{"/bin", "--no-yara", "-x"}) {
		t.Errorf("args = %q", got)
	}
}

func TestStdinDashIsAnArgument(t *testing.T) {
	fs, _, _ := argsFS()
	if err := fs.Parse(interspersed(fs, []string{"-", "--no-yara"})); err != nil {
		t.Fatal(err)
	}
	if got := fs.Args(); !reflect.DeepEqual(got, []string{"-"}) {
		t.Errorf("args = %q", got)
	}
}

func TestAFlagValueIsNotMistakenForAnArgument(t *testing.T) {
	fs, _, format := argsFS()
	if err := fs.Parse(interspersed(fs, []string{"--format", "-weird", "/bin"})); err != nil {
		t.Fatal(err)
	}
	if *format != "-weird" {
		t.Errorf("format = %q", *format)
	}
}

func TestMissingValueIsStillAnError(t *testing.T) {
	fs, _, _ := argsFS()
	if err := fs.Parse(interspersed(fs, []string{"/bin", "--format"})); err == nil {
		t.Fatal("a flag with no value was accepted")
	}
}

func TestUnknownFlagAfterAnArgumentIsAnError(t *testing.T) {
	fs, _, _ := argsFS()
	if err := fs.Parse(interspersed(fs, []string{"/bin", "--nope"})); err == nil {
		t.Fatal("an unknown flag was treated as a path")
	}
}

// `cau scan /bin --no-yara` used to scan a file called --no-yara and leave YARA on.
func TestScanTakesFlagsAfterTheTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "scan", dir, "--no-yara", "--no-heuristics")
	if strings.Contains(out, "--no-yara") || strings.Contains(errOut, "--no-yara") {
		t.Fatalf("the flag was treated as a target:\n%s\n%s", out, errOut)
	}
	if code != report.ExitOK {
		t.Fatalf("code = %d\n%s\n%s", code, out, errOut)
	}
}

// One regex keeps a new command from reintroducing this.
func TestEveryCommandAcceptsFlagsAfterArguments(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`\bfs\.Parse\(args\)`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bare.Match(src) {
			t.Errorf("%s calls fs.Parse(args) directly; use fs.Parse(interspersed(fs, args))", f)
		}
	}
}

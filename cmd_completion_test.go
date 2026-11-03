package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/cau-edr/cau/internal/report"
)

// commandFromUsage extracts the top-level command names from the usage block,
// which is the single place the CLI's surface is written down. If a command is
// added to usage() but not to a completion script, the drift test below fails.
func commandsFromUsage(t *testing.T) []string {
	t.Helper()
	var buf bytes.Buffer
	usage(&buf)
	re := regexp.MustCompile(`(?m)^  cau ([a-z][a-z-]*)[ \t]`)
	var cmds []string
	for _, m := range re.FindAllStringSubmatch(buf.String(), -1) {
		cmds = append(cmds, m[1])
	}
	if len(cmds) < 15 {
		t.Fatalf("extracted only %d commands from usage(); the regex or the usage block is broken", len(cmds))
	}
	return cmds
}

func TestCLICompletionMatchesUsage(t *testing.T) {
	// Read the scripts from disk (not through cmdCompletion) so the check is
	// about the shipped content, not the embedding.
	var scripts = map[string]string{}
	for _, shell := range completionShells {
		raw, err := completions.ReadFile("completions/cau." + shell)
		if err != nil {
			t.Fatalf("completions/cau.%s is missing: %v", shell, err)
		}
		scripts[shell] = string(raw)
	}

	// subcommands that legitimately have no completion table of their own.
	noSubcommands := map[string]bool{
		"version": true, "help": true, "bundle": true,
	}

	for _, cmd := range commandsFromUsage(t) {
		if noSubcommands[cmd] {
			continue
		}
		for shell, script := range scripts {
			if !strings.Contains(script, cmd) {
				t.Errorf("%s completion omits the command %q (add it, or to noSubcommands)", shell, cmd)
			}
		}
	}
}

func TestCLICompletionCommands(t *testing.T) {
	for _, shell := range completionShells {
		code, out, errb := runCLI(t, "completion", shell)
		if code != report.ExitOK {
			t.Errorf("cau completion %s: exit %d (want %d), stderr=%s", shell, code, report.ExitOK, errb)
			continue
		}
		if !strings.Contains(out, "cau") {
			t.Errorf("cau completion %s: output does not mention cau", shell)
		}
	}

	// A completion script must be non-trivial: one that is shorter than the
	// command table is a stub, not a script.
	if out := mustComplete(t, "bash"); len(out) < 500 {
		t.Errorf("bash completion is only %d bytes; looks like a stub", len(out))
	}

	// An unknown shell is a usage error that names the shell, not a silent
	// success and not a script that cannot run.
	code, _, errb := runCLI(t, "completion", "tcsh")
	if code != report.ExitUsage {
		t.Errorf("cau completion tcsh: exit %d (want %d)", code, report.ExitUsage)
	}
	if !strings.Contains(errb, "tcsh") {
		t.Errorf("cau completion tcsh: the error should name the shell, got %q", errb)
	}

	// No argument at all must be a usage error, not a panic or an empty script.
	code, out, _ := runCLI(t, "completion")
	if code != report.ExitUsage {
		t.Errorf("cau completion (no shell): exit %d (want %d)", code, report.ExitUsage)
	}
	if out != "" {
		t.Errorf("cau completion (no shell): wrote %d bytes to stdout, want none", len(out))
	}
}

func mustComplete(t *testing.T, shell string) string {
	t.Helper()
	var out bytes.Buffer
	code := cmdCompletion([]string{shell}, &out, &bytes.Buffer{})
	if code != report.ExitOK {
		t.Fatalf("cmdCompletion(%q): exit %d", shell, code)
	}
	return out.String()
}

package main

import (
	"embed"
	"flag"
	"fmt"
	"io"

	"github.com/cau-edr/cau/internal/report"
)

// completions holds the shell-completion scripts shipped with the binary. They
// are embedded rather than read from the share directory so that "cau
// completion" works next to the binary, inside a container, and in a source
// checkout alike — the same resource-independence rule the rules directory and
// signature database follow.
//
//go:embed completions/cau.bash
//go:embed completions/cau.zsh
//go:embed completions/cau.fish
var completions embed.FS

// completionShells are the shells "cau completion" can emit a script for, in a
// fixed order so "cau completion" with no argument lists them predictably.
var completionShells = []string{"bash", "zsh", "fish"}

// cmdCompletion implements `cau completion <shell>`: it writes the
// completion script for a shell to stdout, ready to be installed by hand or by
// the package (make install, the Debian package and the PKGBUILD all install
// these same files).
func cmdCompletion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintf(stderr, "[ERROR] give exactly one shell, one of: %v\n", completionShells)
		fmt.Fprintf(stderr, "usage: cau completion <bash|zsh|fish>\n")
		return report.ExitUsage
	}

	shell := rest[0]
	switch shell {
	case "bash", "zsh", "fish":
		src, err := completions.ReadFile("completions/cau." + shell)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "read %s completion: %v", shell, err)
		}
		if _, err := stdout.Write(src); err != nil {
			return fail(stderr, report.ExitRunFailed, "write %s completion: %v", shell, err)
		}
		return report.ExitOK
	default:
		return fail(stderr, report.ExitUsage, "unknown shell %q; expected bash, zsh or fish", shell)
	}
}

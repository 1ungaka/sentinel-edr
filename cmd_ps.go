package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/cau-edr/cau/internal/procscan"
	"github.com/cau-edr/cau/internal/report"
)

func psUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau ps [flags]

Point-in-time threat scan of the live process table, read entirely from /proc.
Read-only: it never injects, ptraces, signals, or stops a process. It flags
processes a benign system would not be running:

  - fileless / RAM-only execution (memfd, deleted binary, /dev/shm)
  - name masquerading / PID hijacking (a fake "btop", /tmp/sshd, [kworker] with
    a real userspace exe)
  - library-injection hooks (a .so mapped from /tmp, /dev/shm, a hidden or
    deleted path; a suspicious LD_PRELOAD / LD_LIBRARY_PATH)
  - malicious command lines (reverse shells, curl|bash, droppers)
  - processes under ptrace

Without root most other users' processes are only partly readable; those fields
are skipped rather than failing the scan. Run with sudo for full visibility.

Flags:
  --format <fmt>     text or json (default text)
  --threshold <n>    per-process score to report (default 8)

Exit codes: 0 nothing flagged, 1 one or more processes flagged, 4 usage.
`)
}

func cmdPs(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { psUsage(stderr) }
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", procscan.DefaultThreshold, "per-process score to report")
	feedPath := fs.String("feed", "", "abuse-intel feed file to match process command lines against")
	procRoot := fs.String("proc-root", "", "override /proc (testing)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *threshold < 1 {
		return fail(stderr, report.ExitUsage, "--threshold must be at least 1")
	}

	res := procscan.Scan(procscan.Options{Threshold: *threshold, ProcRoot: *procRoot, Intel: loadFeedQuiet(*feedPath)})

	if *format == "json" {
		if err := writeJSON(stdout, res); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "Processes scanned : %d\n", res.Scanned)
		if res.Unreadable > 0 {
			fmt.Fprintf(stdout, "Unreadable        : %d (run as root for full visibility)\n", res.Unreadable)
		}
		fmt.Fprintf(stdout, "Threshold         : %d\n", res.Threshold)
		fmt.Fprintf(stdout, "Flagged           : %d\n", len(res.Flagged))
		for _, w := range res.Warnings {
			fmt.Fprintf(stdout, "  [warn] %s\n", w)
		}
		for _, p := range res.Flagged {
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, " [!] PID %d (%s) score %d\n", p.PID, p.Comm, p.Score)
			if p.Exe != "" {
				fmt.Fprintf(stdout, "     exe     : %s\n", p.Exe)
			}
			if p.Cmdline != "" {
				fmt.Fprintf(stdout, "     cmdline : %s\n", truncStr(p.Cmdline, 120))
			}
			for _, f := range p.Findings {
				tag := ""
				if f.Technique != "" {
					tag = "  (" + f.Technique + ")"
				}
				fmt.Fprintf(stdout, "     [%s] %d%s\n", f.Class, f.Score, tag)
				detail := f.Detail
				if f.Evidence != "" {
					detail += ": " + f.Evidence
				}
				fmt.Fprintf(stdout, "       %s\n", truncStr(detail, 200))
			}
		}
		if len(res.Flagged) == 0 {
			fmt.Fprintln(stdout, "\n No suspicious processes found.")
		} else {
			fmt.Fprintln(stdout, "\n *** SUSPICIOUS PROCESSES FOUND — INVESTIGATE BEFORE TRUSTING THIS HOST ***")
		}
	}

	if len(res.Flagged) > 0 {
		return report.ExitThreat
	}
	return report.ExitOK
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

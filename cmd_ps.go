package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/procscan"
	"github.com/s-b-repo/cau/internal/report"
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
  - network shells: an interpreter whose stdin and stdout are a live TCP
    connection, whatever its command line says
  - processes under ptrace; anonymous executable memory (context only)

Scanning alone never touches a process. --respond is what acts, and only on a
confirmed process: one carrying a conclusive finding (a network shell, memfd
execution, a masquerade, a reverse-shell or miner command line) or a combined
score of at least --respond-score. Everything else is reported and left running
for a human. PID 1, the responder and its ancestors are never touched.

  stop  SIGSTOP: the process freezes with its memory and sockets intact for
        forensics. Undo a wrong call with 'kill -CONT <pid>'.
  kill  SIGKILL: not reversible.

Without root most other users' processes are only partly readable; those fields
are skipped rather than failing the scan. Run with sudo for full visibility.

Flags:
  --format <fmt>     text or json (default text)
  --threshold <n>    per-process score to report (default 8)
  --respond <action> act on confirmed processes: stop or kill (default: report only)
  --respond-score <n> combined score that counts as confirmed (default 16)
  --interval <d>     re-scan every interval (e.g. 10s) until a termination signal
  --block-exe        with --respond: ask the kernel to refuse a confirmed process's
                     file through cau-kernel (never a system path or an interpreter)
  --kernel-bin <path> the cau-kernel binary --block-exe drives (default cau-kernel)
  --kernel-events <f> correlate the cau-kernel guard's event log with live processes
  --feed <path>      abuse-intel feed to match process command lines against
  --proc-root <dir>  override /proc (testing)

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
	respond := fs.String("respond", "", "act on confirmed processes: stop or kill (default: report only)")
	respondScore := fs.Int("respond-score", procscan.DefaultRespondScore, "combined score that counts as confirmed")
	interval := fs.Duration("interval", 0, "re-scan every interval until a termination signal; 0 scans once")
	blockExe := fs.Bool("block-exe", false, "with --respond: ask the kernel to refuse a confirmed process's file")
	kernelBin := fs.String("kernel-bin", "cau-kernel", "the cau-kernel binary --block-exe drives")
	kernelEvents := fs.String("kernel-events", "", "cau-kernel guard event log (JSON lines) to correlate with live processes")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *threshold < 1 {
		return fail(stderr, report.ExitUsage, "--threshold must be at least 1")
	}

	action := procscan.Action(*respond)
	if action != "" && action != procscan.ActionStop && action != procscan.ActionKill {
		return fail(stderr, report.ExitUsage, "--respond must be stop or kill")
	}
	if *interval < 0 {
		return fail(stderr, report.ExitUsage, "--interval must not be negative")
	}
	if *blockExe && action == "" {
		return fail(stderr, report.ExitUsage, "--block-exe needs --respond")
	}

	feed := loadFeedQuiet(*feedPath)
	code := report.ExitOK
	cycle := func() {
		opts := procscan.Options{Threshold: *threshold, ProcRoot: *procRoot, Intel: feed}
		if *kernelEvents != "" {
			events, err := procscan.LoadKernelEvents(*kernelEvents)
			if err != nil {
				fmt.Fprintf(stderr, "[warn] %v\n", err)
			}
			opts.KernelEvents = events
		}
		res := procscan.Scan(opts)
		var responses []procscan.Response
		if action != "" {
			ro := procscan.RespondOptions{Action: action, MinScore: *respondScore, ProcRoot: *procRoot}
			if *blockExe {
				ro.BlockExe = func(exe string) error { return kernelBlock(*kernelBin, exe) }
			}
			responses = procscan.Respond(res, ro)
		}
		// A watch prints only what it found; a one-shot always reports.
		if *interval > 0 && len(res.Flagged) == 0 {
			return
		}
		if c := writePsReport(stdout, stderr, *format, res, responses); c != report.ExitOK {
			code = c
		}
	}
	if *interval == 0 {
		cycle()
		return code
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	stop := make(chan struct{})
	go func() { <-sig; close(stop) }()
	status := func(f string, a ...interface{}) { fmt.Fprintf(stderr, f+"\n", a...) }
	scanLoop(*interval, func() { runCycle(cycle, status) }, stop)
	return report.ExitOK
}

// psReport is the JSON document: the scan plus what was done about it.
type psReport struct {
	*procscan.Result
	Responses []procscan.Response `json:"responses,omitempty"`
}

func writePsReport(stdout, stderr io.Writer, format string, res *procscan.Result, responses []procscan.Response) int {
	if format == "json" {
		if err := writeJSON(stdout, psReport{res, responses}); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "Processes scanned : %d\n", res.Scanned)
		if res.Unreadable > 0 {
			fmt.Fprintf(stdout, "Unreadable        : %d (run as root for full visibility)\n", res.Unreadable)
		}
		fmt.Fprintf(stdout, "Threshold         : %d\n", res.Threshold)
		fmt.Fprintf(stdout, "Flagged           : %d\n", len(res.Flagged))
		if res.KernelSeen > 0 {
			fmt.Fprintf(stdout, "Kernel guard      : %d exec(s) seen, %d refused\n", res.KernelSeen, res.KernelRefused)
		}
		for _, w := range res.Warnings {
			fmt.Fprintf(stdout, "  [warn] %s\n", report.TermSafe(w))
		}
		for _, p := range res.Flagged {
			fmt.Fprintln(stdout)
			fmt.Fprintf(stdout, " [!] PID %d (%s) score %d\n", p.PID, report.TermSafe(p.Comm), p.Score)
			if p.Exe != "" {
				fmt.Fprintf(stdout, "     exe     : %s\n", report.TermSafe(p.Exe))
			}
			if p.Cmdline != "" {
				fmt.Fprintf(stdout, "     cmdline : %s\n", truncStr(report.TermSafe(p.Cmdline), 120))
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
				fmt.Fprintf(stdout, "       %s\n", truncStr(report.TermSafe(detail), 200))
			}
		}
		if len(res.Flagged) == 0 {
			fmt.Fprintln(stdout, "\n No suspicious processes found.")
		} else {
			fmt.Fprintln(stdout, "\n *** SUSPICIOUS PROCESSES FOUND — INVESTIGATE BEFORE TRUSTING THIS HOST ***")
		}
		for _, r := range responses {
			fmt.Fprintf(stdout, " [response] %s\n", report.TermSafe(r.String()))
		}
	}

	if len(res.Flagged) > 0 {
		return report.ExitThreat
	}
	return report.ExitOK
}

// kernelBlock asks the kernel guard to refuse a file. It shells out rather than
// linking cilium/ebpf, so `cau` stays buildable anywhere and a host with no
// guard gets a clear error rather than a missing feature.
func kernelBlock(bin, path string) error {
	// An alert waits for its response, so a wedged helper must not wait for ever.
	ctx, cancel := context.WithTimeout(context.Background(), kernelBlockTimeout) // audit:ok no caller holds a context here, and this deadline is what bounds the call
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "enforce", "block", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s enforce block: %v: %s", bin, err, strings.TrimSpace(string(out)))
	}
	return nil
}

const kernelBlockTimeout = 30 * time.Second

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

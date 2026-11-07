package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/s-b-repo/cau/internal/persist"
	"github.com/s-b-repo/cau/internal/report"
)

func persistUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau persist [flags]

Audit a Linux host for persistence: what will run after the next reboot or
login, and the accounts and privileges that let an attacker back in. Read-only:
it reports and never edits a file, because the line it would remove may be the
only evidence of the intrusion.

  - dynamic linker hijack (/etc/ld.so.preload, ld.so.conf, exported LD_PRELOAD)
  - cron, systemd units and drop-ins, rc.local, XDG autostart, udev RUN rules,
    shell startup files: hostile commands, or anything run from a world-writable
    location
  - MOTD and init scripts, APT hooks, modprobe install directives
  - SSH authorized_keys forced commands; keys granting direct root login
  - UID 0 accounts other than root, empty passwords
  - passwordless sudo for everyone; sudo keeping a loader variable; PAM
    'sufficient pam_permit' backdoors
  - set-uid programs in /tmp, /var/tmp, /dev/shm; root-equivalent capabilities on
    interpreters; account files or autostart entries anyone can write

Run as root for full visibility: /etc/shadow, other users' home directories and
crontabs are otherwise skipped.

Flags:
  --root <dir>       audit this filesystem (a mounted disk image) instead of /
  --format <fmt>     text or json (default text)
  --threshold <n>    score that counts as a detection (default 8)
  --all              also list observations below the threshold

Exit codes: 0 nothing flagged, 1 one or more detections, 2 the audit could not
read every path (coverage incomplete), 4 usage.
`)
}

func cmdPersist(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("persist", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { persistUsage(stderr) }
	root := fs.String("root", "/", "filesystem to audit")
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", persist.DefaultThreshold, "score that counts as a detection")
	all := fs.Bool("all", false, "also list observations below the threshold")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *threshold < 1 {
		return fail(stderr, report.ExitUsage, "--threshold must be at least 1")
	}

	res := persist.Scan(persist.Options{Root: *root, Threshold: *threshold})
	flagged := res.Flagged()

	if *format == "json" {
		if err := writeJSON(stdout, res); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		shown := flagged
		if *all {
			shown = res.Findings
		}
		fmt.Fprintf(stdout, "Files checked : %d\nDetections    : %d\nObservations  : %d\n", res.Checked, len(flagged), len(res.Findings)-len(flagged))
		for _, f := range shown {
			where := f.Path
			if f.Line > 0 {
				where = fmt.Sprintf("%s:%d", f.Path, f.Line)
			}
			fmt.Fprintf(stdout, "\n [!] %s  score %d  (%s)\n     %s\n     %s\n", f.Class, f.Score, f.Technique, report.TermSafe(where), report.TermSafe(f.Detail))
			if f.Evidence != "" {
				fmt.Fprintf(stdout, "     > %s\n", report.TermSafe(f.Evidence))
			}
		}
		if len(flagged) == 0 {
			fmt.Fprintln(stdout, "\n No persistence detections.")
		}
		// What is listed here was found but never read, so no finding from it
		// says nothing either way: an absent path is the documented skip, an
		// unread one is not.
		if len(res.Incomplete) > 0 {
			fmt.Fprintf(stdout, "\n Incomplete    : %d path(s) could not be read, so those locations are unverified, not clean.\n", len(res.Incomplete))
			for _, p := range res.Incomplete {
				fmt.Fprintf(stdout, "     ? %s\n", report.TermSafe(p))
			}
		}
	}
	if len(flagged) > 0 {
		return report.ExitThreat
	}
	if len(res.Incomplete) > 0 {
		return report.ExitScanFailed
	}
	return report.ExitOK
}

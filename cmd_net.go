package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/netblock"
	"github.com/s-b-repo/cau/internal/netscan"
	"github.com/s-b-repo/cau/internal/report"
)

func netUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau net [flags]
       cau net block <address>… [flags]
       cau net unblock <address>… [flags]
       cau net blocks [flags]
       cau net clear [flags]

Point-in-time threat scan of the host's network plane, read entirely from /proc
and /etc. Read-only: it opens no socket, sends no probe and captures no packets.
Every socket the kernel holds is attributed to the process and the executable
behind it, which is what makes a network finding something you can act on:

  - fileless network presence: a socket held by a process whose executable is a
    memfd, a deleted inode or a tmpfs path (T1620 with T1071/T1571)
  - bind shells and relays: a listener owned by an interpreter, or by nc, ncat,
    socat or telnet, whatever its command line says (T1059.004)
  - known-bad peers: a remote address listed in the abuse-intel feed (T1071)
  - handler ports, and listeners from binaries no package installed (T1571)
  - DNS-plane escape: queries to a nameserver this host is not configured to
    use, encrypted DNS past the host's own resolver (T1071.004, T1572), a
    resolver configuration naming an unexpected nameserver, and a hosts file
    that blackholes a security or update domain (T1562.001)
  - connect sweeps: one process with connections in flight to many peers (T1046)
  - beaconing: repeated connections to one peer on a schedule, which needs more
    than one sample — use --interval, or run 'cau defend' (T1071.001)
  - neighbour-table tampering: the default gateway's MAC moving under the host,
    one MAC answering for the gateway and another address (T1557.002)

Scanning never changes anything. --respond block is what acts, and only on a
confirmed finding: one that asserts live state (a fileless process holding a
socket) or an exact identification (a feed hit). A score alone is an alert for a
human, because a handler port and an unusual listener are a developer's Tuesday.

Blocking asks the kernel to drop traffic to and from an address, in cau's own
nftables table (or its own iptables chains), and it expires: --block-ttl
defaults to 1h so a wrong block on a production host heals itself. These are
never blocked, however confirmed the incident: loopback, this host's own
addresses, its default gateways, its configured resolvers, link-local and
multicast. 'cau net clear' removes everything cau created and leaves the host's
own firewall exactly as it was.

A block is not containment. The peer sees the drop, and a peer with a second
address is back at once. It buys the minutes an operator needs.

Flags:
  --format <fmt>      text or json (default text)
  --threshold <n>     per-subject score to report (default 5)
  --feed <path>       abuse-intel feed to match remote addresses against
  --interval <d>      re-scan every interval until a termination signal; this is
                      what gives the beaconing analytic samples to compare
  --respond block     block the peers of confirmed findings
  --block-ttl <d>     how long a block lasts (default 1h; 0 means until removed)
  --sever             also destroy established connections to a blocked peer
                      (needs the ss tool and a kernel that supports it)
  --dry-run           print the firewall commands and run none of them
  --backend <name>    force nftables or iptables instead of discovering one
  --ledger <path>     append every block to this file with its reason
  --reason <text>     with 'block': why this address is being blocked, for the
                      ledger, so 'cau net blocks' can say who asked and why
  --proc-root <dir>  --etc-root <dir>   override /proc and /etc (testing)

Exit codes: 0 nothing flagged, 1 one or more findings, 3 run failed, 4 usage.
`)
}

// netFlags are shared by the scan and the blocker subcommands.
type netFlags struct {
	format    string
	threshold int
	feed      string
	procRoot  string
	etcRoot   string
	interval  time.Duration
	respond   string
	ttl       time.Duration
	sever     bool
	dryRun    bool
	backend   string
	ledger    string
}

func (n *netFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&n.format, "format", "text", "output format: text or json")
	fs.IntVar(&n.threshold, "threshold", netscan.DefaultThreshold, "per-subject score to report")
	fs.StringVar(&n.feed, "feed", "", "abuse-intel feed file to match remote addresses against")
	fs.StringVar(&n.procRoot, "proc-root", "", "override /proc (testing)")
	fs.StringVar(&n.etcRoot, "etc-root", "", "override /etc (testing)")
	fs.DurationVar(&n.interval, "interval", 0, "re-scan every interval until a termination signal; 0 scans once")
	fs.StringVar(&n.respond, "respond", "", "act on confirmed findings: block (default: report only)")
	fs.DurationVar(&n.ttl, "block-ttl", netblock.DefaultTTL, "how long a block lasts; 0 means until it is removed")
	fs.BoolVar(&n.sever, "sever", false, "also destroy established connections to a blocked peer")
	fs.BoolVar(&n.dryRun, "dry-run", false, "print the firewall commands and run none of them")
	fs.StringVar(&n.backend, "backend", "", "force a firewall backend: nftables or iptables")
	fs.StringVar(&n.ledger, "ledger", "", "append every block to this file with its reason")
}

// blocker builds a Blocker with this host's never-block list.
func (n *netFlags) blocker() (*netblock.Blocker, error) {
	ttl := n.ttl
	if ttl == 0 {
		ttl = -1 // the flag's 0 means "no expiry"; the package's 0 means "default"
	}
	ledger := n.ledger
	if ledger == "" {
		ledger = netblock.DefaultLedger("")
	}
	return netblock.Open(netblock.Options{
		TTL:     ttl,
		DryRun:  n.dryRun,
		Backend: netblock.Backend(n.backend),
		Protect: netblock.LocalProtect(n.procRoot, n.etcRoot),
		Ledger:  ledger,
		Sever:   n.sever,
	})
}

func cmdNet(args []string, stdout, stderr io.Writer) int {
	// A subcommand is a bare first word; everything else is a scan.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "block", "unblock", "blocks", "clear":
			return cmdNetBlock(args[0], args[1:], stdout, stderr)
		default:
			return fail(stderr, report.ExitUsage, "unknown 'cau net' subcommand %q: block, unblock, blocks or clear", args[0])
		}
	}

	fs := flag.NewFlagSet("net", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { netUsage(stderr) }
	var nf netFlags
	nf.bind(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if nf.format != "text" && nf.format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if nf.threshold < 1 {
		return fail(stderr, report.ExitUsage, "--threshold must be at least 1")
	}
	if nf.interval < 0 {
		return fail(stderr, report.ExitUsage, "--interval must not be negative")
	}
	if nf.respond != "" && nf.respond != "block" {
		return fail(stderr, report.ExitUsage, "--respond must be block")
	}
	if nf.ttl < 0 {
		return fail(stderr, report.ExitUsage, "--block-ttl must not be negative")
	}

	var blocker *netblock.Blocker
	if nf.respond == "block" {
		b, err := nf.blocker()
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		blocker = b
	}

	feed := loadFeedQuiet(nf.feed)
	// One History across the whole run: the beaconing and gateway-churn
	// analytics compare samples, so they say nothing on a single pass and more
	// with each one. A --interval run is what makes them useful.
	history := netscan.NewHistory()
	code := report.ExitOK
	cycle := func() {
		res := netscan.Scan(netscan.Options{
			Threshold: nf.threshold, ProcRoot: nf.procRoot, EtcRoot: nf.etcRoot,
			Intel: feed, History: history,
		})
		var actions []string
		if blocker != nil {
			actions = respondNetwork(blocker, res)
		}
		if nf.interval > 0 && len(res.Flagged) == 0 {
			return // a watch prints only what it found
		}
		if c := writeNetReport(stdout, stderr, nf.format, res, actions, blocker); c != report.ExitOK {
			code = c
		}
	}
	if nf.interval == 0 {
		cycle()
		return code
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	stop := make(chan struct{})
	go func() { <-sig; close(stop) }()
	status := func(f string, a ...interface{}) { fmt.Fprintf(stderr, f+"\n", a...) }
	scanLoop(nf.interval, func() { runCycle(cycle, status) }, stop)
	return report.ExitOK
}

// respondNetwork blocks the peers of findings that confirm themselves: live
// state, or an exact identification. A score, however high, is not one of them.
func respondNetwork(b *netblock.Blocker, res *netscan.Result) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range res.Flagged {
		if f.Peer == "" || seen[f.Peer] || !(f.Live || f.Definitive) {
			continue
		}
		seen[f.Peer] = true
		what, err := b.Block(f.Peer, f.Class+": "+f.Detail)
		if err != nil {
			out = append(out, "not blocked: "+err.Error())
			continue
		}
		out = append(out, what)
	}
	if n, err := b.Expire(); err == nil && n > 0 {
		out = append(out, fmt.Sprintf("released %d expired block(s)", n))
	}
	return out
}

// netReport is the JSON document: the scan plus what was done about it.
type netReport struct {
	*netscan.Result
	Backend string   `json:"backend,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

func writeNetReport(stdout, stderr io.Writer, format string, res *netscan.Result, actions []string, b *netblock.Blocker) int {
	doc := netReport{Result: res, Actions: actions}
	if b != nil {
		doc.Backend = string(b.Backend())
	}
	if format == "json" {
		if err := writeJSON(stdout, doc); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "Sockets read      : %d (%d attributed to a process)\n", res.Sockets, res.Attributed)
		fmt.Fprintf(stdout, "Listening         : %d\n", res.Listeners)
		fmt.Fprintf(stdout, "Established       : %d\n", res.Established)
		if res.Unreadable > 0 {
			fmt.Fprintf(stdout, "Unreadable        : %d process(es) (run as root for full visibility)\n", res.Unreadable)
		}
		fmt.Fprintf(stdout, "Threshold         : %d\n", res.Threshold)
		fmt.Fprintf(stdout, "Flagged           : %d\n", len(res.Flagged))
		for _, w := range res.Warnings {
			fmt.Fprintf(stdout, "  [warn] %s\n", report.TermSafe(w))
		}
		for _, f := range res.Flagged {
			fmt.Fprintln(stdout)
			state := ""
			switch {
			case f.Live:
				state = "  LIVE"
			case f.Definitive:
				state = "  KNOWN-BAD"
			}
			tag := ""
			if f.Technique != "" {
				tag = "  (" + f.Technique + ")"
			}
			fmt.Fprintf(stdout, " [!] %s score %d%s%s\n", report.TermSafe(f.Class), f.Score, tag, state)
			fmt.Fprintf(stdout, "     %s\n", truncStr(report.TermSafe(f.Detail), 300))
			if f.Evidence != "" {
				fmt.Fprintf(stdout, "     evidence: %s\n", truncStr(report.TermSafe(f.Evidence), 200))
			}
			if f.PID > 0 {
				line := fmt.Sprintf("     pid %d", f.PID)
				if f.Exe != "" {
					line += " exe " + report.TermSafe(f.Exe)
				}
				fmt.Fprintln(stdout, line)
			}
		}
		if len(res.Flagged) == 0 {
			fmt.Fprintln(stdout, "\n Nothing suspicious on the network plane.")
		} else {
			fmt.Fprintln(stdout, "\n *** NETWORK FINDINGS — INVESTIGATE BEFORE TRUSTING THIS HOST ***")
		}
		for _, a := range actions {
			fmt.Fprintf(stdout, " [response] %s\n", report.TermSafe(a))
		}
	}
	if len(res.Flagged) > 0 {
		return report.ExitThreat
	}
	return report.ExitOK
}

// cmdNetBlock is the blocker's own management surface: what is blocked, block
// this, release that, and remove everything cau created.
func cmdNetBlock(sub string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("net "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { netUsage(stderr) }
	var nf netFlags
	nf.bind(fs)
	reason := fs.String("reason", "", "why this address is being blocked, for the ledger")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	addrs := fs.Args()
	if (sub == "block" || sub == "unblock") && len(addrs) == 0 {
		return fail(stderr, report.ExitUsage, "'cau net %s' needs at least one address", sub)
	}
	b, err := nf.blocker()
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	switch sub {
	case "block":
		why := *reason
		if why == "" {
			why = "blocked by hand"
		}
		code := report.ExitOK
		for _, a := range addrs {
			what, err := b.Block(a, why)
			if err != nil {
				code = fail(stderr, report.ExitRunFailed, "%v", err)
				continue
			}
			fmt.Fprintf(stdout, " [block] %s\n", report.TermSafe(what))
		}
		printCommands(stdout, b, nf.dryRun)
		return code
	case "unblock":
		code := report.ExitOK
		for _, a := range addrs {
			if err := b.Unblock(a); err != nil {
				code = fail(stderr, report.ExitRunFailed, "%v", err)
				continue
			}
			fmt.Fprintf(stdout, " [release] %s is no longer blocked\n", report.TermSafe(a))
		}
		printCommands(stdout, b, nf.dryRun)
		return code
	case "blocks":
		entries, err := b.List()
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		if nf.format == "json" {
			if err := writeJSON(stdout, struct {
				Backend   string           `json:"backend"`
				Protected []string         `json:"protected"`
				Blocked   []netblock.Entry `json:"blocked"`
			}{string(b.Backend()), b.Protected(), entries}); err != nil {
				return fail(stderr, report.ExitRunFailed, "%v", err)
			}
			return report.ExitOK
		}
		fmt.Fprintf(stdout, "Backend : %s\n", b.Backend())
		fmt.Fprintf(stdout, "Blocked : %d\n", len(entries))
		for _, e := range entries {
			line := " [blocked] " + report.TermSafe(e.Addr)
			if !e.Expires.IsZero() {
				line += fmt.Sprintf("  expires in %s", time.Until(e.Expires).Round(time.Second))
			} else {
				line += "  no expiry"
			}
			if e.Reason != "" {
				line += "  — " + truncStr(report.TermSafe(e.Reason), 160)
			}
			fmt.Fprintln(stdout, line)
		}
		fmt.Fprintf(stdout, "Never blocked (this host's own addresses, gateways and resolvers): %s\n",
			strings.Join(b.Protected(), ", "))
		return report.ExitOK
	case "clear":
		if err := b.Clear(); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fmt.Fprintln(stdout, " [clear] every rule cau created is removed; the host's own firewall is untouched")
		printCommands(stdout, b, nf.dryRun)
		return report.ExitOK
	}
	return report.ExitUsage
}

func printCommands(w io.Writer, b *netblock.Blocker, dryRun bool) {
	if !dryRun {
		return
	}
	fmt.Fprintln(w, "\n Dry run — these are the commands that were NOT run:")
	for _, c := range b.Commands() {
		fmt.Fprintf(w, "   %s\n", report.TermSafe(c))
	}
}

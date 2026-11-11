// Package netscan is cau's network-plane sensor: a point-in-time read of every
// socket the host owns, attributed to the process and the executable behind it,
// plus the host's resolver and neighbour state.
//
// It is the NDR half of the engine, and it is READ-ONLY and offline. It opens no
// socket, sends no probe and captures no packets: everything here comes from
// /proc (the kernel's own socket tables, one per network namespace) and from
// /etc/resolv.conf. Acting on a result is a separate, explicit step — see the
// netblock package.
//
// Why /proc and not a packet tap: a tap sees bytes without an owner, and the
// question that matters for response is *which process* is talking to a peer and
// *what file* that process runs from. The kernel already joins those three, so
// the sensor reads the join rather than inferring it. The cost is that content
// is invisible (no payload, no TLS fingerprint) and short-lived connections
// between two samples are missed; both are stated in docs/limitations.md.
//
// What it looks for:
//
//   - Fileless network presence: a socket held by a process whose executable is
//     a memfd, a deleted inode or a tmpfs path. A payload that never touched
//     disk and now holds a connection is the strongest single signal here, and
//     the only network class besides a feed hit that counts as live state
//     (T1620 with T1071 / T1571).
//   - Bind shells and relays: a listener owned by an interpreter, or by nc,
//     ncat, socat or telnet, whatever its command line says (T1059.004).
//   - Known-bad peers: a remote address present in the abuse-intel feed, which
//     is an exact identification rather than a score (T1071).
//   - Handler ports: the default ports of the common reverse-shell handlers,
//     scored as context only because a developer can bind any of them.
//   - Egress from a non-system executable: a listener on a wildcard address, or
//     a connection, owned by a binary no package put there.
//   - DNS-plane escape: a process speaking 53 or 853 directly past the system
//     resolver (T1071.004), and a resolver configuration naming a nameserver
//     that is neither local nor a documented public one.
//   - Connect sweeps: one process with established-or-pending connections to
//     many distinct peers, the shape of service discovery (T1046).
//   - Beaconing: repeated short connections to one peer at a regular interval,
//     measured across samples by History (T1071.001).
//   - Neighbour-table tampering: the default gateway's MAC changing under us, or
//     one MAC claiming the gateway and another address (T1557.002).
//
// Scoring is deliberately conservative. Only two classes assert live state, so
// everything else needs a second layer before the correlator will let a machine
// act on it, and a developer's `python3 -m http.server` scores below the
// reporting threshold on its own.
package netscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/intel"
)

// DefaultThreshold is the per-subject score at which a network finding is
// reported. A subject is one process, or one peer when no process could be read.
const DefaultThreshold = 5

// ATT&CK technique ids used by this package.
const (
	techAppLayer    = "T1071"     // Application Layer Protocol
	techWebProto    = "T1071.001" // Application Layer Protocol: Web Protocols
	techDNSProto    = "T1071.004" // Application Layer Protocol: DNS
	techNonStdPort  = "T1571"     // Non-Standard Port
	techUnixShell   = "T1059.004" // Command and Scripting Interpreter: Unix Shell
	techFileless    = "T1620"     // Reflective Code Loading
	techDiscovery   = "T1046"     // Network Service Discovery
	techARPPoison   = "T1557.002" // Adversary-in-the-Middle: ARP Cache Poisoning
	techProtoTunnel = "T1572"     // Protocol Tunneling
)

// Finding is one signal raised against a socket, a process or the host's
// network configuration.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Exe       string `json:"exe,omitempty"`
	// Peer is the remote address the finding is about, without a port, so it can
	// be matched against a feed and handed to the blocker.
	Peer string `json:"peer,omitempty"`
	Port int    `json:"port,omitempty"`
	// Live marks a state of the host rather than a reading of it: a process with
	// no file on disk really does hold a socket. Argv and configuration text are
	// never live.
	Live bool `json:"live,omitempty"`
	// Definitive marks an exact identification: a feed indicator matched.
	Definitive bool `json:"definitive,omitempty"`

	// subj is what the threshold adds this finding up against, set by whichever
	// analytic raised it: a process, a peer, or the socket itself. It is not
	// reported, because it is a detail of the thresholding and not evidence.
	//
	// Getting it wrong is how a sensor invents findings. Without it, every
	// unattributed socket of one class shares a subject, so six harmless
	// packet sockets scoring 2 each add up to 12 and all six are reported —
	// measured on the development host, which is why this field exists.
	subj string
}

// Result is the whole-scan outcome.
type Result struct {
	Sockets     int       `json:"sockets"`
	Attributed  int       `json:"attributed"`
	Listeners   int       `json:"listeners"`
	Established int       `json:"established"`
	Unreadable  int       `json:"unreadable"`
	Threshold   int       `json:"threshold"`
	Flagged     []Finding `json:"flagged,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
}

// Options configure a scan. The zero value scans the running host.
type Options struct {
	// ProcRoot overrides "/proc" (for tests).
	ProcRoot string
	// EtcRoot overrides "/etc" (for tests).
	EtcRoot string
	// Threshold is the per-subject score to report; 0 means DefaultThreshold.
	Threshold int
	// Intel is the abuse-intel feed remote addresses are matched against. Nil
	// disables the feed classes.
	Intel *intel.Feed
	// History carries what earlier scans saw, which is what the beaconing and
	// gateway-churn analytics need. Nil disables those classes; one History
	// reused across scans enables them without any other change.
	History *History
	// Watch are addresses another source has already identified, mapped to why.
	// A connection to one is reported whatever it would otherwise have scored.
	//
	// This is what makes evidence from elsewhere useful here: a firewall or
	// another host says an address is a command-and-control server, and this
	// host's own quiet, sub-threshold connection to it stops being quiet. The
	// sensor's thresholds are there to keep weak evidence from being reported
	// alone, not to hide it from a source that already knows better.
	Watch map[string]string
	// Now overrides the clock (for tests).
	Now time.Time
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Scan reads the host's network plane and scores what it finds.
func Scan(opts Options) *Result {
	res := &Result{Threshold: opts.Threshold}
	if res.Threshold < 1 {
		res.Threshold = DefaultThreshold
	}
	socks, unreadable, warns := readSockets(opts)
	res.Sockets, res.Unreadable, res.Warnings = len(socks), unreadable, warns
	for _, s := range socks {
		if s.PID > 0 {
			res.Attributed++
		}
		switch {
		case s.listening():
			res.Listeners++
		case s.State == stateEstablished:
			res.Established++
		}
	}

	findings := detect(socks, opts)
	findings = append(findings, resolverFindings(opts)...)
	findings = append(findings, neighbourFindings(opts)...)
	if opts.History != nil {
		findings = append(findings, opts.History.observe(socks, opts.now())...)
	}
	res.Flagged = filter(findings, res.Threshold)
	return res
}

// subject is what a finding is about, for thresholding: whatever the analytic
// said, or failing that one process, one peer, or the class itself — the last
// being right only for the host-configuration classes, where one finding is one
// line of configuration and already scores on its own.
func subject(f Finding) string {
	switch {
	case f.subj != "":
		return f.subj
	case f.PID > 0:
		return "p:" + strconv.Itoa(f.PID)
	case f.Peer != "":
		return "n:" + f.Peer
	default:
		return "c:" + f.Class
	}
}

// filter drops subjects whose signals do not add up to the threshold, and keeps
// every signal of the ones that do. A finding that asserts live state or an
// exact identification always survives: a threshold is a guard against weak
// evidence, and those two are not weak.
func filter(findings []Finding, threshold int) []Finding {
	total := map[string]int{}
	for _, f := range findings {
		total[subject(f)] += f.Score
	}
	var out []Finding
	for _, f := range findings {
		if f.Score < 1 {
			continue
		}
		if f.Live || f.Definitive || total[subject(f)] >= threshold {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// Score is the sum of every reported finding, which is what a caller compares
// against its own policy.
func (r *Result) Score() int {
	n := 0
	for _, f := range r.Flagged {
		n += f.Score
	}
	return n
}

// Peers are the distinct remote addresses the scan flagged, strongest first.
// They are what a blocker is handed.
func (r *Result) Peers() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range r.Flagged {
		if f.Peer != "" && !seen[f.Peer] {
			seen[f.Peer] = true
			out = append(out, f.Peer)
		}
	}
	return out
}

// hostPort renders an address the way an operator reads it.
func hostPort(ip string, port int) string {
	if ip == "" {
		return ""
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

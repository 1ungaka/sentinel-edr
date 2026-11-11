package netscan

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/intel"
	"github.com/1ungaka/sentinel-edr/internal/procscan"
)

// handlerPorts are the default listen ports of the common reverse-shell and
// implant handlers (Metasploit, the shell one-liners that circulate, a few
// botnet families). A developer can bind any of them, so a handler port is
// never more than context: it is scored low on purpose and reaches the
// reporting threshold only next to something else about the same process.
var handlerPorts = map[int]string{
	1337: "handler", 4444: "metasploit default", 4445: "metasploit default",
	5554: "handler", 6666: "handler", 7777: "handler", 9001: "handler",
	9999: "handler", 12345: "handler", 31337: "handler", 53413: "implant",
}

// resolverComms are the programs whose job is DNS. One of them talking to a
// nameserver, over any protocol, is the system working as configured.
var resolverComms = map[string]bool{
	"systemd-resolve": true, "systemd-resolved": true, "resolved": true,
	"dnsmasq": true, "named": true, "unbound": true, "nscd": true,
	"dnscrypt-proxy": true, "stubby": true, "knot-resolver": true, "kresd": true,
	"pdns_recursor": true, "coredns": true, "avahi-daemon": true,
}

// publicResolvers are the nameservers a host is routinely, legitimately pointed
// at. A resolv.conf naming one of these is normal; one naming some other
// address outside the local networks is the signal.
var publicResolvers = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true, "1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "149.112.112.112": true, "208.67.222.222": true,
	"208.67.220.220": true, "76.76.2.0": true, "94.140.14.14": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true,
	"2620:fe::fe": true, "2620:fe::9": true,
}

// sweepPending is how many connections one process may have in flight before
// the shape is service discovery rather than an application opening sockets. A
// browser loading a page holds a handful; a sweep holds dozens.
const sweepPending = 12

// sweepPeers is the distinct-peer count at which even completed connections
// from a process no package installed look like enumeration.
const sweepPeers = 64

// detectCtx is everything the per-socket analytics need besides the socket.
type detectCtx struct {
	feed      *intel.Feed
	resolvers map[string]bool
	watch     map[string]string
}

func detect(socks []Socket, opts Options) []Finding {
	ctx := detectCtx{feed: opts.Intel, resolvers: map[string]bool{}, watch: opts.Watch}
	for _, r := range Resolvers(etcRoot(opts)) {
		ctx.resolvers[r] = true
	}
	var out []Finding
	for _, s := range socks {
		if isCapture(s.Proto) {
			out = append(out, captureFindings(s)...)
			continue
		}
		out = append(out, socketFindings(s, ctx)...)
	}
	return append(out, sweepFindings(socks)...)
}

// socketFindings scores one socket. It is a pure function of the row and the
// context, which is what makes the policy testable without a host or an attack.
func socketFindings(s Socket, ctx detectCtx) []Finding {
	at := func(f Finding) Finding {
		f.PID, f.Exe, f.subj = s.PID, TrimDeleted(s.Exe), s.subject()
		return f
	}
	var out []Finding
	listening := s.listening()
	remote := net.ParseIP(s.Remote.IP)
	local := net.ParseIP(s.Local.IP)
	// A peer on this host is inter-process communication that happens to use the
	// IP stack. It is not network presence, and flagging it would report every
	// database client on the machine.
	loopbackPeer := remote != nil && remote.IsLoopback()
	localOnly := listening && local != nil && local.IsLoopback()
	talking := s.State == stateEstablished || s.State == stateSynSent

	// Fileless network presence. A process whose executable is an anonymous
	// in-memory file, an unlinked inode or a tmpfs path has left nothing on disk
	// to find later, and it holds a socket now. This is a state of the host, not
	// a reading of text about one, so it is the one network class that confirms
	// an incident on its own.
	if s.ExeKind != "" && (talking || listening) {
		class, tech, what := "netscan.egress.fileless", techFileless+","+techAppLayer, "connected to "+s.Remote.String()
		if listening {
			class, tech, what = "netscan.listen.fileless", techFileless+","+techNonStdPort, "listening on "+s.Local.String()
		}
		out = append(out, at(Finding{
			Class: class, Score: 9, Technique: tech, Live: true,
			Detail:   fmt.Sprintf("%s (%s executable, nothing on disk) is %s", s.procName(), s.ExeKind, what),
			Evidence: s.Exe, Peer: s.peerAddr(), Port: s.port(),
		}))
	}

	if talking && !loopbackPeer && ctx.feed != nil {
		if hit, ok := ctx.feed.MatchHost(s.Remote.IP); ok {
			label := hit.Label
			if label == "" {
				label = "listed indicator"
			}
			out = append(out, at(Finding{
				Class: "netscan.egress.intel", Score: 9, Technique: techAppLayer, Definitive: true,
				Detail: fmt.Sprintf("%s is connected to %s, a known-bad %s in the feed: %s",
					s.procName(), s.Remote.String(), hit.Kind, truncate(label, 120)),
				Evidence: string(hit.Kind) + " " + hit.Value, Peer: s.peerAddr(), Port: s.port(),
			}))
		}
	}

	// An address somebody else has already identified. The score is enough to
	// be reported on its own, because the identification did not come from this
	// host's own guesswork — but it is not definitive here, since what the
	// other source knows cannot be checked from here.
	if why, ok := ctx.watch[s.Remote.IP]; ok && talking && !loopbackPeer {
		out = append(out, at(Finding{
			Class: "netscan.egress.watchlist", Score: 6, Technique: techAppLayer,
			Detail: fmt.Sprintf("%s is connected to %s, an address already identified elsewhere: %s",
				s.procName(), s.Remote.String(), truncate(why, 160)),
			Evidence: s.Remote.String(), Peer: s.peerAddr(), Port: s.Remote.Port,
		}))
	}

	switch {
	case listening && !localOnly && procscan.IsShellRelay(s.Comm):
		// nc, ncat, socat or telnet waiting for a peer. The program is the
		// behaviour: there is no configuration in which one of these is a
		// service, and the port it offers is whatever connects to it.
		out = append(out, at(Finding{
			Class: "netscan.listen.relay-tool", Score: 7, Technique: techUnixShell,
			Detail:   fmt.Sprintf("%s, a network relay, is listening on %s: the bind-shell shape", s.procName(), s.Local.String()),
			Evidence: s.Comm + " " + s.Local.String(), Port: s.Local.Port,
		}))
	case listening && !localOnly && procscan.IsInterpreter(s.Comm):
		out = append(out, at(Finding{
			Class: "netscan.listen.interpreter", Score: 4, Technique: techUnixShell,
			Detail:   fmt.Sprintf("the interpreter %s is listening on %s", s.procName(), s.Local.String()),
			Evidence: s.Comm + " " + s.Local.String(), Port: s.Local.Port,
		}))
	case listening && s.wildcard() && s.Exe != "" && !procscan.SystemPath(TrimDeleted(s.Exe)):
		out = append(out, at(Finding{
			Class: "netscan.listen.nonsystem", Score: 3, Technique: techNonStdPort,
			Detail:   fmt.Sprintf("%s, which no package installed, is listening on every address at %s", s.procName(), s.Local.String()),
			Evidence: s.Exe, Port: s.Local.Port,
		}))
	}

	if talking && !loopbackPeer && procscan.IsShellRelay(s.Comm) {
		out = append(out, at(Finding{
			Class: "netscan.egress.relay-tool", Score: 4, Technique: techUnixShell,
			Detail:   fmt.Sprintf("%s, a network relay, is connected out to %s", s.procName(), s.Remote.String()),
			Evidence: s.Comm + " → " + s.Remote.String(), Peer: s.peerAddr(), Port: s.Remote.Port,
		}))
	}

	if what, ok := handlerPorts[s.Remote.Port]; ok && talking && !loopbackPeer {
		out = append(out, at(Finding{
			Class: "netscan.egress.handler-port", Score: 3, Technique: techNonStdPort,
			Detail:   fmt.Sprintf("%s is connected to %s, the %s port", s.procName(), s.Remote.String(), what),
			Evidence: s.Remote.String(), Peer: s.peerAddr(), Port: s.Remote.Port,
		}))
	}
	if what, ok := handlerPorts[s.Local.Port]; ok && listening && !localOnly {
		out = append(out, at(Finding{
			Class: "netscan.listen.handler-port", Score: 4, Technique: techNonStdPort,
			Detail:   fmt.Sprintf("%s is listening on %s, the %s port", s.procName(), s.Local.String(), what),
			Evidence: s.Local.String(), Port: s.Local.Port,
		}))
	}

	out = append(out, dnsFindings(s, ctx, at)...)
	return out
}

// dnsFindings scores the DNS plane as seen from one socket.
//
// A process sending to port 53 is NOT a signal: glibc's resolver runs inside
// every program that looks up a name, so the whole host does it. The signal is a
// query sent somewhere the host was never configured to send one, which is what
// a tunnel to an operator-run nameserver looks like, and an encrypted-DNS
// connection from a program whose job is not DNS.
func dnsFindings(s Socket, ctx detectCtx, at func(Finding) Finding) []Finding {
	if s.State != stateEstablished && !(strings.HasPrefix(s.Proto, "udp") && s.Remote.Port != 0) {
		return nil
	}
	remote := net.ParseIP(s.Remote.IP)
	if remote == nil || remote.IsLoopback() {
		return nil
	}
	if resolverComms[s.Comm] {
		return nil // the resolver resolving is the system working
	}
	switch s.Remote.Port {
	case 53:
		if ctx.resolvers[s.Remote.IP] || len(ctx.resolvers) == 0 {
			return nil
		}
		return []Finding{at(Finding{
			Class: "netscan.dns.off-resolver", Score: 3, Technique: techDNSProto,
			Detail: fmt.Sprintf("%s is querying %s, which is not a nameserver this host is configured to use",
				s.procName(), s.Remote.String()),
			Evidence: "resolv.conf: " + strings.Join(sortedKeys(ctx.resolvers), ", "),
			Peer:     s.peerAddr(), Port: s.Remote.Port,
		})}
	case 853, 8853, 784:
		return []Finding{at(Finding{
			Class: "netscan.dns.encrypted-escape", Score: 3, Technique: techProtoTunnel,
			Detail: fmt.Sprintf("%s is speaking encrypted DNS to %s, past the host's own resolver",
				s.procName(), s.Remote.String()),
			Evidence: s.Remote.String(), Peer: s.peerAddr(), Port: s.Remote.Port,
		})}
	}
	return nil
}

// sweepFindings looks for one process reaching many peers at once: connections
// still waiting for an answer are what separates enumeration from an
// application opening sockets, because a sweep's targets mostly do not reply.
func sweepFindings(socks []Socket) []Finding {
	type fan struct {
		pending, peers map[string]bool
		exe, comm      string
	}
	by := map[int]*fan{}
	for _, s := range socks {
		if isCapture(s.Proto) || s.PID == 0 || s.Remote.IP == "" || s.Remote.Port == 0 {
			continue
		}
		if ip := net.ParseIP(s.Remote.IP); ip == nil || ip.IsLoopback() {
			continue
		}
		f := by[s.PID]
		if f == nil {
			f = &fan{pending: map[string]bool{}, peers: map[string]bool{}, exe: TrimDeleted(s.Exe), comm: s.Comm}
			by[s.PID] = f
		}
		switch s.State {
		case stateSynSent:
			f.pending[s.Remote.IP] = true
			f.peers[s.Remote.IP] = true
		case stateEstablished:
			f.peers[s.Remote.IP] = true
		}
	}
	pids := make([]int, 0, len(by))
	for pid := range by {
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	var out []Finding
	for _, pid := range pids {
		f := by[pid]
		name := f.comm + " pid " + strconv.Itoa(pid)
		system := f.exe == "" || procscan.SystemPath(f.exe)
		switch {
		case len(f.pending) >= sweepPending:
			score := 6
			if !system {
				score = 7
			}
			out = append(out, Finding{
				Class: "netscan.sweep.pending", Score: score, Technique: techDiscovery,
				Detail: fmt.Sprintf("%s has connections in flight to %s at once, the shape of service discovery",
					name, plural(len(f.pending), "peer", "peers")),
				Evidence: strings.Join(firstN(sortedKeys(f.pending), 8), ", "),
				PID:      pid, Exe: f.exe,
			})
		case len(f.peers) >= sweepPeers && !system:
			out = append(out, Finding{
				Class: "netscan.sweep.fanout", Score: 4, Technique: techDiscovery,
				Detail: fmt.Sprintf("%s, which no package installed, is talking to %s",
					name, plural(len(f.peers), "peer", "distinct peers")),
				Evidence: strings.Join(firstN(sortedKeys(f.peers), 8), ", "),
				PID:      pid, Exe: f.exe,
			})
		}
	}
	return out
}

// procName renders the holder of a socket, or says plainly that it could not be
// read, which without root is most other users' processes.
func (s Socket) procName() string {
	if s.PID == 0 {
		return "an unattributed socket (its holder was not readable)"
	}
	return s.Comm + " pid " + strconv.Itoa(s.PID)
}

// peerAddr is the remote address without its port: what a blocker acts on.
func (s Socket) peerAddr() string {
	if ip := net.ParseIP(s.Remote.IP); ip == nil || ip.IsUnspecified() {
		return ""
	}
	return s.Remote.IP
}

func (s Socket) port() int {
	if s.listening() {
		return s.Local.Port
	}
	return s.Remote.Port
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

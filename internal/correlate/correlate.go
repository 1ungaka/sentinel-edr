// Package correlate joins what the detection layers see into incidents.
//
// Each layer answers its own question and is blind to the others. The process
// scanner finds a shell and never reads its file; the persistence audit finds a
// cron line and never scans what it runs; the file scanner reads what it is
// pointed at. An attack is one thing seen from several sides, so this package
// joins signals that share an artefact: a process, its executable and the
// autostart entry that brings it back become one incident.
//
// It is a pure function of its input, which is what makes the response policy
// reviewable: Confirmed decides what a machine may act on, and it can be tested
// without a host or an attack.
package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/parallel"
)

// Layer is the detection layer a signal came from.
type Layer string

// Layers.
const (
	LayerProcess     Layer = "process"
	LayerFile        Layer = "file"
	LayerPersistence Layer = "persistence"
	LayerKernel      Layer = "kernel"
	LayerCanary      Layer = "canary"
	LayerPackage     Layer = "package"
	// LayerNetwork is the network plane as the host's own kernel sees it: which
	// process holds which socket, where it is talking to, what the resolver and
	// the neighbour table say.
	LayerNetwork Layer = "network"
	// LayerExternal is telemetry from somewhere else — another cau host, a
	// firewall, an IDS, anything that speaks one of the formats the ingest
	// package reads. It is what makes a cross-host incident possible, and it is
	// never acted on by machine: see PlanFor.
	LayerExternal Layer = "external"
	// LayerSelf is the agent reporting on itself: a task crashed, so something may
	// have gone unseen, or its detection content no longer matches its baseline.
	// These name no file and no process, so PlanFor gives them nothing to act on.
	// Whether one confirms depends on Live: a crash does not, tampering does.
	LayerSelf Layer = "self"
)

// Signal is one layer's finding. Files and PID are what link it to others.
type Signal struct {
	Layer Layer  `json:"layer"`
	Class string `json:"class"`
	Score int    `json:"score"`
	// Technique is an ATT&CK id, or several separated by commas.
	Technique string   `json:"technique,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Files     []string `json:"files,omitempty"`
	PID       int      `json:"pid,omitempty"`
	// Live marks evidence of a running attack, a state of the host rather than
	// text that describes one: a shell's stdio really is a socket. Argv and file
	// contents are never live, because `grep "/dev/tcp" notes` holds the same
	// text as the attack.
	Live bool `json:"live,omitempty"`
	// Definitive marks an exact identification: a hash or YARA hit.
	Definitive bool `json:"definitive,omitempty"`
	// Peers are the remote network addresses this signal is about. They link a
	// network signal to every other signal about the same peer, and they are
	// what a block acts on.
	Peers []string `json:"peers,omitempty"`
	// Host is where the signal was observed. Empty means this host, which is
	// what every local layer leaves it as. A named host comes from ingested
	// telemetry, and it scopes the links: two hosts each with a /tmp/x are two
	// artefacts, not one, and only this host's artefacts may be acted on.
	Host string `json:"host,omitempty"`
}

// Incident is every signal about one artefact.
type Incident struct {
	ID    string   `json:"id"`
	Files []string `json:"files,omitempty"`
	PIDs  []int    `json:"pids,omitempty"`
	// Peers are the remote addresses this incident involves.
	Peers []string `json:"peers,omitempty"`
	// Hosts are the hosts it was seen on, named only when more than this one is
	// involved: a local-only incident leaves it empty.
	Hosts      []string `json:"hosts,omitempty"`
	Layers     []Layer  `json:"layers"`
	Techniques []string `json:"techniques,omitempty"`
	Score      int      `json:"score"`
	Confirmed  bool     `json:"confirmed"`
	// Why says what confirmed it, or what is missing.
	Why     string   `json:"why"`
	Signals []Signal `json:"signals"`
}

// systemPrefixes hold programs the host itself runs. They never link signals:
// every shell on the machine has /usr/bin/bash as its executable, so joining on
// it would merge every unrelated incident into one.
var systemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/proc/", "/sys/", "/dev/null", "/dev/tty", "/dev/pts/"}

// Linkable reports whether a path identifies an artefact worth joining on, and
// worth acting on.
func Linkable(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	for _, p := range systemPrefixes {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	return true
}

var pathRe = regexp.MustCompile(`(?:^|[\s'"=:;(|&<>])(/[A-Za-z0-9._/+@-]+)`)

// ReferencedPaths extracts the linkable absolute paths named in a line of
// configuration, so a cron entry links to the file it runs.
func ReferencedPaths(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range pathRe.FindAllStringSubmatch(text, 32) {
		p := strings.TrimRight(m[1], ".,/")
		if Linkable(p) && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// LinkablePeer reports whether a remote address identifies a peer worth joining
// signals on, and worth acting on. A peer on this host, or one that stands for
// every host or for a group of them, identifies nothing: joining on it would
// merge every unrelated incident, and blocking it would cut the host off.
func LinkablePeer(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() &&
		!ip.IsInterfaceLocalMulticast() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

// union is a disjoint set over signal indexes.
type union []int

func (u union) find(i int) int {
	for u[i] != i {
		u[i] = u[u[i]]
		i = u[i]
	}
	return i
}

func (u union) join(a, b int) { u[u.find(a)] = u.find(b) }

// Build groups signals sharing a file or a process, strongest incident first.
func Build(signals []Signal) []Incident {
	u := make(union, len(signals))
	for i := range u {
		u[i] = i
	}
	first := map[string]int{}
	link := func(key string, i int) {
		if j, ok := first[key]; ok {
			u.join(i, j)
		} else {
			first[key] = i
		}
	}
	for i, s := range signals {
		// Every artefact key carries the host it was seen on. Without that, one
		// host's /tmp/payload and another's would be joined into a single
		// incident and a response planned for the wrong machine.
		for _, f := range s.Files {
			if Linkable(f) {
				link("f:"+s.Host+":"+f, i)
			}
		}
		if s.PID > 0 {
			link(fmt.Sprintf("p:%s:%d", s.Host, s.PID), i)
		}
		// A peer is the one key that joins ACROSS hosts on purpose: the same
		// command-and-control address seen from two machines is one incident,
		// which is the whole point of taking in telemetry from elsewhere.
		for _, p := range s.Peers {
			if LinkablePeer(p) {
				link("n:"+p, i)
			}
		}
	}
	groups := map[int][]Signal{}
	for i, s := range signals {
		r := u.find(i)
		groups[r] = append(groups[r], s)
	}
	grouped := make([][]Signal, 0, len(groups))
	for _, g := range groups {
		grouped = append(grouped, g)
	}
	out := make([]Incident, len(grouped))
	parallel.For(len(grouped), 0, func(i int) { out[i] = incident(grouped[i]) })
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confirmed != out[j].Confirmed {
			return out[i].Confirmed
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func incident(sigs []Signal) Incident {
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].Class < sigs[j].Class })
	inc := Incident{Signals: sigs}
	files, pids, layers, techs := map[string]bool{}, map[int]bool{}, map[Layer]bool{}, map[string]bool{}
	peers, hosts := map[string]bool{}, map[string]bool{}
	live, definitive := "", ""
	for _, s := range sigs {
		inc.Score += s.Score
		layers[s.Layer] = true
		for _, t := range strings.Split(s.Technique, ",") {
			if t != "" {
				techs[t] = true
			}
		}
		if s.PID > 0 {
			pids[s.PID] = true
		}
		for _, f := range s.Files {
			files[f] = true
		}
		for _, p := range s.Peers {
			if LinkablePeer(p) {
				peers[p] = true
			}
		}
		if s.Host != "" {
			hosts[s.Host] = true
		}
		if s.Live && live == "" {
			live = s.Class
		}
		if s.Definitive && definitive == "" {
			definitive = s.Class
		}
	}
	inc.Files = keys(files)
	inc.Peers = keys(peers)
	inc.Techniques = keys(techs)
	// Hosts is named only when telemetry from elsewhere is part of the incident:
	// for a purely local one there is nothing to say.
	if len(hosts) > 0 {
		inc.Hosts = keys(hosts)
	}
	for p := range pids {
		inc.PIDs = append(inc.PIDs, p)
	}
	sort.Ints(inc.PIDs)
	for l := range layers {
		inc.Layers = append(inc.Layers, l)
	}
	sort.Slice(inc.Layers, func(i, j int) bool { return inc.Layers[i] < inc.Layers[j] })

	// inc.Layers names every layer in the incident, for the report. The count
	// that confirms it is the agreeing one, below: a sensor somewhere else
	// reporting an informational or unknown severity is not a second opinion
	// about this host.
	agreeing := agreeingLayers(sigs)
	switch {
	case live != "":
		inc.Confirmed, inc.Why = true, "live attack state: "+live
	case len(agreeing) >= 2:
		inc.Confirmed, inc.Why = true, fmt.Sprintf("%d independent layers agree", len(agreeing))
	case definitive != "":
		inc.Confirmed, inc.Why = true, "known-bad content: "+definitive
	default:
		inc.Why = "one layer, no live state: alert only, needs a human or a second layer"
	}

	h := sha256.New()
	for _, k := range inc.Hosts {
		fmt.Fprintln(h, "h", k)
	}
	for _, k := range inc.Files {
		fmt.Fprintln(h, "f", k)
	}
	for _, p := range inc.PIDs {
		fmt.Fprintln(h, "p", p)
	}
	for _, k := range inc.Peers {
		fmt.Fprintln(h, "n", k)
	}
	inc.ID = hex.EncodeToString(h.Sum(nil))[:16]
	return inc
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// agreeingLayers is the set of layers whose evidence can stand on its own. A
// signal observed somewhere else joins an incident about the same artefact, and
// with a real score behind it that is a second opinion worth confirming on; at
// informational or unknown severity it says only that a sensor was running, so
// it never counts as the extra layer that turns an alert into a confirmed
// incident. Local layers are their own host's evidence and always count.
func agreeingLayers(sigs []Signal) map[Layer]bool {
	layers := map[Layer]bool{}
	for _, s := range sigs {
		if s.Host != "" && s.Score < minCorroboratingScore {
			continue
		}
		layers[s.Layer] = true
	}
	return layers
}

// Fingerprint changes when an incident gains evidence, so an incident already
// reported is raised again only when something new is known about it.
func (i Incident) Fingerprint() string {
	classes := make([]string, 0, len(i.Signals))
	for _, s := range i.Signals {
		classes = append(classes, string(s.Layer)+"/"+s.Class)
	}
	sort.Strings(classes)
	return i.ID + "|" + strings.Join(classes, ",")
}

// actsOnProcess is the layers that see a process as the kernel does.
func actsOnProcess(l Layer) bool {
	return l == LayerProcess || l == LayerKernel || l == LayerNetwork
}

// Quarantinable reports whether a flagged file may be moved by machine. Nothing
// under /etc may: a PAM stack, a sudoers fragment or a cron table is exactly what
// locks an operator out when it vanishes, and the file is the evidence. Those stay
// an alert for a human, however they were flagged.
//
// The path is judged after cleaning, because the store resolves it with
// filepath.Abs before it acts: "/tmp/../etc/cron.d/job" is a cron table, and
// rejecting only the spelled-out form would let that spelling keep the policy
// bypass. A relative path cannot be judged here at all — it names whatever
// directory the responder happens to be running in — so it is not quarantinable
// either.
func Quarantinable(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	clean := filepath.Clean(path)
	if clean == "/etc" || strings.HasPrefix(clean, "/etc/") {
		return false
	}
	return Linkable(clean)
}

// Plan is what a confirmed incident permits. It is empty for an unconfirmed one.
type Plan struct {
	Stop       []int    `json:"stop,omitempty"`
	Quarantine []string `json:"quarantine,omitempty"`
	// Block are remote addresses the kernel may be asked to drop. They come only
	// from the network layer: a peer named in a script's text is a string, while
	// a peer the kernel reports is a connection that exists.
	Block []string `json:"block,omitempty"`
}

// minCorroboratingScore is what a signal from elsewhere must score before it may
// corroborate a local one and so license a response on this host. The ingest
// scale maps OCSF's informational and unknown severities to 1: a peer host saying
// "something happened" is not evidence about this one, and it must never be what
// stops a process or blocks a peer. A medium finding (4) and above is.
const minCorroboratingScore = 4

// PlanFor decides what may be done. Only a file the content scanner itself
// flagged is quarantined: a persistence signal names a file too, but that file
// may be a cron table or a PAM stack, and the audit stays read-only on purpose
// because removing the line by machine destroys the evidence and can lock the
// operator out.
func PlanFor(inc Incident) Plan {
	var p Plan
	if !inc.Confirmed {
		return p
	}
	// A process may be stopped on its own live or exact evidence, or when some
	// other layer points at it. Sharing an incident is not enough: everything run by
	// one interpreter outside the system paths joins through that file, and a process
	// with only text against it must not be stopped for its neighbour's shell.
	named := map[string]bool{}
	layersOn := map[int]map[Layer]bool{}
	for _, s := range inc.Signals {
		if s.Host == "" && actsOnProcess(s.Layer) {
			if s.PID > 0 {
				if layersOn[s.PID] == nil {
					layersOn[s.PID] = map[Layer]bool{}
				}
				layersOn[s.PID][s.Layer] = true
			}
			continue
		}
		if s.Host == "" {
			for _, f := range s.Files {
				named["f:"+f] = true
			}
		} else if s.Score < minCorroboratingScore {
			// Telemetry from elsewhere corroborates only when it carries a real
			// score. An informational or unknown severity is a sensor saying
			// "something happened", which is not evidence about this host: it
			// joins the incident and is never what licenses acting on it.
			continue
		}
		for _, peer := range s.Peers {
			named["p:"+peer] = true
		}
	}
	corroborated := func(s Signal) bool {
		if s.Live || s.Definitive || len(layersOn[s.PID]) >= 2 {
			return true
		}
		for _, f := range s.Files {
			if named["f:"+f] {
				return true
			}
		}
		for _, peer := range s.Peers {
			if named["p:"+peer] {
				return true
			}
		}
		return false
	}

	stop := map[int]bool{}
	quarantine := map[string]bool{}
	block := map[string]bool{}
	for _, s := range inc.Signals {
		// A signal observed somewhere else names a PID and a path on THAT host.
		// Acting on it here would stop an unrelated process and quarantine an
		// unrelated file, so a remote signal corroborates and never directs.
		if s.Host != "" {
			continue
		}
		// The layers that read the kernel's own view of a process may ask for
		// it to be stopped: the process table, the exec guard, and the socket
		// tables, which attribute a connection to its holder through the same
		// /proc interfaces. A persistence or package signal names a file and no
		// running process, and a remote signal's PID belongs to another host.
		if s.PID > 0 && actsOnProcess(s.Layer) && corroborated(s) {
			stop[s.PID] = true
		}
		if s.Layer == LayerFile {
			for _, f := range s.Files {
				if Quarantinable(f) {
					quarantine[f] = true
				}
			}
		}
		if s.Layer == LayerNetwork {
			for _, peer := range s.Peers {
				if LinkablePeer(peer) {
					block[peer] = true
				}
			}
		}
	}
	for pid := range stop {
		p.Stop = append(p.Stop, pid)
	}
	sort.Ints(p.Stop)
	p.Quarantine = keys(quarantine)
	if len(block) > 0 {
		p.Block = keys(block)
	}
	return p
}

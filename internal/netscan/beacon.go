package netscan

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/procscan"
)

// Beaconing bounds. A command channel checks in on a schedule; an application
// opens a connection when a person does something. The difference is regularity,
// which cannot be seen in one sample, so History carries what earlier samples
// saw and the analytic runs over the record.
const (
	// beaconMinHits is how many separate connections to one peer are needed
	// before an interval means anything. Three intervals is the fewest that can
	// show a cadence rather than a coincidence.
	beaconMinHits = 4
	// beaconMinPeriod and beaconMaxPeriod bound the cadences this reports.
	// Faster than this is a chatty application; slower is beyond a sample
	// window a daemon keeps in memory.
	beaconMinPeriod = 5 * time.Second
	beaconMaxPeriod = time.Hour
	// beaconJitter is the largest relative spread of the intervals that still
	// counts as a schedule. Real implants add jitter; 25 % is the point past
	// which a human's browsing is indistinguishable from one.
	beaconJitter = 0.25
	// beaconWindow is how long a peer with no new connections is remembered.
	beaconWindow = 2 * time.Hour

	maxTracks = 4096
	maxStarts = 64
	maxPorts  = 256
)

// History is what earlier scans saw. It is the only state netscan keeps, and it
// is in memory only: nothing here is written to disk, so a restart loses the
// record and the analytics that need it simply go quiet until it rebuilds.
//
// One History reused across scans enables the time-based classes (beaconing,
// gateway-MAC churn); a nil one disables them, which is what a single
// point-in-time `cau net` run does.
//
// It is safe for concurrent use: the defend daemon samples on its own schedule
// while the correlator reads.
type History struct {
	mu       sync.Mutex
	conns    map[string]*track
	arp      map[string]string // address → MAC, as the last sample saw it
	gateways map[string]string // gateway address → MAC, as the last sample saw it
	samples  int
}

// track is one process-to-peer pair's record of separate connections.
type track struct {
	comm, exe string
	peer      string
	pid       int
	kind      string
	// ports is the local port of every connection seen, with when it was first
	// seen. A local port that was not there last time is a new connection, which
	// is what a check-in is: the kernel picks a fresh ephemeral port each time.
	ports  map[int]time.Time
	starts []time.Time
	last   time.Time
}

// NewHistory returns an empty record.
func NewHistory() *History {
	return &History{conns: map[string]*track{}, arp: map[string]string{}, gateways: map[string]string{}}
}

// Samples is how many scans have been folded in, which is what tells an
// operator whether the time-based classes have had a chance to say anything.
func (h *History) Samples() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.samples
}

// observe folds one sample into the record and reports what the record now
// shows. It is called by Scan; callers do not need it.
func (h *History) observe(socks []Socket, now time.Time) []Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples++
	for _, s := range socks {
		if isCapture(s.Proto) || s.Remote.Port == 0 || s.Local.Port == 0 {
			continue
		}
		if s.State != stateEstablished && s.State != stateSynSent {
			continue
		}
		if ip := net.ParseIP(s.Remote.IP); ip == nil || ip.IsLoopback() {
			continue
		}
		key := s.beaconKey()
		t := h.conns[key]
		if t == nil {
			if len(h.conns) >= maxTracks {
				h.evict()
			}
			t = &track{ports: map[int]time.Time{}}
			h.conns[key] = t
		}
		t.comm, t.exe, t.pid, t.kind = s.Comm, TrimDeleted(s.Exe), s.PID, s.ExeKind
		t.peer = s.Remote.String()
		t.last = now
		if _, seen := t.ports[s.Local.Port]; !seen {
			if len(t.ports) >= maxPorts {
				t.ports = map[int]time.Time{}
			}
			t.ports[s.Local.Port] = now
			if len(t.starts) >= maxStarts {
				t.starts = t.starts[1:]
			}
			t.starts = append(t.starts, now)
		}
	}
	h.prune(now)

	var out []Finding
	for _, key := range sortedKeys(h.conns) {
		if f, ok := beacon(h.conns[key]); ok {
			out = append(out, f)
		}
	}
	return out
}

// evict drops the least recently seen half of the record, so a host that opens
// connections to endless distinct peers cannot grow this without bound.
func (h *History) evict() {
	keys := sortedKeys(h.conns)
	sort.Slice(keys, func(i, j int) bool { return h.conns[keys[i]].last.Before(h.conns[keys[j]].last) })
	for i := 0; i < len(keys)/2; i++ {
		delete(h.conns, keys[i])
	}
}

func (h *History) prune(now time.Time) {
	for k, t := range h.conns {
		if now.Sub(t.last) > beaconWindow {
			delete(h.conns, k)
		}
	}
}

// beaconKey identifies a process-to-peer pair across reconnections. The
// executable, not the PID, is the identity: an implant that re-executes keeps
// its schedule and would otherwise look like a new conversation each time.
func (s Socket) beaconKey() string {
	who := TrimDeleted(s.Exe)
	if who == "" {
		who = s.Comm
	}
	return who + "|" + s.Remote.String()
}

// beacon decides whether a record shows a schedule.
func beacon(t *track) (Finding, bool) {
	if len(t.starts) < beaconMinHits {
		return Finding{}, false
	}
	gaps := make([]float64, 0, len(t.starts)-1)
	for i := 1; i < len(t.starts); i++ {
		gaps = append(gaps, t.starts[i].Sub(t.starts[i-1]).Seconds())
	}
	mean, jitter := spread(gaps)
	if mean < beaconMinPeriod.Seconds() || mean > beaconMaxPeriod.Seconds() || jitter > beaconJitter {
		return Finding{}, false
	}
	host, _, err := net.SplitHostPort(t.peer)
	if err != nil {
		host = t.peer
	}
	// A process a package installed checking in on a schedule is how update
	// agents, time sync and telemetry clients work, so for one of those the
	// cadence is context and needs a second layer. For a binary no package
	// installed, the cadence is the finding.
	score := 3
	if t.exe == "" || !procscan.SystemPath(t.exe) || procscan.IsInterpreter(t.comm) {
		score = 6
	}
	name := t.comm
	if name == "" {
		name = t.exe
	}
	if t.pid > 0 {
		name += " pid " + strconv.Itoa(t.pid)
	}
	return Finding{
		Class: "netscan.beacon.periodic", Score: score, Technique: techWebProto,
		Detail: fmt.Sprintf("%s opened %s to %s on a schedule: every %s, jitter %.0f%%",
			name, plural(len(t.starts), "connection", "connections"), t.peer, round(mean), jitter*100),
		Evidence: fmt.Sprintf("intervals %s", formatGaps(gaps)),
		PID:      t.pid, Exe: t.exe, Peer: host,
	}, true
}

// spread returns the mean of the intervals and their relative standard
// deviation, which is the jitter a scheduler would have to add to hide.
func spread(gaps []float64) (mean, jitter float64) {
	if len(gaps) == 0 {
		return 0, 0
	}
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean <= 0 {
		return 0, 1
	}
	var sum float64
	for _, g := range gaps {
		sum += (g - mean) * (g - mean)
	}
	return mean, math.Sqrt(sum/float64(len(gaps))) / mean
}

func round(sec float64) time.Duration {
	return time.Duration(sec * float64(time.Second)).Round(time.Second)
}

func formatGaps(gaps []float64) string {
	parts := make([]string, 0, len(gaps))
	for _, g := range firstNf(gaps, 8) {
		parts = append(parts, round(g).String())
	}
	return strings.Join(parts, ", ")
}

func firstNf(s []float64, n int) []float64 {
	if len(s) > n {
		return s[:n]
	}
	return s
}

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/behavior"
	"github.com/1ungaka/sentinel-edr/internal/canary"
	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/forward"
	"github.com/1ungaka/sentinel-edr/internal/forward/wazuh"
	"github.com/1ungaka/sentinel-edr/internal/harden"
	"github.com/1ungaka/sentinel-edr/internal/ingest"
	"github.com/1ungaka/sentinel-edr/internal/intel"
	"github.com/1ungaka/sentinel-edr/internal/netblock"
	"github.com/1ungaka/sentinel-edr/internal/netscan"
	"github.com/1ungaka/sentinel-edr/internal/parallel"
	"github.com/1ungaka/sentinel-edr/internal/persist"
	"github.com/1ungaka/sentinel-edr/internal/procscan"
	"github.com/1ungaka/sentinel-edr/internal/provenance"
	"github.com/1ungaka/sentinel-edr/internal/quarantine"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/internal/sdnotify"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
	"github.com/1ungaka/sentinel-edr/internal/trust"
	"github.com/1ungaka/sentinel-edr/internal/watch"
	"github.com/1ungaka/sentinel-edr/scanner"
	"github.com/1ungaka/sentinel-edr/scanner/fusion"
	"github.com/1ungaka/sentinel-edr/scanner/static"
)

// defaultWatchRoots are where attacks land and where they make themselves stay.
// A root that does not exist is skipped, so one list works across hosts.
var defaultWatchRoots = []string{
	"/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv",
	"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
	"/var/spool/cron", "/etc/systemd/system", "/etc/profile.d", "/etc/udev/rules.d",
	"/etc/update-motd.d", "/etc/apt/apt.conf.d", "/etc/sudoers.d", "/etc/pam.d", "/root/.ssh",
}

// dropZones are where a change is a new file to read, not a change to what runs
// at boot. Anything else under a watch needs the persistence audit straight away.
var dropZones = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/var/www/", "/srv/"}

// Tamper classes, one per thing the agent re-reads or is redirected by while it
// runs. They are constants because the raise and the state tracking that keeps
// a persistent fault from going silent have to agree on the spelling.
const (
	tamperFeed           = "defend.tamper.feed"
	tamperSIEMRemoved    = "defend.tamper.siem-removed"
	tamperSIEMRedirected = "defend.tamper.siem-redirected"
	tamperIntegrity      = "defend.tamper.integrity-unverifiable"
	tamperConfig         = "defend.tamper.config-unusable"
	tamperForward        = "defend.tamper.siem-unusable"
	tamperCanary         = "defend.tamper.canary-unusable"
	// tamperContent is a prefix: each resource has its own class, because one
	// fingerprint per class would let a second fault hide behind the first.
	tamperContent = "defend.tamper.content-unusable."
)

// startFault is something the daemon needed from disk and could not use.
//
// Nothing on disk may stop this daemon; only a mistake on its own command line
// can. Refusing to start over a file is an off switch for whoever can plant one:
// the unit fails, systemd retries into the same fault, and the host has no EDR
// while the attacker has the machine to themselves. So each of these runs without
// what it lost and raises tamper, which is what keeps it from being the quiet
// fallback that refusing was meant to prevent: the daemon's state is reported at
// the top score, not inferred from a log line that looks healthy.
type startFault struct{ class, reason, detail string }

// Weakness classes: a guarantee the operator likely believes is in force but
// is not. Alerts for a human, never confirmation of an attack.
const (
	weakSigningKeyOnHost = "defend.weak.signing-key-on-host"
	weakSIEMOverridden   = "defend.weak.siem-pin-overridden"
	weakSIEMInsecureTLS  = "defend.weak.siem-tls-unverified"
)

const (
	defendMaxPending = 65536
	defendMaxFiles   = 65536
	defendMaxSeen    = 65536
	// defendMaxScans is libyara's limit on concurrent scans of one ruleset.
	defendMaxScans = 32
	// defendResponders bounds the incidents acted on at once in one burst.
	defendResponders = 64
	// defendAttempts is how many times a daemon task runs before it waits for its
	// next trigger, so a repeating panic can't spin.
	defendAttempts = 2
	// defendResponseRetries is how many more times a response that failed is tried,
	// and defendRetryBase the wait before the first of them, doubling each time. A
	// vault on a full disk may recover; one that never does must not loop for ever.
	defendResponseRetries = 3
	defendRetryBase       = 5 * time.Second
	// defendLineQueue is how many finished reports wait for a slow consumer before
	// the oldest is dropped, and defendFlushWait how long shutdown gives it to catch
	// up. Detection must never depend on someone reading its output.
	defendLineQueue = 4096
	defendFlushWait = 2 * time.Second
	// defendStopWait is how long a stop waits for scans in progress. A scan can't be
	// interrupted, and one large file can take a minute under load, so past this it
	// exits without them, and without closing the rules they are using.
	defendStopWait = 5 * time.Second
	// defendMemoryLimit is the heap the runtime tries to stay under, unless GOMEMLIMIT
	// says otherwise. It only changes when memory is collected: a large file would
	// otherwise leave the heap at twice its peak until much later, and past this
	// the collector works harder rather than the scan failing.
	defendMemoryLimit = 768 << 20
	// defendMaxExternal bounds how much telemetry from elsewhere is held for
	// correlation. Remote evidence is kept rather than consumed, because its
	// whole value is being there when this host's own layers find the other
	// half of the story minutes later.
	defendMaxExternal = 4096
	// defendRecheck spaces out rescans of a file that keeps changing while it is
	// being scanned. A file that lands and stays is scanned with no delay at all.
	defendRecheck = 100 * time.Millisecond
	// defendRacyWindow covers the kernel's timestamp granularity. A file that
	// changed this close to its scan could change again with the same timestamp,
	// so an equal stamp proves nothing yet and the next event rescans it.
	defendRacyWindow = 20 * time.Millisecond
	// defendMaxScanSize is the largest file the daemon reads. Hashing streams to the
	// end of a file, and a sparse file is any size at no cost to whoever made it: a
	// few of them would hold every scan slot for days, and all the layers behind
	// them. What is over this is reported rather than read.
	defendMaxScanSize = 1 << 30
	// defendSweepEvery re-reads the watched trees. It is what finds a file nothing
	// reported: no inotify at all, a directory past the watch limit, a lost event.
	defendSweepEvery = 5 * time.Minute
	// defendLargeVault is the size above which files enter the vault one at a time.
	// A quarantine holds a file in memory twice over, so a burst of large ones
	// would otherwise be a way to run the daemon out of memory.
	defendLargeVault = 64 << 20
	// classTooLarge is a file over defendMaxScanSize. It says nothing about the
	// contents, so it is never a reason to move the file.
	classTooLarge = "file.too-large"
	// runningPrefix marks the verdict on a running process's bytes, read through
	// /proc, as distinct from the verdict on the file at the same path.
	runningPrefix = "\x00running\x00"
)

func defendUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau defend [flags]

Runs every detection layer at once, each on its own schedule, and joins what they
see into incidents, so a process, its file and the entry that restarts it are one
finding. No layer waits for another, so a slow one delays only itself.

  process      the live process table (cau ps), reading the real bytes of a
               deleted or memfd executable through /proc
  network      the network plane (cau net): every socket the kernel holds,
               attributed to the process and the file behind it, plus the
               resolver configuration and the neighbour table. Beaconing and
               gateway-MAC churn need more than one sample, so they only exist
               here and in 'cau net --interval'
  file         all fifteen detectors over new files, flagged executables and
               whatever persistence entries point at
  persistence  what will run after a reboot or login (cau persist)
  kernel       the cau-kernel exec guard's event log (--kernel-events or
               auto-discovered from /var/log/cau-kernel/events.jsonl)
  canary       planted decoys (--canary-manifest or auto-discovered from
               /var/lib/cau/canary.json): nothing legitimate touches one
  package      installed packages' maintainer scripts (cau installed), hourly
  selftest     the engine's own detection content, verified against the signed
               baseline every --selftest-interval (ATT&CK T1562.001)
  feed         the abuse-intel feed, re-read from disk every --feed-reload, and
               verified against the baseline each time. A 'cau feed update' on
               the host lands without a restart because it re-records the
               baseline as it writes; one that did not would be refused here as
               tampering, and the last trusted feed kept
  external     telemetry from somewhere else (--ingest): another cau host's
               incidents, an OCSF event from a firewall or an IDS, or a plain
               JSON line from a script. It joins this host's evidence on the
               peer address — the one identifier two machines agree on — so the
               same command-and-control address seen from two places is one
               incident. Remote evidence corroborates and never directs: a
               response is only ever planned for this host's own artefacts

New files are scanned as they land, through inotify on the places attacks arrive
and persist. Flagged files are remembered, so a file dropped now joins the process
that runs it an hour later.

It defends by default: confirmed processes are frozen, confirmed files go to the
vault, and the kernel and firewall blocks arm themselves where the host can do
them. --report-only turns the whole response surface off and leaves it alerting
and forwarding, which is the mode to watch in for a while on a host you do not
know yet.

What makes that safe to leave on is not the default, it is what counts as
confirmed. Nothing here acts on one layer's opinion, and every default action is
reversible: 'stop' freezes a process with its memory intact for you to look at,
rather than killing it, and the vault restores. A CONFIRMED incident needs one
of:

  live state     a shell really on a socket or pipe relay, a set-uid shell, memfd
                 execution, a process with no file on disk holding a socket, a
                 kernel guard event, a canary rewritten or deleted
  two layers     independent layers agree on the same artefact
  known-bad      a hash or YARA hit, for a file

One layer's opinion alone is an alert for a human. In particular text in argv
never confirms anything: 'grep "/dev/tcp" notes.txt' reads like the attack. Only a
file the content scanner flagged is quarantined, never a cron table or PAM stack,
and never anything in a system path. PID 1, the responder and its ancestors are
never signalled. Only a peer the kernel reported a connection to is blocked,
never an address that merely appears in a file's text, and never one the host
itself needs.

Flags:
  --report-only         change nothing: alert and forward, never act
  --config <file>       agent configuration (default /etc/cau/cau.conf). The
                        only place a setting can be signed, so it is where the
                        SIEM address belongs. Precedence: built-in default, then
                        this file, then the command line.
  --siem <addr>         where to forward incidents: an IP, host, host:port or a
                        full URL. '10.0.0.5' means https://10.0.0.5:55000
  --once                run one cycle over the watch roots and exit
  --interval <d>        how often the process, persistence and canary layers
                        re-read the host, besides on a change (default 30s)
  --watch <dir>         watch this tree; repeatable (default: high-risk locations)
  --no-watch            do not watch files in real time
  --respond <action>    stop, kill or none for confirmed processes (default
                        stop: frozen, memory intact for forensics, reversible)
  --quarantine          move confirmed files into the vault (default on)
  --quarantine-store <dir>  vault directory
  --netblock            drop traffic to and from a confirmed incident's peers,
                        in cau's own nftables table or iptables chains (default
                        on; skipped with a clear line if there is no firewall)
  --block-ttl <d>       how long such a block lasts (default 1h; 0 means until
                        it is removed). Loopback, this host's own addresses, its
                        gateways and its resolvers are never blocked
  --sever               with --netblock: also destroy established connections to
                        a blocked peer (needs ss and kernel support)
  --netblock-dry-run    log the firewall commands and run none of them
  --ingest <path>       read telemetry from this file or directory; repeatable
  --ingest-max-age <d>  ignore ingested events older than this (default 24h;
                        0 keeps everything)
  --block-exe           ask the kernel to refuse confirmed files (default on;
                        skipped with a clear line if cau-kernel is absent)
  --kernel-bin <path>   the cau-kernel binary (default cau-kernel)
  --kernel-events <f>   cau-kernel guard event log
  --canary-manifest <f> canary manifest from 'cau canary plant'
  --package-interval <d> how often to audit packages (default 1h; 0 disables)
  --selftest-interval <d> how often to verify detection-content integrity
                        (default 15m; 0 disables)
  --selftest-manifest <f> baseline from 'cau selftest --record'
                        (default: integrity.json next to the signature DB)
  --selftest-pubkey <f> Ed25519 public key (hex) for the signed baseline
  --feed-reload <d>     how often to re-read the feed from disk
                        (default 10m; 0 disables)
  --rules <path>  --db <path>  --fuzzy-db <path>  --feed <path>   detection content
  --persist-root <dir>  filesystem the persistence layer audits (default /)
  --host-root <dir>  filesystem the host's own surfaces are read from — the
                     systemd generator directories, the bpffs root, the
                     package database (default /)
  --dpkg-info <dir>  --pacman-local <dir>   where the package layer reads the
                        installed-package databases from
  --format <fmt>        text or json lines (default text)
  --no-process  --no-persistence  --no-network  --no-selftest   disable a layer
  --proc-root <dir>  --etc-root <dir>   override /proc and /etc (testing)

Tamper resistance. The agent is left running, so what it does is decided by
files, which makes those files a target. Every one it reads is checked twice:
how it sits on disk (a symlink, a group- or world-writable file, or one owned by
somebody else is refused, because each is a way to change the contents after the
check), and against the signed baseline from 'cau selftest --record'. The
baseline covers the signature DB, the YARA rules, the fuzzy DB, the threat feed,
this configuration file and the agent binary, and it pins the SIEM address.

  feed      verified on every reload, not just on the selftest interval, since
            the reload is what an emptied feed would ride in on. A feed that
            fails is refused and the last good one stays live
  siem      pinned, so editing the config to point somewhere else neither
            silences the stream nor redirects it: the baselined address is used
            and the edit is raised as an incident
  others    any drift raises a CONFIRMED incident on its own (T1562.001)

A failed check never disables the agent. Refusing to run because one file
changed would hand an attacker a one-file off switch for the defence, so the
agent keeps the last trustworthy value and says so loudly instead.

SIEM forwarding (free, see docs/pricing.md). Each incident is posted as one OCSF
Detection Finding, in the same envelope as 'cau scan --format ocsf', so one rule
matches both. Delivery runs on its own goroutine: detection never waits on the
network, an unreachable manager costs a bounded queue whose oldest entry is
dropped to admit a newer one, and failures are retried with a backoff. The local
report stays the complete record either way.

  --wazuh-url <base>    Wazuh Manager API base (e.g. https://wazuh.host:55000)
  --wazuh-user <user>   API user
  --wazuh-password-env <var>  variable holding the password (default WAZUH_PASSWORD;
                        never passed on argv, which is world-readable in /proc)
  --wazuh-ca <file>     PEM CA bundle to trust for the manager's TLS certificate
  --wazuh-insecure      skip TLS verification (explicit opt-in)
  --wazuh-timeout <d>   per-request timeout (default 10s)
  --forward-queue <n>   incidents buffered while the SIEM is down (default 4096)

Exit codes (with --once): 0 nothing found, 1 incidents, 3 run failed, 4 usage.
`)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type fileStamp struct {
	size int64
	mod  time.Time
	node fileNode
}

// fileEntry is what the file layer last concluded about a path. Flagged entries
// are kept across cycles: that memory is what joins a file dropped now to the
// process that runs it later, which an attacker could otherwise beat by waiting.
type fileEntry struct {
	stamp  fileStamp
	signal correlate.Signal
	hit    bool
	// racy means the file changed too close to its scan for the stamp to rule
	// out a later change with the same timestamp.
	racy bool
}

// layerID names one layer's latest published view of the host.
type layerID int

const (
	viewProcess layerID = iota
	viewPersistence
	viewNetwork
	viewCanary
	viewPackage
	viewSelftest
	viewExternal
	viewBehavior
)

// defender is a set of goroutines that never wait for each other. Each layer owns
// its schedule and publishes what it sees; scan workers publish verdicts; the
// correlator joins whatever is known at that moment and hands what is new to
// goroutines of its own to act on. Evidence is shared only through the fields mu
// guards, so a slow layer delays its own news and nobody else's.
//
//	inotify ─► fileQueue ─► scan workers ──────┐
//	timers, changes ─► process ────────────────┤
//	                ─► persistence ────────────┼─► correlator ─► respond + emit
//	                ─► canary ─────────────────┤    (per incident, at once)
//	hourly ─────────► packages ────────────────┘
type defender struct {
	engine      *scanner.Engine
	procRoot    string
	persistRoot string
	// hostRoot is the filesystem the host's own surfaces are read from: the
	// systemd generator directory, the bpffs root and the package database.
	// It is the host's filesystem, not the tree the persistence layer audits.
	hostRoot string
	// provenance is the package-database index, built once and shared: the
	// behaviour layer runs on every cycle and the index is the expensive
	// part of it.
	provenance *provenance.Resolver
	// feed is swapped atomically so the refresh layer can publish a newer feed
	// without blocking readers; each reader takes a consistent snapshot.
	feed         atomic.Pointer[intel.Feed]
	feedPath     string
	feedInterval time.Duration

	process, persistence bool
	// network is the NDR layer: the socket tables, the resolver configuration
	// and the neighbour table. netHistory is what gives it the analytics that
	// need more than one sample (beaconing, gateway-MAC churn), which is a
	// daemon's advantage over a one-shot scan.
	network    bool
	etcRoot    string
	netHistory *netscan.History
	// blocker is the firewall. Network blocking is on by default, so this is
	// normally set; it is nil when --netblock=false or --report-only turned it
	// off, and also when the host has neither nftables nor iptables, which is
	// reported at startup rather than per incident. A nil blocker cannot drop a
	// packet, so every path that uses it checks first.
	blocker *netblock.Blocker
	// feeder reads telemetry from other hosts and sensors. Nil unless --ingest
	// named somewhere to read from.
	feeder       *ingest.Reader
	ingestPaths  []string
	ingestMaxAge time.Duration
	// clock is time.Now unless a test replaces it, which is what lets the
	// expiry of remote evidence be tested without waiting a day.
	clock               func() time.Time
	kernelEvents        string
	canaryManifest      string
	packageInterval     time.Duration
	dpkgInfo, pacmanDir string

	// selftest layer configuration. If selftestManifest is empty, the layer is
	// disabled: there is no baseline to compare against.
	selftestManifest string
	selftestInterval time.Duration
	selftestPubKey   selftestKey
	selftestKeyFile  string
	// selftestKeyErr is why a key that was asked for could not be used. It is
	// retried on every selftest cycle, so a repair needs no restart.
	selftestKeyErr error

	action     procscan.Action
	quarantine bool
	store      string
	blockExe   bool
	kernelBin  string

	roots []string
	json  bool
	out   io.Writer
	warn  func(string, ...interface{})

	// sink forwards every raised incident to a SIEM. It is nil when no
	// forwarder is configured, and when it is set it never blocks emit: a
	// manager that is down or slow costs queued events, not detection.
	sink    *forward.Sink
	product forward.Product

	// guard is the signed baseline of everything the agent reads, and answers
	// "has this been tampered with" without the caller needing to know whether
	// a baseline exists at all. cmdDefend sets it before any goroutine starts;
	// it stays nil for a defender built directly, as the tests do, and every
	// method on it is nil-safe and then means "nothing recorded".
	guard *trust.Guard

	queue   *fileQueue
	workers int
	slots   chan struct{} // bounds engine scans from every source together
	vault   chan struct{} // one large file entering the vault at a time
	// sweepEvery is how often the sweep runs with nothing asking for it.
	sweepEvery time.Duration
	scanning   stripes // one scan of a path at a time
	acting     stripes // one response to a file at a time
	sweepDue   atomic.Bool

	wakeProcess, wakePersistence, wakeCanary, wakeSweep, wakeCorrelate, wakeSelftest, wakeFeed wakeup
	wakeNetwork, wakeIngest                                                                    wakeup

	outMu sync.Mutex
	// lines carries finished reports to the writer while the daemon runs, so a
	// consumer that stops reading costs the reports it isn't reading and nothing
	// else. It is nil in a synchronous run, which writes directly.
	lines     chan []byte
	unwritten atomic.Int64
	flushWait time.Duration
	// stopWait is defendStopWait, and abandoned says a stop gave up waiting on a
	// scan, which then still holds the engine.
	stopWait  time.Duration
	abandoned atomic.Bool
	// retryBase is the wait before a failed response is tried again.
	retryBase time.Duration

	// Owned by one layer's goroutine, which never runs twice at once.
	lastPackage time.Time
	kernelSeen  map[string]bool // refusals already reported

	mu sync.Mutex
	// running is the executables each layer is currently reading through /proc,
	// by layer. keepRunning prunes a verdict only when no layer names it.
	running  map[layerID][]string
	external []externalEvidence
	files    map[string]fileEntry
	hits     map[string]correlate.Signal // the flagged entries of files
	views    map[layerID][]correlate.Signal
	events   []correlate.Signal // once-only evidence, consumed by the next join
	seen     map[string]bool
	seenOld  map[string]bool // the generation before seen, see markRaised
	retries  map[string]int  // failed responses tried again, by fingerprint
	// tamperMemo is the last reason raised per tamper class, so a resource that
	// stays bad is reported when its state changes rather than on every check.
	tamperMemo map[string]string
	// ps is the process table the process view came from. A view that old is fine
	// to act on: procscan.Respond re-reads identity before any signal.
	ps *procscan.Result
}

// ready sets up everything a defender needs to run, in either mode.
func (d *defender) ready() *defender {
	d.queue = newFileQueue(defendMaxPending, defendRecheck)
	d.workers = max(2, min(runtime.GOMAXPROCS(0), defendMaxScans)) // respects a CPU quota
	d.slots = make(chan struct{}, d.workers)
	if d.engine != nil {
		d.engine.IntelSource = d.feed.Load // the engine sees a reloaded feed too
	}
	d.vault = make(chan struct{}, 1)
	d.sweepEvery = defendSweepEvery
	d.kernelSeen = map[string]bool{}
	d.seenOld, d.retries = map[string]bool{}, map[string]int{}
	d.retryBase, d.flushWait, d.stopWait = defendRetryBase, defendFlushWait, defendStopWait
	d.wakeProcess, d.wakePersistence, d.wakeCanary, d.wakeSweep, d.wakeCorrelate =
		newWakeup(), newWakeup(), newWakeup(), newWakeup(), newWakeup()
	d.wakeSelftest, d.wakeFeed = newWakeup(), newWakeup()
	d.wakeNetwork, d.wakeIngest = newWakeup(), newWakeup()
	d.netHistory = netscan.NewHistory()
	d.files, d.hits, d.seen = map[string]fileEntry{}, map[string]correlate.Signal{}, map[string]bool{}
	d.views = map[layerID][]correlate.Signal{}
	d.tamperMemo = map[string]string{}
	d.running = map[layerID][]string{}
	return d
}

func (d *defender) enqueue(path string) {
	if strings.HasPrefix(path, d.store+string(filepath.Separator)) {
		return // the vault's own writes are not new files
	}
	if !d.queue.push(path) {
		d.requestSweep()
	}
	if !isDropZone(path) {
		d.wakeHostLayers()
	}
}

// wakeHostLayers re-reads what a change could have altered. Each goes at its own
// speed, so the first to finish is correlated without waiting for the rest.
func (d *defender) wakeHostLayers() {
	d.wakeProcess.fire()
	d.wakePersistence.fire()
	d.wakeNetwork.fire()
	d.wakeCanary.fire()
}

func (d *defender) requestSweep() {
	d.sweepDue.Store(true)
	d.wakeSweep.fire()
}

func isDropZone(path string) bool {
	for _, z := range dropZones {
		if strings.HasPrefix(path, z) {
			return true
		}
	}
	return false
}

// sweepRoots queues what is already there: a watch only sees what happens after
// it starts, and an overflow means events were lost.
func (d *defender) sweepRoots() {
	parallel.For(len(d.roots), len(d.roots), func(i int) {
		_ = filepath.WalkDir(safefs.WalkRoot(d.roots[i]), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.Type().IsRegular() && !strings.HasPrefix(p, d.store+string(filepath.Separator)) && !d.queue.pushBacklog(p) {
				return filepath.SkipAll
			}
			return nil
		})
	})
}

// scanFile runs the engine, once per file version. name is the path the evidence
// is about; read is where the bytes are, which differs for a process, whose
// /proc/<pid>/exe still reads a binary deleted from disk or living in a memfd.
//
// Those are two verdicts. The file at a path and the bytes a process is running
// from it can differ, and a path missing from disk says nothing about the second:
// sharing one entry let the persistence audit, which only has the path, erase what
// the process layer had just found.
func (d *defender) scanFile(name, read string) {
	key := name
	if read != name {
		key = runningPrefix + name
	}
	// Two scans of one path could finish in the wrong order, and the older
	// verdict would stand with no event left to correct it.
	lock := d.scanning.of(key)
	lock.Lock()
	defer lock.Unlock()

	fi, err := os.Stat(read)
	if err != nil || !fi.Mode().IsRegular() {
		if read == name {
			d.forget(name)
		}
		return
	}
	stamp := fileStamp{fi.Size(), fi.ModTime(), nodeOf(fi)}
	d.mu.Lock()
	e, ok := d.files[key]
	d.mu.Unlock()
	if ok && e.stamp == stamp && !e.racy {
		return
	}
	if fi.Size() > defendMaxScanSize {
		d.record(key, fileEntry{stamp: stamp, hit: true, signal: correlate.Signal{Layer: correlate.LayerFile, Class: classTooLarge, Score: 3, Files: []string{name},
			Detail: fmt.Sprintf("%d bytes is over the %d byte limit, so this file was not read", fi.Size(), int64(defendMaxScanSize))}})
		return
	}
	racy := time.Since(changedAt(fi)) < defendRacyWindow
	entry := d.verdict(name, read, stamp)
	entry.racy = racy
	if read != name && ok && e.hit && !entry.hit {
		// Two inodes can answer to one path: a flagged decoy started from a clean
		// file there must not wipe the verdict on the implant still running, or the
		// two would flip with every pass. keepRunning retires it when it's done.
		return
	}
	d.record(key, entry)
}

func (d *defender) verdict(name, read string, stamp fileStamp) fileEntry {
	d.slots <- struct{}{}
	defer func() { <-d.slots }()
	res, h := d.engine.ScanFile(read)
	sig, hit := fileSignal(name, res, h)
	if !hit {
		sig = correlate.Signal{} // nothing reads it, and tens of thousands are kept
	}
	return fileEntry{stamp: stamp, signal: sig, hit: hit}
}

// keepRunning drops verdicts on binaries no flagged process is running any more.
// The bytes behind a process exist only while it does, so unlike a flagged file
// there is nothing left for that memory to join.
//
// Two layers read processes through /proc now, and each sees its own set: the
// process table flags a masquerade the network layer has no opinion on, and a
// socket held by a memfd binary may belong to a process the process layer
// scored below its threshold. So a layer replaces only its own list, and a
// verdict is dropped when NO layer still names it — otherwise whichever layer
// ran last would erase the other's evidence on every pass.
func (d *defender) keepRunning(id layerID, names []string) {
	d.mu.Lock()
	d.running[id] = names
	live := map[string]bool{}
	for _, layer := range d.running {
		for _, n := range layer {
			live[n] = true
		}
	}
	dropped := false
	for key := range d.hits {
		if name, ok := strings.CutPrefix(key, runningPrefix); ok && !live[name] {
			delete(d.hits, key)
			delete(d.files, key)
			dropped = true
		}
	}
	d.mu.Unlock()
	if dropped {
		d.wakeCorrelate.fire()
	}
}

func (d *defender) forget(name string) {
	d.mu.Lock()
	_, hit := d.hits[name]
	delete(d.files, name)
	delete(d.hits, name)
	d.mu.Unlock()
	if hit {
		d.wakeCorrelate.fire()
	}
}

// record stores a verdict. A new hit is what makes the other layers worth asking
// now rather than at their next pass: the entry that restarts this file, or the
// process running it, may already be there, somewhere no watch would have said.
func (d *defender) record(name string, e fileEntry) {
	d.mu.Lock()
	_, was := d.hits[name]
	if len(d.files) >= defendMaxFiles {
		for k, old := range d.files {
			if !old.hit {
				delete(d.files, k)
			}
		}
	}
	if e.hit && !was && len(d.hits) >= defendMaxFiles {
		// Flagged files can be made faster than anyone reads them, and each one has
		// already been raised. What goes is one of those, never a running process's
		// verdict, whose bytes can't be scanned twice.
		for k := range d.hits {
			if !strings.HasPrefix(k, runningPrefix) {
				delete(d.hits, k)
				delete(d.files, k)
				break
			}
		}
	}
	d.files[name] = e
	if e.hit {
		d.hits[name] = e.signal
	} else {
		delete(d.hits, name)
	}
	d.mu.Unlock()
	if e.hit && !was {
		d.wakeHostLayers()
	}
	if e.hit || was {
		d.wakeCorrelate.fire()
	}
}

// scanAll scans what a layer's evidence names at once and returns when all of it
// is known, so that layer's view joins the verdicts on first publish rather than
// raising a half-joined incident and correcting it a moment later.
func (d *defender) scanAll(names, reads []string) {
	parallel.For(len(names), d.workers, func(i int) { d.scanFile(names[i], reads[i]) })
}

// publish replaces a layer's view of the host.
func (d *defender) publish(id layerID, signals []correlate.Signal) {
	d.mu.Lock()
	d.views[id] = signals
	d.mu.Unlock()
	d.wakeCorrelate.fire()
}

// fileSignal reduces fifteen detectors to the file layer's one opinion. The
// lattice has already weighed them against each other.
func fileSignal(path string, r scanner.ScanResult, h *scanner.HeuristicResult) (correlate.Signal, bool) {
	sig := correlate.Signal{Layer: correlate.LayerFile, Files: []string{path}}
	if v := r.Fusion; v != nil {
		sig.Technique = strings.Join(v.Techniques, ",")
		sig.Detail = v.Explanation
	}
	switch {
	case r.Verdict == scanner.VerdictMalicious:
		sig.Class, sig.Score, sig.Definitive = "file.malicious", 10, true
		sig.Detail = maliciousName(r)
		return panicNote(sig, r), true
	case r.Fusion != nil && (r.Fusion.Tier == fusion.TierSuspicious || r.Fusion.Tier == fusion.TierMalicious):
		sig.Class, sig.Score = "file.suspicious", 8
		return panicNote(sig, r), true
	}
	if len(r.Panics) > 0 {
		sig.Class, sig.Score = "file.detector-panic", 6
		return panicNote(sig, r), true
	}
	return sig, false
}

// panicNote says which detectors crashed on the file. On its own this is an
// alert and never a confirmation: a parser bug may be tripped by a harmless file,
// so a crash asks for a human, and it joins other evidence like any file signal.
func panicNote(sig correlate.Signal, r scanner.ScanResult) correlate.Signal {
	for _, p := range r.Panics {
		outcome := "completed on retry"
		if !p.Recovered {
			outcome = fmt.Sprintf("gave up after %d attempts, so this file went without it", p.Attempts)
		}
		note := "detector " + p.Detector + " panicked and " + outcome + ": " + p.Value
		if sig.Detail != "" {
			note = sig.Detail + "; " + note
		}
		sig.Detail = note
	}
	return sig
}

func trimDeleted(p string) string { return strings.TrimSuffix(p, " (deleted)") }

func (d *defender) processSignals(res *procscan.Result) []correlate.Signal {
	var names, reads []string
	for _, p := range res.Flagged {
		if exe := trimDeleted(p.Exe); correlate.Linkable(exe) {
			names = append(names, exe)
			reads = append(reads, filepath.Join(d.procRoot, fmt.Sprint(p.PID), "exe"))
		}
	}
	d.keepRunning(viewProcess, names) // before the scans, or another layer's pass could drop what they record
	d.scanAll(names, reads)

	var out []correlate.Signal
	for _, p := range res.Flagged {
		exe := trimDeleted(p.Exe)
		var files []string
		if correlate.Linkable(exe) {
			files = []string{exe}
		}
		for _, f := range p.Findings {
			if f.Score == 0 {
				continue
			}
			layer := correlate.LayerProcess
			if procscan.KernelClass(f.Class) {
				layer = correlate.LayerKernel
			}
			out = append(out, correlate.Signal{Layer: layer, Class: f.Class, Score: f.Score, Technique: f.Technique,
				Detail: f.Detail, Files: files, PID: p.PID, Live: procscan.LiveEvidence(f.Class)})
		}
	}
	return out
}

// kernelRefusals reports exec attempts the guard refused. They are not in the
// process layer when the program has since exited, and a refused attack is still
// an attack someone should hear about.
//
// What is new is decided by what a refusal says, not by a count of lines read: the
// log is read as a window of its tail, so past that size a count stops growing and
// nothing would ever be new again.
func (d *defender) kernelRefusals(events []procscan.KernelEvent) []correlate.Signal {
	var out []correlate.Signal
	for _, e := range events {
		if !e.Denied {
			continue
		}
		key := fmt.Sprint(e.TGID, "\x00", e.Reason, "\x00", e.Comm, "\x00", e.Exe, "\x00", e.Peer)
		if d.kernelSeen[key] {
			continue
		}
		if len(d.kernelSeen) >= defendMaxSeen {
			d.kernelSeen = map[string]bool{}
		}
		d.kernelSeen[key] = true
		out = append(out, correlate.Signal{Layer: correlate.LayerKernel, Class: "kernel.refused." + e.Reason, Score: 9,
			Technique: "T1059.004", Detail: "the guard refused " + e.Exe + " from " + e.Comm + " peer " + e.Peer, PID: d.refusedPID(e), Live: true})
	}
	return out
}

// refusedPID is the process a refusal is about, if it is still there. A PID alone
// is not identity: the log outlives processes and PIDs are reused, so without the
// name agreeing, last week's refusal would stop whatever holds that number today.
// A refusal with no PID is still reported and can still confirm. It just can't
// direct a signal at anything.
//
// An event that records the process start time settles the question outright:
// the refusal is only about the process that is there when those ticks agree.
// A refusal from before the guard recorded it is never pointed at a PID, since
// nothing about it says today's process is the one it refused.
func (d *defender) refusedPID(e procscan.KernelEvent) int {
	if e.Identity() {
		p, ok := procscan.Lookup(d.procRoot, e.TGID)
		if !ok || p.StartTicks != e.StartTicks {
			return 0
		}
		return e.TGID
	}
	raw, err := safefs.ReadFile(filepath.Join(d.procRoot, fmt.Sprint(e.TGID), "comm"), 256)
	if err != nil {
		return 0
	}
	comm := strings.TrimSpace(string(raw))
	// comm is cut at 15 bytes by the kernel, and a refused exec leaves the old name.
	if comm != "" && (comm == e.Comm || strings.HasPrefix(filepath.Base(e.Exe), comm)) {
		return e.TGID
	}
	return 0
}

func (d *defender) persistenceSignals() []correlate.Signal {
	flagged := persist.Scan(persist.Options{Root: d.persistRoot}).Flagged()
	refs := make([][]string, len(flagged))
	var named []string
	for i, f := range flagged {
		refs[i] = correlate.ReferencedPaths(f.Evidence)
		named = append(named, refs[i]...)
	}
	d.scanAll(named, named)

	out := make([]correlate.Signal, 0, len(flagged))
	for i, f := range flagged {
		out = append(out, correlate.Signal{Layer: correlate.LayerPersistence, Class: f.Class, Score: f.Score, Technique: f.Technique,
			Detail: f.Detail, Files: append([]string{f.Path}, refs[i]...)})
	}
	return out
}

// networkSignals reads the host's network plane. The files it names are the
// executables behind the sockets, which is what joins a connection to the file
// scanner's verdict on the same binary and to the persistence entry that starts
// it: a peer address on its own is a fact about the internet, while a peer plus
// a file plus an autostart entry is an incident.
func (d *defender) networkSignals() []correlate.Signal {
	res := netscan.Scan(netscan.Options{
		ProcRoot: d.procRoot, EtcRoot: d.etcRoot, Intel: d.feed.Load(), History: d.netHistory,
		Watch: d.watchlist(),
	})
	for _, w := range res.Warnings {
		d.warn("[WARN] network: %s", report.TermSafe(w))
	}

	// Scan the executables the network layer named, so a file verdict and a
	// socket meet in the correlator rather than in an operator's head.
	//
	// Read through /proc/<pid>/exe rather than the path, for the same reason the
	// process layer does: the strongest thing this layer finds is a process with
	// no file on disk holding a socket, and a path that is a memfd or an unlinked
	// inode cannot be opened. Those bytes exist only while the process does, so
	// this is the only chance to read them — and a path that IS on disk can hold
	// different bytes from the ones running, which is worth knowing too.
	var names, reads []string
	seen := map[string]bool{}
	for _, f := range res.Flagged {
		exe := netscan.TrimDeleted(f.Exe)
		if !correlate.Linkable(exe) || seen[exe] {
			continue
		}
		seen[exe] = true
		names = append(names, exe)
		if f.PID > 0 {
			reads = append(reads, filepath.Join(d.procRoot, fmt.Sprint(f.PID), "exe"))
		} else {
			reads = append(reads, exe)
		}
	}
	d.keepRunning(viewNetwork, names)
	d.scanAll(names, reads)

	out := make([]correlate.Signal, 0, len(res.Flagged))
	for _, f := range res.Flagged {
		var files []string
		if exe := netscan.TrimDeleted(f.Exe); correlate.Linkable(exe) {
			files = []string{exe}
		}
		var peers []string
		if f.Peer != "" {
			peers = []string{f.Peer}
		}
		out = append(out, correlate.Signal{
			Layer: correlate.LayerNetwork, Class: f.Class, Score: f.Score, Technique: f.Technique,
			Detail: f.Detail, Files: files, Peers: peers, PID: f.PID,
			Live: f.Live, Definitive: f.Definitive,
		})
	}
	return out
}

// watchlist is the peers another source has already identified, which the
// sensor reports a connection to whatever it would otherwise have scored.
//
// Only strong remote evidence gets in: an exact identification, live state, or a
// score high enough that the other source was not guessing either. A peer
// mentioned in passing by a chatty sensor would otherwise turn every ordinary
// connection into a finding, which is how cross-domain correlation becomes
// noise instead of a second opinion.
func (d *defender) watchlist() map[string]string {
	// Pruning here as well as on ingest is what makes the expiry real: a sensor
	// that stopped writing produces no ingest pass to prune on, and its last
	// identification would otherwise stay on the watchlist for ever.
	now := d.now()
	d.mu.Lock()
	d.external = pruneExternal(d.external, now, d.ingestMaxAge)
	external := make([]correlate.Signal, 0, len(d.external))
	for _, e := range d.external {
		external = append(external, e.sig)
	}
	d.mu.Unlock()
	if len(external) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, s := range external {
		if !s.Definitive && !s.Live && s.Score < 7 {
			continue
		}
		for _, p := range s.Peers {
			if !correlate.LinkablePeer(p) {
				continue
			}
			why := s.Host + " reported " + s.Class
			if s.Detail != "" {
				why = s.Host + ": " + s.Detail
			}
			out[p] = why
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// networkLayer publishes the network view and releases blocks that have expired.
// On nftables the kernel releases them itself; the iptables fallback needs
// somebody to come back, and this is the layer that does.
func (d *defender) networkLayer() {
	if !d.network {
		return
	}
	d.publish(viewNetwork, d.networkSignals())
	if d.blocker != nil {
		if n, err := d.blocker.Expire(); err != nil {
			d.warn("[WARN] releasing expired blocks: %s", report.TermSafe(err.Error()))
		} else if n > 0 {
			d.warn("[*] released %d expired network block(s)", n)
		}
	}
}

// externalEvidence is one remote signal and when this host took it in.
//
// The time is what makes the claim expire. An identification is a statement
// about an address at a moment: addresses are reassigned, and a sensor that
// stopped writing a month ago should not still be putting a peer on this host's
// watchlist, where it can confirm an incident and license a block. Holding
// evidence for as long as the daemon happens to have been up is not a policy.
type externalEvidence struct {
	sig correlate.Signal
	at  time.Time
}

// pruneExternal drops remote evidence that has aged past maxAge, then bounds
// what is left. A maxAge of 0 keeps everything, which is what --ingest-max-age 0
// asks for; the size cap applies either way, so a flooding sensor still costs
// memory it cannot exceed.
func pruneExternal(held []externalEvidence, now time.Time, maxAge time.Duration) []externalEvidence {
	if maxAge > 0 {
		kept := held[:0]
		for _, e := range held {
			if now.Sub(e.at) <= maxAge {
				kept = append(kept, e)
			}
		}
		held = kept
	}
	if len(held) > defendMaxExternal {
		held = held[len(held)-defendMaxExternal:]
	}
	return held
}

// now is the clock, which a test replaces.
func (d *defender) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

// ingestLayer reads telemetry from other hosts and sensors.
//
// Remote evidence is accumulated rather than replaced, because it is about
// another machine's view of a peer and this host may not meet that peer for
// another hour. The list is bounded and the oldest is dropped, the same bargain
// the forwarder's queue makes: a sensor flooding events costs memory it cannot
// exceed, never detection.
func (d *defender) ingestLayer() {
	if d.feeder == nil {
		return
	}
	signals, warnings := d.feeder.Collect(d.ingestPaths)
	for _, w := range warnings {
		d.warn("[WARN] %s", report.TermSafe(w))
	}
	if len(signals) == 0 {
		return
	}
	now := d.now()
	d.mu.Lock()
	for _, sig := range signals {
		d.external = append(d.external, externalEvidence{sig: sig, at: now})
	}
	d.external = pruneExternal(d.external, now, d.ingestMaxAge)
	view := make([]correlate.Signal, 0, len(d.external))
	for _, e := range d.external {
		view = append(view, e.sig)
	}
	d.mu.Unlock()
	d.publish(viewExternal, view)
	// A peer another source has identified changes what the network layer is
	// looking for, so it re-reads rather than waiting for its next tick.
	d.wakeNetwork.fire()
}

func (d *defender) canarySignals() []correlate.Signal {
	if d.canaryManifest == "" {
		return nil
	}
	m, err := canary.ReadManifest(d.canaryManifest)
	if err != nil {
		// Without the manifest no canary can trip, and a line on stderr is not
		// what anyone is watching for that.
		d.warn("[WARN] canary manifest: %s", report.TermSafe(err.Error()))
		d.tamper(tamperCanary, err.Error(),
			"the canary manifest cannot be read, so no canary on this host can raise an alert: "+err.Error())
		return nil
	}
	// A manifest that parses is not evidence that anything can still trip. The
	// file lives on the same disk, owned by the same UID, as the decoys it
	// describes, so one that validates while recording nothing planted is the
	// cheap way to silence every canary here: clearing the alert on it would
	// turn the tamper state off exactly when the baseline was gutted.
	if len(m.Canaries) == 0 {
		reason := "canary manifest records no planted decoy"
		d.warn("[WARN] %s: %s", reason, d.canaryManifest)
		d.tamper(tamperCanary, reason,
			"the canary manifest at "+d.canaryManifest+" records no canary, so no canary on this host can raise an alert: the baseline was emptied rather than read")
		return nil
	}
	d.clearTamper(tamperCanary)
	var out []correlate.Signal
	for _, r := range canary.Tripped(canary.Check(m)) {
		rewritten := r.Status == canary.StatusModified || r.Status == canary.StatusDeleted
		score := 4
		if rewritten {
			score = 9
		}
		out = append(out, correlate.Signal{Layer: correlate.LayerCanary, Class: "canary." + string(r.Status), Score: score,
			Technique: "T1486", Detail: r.Detail, Files: []string{r.Canary.Path}, Live: rewritten})
	}
	return out
}

func (d *defender) packageSignals() []correlate.Signal {
	dpkg, pacman := &installedResult{Threshold: 8}, &installedResult{Threshold: 8}
	feed := d.feed.Load()
	parallel.Do(
		func() { auditDpkg(d.dpkgInfo, dpkg.Threshold, feed, dpkg) },
		func() { auditPacman(d.pacmanDir, pacman.Threshold, feed, pacman) },
	)
	var out []correlate.Signal
	for _, p := range slices.Concat(dpkg.Flagged, pacman.Flagged) {
		for _, f := range p.Findings {
			out = append(out, correlate.Signal{Layer: correlate.LayerPackage, Class: f.Class, Score: f.Score, Technique: f.Technique,
				Detail: "package " + p.Name + ": " + f.Detail})
		}
	}
	return out
}

// processLayer reads the process table and the kernel guard's log. Refusals are
// events rather than state, so they go in once and survive however many passes
// land before the next join.
func (d *defender) processLayer() {
	if !d.process {
		return
	}
	var events []procscan.KernelEvent
	if d.kernelEvents != "" {
		var err error
		if events, err = procscan.LoadKernelEvents(d.kernelEvents); err != nil {
			d.warn("[WARN] %s", report.TermSafe(err.Error()))
		}
	}
	ps := procscan.Scan(procscan.Options{ProcRoot: d.procRoot, Intel: d.feed.Load(), KernelEvents: events})
	// A scan that stopped at a read cap saw part of a process and none of what
	// was past the cap. The daemon says so every pass, because a quiet run that
	// read half a command line is not a run that found nothing.
	for _, w := range ps.Warnings {
		if strings.HasPrefix(w, "partial scan:") {
			d.warn("[WARN] %s", report.TermSafe(w))
		}
	}
	signals := d.processSignals(ps)
	refused := d.kernelRefusals(events)

	d.mu.Lock()
	d.views[viewProcess], d.ps = signals, ps
	d.events = append(d.events, refused...)
	d.mu.Unlock()
	d.wakeCorrelate.fire()
}

func (d *defender) persistenceLayer() {
	if d.persistence {
		d.publish(viewPersistence, d.persistenceSignals())
	}
}

func (d *defender) canaryLayer() { d.publish(viewCanary, d.canarySignals()) }

// behaviorLayer reads the host's own behaviour: the inventories that say
// something on this host is arranging for the next file to be missed — an
// auditor library in every process, a fanotify listener that ignores events, a
// systemd generator that adds a unit at every boot, a BPF program nobody's
// package owns.
//
// The inventories are state, not proof, so their scores sit below the
// response threshold: they corroborate, and they are published so an operator
// can see what the host is doing.
func (d *defender) behaviorLayer() { d.publish(viewBehavior, d.behaviorSignals()) }

// behaviorSignals reads the behaviour inventories and turns them into signals.
//
// The inventories are about *this host* — an auditor library in a running
// process, a fanotify listener, a systemd generator, a pinned BPF object — so
// they read the host's own filesystem, not the tree the persistence layer is
// auditing. With --persist-root pointing somewhere else, the generator
// directory and the bpffs root would be looked for on that filesystem, where
// they are absent, and the host would look like it had neither.
//
// The resolver is the defender's own and is built once: the package database is
// read and indexed once, not on every cycle. A new resolver per cycle would
// re-read every package's file list on every pass.
func (d *defender) behaviorSignals() []correlate.Signal {
	res := behavior.Check(behavior.Options{ProcRoot: d.procRoot, Root: d.hostRoot, Resolver: d.provenance})
	out := make([]correlate.Signal, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, correlate.Signal{
			Layer:  correlate.LayerBehavior,
			Class:  f.Class,
			Score:  f.Score,
			Detail: f.Detail,
			Files:  correlate.ReferencedPaths(f.Evidence),
		})
	}
	return out
}

func (d *defender) packageLayer() {
	d.lastPackage = time.Now()
	d.publish(viewPackage, d.packageSignals())
}

// selftestLayer checks that the detection content on disk still matches the
// recorded baseline. An attacker who gutted the signature DB or neutered a YARA
// rule while the daemon is running is the T1562.001 move this catches, so the
// alert it emits is high-confidence even though nothing else corroborates it:
// the defender is attesting to its own integrity. A missing manifest disables
// the layer rather than crashing the daemon.
func (d *defender) selftestLayer() {
	d.recheckTrust()
	if d.selftestManifest == "" {
		return
	}
	baseline, err := selftest.ReadManifest(d.selftestManifest)
	if err != nil {
		d.publish(viewSelftest, []correlate.Signal{{
			Layer: correlate.LayerSelf, Class: "defend.selftest.manifest-unreadable", Score: 7,
			Technique: "T1562.001",
			Detail:    "selftest baseline " + d.selftestManifest + " could not be read: " + report.TermSafe(err.Error()),
			Live:      true,
		}})
		return
	}
	var out []correlate.Signal
	// A schema-2 baseline is still verified, but its signature does not cover
	// the resource paths: an editor without the key could redirect an entry to a
	// clean copy while the digest and the signature still match. Say so, because
	// the guarantee the operator believes they have is the smaller one.
	if baseline.Schema < selftest.ManifestSchema {
		d.warn("[WARN] selftest baseline %s is schema %d: resource paths are not signed (re-record with this build to cover them)", d.selftestManifest, baseline.Schema)
	}
	if d.selftestPubKey.set {
		if err := baseline.VerifySignature(d.selftestPubKey.key); err != nil {
			out = append(out, correlate.Signal{
				Layer: correlate.LayerSelf, Class: "defend.selftest.bad-signature", Score: 10,
				Technique: "T1562.001",
				Detail:    "selftest manifest signature did not verify against the pinned key: " + report.TermSafe(err.Error()),
				Live:      true,
			})
			d.publish(viewSelftest, out)
			return
		}
	}
	drift, err := selftest.Verify(baseline)
	if err != nil {
		d.publish(viewSelftest, []correlate.Signal{{
			Layer: correlate.LayerSelf, Class: "defend.selftest.verify-failed", Score: 7,
			Technique: "T1562.001",
			Detail:    "selftest verification failed: " + report.TermSafe(err.Error()),
			Live:      true,
		}})
		return
	}
	for _, dr := range drift {
		out = append(out, correlate.Signal{
			Layer: correlate.LayerSelf, Class: "defend.selftest.drift." + dr.Name, Score: 10,
			Technique: "T1562.001",
			Detail:    "a resource the agent trusts was changed: " + dr.Name + ": " + dr.Reason,
			Live:      true,
		})
	}
	d.publish(viewSelftest, out)
}

// recheckTrust retries a broken chain of trust. The daemon keeps running through
// one, so this is how it comes back: repairing the key or the baseline takes
// effect on the next cycle, without a restart that would be a window with no EDR.
func (d *defender) recheckTrust() {
	if d.selftestKeyErr == nil && d.guard.Fault() == nil {
		return
	}
	// The key is read again even if the last read worked: a valid key that did
	// not sign this baseline is a fault too, and the repair for it is a new key.
	key, err := defendPubkey(d.selftestKeyFile)
	d.selftestKeyErr = err
	if err != nil {
		d.distrust(err)
		return
	}
	d.selftestPubKey = key
	if err := d.guard.Recover(key.key); err != nil {
		d.distrust(err)
		return
	}
	d.clearTamper(tamperIntegrity)
	d.warn("[*] the integrity baseline can be checked again: %s", integrityState(d.guard))
	d.wakeFeed.fire()
}

// distrust raises the integrity fault. A new reason is news, so a repair that
// only moved the problem is said again.
func (d *defender) distrust(fault error) {
	d.tamper(tamperIntegrity, fault.Error(),
		"the integrity baseline cannot be checked, so nothing the agent reads is verified against it: "+fault.Error())
}

// feedLayer re-reads the abuse-intel feed from disk and publishes the new
// pointer, so a `cau feed update` on the host is picked up without restarting
// the daemon. A feed with no path, or one that could not be read, is a quiet
// no-op: the feed is always optional and readers already tolerate nil.
// feedLayer re-reads the threat feed from disk, so a `cau feed update` lands
// without a restart.
//
// That hot reload is also the cheapest way to blind this agent: the feed is a
// plain text file, and replacing it with an empty one would silence every
// intel-based verdict within the reload interval, without touching a rule or
// restarting anything. So nothing on disk is believed until it is checked, both
// for how it sits there and against the signed baseline.
//
// A feed that fails either check is refused and the last good one stays in
// place. It is deliberately not treated as a reason to stop: an attacker who
// can corrupt one file should not be able to turn the intel layer off, only to
// freeze it at its last trustworthy state, loudly.
func (d *defender) feedLayer() {
	if d.feedPath == "" {
		return
	}
	// With no baseline to believe, a feed already in use stays frozen. With none
	// loaded this is startup, and freezing would mean no intel at all: an
	// unverified feed still detects where an absent one does not, and the
	// integrity alert already says it is unverified.
	if d.guard.Fault() != nil && d.feed.Load() != nil {
		return
	}
	// Re-read the baseline first, so an operator who updated the feed and then
	// re-recorded is believed without a restart.
	if err := d.guard.Refresh(); err != nil {
		d.tamper(tamperFeed, "baseline-unreadable",
			"the integrity baseline could not be re-read, so the feed was not reloaded: "+err.Error())
		return
	}
	reason, err := d.guard.VerifyFile(selftestResFeed, d.feedPath)
	if err != nil {
		// Being unable to compute the digest is not a clean bill of health. The
		// feed stays as it was and this is said once, as evidence, rather than
		// only on stderr where nothing correlates it.
		d.tamper(tamperFeed, "unverifiable:"+err.Error(),
			"the threat-intel feed "+d.feedPath+" could not be verified, so it was not loaded: "+err.Error())
		return
	}
	if reason != "" {
		d.tamper(tamperFeed, reason,
			"threat-intel feed "+d.feedPath+" is not the one that was baselined, so it was not loaded: "+reason)
		return
	}
	f, ok, err := intel.Load(d.feedPath)
	if err != nil {
		d.warn("[WARN] feed reload %s: %s", d.feedPath, report.TermSafe(err.Error()))
		return
	}
	if !ok {
		return
	}
	// An empty feed replacing a populated one is how the intel layer goes quiet,
	// and on a host with no baseline the digest check is not there to catch it.
	// `cau scan` has always refused a zero-indicator feed for the same reason;
	// the daemon now agrees with it rather than silently taking the emptier one.
	if f.Count() == 0 {
		if prev := d.feed.Load(); prev != nil && prev.Count() > 0 {
			d.tamper(tamperFeed, "emptied",
				"threat-intel feed "+d.feedPath+" now holds no indicators, so the previous one is still in use")
			return
		}
		return
	}
	d.clearTamper(tamperFeed)
	d.feed.Store(f)
}

// tamper raises evidence that something the agent depends on was changed under
// it. It is live, scores at the top, and names T1562.001: unlike a score from a
// detector, a resource that no longer matches its signed baseline is a fact
// about this host, so it confirms on its own and does not wait for a second
// layer to agree.
// It raises on a change of state, not on every check. The feed is verified on
// every reload, so a resource that stays bad would otherwise do one of two
// useless things: alert every few minutes, or — because a self-layer incident's
// fingerprint is derived from its artefacts and this signal has none, making it
// identical every time — go silent after the very first one for the rest of the
// daemon's life. So a new reason is news, the same reason repeated is not, and
// clearTamper forgets a resource that verifies clean again so that a later
// tamper is news once more.
func (d *defender) tamper(class, reason, detail string) {
	sig := correlate.Signal{
		Layer: correlate.LayerSelf, Class: class, Score: 10,
		Technique: "T1562.001", Detail: report.TermSafe(detail), Live: true,
	}
	d.mu.Lock()
	if d.tamperMemo[class] == reason {
		d.mu.Unlock()
		return
	}
	d.tamperMemo[class] = reason
	// This incident's fingerprint is the same for every raise of this class, so
	// the join's once-only memory has to be cleared or the new reason never
	// reaches anybody.
	d.unraise(tamperFingerprint(sig))
	d.events = append(d.events, sig)
	d.mu.Unlock()
	d.wakeCorrelate.fire()
}

// weakness reports that a guarantee the operator probably believes they have is
// not actually in force — a signing key left on the host, TLS verification
// turned off, a pinned address overridden from the environment.
//
// It is deliberately not tamper(): none of these is evidence of an attack, and
// scoring them as live state would confirm an incident and arm a response
// against a misconfiguration. They are alerts for a human at a score that
// corroborates but never confirms on its own, which is the same treatment any
// single non-live observation gets. The point is that these stop being silent:
// a hollow guarantee that nobody is told about is worse than no guarantee,
// because it is budgeted for.
func (d *defender) weakness(class, reason, detail string) {
	sig := correlate.Signal{
		Layer: correlate.LayerSelf, Class: class, Score: 5,
		Technique: "T1562.001", Detail: report.TermSafe(detail),
	}
	d.mu.Lock()
	if d.tamperMemo[class] == reason {
		d.mu.Unlock()
		return
	}
	d.tamperMemo[class] = reason
	d.unraise(tamperFingerprint(sig))
	d.events = append(d.events, sig)
	d.mu.Unlock()
	d.wakeCorrelate.fire()
}

// clearTamper forgets a resource whose checks now pass, so that if it is
// tampered with again the alert is raised again rather than suppressed as
// something already reported hours ago.
func (d *defender) clearTamper(class string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, had := d.tamperMemo[class]; !had {
		return
	}
	delete(d.tamperMemo, class)
	d.unraise(tamperFingerprint(correlate.Signal{
		Layer: correlate.LayerSelf, Class: class, Score: 10,
		Technique: "T1562.001", Live: true,
	}))
}

// tamperFingerprint is the join's identity for a tamper signal. Detail is not
// part of it, which is exactly why the state tracking above is needed.
func tamperFingerprint(sig correlate.Signal) string {
	incs := correlate.Build([]correlate.Signal{sig})
	if len(incs) == 0 {
		return ""
	}
	return incs[0].Fingerprint()
}

// once queues evidence that describes a moment rather than a state, so the next
// join sees it and no later one repeats it. A layer's view is replaced wholesale
// each pass, which is right for "what is true now" and wrong for "this happened".
func (d *defender) once(sig correlate.Signal) {
	d.mu.Lock()
	d.events = append(d.events, sig)
	d.mu.Unlock()
	d.wakeCorrelate.fire()
}

// alertCrash puts a crashed task on the incident stream, where an operator is
// watching, rather than only in the service log. It goes straight out instead of
// through the correlator, which may be the part that crashed. Once per task is
// enough to be told; the log has every occurrence.
func (d *defender) alertCrash(task string) {
	sig := correlate.Signal{Layer: correlate.LayerSelf, Class: "defend.crash." + task, Score: 5,
		Detail: "the " + task + " task panicked, so something may have gone unseen while it was down; the stack is in the service log"}
	inc := correlate.Build([]correlate.Signal{sig})[0]
	fp := inc.Fingerprint()
	d.mu.Lock()
	already := d.raised(fp)
	d.markRaised(fp)
	d.mu.Unlock()
	if !already {
		d.emit(inc, nil)
	}
}

// raised reports whether an incident has been raised. The caller holds mu.
func (d *defender) raised(fp string) bool {
	if d.seen[fp] {
		return true
	}
	if d.seenOld[fp] {
		d.markRaised(fp) // still live, so it must outlast the next rotation
		return true
	}
	return false
}

// markRaised remembers an incident. The caller holds mu. The memory is bounded in
// two generations rather than wiped when full: a wipe forgets every live incident at
// once, and the next join raises all of them again.
func (d *defender) markRaised(fp string) {
	if len(d.seen) >= defendMaxSeen {
		d.seenOld, d.seen = d.seen, map[string]bool{}
	}
	d.seen[fp] = true
}

// unraise forgets an incident, so the same evidence raises it again. The caller
// holds mu.
func (d *defender) unraise(fp string) {
	delete(d.seen, fp)
	delete(d.seenOld, fp)
}

// retryLater raises an incident again after a wait, because its response failed:
// the file is still there or the peer still reachable, so saying so once is not
// the end of it. Going back through the join means the retry acts on the evidence
// as it stands then, and through PlanFor like everything else. It is bounded per
// incident, and each attempt reports its own outcome.
func (d *defender) retryLater(inc correlate.Incident) {
	fp := inc.Fingerprint()
	d.mu.Lock()
	n := d.retries[fp]
	if n >= defendResponseRetries {
		d.mu.Unlock()
		return
	}
	if len(d.retries) >= defendMaxSeen {
		d.retries = map[string]int{}
	}
	d.retries[fp] = n + 1
	d.mu.Unlock()
	time.AfterFunc(d.retryBase<<n, func() {
		d.mu.Lock()
		d.unraise(fp)
		d.mu.Unlock()
		d.wakeCorrelate.fire()
	})
}

func (d *defender) packageDue() bool {
	return d.packageInterval > 0 && time.Since(d.lastPackage) >= d.packageInterval
}

// scanWorker scans queued paths until the queue ends. liveOnly reserves it for
// paths that just changed.
func (d *defender) scanWorker(liveOnly bool) {
	for {
		p, ok := d.queue.pop(liveOnly)
		if !ok {
			return
		}
		func() {
			defer d.queue.done(p)
			d.scanFile(p, p)
		}()
	}
}

// drainFiles sweeps if one is due and scans everything queued, and returns when
// the queue is empty.
func (d *defender) drainFiles() {
	defer d.queue.reopen()
	parallel.Do(
		func() { parallel.For(d.workers, d.workers, func(int) { d.scanWorker(false) }) },
		func() {
			defer d.queue.finish()
			if d.sweepDue.Swap(false) {
				d.sweepRoots()
			}
		},
	)
}

// cycle runs every layer and every queued file at once, waits for all of it, and
// acts on what is new. It is the whole of --once; the daemon runs the same parts
// without the waiting.
func (d *defender) cycle() []correlate.Incident {
	// Telemetry from elsewhere is read first, and only here: it is a few file
	// reads, and it is what puts a peer on the sensor's watchlist, so a single
	// --once run can still join another source's identification to this host's
	// own quiet connection. In the daemon nothing waits — the ingest layer fires
	// the network layer when it learns something new.
	d.ingestLayer()
	parallel.Do(d.processLayer, d.persistenceLayer, d.networkLayer, d.canaryLayer, d.selftestLayer, d.behaviorLayer, d.drainFiles, func() {
		if d.packageDue() {
			d.packageLayer()
		}
	})
	fresh, ps := d.join()
	d.act(fresh, ps, true)
	return fresh
}

// join correlates everything known now and returns what has not been raised. It
// is one call at a time only because a join has to see one view of the evidence.
// It does no I/O, so everything feeding it and everything it feeds keeps running.
func (d *defender) join() ([]correlate.Incident, *procscan.Result) {
	d.mu.Lock()
	signals := append([]correlate.Signal(nil), d.events...)
	taken := len(d.events)
	for _, view := range d.views {
		signals = append(signals, view...)
	}
	// A file and the process running it usually agree, and that is one opinion.
	opinions := make(map[string]bool, len(d.hits))
	for _, sig := range d.hits {
		if o := sig.Files[0] + "\x00" + sig.Class; !opinions[o] {
			opinions[o] = true
			signals = append(signals, sig)
		}
	}
	ps := d.ps
	d.mu.Unlock()

	incidents := correlate.Build(signals)

	d.mu.Lock()
	defer d.mu.Unlock()
	// Only now: a panic above leaves them in place for the retry.
	d.events = d.events[taken:]
	var fresh []correlate.Incident
	for _, inc := range incidents {
		fp := inc.Fingerprint()
		if d.raised(fp) {
			continue
		}
		d.markRaised(fp)
		fresh = append(fresh, inc)
	}
	return fresh, ps
}

// act responds to every incident at once and reports each as soon as its own
// response is done, so a large quarantine holds up nothing but its own alert.
// inOrder keeps a synchronous run's output in strongest-first order, for a human
// reading it or a script comparing it.
//
// The reports are deferred because join has already marked these incidents raised:
// a response that panics must not take the only record of them with it.
func (d *defender) act(fresh []correlate.Incident, ps *procscan.Result, inOrder bool) {
	actions := make([][]string, len(fresh))
	if inOrder {
		defer func() {
			for i := range fresh {
				d.emit(fresh[i], actions[i])
			}
		}()
	}
	parallel.For(len(fresh), defendResponders, func(i int) {
		if !inOrder {
			defer func() { d.emit(fresh[i], actions[i]) }()
		}
		actions[i] = d.respond(fresh[i], ps)
	})
}

// respond carries out what the incident permits, every action at once. The policy
// is in correlate.PlanFor; the guards that protect the host stay in procscan.Respond.
func (d *defender) respond(inc correlate.Incident, ps *procscan.Result) []string {
	plan := correlate.PlanFor(inc)
	var steps []func() []string
	var failed atomic.Bool
	if d.action != "" && len(plan.Stop) > 0 && ps != nil {
		// MinScore 1: correlate has already confirmed this incident.
		ro := procscan.RespondOptions{Action: d.action, MinScore: 1, ProcRoot: d.procRoot}
		if d.blockExe {
			ro.BlockExe = func(exe string) error { return kernelBlock(d.kernelBin, exe) }
		}
		for _, p := range ps.Flagged {
			if !slices.Contains(plan.Stop, p.PID) {
				continue
			}
			steps = append(steps, func() []string {
				var done []string
				for _, r := range procscan.Respond(&procscan.Result{Flagged: []procscan.Process{p}}, ro) {
					done = append(done, r.String())
				}
				return done
			})
		}
	}
	if d.action != "" {
		// A process the process scan never flagged can still be the one worth
		// stopping: the network sensor finds a memfd binary holding a
		// command-and-control connection that scores below procscan's own
		// threshold, and before this that stop was planned, reported and never
		// carried out. Its identity is read from /proc now, which is what
		// Respond needs, and every guard still applies — the start time it reads
		// is what refuses a recycled PID, and PID 1, the responder and its
		// ancestors are still protected.
		//
		// MinScore 1 with a Score of 1 states the grounds plainly: correlate
		// confirmed this incident, so procscan is being asked to act on another
		// layer's conclusion rather than to re-derive one it never had.
		for _, pid := range plan.Stop {
			if ps != nil && slices.ContainsFunc(ps.Flagged, func(p procscan.Process) bool { return p.PID == pid }) {
				continue
			}
			ro := procscan.RespondOptions{Action: d.action, MinScore: 1, ProcRoot: d.procRoot}
			if d.blockExe {
				ro.BlockExe = func(exe string) error { return kernelBlock(d.kernelBin, exe) }
			}
			steps = append(steps, func() []string {
				p, ok := procscan.Lookup(d.procRoot, pid)
				if !ok {
					return []string{fmt.Sprintf("not stopped: pid %d is gone, so there is nothing left to signal", pid)}
				}
				p.Score = 1
				var done []string
				for _, r := range procscan.Respond(&procscan.Result{Flagged: []procscan.Process{p}}, ro) {
					done = append(done, r.String())
				}
				return done
			})
		}
	}
	for _, peer := range plan.Block {
		if d.blocker == nil {
			break
		}
		steps = append(steps, func() []string {
			what, err := d.blocker.Block(peer, "incident "+inc.ID+": "+inc.Why)
			if err != nil {
				failed.Store(true)
				return []string{"not blocked: " + err.Error()}
			}
			return []string{what}
		})
	}
	for _, f := range plan.Quarantine {
		switch {
		case d.quarantine:
			steps = append(steps, func() []string {
				outcome := d.quarantineFile(f, inc)
				if strings.HasPrefix(outcome, "quarantine failed") {
					failed.Store(true)
				}
				return []string{outcome}
			})
		case d.blockExe:
			steps = append(steps, func() []string {
				if err := kernelBlock(d.kernelBin, f); err != nil {
					failed.Store(true)
					return []string{"kernel block failed: " + err.Error()}
				}
				return []string{"kernel refuses " + f}
			})
		}
	}
	// Each step's outcome is kept separately: a process that was killed has to be
	// reported as killed even if the quarantine beside it panicked.
	done := make([][]string, len(steps))
	var crashed atomic.Bool
	parallel.For(len(steps), len(steps), func(i int) {
		defer func() {
			if r := recover(); r != nil {
				crashed.Store(true)
				done[i] = []string{fmt.Sprintf("response step crashed: %v", r)}
			}
		}()
		done[i] = steps[i]()
	})
	if crashed.Load() {
		d.alertCrash("response")
	}
	if failed.Load() {
		d.retryLater(inc)
	}
	return slices.Concat(done...)
}

func (d *defender) quarantineFile(path string, inc correlate.Incident) string {
	// Two incidents can name one file: new evidence raises it again while the
	// first response is still moving it.
	lock := d.acting.of(path)
	lock.Lock()
	defer lock.Unlock()
	fi, err := os.Lstat(path)
	if err != nil {
		return "nothing to quarantine at " + path // a deleted or memfd binary
	}
	// The evidence may be about the bytes a process is running, and the file at this
	// path now may be something else: moved there, restored, or named to be mistaken
	// for it. Only the file's own verdict can send it to the vault.
	d.scanFile(path, path)
	d.mu.Lock()
	sig, flagged := d.hits[path]
	d.mu.Unlock()
	if !flagged || sig.Class == classTooLarge {
		return "left " + path + " in place: the evidence was not about the file there now"
	}
	if fi.Size() > defendLargeVault {
		d.vault <- struct{}{}
		defer func() { <-d.vault }()
	}
	s, err := quarantine.Open(d.store)
	if err != nil {
		return "quarantine failed: " + err.Error()
	}
	if _, err := s.Quarantine(path, "incident "+inc.ID+": "+inc.Why, false); err != nil {
		return "quarantine failed: " + err.Error()
	}
	d.forget(path)
	// This incident is over. Its fingerprint is about the path, so left in place it
	// would silence the same file written there again, which is a new attack.
	d.mu.Lock()
	d.unraise(inc.Fingerprint())
	d.mu.Unlock()
	// A scan in flight would put the verdict back. Queued behind it, this one
	// finds nothing there and clears it.
	d.enqueue(path)
	return "quarantined " + path
}

// emit writes one incident in one call, so concurrent ones never interleave.
// emit writes the incident to the local report and hands it to the forwarder.
// The local write comes first and is what the daemon's own record depends on;
// the forward is an offer to a bounded queue that cannot fail or block, so a
// SIEM can be unreachable for a week without the host noticing.
func (d *defender) emit(inc correlate.Incident, actions []string) {
	var w bytes.Buffer
	d.format(&w, inc, actions)
	d.write(w.Bytes())

	if d.sink != nil {
		d.sink.Offer(forward.OCSFIncident(inc, d.product, time.Now()))
	}
}

// write hands a finished report to the output. While the daemon runs it never
// blocks: a consumer that stops reading must not stop the responses, the SIEM or
// the shutdown waiting behind it, so the oldest waiting report is dropped instead,
// and said to have been on stderr, which is a different consumer.
func (d *defender) write(line []byte) {
	if d.lines == nil {
		d.outMu.Lock()
		defer d.outMu.Unlock()
		_, _ = d.out.Write(line)
		return
	}
	for {
		select {
		case d.lines <- line:
			return
		default:
		}
		select {
		case <-d.lines:
			if d.unwritten.Add(1) == 1 {
				d.warn("[WARN] output is not being read: dropping the oldest reports to keep the defence running")
			}
		default:
		}
	}
}

func (d *defender) format(w io.Writer, inc correlate.Incident, actions []string) {
	if d.json {
		_ = json.NewEncoder(w).Encode(struct {
			Time     string             `json:"time"`
			Incident correlate.Incident `json:"incident"`
			Actions  []string           `json:"actions,omitempty"`
		}{time.Now().UTC().Format(time.RFC3339), inc, actions})
		return
	}
	state := "ALERT"
	if inc.Confirmed {
		state = "CONFIRMED"
	}
	layers := make([]string, len(inc.Layers))
	for i, l := range inc.Layers {
		layers[i] = string(l)
	}
	fmt.Fprintf(w, "\n [!] %s incident %s  score %d  layers: %s\n", state, inc.ID, inc.Score, strings.Join(layers, ", "))
	fmt.Fprintf(w, "     why    : %s\n", report.TermSafe(inc.Why))
	for _, f := range inc.Files {
		fmt.Fprintf(w, "     file   : %s\n", report.TermSafe(f))
	}
	if len(inc.PIDs) > 0 {
		fmt.Fprintf(w, "     pids   : %v\n", inc.PIDs)
	}
	for _, peer := range inc.Peers {
		fmt.Fprintf(w, "     peer   : %s\n", report.TermSafe(peer))
	}
	if len(inc.Hosts) > 0 {
		fmt.Fprintf(w, "     hosts  : %s\n", report.TermSafe(strings.Join(inc.Hosts, ", ")))
	}
	if len(inc.Techniques) > 0 {
		fmt.Fprintf(w, "     attack : %s\n", strings.Join(inc.Techniques, ", "))
	}
	for _, s := range inc.Signals {
		fmt.Fprintf(w, "     [%s] %s %d: %s\n", s.Layer, report.TermSafe(s.Class), s.Score, report.TermSafe(truncStr(s.Detail, 160)))
	}
	for _, a := range actions {
		fmt.Fprintf(w, "     action : %s\n", report.TermSafe(a))
	}
}

// run starts everything and waits for stop. Nothing here runs in sequence: each
// layer, each scan worker, the sweep and the correlator is its own goroutine with
// its own trigger, carrying the daemon's protections, because this is the
// long-lived privileged process an attacker most wants gone. A panic costs one
// pass of one part.
func (d *defender) run(w *watch.Watcher, interval time.Duration, stop <-chan struct{}, status func(string, ...interface{})) {
	// guarded runs fn up to attempts times, stopping at the first that completes.
	// Every panic is logged and raised as an alert: a retry that works still means
	// part of the defence went down for a moment on this host.
	guarded := func(task string, attempts int, fn func()) {
		for range attempts {
			if !runCycle(fn, status) {
				break
			}
			status("[WARN] the defend %s task crashed and was recovered", task)
			runCycle(func() { d.alertCrash(task) }, status)
		}
		if sdnotify.Enabled() {
			_ = sdnotify.Watchdog()
		}
	}
	// Scan something harmless before taking work. Filters are built on first use, and
	// that must not be paid by the first file to land, which may be the attack.
	d.engine.ScanFile("/proc/self/status")

	// The channel is never closed: a scan abandoned at shutdown can still report
	// something after the writer has gone, and that must be a line nobody reads
	// rather than a send on a closed channel.
	d.lines = make(chan []byte, defendLineQueue)
	flush, flushed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(flushed)
		for {
			select {
			case line := <-d.lines:
				_, _ = d.out.Write(line)
			case <-flush:
				for {
					select {
					case line := <-d.lines:
						_, _ = d.out.Write(line)
					default:
						return
					}
				}
			}
		}
	}()

	// Three groups, because a stop treats them differently. Scanning work can be
	// left behind, the correlator can't start anything once it has gone, and a
	// response is always seen through: a half-done quarantine is worse than a late
	// exit, and the helpers it runs have timeouts of their own.
	var wg, correlator, responses sync.WaitGroup
	startIn := func(group *sync.WaitGroup, fn func()) {
		group.Add(1)
		go func() {
			defer group.Done()
			fn()
		}()
	}
	start := func(fn func()) { startIn(&wg, fn) }
	// loopIn runs fn now, then on every tick and every wake until stop. A pass in
	// progress is never interrupted.
	loopIn := func(group *sync.WaitGroup, task string, every time.Duration, wake wakeup, fn func()) {
		startIn(group, func() {
			guarded(task, defendAttempts, fn)
			var tick <-chan time.Time
			if every > 0 {
				t := time.NewTicker(every)
				defer t.Stop()
				tick = t.C
			}
			for {
				select {
				case <-stop:
					return
				case <-tick:
				case <-wake:
				}
				guarded(task, defendAttempts, fn)
			}
		})
	}
	loop := func(task string, every time.Duration, wake wakeup, fn func()) {
		loopIn(&wg, task, every, wake, fn)
	}

	for i := range d.workers {
		start(func() {
			for finished := false; !finished; {
				guarded("scan", defendAttempts, func() {
					// Half the workers never touch the sweep: it is background work
					// and must not take every core, while what just landed may use
					// all of them.
					d.scanWorker(i%2 == 0)
					finished = true
				})
			}
		})
	}
	// A response is not retried: part of it may already have happened, and it can
	// be read in the alert that follows.
	act := func(fresh []correlate.Incident, ps *procscan.Result) {
		guarded("response", 1, func() { d.act(fresh, ps, false) })
	}
	loopIn(&correlator, "correlate", 0, d.wakeCorrelate, func() {
		if fresh, ps := d.join(); len(fresh) > 0 {
			startIn(&responses, func() { act(fresh, ps) })
		}
	})
	loop("sweep", d.sweepEvery, d.wakeSweep, func() {
		d.sweepDue.Store(false)
		d.sweepRoots()
	})
	loop("process", interval, d.wakeProcess, d.processLayer)
	loop("persistence", interval, d.wakePersistence, d.persistenceLayer)
	if d.network {
		loop("network", interval, d.wakeNetwork, d.networkLayer)
	}
	if d.feeder != nil {
		loop("ingest", interval, d.wakeIngest, d.ingestLayer)
	}
	loop("canary", interval, d.wakeCanary, d.canaryLayer)
	if d.packageInterval > 0 {
		loop("package", d.packageInterval, nil, d.packageLayer)
	}
	if d.selftestInterval > 0 && (d.selftestManifest != "" || d.guard.Fault() != nil) {
		loop("selftest", d.selftestInterval, d.wakeSelftest, d.selftestLayer)
	}
	if d.feedInterval > 0 && d.feedPath != "" {
		loop("feed", d.feedInterval, d.wakeFeed, d.feedLayer)
	}
	if w != nil {
		go func() {
			_ = w.Run(func(e watch.Event) {
				if e.Overflow {
					// Lost events can hide a change to what runs at boot as
					// easily as a new file, and a sweep only finds files.
					d.requestSweep()
					d.wakeHostLayers()
				} else {
					d.enqueue(e.Path)
				}
			})
		}()
	}

	<-stop
	d.queue.close()
	correlator.Wait() // nothing starts a response after this
	settled := make(chan struct{})
	go func() {
		wg.Wait()
		close(settled)
	}()
	select {
	case <-settled:
	case <-time.After(d.stopWait):
		d.abandoned.Store(true)
		status("[WARN] exiting with a scan still running: it can't be interrupted, and nothing depends on it")
	}
	responses.Wait()
	// Whatever finished during the shutdown is still worth reporting.
	fresh, ps := []correlate.Incident(nil), (*procscan.Result)(nil)
	guarded("correlate", 1, func() { fresh, ps = d.join() })
	act(fresh, ps)

	// A consumer that has stopped reading gets a moment and no more: this is the
	// last thing between a stop request and exiting.
	close(flush)
	select {
	case <-flushed:
	case <-time.After(d.flushWait):
		status("[WARN] output is not being read: exiting with %d report(s) unwritten", len(d.lines))
	}
	if n := d.unwritten.Load(); n > 0 {
		status("[WARN] %d report(s) were dropped because output was not being read", n)
	}
}

func cmdDefend(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("defend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { defendUsage(stderr) }
	var watchDirs multiFlag
	fs.Var(&watchDirs, "watch", "watch this tree (repeatable)")
	once := fs.Bool("once", false, "run one cycle and exit")
	interval := fs.Duration("interval", 30*time.Second, "cycle period")
	noWatch := fs.Bool("no-watch", false, "do not watch files in real time")
	respond := fs.String("respond", string(procscan.ActionStop), "act on confirmed processes: stop, kill or none")
	quarantineFlag := fs.Bool("quarantine", true, "move confirmed files into the vault")
	reportOnly := fs.Bool("report-only", false, "change nothing: alert and forward, but never stop, quarantine or block")
	configPath := fs.String("config", "", "agent configuration file (default "+trust.DefaultConfigPath+")")
	siem := fs.String("siem", "", "SIEM address: an IP, host, host:port or full URL (overrides the config file)")
	store := fs.String("quarantine-store", "", "vault directory")
	blockExe := fs.Bool("block-exe", true, "ask the kernel to refuse confirmed files (skipped when cau-kernel is absent)")
	kernelBin := fs.String("kernel-bin", "cau-kernel", "the cau-kernel binary")
	kernelEvents := fs.String("kernel-events", "", "cau-kernel guard event log")
	canaryManifest := fs.String("canary-manifest", "", "canary manifest")
	packageInterval := fs.Duration("package-interval", time.Hour, "how often to audit packages; 0 disables")
	rulesFlag := fs.String("rules", "", "YARA rule file or directory")
	dbFlag := fs.String("db", "", "signature database")
	fuzzyFlag := fs.String("fuzzy-db", "", "fuzzy signature database")
	feedPath := fs.String("feed", "", "abuse-intel feed")
	feedInterval := fs.Duration("feed-reload", 10*time.Minute, "how often to re-read the feed from disk; 0 disables")
	selftestManifest := fs.String("selftest-manifest", "", "selftest baseline manifest (default: integrity.json next to the signature DB)")
	selftestInterval := fs.Duration("selftest-interval", 15*time.Minute, "how often to verify detection-content integrity; 0 disables")
	selftestPubKeyFile := fs.String("selftest-pubkey", "", "Ed25519 public key (hex) for the signed selftest manifest")
	format := fs.String("format", "text", "text or json")
	wazuhURL := fs.String("wazuh-url", "", "Wazuh Manager API base; forwards each incident as an OCSF Detection Finding")
	wazuhUser := fs.String("wazuh-user", "", "Wazuh API user for --wazuh-url")
	wazuhPasswordEnv := fs.String("wazuh-password-env", "WAZUH_PASSWORD", "environment variable holding the Wazuh API password (never on argv)")
	wazuhCA := fs.String("wazuh-ca", "", "PEM CA bundle to trust the Wazuh manager's TLS certificate")
	wazuhInsecure := fs.Bool("wazuh-insecure", false, "skip Wazuh TLS verification (explicit opt-in; also allows http://)")
	wazuhTimeout := fs.Duration("wazuh-timeout", wazuh.DefaultTimeout, "per-request timeout for the forwarder")
	forwardQueue := fs.Int("forward-queue", forward.DefaultQueue, "incidents buffered while the SIEM is unreachable; the oldest is dropped when full")
	netblockOn := fs.Bool("netblock", true, "drop traffic to and from a confirmed incident's peers (skipped with no firewall)")
	blockTTL := fs.Duration("block-ttl", netblock.DefaultTTL, "how long a network block lasts; 0 means until it is removed")
	sever := fs.Bool("sever", false, "with --netblock: also destroy established connections to a blocked peer")
	netblockDry := fs.Bool("netblock-dry-run", false, "log the firewall commands and run none of them")
	var ingestPaths multiFlag
	fs.Var(&ingestPaths, "ingest", "read telemetry from this file or directory (repeatable)")
	ingestMaxAge := fs.Duration("ingest-max-age", 24*time.Hour, "ignore ingested events older than this; 0 keeps everything")
	noNetwork := fs.Bool("no-network", false, "disable the network layer")
	etcRoot := fs.String("etc-root", "/etc", "override /etc (testing)")
	noProcess := fs.Bool("no-process", false, "disable the process layer")
	noPersistence := fs.Bool("no-persistence", false, "disable the persistence layer")
	noSelftest := fs.Bool("no-selftest", false, "disable the selftest layer")
	procRoot := fs.String("proc-root", "/proc", "override /proc (testing)")
	persistRoot := fs.String("persist-root", "/", "filesystem to audit for persistence")
	hostRoot := fs.String("host-root", "/", "filesystem to read the host's own surfaces from (the systemd generator directory, the bpffs root, the package database)")
	dpkgInfo := fs.String("dpkg-info", defaultDpkgInfo, "dpkg info directory")
	pacmanDir := fs.String("pacman-local", defaultPacmanLocal, "pacman local database")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	// Which flags were typed, so the configuration file can sit between the
	// built-in defaults and an explicit command line without ever overriding
	// something the operator just asked for.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	status := func(f string, a ...interface{}) { fmt.Fprintf(stderr, f+"\n", a...) }

	cfg, cfgErr := trust.LoadConfig(*configPath)
	var faults []startFault
	if cfgErr != nil {
		// A configuration file that exists but cannot be trusted is not believed
		// and not silently skipped: falling back to defaults without a word is
		// what an attacker who made it unsafe would be hoping for, and it would
		// look like a healthy start. Tamper is what stops it looking healthy.
		status("[TAMPER] running on built-in defaults: %s", report.TermSafe(cfgErr.Error()))
		faults = append(faults, startFault{tamperConfig, cfgErr.Error(),
			"the configuration cannot be trusted, so the agent is running on built-in defaults: " + cfgErr.Error()})
		cfg = trust.Config{}
	}
	if cfg.Path != "" {
		status("[*] configuration: %s", cfg.Path)
		for _, k := range cfg.Unknown {
			status("[WARN] %s: unknown setting %q, ignored", cfg.Path, k)
		}
	}
	applyConfigDefaults(cfg, given, respond, quarantineFlag, blockExe, netblockOn, reportOnly, feedPath)

	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	// report-only is the one switch that turns the whole response surface off,
	// so an operator who wants to watch first does not have to find and negate
	// every action individually.
	applyReportOnly(*reportOnly, respond, quarantineFlag, blockExe, netblockOn)
	action := procscan.Action(*respond)
	if action != "" && action != procscan.ActionStop && action != procscan.ActionKill {
		return fail(stderr, report.ExitUsage, "--respond must be stop, kill or none")
	}
	if *interval <= 0 {
		return fail(stderr, report.ExitUsage, "--interval must be positive")
	}
	if *store == "" {
		*store = defaultQuarantineDir()
	}
	if *blockTTL < 0 {
		return fail(stderr, report.ExitUsage, "--block-ttl must not be negative")
	}
	// These only conflict when network blocking was turned off deliberately;
	// --report-only turns the whole response surface off, so asking about one
	// action within it is not an error worth stopping a start for.
	if !*reportOnly {
		if *sever && !*netblockOn {
			return fail(stderr, report.ExitUsage, "--sever needs network blocking, which --netblock=false turned off")
		}
		if *netblockDry && !*netblockOn {
			return fail(stderr, report.ExitUsage, "--netblock-dry-run needs network blocking, which --netblock=false turned off")
		}
	}

	// A fixture /proc describes processes that do not exist, but a signal has
	// only one kernel to go to: identity is checked against the fixture and the
	// signal lands on whatever really holds that PID. Measured the hard way —
	// a scenario built around a made-up PID 900 stopped this host's real
	// process 900 — so an armed response against an overridden root says so
	// before it runs rather than afterwards.
	if *procRoot != "" && *procRoot != "/proc" {
		if armed := armedActions(action, *quarantineFlag, *netblockOn, *blockExe); armed != "" {
			status("[WARN] --proc-root is %s, not /proc, so process identity is read from a fixture while "+
				"signals still reach this kernel: %s will act on whatever really holds the PIDs that fixture names",
				*procRoot, armed)
		}
	}

	engine, closeEngine, contentFaults := defendEngine(*rulesFlag, *dbFlag, *fuzzyFlag, status)
	faults = append(faults, contentFaults...)
	var engineInUse atomic.Bool // a scan abandoned at stop is still reading the rules
	defer func() {
		if !engineInUse.Load() {
			closeEngine()
		}
	}()

	roots := []string(watchDirs)
	if len(roots) == 0 {
		roots = defaultWatchRoots
	}
	canaryPath := *canaryManifest
	if canaryPath == "" {
		canaryPath = discoverCanaryManifest(status)
	}
	kernelPath := *kernelEvents
	if kernelPath == "" {
		kernelPath = discoverKernelEvents(status)
	}
	stManifest := *selftestManifest
	if stManifest == "" && !*noSelftest {
		stManifest = discoverSelftestManifest(*dbFlag)
	}
	if *noSelftest {
		stManifest = ""
	}
	resolvedFeed := resolveFeedPath(*feedPath)
	// --block-exe is on by default, so a host without the kernel guard is told
	// once here instead of producing a failed block per confirmed file.
	if *blockExe && !kernelGuardAvailable(*kernelBin) {
		status("[*] kernel exec-blocking unavailable (%s not found): the other responses still act", *kernelBin)
		*blockExe = false
	}
	// A pinned key that cannot be used is neither a refusal to start nor a silent
	// downgrade to digest-only checking. This daemon runs for weeks, so the
	// difference between "signature verified" and "nobody checked" is said out
	// loud, as tamper, below; see startFault for why it does not stop here.
	selftestPub, keyErr := defendPubkey(*selftestPubKeyFile)
	d := &defender{
		engine: engine, procRoot: *procRoot, persistRoot: *persistRoot, hostRoot: *hostRoot,
		provenance: provenance.New(*hostRoot),
		feedPath:   resolvedFeed, feedInterval: *feedInterval,
		process: !*noProcess, persistence: !*noPersistence, kernelEvents: kernelPath, canaryManifest: canaryPath,
		packageInterval:  *packageInterval,
		selftestManifest: stManifest, selftestInterval: *selftestInterval, selftestPubKey: selftestPub,
		selftestKeyFile: *selftestPubKeyFile, selftestKeyErr: keyErr,
		dpkgInfo: *dpkgInfo, pacmanDir: *pacmanDir,
		action: action, quarantine: *quarantineFlag, store: *store, blockExe: *blockExe, kernelBin: *kernelBin,
		network: !*noNetwork, etcRoot: *etcRoot,
		roots: roots, json: *format == "json", out: stdout, warn: status,
	}
	if len(ingestPaths) > 0 {
		d.ingestPaths = []string(ingestPaths)
		d.feeder = ingest.NewReader(ingest.Options{MaxAge: *ingestMaxAge})
		d.ingestMaxAge = *ingestMaxAge
	}
	if *netblockOn {
		b, err := netblock.Open(netblock.Options{
			TTL:     blockTTLValue(*blockTTL),
			DryRun:  *netblockDry,
			Protect: netblock.LocalProtect(*procRoot, *etcRoot),
			Ledger:  netblock.DefaultLedger(""),
			Sever:   *sever,
		})
		if err != nil {
			// A host with no firewall is told at startup rather than at the
			// moment a block is needed, and the rest of the defence still runs.
			status("[WARN] --netblock: %v", err)
		} else {
			d.blocker = b
			status("[*] network blocking armed: %s, blocks last %s, never touching %s",
				b.Backend(), blockDuration(b), strings.Join(b.Protected(), " "))
		}
	}
	d.ready()

	// The signed baseline, read once at startup. Everything that asks "is this
	// file still the one somebody trusted" goes through it, including the feed
	// reload while the daemon runs.
	guard, gerr := trust.NewGuard(stManifest, d.selftestPubKey.key)
	switch {
	case keyErr != nil:
		guard = trust.Distrusted(stManifest, nil, keyErr)
	case gerr != nil:
		guard = trust.Distrusted(stManifest, d.selftestPubKey.key, gerr)
	}
	d.guard = guard
	for _, f := range faults {
		d.tamper(f.class, f.reason, f.detail)
	}
	switch {
	case guard.Fault() != nil:
		// Running with every integrity check silently answering "fine" is the
		// danger here, so nothing is checked against this baseline and the
		// reason goes out as tamper. It is retried on every selftest cycle.
		status("[TAMPER] the integrity baseline cannot be checked: %s", report.TermSafe(guard.Fault().Error()))
		d.distrust(guard.Fault())
	case !guard.Loaded():
		status("[*] no integrity baseline: content and configuration cannot be verified (record one with 'cau selftest --record')")
	case guard.Signed():
		status("[*] integrity baseline %s verified against the pinned key", guard.Path())
		// A signed baseline is only worth more than an unsigned one while the
		// private key is somewhere this host is not. Left in /etc/cau beside
		// the manifest it signed, it reduces the signed case to the unsigned
		// one exactly, and nothing about the running daemon would look wrong.
		if keys := trust.SigningKeysNearby(filepath.Dir(guard.Path()), filepath.Dir(trust.DefaultConfigPath)); len(keys) > 0 {
			status("[WARN] what looks like a signing key is on this host (%s): an attacker who can rewrite the content can sign their own baseline over it, which makes the signature worth no more than a digest. Keep it elsewhere.",
				strings.Join(keys, " "))
			d.weakness(weakSigningKeyOnHost, strings.Join(keys, " "),
				"a signing key appears to be stored on the host it signs for ("+strings.Join(keys, " ")+"), so the baseline's signature can be forged locally")
		}
	default:
		status("[*] integrity baseline %s loaded, unsigned (pin a key with --selftest-pubkey to resist a rewrite of the baseline itself)", guard.Path())
	}

	// The first feed load goes through the same verified path as every reload.
	// It used to be a plain read before the guard existed, which left the one
	// moment an attacker is most likely to catch — the restart after they have
	// rewritten the feed — as the one load that was never checked.
	d.feedLayer()

	siemAddr := d.resolveSIEM(*siem, given["siem"], cfg, status)
	forwardOpts := defendForward{
		url: trust.SIEMURL(siemAddr), user: *wazuhUser, passwordEnv: *wazuhPasswordEnv,
		ca: *wazuhCA, insecure: *wazuhInsecure, timeout: *wazuhTimeout, queue: *forwardQueue,
	}
	// --wazuh-url stays the explicit, fully-specified form and wins over the
	// --siem shorthand when both are given.
	if strings.TrimSpace(*wazuhURL) != "" {
		forwardOpts.url = *wazuhURL
	}
	if forwardOpts.user == "" {
		forwardOpts.user = cfg.SIEMUser
	}
	if forwardOpts.ca == "" {
		forwardOpts.ca = cfg.SIEMCA
	}
	if cfg.SIEMInsecure && !given["wazuh-insecure"] {
		forwardOpts.insecure = true
	}
	if cfg.SIEMPasswordEnv != "" && !given["wazuh-password-env"] {
		forwardOpts.passwordEnv = cfg.SIEMPasswordEnv
	}
	forwardOpts.certPins = d.resolveCertPins(cfg, status)
	closeSink, err := d.startForward(forwardOpts, status)
	if err != nil {
		// A forwarder named on the command line that cannot work is a mistake to
		// report now. One that came from a file or the environment is the same
		// off switch as any other planted file: `siem =` in the configuration
		// with no password to go with it would stop the daemon.
		if given["wazuh-url"] || given["siem"] {
			return fail(stderr, report.ExitUsage, "%v", err)
		}
		status("[TAMPER] incidents are only being reported locally: %s", report.TermSafe(err.Error()))
		d.tamper(tamperForward, err.Error(),
			"the configured SIEM forwarder cannot run, so incidents are only being reported locally: "+err.Error())
		closeSink = func() {}
	}
	defer closeSink()

	if *once {
		d.sweepDue.Store(!*noWatch)
		d.cycle()
		if len(d.seen) > 0 {
			return report.ExitThreat
		}
		return report.ExitOK
	}

	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(defendMemoryLimit)
	}
	status("[*] %s", harden.Apply().Summary())
	var w *watch.Watcher
	if !*noWatch {
		if w, err = watch.New(roots, 0); err != nil {
			status("[WARN] real-time watching unavailable, relying on the %s interval: %v", *interval, err)
			w = nil
		} else {
			defer w.Close()
			status("[*] watching %d directories", w.Dirs())
			if w.Truncated() {
				status("[WARN] real-time coverage is incomplete: the directory limit was reached, or a directory could not be read or watched, so the %s interval is what covers those gaps", *interval)
			}
			d.sweepDue.Store(true)
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	stop := make(chan struct{})
	go func() { <-sig; close(stop) }()
	startWatchdog(stop, status)
	if sdnotify.Enabled() {
		_ = sdnotify.Ready()
	}
	selftestState := "off"
	if d.selftestManifest != "" && d.selftestInterval > 0 {
		selftestState = d.selftestInterval.String() + " (" + d.selftestManifest + ")"
	}
	feedState := "off"
	if d.feedPath != "" && d.feedInterval > 0 {
		feedState = d.feedInterval.String() + " (" + d.feedPath + ")"
	}
	forwardState := "off"
	if d.sink != nil {
		forwardState = *wazuhURL
	}
	netState := "off"
	if d.network {
		netState = "on"
		if d.blocker != nil {
			netState = "on, blocking with " + string(d.blocker.Backend())
		}
	}
	ingestState := "off"
	if d.feeder != nil {
		ingestState = strings.Join(d.ingestPaths, ", ")
	}
	status("[*] network layer %s; external telemetry %s", netState, ingestState)
	stance := "DEFENDING"
	if *reportOnly {
		stance = "REPORT-ONLY (changing nothing)"
	}
	status("[*] %s: %d scan workers, every layer on its own schedule, host re-read every %s and on any change",
		stance, d.workers, *interval)
	status("[*] response: respond=%q quarantine=%v block-exe=%v netblock=%v | integrity=%s | selftest=%s feed-reload=%s forward=%s",
		*respond, *quarantineFlag, *blockExe, d.blocker != nil, integrityState(d.guard), selftestState, feedState, forwardState)
	d.run(w, *interval, stop, status)
	engineInUse.Store(d.abandoned.Load())
	if sdnotify.Enabled() {
		_ = sdnotify.Stopping()
	}
	return report.ExitOK
}

// armedActions names the responses that are switched on, for the warning a
// fixture root deserves. It returns "" when nothing would act.
func armedActions(action procscan.Action, quarantine, netblock, blockExe bool) string {
	var on []string
	if action != "" {
		on = append(on, "--respond "+string(action))
	}
	if quarantine {
		on = append(on, "--quarantine")
	}
	if netblock {
		on = append(on, "--netblock")
	}
	if blockExe {
		on = append(on, "--block-exe")
	}
	return strings.Join(on, ", ")
}

// blockTTLValue translates the flag's meaning into the package's: on the
// command line 0 means "no expiry", which is a thing an operator has to ask for
// explicitly, while the package reserves 0 for its own default.
func blockTTLValue(d time.Duration) time.Duration {
	if d == 0 {
		return -1
	}
	return d
}

func blockDuration(b *netblock.Blocker) string {
	if b.TTL() <= 0 {
		return "until removed"
	}
	return b.TTL().String()
}

// discoverCanaryManifest looks in standard locations for a canary manifest left
// by `cau canary plant`, so a plain `cau defend` picks it up. A missing file
// returns "": the canary layer tolerates that.
func discoverCanaryManifest(status func(string, ...interface{})) string {
	candidates := []string{
		os.Getenv("CAU_CANARY_MANIFEST"),
		"/var/lib/cau/canary.json",
		"/etc/cau/canary.json",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".cau", "canary.json"))
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			status("[*] canary manifest discovered: %s", p)
			return p
		}
	}
	return ""
}

// kernelEventPaths are the places the cau-kernel guard's event log is looked
// for.
//
// The first one is where the guard's shipped systemd unit writes it
// (`cau-kernel enforce netshell --log /run/cau/kernel-events.jsonl`). A path
// the daemon does not look at is a log nobody reads, so the unit's path and
// the daemon's list are one thing and are pinned by a test.
var kernelEventPaths = []string{
	"/run/cau/kernel-events.jsonl",
	"/var/log/cau-kernel/events.jsonl",
	"/var/lib/cau-kernel/events.jsonl",
}

// discoverKernelEvents looks in standard locations for the cau-kernel exec-guard
// event log, so the kernel layer joins the daemon without extra flags on a host
// where cau-kernel is installed.
func discoverKernelEvents(status func(string, ...interface{})) string {
	candidates := append([]string{os.Getenv("CAU_KERNEL_EVENTS")}, kernelEventPaths...)
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			status("[*] kernel event log discovered: %s", p)
			return p
		}
	}
	return ""
}

// discoverSelftestManifest resolves the baseline manifest the same way
// `cau selftest` does: integrity.json next to the signature DB. Nothing there
// (an install without `cau selftest --record`) returns "": the selftest layer
// is a no-op in that case rather than noisy.
func discoverSelftestManifest(dbFlag string) string {
	dbPath, _ := findResource(dbFlag, envSignatures, relSignatures)
	if dbPath == "" {
		return ""
	}
	p := filepath.Join(filepath.Dir(dbPath), "integrity.json")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// integrityState says in one word how much the integrity checks are worth on
// this host, because "verified" and "nothing recorded" are very different
// things to be reading in a log a week later.
func integrityState(g *trust.Guard) string {
	switch {
	case g.Fault() != nil:
		return "UNVERIFIED"
	case g.Signed():
		return "signed+verified"
	case g.Loaded():
		return "baselined (unsigned)"
	default:
		return "none"
	}
}

// envSIEM configures the SIEM address from the environment, which is what a
// container or a systemd EnvironmentFile can set alongside the password.
const envSIEM = "CAU_SIEM"

// resolveSIEM decides where incidents are forwarded, and declines to be
// redirected by an edit to a file.
//
// The configuration file is the only one of the three sources that can be
// signed, and it is also the one an attacker can reach: rewriting one line of
// it both stops the real SIEM hearing about an intrusion and delivers the
// agent's own findings to whoever wrote the line. So when the baseline pins an
// address and the file now says something else, the pinned address is used and
// the edit is raised as tampering.
//
// A flag or an environment variable still wins. Those come from whoever started
// the process, not from a file lying around on the host, and an operator moving
// their SIEM must not have to re-record a baseline before the agent will talk
// to it. The honest limit of all this is in docs/limitations.md: someone who
// can edit the configuration can usually also re-record an unsigned baseline,
// which is exactly why the key belongs off the host.
func (d *defender) resolveSIEM(flagVal string, flagGiven bool, cfg trust.Config, status func(string, ...interface{})) string {
	// An override still wins, but it no longer does so silently. A flag or an
	// environment variable is the one way left to send this agent's incidents
	// somewhere other than the baselined address without the config digest
	// changing, and whoever can edit the unit file or its EnvironmentFile can
	// use it. Honouring operator intent and reporting it are not in conflict:
	// the override is applied, and a human is told the pin was set aside.
	if override := d.overrideSIEM(flagVal, flagGiven); override != "" {
		if pinned, ok := d.guard.Pin(selftest.PinSIEM); ok && strings.TrimSpace(pinned) != override {
			status("[WARN] the SIEM address was overridden to %q, setting aside the baselined %s", override, pinned)
			d.weakness(weakSIEMOverridden, override,
				"the baselined SIEM address "+pinned+" was overridden to "+override+
					" from the command line or the environment, which the integrity baseline cannot cover")
		}
		return override
	}
	onDisk := strings.TrimSpace(cfg.SIEM)
	pinned, hasPin := d.guard.Pin(selftest.PinSIEM)
	pinned = strings.TrimSpace(pinned)
	if !hasPin || pinned == onDisk {
		return onDisk
	}
	switch {
	case onDisk == "":
		d.tamper(tamperSIEMRemoved, "removed",
			"the SIEM address was removed from "+cfgOrigin(cfg)+", which would stop incidents being forwarded; the baselined address "+pinned+" is being used instead")
	default:
		d.tamper(tamperSIEMRedirected, onDisk,
			"the SIEM address in "+cfgOrigin(cfg)+" was changed to "+onDisk+", which would send incidents somewhere other than the baselined "+pinned+"; the baselined address is being used instead")
	}
	status("[WARN] configured SIEM address does not match the signed baseline: using the baselined %s, not %q", pinned, onDisk)
	return pinned
}

// resolveCertPins decides which public-key pins the forwarder enforces, and
// prefers the signed ones over what is on disk now.
//
// This is the address pin's other half. Pinning where incidents go says nothing
// about who answers there, and "TLS verifies it" holds only while every CA the
// host trusts does. So the manager's key is pinned too — and because an
// attacker who could edit that pin would just substitute their own collector's,
// the pin itself is signed into the baseline and the signed value wins.
func (d *defender) resolveCertPins(cfg trust.Config, status func(string, ...interface{})) []string {
	onDisk := strings.Join(cfg.SIEMCertPins, ",")
	pinned, hasPin := d.guard.Pin(selftest.PinSIEMCert)
	pinned = strings.TrimSpace(pinned)
	if !hasPin || pinned == onDisk {
		return cfg.SIEMCertPins
	}
	if onDisk == "" {
		d.tamper("defend.tamper.siem-cert-pin-removed",
			"removed",
			"the SIEM certificate pin was removed from "+cfgOrigin(cfg)+", which would let any certificate the host trusts receive incidents; the baselined pin is being used instead")
	} else {
		d.tamper("defend.tamper.siem-cert-pin-changed", onDisk,
			"the SIEM certificate pin in "+cfgOrigin(cfg)+" was changed, which would let a different server receive incidents; the baselined pin is being used instead")
	}
	status("[WARN] the configured SIEM certificate pin does not match the signed baseline: using the baselined pin")
	return strings.Split(pinned, ",")
}

// overrideSIEM returns the address given outside any file, or "" if none was.
func (d *defender) overrideSIEM(flagVal string, flagGiven bool) string {
	if flagGiven && strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	return strings.TrimSpace(os.Getenv(envSIEM))
}

// cfgOrigin names the configuration file for a message, including the case
// where it was deleted entirely.
func cfgOrigin(cfg trust.Config) string {
	if cfg.Path == "" {
		return "the agent configuration (" + trust.DefaultConfigPath + ", now absent)"
	}
	return cfg.Path
}

// applyConfigDefaults lets the configuration file change a setting the operator
// did not type. Precedence is built-in default, then the file, then the command
// line: a flag that was given always wins, because it is the more recent and
// more specific statement of intent.
func applyConfigDefaults(cfg trust.Config, given map[string]bool, respond *string, quarantine, blockExe, netblock, reportOnly *bool, feed *string) {
	if cfg.Respond != "" && !given["respond"] {
		*respond = cfg.Respond
	}
	if cfg.Quarantine != nil && !given["quarantine"] {
		*quarantine = *cfg.Quarantine
	}
	if cfg.BlockExe != nil && !given["block-exe"] {
		*blockExe = *cfg.BlockExe
	}
	if cfg.Netblock != nil && !given["netblock"] {
		*netblock = *cfg.Netblock
	}
	if cfg.ReportOnly != nil && !given["report-only"] {
		*reportOnly = *cfg.ReportOnly
	}
	if cfg.Feed != "" && !given["feed"] {
		*feed = cfg.Feed
	}
}

// applyReportOnly collapses the whole response surface to nothing, so an
// operator who wants to watch first has one switch to find rather than four
// actions to remember to negate. It also normalises "none", which reads better
// in a configuration file than an empty string, into the empty action the
// responder already understands.
func applyReportOnly(reportOnly bool, respond *string, quarantine, blockExe, netblock *bool) {
	if reportOnly {
		*respond, *quarantine, *blockExe, *netblock = "none", false, false, false
	}
	if *respond == "none" {
		*respond = ""
	}
}

// kernelGuardAvailable reports whether the cau-kernel binary this build would
// call is actually on the host.
//
// --block-exe defaults on, and most hosts do not have the kernel guard
// installed. Failing the start would make the common case a broken one, and
// leaving it armed would mean every confirmed file produced a failed block and
// a misleading action line. So the capability is checked once, reported once,
// and the rest of the defence runs.
// It resolves $PATH itself rather than importing os/exec, so this file stays
// out of the exec allowlist: asking whether a program exists does not need the
// ability to start one, and the gate in source_gates_test.go is worth more than
// the three lines it saves.
func kernelGuardAvailable(bin string) bool {
	if bin == "" {
		return false
	}
	executable := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	}
	if strings.ContainsRune(bin, os.PathSeparator) {
		return executable(bin)
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		if executable(filepath.Join(dir, bin)) {
			return true
		}
	}
	return false
}

// defendForward is the forwarder's configuration as the flags give it.
type defendForward struct {
	url, user, passwordEnv, ca string
	insecure                   bool
	timeout                    time.Duration
	queue                      int
	// certPins additionally require the manager's public key to match, so a
	// certificate from any CA the host trusts is not enough to receive these
	// incidents.
	certPins []string
}

// defendForwardGrace bounds how long shutdown waits for queued incidents to
// reach the SIEM. It is well inside the unit's TimeoutStopSec, so a hung
// manager delays the stop rather than causing systemd to SIGKILL the daemon
// before its own shutdown correlation has run.
const defendForwardGrace = 20 * time.Second

// startForward builds the SIEM sink, if one is configured, and returns the
// function that flushes and stops it.
//
// A forwarder the operator asked for and that cannot possibly work is a startup
// error, not a warning. The alternative is the failure this whole daemon is
// built to avoid: a process that looks healthy, logs nothing unusual, and
// delivers nothing to the place someone is watching.
func (d *defender) startForward(o defendForward, status func(string, ...interface{})) (func(), error) {
	noop := func() {}
	if strings.TrimSpace(o.url) == "" {
		return noop, nil
	}
	password := os.Getenv(o.passwordEnv)
	if password == "" {
		return nil, fmt.Errorf("--wazuh-url is set but $%s is empty: set --wazuh-password-env to the variable holding the API password", o.passwordEnv)
	}
	client, err := wazuh.New(wazuh.Options{
		URL: o.url, User: o.user, Password: password,
		CAFile: o.ca, Insecure: o.insecure, Timeout: o.timeout,
		CertPins: o.certPins,
		ObservePin: func(pin string) {
			status("[WARN] the SIEM presented public key %s, which matches no configured pin; if that is really your manager, set siem-cert-pin to it and re-record the baseline", pin)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("wazuh forwarder: %w", err)
	}
	host, _ := os.Hostname()
	d.product = forward.DefaultProduct(host)
	d.sink = forward.NewSink(forward.WazuhSender{Client: client}, forward.SinkOptions{
		Queue:   o.queue,
		Batch:   forward.WazuhBatch,
		Timeout: 2 * o.timeout,
		Warn:    status,
	})
	d.sink.Start()
	status("[*] forwarding incidents to %s as OCSF %s Detection Findings (queue %d)", o.url, report.OCSFVersion, o.queue)
	// Pinning where incidents go says nothing about who answers at that
	// address. TLS verification is the half that does, so turning it off
	// reopens the redirect the pin was meant to close — this time on the
	// network rather than on disk.
	if o.insecure {
		status("[WARN] TLS verification is off for %s: the pinned address no longer guarantees who receives these incidents", o.url)
		d.weakness(weakSIEMInsecureTLS, o.url,
			"incidents are forwarded to "+o.url+" without verifying its TLS certificate, so anything that can answer at that address receives them")
	}
	return func() {
		st := d.sink.Close(defendForwardGrace)
		status("[*] forward: %d offered, %d delivered, %d dropped, %d failed", st.Offered, st.Delivered, st.Dropped, st.Failed)
	}, nil
}

// defendEngine builds the same engine `cau scan` runs by default. YARA and hash
// content are optional here: a host with neither still has the other layers.
//
// A resource that cannot be loaded is a startFault and not an error: the layers
// that do not need it keep running, and the ones that do are in the state they
// are in on a host that never had it.
func defendEngine(rules, db, fuzzyPath string, status func(string, ...interface{})) (*scanner.Engine, func(), []startFault) {
	e := &scanner.Engine{Heuristics: true, Static: true, Stego: true, EncChain: true, LNK: true, OLE: true, PDF: true,
		ISO: true, LinuxPkg: true, Peel: true, PeelIndicators: true, Archive: true, CHM: true, Tradecraft: true}
	closer := func() {}
	var faults []startFault
	unusable := func(class, what string, err error) {
		status("[TAMPER] running without the %s: %s", what, report.TermSafe(err.Error()))
		faults = append(faults, startFault{tamperContent + class, err.Error(),
			"the " + what + " could not be loaded, so the agent is running without it: " + err.Error()})
	}
	if p, _ := findResource(db, envSignatures, relSignatures); p != "" {
		if sigs, err := scanner.LoadSignatures(p); err != nil {
			unusable("signatures", "signature database", err)
		} else {
			e.DB = sigs
		}
	}
	if p, _ := findResource(rules, envRules, relRules); p != "" {
		if ys, _, err := scanner.LoadYaraRules(p); err != nil {
			unusable("rules", "YARA rules", err)
		} else {
			e.Yara = ys
			closer = func() { _ = ys.Close() }
		}
	} else {
		status("[WARN] no YARA rules found: known-bad content will not be identified")
	}
	if p, _ := findResource(fuzzyPath, envFuzzy, relFuzzy); p != "" {
		if fz, err := static.LoadFuzzyDB(p); err != nil {
			unusable("fuzzy", "fuzzy database", err)
		} else {
			e.FuzzyDB = fz
		}
	}
	return e, closer, faults
}

// defendPubkey is resolveSelftestPubkey for a daemon, with one more question:
// who can replace this file? A key is only worth checking against if the host's
// other users cannot swap it, and with it the baseline it vouches for. So it has
// to sit as safely as what it protects, and a key that does not is reported the
// same way as one that cannot be read, not believed. That also rules out a pipe:
// this path is re-read on every retry, and $CAU_SELFTEST_PUBKEY is the way to
// supply a key with no file.
func defendPubkey(file string) (selftestKey, error) {
	if file != "" {
		if err := trust.CheckFile(file); err != nil {
			return selftestKey{}, fmt.Errorf("the pinned public key cannot be relied on: %w", err)
		}
	}
	return resolveSelftestPubkey(file)
}

// Package procscan is a point-in-time threat scan of the live process table,
// read entirely from /proc. It is the runtime complement to the static file
// scanner: where that asks "is this file malicious?", procscan asks "is anything
// running right now that a benign system would not be running?".
//
// It is READ-ONLY and offline. It never injects, ptraces, signals, or stops a
// process; it only reads the public /proc interfaces (exe symlink, comm,
// cmdline, maps, environ, status) and scores what it finds. Every read is
// best-effort: an entry that disappears mid-scan, or one this user may not read
// (another user's process, without root), is counted as unreadable and skipped,
// never fatal.
//
// The detection logic (detect) is a pure function of the fields read from one
// process, so it is unit-testable without spawning hostile processes. What it
// looks for:
//
//   - Fileless / RAM-only execution: the exe symlink resolves to an anonymous
//     memfd, a deleted inode, or a tmpfs path (/dev/shm, /tmp) — a process whose
//     backing binary is not a normal on-disk file (T1620 / T1055).
//   - Name masquerading / PID hijacking: the process's advertised name (comm /
//     argv[0]) impersonates a well-known system process or a common tool, but its
//     real exe lives somewhere that process never lives — the fake-"btop",
//     "[kworker/…]"-with-a-real-exe, or /tmp/sshd shape (T1036.004/005).
//   - Library-injection hooks: a shared object mapped into the address space, or
//     an LD_PRELOAD/LD_LIBRARY_PATH in the environment, pointing at a world-
//     writable, hidden, or deleted path (T1574.006).
//   - Malicious command lines: the process argv run through the same install-
//     script vectors the file scanner uses (reverse shells, curl|bash, droppers).
//   - Being traced: a non-zero TracerPid, surfaced as context (T1055.008).
//   - Network shells: an interpreter whose stdin and stdout are both the same
//     live TCP connection, which is what a reverse or bind shell is whatever
//     its argv says (T1059.004). Two different connections instead are reported
//     as context: a harness or multiplexer leaves that shape, and nothing is
//     stopped on it alone.
//   - Pipe relays: an interpreter fed by, and writing to, a network tool through
//     pipes, the `mkfifo | sh | nc` shape that puts no socket on the shell.
//   - Setuid shells: an interpreter whose effective uid differs from its real
//     uid, what a SUID GTFOBin leaves behind (T1548.001).
//   - Anonymous executable memory: a writable and executable mapping with no
//     backing file, context only because JIT runtimes do this too (T1055).
//   - Kernel events: what the cau-kernel exec guard recorded about a live
//     process, matched on the start time when the event carries one so a
//     process that reused the PID does not inherit the finding.
//
// Scanning stays read-only. Acting on a result is a separate, explicit step:
// see Respond.
package procscan

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/intel"
	"github.com/1ungaka/sentinel-edr/internal/parallel"
	"github.com/1ungaka/sentinel-edr/scanner/linuxpkg"
	"github.com/1ungaka/sentinel-edr/scanner/tradecraft"
)

// DefaultThreshold is the per-process score at which a process is reported.
const DefaultThreshold = 8

// Caps keep a hostile or huge process table bounded.
const (
	maxProcs       = 65536
	maxMapsBytes   = 4 << 20
	maxCmdlineByte = 64 << 10
	maxEnvironByte = 64 << 10
	// maxMappedEntries caps the distinct mapped pathnames kept from one maps
	// file, on top of the byte cap above.
	maxMappedEntries = 4096
)

// ATT&CK technique ids.
const (
	techFileless   = "T1620"     // Reflective Code Loading (memfd / anonymous exec)
	techMasqName   = "T1036.005" // Masquerading: Match Legitimate Name or Location
	techMasqProc   = "T1036.004" // Masquerading: Masquerade Task or Service
	techPreload    = "T1574.006" // Hijack Execution Flow: Dynamic Linker Hijacking
	techPtrace     = "T1055.008" // Process Injection: Ptrace System Call
	techProcInject = "T1055"     // Process Injection (generic)
	techSetuid     = "T1548.001" // Abuse Elevation Control: Setuid and Setgid
)

// Finding is one signal raised against a process.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Process is one scored process in the report.
type Process struct {
	// startTicks is the kernel's start time for this PID, which is what tells it
	// from a later process that reused the number.
	startTicks uint64

	PID      int       `json:"pid"`
	PPID     int       `json:"ppid,omitempty"`
	Comm     string    `json:"comm"`
	Exe      string    `json:"exe,omitempty"`
	Cmdline  string    `json:"cmdline,omitempty"`
	Score    int       `json:"score"`
	Findings []Finding `json:"findings,omitempty"`
	// StartTicks is the exported kernel start time: it is the only thing that
	// tells this PID from the next process that held the number, so a caller
	// holding evidence recorded earlier (an exec-guard event, say) can check
	// the evidence is still about this process before acting on it.
	StartTicks uint64 `json:"start_ticks,omitempty"`
}

// Result is the whole-scan outcome.
type Result struct {
	Scanned    int       `json:"scanned"`
	Unreadable int       `json:"unreadable"`
	Threshold  int       `json:"threshold"`
	Flagged    []Process `json:"flagged,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
	// KernelRefused and KernelSeen count the guard's events in the window read,
	// including processes that no longer exist.
	KernelRefused int `json:"kernel_refused,omitempty"`
	KernelSeen    int `json:"kernel_seen,omitempty"`
}

// Options configure a scan.
type Options struct {
	Threshold int
	// ProcRoot overrides "/proc" (for tests).
	ProcRoot string
	// Intel, when non-nil, matches process command lines against the abuse-intel
	// feed (a running process talking to a known-bad host).
	Intel *intel.Feed
	// KernelEvents are exec events from the cau-kernel guard, matched to live
	// processes by LoadKernelEvents' caller.
	KernelEvents []KernelEvent
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return DefaultThreshold
}

func (o Options) procRoot() string {
	if o.ProcRoot != "" {
		return o.ProcRoot
	}
	return "/proc"
}

// rawProc is the set of /proc fields detect() scores. Kept separate from the
// reading so detection is a pure, testable function.
type rawProc struct {
	pid        int
	startTicks uint64 // field 22 of /proc/<pid>/stat
	ppid       int
	comm       string
	exeTarget  string // raw readlink of /proc/<pid>/exe ("" if unreadable)
	exeErr     bool
	cmdline    string // argv joined with spaces
	argv0      string
	libs       []string // file-backed pathnames from maps
	preload    string   // LD_PRELOAD from environ
	libpath    string   // LD_LIBRARY_PATH from environ
	tracerPID  int
	anonRWX    int    // anonymous rwx mappings
	stdioPeer  string // the one TCP peer both descriptors are wired to, "" when they are not
	stdioSplit string // the two different peers of stdin and stdout, "" when they agree
	stdin      string // /proc/<pid>/fd/0 target
	stdout     string // /proc/<pid>/fd/1 target
	stdinFIFO  bool   // stdin is a pipe or a named pipe
	pipeRelay  string // the network tool this interpreter's stdout feeds
	hasUID     bool
	ruid       int
	euid       int
	// partial names the fields this process's reads hit a cap on, so the scan
	// can report what was left unread instead of presenting the rest as whole.
	partial map[string]bool
}

// knownSystemNames are process names that attackers impersonate; a process
// advertising one of these whose real exe is in an unexpected place is a strong
// masquerade signal.
var knownSystemNames = map[string]bool{
	"systemd": true, "sshd": true, "cron": true, "crond": true, "init": true,
	"bash": true, "dbus-daemon": true, "rsyslogd": true, "nginx": true,
	"docker": true, "containerd": true, "gnome-shell": true, "Xorg": true,
	// common tools a user watches, whose name a miner/implant likes to borrow:
	"btop": true, "htop": true, "top": true, "ps": true, "sshd:": true,
}

// Scan walks the process table under ProcRoot and returns the flagged processes.
// A read that stopped at one of the byte caps is reported as a warning naming
// the process, so a partial look at a command line is never read as a whole one.
func Scan(opts Options) *Result {
	root := opts.procRoot()
	th := opts.threshold()
	res := &Result{Threshold: th}

	entries, err := os.ReadDir(root)
	if err != nil {
		res.Warnings = append(res.Warnings, "cannot read "+root+": "+err.Error())
		return res
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, perr := strconv.Atoi(e.Name()); perr == nil && pid > 0 {
			pids = append(pids, pid) // anything else is not a pid directory
		}
	}
	if len(pids) > maxProcs {
		pids = pids[:maxProcs]
		res.Warnings = append(res.Warnings, "process cap reached")
	}

	// Every process is read at once: a table is mostly waiting on the kernel, and
	// slots keep the result in directory order whatever finishes first.
	raw := make([]rawProc, len(pids))
	readable := make([]bool, len(pids))
	parallel.For(len(pids), 0, func(i int) { raw[i], readable[i] = readProc(root, pids[i]) })
	procs := make([]rawProc, 0, len(pids))
	partial := map[string]string{}
	for i := range raw {
		if !readable[i] {
			res.Unreadable++
			continue
		}
		res.Scanned++
		procs = append(procs, raw[i])
		for field := range raw[i].partial {
			if _, seen := partial[field]; !seen {
				partial[field] = fieldSample(raw[i], field)
			}
		}
	}
	// A read that stopped at a cap left something unread, and a report that
	// presents what was read as the whole is a coverage gap with no marker on
	// it. Each capped field is named once, with a process it happened to.
	for _, field := range slices.Sorted(maps.Keys(partial)) {
		res.Warnings = append(res.Warnings,
			"partial scan: "+partial[field]+" hit its read cap, so the rest of its "+field+" was not inspected")
	}
	markPipeRelays(root, procs)
	kernel := indexKernelEvents(opts.KernelEvents, res)

	scored := make([]Process, len(procs))
	parallel.For(len(procs), 0, func(i int) {
		rp := procs[i]
		p := detect(rp, th)
		for _, f := range kernel.findings(rp) {
			p.Findings = append(p.Findings, f)
			p.Score += f.Score
		}
		// Abuse-intel feed over the command line (kept out of the pure detect so
		// detect stays feed-free and unit-testable).
		if opts.Intel != nil && rp.cmdline != "" {
			for _, h := range opts.Intel.MatchText(rp.cmdline) {
				f := Finding{Class: "procscan.intel." + string(h.Kind), Score: 8, Technique: techProcInject,
					Detail: "process command line references a known-bad " + string(h.Kind) + " from the abuse-intel feed", Evidence: h.Value}
				p.Findings = append(p.Findings, f)
				p.Score += f.Score
			}
		}
		scored[i] = p
	})
	for _, p := range scored {
		if p.Score >= th {
			res.Flagged = append(res.Flagged, p)
		}
	}
	sort.Slice(res.Flagged, func(i, j int) bool {
		if res.Flagged[i].Score != res.Flagged[j].Score {
			return res.Flagged[i].Score > res.Flagged[j].Score
		}
		return res.Flagged[i].PID < res.Flagged[j].PID
	})
	return res
}

// detect scores one process. Pure function of rp.
// cmdlineFindings runs argv through the package-script and tradecraft
// recognisers. They overlap on purpose, so together they are one piece of
// evidence: the strongest keeps its score and the rest are reported at zero.
// Without that, two recognisers agreeing about the text of `grep "/dev/tcp" note`
// would add up to a confirmed process.
func cmdlineFindings(cmdline string) []Finding {
	if cmdline == "" {
		return nil
	}
	var out []Finding
	for _, f := range linuxpkg.ScanText("cmdline", cmdline) {
		out = append(out, Finding{Class: "procscan.cmdline." + strings.TrimPrefix(f.Class, "linuxpkg.script."),
			Score: f.Score, Technique: f.Technique, Detail: f.Detail, Evidence: f.Evidence})
	}
	for _, f := range tradecraft.Analyze([]byte(cmdline), tradecraft.Options{}).Findings {
		if f.Score >= tradecraft.DefaultThreshold {
			out = append(out, Finding{Class: "procscan.cmdline." + strings.TrimPrefix(f.Class, "tradecraft."),
				Score: f.Score, Technique: f.Technique, Detail: f.Detail, Evidence: trunc(f.Evidence, 160)})
		}
	}
	best := -1
	for i, f := range out {
		if best < 0 || f.Score > out[best].Score {
			best = i
		}
	}
	for i := range out {
		if i != best {
			out[i].Score = 0
		}
	}
	return out
}

// fieldSample names one process whose field hit a read cap, for the warning
// that says the scan was partial.
func fieldSample(rp rawProc, field string) string {
	name := rp.comm
	if name == "" {
		name = "pid " + strconv.Itoa(rp.pid)
	} else {
		name = name + " (pid " + strconv.Itoa(rp.pid) + ")"
	}
	return name + "'s " + field
}

func detect(rp rawProc, th int) Process {
	p := Process{startTicks: rp.startTicks, PID: rp.pid, PPID: rp.ppid, Comm: rp.comm, Cmdline: rp.cmdline}
	p.Exe = rp.exeTarget
	p.StartTicks = rp.startTicks

	var out []Finding

	// 1) Fileless / RAM-only execution.
	if cls, detail := filelessExe(rp.exeTarget, rp.exeErr); cls != "" {
		out = append(out, Finding{Class: cls, Score: 9, Technique: techFileless,
			Detail: detail, Evidence: rp.exeTarget})
	}

	// 2) Name masquerading. The advertised name impersonates a known process but
	// the real exe is deleted/memfd or lives somewhere that name never runs from.
	if cls, score, tech, detail, ev := masquerade(rp); cls != "" {
		out = append(out, Finding{Class: cls, Score: score, Technique: tech, Detail: detail, Evidence: ev})
	}

	// 3) Injected / preloaded libraries.
	for _, lib := range rp.libs {
		if suspiciousLibPath(lib) {
			out = append(out, Finding{Class: "procscan.hook.injected-library", Score: 7, Technique: techPreload,
				Detail:   "a shared object is mapped from a world-writable or self-deleted path (library injection)",
				Evidence: trunc(lib, 160)})
			break
		}
	}
	if p := firstSuspiciousPreload(rp.preload); p != "" {
		out = append(out, Finding{Class: "procscan.hook.ld-preload", Score: 7, Technique: techPreload,
			Detail: "LD_PRELOAD points at a world-writable, hidden, or deleted library", Evidence: trunc(p, 160)})
	} else if rp.preload != "" {
		out = append(out, Finding{Class: "procscan.hook.ld-preload-set", Score: 2, Technique: techPreload,
			Detail: "LD_PRELOAD is set in the process environment", Evidence: trunc(rp.preload, 160)})
	}
	if firstSuspiciousPreload(rp.libpath) != "" {
		out = append(out, Finding{Class: "procscan.hook.ld-library-path", Score: 3, Technique: techPreload,
			Detail: "LD_LIBRARY_PATH includes a world-writable or hidden directory", Evidence: trunc(rp.libpath, 160)})
	}

	// 4) Malicious command line: the package and tradecraft recognisers.
	out = append(out, cmdlineFindings(rp.cmdline)...)

	// 5) A network shell: the wiring, not the argv.
	if rp.stdioPeer != "" && isInterpreter(rp.comm) {
		out = append(out, Finding{Class: "procscan.netshell.socket-stdio", Score: 9, Technique: techUnixShell,
			Detail:   "an interpreter's stdin and stdout are a live TCP connection (reverse or bind shell)",
			Evidence: "peer " + rp.stdioPeer})
	}
	// The same two descriptors on two different peers: reported, because it is
	// the shape a multiplexer or a harness leaves, and never conclusive, because
	// a shell answered to somewhere it was not driven from is an ordinary
	// process. Nothing may be stopped on this alone.
	if rp.stdioSplit != "" {
		out = append(out, Finding{Class: "procscan.netshell.stdio-split", Score: 2, Technique: techUnixShell,
			Detail:   "an interpreter's stdin and stdout are live TCP connections to two different peers, not one shared connection",
			Evidence: rp.stdioSplit})
	}

	if rp.pipeRelay != "" {
		out = append(out, Finding{Class: "procscan.netshell.pipe-relay", Score: 9, Technique: techUnixShell,
			Detail:   "an interpreter's output feeds a network tool through a pipe while its input is also piped (a relayed shell)",
			Evidence: rp.pipeRelay})
	}
	if rp.hasUID && rp.ruid != rp.euid && isInterpreter(rp.comm) {
		out = append(out, Finding{Class: "procscan.privesc.setuid-shell", Score: 9, Technique: techSetuid,
			Detail:   "an interpreter runs with an effective uid other than its real uid: nothing legitimate runs a set-uid shell",
			Evidence: "ruid=" + strconv.Itoa(rp.ruid) + " euid=" + strconv.Itoa(rp.euid)})
	}

	// 6) Anonymous executable memory. Context only: node, KDE and other JIT
	// users carry these on a clean host (measured), so it can only corroborate.
	if rp.anonRWX > 0 {
		out = append(out, Finding{Class: "procscan.inject.anon-rwx", Score: 2, Technique: techProcInject,
			Detail:   "anonymous memory that is writable and executable (JIT runtimes do this; so does injected shellcode)",
			Evidence: strconv.Itoa(rp.anonRWX) + " mapping(s)"})
	}

	// 7) Being traced — context, low weight on its own.
	if rp.tracerPID > 0 {
		out = append(out, Finding{Class: "procscan.inject.traced", Score: 2, Technique: techPtrace,
			Detail: "process is being ptrace-attached by another process", Evidence: "TracerPid=" + strconv.Itoa(rp.tracerPID)})
	}

	for _, f := range out {
		p.Score += f.Score
	}
	p.Findings = out
	return p
}

// filelessExe classifies an exe symlink target as fileless execution.
func filelessExe(target string, exeErr bool) (class, detail string) {
	switch {
	case strings.HasPrefix(target, "/memfd:"), strings.HasPrefix(target, "memfd:"), strings.Contains(target, "/memfd:"):
		return "procscan.fileless.memfd", "process executes from an anonymous in-memory file (memfd) — no on-disk binary"
	case strings.HasSuffix(target, " (deleted)"):
		return "procscan.fileless.deleted", "the backing executable has been deleted from disk while the process keeps running"
	case strings.HasPrefix(target, "/dev/shm/"), strings.HasPrefix(target, "/run/shm/"):
		return "procscan.fileless.tmpfs", "process executes from tmpfs shared memory (/dev/shm) rather than a normal binary"
	}
	return "", ""
}

// masquerade scores a mismatch between the advertised name and the real exe.
func masquerade(rp rawProc) (class string, score int, technique, detail, evidence string) {
	name := rp.comm
	if name == "" {
		name = baseName(rp.argv0)
	}
	if name == "" || rp.exeTarget == "" {
		return "", 0, "", "", ""
	}
	exeBase := baseName(strings.TrimSuffix(rp.exeTarget, " (deleted)"))

	// A kernel-thread-looking name ([kworker/…]) with a real userspace exe is a
	// classic hider.
	if strings.HasPrefix(rp.comm, "[") && strings.HasSuffix(rp.comm, "]") &&
		rp.exeTarget != "" && !rp.exeErr && !strings.HasSuffix(rp.exeTarget, " (deleted)") {
		return "procscan.masquerade.kthread", 8, techMasqProc,
			"a process styled as a kernel thread (" + rp.comm + ") has a real userspace executable (" + exeBase + ")",
			rp.comm + " -> " + rp.exeTarget
	}

	if !knownSystemNames[name] {
		return "", 0, "", "", ""
	}
	// The name impersonates a known process. Flag when the exe is fileless, or
	// its path is not a system location.
	if rp.exeErr || strings.HasSuffix(rp.exeTarget, " (deleted)") || strings.HasPrefix(rp.exeTarget, "/memfd") {
		return "procscan.masquerade.fileless-name", 8, techMasqName,
			"process advertises the name " + name + " but has no normal on-disk binary", name + " -> " + rp.exeTarget
	}
	if !systemExePath(rp.exeTarget) && (suspiciousPath(rp.exeTarget) || exeBase != name) {
		return "procscan.masquerade.name-location", 8, techMasqName,
			"process advertises the name " + name + " but its executable is " + rp.exeTarget + " (not a system path)", name + " -> " + rp.exeTarget
	}
	return "", 0, "", "", ""
}

// systemExePath reports whether a path is a normal location for a system binary.
func systemExePath(p string) bool {
	for _, pre := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/opt/", "/snap/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// suspiciousLibPath reports whether a MAPPED shared object looks injected. It is
// stricter than suspiciousPath to avoid the many benign maps a real process has:
// anonymous memfd IPC segments (browsers, systemd), and ordinary data files in a
// user's hidden config dir (browser extensions, caches) are not flagged. The
// signal is a real .so loaded from a world-writable location, or a shared object
// that has unlinked itself from disk while mapped (but not a memfd).
func suspiciousLibPath(p string) bool {
	if strings.Contains(p, "/memfd:") || strings.HasPrefix(p, "memfd:") {
		return false
	}
	base := strings.TrimSuffix(p, " (deleted)")
	isLib := strings.Contains(base, ".so")
	for _, pre := range []string{"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"} {
		if strings.HasPrefix(base, pre) && (isLib || strings.HasSuffix(p, " (deleted)")) {
			return true
		}
	}
	return isLib && strings.HasSuffix(p, " (deleted)")
}

// suspiciousPath reports whether a file path is somewhere a legitimately-shipped
// library would not live.
func suspiciousPath(p string) bool {
	base := strings.TrimSuffix(p, " (deleted)")
	if strings.HasSuffix(p, " (deleted)") {
		return true
	}
	for _, pre := range []string{"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"} {
		if strings.HasPrefix(base, pre) {
			return true
		}
	}
	// a hidden directory or file component anywhere in the path
	return strings.Contains(base, "/.")
}

// firstSuspiciousPreload returns the first colon/space-separated entry of an
// LD_PRELOAD/LD_LIBRARY_PATH value that looks suspicious, or "".
func firstSuspiciousPreload(v string) string {
	if v == "" {
		return ""
	}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' }) {
		if suspiciousPath(f) {
			return f
		}
	}
	return ""
}

func baseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

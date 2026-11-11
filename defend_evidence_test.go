package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/netblock"
	"github.com/1ungaka/sentinel-edr/internal/procscan"
)

// A rewrite that keeps the size and restores the mtime is what `touch -r` does.
// Nothing may be able to swap a scanned file's contents and keep the old verdict.
func TestRewriteKeepingSizeAndMtimeIsRescanned(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.dir, "looks-clean")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", len(fixtureShell))), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(p, p)
	if f.d.files[p].hit {
		t.Fatal("the fixture must start clean")
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(p, p)
	if !f.d.files[p].hit {
		t.Fatal("the payload kept the old clean verdict: size and mtime are both forgeable")
	}
}

// deletedImplant is a running process whose binary has been unlinked: the bytes
// exist only behind /proc/<pid>/exe, and a cron line still names the path.
func (f *fixture) deletedImplant(t *testing.T) (path string, pid int) {
	t.Helper()
	c := child(t)
	path = filepath.Join(f.dir, "gone")
	// A real /proc reports "<path> (deleted)" and still reads the bytes. A file of
	// that name gives the fixture /proc the same behaviour.
	if err := os.WriteFile(path+" (deleted)", []byte(fixtureShell), 0o755); err != nil {
		t.Fatal(err)
	}
	f.addProc(t, c.Process.Pid, "bash", path+" (deleted)", "bash", "socket:[777]")
	f.cron(t, path)
	return path, c.Process.Pid
}

// A path missing from disk says nothing about the bytes a live process is running.
func TestPersistenceDoesNotEraseADeletedBinarysVerdict(t *testing.T) {
	f := newFixture(t)
	path, _ := f.deletedImplant(t)
	for range 5 {
		f.d.cycle()
		if _, hit := f.d.hits[runningPrefix+path]; !hit {
			t.Fatal("the verdict on the running binary was erased")
		}
	}
}

// A new hit wakes the other layers, so anything that clears and re-raises a hit
// becomes a loop. The interval here is an hour: every pass beyond a handful was
// caused by the daemon waking itself.
func TestDeletedBinaryDoesNotSpinTheDaemon(t *testing.T) {
	f := newFixture(t)
	f.deletedImplant(t)
	var passes atomic.Int64
	// An event log that can't be read warns once per process pass, which makes a
	// pass countable. A missing one would not: that is a host with no guard.
	f.d.kernelEvents = f.dir
	f.d.warn = func(string, ...interface{}) { passes.Add(1) }
	f.startDaemon(t, t.TempDir())
	time.Sleep(500 * time.Millisecond)
	n := passes.Load()
	if n == 0 {
		t.Fatal("no pass was counted, so this test proved nothing")
	}
	if n > 6 {
		t.Fatalf("%d process passes in 500 ms with an hourly interval: the layers are waking each other", n)
	}
}

// join marks an incident raised before anything is done about it, so a response
// that panics must not take the report with it, nor what the other steps did.
func TestPanickingResponseStillReportsTheIncident(t *testing.T) {
	f := newFixture(t)
	impl := f.implant(t)
	c := child(t)
	f.d.quarantine, f.d.action = true, procscan.ActionStop
	inc := correlate.Incident{ID: "abc", Confirmed: true, Why: "test", Signals: []correlate.Signal{
		{Layer: correlate.LayerFile, Files: []string{impl}},
		{Layer: correlate.LayerProcess, PID: c.Process.Pid, Live: true},
	}}
	f.addProc(t, c.Process.Pid, "sleep", "/usr/bin/sleep", "sleep 60", "")
	ps := procscan.Scan(procscan.Options{ProcRoot: f.proc})
	ps.Flagged = []procscan.Process{{PID: c.Process.Pid, Comm: "sleep", Score: 9}}
	f.d.queue = nil // quarantineFile's follow-up on the queue is the step that panics

	f.d.act([]correlate.Incident{inc}, ps, false)
	out := f.out.String()
	if !strings.Contains(out, `"id":"abc"`) {
		t.Fatalf("the incident was lost when its response panicked: %q", out)
	}
	if !strings.Contains(out, "response step crashed") {
		t.Fatalf("the crash must be part of the report: %q", out)
	}
	if !strings.Contains(out, "defend.crash.response") {
		t.Fatalf("the crash must raise its own alert: %q", out)
	}
}

// A panic outside any one step still reports what was found.
func TestIncidentIsReportedInOrderEvenIfActingPanics(t *testing.T) {
	f := newFixture(t)
	f.d.acting = stripes{}
	var nilMap *fileQueue
	f.d.queue = nilMap
	func() {
		defer func() { _ = recover() }()
		f.d.act([]correlate.Incident{{ID: "first"}, {ID: "second"}}, nil, true)
	}()
	first, second := strings.Index(f.out.String(), `"first"`), strings.Index(f.out.String(), `"second"`)
	if first < 0 || second < first {
		t.Fatalf("got %q", f.out.String())
	}
}

// Once the process is gone so are the bytes, and the verdict goes with them. The
// flagged file on disk is a different thing and stays remembered.
func TestRunningVerdictLeavesWithTheProcess(t *testing.T) {
	f := newFixture(t)
	path, _ := f.deletedImplant(t)
	f.d.cycle()
	if _, ok := f.d.hits[runningPrefix+path]; !ok {
		t.Fatal("the running binary must be flagged")
	}
	if err := os.RemoveAll(f.proc); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.proc, 0o755); err != nil {
		t.Fatal(err)
	}
	f.d.cycle()
	if _, ok := f.d.hits[runningPrefix+path]; ok {
		t.Fatal("the process exited: its bytes are no longer evidence")
	}
}

// The file on disk and the bytes running from it are two verdicts: a clean file
// put back over a running implant must clear neither the wrong one nor both.
func TestCleanFileOverARunningImplantKeepsTheRunningVerdict(t *testing.T) {
	f := newFixture(t)
	path, _ := f.deletedImplant(t)
	if err := os.WriteFile(path, []byte("harmless\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		f.d.cycle()
	}
	if f.d.files[path].hit {
		t.Fatal("the file on disk is clean")
	}
	if _, ok := f.d.hits[runningPrefix+path]; !ok {
		t.Fatal("the process is still running the implant")
	}
}

// A file and the process running it agreeing is one opinion. Counted twice it
// would inflate the score and change the fingerprint with no new evidence.
func TestSameVerdictTwiceIsOneSignal(t *testing.T) {
	f := newFixture(t)
	impl := f.implant(t)
	sig := correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Score: 8, Files: []string{impl}}
	f.d.hits[impl], f.d.hits[runningPrefix+impl] = sig, sig
	fresh, _ := f.d.join()
	if len(fresh) != 1 || fresh[0].Score != 8 {
		t.Fatalf("got %+v", fresh)
	}
}

// The file was scanned in the same instant it was written, so a second write can
// carry the same timestamp. The stamp must not be trusted until time has passed.
func TestFileChangedJustBeforeItsScanIsRescannedOnTheNextEvent(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.dir, "fresh")
	if err := os.WriteFile(p, []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(p, p)
	if !f.d.files[p].racy {
		t.Skip("the scan landed outside the window on this machine")
	}
	e := f.d.files[p]
	e.hit, e.signal = true, correlate.Signal{Layer: correlate.LayerFile, Class: "marker", Files: []string{p}}
	f.d.files[p] = e
	f.d.scanFile(p, p)
	if f.d.files[p].hit {
		t.Fatal("a racy stamp must not be taken as proof of no change")
	}
}

// A chmod arms a dropped file, and the docs promise it is looked at again.
func TestChmodIsScannedAgain(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.dir, "dropper")
	if err := os.WriteFile(p, []byte("clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(p, p)
	before := f.d.files[p].stamp
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	f.d.scanFile(p, p)
	if f.d.files[p].stamp == before {
		t.Fatal("a chmod must count as a new version of the file")
	}
}

// Blocks run concurrently now, against each other and against Expire.
func TestConcurrentBlocksAreSafe(t *testing.T) {
	b, err := netblock.Open(netblock.Options{DryRun: true})
	if err != nil {
		t.Skipf("no firewall backend: %v", err)
	}
	var started atomic.Int32
	done := make(chan struct{})
	for i := range 32 {
		go func() {
			defer func() { done <- struct{}{} }()
			started.Add(1)
			_, _ = b.Block("198.51.100."+strconv.Itoa(i+1), fmt.Sprint("incident ", i))
			_, _ = b.Expire()
		}()
	}
	for range 32 {
		<-done
	}
	if len(b.Commands()) == 0 {
		t.Fatal("a dry run must record what it would do")
	}
}

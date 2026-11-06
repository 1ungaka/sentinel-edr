package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/procscan"
	"github.com/s-b-repo/cau/internal/quarantine"
)

// A file back at a quarantined path is a new attack, and the fingerprint of the old
// incident must not silence it.
func TestReDroppedFileIsRaisedAndActedOnAgain(t *testing.T) {
	f := newFixture(t)
	f.d.quarantine = true
	impl := f.implant(t)
	f.cron(t, impl)
	f.d.enqueue(impl)
	if got := f.d.cycle(); len(got) == 0 || !got[0].Confirmed {
		t.Fatalf("the first drop must confirm: %+v", got)
	}
	if _, err := os.Stat(impl); !os.IsNotExist(err) {
		t.Fatalf("the first drop must be quarantined: %v", err)
	}
	f.d.cycle() // the join that sees it gone
	if err := os.WriteFile(impl, []byte(fixtureShell), 0o755); err != nil {
		t.Fatal(err)
	}
	f.d.enqueue(impl)
	f.d.cycle()
	if _, err := os.Stat(impl); !os.IsNotExist(err) {
		t.Fatalf("the second drop sat there untouched: %v\n%s", err, f.out.String())
	}
	s, err := quarantine.Open(f.store)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := s.List(); len(entries) != 2 {
		t.Fatalf("vault holds %d entries, want both drops", len(entries))
	}
}

// The log outlives processes and PIDs are reused, so a refusal from last week must
// not stop whatever holds that PID now.
func TestOldRefusalDoesNotStopWhoeverHasThePIDNow(t *testing.T) {
	f := newFixture(t)
	c := child(t)
	f.addProc(t, c.Process.Pid, "grep", "/usr/bin/grep", `grep /dev/tcp/192.0.2.1/443 notes.txt`, "")
	log := filepath.Join(f.dir, "kernel.jsonl")
	line := fmt.Sprintf(`{"pid":%d,"tgid":%d,"uid":33,"reason":"netshell","denied":true,"peer":"192.0.2.1:443","comm":"php","exe":"sh"}`+"\n", c.Process.Pid, c.Process.Pid)
	if err := os.WriteFile(log, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	f.d.kernelEvents, f.d.action = log, procscan.ActionKill
	for _, inc := range f.d.cycle() {
		if p := correlate.PlanFor(inc); len(p.Stop) != 0 {
			t.Fatalf("a stale refusal planned a stop: %+v", inc)
		}
	}
	// The check above is the deterministic one: no stop was planned, so none
	// could have been carried out. This second check is belt and braces on the
	// real process, and it needs a settle to be worth anything.
	//
	// kill(2) returns when a signal is queued, not when the target has acted on
	// it. Measured here against a busy-looping target, with no fork between the
	// kill and the read: 379 of 400 immediate reads of /proc/<pid>/stat after a
	// SIGSTOP still reported the old state, and 0 of 400 did after 200 ms.
	// Reading at once would therefore miss a signal that really was sent, and
	// this is the expensive assertion to get wrong, because it is the one
	// saying nothing was signalled that should not have been. Note that a
	// harness which shells out to read the state hides the race, because the
	// fork is itself a settle.
	time.Sleep(200 * time.Millisecond)
	if s := state(t, c.Process.Pid); s == "T" || s == "Z" {
		t.Fatalf("an innocent process was signalled: state %s", s)
	}
}

func refusal(i int) procscan.KernelEvent {
	return procscan.KernelEvent{TGID: 1000 + i, Reason: "netshell", Denied: true, Comm: "php", Exe: "sh", Peer: "192.0.2.1:443"}
}

// Past the 4 MiB window the event count stops growing, and a count of lines already
// read then says there is nothing new.
func TestRefusalsKeepBeingReportedPastTheLogWindow(t *testing.T) {
	f := newFixture(t)
	window := make([]procscan.KernelEvent, 100)
	for i := range window {
		window[i] = refusal(i)
	}
	if n := len(f.d.kernelRefusals(window)); n != 100 {
		t.Fatalf("got %d", n)
	}
	moved := append([]procscan.KernelEvent(nil), window[10:]...)
	for i := range 10 {
		moved = append(moved, refusal(500+i))
	}
	if n := len(f.d.kernelRefusals(moved)); n != 10 {
		t.Fatalf("the window moved by 10 new refusals, %d reported", n)
	}
	if n := len(f.d.kernelRefusals(moved)); n != 0 {
		t.Fatalf("%d reported again from an unchanged log", n)
	}
}

// A verdict on the bytes a process runs says nothing about the file at that path
// now. Moving a clean file there must not get it quarantined.
func TestCleanFileAtARunningImplantsPathIsNotQuarantined(t *testing.T) {
	f := newFixture(t)
	path, _ := f.deletedImplant(t)
	if err := os.WriteFile(path, []byte("harmless\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.quarantine = true
	f.d.cycle()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a clean file was quarantined for what the process runs: %v\n%s", err, f.out.String())
	}
}

// A sparse file costs its creator nothing and takes days to hash.
func TestSparseFileCannotHoldAScanSlot(t *testing.T) {
	f := newFixture(t)
	p := filepath.Join(f.dir, "sparse")
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(1 << 42); err != nil {
		fh.Close()
		t.Skipf("no sparse files here: %v", err)
	}
	fh.Close()
	for range cap(f.d.slots) { // every slot taken: only a scan that needs none can finish
		f.d.slots <- struct{}{}
	}
	defer func() {
		for range cap(f.d.slots) {
			<-f.d.slots
		}
	}()
	done := make(chan struct{})
	go func() {
		f.d.scanFile(p, p)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a sparse file is being hashed")
	}
	if !f.d.files[p].hit {
		t.Fatal("a file too large to read must be reported, not silently passed")
	}
}

// Two inodes can answer to one path. A clean decoy must not wipe the verdict on the
// implant, or the two flip for ever.
func TestRunningVerdictOnlyGetsStronger(t *testing.T) {
	f := newFixture(t)
	bad, good := filepath.Join(f.dir, "bad"), filepath.Join(f.dir, "good")
	_ = os.WriteFile(bad, []byte(fixtureShell), 0o755)
	_ = os.WriteFile(good, []byte("harmless\n"), 0o755)
	name := filepath.Join(f.dir, "x")
	f.d.scanFile(name, bad)
	f.d.scanFile(name, good)
	if _, ok := f.d.hits[runningPrefix+name]; !ok {
		t.Fatal("a clean decoy erased the verdict on the implant")
	}
}

// A confirmed stop that can't be carried out must say so.
func TestUnmatchedStopIsReported(t *testing.T) {
	f := newFixture(t)
	f.d.action = procscan.ActionStop
	inc := correlate.Incident{ID: "abc", Confirmed: true, Signals: []correlate.Signal{{Layer: correlate.LayerNetwork, PID: 4242, Definitive: true}}}
	got := strings.Join(f.d.respond(inc, &procscan.Result{}), "\n")
	if !strings.Contains(got, strconv.Itoa(4242)) {
		t.Fatalf("a planned stop vanished: %q", got)
	}
}

// Without a watcher the sweep is the only thing that finds files.
func TestSweepRunsOnAnIntervalWithoutAWatcher(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.sweepEvery = 20 * time.Millisecond
	drop := t.TempDir()
	f.d.roots = []string{drop}
	out := &syncWriter{}
	f.d.out = out
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	defer func() { close(stop); <-done }()
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(drop, "s.php"), []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the sweep to find the file", func() bool {
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var v struct{ Incident correlate.Incident }
			if json.Unmarshal([]byte(line), &v) == nil && len(v.Incident.Files) > 0 {
				return true
			}
		}
		return false
	})
}

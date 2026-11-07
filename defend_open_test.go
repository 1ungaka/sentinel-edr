package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
)

// A response that failed is unfinished business: the implant is still there. It has
// to be tried again, a bounded number of times, and each outcome reported.
func TestFailedResponseIsRetried(t *testing.T) {
	f := newFixture(t)
	f.d.quarantine = true
	f.d.retryBase = time.Millisecond
	impl := f.implant(t)
	f.cron(t, impl)
	// A file where the vault's directory should be, so the first attempts fail.
	if err := os.WriteFile(f.store, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.d.enqueue(impl)
	if got := f.d.cycle(); len(got) == 0 {
		t.Fatal("nothing raised")
	}
	if !strings.Contains(f.out.String(), "quarantine failed") {
		t.Fatalf("the failure must be reported: %s", f.out.String())
	}
	if err := os.Remove(f.store); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the retry to finish the job", func() bool {
		f.d.mu.Lock()
		retried := !f.d.seen[anyFingerprint(f.d)]
		f.d.mu.Unlock()
		if retried {
			f.d.cycle()
		}
		_, err := os.Stat(impl)
		return os.IsNotExist(err)
	})
}

func anyFingerprint(d *defender) string {
	for fp := range d.retries {
		return fp
	}
	return ""
}

// The retry is bounded: a vault that never comes back must not loop for ever.
func TestRetriesRunOut(t *testing.T) {
	f := newFixture(t)
	f.d.retryBase = time.Hour
	inc := correlate.Incident{ID: "x", Signals: []correlate.Signal{{Layer: correlate.LayerFile, Class: "file.malicious"}}}
	for range defendResponseRetries + 5 {
		f.d.retryLater(inc)
	}
	if n := f.d.retries[inc.Fingerprint()]; n != defendResponseRetries {
		t.Fatalf("%d retries scheduled, want %d", n, defendResponseRetries)
	}
}

type stalled struct{ release chan struct{} }

func (s *stalled) Write(p []byte) (int, error) {
	<-s.release
	return len(p), nil
}

// A consumer that stops reading must cost it the alerts it isn't reading, and
// nothing else: detection carries on, and the daemon can still be stopped.
func TestStalledOutputHoldsUpNothing(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	out := &stalled{release: make(chan struct{})}
	defer close(out.release)
	f.d.out = out
	f.d.flushWait = 100 * time.Millisecond
	drop := t.TempDir()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	for i := range 3 {
		p := filepath.Join(drop, fmt.Sprintf("s%d.php", i))
		if err := os.WriteFile(p, []byte(fixtureShell), 0o644); err != nil {
			t.Fatal(err)
		}
		f.d.enqueue(p)
	}
	waitFor(t, "correlation to keep going", func() bool {
		f.d.mu.Lock()
		defer f.d.mu.Unlock()
		return len(f.d.seen) >= 3
	})
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled stdout hung the shutdown")
	}
}

// Everything still written is written, in full, before the daemon exits.
func TestShutdownFlushesWhatIsQueued(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	out := &syncWriter{}
	f.d.out = out
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	p := filepath.Join(t.TempDir(), "s.php")
	if err := os.WriteFile(p, []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.enqueue(p)
	waitFor(t, "the incident", func() bool {
		f.d.mu.Lock()
		defer f.d.mu.Unlock()
		return len(f.d.seen) >= 1
	})
	close(stop)
	<-done
	if len(out.incidents(t)) != 1 {
		t.Fatalf("got %q", out.String())
	}
}

// Past the cap the memory of what was raised must not be wiped whole, or every live
// incident is raised again at once.
func TestFullSeenSetDoesNotReRaiseEverything(t *testing.T) {
	f := newFixture(t)
	f.d.persistence, f.d.process = false, false
	a, b := filepath.Join(f.dir, "a"), filepath.Join(f.dir, "b")
	f.d.hits[a] = correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Score: 8, Files: []string{a}}
	if got, _ := f.d.join(); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	for i := range defendMaxSeen {
		f.d.seen[fmt.Sprint("filler", i)] = true
	}
	f.d.hits[b] = correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Score: 8, Files: []string{b}}
	if got, _ := f.d.join(); len(got) != 1 {
		t.Fatalf("only the new file is news: %+v", got)
	}
	if got, _ := f.d.join(); len(got) != 0 {
		t.Fatalf("a live incident was raised again: %+v", got)
	}
}

// Flagged files can be made faster than they are looked at, so the evidence memory
// has a ceiling too, and a new hit still gets in.
func TestEvidenceMemoryIsBounded(t *testing.T) {
	f := newFixture(t)
	for i := range defendMaxFiles {
		k := fmt.Sprint("/tmp/f", i)
		sig := correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Files: []string{k}}
		f.d.hits[k], f.d.files[k] = sig, fileEntry{hit: true, signal: sig}
	}
	sig := correlate.Signal{Layer: correlate.LayerFile, Class: "file.suspicious", Files: []string{"/tmp/new"}}
	f.d.record("/tmp/new", fileEntry{hit: true, signal: sig})
	if len(f.d.hits) > defendMaxFiles {
		t.Fatalf("%d hits held, ceiling is %d", len(f.d.hits), defendMaxFiles)
	}
	if _, ok := f.d.hits["/tmp/new"]; !ok {
		t.Fatal("the newest hit is the one that must not be lost")
	}
}

// A scan can't be interrupted, so a stop must not wait for one for ever.
func TestStopDoesNotWaitForAStuckScan(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.stopWait = 50 * time.Millisecond
	f.d.out = &syncWriter{}
	for range cap(f.d.slots) { // a worker asking for a slot is a scan that won't finish
		f.d.slots <- struct{}{}
	}
	defer func() {
		for range cap(f.d.slots) {
			<-f.d.slots
		}
	}()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	p := filepath.Join(t.TempDir(), "stuck.php")
	if err := os.WriteFile(p, []byte(fixtureShell), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.enqueue(p)
	// A fixed sleep can lose to a loaded machine, and then nothing is stuck yet.
	waitFor(t, "a worker to be stuck on the file", func() bool {
		f.d.queue.mu.Lock()
		defer f.d.queue.mu.Unlock()
		return f.d.queue.busy[p]
	})
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stuck scan held up the stop")
	}
	if !f.d.abandoned.Load() {
		t.Fatal("the engine must be left open for a scan still using it")
	}
}

// An abandoned scan can report after the writer has gone, which must be harmless.
func TestReportAfterShutdownDoesNotPanic(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.out = &syncWriter{}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	close(stop)
	<-done
	f.d.emit(correlate.Incident{ID: "late"}, nil)
}

// A response is seen through: a half-done one is worse than a late exit.
func TestStopWaitsForResponses(t *testing.T) {
	f := newFixture(t)
	f.d.process, f.d.persistence = false, false
	f.d.stopWait = time.Millisecond
	f.d.blockExe = true
	began, marker := filepath.Join(f.dir, "began"), filepath.Join(f.dir, "finished")
	helper := filepath.Join(f.dir, "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ntouch "+began+"\nsleep 0.3\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.d.kernelBin = helper
	impl := f.implant(t)
	f.d.out = &syncWriter{}
	f.d.publish(viewPersistence, []correlate.Signal{{Layer: correlate.LayerPersistence, Class: "persist.cron.x", Score: 8, Files: []string{"/etc/cron.d/j", impl}}})
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { f.d.run(nil, time.Hour, stop, func(string, ...interface{}) {}); close(done) }()
	f.d.enqueue(impl)
	// Only a response under way proves anything. An incident having been raised
	// doesn't: the persistence signal alone raises an alert with nothing to do.
	waitFor(t, "a response to begin", func() bool {
		_, err := os.Stat(began)
		return err == nil
	})
	close(stop)
	<-done
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("exited with a response half done: %v", err)
	}
}

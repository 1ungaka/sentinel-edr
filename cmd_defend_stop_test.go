package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/procscan"
)

// TestStopsAProcessOnlyTheNetworkLayerFound: the case this whole layer exists
// for is a payload with no file on disk holding a command-and-control
// connection — and such a process can score below procscan's own threshold and
// never appear in its Result. The stop was planned and reported before this,
// but never carried out.
func TestStopsAProcessOnlyTheNetworkLayerFound(t *testing.T) {
	f := newNetFixture(t)
	f.d.action = procscan.ActionStop
	f.d.procRoot = "/proc" // Lookup and the identity re-read need the real one

	// A real process to act on, started by the test and cleaned up by it.
	victim := exec.Command("sleep", "60")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	pid := victim.Process.Pid
	t.Cleanup(func() { _ = victim.Process.Kill(); _ = victim.Wait() })

	// An incident the network layer confirms on its own: live state, so
	// correlate licenses a stop. The process scan never saw it (ps is nil).
	inc := correlate.Build([]correlate.Signal{{
		Layer: correlate.LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Live: true,
		Detail: "a memfd binary holding a connection", Peers: []string{"203.0.113.9"}, PID: pid,
	}})[0]
	if !inc.Confirmed {
		t.Fatalf("fixture is wrong, incident not confirmed: %s", inc.Why)
	}
	if plan := correlate.PlanFor(inc); len(plan.Stop) != 1 || plan.Stop[0] != pid {
		t.Fatalf("plan.Stop = %v, want the holder of the socket", plan.Stop)
	}

	actions := f.d.respond(inc, nil)
	joined := strings.Join(actions, "; ")
	if strings.Contains(joined, "not stopped") || strings.Contains(joined, "was not flagged") {
		t.Fatalf("the stop was reported but not carried out: %s", joined)
	}
	if !strings.Contains(joined, "stop pid") {
		t.Fatalf("actions = %q, want the stop recorded", joined)
	}
	waitState(t, pid, "T")
	// Leave it running for the cleanup to kill.
	_ = exec.Command("kill", "-CONT", strconv.Itoa(pid)).Run()
}

// A PID that has exited between detection and response is reported as gone,
// not signalled and not silently dropped.
// waitState waits for a process to reach a state, because signal delivery is
// not synchronous with kill(2) returning: the signal is queued and the target
// has to be scheduled to act on it. Measured on this host, a busy-looping
// target was still not in T on 369 of 400 immediate reads, and under parallel
// test load a sleeping one loses the same race — which is how this test failed
// once in a full-suite run and passed three times in isolation. An independent
// run put it at 379 of 400, and at 0 of 400 after a 200 ms settle.
//
// If you reproduce that, do it in-process with no fork between the kill and the
// read: a harness that shells out to read /proc/<pid>/stat reports no misses at
// all, because forking is itself a settle, and it hides exactly the race it is
// measuring.
//
// It asserts the state rather than tolerating either, so the test still proves
// the process was really stopped.
func waitState(t *testing.T, pid int, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for state(t, pid) != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s := state(t, pid); s != want {
		t.Fatalf("process state %q, want %q after waiting 2s", s, want)
	}
}

func TestAVanishedProcessIsReportedNotSignalled(t *testing.T) {
	f := newNetFixture(t)
	f.d.action = procscan.ActionStop
	f.d.procRoot = "/proc"

	victim := exec.Command("sleep", "0.01")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	pid := victim.Process.Pid
	_ = victim.Wait() // it is gone before the response runs

	inc := correlate.Build([]correlate.Signal{{
		Layer: correlate.LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Live: true,
		Detail: "gone by now", Peers: []string{"203.0.113.9"}, PID: pid,
	}})[0]
	actions := strings.Join(f.d.respond(inc, nil), "; ")
	if !strings.Contains(actions, "gone") {
		t.Errorf("actions = %q, want it said plainly that the process had exited", actions)
	}
}

// Lookup must not become a way around the guards: it refuses PID 1 outright,
// and the Score it returns is 0 so Confirmed still says no on its own.
func TestLookupDoesNotWeakenTheGuards(t *testing.T) {
	if _, ok := procscan.Lookup("/proc", 1); ok {
		t.Error("Lookup returned PID 1, which must never be a response target")
	}
	if _, ok := procscan.Lookup("/proc", 0); ok {
		t.Error("Lookup returned PID 0")
	}
	p, ok := procscan.Lookup("/proc", 999999999)
	if ok {
		t.Errorf("Lookup invented a process: %+v", p)
	}
	self, ok := procscan.Lookup("/proc", 2)
	if ok && self.Score != 0 {
		t.Errorf("Lookup returned Score %d; the caller must state its own grounds", self.Score)
	}
	if ok && procscan.Confirmed(self, 0) {
		t.Error("a looked-up process with no findings must not be Confirmed on its own")
	}
}

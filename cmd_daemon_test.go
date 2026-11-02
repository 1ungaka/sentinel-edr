package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestScanLoopRunsImmediatelyAndStops verifies the daemon core: it scans once
// right away, repeats on the interval, and returns promptly when stopped.
func TestScanLoopRunsImmediatelyAndStops(t *testing.T) {
	var count atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		scanLoop(10*time.Millisecond, func() { count.Add(1) }, stop)
		close(done)
	}()

	// The immediate cycle must have run essentially at once.
	time.Sleep(5 * time.Millisecond)
	if count.Load() < 1 {
		t.Fatal("scanLoop did not run the immediate cycle")
	}

	// Let a few ticks accumulate, then stop.
	time.Sleep(45 * time.Millisecond)
	close(stop)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanLoop did not return after stop was closed")
	}

	n := count.Load()
	if n < 2 {
		t.Errorf("expected multiple cycles (immediate + ticks), got %d", n)
	}
}

// TestRunCycleRecoversPanic confirms the per-cycle panic barrier: a cycle that
// panics is caught, reported as crashed, and control returns normally.
func TestRunCycleRecoversPanic(t *testing.T) {
	var logged bool
	status := func(string, ...interface{}) { logged = true }

	// A clean cycle: no crash, no log.
	if crashed := runCycle(func() {}, status); crashed {
		t.Error("clean cycle reported as crashed")
	}
	if logged {
		t.Error("clean cycle logged a crash")
	}

	// A panicking cycle: recovered, reported, and runCycle still returns.
	logged = false
	crashed := runCycle(func() { panic("boom") }, status)
	if !crashed {
		t.Error("panicking cycle not reported as crashed")
	}
	if !logged {
		t.Error("panicking cycle did not log")
	}
}

// TestScanLoopSurvivesCrashingCycle is the integration proof of daemon crash
// auto-recovery: when the work panics every time, the loop (running guarded
// cycles) keeps ticking and attempting work rather than dying on the first
// panic, exactly as runScanDaemon wires it.
func TestScanLoopSurvivesCrashingCycle(t *testing.T) {
	var attempts, recovered atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})

	guarded := func() {
		if runCycle(func() {
			attempts.Add(1)
			panic("every cycle fails")
		}, func(string, ...interface{}) {}) {
			recovered.Add(1)
		}
	}
	go func() {
		scanLoop(10*time.Millisecond, guarded, stop)
		close(done)
	}()

	time.Sleep(55 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanLoop died on a panicking cycle instead of recovering")
	}

	if a := attempts.Load(); a < 2 {
		t.Errorf("loop stopped attempting after a crash: %d attempt(s), want multiple", a)
	}
	if recovered.Load() != attempts.Load() {
		t.Errorf("recovered=%d != attempts=%d (a panic escaped the barrier)", recovered.Load(), attempts.Load())
	}
}

func TestScanLoopStopsBeforeFirstTick(t *testing.T) {
	// A long interval with an immediate stop still runs exactly the one
	// immediate cycle and returns without waiting for a tick.
	var count atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		scanLoop(time.Hour, func() { count.Add(1) }, stop)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scanLoop blocked on the long interval instead of honoring stop")
	}
	if got := count.Load(); got != 1 {
		t.Errorf("immediate cycles = %d, want 1", got)
	}
}

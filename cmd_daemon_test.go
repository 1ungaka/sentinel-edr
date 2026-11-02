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

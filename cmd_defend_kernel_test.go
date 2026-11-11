package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The daemon looks for the kernel guard's event log on its own, so a host with
// the guard installed gets the kernel layer without a flag.
//
// The path the guard's shipped systemd unit writes to has to be one of them:
// a path the daemon does not look at is a log nobody reads, and the kernel
// layer is then silently absent from every report.
func TestTheKernelEventLogIsFoundWhereTheGuardWritesIt(t *testing.T) {
	const unitPath = "/run/cau/kernel-events.jsonl"
	found := false
	for _, p := range kernelEventPaths {
		if p == unitPath {
			found = true
		}
	}
	if !found {
		t.Errorf("the daemon does not look for %s, which is where the guard's unit writes it: %v", unitPath, kernelEventPaths)
	}
}

// The environment override wins, so an operator can point the daemon at a log
// anywhere.
func TestTheKernelEventLogCanBeOverridden(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAU_KERNEL_EVENTS", p)
	var said string
	got := discoverKernelEvents(func(f string, a ...interface{}) { said = f })
	if got != p {
		t.Fatalf("discovered %q, want %q", got, p)
	}
	if said == "" {
		t.Error("the discovery was not reported")
	}
}

// Nothing to find is not an error: the daemon runs on hosts without the guard.
func TestNoKernelEventLogIsNotAnError(t *testing.T) {
	t.Setenv("CAU_KERNEL_EVENTS", filepath.Join(t.TempDir(), "absent.jsonl"))
	if got := discoverKernelEvents(func(string, ...interface{}) {}); got != "" {
		t.Fatalf("discovered %q, want nothing", got)
	}
}

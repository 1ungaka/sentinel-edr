//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A public key is what cau defend reads at startup with nobody watching, so a
// writer that has gone quiet must cost seconds of EDR downtime and not minutes.
// Both resolvers are covered because each is reached from a path no one is
// sitting at: the daemon for one, verify-self and the update timer for the other.
func TestSilentPipeAtPublicKeyFailsWithinSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the real deadline")
	}
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "pub")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Held open and never written to: a writer exists, so the reader has to wait.
	w, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("holding the FIFO open: %v", err)
	}
	defer w.Close()

	for name, resolve := range map[string]func() error{
		"selftest": func() error { _, err := resolveSelftestPubkey(fifo); return err },
		"update":   func() error { _, err := resolveUpdateKey(fifo); return err },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			if err := resolve(); err == nil {
				t.Fatal("a pipe that delivered nothing resolved to a key")
			}
			if took := time.Since(start); took > 30*time.Second {
				t.Fatalf("took %v, which is a stalled daemon start", took)
			}
		})
	}
}

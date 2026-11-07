//go:build unix

package netblock

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The ledger only supplies reasons, so a FIFO there costs the reasons.
func TestAFIFOLedgerDoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	b := &Blocker{opts: Options{Ledger: path}}
	done := make(chan map[string]string, 1)
	go func() { done <- b.ledgerReasons() }()
	select {
	case got := <-done:
		if len(got) != 0 {
			t.Errorf("got %v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

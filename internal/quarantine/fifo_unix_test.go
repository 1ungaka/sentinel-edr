//go:build unix

package quarantine

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestAFIFOIndexDoesNotBlockTheVault(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.indexPath()); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(s.indexPath(), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.readIndex(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO read as an index")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

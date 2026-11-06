//go:build unix

package persist

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func testFIFO(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd})
	if err := syscall.Mkfifo(filepath.Join(root, "etc/ld.so.preload"), 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan struct{})
	go func() { Scan(Options{Root: root}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the audit blocked on a FIFO")
	}
}

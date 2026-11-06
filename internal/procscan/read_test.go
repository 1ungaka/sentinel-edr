//go:build unix

package procscan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// /proc/<pid>/maps and /proc/<pid>/net/tcp are seq_files: one read returns at
// most a page. Reading them once saw the first 27 of 40 sockets on the
// development host, so a reverse shell further down the table had no peer and
// did not count as one.
func TestReadSmallKeepsReadingPastAShortRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip(err)
	}
	go func() {
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer w.Close()
		w.WriteString("first-page\n")
		time.Sleep(20 * time.Millisecond) // forces the reader's first read to return short
		w.WriteString("second-page\n")
	}()
	if got := readSmall(path, 1<<20); got != "first-page\nsecond-page\n" {
		t.Fatalf("readSmall stopped at a short read: %q", got)
	}
}

func TestReadSmallStillHonoursItsLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readSmall(path, 10); len(got) != 10 {
		t.Fatalf("readSmall returned %d bytes, want the 10 byte limit", len(got))
	}
}

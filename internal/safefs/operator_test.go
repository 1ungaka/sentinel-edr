//go:build unix

package safefs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// heldPipe is a FIFO with a writer attached, which is what a process that has
// started but not yet written looks like from the reading end.
func heldPipe(t *testing.T) (string, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	w, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("holding a FIFO open: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	return path, w
}

func TestReadOperatorFileRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadOperatorFile(path, 4, time.Minute)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ReadOperatorFile(path, 3, time.Minute); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty regular file is the caller's to judge; only an empty pipe means
	// that nothing was delivered.
	if got, err := ReadOperatorFile(path, 4, time.Minute); err != nil || len(got) != 0 {
		t.Fatalf("empty file: %q, %v", got, err)
	}
}

// A key that takes a moment to arrive, in pieces, is the normal case: the
// command behind <(...) has to start, and may stop to ask for a passphrase.
func TestReadOperatorFilePipeArrivesLateInPieces(t *testing.T) {
	path, w := heldPipe(t)
	go func() {
		time.Sleep(30 * time.Millisecond)
		w.WriteString("abc")
		time.Sleep(30 * time.Millisecond)
		w.WriteString("def")
		w.Close()
	}()
	got, err := ReadOperatorFile(path, 64, time.Minute)
	if err != nil || string(got) != "abcdef" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// This is the form a shell really hands over, and it is a symlink into /proc on
// Linux, so it fails if the read stops following links.
func TestReadOperatorFileProcessSubstitutionPath(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	path := fmt.Sprintf("/dev/fd/%d", r.Fd())
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no %s here: %v", path, err)
	}
	w.WriteString("abc")
	w.Close()
	got, err := ReadOperatorFile(path, 64, time.Minute)
	if err != nil || string(got) != "abc" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadOperatorFilePipeNoWriterFailsAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	start := time.Now()
	got, err := ReadOperatorFile(path, 64, time.Minute)
	if err == nil {
		t.Fatalf("a pipe nobody writes to read as %q and no error", got)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("took %v; there is nothing to wait for", took)
	}
}

func TestReadOperatorFilePipeSilentWriterHitsTheDeadline(t *testing.T) {
	path, _ := heldPipe(t)
	got, err := ReadOperatorFile(path, 64, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("got %q, %v", got, err)
	}
}

// Half a key is not a key, so the bytes that did arrive must not come back.
func TestReadOperatorFilePipeStallsMidwayReturnsNothing(t *testing.T) {
	path, w := heldPipe(t)
	w.WriteString("abc")
	got, err := ReadOperatorFile(path, 64, 50*time.Millisecond)
	if err == nil || got != nil {
		t.Fatalf("got %q, %v", got, err)
	}
}

// The limit has to stop the read by itself. If this waited for the deadline, a
// writer that never stops would be held only by the clock.
func TestReadOperatorFilePipeOverLimitStopsWithoutWaiting(t *testing.T) {
	path, w := heldPipe(t)
	if _, err := w.Write(bytes.Repeat([]byte("a"), 65)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := ReadOperatorFile(path, 64, time.Minute); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("took %v; the limit should have ended it", took)
	}
}

func TestReadOperatorFileRefusesEverythingElse(t *testing.T) {
	for _, path := range []string{"/dev/zero", t.TempDir()} {
		if _, err := os.Stat(path); err != nil {
			t.Logf("no %s here: %v", path, err)
			continue
		}
		if got, err := ReadOperatorFile(path, 64, time.Minute); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: got %d bytes, %v", path, len(got), err)
		}
	}
}

//go:build unix

package safefs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(path, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO: a swapped-in pipe would hang the scanner")
	}
}

func TestReadFileRefusesADevice(t *testing.T) {
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Skip(err)
	}
	if _, err := ReadFile(link, 1024); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
}

func TestNoFollowRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skip(err)
	}
	if _, _, err := ReadFileNoFollow(link, 1024); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v, want ErrNotRegular", err)
	}
	if got, err := ReadFile(link, 1024); err != nil || string(got) != "s" {
		t.Fatalf("ReadFile through a link = %q, %v", got, err)
	}
}

func TestReadFileNeverReturnsAPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(path, 10); !errors.Is(err, ErrTooLarge) || b != nil {
		t.Fatalf("ReadFile = %d bytes, %v; want nil, ErrTooLarge", len(b), err)
	}
	if b, err := ReadFile(path, 11); err != nil || len(b) != 11 {
		t.Fatalf("exactly at the limit: %d bytes, %v", len(b), err)
	}
}

// The scanner tells "empty file" from "not read into memory" by nil.
func TestReadFileOfAnEmptyFileIsNotNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(path, 10); err != nil || b == nil {
		t.Fatalf("ReadFile = %v, %v", b, err)
	}
}

func TestWalkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir, linkFile := filepath.Join(dir, "ld"), filepath.Join(dir, "lf")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(file, linkFile); err != nil {
		t.Skip(err)
	}
	if got := WalkRoot(linkDir); !strings.HasSuffix(got, string(os.PathSeparator)) {
		t.Errorf("symlink to a directory: %q has no trailing separator", got)
	}
	for _, p := range []string{real, file, linkFile, filepath.Join(dir, "missing")} {
		if got := WalkRoot(p); got != p {
			t.Errorf("WalkRoot(%q) = %q, want it unchanged", p, got)
		}
	}
}

//go:build unix

package selftest

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// `cau selftest` runs as ExecStartPre. The "-" on that line forgives a failure
// but not a timeout, so a read that blocks here stops the daemon from ever
// starting, however carefully the daemon itself handles the same file.
func TestAFIFONeverBlocksTheSelftest(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "planted")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(tree, "skipped.yar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "ok.yar"), []byte("rule ok { condition: false }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func() error{
		"manifest": func() error {
			_, err := ReadManifest(fifo)
			if !errors.Is(err, safefs.ErrNotRegular) {
				t.Errorf("manifest: %v", err)
			}
			return nil
		},
		"resource": func() error {
			_, _, _, err := Digest(fifo)
			if !errors.Is(err, safefs.ErrNotRegular) {
				t.Errorf("resource: %v", err)
			}
			return nil
		},
		"tree": func() error { _, _, _, err := Digest(tree); return err },
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- read() }()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("blocked on a FIFO")
			}
		})
	}
}

// Moving to a streaming read must not change a digest: a recorded baseline has to
// keep verifying.
func TestDigestIsStillTheSHA256OfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, _, err := Digest(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("got %s", got)
	}
}

//go:build unix

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

// --from is the air-gap path, so this directory can be whatever was on the media.
// Nothing here has been verified yet: the read happens before the signature is
// checked, so a FIFO hung the update and a huge file filled memory.
func TestLoadBundleDirRefusesAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, PayloadName), 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadBundleDir(dir)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, safefs.ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO in the bundle directory")
	}
}

func TestLoadBundleDirBoundsEachFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{PayloadName, SignatureName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	big := filepath.Join(dir, ManifestName)
	if err := os.WriteFile(big, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, maxManifestBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundleDir(dir); !errors.Is(err, safefs.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

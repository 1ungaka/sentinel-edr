//go:build linux

package watch

import (
	"os"
	"path/filepath"
	"testing"
)

// /bin and /lib are symlinks on a merged-/usr host. WalkDir lstats its root, so
// a watch on one found no directory and quietly watched nothing.
func TestWatchesThroughASymlinkedRoot(t *testing.T) {
	real := t.TempDir()
	if err := os.Mkdir(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	w, err := New([]string{link}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if got := w.Dirs(); got != 2 {
		t.Fatalf("watching %d directories through a symlinked root, want 2", got)
	}
}

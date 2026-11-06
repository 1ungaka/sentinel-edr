//go:build linux

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func start(t *testing.T, root string) (*Watcher, <-chan Event) {
	t.Helper()
	w, err := New([]string{root}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Event, 256)
	go func() { _ = w.Run(func(e Event) { ch <- e }) }()
	t.Cleanup(func() { _ = w.Close() })
	return w, ch
}

func expect(t *testing.T, ch <-chan Event, path string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Path == path {
				return
			}
		case <-deadline:
			t.Fatalf("no event for %s", path)
		}
	}
}

func TestReportsNewFile(t *testing.T) {
	root := t.TempDir()
	_, ch := start(t, root)
	p := filepath.Join(root, "drop")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, p)
}

func TestReportsRename(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	src := filepath.Join(other, "a")
	_ = os.WriteFile(src, []byte("x"), 0o644)
	_, ch := start(t, root)
	dst := filepath.Join(root, "a")
	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, dst)
}

func TestArmingAFileIsAnEvent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "dropper")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	_, ch := start(t, root)
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, p)
}

// A directory created under a watch is filled before its own watch exists.
func TestNewDirectoryIsWatchedAndSwept(t *testing.T) {
	root := t.TempDir()
	_, ch := start(t, root)
	dir := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "implant")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, p)
}

func TestSymlinkDirectoryIsNotFollowed(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	w, _ := start(t, root)
	if w.Dirs() != 1 {
		t.Fatalf("watched %d dirs, want only the root", w.Dirs())
	}
}

func TestMissingRootIsSkipped(t *testing.T) {
	w, err := New([]string{"/no/such/dir"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Dirs() != 0 {
		t.Fatal("a missing root must add nothing")
	}
}

func TestLimitIsReportedNotHidden(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "b", "c"} {
		_ = os.Mkdir(filepath.Join(root, d), 0o755)
	}
	w, err := New([]string{root}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !w.Truncated() {
		t.Fatal("hitting the limit must be visible")
	}
}

func TestCloseStopsRun(t *testing.T) {
	w, err := New([]string{t.TempDir()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.Run(func(Event) {}) }()
	_ = w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

// A hard link makes a new name with no write and no close.
func TestHardLinkIsAnEvent(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	src := filepath.Join(other, "a")
	_ = os.WriteFile(src, []byte("x"), 0o644)
	_, ch := start(t, root)
	dst := filepath.Join(root, "a")
	if err := os.Link(src, dst); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	expect(t, ch, dst)
}

// A writer that keeps the file open never produces a close.
func TestFileHeldOpenIsAnEvent(t *testing.T) {
	root := t.TempDir()
	_, ch := start(t, root)
	p := filepath.Join(root, "held")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, _ = f.WriteString("payload")
	expect(t, ch, p)
}

// Looking at a new name must not undo the rule about symlinks.
func TestNewSymlinkIsNotReported(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	target := filepath.Join(other, "t")
	_ = os.WriteFile(target, []byte("x"), 0o644)
	_, ch := start(t, root)
	link := filepath.Join(root, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-ch:
		if e.Path == link {
			t.Fatal("a symlink must not be followed")
		}
	case <-time.After(300 * time.Millisecond):
	}
}

// A deleted file has to be reported or its verdict stays for ever.
func TestDeletionIsAnEvent(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "gone")
	_ = os.WriteFile(p, []byte("x"), 0o644)
	_, ch := start(t, root)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	expect(t, ch, p)
}

// Past the directory limit a new tree goes unwatched, and the consumer has to be
// told at the moment it happens to find what landed in it.
func TestReachingTheLimitAtRuntimeAsksForASweep(t *testing.T) {
	root := t.TempDir()
	w, err := New([]string{root}, 1)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Event, 16)
	go func() { _ = w.Run(func(e Event) { ch <- e }) }()
	t.Cleanup(func() { _ = w.Close() })
	if err := os.Mkdir(filepath.Join(root, "new"), 0o755); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Overflow {
				return
			}
		case <-deadline:
			t.Fatal("nobody was told the new directory is not watched")
		}
	}
}

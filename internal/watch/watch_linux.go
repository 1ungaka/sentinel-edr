//go:build linux

package watch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/s-b-repo/cau/internal/safefs"
)

const mask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_CREATE | syscall.IN_ATTRIB |
	syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_DELETE_SELF | syscall.IN_ONLYDIR | syscall.IN_DONT_FOLLOW

// createGrace is how long a new name gets to produce its close before it is
// reported anyway. A normal write closes well inside it, and is reported by that.
const createGrace = 50 * time.Millisecond

// maxWalks bounds the new trees walked at once, so renaming a large tree back and
// forth makes the reader wait, and the kernel report lost events, rather than
// growing goroutines without limit.
const maxWalks = 8

// Watcher reports changed files under its roots. Symlinks are not followed: a
// root-run watcher must not be steered into another tree by a link someone
// dropped in /tmp.
type Watcher struct {
	f       *os.File
	maxDirs int

	walks chan struct{}

	mu        sync.Mutex
	dirs      map[int32]string
	truncated bool
	creating  map[string]*time.Timer // new names waiting for a close
}

// New watches roots recursively. A root that does not exist is skipped, so one
// default list works across hosts.
func New(roots []string, maxDirs int) (*Watcher, error) {
	if maxDirs <= 0 {
		maxDirs = DefaultMaxDirs
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	// A non-blocking descriptor in an os.File goes through the runtime poller,
	// so Close unblocks a pending Read.
	w := &Watcher{f: os.NewFile(uintptr(fd), "inotify"), maxDirs: maxDirs, dirs: map[int32]string{},
		walks: make(chan struct{}, maxWalks), creating: map[string]*time.Timer{}}
	for _, r := range roots {
		w.addTree(r, nil, nil)
	}
	return w, nil
}

// Truncated reports that coverage is incomplete: the directory limit was
// reached, a watch could not be placed, or a subtree could not be read. In
// every case part of the tree will not produce events.
func (w *Watcher) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// Dirs reports how many directories are watched.
func (w *Watcher) Dirs() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.dirs)
}

// markIncomplete records that part of the tree is not covered. A consumer
// cannot otherwise tell a file nobody watches from a file nothing happened to.
func (w *Watcher) markIncomplete() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.truncated = true
}

// addTree watches root and everything below it. A directory created under a
// watch can be filled before the watch on it exists, so found, when set,
// receives the files already inside. full, when set, hears that the limit stopped
// the walk: what is under the rest of the tree has been seen by nothing.
func (w *Watcher) addTree(root string, found func(string), full func()) {
	stopped := false
	defer func() {
		if stopped && full != nil {
			full()
		}
	}()
	walked := safefs.WalkRoot(root)
	_ = filepath.WalkDir(walked, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A root that is not there is the documented skip, so one default
			// list works across hosts. Anything else — an unreadable subtree, a
			// directory that went away mid-walk — is a coverage gap, and the
			// files under it would never be reported without it.
			if !(p == walked && errors.Is(err, fs.ErrNotExist)) {
				w.markIncomplete()
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() {
			if found != nil && d.Type().IsRegular() {
				found(p)
			}
			return nil
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.dirs) >= w.maxDirs {
			w.truncated, stopped = true, true
			return filepath.SkipAll
		}
		wd, err := syscall.InotifyAddWatch(int(w.f.Fd()), p, mask)
		if err != nil {
			// ENOSPC is the per-user watch limit and it lands here rather than
			// at the count above: this subtree is unwatched, and silently so.
			w.truncated = true
			return nil
		}
		w.dirs[int32(wd)] = p
		return nil
	})
}

// Run delivers events to fn until Close. It returns nil after Close. fn is called
// from more than one goroutine.
func (w *Watcher) Run(fn func(Event)) error {
	buf := make([]byte, 64<<10)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			end := off + syscall.SizeofInotifyEvent + int(ev.Len)
			if end > n {
				break
			}
			name := strings.TrimRight(string(buf[off+syscall.SizeofInotifyEvent:end]), "\x00")
			w.handle(ev, name, fn)
			off = end
		}
	}
}

func (w *Watcher) handle(ev *syscall.InotifyEvent, name string, fn func(Event)) {
	if ev.Mask&syscall.IN_Q_OVERFLOW != 0 {
		fn(Event{Overflow: true})
		return
	}
	w.mu.Lock()
	dir, ok := w.dirs[ev.Wd]
	if ev.Mask&syscall.IN_IGNORED != 0 {
		delete(w.dirs, ev.Wd)
	}
	w.mu.Unlock()
	if !ok || name == "" {
		return
	}
	p := filepath.Join(dir, name)
	if ev.Mask&syscall.IN_ISDIR != 0 {
		if ev.Mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
			// Not on this goroutine: the kernel's queue fills while the reader
			// walks, and a new tree is exactly when events arrive fastest.
			w.walks <- struct{}{}
			go func() {
				defer func() { <-w.walks }()
				w.addTree(p, func(f string) { fn(Event{Path: f}) }, func() { fn(Event{Overflow: true}) })
			}()
		}
		return
	}
	// IN_CREATE fires while a file is still being written, and the close that
	// follows is what makes it worth reading. But nothing else follows a hard link,
	// or a writer that keeps its descriptor, so a name with no close by the end of
	// the grace period is reported as it stands. IN_ATTRIB is kept because
	// `chmod +x` is often the step that arms a dropped file, and a name going away
	// is reported so whatever was concluded about it can go too.
	switch {
	case ev.Mask&syscall.IN_CREATE != 0:
		w.expectClose(p, fn)
	case ev.Mask&(syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO|syscall.IN_ATTRIB|syscall.IN_DELETE|syscall.IN_MOVED_FROM) != 0:
		if ev.Mask&syscall.IN_ATTRIB == 0 {
			w.closed(p)
		}
		fn(Event{Path: p})
	}
}

func (w *Watcher) expectClose(p string, fn func(Event)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.creating[p] = time.AfterFunc(createGrace, func() {
		w.closed(p)
		// A link must not steer a root-run scan, so only a regular file counts.
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			fn(Event{Path: p})
		}
	})
}

func (w *Watcher) closed(p string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.creating[p]; ok {
		t.Stop()
		delete(w.creating, p)
	}
}

// Close stops Run and releases every watch.
func (w *Watcher) Close() error { return w.f.Close() }

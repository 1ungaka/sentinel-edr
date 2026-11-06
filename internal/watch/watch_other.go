//go:build !linux

package watch

// Watcher is unavailable on this platform.
type Watcher struct{}

// New reports that watching is unsupported here.
func New([]string, int) (*Watcher, error) { return nil, ErrUnsupported }

// Run does nothing.
func (*Watcher) Run(func(Event)) error { return ErrUnsupported }

// Close does nothing.
func (*Watcher) Close() error { return nil }

// Truncated is always false.
func (*Watcher) Truncated() bool { return false }

// Dirs is always zero.
func (*Watcher) Dirs() int { return 0 }

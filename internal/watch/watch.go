// Package watch reports files as they appear, so a dropped implant is scanned
// when it lands rather than at the next scheduled pass.
package watch

import "errors"

// ErrUnsupported is returned where the kernel interface is not available. The
// caller falls back to its interval.
var ErrUnsupported = errors.New("watch: real-time file watching needs Linux inotify")

// DefaultMaxDirs bounds the watches placed. Past it a tree is reported as
// truncated rather than silently half-covered, since inotify watches are a
// limited per-user resource.
const DefaultMaxDirs = 8192

// Event is one change. Path is empty and Overflow true when the kernel dropped
// events: anything could have happened, so the consumer should rescan.
type Event struct {
	Path     string
	Overflow bool
}

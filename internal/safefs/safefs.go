// Package safefs reads files an attacker may be racing.
//
// The engine runs as a privileged service against directories anyone can write
// to, so a stat followed by an open checks one file and reads another: swap a
// regular file for a FIFO after the stat and the reader blocks forever, swap it
// for a link to /dev/zero and it reads until the host runs out of memory, swap
// it for a link to /etc/shadow and the quarantine vault takes a copy. Everything
// here opens first and then asks the open descriptor, which cannot be swapped.
package safefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	// ErrNotRegular reports a FIFO, device, socket or directory, or a symlink
	// where the caller refused to follow one.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge reports a file over the caller's limit. A partial read is never
	// returned: a scan of the first N bytes would present as a scan of the file.
	ErrTooLarge = errors.New("file exceeds the read limit")
)

// Open opens path for reading, following symlinks, and fails with ErrNotRegular
// on anything but a regular file. It cannot block on a FIFO.
func Open(path string) (*os.File, os.FileInfo, error) { return open(path, 0) }

// OpenNoFollow is Open that also refuses a symlink in the final path component.
func OpenNoFollow(path string) (*os.File, os.FileInfo, error) { return open(path, noFollow) }

func open(path string, flags int) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock|flags, 0)
	if err != nil {
		if isSymlinkRefusal(err) {
			return nil, nil, fmt.Errorf("%s: %w (symbolic link)", path, ErrNotRegular)
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: %w (%s)", path, ErrNotRegular, fi.Mode().Type())
	}
	return f, fi, nil
}

// ReadAll reads f to its end, failing with ErrTooLarge past limit. The size from
// a stat is only a hint: the file can grow while it is being read.
func ReadAll(f *os.File, fi os.FileInfo, limit int64) ([]byte, error) {
	hint := fi.Size()
	if hint > limit {
		hint = limit
	}
	buf := bytes.NewBuffer(make([]byte, 0, hint+bytes.MinRead))
	if _, err := buf.ReadFrom(io.LimitReader(f, limit+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("%s: %w of %d bytes", f.Name(), ErrTooLarge, limit)
	}
	return buf.Bytes(), nil
}

// ReadFile reads the regular file at path, following symlinks. It is a drop-in
// for os.ReadFile on a path an attacker can reach.
func ReadFile(path string, limit int64) ([]byte, error) {
	f, fi, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadAll(f, fi, limit)
}

// ReadFileNoFollow is ReadFile for a caller acting on the path itself rather than
// what it points at. The FileInfo describes the file that was read.
func ReadFileNoFollow(path string, limit int64) ([]byte, os.FileInfo, error) {
	f, fi, err := OpenNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := ReadAll(f, fi, limit)
	return data, fi, err
}

// WalkRoot returns the path to give filepath.Walk or WalkDir for a directory the
// caller named. Both lstat their root, so a symlink to a directory comes back as
// a non-directory and nothing is visited, which is what /bin and /lib are on a
// merged-/usr host. A trailing separator makes that lstat resolve the link, and
// the walk's joins drop it again, so results keep the caller's spelling.
func WalkRoot(root string) string {
	lfi, err := os.Lstat(root)
	if err != nil || lfi.Mode()&os.ModeSymlink == 0 {
		return root
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return root
	}
	return root + string(os.PathSeparator)
}

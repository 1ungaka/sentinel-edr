package hwanchor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Bounds. sysfs is kernel-generated, but the root is injectable and a
// snapshot must stay bounded whatever it is pointed at.
const (
	// maxAttrBytes is the most one attribute may hold: a sysfs attribute is
	// at most one page.
	maxAttrBytes = 4096
	// maxInterfaces caps how many class/net entries are looked at.
	maxInterfaces = 1024
	// maxIfName is IFNAMSIZ-1: the kernel cannot create a longer interface
	// name, so a longer entry is not an interface.
	maxIfName = 15
	// maxLinkHops is the kernel's own symbolic-link limit.
	maxLinkHops = 40
)

var (
	errOutsideRoot = errors.New("resolves outside the sysfs root; not followed")
	errLinkLoop    = errors.New("too many symbolic links")
)

// sysfs reads attributes below one root directory and nowhere else.
type sysfs struct {
	// real is the root with its own symbolic links resolved. Everything read
	// is below it.
	real string
}

// openSysfs resolves the root. The root itself may be reached through
// symbolic links; nothing below it may lead back out.
func openSysfs(root string) (*sysfs, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("sysfs root %s: %s", root, shortErr(err))
	}
	if real, err = filepath.Abs(real); err != nil {
		return nil, fmt.Errorf("sysfs root %s: %s", root, shortErr(err))
	}
	fi, err := os.Lstat(real)
	if err != nil {
		return nil, fmt.Errorf("sysfs root %s: %s", root, shortErr(err))
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("sysfs root %s is not a directory", root)
	}
	s := &sysfs{real: real}
	// A tree with no class directory is not sysfs. Reporting every anchor of
	// such a tree as absent would describe a mistyped path as a machine with
	// no hardware identity.
	fi, err = s.lstat("class")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s has no class directory: not a sysfs tree", root)
	case err != nil:
		return nil, fmt.Errorf("sysfs root %s: class: %s", root, shortErr(err))
	case !fi.IsDir():
		return nil, fmt.Errorf("%s: class is not a directory: not a sysfs tree", root)
	}
	return s, nil
}

// shortErr is an error's cause without the path the os package prefixes: the
// caller names the anchor, and paths are attacker-influenced text.
func shortErr(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// resolve turns a slash-separated path relative to the root into a real path,
// following symbolic links by hand so that each step can be checked: a link
// that is absolute, or that climbs above the root, is refused before anything
// it points at is touched.
func (s *sysfs) resolve(rel string) (string, error) {
	cur := s.real
	pending := strings.Split(rel, "/")
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if cur == s.real {
				return "", errOutsideRoot
			}
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", errLinkLoop
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		// sysfs links are always relative. An absolute one is refused, not
		// tested against the root.
		if filepath.IsAbs(target) {
			return "", errOutsideRoot
		}
		// The target is relative to the directory holding the link, which
		// is cur.
		pending = append(strings.Split(filepath.ToSlash(target), "/"), pending...)
	}
	return cur, nil
}

// lstat resolves rel and stats what it finally names.
func (s *sysfs) lstat(rel string) (fs.FileInfo, error) {
	p, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	return os.Lstat(p)
}

// lstatChild stats one entry of a resolved directory without following it.
func (s *sysfs) lstatChild(rel, child string) (fs.FileInfo, error) {
	p, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	return os.Lstat(filepath.Join(p, child))
}

// relPath is where rel really lives, relative to the root and slash-separated:
// "class/net/eth0" becomes "devices/pci0000:00/.../net/eth0".
func (s *sysfs) relPath(rel string) (string, error) {
	p, err := s.resolve(rel)
	if err != nil {
		return "", err
	}
	out, err := filepath.Rel(s.real, p)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(out), nil
}

// failed is the Field for something that could not be read: absent when it
// does not exist, unreadable for every other cause.
func failed(err error) Field {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Field{State: StateAbsent}
	case errors.Is(err, fs.ErrPermission):
		return Field{State: StateUnreadable, Reason: "permission denied; reading this needs root"}
	}
	return Field{State: StateUnreadable, Reason: shortErr(err)}
}

// attr reads one attribute as trimmed text. The result is StateOK with the
// value, StateAbsent, or StateUnreadable with the reason; deciding whether a
// value is a placeholder is the caller's job. Invalid UTF-8 is replaced so
// that a value survives a JSON round trip unchanged; control characters are
// kept, and it is the renderer that must escape them.
func (s *sysfs) attr(rel string) Field {
	p, err := s.resolve(rel)
	if err != nil {
		return failed(err)
	}
	before, err := os.Lstat(p)
	if err != nil {
		return failed(err)
	}
	// Never open anything but a regular file: opening a FIFO blocks.
	if !before.Mode().IsRegular() {
		return Field{State: StateUnreadable, Reason: "not a regular file"}
	}
	in, err := os.Open(p)
	if err != nil {
		return failed(err)
	}
	defer in.Close()
	if after, serr := in.Stat(); serr != nil || !os.SameFile(before, after) {
		return Field{State: StateUnreadable, Reason: "replaced while it was being read"}
	}
	buf := make([]byte, maxAttrBytes+1)
	n, err := io.ReadFull(in, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return failed(err)
	}
	if n > maxAttrBytes {
		// A truncated value is not the value. Refuse it rather than record
		// the first page of something as an identity.
		return Field{State: StateUnreadable, Reason: fmt.Sprintf("larger than %d bytes: not a sysfs attribute", maxAttrBytes)}
	}
	return Field{State: StateOK, Value: strings.TrimSpace(strings.ToValidUTF8(string(buf[:n]), "\uFFFD"))}
}

// list returns up to max entry names of a directory, sorted, and whether more
// were left unread.
func (s *sysfs) list(rel string, max int) (names []string, truncated bool, err error) {
	p, err := s.resolve(rel)
	if err != nil {
		return nil, false, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, false, err
	}
	if !fi.IsDir() {
		return nil, false, errors.New("not a directory")
	}
	dir, err := os.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(max + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if len(entries) > max {
		entries, truncated = entries[:max], true
	}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, truncated, nil
}

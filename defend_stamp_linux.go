//go:build linux

package main

import (
	"os"
	"syscall"
	"time"
)

// fileNode is the part of a file's stamp its writer cannot choose. Size is theirs
// and so is mtime, which `touch -r` restores after a rewrite. The inode and ctime
// are the kernel's: no call sets ctime, and a chmod, a rename or a rewrite moves it.
type fileNode struct {
	dev, ino             uint64
	ctimeSec, ctimeNanos int64
}

func nodeOf(fi os.FileInfo) fileNode {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileNode{}
	}
	sec, nanos := st.Ctim.Unix()
	return fileNode{uint64(st.Dev), uint64(st.Ino), sec, nanos}
}

// changedAt is when the file last changed, as the kernel recorded it.
func changedAt(fi os.FileInfo) time.Time {
	n := nodeOf(fi)
	return time.Unix(n.ctimeSec, n.ctimeNanos)
}

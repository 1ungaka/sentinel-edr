//go:build !linux

package main

import (
	"os"
	"time"
)

// fileNode is empty where the kernel's own record of a change is not available
// the same way, which leaves a stamp of size and mtime.
type fileNode struct{}

func nodeOf(os.FileInfo) fileNode { return fileNode{} }

func changedAt(fi os.FileInfo) time.Time { return fi.ModTime() }

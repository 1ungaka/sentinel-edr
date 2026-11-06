//go:build linux

package persist

import "syscall"

// fileCaps reads a file's security.capability attribute, nil when it has none.
func fileCaps(path string) []byte {
	buf := make([]byte, 64)
	n, err := syscall.Getxattr(path, "security.capability", buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}

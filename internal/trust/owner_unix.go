//go:build unix

package trust

import (
	"os"
	"syscall"
)

// ownerUID reports the file's owner. The second return is false when the OS
// does not expose one, which leaves the caller with the mode checks alone.
func ownerUID(info os.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

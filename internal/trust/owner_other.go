//go:build !unix

package trust

import "os"

// ownerUID has no portable answer off unix, so the mode checks carry the
// decision on their own there.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }

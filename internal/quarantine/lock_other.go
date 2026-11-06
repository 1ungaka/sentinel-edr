//go:build !unix

package quarantine

import "sync"

var processLock sync.Mutex

// lockFile serialises callers in this process only: this platform has no flock.
func lockFile(string) (func(), error) {
	processLock.Lock()
	return processLock.Unlock, nil
}

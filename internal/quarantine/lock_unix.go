//go:build unix

package quarantine

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on path, waiting for it, and returns
// the function that releases it. Closing the descriptor drops the lock, so a
// process that dies holding it cannot wedge the vault.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

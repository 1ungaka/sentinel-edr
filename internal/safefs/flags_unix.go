//go:build unix

package safefs

import (
	"errors"
	"syscall"
)

const (
	noFollow = syscall.O_NOFOLLOW
	nonBlock = syscall.O_NONBLOCK
)

func isSymlinkRefusal(err error) bool { return errors.Is(err, syscall.ELOOP) }

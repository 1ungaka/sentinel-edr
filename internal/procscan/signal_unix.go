//go:build unix

package procscan

import (
	"fmt"
	"syscall"
)

func signalProcess(pid int, a Action) error {
	var sig syscall.Signal
	switch a {
	case ActionStop:
		sig = syscall.SIGSTOP
	case ActionKill:
		sig = syscall.SIGKILL
	default:
		return fmt.Errorf("unknown action %q", a)
	}
	return syscall.Kill(pid, sig)
}

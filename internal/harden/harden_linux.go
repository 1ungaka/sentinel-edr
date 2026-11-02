//go:build linux

// Package harden applies in-process, OS-level self-protection: it makes the
// running process harder to inspect, tamper with, or extract secrets from,
// independent of any external supervisor. It is best-effort and fail-open — a
// host that denies a hardening step is reported, never fatal, because the
// scanner's job (detection) must keep running even where it cannot lock itself
// down.
package harden

import "syscall"

// Linux prctl options not exported by the standard library's syscall package.
const (
	prSetDumpable         = 4  // PR_SET_DUMPABLE
	prSetNoNewPrivs       = 38 // PR_SET_NO_NEW_PRIVS
	prSetDumpableNonDump  = 0  // SUID_DUMP_DISABLE — core dumps and foreign /proc access off
	prSetNoNewPrivsEnable = 1
)

// ProtectMemory makes the process non-dumpable. With the dumpable flag cleared,
// the kernel refuses ptrace-attach and /proc/<pid>/mem reads from any process
// that is not already running as the owner's effective UID (so a same-UID
// attacker is stopped too for the typical root-vs-service split), and it
// produces no core dump — closing the two cheapest ways to read the daemon's
// in-memory state (the pinned trust anchor, the signature set, the config) off
// a running host. Returns whether it was applied and any error.
func ProtectMemory() (applied bool, err error) {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, prSetDumpableNonDump, 0); errno != 0 {
		return false, errno
	}
	return true, nil
}

// LockPrivileges sets no_new_privs, so no execve from this process (or any
// child) can ever gain privileges through setuid/setgid/file capabilities.
// Defense in depth for the case where an attacker coerces the daemon into
// executing something: the exec cannot escalate. Idempotent and irreversible
// for the lifetime of the process, exactly as the kernel intends.
func LockPrivileges() (applied bool, err error) {
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetNoNewPrivs, prSetNoNewPrivsEnable, 0); errno != 0 {
		return false, errno
	}
	return true, nil
}

// supported reports that memory/privilege hardening is a no-op-free path on
// this platform. Always true on Linux.
func supported() bool { return true }

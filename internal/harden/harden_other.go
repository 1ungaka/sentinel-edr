//go:build !linux

package harden

// On non-Linux platforms the prctl-based protections do not exist; these are
// honest no-ops that report "not applied" so the caller logs the gap instead of
// claiming a protection it does not have.

// ProtectMemory is a no-op off Linux.
func ProtectMemory() (applied bool, err error) { return false, nil }

// LockPrivileges is a no-op off Linux.
func LockPrivileges() (applied bool, err error) { return false, nil }

func supported() bool { return false }

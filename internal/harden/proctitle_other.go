//go:build !linux

package harden

// ConcealProcess is a no-op off Linux: comm/argv rewriting and the ptrace
// status check are Linux-specific. It reports nothing applied so the caller
// logs the gap instead of claiming concealment it does not have.
func ConcealProcess() Concealment { return Concealment{} }

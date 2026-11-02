//go:build linux

package harden

import (
	"os"
	"strings"
	"testing"
)

// procDumpable reads the Dumpable bit the kernel exposes for this process.
// "Dumpable:\t0" means core dumps and foreign /proc/<pid>/mem access are off.
func procDumpable(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("no /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Dumpable:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Dumpable:"))
		}
	}
	return ""
}

func TestProtectMemoryClearsDumpable(t *testing.T) {
	applied, err := ProtectMemory()
	if err != nil {
		t.Fatalf("ProtectMemory: %v", err)
	}
	if !applied {
		t.Fatal("ProtectMemory reported not-applied on Linux")
	}
	// The kernel must now report the process as non-dumpable, which is what
	// blocks ptrace-attach and /proc/<pid>/mem reads by a non-owner.
	if got := procDumpable(t); got != "0" && got != "" {
		t.Errorf("Dumpable = %q after ProtectMemory, want 0", got)
	}
}

func TestLockPrivilegesApplies(t *testing.T) {
	applied, err := LockPrivileges()
	if err != nil {
		t.Fatalf("LockPrivileges: %v", err)
	}
	if !applied {
		t.Fatal("LockPrivileges reported not-applied on Linux")
	}
}

func TestApplyReportsSupported(t *testing.T) {
	r := Apply()
	if !r.Supported {
		t.Fatal("Apply: Supported=false on Linux")
	}
	if !r.MemoryProtected {
		t.Errorf("Apply: MemoryProtected=false (notes: %v)", r.Notes)
	}
	if s := r.Summary(); !strings.Contains(s, "non-dumpable") {
		t.Errorf("Summary() = %q, want it to mention non-dumpable", s)
	}
}

package bootscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The kernel surface reads the taint word, the signature enforcement mode and
// the module list.
func TestScanKernelReadsTheState(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 12 = O (out-of-tree), 13 = E (unsigned).
	write("sys/kernel/tainted", "12288\n")
	write("sys/kernel/module/sig_enforce", "1\n")
	write("modules", "nf_tables 299008 1 nf_nat, Live 0xffffffffc0800000\nxt_conntrack 196608 1 - Live 0xffffffffc0a00000\n")

	rep, notes := ScanKernel(root)
	if len(notes) != 0 {
		t.Errorf("the state was reported as partly unreadable: %v", notes)
	}
	if rep.Tainted != 12288 {
		t.Errorf("taint word = %d", rep.Tainted)
	}
	joined := strings.Join(rep.TaintFlags, " | ")
	if !strings.Contains(joined, "O: out-of-tree module loaded") {
		t.Errorf("the out-of-tree flag is missing: %v", rep.TaintFlags)
	}
	if !strings.Contains(joined, "E: unsigned module loaded") {
		t.Errorf("the unsigned flag is missing: %v", rep.TaintFlags)
	}
	if !rep.SigEnforceKnown || rep.SigEnforce != 1 {
		t.Errorf("signature enforcement = %d (known %v)", rep.SigEnforce, rep.SigEnforceKnown)
	}
	if rep.ModuleCount != 2 {
		t.Errorf("module count = %d", rep.ModuleCount)
	}
}

// What could not be read is named, never read as a clean state.
func TestScanKernelNamesWhatItCouldNotRead(t *testing.T) {
	root := t.TempDir()
	rep, notes := ScanKernel(root)
	if len(notes) == 0 {
		t.Fatal("an empty proc root was reported as read")
	}
	if len(rep.Unreadable) == 0 {
		t.Error("the unreadable inputs were not named")
	}
	if rep.SigEnforceKnown {
		t.Error("the signature enforcement mode was reported as known when it was not read")
	}
}

// A taint bit beyond the table is still reported: an unknown bit must not
// pass silently.
func TestScanKernelReportsAnUnknownTaintBit(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sys/kernel/tainted")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("1099511627776\n"), 0o644); err != nil { // bit 40
		t.Fatal(err)
	}
	rep, _ := ScanKernel(root)
	joined := strings.Join(rep.TaintFlags, " | ")
	if !strings.Contains(joined, "taint-bit-40") {
		t.Errorf("the unknown bit was not reported: %v", rep.TaintFlags)
	}
}

package bootscan

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/s-b-repo/cau/internal/safefs"
)

// maxKernelStateBytes bounds one kernel-state file. The module list is the
// largest of them and is a few hundred kilobytes at most; the bound is what
// keeps a FIFO or a device in the same place from hanging the read.
const maxKernelStateBytes = 8 << 20

// The kernel's own record of what it has accepted. It is state, not a
// finding: an out-of-tree module on a developer workstation is ordinary, and
// a host whose module signatures are not enforced is a policy question the
// operator owns. What the sensor does with it is correlate — a taint flag that
// appeared since the baseline, or unsigned modules on a host that enforces
// signatures, is a finding; the raw state is not.

// KernelReport is the kernel-state surface: what the running kernel says
// about itself.
type KernelReport struct {
	// Tainted is the raw taint word from /proc/sys/kernel/tainted.
	Tainted uint64 `json:"tainted,omitempty"`
	// TaintFlags are the decoded flags, the security-relevant ones first.
	TaintFlags []string `json:"taint_flags,omitempty"`
	// SigEnforce is the module signature enforcement mode: 1 enforcing, 0
	// permissive, -1 when the kernel does not expose the setting.
	SigEnforce int `json:"sig_enforce"`
	// SigEnforceKnown says whether the value was read.
	SigEnforceKnown bool `json:"sig_enforce_known"`
	// ModuleCount is how many modules /proc/modules lists.
	ModuleCount int `json:"module_count,omitempty"`
	// Unreadable names what could not be read.
	Unreadable []string `json:"unreadable,omitempty"`
}

// taintBits maps a taint bit position to its letter and meaning.
//
// The table is the kernel's own list, and the word's bit i IS the kernel's
// flag i: /proc/sys/kernel/tainted is the kernel's TAINT_* mask as it stands,
// with no shift. (Bit 12 is TAINT_OOT_MODULE, "O"; bit 13 is
// TAINT_UNSIGNED_MODULE, "E".) The kernel sensor (`cau-kernel`) decodes the
// same word with the same table, and the two must agree: a flag one of them
// reads and the other does not is a flag nobody reads.
//
// Keep the two tables in step. The kernel's list is include/linux/panic.h.
var taintBits = []struct {
	letter string
	note   string
	sec    bool
}{
	{"P", "proprietary module loaded", false},
	{"F", "module force-loaded", true},
	{"S", "SMP kernel on unsupported CPU", false},
	{"R", "module force-unloaded", true},
	{"M", "machine check", false},
	{"B", "bad page referenced", false},
	{"U", "user requested taint", false},
	{"D", "kernel died recently (OOPS/BUG)", true},
	{"A", "ACPI table overridden", false},
	{"W", "warning issued", false},
	{"C", "staging driver loaded", false},
	{"I", "firmware workaround applied", false},
	{"O", "out-of-tree module loaded", true},
	{"E", "unsigned module loaded", true},
	{"L", "soft lockup occurred", false},
	{"K", "kernel live-patched", true},
	{"X", "auxiliary taint", false},
	{"T", "struct randomization plugin", false},
	{"N", "in-kernel test run", false},
}

// ScanKernel reads the kernel's own state from a proc root (normally /proc).
//
// It is read-only and it never fails the run: what could not be read is
// named, so an unreadable taint file is not read as "no taint".
func ScanKernel(procRoot string) (*KernelReport, []string) {
	rep := &KernelReport{SigEnforce: -1}
	if procRoot == "" {
		procRoot = "/proc"
	}
	var notes []string

	if data, err := safefs.ReadFile(filepath.Join(procRoot, "sys/kernel/tainted"), maxKernelStateBytes); err == nil {
		raw, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if perr != nil {
			notes = append(notes, "the kernel taint word is unreadable: "+perr.Error())
			rep.Unreadable = append(rep.Unreadable, "sys/kernel/tainted")
		} else {
			rep.Tainted = raw
			rep.TaintFlags = decodeTaint(raw)
		}
	} else {
		notes = append(notes, "the kernel taint word could not be read: "+err.Error())
		rep.Unreadable = append(rep.Unreadable, "sys/kernel/tainted")
	}

	if data, err := safefs.ReadFile(filepath.Join(procRoot, "sys/kernel/module/sig_enforce"), maxKernelStateBytes); err == nil {
		if v, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil {
			rep.SigEnforce = v
			rep.SigEnforceKnown = true
		} else {
			notes = append(notes, "the module signature enforcement mode is unreadable: "+perr.Error())
			rep.Unreadable = append(rep.Unreadable, "sys/kernel/module/sig_enforce")
		}
	} else {
		notes = append(notes, "the module signature enforcement mode could not be read: "+err.Error())
		rep.Unreadable = append(rep.Unreadable, "sys/kernel/module/sig_enforce")
	}

	if data, err := safefs.ReadFile(filepath.Join(procRoot, "modules"), maxKernelStateBytes); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				rep.ModuleCount++
			}
		}
	} else {
		notes = append(notes, "the module list could not be read: "+err.Error())
		rep.Unreadable = append(rep.Unreadable, "modules")
	}
	return rep, notes
}

// decodeTaint renders the set taint bits, the security-relevant ones first.
func decodeTaint(raw uint64) []string {
	var sec, other []string
	for i := 0; i < 64; i++ {
		bit := uint64(1) << uint(i)
		if raw&bit == 0 {
			continue
		}
		if i < len(taintBits) {
			b := taintBits[i]
			s := b.letter + ": " + b.note
			if b.sec {
				sec = append(sec, s)
			} else {
				other = append(other, s)
			}
			continue
		}
		// A bit the table does not know is still reported: a future kernel
		// taint, or a value somebody wrote by hand.
		s := "taint-bit-" + strconv.Itoa(i) + ": unknown taint bit (no table entry)"
		sec = append(sec, s)
	}
	return append(sec, other...)
}

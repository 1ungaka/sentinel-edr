package harden

import (
	"strconv"
	"strings"
)

// Concealment describes the process-name obfuscation and anti-hook steps.
type Concealment struct {
	// Applied is true when either the comm or the command line was rewritten.
	Applied bool
	// ProcessName is the randomised name chosen, recorded so the daemon banner
	// can log the real → random mapping for the administrator.
	ProcessName string
	// CommSet / CmdlineMasked report which of the two name surfaces took: comm
	// (pgrep/pkill, /proc/<pid>/comm) and the command line (ps, cmdline).
	CommSet       bool
	CmdlineMasked bool
	// CommNote says why the process name did not take, when it did not. A
	// concealment that reports success while the name a hunt looks for is
	// unchanged is worse than no concealment: it is a claim that is not
	// true.
	CommNote string
	// EnvStripped lists loader-injection variables (LD_PRELOAD, …) removed from
	// the environment at launch — a non-empty list is a tamper signal.
	EnvStripped []string
	// TracerPID is a non-zero attached-tracer PID (ptrace), or 0 if none.
	TracerPID int
}

// Report describes what self-protection was applied, for honest logging.
type Report struct {
	Supported       bool
	MemoryProtected bool
	PrivsLocked     bool
	Concealment     Concealment
	// Notes carries any step that could not be applied, so a degraded host is
	// visible rather than silently unprotected.
	Notes []string
}

// Summary is a single human line for the daemon banner.
func (r Report) Summary() string {
	if !r.Supported {
		return "self-protection: not available on this platform (detection unaffected)"
	}
	var on []string
	if r.MemoryProtected {
		on = append(on, "memory non-dumpable")
	}
	if r.PrivsLocked {
		on = append(on, "no-new-privs")
	}
	if c := r.Concealment; c.Applied {
		where := []string{}
		if c.CommSet {
			where = append(where, "comm")
		}
		if c.CmdlineMasked {
			where = append(where, "cmdline")
		}
		on = append(on, "process name "+c.ProcessName+" ("+strings.Join(where, "+")+")")
	}
	if len(r.Concealment.EnvStripped) > 0 {
		on = append(on, "stripped "+strings.Join(r.Concealment.EnvStripped, ","))
	}
	s := "self-protection: " + strings.Join(on, ", ")
	notes := append([]string(nil), r.Notes...)
	if r.Concealment.TracerPID != 0 {
		notes = append(notes, "WARNING tracer attached pid "+strconv.Itoa(r.Concealment.TracerPID))
	}
	if len(notes) > 0 {
		s += " (" + strings.Join(notes, "; ") + ")"
	}
	return s
}

// Apply engages the available in-process protections and returns a report. It
// never fails: a step the kernel refuses is recorded in Notes, because a host
// that cannot be locked down must still be scanned.
//
// The concealment comes first, and the order matters. PR_SET_DUMPABLE(0) hands
// the process's /proc entries to root, and after that the process can no longer
// write its own /proc/<pid>/comm — which is how the *process* name (the one
// pgrep, pkill and top read) is set. Once the process is non-dumpable only
// PR_SET_NAME is left, and that sets the calling thread's name, which in a Go
// program is usually not the process's.
func Apply() Report {
	r := Report{Supported: supported()}
	if !r.Supported {
		return r
	}
	r.Concealment = ConcealProcess()
	if r.Concealment.CommNote != "" {
		r.Notes = append(r.Notes, "the process name did not change: "+r.Concealment.CommNote)
	}
	if ok, err := ProtectMemory(); err != nil {
		r.Notes = append(r.Notes, "memory protection unavailable: "+err.Error())
	} else {
		r.MemoryProtected = ok
	}
	if ok, err := LockPrivileges(); err != nil {
		r.Notes = append(r.Notes, "no-new-privs unavailable: "+err.Error())
	} else {
		r.PrivsLocked = ok
	}
	return r
}

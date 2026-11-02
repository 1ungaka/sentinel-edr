package harden

import "strings"

// Report describes what self-protection was applied, for honest logging.
type Report struct {
	Supported       bool
	MemoryProtected bool
	PrivsLocked     bool
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
	s := "self-protection: " + strings.Join(on, ", ")
	if len(r.Notes) > 0 {
		s += " (" + strings.Join(r.Notes, "; ") + ")"
	}
	return s
}

// Apply engages the available in-process protections and returns a report. It
// never fails: a step the kernel refuses is recorded in Notes, because a host
// that cannot be locked down must still be scanned.
func Apply() Report {
	r := Report{Supported: supported()}
	if !r.Supported {
		return r
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

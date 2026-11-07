package procscan

// Lookup reads one process's identity from /proc, so a caller that found it
// some other way can still be acted on through Respond.
//
// It exists because the process table is no longer the only layer that finds a
// process worth stopping. The network sensor attributes a socket to its holder
// through /proc/<pid>/fd, and the strongest thing it finds — a process with no
// file on disk holding a command-and-control connection — may score below this
// package's own threshold and never appear in a Result at all. Before this, a
// response planned for such a PID could not be carried out: Respond matches on
// entries it was given, and Process carries an unexported start time that
// nothing outside this package could fill.
//
// What it does NOT do is weaken any guard. The Process it returns carries the
// real start time, so Respond's identity re-read still refuses a PID recycled
// since the caller found it; PID 1, the responder and its ancestors are still
// protected; and the returned Score is 0, so Confirmed still refuses it unless
// the caller states its own grounds by setting Score or MinScore. The caller is
// asserting "something else confirmed this", not "skip the checks".
//
// The second return is false when the PID is gone or unreadable, which is the
// normal outcome for a process that exited between detection and response.
func Lookup(procRoot string, pid int) (Process, bool) {
	if pid <= 1 {
		return Process{}, false
	}
	root := Options{ProcRoot: procRoot}.procRoot()
	rp, ok := readProc(root, pid)
	if !ok || rp.comm == "" {
		return Process{}, false
	}
	return Process{
		startTicks: rp.startTicks,
		StartTicks: rp.startTicks,
		PID:        rp.pid,
		PPID:       rp.ppid,
		Comm:       rp.comm,
		Cmdline:    rp.cmdline,
		Exe:        rp.exeTarget,
	}, true
}

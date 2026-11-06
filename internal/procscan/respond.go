package procscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Action is what Respond does to a confirmed process.
type Action string

const (
	// ActionStop freezes the process with SIGSTOP. It is the default response:
	// the implant stops acting, its memory and sockets stay in place for
	// forensics, and a wrong call is undone with SIGCONT.
	ActionStop Action = "stop"
	// ActionKill terminates the process with SIGKILL, which cannot be undone.
	ActionKill Action = "kill"
)

// DefaultRespondScore is the combined score at which a process is treated as
// confirmed even though no single finding is conclusive.
const DefaultRespondScore = 16

// conclusiveClasses are the findings that justify acting without a human.
// Membership is about false positives, not about score. procscan.fileless.deleted
// is deliberately absent: it scores 9 and fires on any program upgraded while it
// runs (measured on the development host, after an npm update), and freezing a
// service for having been upgraded is an outage caused by the defender.
var conclusiveClasses = map[string]bool{
	"procscan.netshell.socket-stdio":    true,
	"procscan.netshell.pipe-relay":      true,
	"procscan.privesc.setuid-shell":     true,
	"procscan.kernel.netshell":          true,
	"procscan.kernel.memfd-exec":        true,
	"procscan.fileless.memfd":           true,
	"procscan.fileless.tmpfs":           true,
	"procscan.masquerade.kthread":       true,
	"procscan.masquerade.fileless-name": true,
	"procscan.masquerade.name-location": true,
}

// cmdlineShell reports argv naming a network shell. It is conclusive only on a
// program that would run it, because argv text is only an action when something
// executes it: 'grep "/dev/tcp" notes.txt' and an editor open on a reverse-shell
// script carry the same text.
func cmdlineShell(class string) bool {
	return class == "procscan.cmdline.reverse-shell" || strings.HasPrefix(class, "procscan.cmdline.netshell.")
}

// Confirmed reports whether p carries enough evidence to act on automatically.
func Confirmed(p Process, minScore int) bool {
	if minScore <= 0 {
		minScore = DefaultRespondScore
	}
	if p.Score >= minScore {
		return true
	}
	for _, f := range p.Findings {
		if conclusiveClasses[f.Class] || (cmdlineShell(f.Class) && (isInterpreter(p.Comm) || isRelayTool(p.Comm))) {
			return true
		}
	}
	return false
}

// Response records what was done, or why nothing was, for one flagged process.
type Response struct {
	PID     int    `json:"pid"`
	Comm    string `json:"comm"`
	Action  Action `json:"action"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
	// Blocked is what the kernel was asked to refuse from now on, and
	// BlockNote says why nothing was.
	Blocked   string `json:"blocked,omitempty"`
	BlockNote string `json:"block_note,omitempty"`
}

// RespondOptions configure Respond.
type RespondOptions struct {
	Action Action
	// MinScore overrides DefaultRespondScore.
	MinScore int
	// ProcRoot overrides "/proc" (for tests).
	ProcRoot string
	// BlockExe, when set, asks the kernel to refuse the process's executable.
	// It receives the /proc path of the exe and runs before the signal, because
	// that path is gone once the process is.
	BlockExe func(procExe string) error
	// signal delivers the action; nil means the real one. A seam for tests.
	signal func(pid int, a Action) error
}

// Respond applies the action to every confirmed process in res and records an
// entry for every flagged one, so a report always says what was left running
// and why. It never touches PID 1, itself, or its own ancestors: stopping the
// shell or supervisor that is running the responder would end the response.
func Respond(res *Result, opts RespondOptions) []Response {
	root := Options{ProcRoot: opts.ProcRoot}.procRoot()
	send := opts.signal
	if send == nil {
		send = signalProcess
	}
	protected := ancestors(root, os.Getpid())

	out := make([]Response, 0, len(res.Flagged))
	for _, p := range res.Flagged {
		r := Response{PID: p.PID, Comm: p.Comm, Action: opts.Action}
		switch {
		case !Confirmed(p, opts.MinScore):
			r.Reason = "not confirmed: left running for a human"
		case p.PID <= 1 || protected[p.PID]:
			r.Reason = "protected: PID 1, the responder, or one of its ancestors"
		case !sameProcess(root, p):
			r.Reason = "process changed since the scan (exited or PID reused)"
		default:
			if opts.BlockExe != nil {
				r.Blocked, r.BlockNote = blockExe(root, p, opts.BlockExe)
			}
			if err := send(p.PID, opts.Action); err != nil {
				r.Reason = err.Error()
			} else {
				r.Applied = true
			}
		}
		out = append(out, r)
	}
	return out
}

// blockExe asks the kernel to refuse p's executable, unless that executable is
// something the host runs. The exe of a reverse shell is usually /bin/bash, and
// refusing that inode would take the host down faster than the attacker could.
func blockExe(root string, p Process, block func(string) error) (blocked, note string) {
	exe := strings.TrimSuffix(p.Exe, " (deleted)")
	switch {
	case exe == "":
		return "", "no readable executable"
	case systemExePath(exe):
		return "", "refused: " + exe + " is in a system path"
	case isInterpreter(baseName(exe)):
		return "", "refused: " + exe + " is an interpreter"
	}
	if err := block(filepath.Join(root, strconv.Itoa(p.PID), "exe")); err != nil {
		return "", err.Error()
	}
	return exe, ""
}

// ancestors returns pid and every process above it.
func ancestors(root string, pid int) map[int]bool {
	seen := map[int]bool{pid: true}
	for cur := pid; cur > 1; {
		var rp rawProc
		parseStatus(filepath.Join(root, strconv.Itoa(cur), "status"), &rp)
		if rp.ppid <= 0 || seen[rp.ppid] {
			break
		}
		seen[rp.ppid] = true
		cur = rp.ppid
	}
	return seen
}

// sameProcess re-reads the identity of p immediately before a signal is sent,
// so a PID recycled since the scan is not hit with a response meant for
// something else. Comm and exe alone are not identity: a reverse shell is usually
// /usr/bin/bash, and so is whichever shell got its PID next. The start time
// cannot repeat on a PID, and comm and exe still catch an exec in place. The
// window that remains is a few system calls wide.
func sameProcess(root string, p Process) bool {
	cur, ok := readProc(root, p.PID)
	return ok && cur.startTicks == p.startTicks && cur.comm == p.Comm && cur.exeTarget == p.Exe
}

func (r Response) String() string {
	if r.Applied {
		s := fmt.Sprintf("%s pid %d (%s)", r.Action, r.PID, r.Comm)
		if r.Blocked != "" {
			s += ", kernel refuses " + r.Blocked
		} else if r.BlockNote != "" {
			s += ", exe not blocked: " + r.BlockNote
		}
		return s
	}
	return fmt.Sprintf("left pid %d (%s): %s", r.PID, r.Comm, r.Reason)
}

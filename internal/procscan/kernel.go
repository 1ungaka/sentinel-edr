package procscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxKernelLog is how much of the guard's log is read, from the end. The log is
// append-only and a long-lived host has no use for last month's PIDs.
const maxKernelLog = 4 << 20

// KernelEvent is one line of the log `cau-kernel enforce netshell --log` writes.
// The field names are that command's contract.
type KernelEvent struct {
	PID    int    `json:"pid"`
	TGID   int    `json:"tgid"`
	UID    int    `json:"uid"`
	Reason string `json:"reason"`
	Denied bool   `json:"denied"`
	Peer   string `json:"peer"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe"`
	// StartTicks is the kernel start time of the process the event is about
	// (field 22 of its /proc/<pid>/stat), which is what lets a matcher tell this
	// event from an older one about a process that has since let go of the PID,
	// and Time is when it was recorded. Both are new in the event schema, so a
	// log written by an older guard carries neither; see Identity.
	StartTicks uint64    `json:"start_ticks,omitempty"`
	Time       time.Time `json:"time,omitempty"`
}

// Identity reports whether the event says which process it happened to. The
// start time cannot repeat on a PID, so an event carrying it can be matched to
// the live process at that PID conclusively; one that carries none — a log
// written before the field existed — can only ever be matched on the name, which
// is what a later process that reused the PID and the name also has.
func (e KernelEvent) Identity() bool { return e.StartTicks != 0 }

// LoadKernelEvents reads the guard's event log. A missing file is not an error:
// it means the guard is not running, and the scan is still valid without it. A
// malformed line is skipped, since a writer killed mid-line leaves one.
func LoadKernelEvents(path string) ([]KernelEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("kernel events: %w", err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > maxKernelLog {
		if _, err := f.Seek(-maxKernelLog, io.SeekEnd); err != nil {
			return nil, fmt.Errorf("kernel events: %w", err)
		}
	}
	var out []KernelEvent
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e KernelEvent
		if json.Unmarshal(s.Bytes(), &e) == nil && e.Reason != "" {
			out = append(out, e)
		}
	}
	return out, s.Err()
}

type kernelIndex map[int][]KernelEvent

func indexKernelEvents(events []KernelEvent, res *Result) kernelIndex {
	idx := kernelIndex{}
	for _, e := range events {
		res.KernelSeen++
		if e.Denied {
			res.KernelRefused++
		}
		idx[e.TGID] = append(idx[e.TGID], e)
	}
	return idx
}

// findings matches events to a live process. A PID alone is not identity: the
// log outlives processes and PIDs are reused, so the name must agree too. A
// refused exec leaves the original program running under the old comm, and an
// allowed one leaves the new program, so either name is a match.
//
// The conclusive match is the start time as well: an event that names the
// process it happened to is only raised against that one, so a process that
// later inherits the PID cannot inherit the finding with it. An event that
// carries no start time — a log written before the schema had one — is still
// reported when the name agrees, but as context about the PID only, because
// nothing about it says the process running here is the process it saw.
func (idx kernelIndex) findings(rp rawProc) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, e := range idx[rp.pid] {
		if seen[e.Reason] {
			continue
		}
		if e.Identity() && e.StartTicks != rp.startTicks {
			continue
		}
		if e.Comm != rp.comm && e.Exe != rp.comm && e.Exe != baseName(strings.TrimSuffix(rp.exeTarget, " (deleted)")) {
			continue
		}
		seen[e.Reason] = true
		verb := "ran"
		if e.Denied {
			verb = "tried to run"
		}
		tech := techUnixShell
		if e.Reason == "memfd-exec" {
			tech = techFileless
		}
		score := 9
		note := ""
		if !e.Identity() {
			// Context, not an attribution: the name agrees and the PID agrees,
			// but nothing ties the event to this process, so it cannot carry
			// a response on its own.
			score = 0
			note = " (no process start time recorded, so this may be an earlier process at the same PID)"
		}
		ev := "uid " + strconv.Itoa(e.UID) + " peer " + e.Peer
		if !e.Time.IsZero() {
			ev += " at " + e.Time.UTC().Format(time.RFC3339)
		}
		out = append(out, Finding{Class: "procscan.kernel." + e.Reason, Score: score, Technique: tech,
			Detail:   "the kernel guard saw this process " + verb + " " + e.Exe + " (" + e.Reason + ")" + note,
			Evidence: strings.TrimSpace(ev)})
	}
	return out
}

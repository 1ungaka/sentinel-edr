package procscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
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
}

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
func (idx kernelIndex) findings(rp rawProc) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, e := range idx[rp.pid] {
		if seen[e.Reason] {
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
		out = append(out, Finding{Class: "procscan.kernel." + e.Reason, Score: 9, Technique: tech,
			Detail:   "the kernel guard saw this process " + verb + " " + e.Exe + " (" + e.Reason + ")",
			Evidence: strings.TrimSpace("uid " + strconv.Itoa(e.UID) + " peer " + e.Peer)})
	}
	return out
}

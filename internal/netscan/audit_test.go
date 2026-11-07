package netscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── the socket cap is applied while the tables are read ──────────────────────

func warningsHave(ws []string, want string) bool {
	for _, w := range ws {
		if strings.Contains(w, want) {
			return true
		}
	}
	return false
}

func countProto(socks []Socket, proto string) int {
	n := 0
	for _, s := range socks {
		if s.Proto == proto {
			n++
		}
	}
	return n
}

// TestRowBudgetStopsAtTheCap: the budget is spent as the tables are read, so a
// table past the cap is cut where it is read rather than retained in full.
func TestRowBudgetStopsAtTheCap(t *testing.T) {
	rows := []Socket{{Inode: "1"}, {Inode: "2"}, {Inode: "3"}}
	b := newRowBudget(2)
	if got := b.take(rows); len(got) != 2 || got[1].Inode != "2" {
		t.Fatalf("take(3) with a budget of 2 = %d rows", len(got))
	}
	if !b.truncated() {
		t.Error("dropping a row past the cap marks the read cut short")
	}
	if got := b.take(rows); len(got) != 0 {
		t.Errorf("a spent budget keeps nothing, got %d rows", len(got))
	}
	if !b.spent() {
		t.Error("a budget of 2 that kept 2 rows is spent")
	}
	// A budget that covers every row keeps them all and says nothing was cut.
	full := newRowBudget(5)
	if got := full.take(rows); len(got) != 3 || full.truncated() {
		t.Errorf("a budget past the rows kept %d, truncated %v", len(got), full.truncated())
	}
	if full.spent() {
		t.Error("a budget past the rows is not spent")
	}
	// A nil budget (the host-table path with no cap in play) keeps everything.
	if got := (*rowBudget)(nil).take(rows); len(got) != 3 {
		t.Errorf("a nil budget must not drop rows, kept %d", len(got))
	}
	if (*rowBudget)(nil).spent() || (*rowBudget)(nil).truncated() {
		t.Error("a nil budget is neither spent nor cut")
	}
}

// TestReadNetTablesStopsPastTheCap: once the budget is spent the remaining
// tables of the namespace are not read at all — the point of the cap is also
// the point where reading stops.
func TestReadNetTablesStopsPastTheCap(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "nc", "/usr/bin/nc", "ns1", "1", "2", "3", "9")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 4444), hexEP(t, "0.0.0.0", 0), "0A", "1")
	f.sock("ns1", "tcp", hexEP(t, "10.0.0.2", 5000), hexEP(t, "203.0.113.9", 443), "01", "2")
	f.sock("ns1", "tcp", hexEP(t, "10.0.0.2", 5001), hexEP(t, "203.0.113.9", 443), "01", "3")
	f.sock("ns1", "udp", hexEP(t, "10.0.0.2", 53000), hexEP(t, "203.0.113.9", 53), "01", "9")
	f.sock("ns1", "packet", "", "", "", "8")
	base := filepath.Join(f.build(), "1", "net")

	got := readNetTables(base, "ns1", newRowBudget(3))
	if len(got) != 3 || countProto(got, "udp") != 0 {
		t.Errorf("a budget of 3 must stop after the tcp table: %d rows, %d udp", len(got), countProto(got, "udp"))
	}
	// Four rows leave the packet table unread too, and say the read was cut.
	four := newRowBudget(4)
	if got = readNetTables(base, "ns1", four); len(got) != 4 || !four.truncated() {
		t.Errorf("a budget of 4 = %d rows, truncated %v", len(got), four.truncated())
	}
	// Everything fits: no truncation, every table read.
	all := newRowBudget(64)
	if got = readNetTables(base, "ns1", all); len(got) != 5 || all.truncated() {
		t.Errorf("five rows must all be read: %d rows, truncated %v", len(got), all.truncated())
	}
}

// TestSocketCapStopsTheScanEarly: a namespace whose table alone is past the cap
// is read to the cap and no further, and the result says it was cut short
// instead of looking like a complete read.
func TestSocketCapStopsTheScanEarly(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	for i := 0; i < maxSockets+8; i++ {
		f.sock("ns1", "tcp", hexEP(t, "10.0.0.1", 40000+i%20000), hexEP(t, "203.0.113.9", 443), "01", strconv.Itoa(100000+i))
	}
	f.sock("ns1", "udp", hexEP(t, "10.0.0.1", 53000), hexEP(t, "203.0.113.9", 53), "01", "999999")

	socks, _, warnings := readSockets(Options{ProcRoot: f.build()})
	if len(socks) != maxSockets {
		t.Fatalf("read %d rows, want the cap (%d)", len(socks), maxSockets)
	}
	if !warningsHave(warnings, truncatedAt(maxSockets)) {
		t.Errorf("a capped read must say so: %v", warnings)
	}
	if countProto(socks, "udp") != 0 {
		t.Errorf("the table behind the cap must not be read: %d udp rows", countProto(socks, "udp"))
	}
}

// ── the per-process fd cap is applied while the directory is read ────────────

// fdTree writes n socket descriptors into a fresh directory.
func fdTree(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < n; i++ {
		link := filepath.Join(dir, fmt.Sprintf("fd%06d", i))
		if err := os.Symlink("socket:["+strconv.Itoa(1000+i)+"]", link); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSocketInodesCapsWhileReading(t *testing.T) {
	// A directory well under the cap: everything read, nothing partial.
	inodes, partial := socketInodes(fdTree(t, 32))
	if partial || len(inodes) != 32 {
		t.Fatalf("32 descriptors: %d inodes, partial %v", len(inodes), partial)
	}
	// Exactly the cap: the whole table was read, so it is not partial.
	inodes, partial = socketInodes(fdTree(t, maxFDs))
	if partial || len(inodes) != maxFDs {
		t.Errorf("exactly maxFDs descriptors: %d inodes, partial %v (want %d, false)", len(inodes), partial, maxFDs)
	}
	// Past the cap: the read stops at the cap and says the rest was not seen.
	inodes, partial = socketInodes(fdTree(t, maxFDs+50))
	if !partial || len(inodes) != maxFDs {
		t.Fatalf("past the cap: %d inodes, partial %v (want %d, true)", len(inodes), partial, maxFDs)
	}
	seen := map[string]bool{}
	for _, ino := range inodes {
		if seen[ino] {
			t.Fatalf("inode %s listed twice", ino)
		}
		seen[ino] = true
	}
	// A directory that cannot be opened is a partial read.
	if _, partial := socketInodes(filepath.Join(t.TempDir(), "gone")); !partial {
		t.Error("an unreadable fd directory must be partial")
	}
}

// ── an unreadable process stays counted as unreadable ────────────────────────

// TestPartialReadSurvivesAReadableFDDirectory: a process whose executable and
// namespace links cannot be read must not have those failures erased by a
// readable descriptor directory, or the scan undercounts what it could not see.
func TestPartialReadSurvivesAReadableFDDirectory(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "777")
	mkdir(t, filepath.Join(base, "fd"))
	write(t, filepath.Join(base, "comm"), "other-user\n")
	symlink(t, "socket:[7001]", filepath.Join(base, "fd", "3"))
	// No exe link, no ns/net link: both leaves are unreadable.

	p := readProc(root, 777)
	if !p.partial {
		t.Error("a process with unreadable exe and ns links is a partial read")
	}
	if len(p.inodes) != 1 || p.inodes[0] != "7001" {
		t.Errorf("the readable descriptors must still be listed: %v", p.inodes)
	}

	// Through the whole reader: one process the scan could not fully read.
	_, unreadable := readProcs(root)
	if unreadable != 1 {
		t.Errorf("unreadable = %d, want 1", unreadable)
	}
}

// ── a shared socket names every holder ──────────────────────────────────────

func TestSharedSocketNamesEveryHolder(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(100, "nginx", "/usr/sbin/nginx", "ns1", "5001")
	f.proc(200, "nc", "/tmp/nc", "ns1", "5001")
	f.proc(300, "socat", "/tmp/socat", "ns1", "5001")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 4444), hexEP(t, "0.0.0.0", 0), "0A", "5001")

	socks, _, warnings := readSockets(Options{ProcRoot: f.build()})
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if len(socks) != 1 {
		t.Fatalf("one kernel socket is one row, got %d", len(socks))
	}
	s := socks[0]
	if s.PID != 100 || s.Comm != "nginx" {
		t.Errorf("the row stays attributed to the lowest PID: %+v", s)
	}
	if len(s.SharedWith) != 2 || s.SharedWith[0] != 200 || s.SharedWith[1] != 300 {
		t.Errorf("the co-holders must be named, in PID order: %v", s.SharedWith)
	}
}

func TestSharedHoldersAreBounded(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	for pid := 100; pid < 100+maxSharedHolders+5; pid++ {
		f.proc(pid, "worker", "/tmp/worker", "ns1", "5001")
	}
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 4444), hexEP(t, "0.0.0.0", 0), "0A", "5001")
	socks, _, _ := readSockets(Options{ProcRoot: f.build()})
	if len(socks) != 1 || len(socks[0].SharedWith) != maxSharedHolders {
		t.Errorf("the holder list is bounded: %d holders on one row", len(socks[0].SharedWith))
	}
}

// ── beacon tracks are per process ───────────────────────────────────────────

// TestBeaconSeparatesProcesses: two processes running the same executable to
// the same peer on the same schedule are two conversations, not one cadence
// pooled across both and pinned on whichever process was sampled last.
func TestBeaconSeparatesProcesses(t *testing.T) {
	h := NewHistory()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := range beaconMinHits {
		at := start.Add(time.Duration(i) * 60 * time.Second)
		h.observe([]Socket{{
			Proto: "tcp", State: stateEstablished, Comm: "agent", Exe: "/home/user/.cache/agent",
			PID: 1001, Local: Endpoint{"192.168.1.20", 40000 + i}, Remote: Endpoint{"203.0.113.9", 443},
		}}, at)
		h.observe([]Socket{{
			Proto: "tcp", State: stateEstablished, Comm: "agent", Exe: "/home/user/.cache/agent",
			PID: 1002, Local: Endpoint{"192.168.1.21", 41000 + i}, Remote: Endpoint{"203.0.113.9", 443},
		}}, at.Add(time.Second))
	}
	got := h.observe(nil, start.Add(time.Hour))
	if len(got) != 2 {
		t.Fatalf("two processes on a schedule must be two findings, got %d: %+v", len(got), got)
	}
	pids := map[int]bool{}
	for _, f := range got {
		if f.Class != "netscan.beacon.periodic" {
			t.Errorf("class %q", f.Class)
		}
		pids[f.PID] = true
	}
	if !pids[1001] || !pids[1002] {
		t.Errorf("each process must carry its own finding: %v", pids)
	}
	// And the key itself separates what it must.
	a := Socket{PID: 1001, Exe: "/x", Remote: Endpoint{"203.0.113.9", 443}}
	if a.beaconKey() == (Socket{PID: 1002, Exe: "/x", Remote: Endpoint{"203.0.113.9", 443}}).beaconKey() {
		t.Error("two PIDs must not share a track key")
	}
	if a.beaconKey() == (Socket{PID: 1001, Exe: "/x", NetNS: "net:[2]", Remote: Endpoint{"203.0.113.9", 443}}).beaconKey() {
		t.Error("two namespaces must not share a track key")
	}
	if a.beaconKey() == (Socket{PID: 1001, Exe: "/x", Remote: Endpoint{"203.0.113.10", 443}}).beaconKey() {
		t.Error("two peers must not share a track key")
	}
}

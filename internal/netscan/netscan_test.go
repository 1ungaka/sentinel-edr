package netscan

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/intel"
)

// hexEP renders an address the way the kernel writes it in /proc/net/tcp: each
// 32-bit word of the address in host byte order, then the port in hex.
func hexEP(t *testing.T, addr string, port int) string {
	t.Helper()
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("hexEP: %q is not an address", addr)
	}
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	var s strings.Builder
	for i := 0; i+4 <= len(b); i += 4 {
		fmt.Fprintf(&s, "%02X%02X%02X%02X", b[i+3], b[i+2], b[i+1], b[i])
	}
	return fmt.Sprintf("%s:%04X", s.String(), port)
}

// fakeProc builds a /proc tree. Every socket this package reads comes from one,
// so a test can stand up a host with a bind shell on it and no privileges.
type fakeProc struct {
	t    *testing.T
	root string
	// rows accumulate per namespace and protocol.
	rows map[string]map[string][]string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	return &fakeProc{t: t, root: t.TempDir(), rows: map[string]map[string][]string{}}
}

// proc declares a process holding socket inodes.
func (f *fakeProc) proc(pid int, comm, exe, netns string, inodes ...string) *fakeProc {
	f.t.Helper()
	base := filepath.Join(f.root, fmt.Sprint(pid))
	mkdir(f.t, filepath.Join(base, "fd"))
	mkdir(f.t, filepath.Join(base, "ns"))
	write(f.t, filepath.Join(base, "comm"), comm+"\n")
	if exe != "" {
		symlink(f.t, exe, filepath.Join(base, "exe"))
	}
	symlink(f.t, "net:["+netns+"]", filepath.Join(base, "ns", "net"))
	for i, ino := range inodes {
		symlink(f.t, "socket:["+ino+"]", filepath.Join(base, "fd", fmt.Sprint(i+3)))
	}
	return f
}

// sock adds a row to a namespace's table. The inode is what ties it to a
// process declared with proc.
func (f *fakeProc) sock(netns, proto, local, remote, state, inode string) *fakeProc {
	f.t.Helper()
	if f.rows[netns] == nil {
		f.rows[netns] = map[string][]string{}
	}
	n := len(f.rows[netns][proto])
	f.rows[netns][proto] = append(f.rows[netns][proto],
		fmt.Sprintf("%4d: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 %s 1 0000000000000000 100 0 0 10 0",
			n, local, remote, state, inode))
	return f
}

// build writes every namespace's tables into the tree of a process that is in
// it, which is where this package reads them from.
func (f *fakeProc) build() string {
	f.t.Helper()
	// Map namespace → the lowest PID in it, the same way the reader does.
	owner := map[string]int{}
	entries, err := os.ReadDir(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, e := range entries {
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join(f.root, e.Name(), "ns", "net"))
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(ns, "net:["), "]")
		if cur, ok := owner[id]; !ok || pid < cur {
			owner[id] = pid
		}
	}
	for ns, tables := range f.rows {
		pid, ok := owner[ns]
		if !ok {
			f.t.Fatalf("namespace %s has rows but no process", ns)
		}
		dir := filepath.Join(f.root, fmt.Sprint(pid), "net")
		mkdir(f.t, dir)
		for proto, rows := range tables {
			header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			write(f.t, filepath.Join(dir, proto), header+strings.Join(rows, "\n")+"\n")
		}
	}
	return f.root
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, body string) {
	t.Helper()
	mkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// etcDir writes a minimal /etc for the resolver and hosts analytics.
func etcDir(t *testing.T, resolv, hosts string) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "resolv.conf"), resolv)
	write(t, filepath.Join(dir, "hosts"), hosts)
	return dir
}

func classes(res *Result) []string {
	var out []string
	for _, f := range res.Flagged {
		out = append(out, f.Class)
	}
	return out
}

func has(res *Result, class string) *Finding {
	for i, f := range res.Flagged {
		if f.Class == class {
			return &res.Flagged[i]
		}
	}
	return nil
}

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:0035", "127.0.0.1", 53},
		{"00000000:0016", "0.0.0.0", 22},
		{"0500000A:115C", "10.0.0.5", 4444},
		{"000080FE00000000FF57A6050E9BFE88:1F90", "fe80::5a6:57ff:88fe:9b0e", 8080},
	}
	for _, c := range cases {
		got, ok := parseEndpoint(c.in)
		if !ok {
			t.Fatalf("parseEndpoint(%q) failed", c.in)
		}
		if got.IP != c.ip || got.Port != c.port {
			t.Errorf("parseEndpoint(%q) = %s:%d, want %s:%d", c.in, got.IP, got.Port, c.ip, c.port)
		}
	}
	for _, bad := range []string{"", "nonsense", "ZZ:0016", "0100007F", "0100007F:ZZZZ", "010000:0016"} {
		if _, ok := parseEndpoint(bad); ok {
			t.Errorf("parseEndpoint(%q) should have failed", bad)
		}
	}
}

// TestOrdinaryHostIsQuiet is the false-positive floor: a host running the
// services every Linux box runs must produce nothing at all. Every detection
// test below adds one hostile process to this same set.
func TestOrdinaryHostIsQuiet(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(100, "sshd", "/usr/sbin/sshd", "ns1", "1001")
	f.proc(200, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "ns1", "1002", "1003")
	f.proc(300, "nginx", "/usr/sbin/nginx", "ns1", "1004")
	f.proc(400, "firefox", "/usr/lib/firefox/firefox", "ns1", "1005", "1006")
	f.proc(500, "curl", "/usr/bin/curl", "ns1", "1007")
	f.proc(600, "postgres", "/usr/lib/postgresql/16/bin/postgres", "ns1", "1008")
	f.proc(700, "python3", "/usr/bin/python3", "ns1", "1009")

	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 22), hexEP(t, "0.0.0.0", 0), "0A", "1001")
	f.sock("ns1", "udp", hexEP(t, "127.0.0.53", 53), hexEP(t, "0.0.0.0", 0), "07", "1002")
	f.sock("ns1", "udp", hexEP(t, "192.168.1.20", 41234), hexEP(t, "192.168.1.1", 53), "01", "1003")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 443), hexEP(t, "0.0.0.0", 0), "0A", "1004")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 55012), hexEP(t, "93.184.216.34", 443), "01", "1005")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 55013), hexEP(t, "140.82.121.4", 443), "01", "1006")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 55014), hexEP(t, "151.101.1.69", 443), "01", "1007")
	f.sock("ns1", "tcp", hexEP(t, "127.0.0.1", 5432), hexEP(t, "0.0.0.0", 0), "0A", "1008")
	// A developer's static file server: an interpreter on a wildcard address.
	// It scores, but not enough to be reported, which is the point.
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 8000), hexEP(t, "0.0.0.0", 0), "0A", "1009")

	etc := etcDir(t, "nameserver 127.0.0.53\nnameserver 192.168.1.1\n", "127.0.0.1 localhost\n::1 localhost\n")
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etc})

	if len(res.Flagged) != 0 {
		t.Fatalf("an ordinary host produced %d findings, want 0: %v", len(res.Flagged), classes(res))
	}
	if res.Sockets != 9 {
		t.Errorf("read %d sockets, want 9", res.Sockets)
	}
	if res.Attributed != 9 {
		t.Errorf("attributed %d sockets, want 9", res.Attributed)
	}
	if res.Listeners != 5 || res.Established != 4 {
		t.Errorf("listeners %d established %d, want 5 and 4", res.Listeners, res.Established)
	}
}

func TestFilelessEgressIsLive(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(900, "bash", "/memfd:payload (deleted)", "ns1", "2001")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 44100), hexEP(t, "203.0.113.9", 443), "01", "2001")

	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	got := has(res, "netscan.egress.fileless")
	if got == nil {
		t.Fatalf("no fileless egress finding: %v", classes(res))
	}
	if !got.Live {
		t.Error("a process with no file on disk holding a socket must assert live state")
	}
	if got.Peer != "203.0.113.9" || got.PID != 900 {
		t.Errorf("finding names peer %q pid %d, want 203.0.113.9 and 900", got.Peer, got.PID)
	}
	if !strings.Contains(got.Detail, "memfd") {
		t.Errorf("detail should say what kind of executable it is: %q", got.Detail)
	}
}

func TestBindShellListener(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(910, "nc", "/usr/bin/nc", "ns1", "2002")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 4444), hexEP(t, "0.0.0.0", 0), "0A", "2002")

	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	if has(res, "netscan.listen.relay-tool") == nil {
		t.Fatalf("a netcat listener must be reported: %v", classes(res))
	}
	if has(res, "netscan.listen.handler-port") == nil {
		t.Errorf("port 4444 should be named as a handler port: %v", classes(res))
	}
	for _, f := range res.Flagged {
		if f.Live {
			t.Errorf("%s asserts live state; a listening tool is an alert, not a confirmed attack", f.Class)
		}
	}
}

func TestKnownBadPeerIsDefinitive(t *testing.T) {
	feed := intel.New()
	if !feed.Add("ip|198.51.100.7|Cobalt Strike team server") {
		t.Fatal("feed did not take the indicator")
	}
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(920, "updater", "/opt/vendor/updater", "ns1", "2003")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 44120), hexEP(t, "198.51.100.7", 8443), "01", "2003")

	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", ""), Intel: feed})
	got := has(res, "netscan.egress.intel")
	if got == nil {
		t.Fatalf("a connection to a listed indicator must be reported: %v", classes(res))
	}
	if !got.Definitive {
		t.Error("a feed match is an exact identification")
	}
	if !strings.Contains(got.Detail, "Cobalt Strike") {
		t.Errorf("the label belongs in the detail: %q", got.Detail)
	}
	if peers := res.Peers(); len(peers) != 1 || peers[0] != "198.51.100.7" {
		t.Errorf("Peers() = %v, want [198.51.100.7]", peers)
	}
}

func TestContainerNamespaceIsRead(t *testing.T) {
	// A process in its own network namespace has its own socket table. Reading
	// only the host's would miss this listener entirely.
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(100, "sshd", "/usr/sbin/sshd", "ns1", "1001")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 22), hexEP(t, "0.0.0.0", 0), "0A", "1001")
	f.proc(2000, "socat", "/tmp/socat", "ns2", "3001")
	f.sock("ns2", "tcp", hexEP(t, "0.0.0.0", 9001), hexEP(t, "0.0.0.0", 0), "0A", "3001")

	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	got := has(res, "netscan.listen.relay-tool")
	if got == nil {
		t.Fatalf("a listener inside a container namespace must be read: %v", classes(res))
	}
	if got.PID != 2000 {
		t.Errorf("attributed to pid %d, want 2000", got.PID)
	}
}

func TestSweepPending(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	var inodes []string
	for i := range sweepPending + 2 {
		inodes = append(inodes, fmt.Sprintf("40%02d", i))
	}
	f.proc(930, "scanner", "/home/user/scanner", "ns1", inodes...)
	for i, ino := range inodes {
		f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 50000+i), hexEP(t, fmt.Sprintf("10.0.0.%d", i+1), 445), "02", ino)
	}
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	got := has(res, "netscan.sweep.pending")
	if got == nil {
		t.Fatalf("connections in flight to many peers must be reported: %v", classes(res))
	}
	if got.PID != 930 {
		t.Errorf("attributed to pid %d, want 930", got.PID)
	}
}

func TestUnattributedSocketIsStillRead(t *testing.T) {
	// Without root most holders are unreadable. A socket whose process could not
	// be read is still in the table and must still be scored, with the report
	// saying plainly that the holder is unknown.
	feed := intel.New()
	feed.Add("ip|198.51.100.7|handler")
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 44130), hexEP(t, "198.51.100.7", 443), "01", "9999")
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", ""), Intel: feed})
	got := has(res, "netscan.egress.intel")
	if got == nil {
		t.Fatalf("want the feed hit even with no holder: %v", classes(res))
	}
	if got.PID != 0 || !strings.Contains(got.Detail, "not readable") {
		t.Errorf("an unattributed socket must say so: pid %d, %q", got.PID, got.Detail)
	}
}

func TestThresholdKeepsWeakEvidenceQuiet(t *testing.T) {
	// A handler port on its own is 3 points: context, not a finding.
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(940, "chrome", "/usr/lib/chromium/chromium", "ns1", "5001")
	f.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 44140), hexEP(t, "203.0.113.50", 9999), "01", "5001")
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	if len(res.Flagged) != 0 {
		t.Fatalf("one weak signal should stay below the threshold: %v", classes(res))
	}
	// The same connection from a binary no package installed adds up and is
	// reported: two weak signals about one process are a finding.
	f2 := newFakeProc(t)
	f2.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f2.proc(941, "nc", "/home/user/.cache/nc", "ns1", "5002")
	f2.sock("ns1", "tcp", hexEP(t, "192.168.1.20", 44141), hexEP(t, "203.0.113.50", 9999), "01", "5002")
	res2 := Scan(Options{ProcRoot: f2.build(), EtcRoot: etcDir(t, "", "")})
	if len(res2.Flagged) < 2 {
		t.Fatalf("a relay tool on a handler port should be reported: %v", classes(res2))
	}
	if res2.Score() < 7 {
		t.Errorf("score %d, want at least 7", res2.Score())
	}
}

func TestExeKind(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/bash":            "",
		"/memfd:payload (deleted)": "memfd",
		"/home/user/app (deleted)": "deleted",
		"/dev/shm/x":               "tmpfs",
		"/tmp/dropper":             "tmpfs",
		"/var/tmp/.hidden/implant": "tmpfs",
		"":                         "",
		"/opt/vendor/agent":        "",
	}
	for in, want := range cases {
		if got := ExeKind(in); got != want {
			t.Errorf("ExeKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUnreadableNamespaceIsNotANamespace is a regression test for a bug the
// development host found: a process whose ns/net link could not be read was
// grouped as a namespace of its own, so the host's socket tables were read a
// second time and every socket on the machine was reported twice. One harmless
// raw socket became two findings that added up past the threshold.
func TestUnreadableNamespaceIsNotANamespace(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1", "1001")
	f.sock("ns1", "tcp", hexEP(t, "0.0.0.0", 22), hexEP(t, "0.0.0.0", 0), "0A", "1001")
	// A process this user may not fully read: comm is there, ns/net is not.
	base := filepath.Join(f.root, "777")
	mkdir(t, filepath.Join(base, "fd"))
	write(t, filepath.Join(base, "comm"), "other-user\n")

	root := f.build()
	socks, _, warnings := readSockets(Options{ProcRoot: root})
	if len(socks) != 1 {
		t.Fatalf("read %d sockets, want 1 (the table must not be read twice): %+v", len(socks), socks)
	}
	if socks[0].PID != 1 {
		t.Errorf("attribution = pid %d, want 1", socks[0].PID)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
}

// TestNoReadableNamespaceFallsBackToTheHostTable: if nothing's namespace can be
// read, the host's own /proc/net is still read, rather than nothing at all.
func TestNoReadableNamespaceFallsBackToTheHostTable(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "500")
	mkdir(t, filepath.Join(base, "fd"))
	write(t, filepath.Join(base, "comm"), "nc\n")
	symlink(t, "/usr/bin/nc", filepath.Join(base, "exe"))
	symlink(t, "socket:[7001]", filepath.Join(base, "fd", "3"))
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write(t, filepath.Join(root, "net", "tcp"), header+
		"   0: "+hexEP(t, "0.0.0.0", 4444)+" "+hexEP(t, "0.0.0.0", 0)+" 0A 00000000:00000000 00:00000000 00000000 1000 0 7001 1 0000 20 4\n")

	res := Scan(Options{ProcRoot: root, EtcRoot: etcDir(t, "", "")})
	if res.Sockets != 1 {
		t.Fatalf("read %d sockets, want 1", res.Sockets)
	}
	got := has(res, "netscan.listen.relay-tool")
	if got == nil || got.PID != 500 {
		t.Fatalf("the listener must still be found and attributed: %v", classes(res))
	}
}

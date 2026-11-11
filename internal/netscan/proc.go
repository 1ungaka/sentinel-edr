package netscan

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/1ungaka/sentinel-edr/internal/parallel"
)

// Caps keep a hostile or very large host bounded. None of them is a security
// boundary: they are the point past which more reading cannot change a verdict.
const (
	maxProcs    = 65536
	maxFDs      = 1024
	maxNetBytes = 16 << 20
	maxSockets  = 1 << 17
	// maxNetNS bounds how many network namespaces are read. A host running
	// hundreds of containers is read up to this many namespaces and then warns,
	// rather than spending the scan on /proc.
	maxNetNS = 256
	// maxSharedHolders bounds how many co-owners of one socket are named in a
	// row. One descriptor passed to a hundred processes is one socket, and the
	// report says who holds it, not a hundred rows.
	maxSharedHolders = 8
)

// TCP states, as /proc/net/tcp writes them.
const (
	stateEstablished = "ESTABLISHED"
	stateSynSent     = "SYN_SENT"
	stateListen      = "LISTEN"
	stateClose       = "CLOSE"
)

var tcpStates = map[string]string{
	"01": stateEstablished, "02": stateSynSent, "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": stateClose,
	"08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": stateListen, "0B": "CLOSING",
}

// Endpoint is one side of a socket.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (e Endpoint) String() string { return hostPort(e.IP, e.Port) }

// Socket is one row of a kernel socket table, with the process that holds it
// when that could be read. PID is 0 when it could not: a socket owned by
// another user's process is visible in the table without root, its holder is
// not, and that is reported as unreadable rather than guessed at.
type Socket struct {
	Proto  string   `json:"proto"`
	State  string   `json:"state"`
	Local  Endpoint `json:"local"`
	Remote Endpoint `json:"remote"`
	UID    int      `json:"uid"`
	Inode  string   `json:"inode"`
	NetNS  string   `json:"netns,omitempty"`
	PID    int      `json:"pid,omitempty"`
	Comm   string   `json:"comm,omitempty"`
	Exe    string   `json:"exe,omitempty"`
	// ExeKind names why the executable is not a normal file on disk: memfd,
	// deleted or tmpfs. It is empty for an ordinary binary.
	ExeKind string `json:"exe_kind,omitempty"`
	// SharedWith names the other processes that hold this same socket: a
	// forked child, or a descriptor another process was handed. The row stays
	// attributed to the lowest PID, which is the one still there after a
	// worker exits; without this the co-owners are invisible, and the socket
	// is reported against one process when several of them hold it.
	SharedWith []int `json:"shared_with,omitempty"`
}

// listening reports whether the socket is waiting for peers. A UDP socket is
// bound rather than listening, so one with no peer counts as a listener: that is
// what a UDP backdoor looks like in the table.
func (s Socket) listening() bool {
	if isCapture(s.Proto) {
		return false // nothing connects to a socket that reads the wire
	}
	if s.State == stateListen {
		return true
	}
	return strings.HasPrefix(s.Proto, "udp") && s.Remote.Port == 0
}

// subject is what this socket's findings are added up against. The process is
// the right subject when it could be read, because several weak signals about
// one program are what a threshold is for. Without a process it is the peer, so
// two findings about one conversation still meet — and failing that the socket
// itself, so unrelated sockets never pool their scores.
func (s Socket) subject() string {
	switch {
	case s.PID > 0:
		return "p:" + strconv.Itoa(s.PID)
	case s.Remote.IP != "" && s.Remote.Port != 0:
		return "n:" + s.Remote.IP
	default:
		return "k:" + s.Proto + ":" + s.Inode
	}
}

// wildcard reports whether the socket is bound to every address, which is what
// separates a service exposed to the network from one bound to loopback.
func (s Socket) wildcard() bool {
	ip := net.ParseIP(s.Local.IP)
	return ip != nil && ip.IsUnspecified()
}

// proc is what one process contributes: its identity and the socket inodes it
// holds.
type proc struct {
	pid     int
	comm    string
	exe     string
	exeKind string
	netns   string
	inodes  []string
	partial bool // some of /proc/<pid> could not be read
}

func procRoot(opts Options) string {
	if opts.ProcRoot != "" {
		return opts.ProcRoot
	}
	return "/proc"
}

func etcRoot(opts Options) string {
	if opts.EtcRoot != "" {
		return opts.EtcRoot
	}
	return "/etc"
}

// readSockets builds the host's socket table, attributed to processes.
//
// Sockets are read per network namespace, not once from the host's /proc/net:
// a process in a container has its own table, and reading only the host's would
// report a container's backdoor as unattributed or miss it entirely. Namespaces
// are identified by the inode behind /proc/<pid>/ns/net, so one read covers
// every process that shares it.
func readSockets(opts Options) (socks []Socket, unreadable int, warnings []string) {
	root := procRoot(opts)
	procs, unreadable := readProcs(root)

	// Group processes by namespace, and map every inode to the processes that
	// hold it. A socket shared by a parent and child (a forked daemon) is
	// attributed to the lowest PID, which is the one that is still there after
	// the worker exits, and the co-owners are named on the row: the child is a
	// process of its own, and reporting the socket against one holder alone
	// hides what the other one is doing with it.
	//
	// A process whose ns/net link could not be read is NOT its own namespace. It
	// is almost always in the host's, and treating the unknown as a namespace of
	// its own would read the host's socket tables a second time and report every
	// socket on the machine twice — measured on the development host, where one
	// raw socket was reported as two.
	byNS := map[string][]*proc{}
	holders := map[string][]*proc{}
	for i := range procs {
		p := &procs[i]
		if p.netns != "" {
			byNS[p.netns] = append(byNS[p.netns], p)
		}
		for _, ino := range p.inodes {
			holders[ino] = append(holders[ino], p)
		}
	}
	// Nothing's namespace could be read, so read the host's own tables once.
	if len(byNS) == 0 {
		budget := newRowBudget(maxSockets)
		for _, s := range readNetTables(filepath.Join(root, "net"), "", budget) {
			attribute(&s, holders)
			socks = append(socks, s)
		}
		if budget.truncated() {
			warnings = append(warnings, truncatedAt(maxSockets))
		}
		sortSockets(socks)
		return socks, unreadable, warnings
	}

	spaces := sortedKeys(byNS)
	if len(spaces) > maxNetNS {
		warnings = append(warnings, "more than "+strconv.Itoa(maxNetNS)+" network namespaces; only the first were read")
		spaces = spaces[:maxNetNS]
	}
	// The row budget is spent as the tables are read, not after they are all in
	// memory: every namespace's tables are up to 16 MiB each, and a host with
	// hundreds of them would allocate all of that before the advertised cap
	// took effect. A namespace whose budget is spent is not read at all.
	budget := newRowBudget(maxSockets)
	tables := make([][]Socket, len(spaces))
	parallel.For(len(spaces), 0, func(i int) {
		if budget.spent() {
			// This namespace's table was not read: what it holds was not seen,
			// which is a partial result and not a clean one.
			budget.cut.Store(true)
			return
		}
		ns := spaces[i]
		// Any process in the namespace sees the whole namespace's table.
		base := filepath.Join(root, strconv.Itoa(byNS[ns][0].pid), "net")
		tables[i] = readNetTables(base, ns, budget)
	})

	for _, t := range tables {
		for _, s := range t {
			if len(socks) >= maxSockets {
				warnings = append(warnings, truncatedAt(maxSockets))
				return socks, unreadable, warnings
			}
			// A holder whose own namespace could not be read may still be the
			// one: the inode is the kernel's, and it is unique across the host.
			attribute(&s, holders)
			socks = append(socks, s)
		}
	}
	if budget.truncated() {
		warnings = append(warnings, truncatedAt(maxSockets))
	}
	sortSockets(socks)
	return socks, unreadable, warnings
}

func truncatedAt(n int) string {
	return "socket table truncated at " + strconv.Itoa(n) + " rows"
}

// attribute stamps a socket row with the process that holds it, and names the
// other holders of the same inode. The row is attributed to the lowest PID
// whose namespace matches the table it was read from; a holder whose namespace
// could not be read is grouped with the host's, which is where it almost
// certainly is.
func attribute(s *Socket, holders map[string][]*proc) {
	for _, p := range holders[s.Inode] {
		if p.netns != s.NetNS && p.netns != "" {
			continue // a socket in one namespace is not held from another
		}
		if s.PID == 0 {
			s.PID, s.Comm, s.Exe, s.ExeKind = p.pid, p.comm, p.exe, p.exeKind
			continue
		}
		if len(s.SharedWith) < maxSharedHolders {
			s.SharedWith = append(s.SharedWith, p.pid)
		}
	}
}

// rowBudget bounds how many socket rows the whole scan keeps. It is maxSockets
// applied while the tables are read: the point past which more reading cannot
// change a verdict is also the point where reading stops, instead of every
// namespace's tables being allocated first and truncated afterwards.
type rowBudget struct {
	left atomic.Int64
	cut  atomic.Bool
}

func newRowBudget(n int) *rowBudget {
	b := &rowBudget{}
	b.left.Store(int64(n))
	return b
}

// take returns as many of rows as the budget still allows and spends them. The
// rows past the cap are dropped here, before they are retained, and record that
// the read was cut short.
func (b *rowBudget) take(rows []Socket) []Socket {
	if b == nil {
		return rows
	}
	for {
		cur := b.left.Load()
		if cur <= 0 {
			if len(rows) > 0 {
				b.cut.Store(true)
			}
			return nil
		}
		n := int64(len(rows))
		if n > cur {
			n = cur
		}
		if b.left.CompareAndSwap(cur, cur-n) {
			if n < int64(len(rows)) {
				b.cut.Store(true)
			}
			return rows[:n]
		}
	}
}

// spent reports whether the cap is reached, so no further table is worth
// reading.
func (b *rowBudget) spent() bool { return b != nil && b.left.Load() <= 0 }

// truncated reports whether the cap dropped rows or stopped a read part-way.
func (b *rowBudget) truncated() bool { return b != nil && b.cut.Load() }

func sortSockets(socks []Socket) {
	sort.SliceStable(socks, func(i, j int) bool {
		if socks[i].PID != socks[j].PID {
			return socks[i].PID < socks[j].PID
		}
		if socks[i].Proto != socks[j].Proto {
			return socks[i].Proto < socks[j].Proto
		}
		return socks[i].Inode < socks[j].Inode
	})
}

// readProcs reads every process's identity and socket inodes. A process that
// exits mid-scan, or one this user may not read, is counted and skipped: a
// partial view is the normal case without root and must never fail the scan.
func readProcs(root string) ([]proc, int) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
			if len(pids) >= maxProcs {
				break
			}
		}
	}
	out := make([]proc, len(pids))
	parallel.For(len(pids), 0, func(i int) { out[i] = readProc(root, pids[i]) })

	procs := make([]proc, 0, len(out))
	unreadable := 0
	for _, p := range out {
		if p.pid == 0 {
			unreadable++
			continue
		}
		if p.partial {
			unreadable++
		}
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].pid < procs[j].pid })
	return procs, unreadable
}

func readProc(root string, pid int) proc {
	base := filepath.Join(root, strconv.Itoa(pid))
	comm := strings.TrimSpace(readLimit(filepath.Join(base, "comm"), 256))
	if comm == "" {
		// Gone, or not ours to read: either way there is nothing to attribute.
		return proc{}
	}
	p := proc{pid: pid, comm: comm}
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.exe, p.exeKind = exe, ExeKind(exe)
	} else {
		p.partial = true
	}
	// The namespace id. Kernel threads have no ns link readable to us; they hold
	// no sockets either, so the empty key groups them harmlessly.
	if ns, err := os.Readlink(filepath.Join(base, "ns", "net")); err == nil {
		p.netns = ns
	} else {
		p.partial = true
	}
	// What the descriptor directory could not say is another partial read, and
	// it must not replace the failures above: a readable fd directory would
	// otherwise erase them and undercount the processes this user cannot read.
	inodes, fdPartial := socketInodes(filepath.Join(base, "fd"))
	p.inodes = inodes
	if fdPartial {
		p.partial = true
	}
	return p
}

// socketInodes lists the socket inodes a process holds. It returns partial=true
// when the directory could not be read at all — which without root is most other
// users' processes — or when the descriptor count reached maxFDs, past which
// more inodes cannot change a verdict.
func socketInodes(dir string) (inodes []string, partial bool) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, true
	}
	defer f.Close()
	// The directory is paged a cap at a time rather than listed whole: a
	// process with a very large descriptor table is not read past maxFDs, which
	// os.ReadDir would do before the cap could be applied.
	seen := 0
	for seen < maxFDs {
		want := maxFDs - seen
		entries, rerr := f.ReadDir(want)
		for _, e := range entries {
			seen++
			t, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil {
				continue // closed between the listing and the read
			}
			if ino, ok := strings.CutPrefix(t, "socket:["); ok {
				inodes = append(inodes, strings.TrimSuffix(ino, "]"))
			}
		}
		switch {
		case errors.Is(rerr, io.EOF):
			return inodes, false // the end of the directory
		case rerr != nil:
			return inodes, true // the listing stopped early: the rest is unknown
		case len(entries) < want:
			return inodes, false // a short page is the end of the directory
		}
	}
	// The cap is reached: one more name says whether the descriptor table holds
	// more than was read, which is exactly what partial claims.
	if _, more := f.ReadDir(1); more == nil {
		return inodes, true
	}
	return inodes, false
}

// readNetTables reads one namespace's socket tables: the four IP ones, the two
// raw ones, and the packet sockets that read the wire itself. A non-nil budget
// bounds how many rows this namespace may keep, so reading stops at the
// host-wide cap instead of after every namespace's tables are in memory.
func readNetTables(base, ns string, budget *rowBudget) []Socket {
	var out []Socket
	add := func(socks []Socket) {
		for _, s := range budget.take(socks) { // audit:ok the copy is the point: each socket is labelled and appended
			s.NetNS = ns
			out = append(out, s)
		}
	}
	// read applies the budget before a table is read at all: past the cap the
	// table is not opened, and the fact that it was not read is what makes the
	// result partial — not only the rows a table lost past it.
	read := func(proto string) {
		if budget.spent() {
			budget.cut.Store(true)
			return
		}
		add(parseNetTable(readLimit(filepath.Join(base, proto), maxNetBytes), proto))
	}
	// readPacket reads /proc/net/packet, which has a layout of its own: sk,
	// RefCnt, Type, Proto, Iface and the rest, with no local or remote
	// endpoint for parseNetTable to decode. Read through it every row is
	// dropped, which is how a sniffer on the wire disappears from the report.
	readPacket := func() {
		if budget.spent() {
			budget.cut.Store(true)
			return
		}
		add(parsePacketTable(readLimit(filepath.Join(base, protoPacket), maxNetBytes)))
	}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6", protoRaw, protoRaw6} {
		read(proto)
	}
	readPacket()
	return out
}

// parseNetTable reads a /proc/net/{tcp,tcp6,udp,udp6} table.
//
//	sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
//	 0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 101 0 25879 1 …
func parseNetTable(text, proto string) []Socket {
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return nil
	}
	out := make([]Socket, 0, len(lines)-1)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		local, lok := parseEndpoint(f[1])
		remote, rok := parseEndpoint(f[2])
		if !lok || !rok {
			continue
		}
		state, ok := tcpStates[strings.ToUpper(f[3])]
		if !ok {
			state = "UNKNOWN"
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			uid = -1
		}
		out = append(out, Socket{
			Proto: proto, State: state, Local: local, Remote: remote,
			UID: uid, Inode: f[9],
		})
	}
	return out
}

// parseEndpoint decodes the kernel's hex ADDR:PORT. The address is a run of
// 32-bit words in host order (little-endian on every platform this ships on),
// so each word is reversed before it is read as bytes.
func parseEndpoint(s string) (Endpoint, bool) {
	addr, port, ok := strings.Cut(s, ":")
	if !ok {
		return Endpoint{}, false
	}
	raw, err := hex.DecodeString(addr)
	if err != nil || len(raw) == 0 || len(raw)%4 != 0 {
		return Endpoint{}, false
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return Endpoint{}, false
	}
	ip := net.IP(raw)
	if ip.To4() != nil {
		ip = ip.To4()
	}
	return Endpoint{IP: ip.String(), Port: int(p)}, true
}

// tmpfsPrefixes are filesystems that do not survive a reboot. A program running
// from one left nothing behind to find later.
var tmpfsPrefixes = []string{"/dev/shm/", "/run/shm/", "/tmp/", "/var/tmp/"}

// ExeKind names why an executable is not an ordinary file on disk: "memfd" for
// an anonymous in-memory file, "deleted" for an unlinked inode, "tmpfs" for a
// path that a reboot erases. It is empty for an ordinary binary.
func ExeKind(exe string) string {
	switch {
	case exe == "":
		return ""
	case strings.HasPrefix(exe, "/memfd:"), strings.Contains(exe, "memfd:"):
		return "memfd"
	case strings.HasSuffix(exe, " (deleted)"):
		return "deleted"
	}
	for _, p := range tmpfsPrefixes {
		if strings.HasPrefix(exe, p) {
			return "tmpfs"
		}
	}
	return ""
}

// TrimDeleted strips the kernel's " (deleted)" suffix, so the path can be
// matched and linked.
func TrimDeleted(p string) string { return strings.TrimSuffix(p, " (deleted)") }

func readLimit(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, int64(max)))
	return string(b)
}

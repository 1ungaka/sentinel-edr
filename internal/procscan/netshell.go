package procscan

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const techUnixShell = "T1059.004" // Command and Scripting Interpreter: Unix Shell

// interpreters are the programs a remote operator drives through a socket.
// Matched on comm, with the version suffix python and friends carry trimmed.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"fish": true, "csh": true, "tcsh": true, "busybox": true,
	"python": true, "perl": true, "ruby": true, "php": true, "lua": true,
}

// relayTools carry a shell's bytes across the network when the shell itself
// holds no socket.
var relayTools = map[string]bool{
	"nc": true, "ncat": true, "netcat": true, "nc.openbsd": true, "nc.traditional": true,
	"socat": true, "telnet": true, "openssl": true, "curl": true, "rcat": true, "busybox": true,
}

func isRelayTool(comm string) bool { return relayTools[comm] }

const maxFDsChecked = 1024

// holdsTCP reports whether a process owns an established TCP connection.
func holdsTCP(base string) bool {
	entries, err := os.ReadDir(filepath.Join(base, "fd"))
	if err != nil {
		return false
	}
	conns := tcpConnections(base)
	for i, e := range entries {
		if i >= maxFDsChecked {
			break
		}
		if ino := socketInode(filepath.Join(base, "fd", e.Name())); ino != "" {
			if _, ok := conns[ino]; ok {
				return true
			}
		}
	}
	return false
}

// markPipeRelays finds the `mkfifo | sh | nc` shape: an interpreter whose stdout
// is the stdin of a network tool holding a live connection, with its own stdin
// also a pipe. Both halves matter. `curl x | sh` feeds a shell from the network
// but its stdout stays a terminal, and `./report.sh | nc host` ships output but
// its stdin is not fed from anywhere.
func markPipeRelays(root string, procs []rawProc) {
	feeds := map[string]string{}
	for i := range procs {
		p := &procs[i]
		if !isRelayTool(p.comm) || !strings.HasPrefix(p.stdin, "pipe:[") {
			continue
		}
		if holdsTCP(filepath.Join(root, strconv.Itoa(p.pid))) {
			feeds[p.stdin] = p.comm + " pid " + strconv.Itoa(p.pid)
		}
	}
	if len(feeds) == 0 {
		return
	}
	for i := range procs {
		p := &procs[i]
		if isInterpreter(p.comm) && p.stdinFIFO {
			if tool, ok := feeds[p.stdout]; ok {
				p.pipeRelay = tool
			}
		}
	}
}

func isInterpreter(comm string) bool {
	return interpreters[comm] || interpreters[strings.TrimRight(comm, "0123456789.")]
}

// stdioPeer reports the TCP peer an interpreter's stdin and stdout are both
// wired to, or "" when they are not. That wiring is what a reverse or bind
// shell is, whatever its argv claims, so it survives a renamed or empty command
// line. It reads /proc/<pid>/fd/{0,1}, which needs the same uid or root.
//
// Only a real TCP connection counts. Harnesses and IDEs routinely run shells
// over AF_UNIX socketpairs, which also read back as "socket:[n]" (measured on
// the development host), so the inode is resolved against the process's own
// network namespace rather than trusted from the link text.
func stdioPeer(base string) string {
	in := socketInode(filepath.Join(base, "fd", "0"))
	out := socketInode(filepath.Join(base, "fd", "1"))
	if in == "" || out == "" {
		return ""
	}
	conns := tcpConnections(base)
	if peer, ok := conns[in]; ok {
		if _, ok := conns[out]; ok {
			return peer
		}
	}
	return ""
}

func socketInode(link string) string {
	t, err := readlink(link)
	if err != nil {
		return ""
	}
	if s, ok := strings.CutPrefix(t, "socket:["); ok {
		return strings.TrimSuffix(s, "]")
	}
	return ""
}

// tcpConnections maps socket inode to remote endpoint for the ESTABLISHED
// connections visible from a process's network namespace.
func tcpConnections(base string) map[string]string {
	conns := map[string]string{}
	for _, name := range []string{"tcp", "tcp6"} {
		lines := strings.Split(readSmall(filepath.Join(base, "net", name), maxMapsBytes), "\n")
		if len(lines) < 2 {
			continue
		}
		for _, line := range lines[1:] {
			if inode, peer := parseTCPLine(line); inode != "" {
				conns[inode] = peer
			}
		}
	}
	return conns
}

// parseTCPLine reads one /proc/net/tcp row, returning its inode and remote
// endpoint when the connection is ESTABLISHED.
func parseTCPLine(line string) (inode, peer string) {
	const established = "01"
	f := strings.Fields(line)
	if len(f) < 10 || f[3] != established {
		return "", ""
	}
	return f[9], decodeEndpoint(f[2])
}

// decodeEndpoint renders the kernel's hex ADDR:PORT, whose address is a run of
// host-order (little-endian on the platforms this ships on) 32-bit words.
func decodeEndpoint(s string) string {
	addr, port, ok := strings.Cut(s, ":")
	if !ok {
		return s
	}
	raw, err := hex.DecodeString(addr)
	if err != nil || len(raw)%4 != 0 {
		return s
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	var p int
	if _, err := fmt.Sscanf(port, "%X", &p); err != nil {
		return s
	}
	return net.JoinHostPort(net.IP(raw).String(), fmt.Sprint(p))
}

package procscan

import (
	"os"
	"path/filepath"
	"testing"
)

// splitProc builds /proc/<pid> for an interpreter whose stdin and stdout are two
// different established TCP connections.
func splitProc(t *testing.T, root, pid, comm, inInode, outInode, tcp string) {
	t.Helper()
	base := filepath.Join(root, pid)
	for _, d := range []string{"fd", "net"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"comm": comm + "\n", "status": "PPid:\t1\nTracerPid:\t0\n", "net/tcp": tcp,
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("socket:["+inInode+"]", filepath.Join(base, "fd", "0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+outInode+"]", filepath.Join(base, "fd", "1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/"+comm, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
}

func tcpRow(inode, peer string) string {
	// peer as the kernel writes it: hex little-endian address, hex port.
	return "   0: 0100007F:A0B4 " + peer + " 01 00000000:00000000 00:00000000 00000000  1000        0 " + inode + " 1 0000 20 4\n"
}

func TestStdioWiringNeedsOnePeerOnBothDescriptors(t *testing.T) {
	root := t.TempDir()
	// Both descriptors on one connection: 192.168.0.2:4444.
	both := tcpHeader + tcpRow("777", "0200A8C0:115C")
	// Two different connections: 192.168.0.2:4444 in, 203.0.113.9:443 out.
	split := tcpHeader + tcpRow("777", "0200A8C0:115C") + tcpRow("888", "097100CB:01BB")

	splitProc(t, root, "100", "bash", "777", "777", both)
	splitProc(t, root, "101", "bash", "777", "888", split)

	if peer, in, out := stdioWiring(filepath.Join(root, "100")); peer != "192.168.0.2:4444" || in != peer || out != peer {
		t.Errorf("one peer on both: peer=%q in=%q out=%q", peer, in, out)
	}
	if peer, in, out := stdioWiring(filepath.Join(root, "101")); peer != "" || in != "192.168.0.2:4444" || out != "203.0.113.9:443" {
		t.Errorf("two peers: peer=%q in=%q out=%q, want no peer and both endpoints", peer, in, out)
	}
	// A single descriptor, or one that is not TCP at all, is not wiring.
	if peer, _, _ := stdioWiring(filepath.Join(root, "404")); peer != "" {
		t.Errorf("an absent process reported peer %q", peer)
	}
}

// The finding: an interpreter whose input and output go to different peers must
// not be reported as the reverse or bind shell that stops a process.
func TestSplitStdioIsReportedButNeverConclusive(t *testing.T) {
	root := t.TempDir()
	split := tcpHeader + tcpRow("777", "0200A8C0:115C") + tcpRow("888", "097100CB:01BB")
	splitProc(t, root, "200", "bash", "777", "888", split)

	res := Scan(Options{ProcRoot: root})
	if len(res.Flagged) != 0 {
		t.Fatalf("a split-stdio shell alone must not even be flagged: %+v", res.Flagged)
	}

	// With the split as the only evidence, nothing about the process may be
	// acted on: the class is not in conclusiveClasses and the score is context.
	p := detect(rawProc{comm: "bash", exeTarget: "/usr/bin/bash", stdioSplit: "192.168.0.2:4444 -> 203.0.113.9:443"}, DefaultThreshold)
	if scoreHas(p, "procscan.netshell.socket-stdio") {
		t.Fatalf("the conclusive class fired on two different peers: %+v", p)
	}
	if !scoreHas(p, "procscan.netshell.stdio-split") {
		t.Fatalf("the split itself must still be reported: %+v", p)
	}
	if Confirmed(p, 0) {
		t.Errorf("a split-stdio shell was confirmed: %+v", p)
	}

	// And the same wiring, when both descriptors really are one connection, is
	// still the conclusive finding it always was.
	same := detect(rawProc{comm: "bash", exeTarget: "/usr/bin/bash", stdioPeer: "192.168.0.2:4444"}, DefaultThreshold)
	if !scoreHas(same, "procscan.netshell.socket-stdio") || !Confirmed(same, 0) {
		t.Fatalf("one peer on both descriptors must still be a shell: %+v", same)
	}
}

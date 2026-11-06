package netscan

import (
	"fmt"
	"path/filepath"
	"testing"
)

// packetTable writes a /proc/net/packet into the namespace owner's tree.
func (f *fakeProc) packet(t *testing.T, pid int, inode string, proto int, sockType int) *fakeProc {
	t.Helper()
	dir := filepath.Join(f.root, fmt.Sprint(pid), "net")
	mkdir(t, dir)
	body := "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n" +
		fmt.Sprintf("ffff9a1 3      %d    %04x   2     1 0      0      %s\n", sockType, proto, inode)
	write(t, filepath.Join(dir, "packet"), body)
	return f
}

func TestParsePacketTable(t *testing.T) {
	body := "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n" +
		"ffff9a1 3      3    0003   2     1 0      1000   4242\n" +
		"ffff9a2 3      2    0806   2     1 0      0      4243\n" +
		"short line\n"
	got := parsePacketTable(body)
	if len(got) != 2 {
		t.Fatalf("parsed %d rows, want 2: %+v", len(got), got)
	}
	if got[0].Inode != "4242" || got[0].Local.Port != ethPAll || got[0].UID != 1000 {
		t.Errorf("first row = %+v", got[0])
	}
	if got[1].Local.Port != 0x0806 {
		t.Errorf("second row's ethertype = %#04x, want 0x0806", got[1].Local.Port)
	}
	if n := parsePacketTable(""); n != nil {
		t.Errorf("an empty table should read as nothing, got %+v", n)
	}
}

// A packet socket bound to every ethertype receives all traffic the interface
// sees. From a binary no package installed that is the whole finding; from
// tcpdump it is context that needs a second layer.
func TestPacketSocketSniffer(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(950, "update", "/dev/shm/update", "ns1", "4242")
	f.packet(t, 1, "4242", ethPAll, 3)
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})

	got := has(res, "netscan.capture.packet-socket")
	if got == nil {
		t.Fatalf("a sniffer must be reported: %v", classes(res))
	}
	if got.Score != 8 || got.PID != 950 {
		t.Errorf("finding = %+v, want score 8 for a binary no package installed", *got)
	}
	if got.Technique != techSniffing {
		t.Errorf("technique %q, want %q", got.Technique, techSniffing)
	}
	// It is also a process with no file on disk, which is live state and is
	// reported as such — but never as a *listener*: nothing connects to a
	// packet socket.
	if has(res, "netscan.listen.fileless") != nil {
		t.Error("a packet socket is not a listener and must not be reported as one")
	}
	fileless := has(res, "netscan.capture.fileless")
	if fileless == nil || !fileless.Live {
		t.Fatalf("a sniffer with no file on disk must assert live state: %v", classes(res))
	}
}

func TestPackagedSnifferIsContextOnly(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(951, "tcpdump", "/usr/bin/tcpdump", "ns1", "4242")
	f.packet(t, 1, "4242", ethPAll, 3)
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	if len(res.Flagged) != 0 {
		t.Fatalf("tcpdump scores 4, below the threshold, and must not alert alone: %v", classes(res))
	}
}

func TestFilteredPacketSocketIsBarelyAMention(t *testing.T) {
	// A DHCP client binds a packet socket to one ethertype. Flagging that would
	// flag address configuration on every host.
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(952, "dhclient", "/usr/sbin/dhclient", "ns1", "4243")
	f.packet(t, 1, "4243", 0x0806, 2)
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})
	if len(res.Flagged) != 0 {
		t.Fatalf("a filtered packet socket must stay quiet: %v", classes(res))
	}
}

func TestRawSocket(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(960, "ping", "/usr/bin/ping", "ns1", "5001")
	f.proc(961, "beacon", "/tmp/.x/beacon", "ns1", "5002")
	f.sock("ns1", "raw", hexEP(t, "0.0.0.0", 1), hexEP(t, "0.0.0.0", 0), "07", "5001")
	f.sock("ns1", "raw", hexEP(t, "0.0.0.0", 1), hexEP(t, "203.0.113.9", 0), "07", "5002")
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "", "")})

	// ping scores 3 and stays quiet; the implant in /tmp does not.
	raw := has(res, "netscan.capture.raw-socket")
	if raw == nil {
		t.Fatalf("a raw socket from a binary no package installed must be reported: %v", classes(res))
	}
	if raw.PID != 961 {
		t.Errorf("attributed to pid %d, want 961 (ping is context only)", raw.PID)
	}
	if raw.Technique != techNonAppL {
		t.Errorf("technique %q, want %q", raw.Technique, techNonAppL)
	}
	for _, f := range res.Flagged {
		if f.PID == 960 {
			t.Errorf("ping was reported: %+v", f)
		}
	}
}

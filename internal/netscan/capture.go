package netscan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/procscan"
)

// Protocols that are not a conversation with a peer. They are read from the
// same /proc directory and carry the same inode, so they are attributed to a
// process exactly like a TCP socket, but nothing about a local or remote port
// applies to them and the ordinary analytics skip them.
const (
	protoRaw    = "raw"
	protoRaw6   = "raw6"
	protoPacket = "packet"
)

// ATT&CK.
const (
	techSniffing = "T1040" // Network Sniffing
	techNonAppL  = "T1095" // Non-Application Layer Protocol
)

// ethPAll is ETH_P_ALL: an AF_PACKET socket bound to it receives every frame
// on the interface. One bound to a specific protocol is how a DHCP client and
// an ARP tool work, which is why the two are scored differently.
const ethPAll = 0x0003

func isCapture(proto string) bool {
	switch proto {
	case protoRaw, protoRaw6, protoPacket:
		return true
	}
	return false
}

// parsePacketTable reads /proc/net/packet, which has a layout of its own.
//
//	sk       RefCnt Type Proto  Iface R Rmem   User   Inode
//	ffff9... 3      3    0003   2     1 0      0      34567
//
// Type 3 is SOCK_RAW and 2 is SOCK_DGRAM; Proto is the hex ethertype the socket
// is bound to.
func parsePacketTable(text string) []Socket {
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return nil
	}
	out := make([]Socket, 0, len(lines)-1)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		proto, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		if err != nil {
			uid = -1
		}
		out = append(out, Socket{
			Proto: protoPacket, State: "CAPTURE", UID: uid, Inode: f[8],
			// Local.Port carries the bound ethertype: there is no port on a
			// packet socket, and this is what the analytic reads.
			Local: Endpoint{Port: int(proto)},
		})
	}
	return out
}

// captureFindings scores a socket that reads the wire rather than talking to a
// peer.
//
// A packet socket bound to every ethertype receives all traffic the interface
// sees, which is credential harvesting and reconnaissance (T1040). The honest
// complication is that this is also exactly what tcpdump does, so a program a
// package installed scores low enough to need corroboration while one no
// package installed does not. A packet socket bound to a single ethertype is
// how a DHCP client works and is barely worth a mention.
//
// Provenance weighs more than the kind of socket here, and that was measured
// rather than assumed. These classes first shipped scoring the socket: a raw
// socket was 3 and a filtered packet socket 2 whoever held them. On a stock
// host read as root, NetworkManager holds one of each — a raw socket for
// ICMPv6 and a packet socket for ARP — and those two add up to exactly the
// reporting threshold, so a system daemon doing its job was a reported finding.
// Unprivileged runs had hidden it, because an unattributed socket has no
// executable to group by. The scores below put the weight on who holds the
// socket, which is the discriminator the rest of this package already uses.
func captureFindings(s Socket) []Finding {
	exe := TrimDeleted(s.Exe)
	system := exe == "" || procscan.SystemPath(exe)
	at := func(f Finding) Finding {
		f.PID, f.Exe, f.subj = s.PID, exe, s.subject()
		return f
	}
	var out []Finding
	// A process with no file on disk is live state whatever kind of socket it
	// holds, and a sniffer or a raw-socket channel is no exception. The same
	// class the conversation analytics raise is raised here, so the correlator
	// and the response policy see one rule rather than two.
	if s.ExeKind != "" {
		out = append(out, at(Finding{
			Class: "netscan.capture.fileless", Score: 9, Technique: techFileless + "," + techSniffing, Live: true,
			Detail: fmt.Sprintf("%s (%s executable, nothing on disk) holds a %s socket, reading or writing the wire directly",
				s.procName(), s.ExeKind, s.Proto),
			Evidence: s.Exe,
		}))
	}
	switch s.Proto {
	case protoPacket:
		if s.Local.Port != ethPAll {
			// Inventory, for a packaged binary: address configuration is what
			// these are for. Measured on a stock host, NetworkManager and
			// wpa_supplicant hold three between them.
			score := 1
			if !system {
				score = 3
			}
			return append(out, at(Finding{
				Class: "netscan.capture.packet-socket-filtered", Score: score, Technique: techSniffing,
				Detail: fmt.Sprintf("%s holds a packet socket bound to ethertype 0x%04x, which is how address "+
					"configuration and ARP tools work", s.procName(), s.Local.Port),
				Evidence: fmt.Sprintf("AF_PACKET proto 0x%04x", s.Local.Port),
			}))
		}
		score := 4
		if !system {
			score = 8
		}
		return append(out, at(Finding{
			Class: "netscan.capture.packet-socket", Score: score, Technique: techSniffing,
			Detail: fmt.Sprintf("%s holds a packet socket bound to every ethertype: it receives all traffic "+
				"the interface sees, credentials included", s.procName()),
			Evidence: "AF_PACKET proto 0x0003 (ETH_P_ALL)",
		}))
	case protoRaw, protoRaw6:
		// A raw IP socket builds its own packets, which is a covert channel's
		// requirement — and also how ping, traceroute and every network
		// management daemon work. For a packaged binary this is inventory.
		score := 2
		if !system {
			score = 6
		}
		return append(out, at(Finding{
			Class: "netscan.capture.raw-socket", Score: score, Technique: techNonAppL,
			Detail: fmt.Sprintf("%s holds a raw IP socket, which sends and receives packets the kernel's own "+
				"protocols do not account for", s.procName()),
			Evidence: s.Proto + " socket, peer " + orNone(s.Remote.IP),
		}))
	}
	return out
}

func orNone(s string) string {
	if s == "" || s == "0.0.0.0" || s == "::" {
		return "unbound"
	}
	return s
}

package netscan

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
)

const maxNeighbours = 65536

// Neighbour is one row of the kernel's ARP cache.
type Neighbour struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Device string `json:"device"`
	Flags  string `json:"flags"`
}

// Neighbours reads /proc/net/arp.
//
//	IP address       HW type   Flags   HW address          Mask  Device
//	192.168.1.1      0x1       0x2     aa:bb:cc:dd:ee:ff   *     eth0
func Neighbours(procRoot string) []Neighbour {
	lines := strings.Split(readLimit(filepath.Join(procRoot, "net", "arp"), maxNetBytes), "\n")
	if len(lines) < 2 {
		return nil
	}
	var out []Neighbour
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if net.ParseIP(f[0]) == nil {
			continue
		}
		mac := strings.ToLower(f[3])
		if mac == "00:00:00:00:00:00" {
			continue // an incomplete entry: the neighbour never answered
		}
		out = append(out, Neighbour{IP: f[0], MAC: mac, Flags: f[2], Device: f[5]})
		if len(out) >= maxNeighbours {
			break
		}
	}
	return out
}

// Gateways are the next hops the host sends everything through: the IPv4
// default routes from /proc/net/route and the IPv6 ones from
// /proc/net/ipv6_route. They are what a machine-made block must never cut off,
// and what an adversary-in-the-middle has to own.
func Gateways(procRoot string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	// /proc/net/route: Iface Destination Gateway Flags … , all little-endian hex.
	lines := strings.Split(readLimit(filepath.Join(procRoot, "net", "route"), maxNetBytes), "\n")
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] == "Destination" {
			continue
		}
		if f[1] != "00000000" {
			continue // not a default route
		}
		if ip, ok := leHexIP(f[2]); ok && !ip.IsUnspecified() {
			add(ip.String())
		}
	}
	// /proc/net/ipv6_route: dest prefixlen src srclen nexthop metric … , big-endian hex.
	for _, line := range strings.Split(readLimit(filepath.Join(procRoot, "net", "ipv6_route"), maxNetBytes), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[1] != "00" {
			continue // only the ::/0 default
		}
		if raw, err := hex.DecodeString(f[4]); err == nil && len(raw) == 16 {
			if ip := net.IP(raw); !ip.IsUnspecified() {
				add(ip.String())
			}
		}
	}
	return out
}

// leHexIP decodes the 32-bit little-endian hex the IPv4 route table uses.
func leHexIP(s string) (net.IP, bool) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 4 {
		return nil, false
	}
	return net.IPv4(raw[3], raw[2], raw[1], raw[0]), true
}

// neighbourFindings audits the host's view of the local segment.
//
// Honesty first: one host cannot verify a switching fabric. What it can see is
// its own neighbour table, and two things in it are worth saying out loud — the
// default gateway's hardware address changing under it, and one hardware
// address claiming the gateway and something else as well. Both have innocent
// explanations (a router failover, a VRRP pair, a hypervisor bridge), so
// neither asserts live state: they are alerts that need a second layer or a
// human, which is what the correlator enforces.
func neighbourFindings(opts Options) []Finding {
	root := procRoot(opts)
	neigh := Neighbours(root)
	if len(neigh) == 0 {
		return nil
	}
	gateways := map[string]bool{}
	for _, g := range Gateways(root) {
		gateways[g] = true
	}

	byMAC := map[string][]string{}
	for _, n := range neigh {
		byMAC[n.MAC] = append(byMAC[n.MAC], n.IP)
	}

	var out []Finding
	if opts.History != nil {
		out = append(out, opts.History.churn(neigh, gateways)...)
	}
	for _, mac := range sortedKeys(byMAC) {
		ips := byMAC[mac]
		if len(ips) < 2 {
			continue
		}
		var gw []string
		for _, ip := range ips {
			if gateways[ip] {
				gw = append(gw, ip)
			}
		}
		if len(gw) == 0 {
			continue // a router answering for several addresses: proxy ARP, not a signal
		}
		sort.Strings(ips)
		out = append(out, Finding{
			Class: "netscan.arp.gateway-shared", Score: 5, Technique: techARPPoison,
			Detail: fmt.Sprintf("%s answers for the default gateway %s and %s besides: one machine holding the gateway's "+
				"address and another is what an adversary-in-the-middle looks like from here",
				mac, strings.Join(gw, ", "), plural(len(ips)-len(gw), "other address", "other addresses")),
			Evidence: mac + " → " + strings.Join(firstN(ips, 8), ", "),
		})
	}
	return out
}

// churn compares the neighbour table with the last sample and reports a gateway
// whose hardware address moved.
func (h *History) churn(neigh []Neighbour, gateways map[string]bool) []Finding {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Finding
	for _, n := range neigh {
		prev, had := h.arp[n.IP]
		if len(h.arp) < maxNeighbours {
			h.arp[n.IP] = n.MAC
		}
		if !had || prev == n.MAC || !gateways[n.IP] {
			continue
		}
		out = append(out, Finding{
			Class: "netscan.arp.gateway-churn", Score: 7, Technique: techARPPoison,
			Detail: fmt.Sprintf("the default gateway %s changed hardware address from %s to %s between samples: "+
				"everything this host sends off the segment now goes to a different machine", n.IP, prev, n.MAC),
			Evidence: n.IP + ": " + prev + " → " + n.MAC + " on " + n.Device,
		})
	}
	return out
}

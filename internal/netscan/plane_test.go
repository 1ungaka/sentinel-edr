package netscan

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/intel"
)

func TestResolvers(t *testing.T) {
	etc := etcDir(t, "# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver 1.1.1.1 ; trailing\nnameserver nonsense\nsearch example.com\n", "")
	got := Resolvers(etc)
	want := []string{"127.0.0.53", "1.1.1.1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Resolvers = %v, want %v", got, want)
	}
	if r := Resolvers(filepath.Join(t.TempDir(), "nothing")); len(r) != 0 {
		t.Errorf("a missing resolv.conf must read as no resolvers, got %v", r)
	}
}

func TestResolverFindings(t *testing.T) {
	proc := newFakeProc(t).proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1").build()

	// Local and documented public resolvers are how hosts are configured.
	quiet := Scan(Options{ProcRoot: proc, EtcRoot: etcDir(t, "nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n", "")})
	if len(quiet.Flagged) != 0 {
		t.Fatalf("an ordinary resolver configuration must be quiet: %v", classes(quiet))
	}

	// One nobody recognises answers every name this host looks up.
	res := Scan(Options{ProcRoot: proc, EtcRoot: etcDir(t, "nameserver 203.0.113.44\n", "")})
	got := has(res, "netscan.resolver.unexpected")
	if got == nil {
		t.Fatalf("an unexpected nameserver must be reported: %v", classes(res))
	}
	if got.Peer != "203.0.113.44" {
		t.Errorf("peer %q, want 203.0.113.44", got.Peer)
	}
	if got.Technique != "" {
		t.Errorf("this row is deliberately unmapped to ATT&CK, got %q", got.Technique)
	}

	// A resolver the feed knows is an exact identification, not a guess.
	feed := intel.New()
	feed.Add("ip|203.0.113.44|rogue DNS")
	fed := Scan(Options{ProcRoot: proc, EtcRoot: etcDir(t, "nameserver 203.0.113.44\n", ""), Intel: feed})
	if g := has(fed, "netscan.resolver.intel"); g == nil || !g.Definitive {
		t.Fatalf("a listed resolver must be definitive: %v", classes(fed))
	}
}

func TestHostsFileSinkhole(t *testing.T) {
	proc := newFakeProc(t).proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1").build()

	hosts := "127.0.0.1 localhost\n" +
		"::1 localhost ip6-localhost\n" +
		"192.168.1.50 nas.home.lan\n" +
		"0.0.0.0 security.debian.org\n"
	res := Scan(Options{ProcRoot: proc, EtcRoot: etcDir(t, "", hosts)})
	got := has(res, "netscan.hosts.sinkholed-defence")
	if got == nil {
		t.Fatalf("an update domain pointed at a dead address must be reported: %v", classes(res))
	}
	if got.Technique != techImpair {
		t.Errorf("technique %q, want %q", got.Technique, techImpair)
	}
	if len(res.Flagged) != 1 {
		t.Errorf("the ordinary entries must stay quiet: %v", classes(res))
	}
}

func TestBlackholedMatching(t *testing.T) {
	yes := []string{"security.debian.org", "www.clamav.net", "updates.example.com", "defender.microsoft.com", "deb.debian.org"}
	no := []string{"security-blog.example.com", "myupdates.example.com", "example.com", "clamav.net.evil.test", "notdefender"}
	for _, h := range yes {
		if !blackholed(h) {
			t.Errorf("blackholed(%q) = false, want true", h)
		}
	}
	for _, h := range no {
		if blackholed(h) {
			t.Errorf("blackholed(%q) = true, want false", h)
		}
	}
}

func TestDNSOffResolver(t *testing.T) {
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(200, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", "ns1", "1001")
	f.proc(300, "dropper", "/tmp/.x/dropper", "ns1", "1002")
	// The resolver doing its job, to a nameserver that is not in resolv.conf:
	// that is a forwarder's business and not a signal.
	f.sock("ns1", "udp", hexEP(t, "192.168.1.20", 33001), hexEP(t, "9.9.9.9", 53), "01", "1001")
	// Any other program querying a nameserver this host is not configured to
	// use is the DNS-tunnel shape.
	f.sock("ns1", "udp", hexEP(t, "192.168.1.20", 33002), hexEP(t, "203.0.113.60", 53), "01", "1002")

	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "nameserver 192.168.1.1\n", "")})
	got := has(res, "netscan.dns.off-resolver")
	if got == nil {
		t.Fatalf("a query to an unconfigured nameserver must be reported: %v", classes(res))
	}
	if got.PID != 300 {
		t.Errorf("attributed to pid %d, want 300 (the resolver itself is exempt)", got.PID)
	}
}

func TestGlibcResolverTrafficIsQuiet(t *testing.T) {
	// Every program that looks up a name sends to port 53 itself. Flagging that
	// would flag the whole host, so only an unconfigured nameserver counts.
	f := newFakeProc(t)
	f.proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	f.proc(400, "apt-get", "/usr/bin/apt-get", "ns1", "1001")
	f.sock("ns1", "udp", hexEP(t, "192.168.1.20", 33003), hexEP(t, "192.168.1.1", 53), "01", "1001")
	res := Scan(Options{ProcRoot: f.build(), EtcRoot: etcDir(t, "nameserver 192.168.1.1\n", "")})
	if len(res.Flagged) != 0 {
		t.Fatalf("ordinary name resolution must be quiet: %v", classes(res))
	}
}

func TestGatewaysAndNeighbours(t *testing.T) {
	root := t.TempDir()
	// 192.168.1.1 as the kernel writes it: little-endian hex, default route.
	write(t, filepath.Join(root, "net", "route"),
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
			"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	write(t, filepath.Join(root, "net", "ipv6_route"),
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n")
	got := Gateways(root)
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "fe80::1" {
		t.Fatalf("Gateways = %v, want [192.168.1.1 fe80::1]", got)
	}

	write(t, filepath.Join(root, "net", "arp"),
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"+
			"192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"+
			"192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:02     *        eth0\n")
	n := Neighbours(root)
	if len(n) != 2 {
		t.Fatalf("Neighbours = %v, want the two complete entries", n)
	}
	if n[0].IP != "192.168.1.1" || n[0].MAC != "aa:bb:cc:dd:ee:01" || n[0].Device != "eth0" {
		t.Errorf("first neighbour = %+v", n[0])
	}
}

func TestGatewayMACChurn(t *testing.T) {
	root := t.TempDir()
	newFakeProcAt(t, root).proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	write(t, filepath.Join(root, "net", "route"),
		"Iface\tDestination\tGateway\tFlags\n"+"eth0\t00000000\t0101A8C0\t0003\n")
	arp := func(mac string) {
		write(t, filepath.Join(root, "net", "arp"),
			"IP address       HW type     Flags       HW address            Mask     Device\n"+
				"192.168.1.1      0x1         0x2         "+mac+"     *        eth0\n")
	}
	etc := etcDir(t, "", "")
	h := NewHistory()

	arp("aa:bb:cc:dd:ee:01")
	if res := Scan(Options{ProcRoot: root, EtcRoot: etc, History: h}); len(res.Flagged) != 0 {
		t.Fatalf("the first sample has nothing to compare with: %v", classes(res))
	}
	arp("aa:bb:cc:dd:ee:99")
	res := Scan(Options{ProcRoot: root, EtcRoot: etc, History: h})
	got := has(res, "netscan.arp.gateway-churn")
	if got == nil {
		t.Fatalf("the gateway's MAC moved and must be reported: %v", classes(res))
	}
	if got.Live {
		t.Error("a MAC change has innocent explanations and must not assert live state")
	}
	if got.Technique != techARPPoison {
		t.Errorf("technique %q, want %q", got.Technique, techARPPoison)
	}
	// A third sample at the same MAC says nothing new.
	if res := Scan(Options{ProcRoot: root, EtcRoot: etc, History: h}); has(res, "netscan.arp.gateway-churn") != nil {
		t.Error("an unchanged table must not report churn again")
	}
}

func TestGatewaySharedMAC(t *testing.T) {
	root := t.TempDir()
	newFakeProcAt(t, root).proc(1, "systemd", "/usr/lib/systemd/systemd", "ns1")
	write(t, filepath.Join(root, "net", "route"), "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n")
	write(t, filepath.Join(root, "net", "arp"),
		"IP address       HW type     Flags       HW address            Mask     Device\n"+
			"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n"+
			"192.168.1.77     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n")
	res := Scan(Options{ProcRoot: root, EtcRoot: etcDir(t, "", "")})
	if has(res, "netscan.arp.gateway-shared") == nil {
		t.Fatalf("one MAC holding the gateway and another address must be reported: %v", classes(res))
	}
}

// newFakeProcAt is newFakeProc with the caller's own directory, for tests that
// also write host-level /proc/net files.
func newFakeProcAt(t *testing.T, root string) *fakeProc {
	t.Helper()
	f := newFakeProc(t)
	f.root = root
	return f
}

func TestBeaconDetection(t *testing.T) {
	h := NewHistory()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// A payload in /tmp checking in every 60 seconds, from a fresh ephemeral
	// port each time, which is what a new connection looks like in the table.
	for i := range 6 {
		sock := Socket{
			Proto: "tcp", State: stateEstablished, Comm: "agent", Exe: "/home/user/.cache/agent",
			PID: 777, Local: Endpoint{"192.168.1.20", 40000 + i}, Remote: Endpoint{"203.0.113.9", 443},
		}
		got := h.observe([]Socket{sock}, start.Add(time.Duration(i)*60*time.Second))
		if i < beaconMinHits-1 && len(got) != 0 {
			t.Fatalf("sample %d: reported a schedule from %d connections", i, i+1)
		}
	}
	got := h.observe(nil, start.Add(6*60*time.Second))
	if len(got) != 1 {
		t.Fatalf("want one beacon finding, got %d", len(got))
	}
	if got[0].Class != "netscan.beacon.periodic" || got[0].Score != 6 {
		t.Errorf("finding = %+v", got[0])
	}
	if got[0].Peer != "203.0.113.9" {
		t.Errorf("peer %q, want 203.0.113.9", got[0].Peer)
	}
	if h.Samples() != 7 {
		t.Errorf("Samples = %d, want 7", h.Samples())
	}
}

func TestBeaconIgnoresIrregularTraffic(t *testing.T) {
	h := NewHistory()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	gaps := []int{0, 5, 70, 9, 600, 11}
	for i, g := range gaps {
		sock := Socket{
			Proto: "tcp", State: stateEstablished, Comm: "firefox", Exe: "/usr/lib/firefox/firefox",
			PID: 778, Local: Endpoint{"192.168.1.20", 41000 + i}, Remote: Endpoint{"93.184.216.34", 443},
		}
		h.observe([]Socket{sock}, start.Add(time.Duration(g)*time.Second))
	}
	if got := h.observe(nil, start.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("a person browsing is not a beacon: %+v", got)
	}
}

func TestBeaconFromSystemBinaryIsContextOnly(t *testing.T) {
	// Update agents and time sync check in on a schedule. The cadence is real,
	// so it is reported, but at a score that needs a second layer.
	h := NewHistory()
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		sock := Socket{
			Proto: "tcp", State: stateEstablished, Comm: "telemetry", Exe: "/usr/bin/telemetry",
			PID: 779, Local: Endpoint{"192.168.1.20", 42000 + i}, Remote: Endpoint{"198.51.100.200", 443},
		}
		h.observe([]Socket{sock}, start.Add(time.Duration(i)*300*time.Second))
	}
	got := h.observe(nil, start.Add(2000*time.Second))
	if len(got) != 1 {
		t.Fatalf("want the cadence reported, got %+v", got)
	}
	if got[0].Score != 3 {
		t.Errorf("score %d, want 3 for a packaged binary's schedule", got[0].Score)
	}
}

func TestSpread(t *testing.T) {
	mean, jitter := spread([]float64{60, 60, 60})
	if mean != 60 || jitter != 0 {
		t.Errorf("spread of a perfect schedule = %v, %v", mean, jitter)
	}
	mean, jitter = spread([]float64{10, 110})
	if mean != 60 || jitter < 0.8 {
		t.Errorf("spread of two very different gaps = %v, %v", mean, jitter)
	}
	if m, j := spread(nil); m != 0 || j != 0 {
		t.Errorf("spread of nothing = %v, %v", m, j)
	}
}

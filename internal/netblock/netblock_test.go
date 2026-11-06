package netblock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFW stands in for the firewall. Every command this package would run is
// recorded instead of run, which is how the response policy is tested without
// root and without touching the host's own rules.
type fakeFW struct {
	mu        sync.Mutex
	calls     []string
	out       map[string]string
	fail      map[string]error
	installed map[string]bool
}

func newFakeFW(tools ...string) *fakeFW {
	f := &fakeFW{out: map[string]string{}, fail: map[string]error{}, installed: map[string]bool{}}
	for _, t := range tools {
		f.installed[t] = true
	}
	return f
}

func (f *fakeFW) run(name string, args []string, stdin string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if err, ok := f.fail[line]; ok {
		return []byte(f.out[line]), err
	}
	return []byte(f.out[line]), nil
}

func (f *fakeFW) look(name string) (string, error) {
	if f.installed[name] {
		return "/usr/sbin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f *fakeFW) called(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// TestCheckRefusesWhatTheHostNeeds is the response policy. These addresses are
// never blocked however confirmed an incident is, because blocking one is how
// an attacker would use a confirmed-looking incident to take the host off the
// network or lock the operator out.
func TestCheckRefusesWhatTheHostNeeds(t *testing.T) {
	protect := map[string]bool{"192.168.1.20": true, "192.168.1.1": true, "1.1.1.1": true}
	refused := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"224.0.0.251", "ff02::fb", "169.254.1.1", "fe80::1",
		"192.168.1.20", "192.168.1.1", "1.1.1.1",
	}
	for _, a := range refused {
		if err := Check(a, protect); err == nil {
			t.Errorf("Check(%q) allowed a block it must refuse", a)
		} else if !errors.Is(err, ErrProtected) {
			t.Errorf("Check(%q) = %v, want an ErrProtected", a, err)
		}
	}
	for _, a := range []string{"203.0.113.9", "198.51.100.7", "10.0.0.5", "2001:db8::1"} {
		if err := Check(a, protect); err != nil {
			t.Errorf("Check(%q) = %v, want it allowed", a, err)
		}
	}
	for _, a := range []string{"", "nonsense", "203.0.113.0/24", "example.com"} {
		if err := Check(a, protect); err == nil {
			t.Errorf("Check(%q) accepted something that is not an address", a)
		}
	}
}

func TestNFTScriptIsIdempotent(t *testing.T) {
	fw := newFakeFW("nft")
	b, err := Open(Options{Run: fw.run, Look: fw.look})
	if err != nil {
		t.Fatal(err)
	}
	if b.Backend() != BackendNFT {
		t.Fatalf("backend = %s, want nftables", b.Backend())
	}
	if len(fw.calls) != 1 || !strings.HasPrefix(fw.calls[0], "nft -f -") {
		t.Fatalf("Open should apply one ruleset, got %v", fw.calls)
	}
	script := b.nftScript()
	// `add` on an object that exists is a no-op, so the table and the sets keep
	// every live block across a restart...
	for _, want := range []string{
		"add table inet cau",
		"add set inet cau blocked4 { type ipv4_addr; flags timeout; }",
		"add set inet cau blocked6 { type ipv6_addr; flags timeout; }",
		"add chain inet cau egress { type filter hook output priority 0; policy accept; }",
		"add chain inet cau forward { type filter hook forward priority 0; policy accept; }",
		"add rule inet cau egress ip daddr @blocked4 counter drop",
		"add rule inet cau ingress ip6 saddr @blocked6 counter drop",
		"add rule inet cau forward ip daddr @blocked4 counter drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the ruleset is missing %q:\n%s", want, script)
		}
	}
	// ...while the chains are flushed first, so applying it again cannot stack
	// duplicate rules.
	for _, chain := range []string{"egress", "ingress", "forward"} {
		if !strings.Contains(script, "flush chain inet cau "+chain) {
			t.Errorf("chain %s is not flushed before its rules go back in", chain)
		}
	}
	if strings.Contains(script, "flush set") || strings.Contains(script, "flush table") {
		t.Error("the script must never flush the sets: that would release every live block")
	}
}

func TestNFTBlockUnblockClear(t *testing.T) {
	fw := newFakeFW("nft")
	b, err := Open(Options{Run: fw.run, Look: fw.look, TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	what, err := b.Block("203.0.113.9", "incident abc: fileless egress")
	if err != nil {
		t.Fatal(err)
	}
	if !fw.called("nft add element inet cau blocked4 { 203.0.113.9 timeout 1800s }") {
		t.Fatalf("wrong block command: %v", fw.calls)
	}
	if !strings.Contains(what, "30m") || !strings.Contains(what, "203.0.113.9") {
		t.Errorf("the report should say what and for how long: %q", what)
	}
	if _, err := b.Block("2001:db8::1", "v6"); err != nil {
		t.Fatal(err)
	}
	if !fw.called("nft add element inet cau blocked6 { 2001:db8::1 timeout 1800s }") {
		t.Fatalf("an IPv6 address belongs in blocked6: %v", fw.calls)
	}
	if err := b.Unblock("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if !fw.called("nft delete element inet cau blocked4 { 203.0.113.9 }") {
		t.Fatalf("wrong unblock command: %v", fw.calls)
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if !fw.called("nft delete table inet cau") {
		t.Fatalf("clear must remove only cau's own table: %v", fw.calls)
	}
}

func TestNoExpiryMustBeAskedFor(t *testing.T) {
	fw := newFakeFW("nft")
	b, err := Open(Options{Run: fw.run, Look: fw.look, TTL: -1})
	if err != nil {
		t.Fatal(err)
	}
	if b.TTL() != 0 {
		t.Fatalf("TTL = %v, want no expiry", b.TTL())
	}
	what, _ := b.Block("203.0.113.9", "by hand")
	if !fw.called("nft add element inet cau blocked4 { 203.0.113.9 }") {
		t.Fatalf("a permanent block carries no timeout: %v", fw.calls)
	}
	if !strings.Contains(what, "until it is removed") {
		t.Errorf("the report must say it does not expire: %q", what)
	}
	// The default, which is what a machine-made block gets, does expire.
	def, _ := Open(Options{Run: fw.run, Look: fw.look})
	if def.TTL() != DefaultTTL {
		t.Errorf("default TTL = %v, want %v", def.TTL(), DefaultTTL)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	fw := newFakeFW("nft")
	b, err := Open(Options{Run: fw.run, Look: fw.look, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Block("203.0.113.9", "test"); err != nil {
		t.Fatal(err)
	}
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(fw.calls) != 0 {
		t.Fatalf("a dry run ran %d commands: %v", len(fw.calls), fw.calls)
	}
	if len(b.Commands()) < 3 {
		t.Fatalf("a dry run must still report what it would have run: %v", b.Commands())
	}
	if !strings.Contains(strings.Join(b.Commands(), "\n"), "add element inet cau blocked4") {
		t.Errorf("the rendered commands are wrong: %v", b.Commands())
	}
}

func TestParseNFTSet(t *testing.T) {
	// Elements with a timeout are objects carrying the seconds left; a
	// permanent one is a bare string.
	doc := `{"nftables":[{"metainfo":{"version":"1.0.9"}},
	 {"set":{"family":"inet","name":"blocked4","table":"cau","type":"ipv4_addr","flags":["timeout"],
	   "elem":[{"elem":{"val":"203.0.113.9","timeout":3600,"expires":3540}},"198.51.100.7"]}}]}`
	got, err := parseNFTSet([]byte(doc), "blocked4")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d elements, want 2: %+v", len(got), got)
	}
	if got[0].Addr != "203.0.113.9" || got[0].Expires.IsZero() {
		t.Errorf("first element = %+v, want an expiry", got[0])
	}
	if left := time.Until(got[0].Expires); left < 50*time.Minute || left > time.Hour {
		t.Errorf("expiry is %v away, want about 59 minutes", left)
	}
	if got[1].Addr != "198.51.100.7" || !got[1].Expires.IsZero() {
		t.Errorf("second element = %+v, want no expiry", got[1])
	}
	if _, err := parseNFTSet(nil, "blocked4"); err != nil {
		t.Errorf("empty output must read as no elements, got %v", err)
	}
	if _, err := parseNFTSet([]byte("not json"), "blocked4"); err == nil {
		t.Error("unreadable output must be an error, not an empty list")
	}
}

func TestNFTListTolerantOfMissingSets(t *testing.T) {
	// Before the first block the sets may not exist. That is a host with
	// nothing blocked, not a failure.
	fw := newFakeFW("nft")
	fw.fail["nft -j list set inet cau blocked4"] = errors.New("exit 1")
	fw.fail["nft -j list set inet cau blocked6"] = errors.New("exit 1")
	b, _ := Open(Options{Run: fw.run, Look: fw.look})
	got, err := b.List()
	if err != nil || len(got) != 0 {
		t.Fatalf("List = %v, %v; want empty and no error", got, err)
	}
}

func TestIPTablesFallback(t *testing.T) {
	fw := newFakeFW("iptables", "ip6tables")
	// The jump is not there yet, so the check fails and an insert follows.
	fw.fail["iptables -w -C OUTPUT -j CAU-OUT"] = errors.New("exit 1")
	fw.fail["iptables -w -C INPUT -j CAU-IN"] = errors.New("exit 1")
	fw.fail["ip6tables -w -C OUTPUT -j CAU-OUT"] = errors.New("exit 1")
	fw.fail["ip6tables -w -C INPUT -j CAU-IN"] = errors.New("exit 1")

	b, err := Open(Options{Run: fw.run, Look: fw.look, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if b.Backend() != BackendIPTables {
		t.Fatalf("backend = %s, want iptables", b.Backend())
	}
	for _, want := range []string{
		"iptables -w -N CAU-OUT", "iptables -w -N CAU-IN",
		"iptables -w -I OUTPUT 1 -j CAU-OUT", "iptables -w -I INPUT 1 -j CAU-IN",
		"ip6tables -w -I OUTPUT 1 -j CAU-OUT",
	} {
		if !fw.called(want) {
			t.Errorf("Open did not run %q: %v", want, fw.calls)
		}
	}

	if _, err := b.Block("203.0.113.9", "test"); err != nil {
		t.Fatal(err)
	}
	// Both directions, and the expiry travels in the rule's own comment so it
	// survives a restart of this program.
	if !fw.called("iptables -w -A CAU-OUT -d 203.0.113.9 -m comment --comment cau:expires=") {
		t.Errorf("no outbound drop rule: %v", fw.calls)
	}
	if !fw.called("iptables -w -A CAU-IN -s 203.0.113.9 -m comment --comment cau:expires=") {
		t.Errorf("no inbound drop rule: %v", fw.calls)
	}
}

func TestIPTablesWithoutIP6Tables(t *testing.T) {
	fw := newFakeFW("iptables")
	fw.fail["iptables -w -C OUTPUT -j CAU-OUT"] = errors.New("exit 1")
	fw.fail["iptables -w -C INPUT -j CAU-IN"] = errors.New("exit 1")
	b, err := Open(Options{Run: fw.run, Look: fw.look})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Block("2001:db8::1", "v6"); err == nil {
		t.Fatal("an IPv6 block with no ip6tables must fail loudly, not silently do nothing")
	} else if !strings.Contains(err.Error(), "ip6tables") {
		t.Errorf("the error should name what is missing: %v", err)
	}
}

func TestIPTablesListAndExpire(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()
	fw := newFakeFW("iptables")
	fw.fail["iptables -w -C OUTPUT -j CAU-OUT"] = errors.New("exit 1")
	fw.fail["iptables -w -C INPUT -j CAU-IN"] = errors.New("exit 1")
	// iptables -S quotes a comment, which a shell would normally strip. These
	// rows are quoted exactly as the tool prints them.
	save := fmt.Sprintf(`-N CAU-OUT
-A CAU-OUT -d 203.0.113.9/32 -m comment --comment "cau:expires=%d" -j DROP
-A CAU-OUT -d 198.51.100.7/32 -m comment --comment "cau:expires=%d" -j DROP
-A CAU-OUT -d 192.0.2.5/32 -m comment --comment "cau:expires=never" -j DROP
`, past, future)
	fw.out["iptables -w -S CAU-OUT"] = save
	fw.out["iptables -w -S CAU-IN"] = ""

	b, _ := Open(Options{Run: fw.run, Look: fw.look})
	got, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d entries, want 3: %+v", len(got), got)
	}
	if got[0].Addr != "192.0.2.5" || !got[0].Expires.IsZero() {
		t.Errorf("the permanent entry = %+v", got[0])
	}

	n, err := b.Expire()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Expire released %d, want only the one that is past", n)
	}
	// The delete carries the rule's own spec with the quotes removed: passed
	// through, they would become part of the comment and match nothing.
	if !fw.called("iptables -w -D CAU-OUT -d 203.0.113.9/32 -m comment --comment cau:expires=") {
		t.Errorf("the expired rule was not deleted with its own spec: %v", fw.calls)
	}
	for _, c := range fw.calls {
		if strings.Contains(c, `"cau:expires=`) {
			t.Errorf("a quoted comment was passed through as an argument: %s", c)
		}
	}
	if fw.called("-D CAU-OUT -d 198.51.100.7/32") || fw.called("-D CAU-OUT -d 192.0.2.5/32") {
		t.Errorf("Expire removed a block that had not expired: %v", fw.calls)
	}
}

func TestNFTDuration(t *testing.T) {
	// nftables' grammar has no fractional seconds, which Go's own formatting
	// produces: time.Duration(1500ms).String() is "1.5s" and nft rejects it.
	cases := map[time.Duration]string{
		time.Hour:               "3600s",
		30 * time.Minute:        "1800s",
		90 * time.Second:        "90s",
		1500 * time.Millisecond: "1s",
		time.Millisecond:        "1s",
	}
	for in, want := range cases {
		if got := nftDuration(in); got != want {
			t.Errorf("nftDuration(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestExpireIsANoOpOnNFTables(t *testing.T) {
	// nftables holds the timeout itself, so there is nothing to come back for.
	fw := newFakeFW("nft")
	b, _ := Open(Options{Run: fw.run, Look: fw.look})
	before := len(fw.calls)
	n, err := b.Expire()
	if err != nil || n != 0 || len(fw.calls) != before {
		t.Errorf("Expire on nftables = %d, %v with %d new commands", n, err, len(fw.calls)-before)
	}
}

func TestNoBackend(t *testing.T) {
	fw := newFakeFW()
	b, err := Open(Options{Run: fw.run, Look: fw.look})
	if err == nil {
		t.Fatal("a host with no firewall must say so at Open")
	}
	if _, err := b.Block("203.0.113.9", "test"); err == nil {
		t.Fatal("Block must fail rather than report a block that did not happen")
	}
}

func TestSeverDestroysEstablishedConnections(t *testing.T) {
	fw := newFakeFW("nft", "ss")
	b, _ := Open(Options{Run: fw.run, Look: fw.look, Sever: true})
	what, err := b.Block("203.0.113.9", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !fw.called("ss -K dst 203.0.113.9") {
		t.Fatalf("--sever must destroy the open sockets too: %v", fw.calls)
	}
	if !strings.Contains(what, "connections destroyed") {
		t.Errorf("the report should say so: %q", what)
	}
	// A host without ss still blocks; it just cannot sever.
	fw2 := newFakeFW("nft")
	b2, _ := Open(Options{Run: fw2.run, Look: fw2.look, Sever: true})
	if what, err := b2.Block("203.0.113.9", "test"); err != nil {
		t.Fatalf("a missing ss must not fail the block: %v", err)
	} else if strings.Contains(what, "destroyed") {
		t.Errorf("it must not claim to have severed: %q", what)
	}
}

func TestLedgerRecordsWhy(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "netblock.log")
	fw := newFakeFW("nft")
	fw.out["nft -j list set inet cau blocked4"] =
		`{"nftables":[{"set":{"name":"blocked4","elem":["203.0.113.9"]}}]}`
	fw.fail["nft -j list set inet cau blocked6"] = errors.New("exit 1")
	b, _ := Open(Options{Run: fw.run, Look: fw.look, Ledger: ledger})
	if _, err := b.Block("203.0.113.9", "incident abc: fileless egress"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "203.0.113.9") || !strings.Contains(string(data), "fileless egress") {
		t.Fatalf("the ledger line is missing the address or the reason: %q", data)
	}
	entries, err := b.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Reason != "incident abc: fileless egress" {
		t.Errorf("List should read the reason back from the ledger: %+v", entries)
	}
}

func TestLocalProtectReadsTheHost(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "route"),
		[]byte("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("nameserver 192.168.1.1\nnameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LocalProtect(proc, etc)
	want := map[string]bool{"192.168.1.1": true, "9.9.9.9": true}
	for a := range want {
		found := false
		for _, g := range got {
			if g == a {
				found = true
			}
		}
		if !found {
			t.Errorf("LocalProtect is missing %s: %v", a, got)
		}
	}
	// The host's own addresses are in there too, whatever they are here.
	if addrs, err := net.InterfaceAddrs(); err == nil && len(addrs) > 0 && len(got) < 3 {
		t.Errorf("LocalProtect should include this host's own addresses: %v", got)
	}
}

func TestProtectedIsSorted(t *testing.T) {
	fw := newFakeFW("nft")
	b, _ := Open(Options{Run: fw.run, Look: fw.look, Protect: []string{"9.9.9.9", "1.1.1.1", "nonsense"}})
	got := b.Protected()
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "9.9.9.9" {
		t.Errorf("Protected = %v, want the two valid addresses sorted", got)
	}
}

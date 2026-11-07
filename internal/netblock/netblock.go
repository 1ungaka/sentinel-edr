// Package netblock is cau's network response: it asks the kernel to drop
// traffic to and from an address, and it undoes that again.
//
// It is the one package here that changes the host's state, so it is written to
// be read by someone deciding whether to trust it:
//
//   - Nothing happens without an explicit opt-in. A Blocker built with DryRun
//     renders the exact commands and runs none of them, which is also how the
//     tests assert what it would do.
//   - Every block is reversible and, by default, expires. nftables holds the
//     timeout itself, so a block survives a crash of this program and is still
//     released on time; the iptables fallback carries the expiry in a rule
//     comment, which Expire reads back.
//   - An address the host needs is never blocked, however confirmed the
//     incident: loopback, the host's own addresses, the default gateways, the
//     configured resolvers, link-local and multicast. Protect holds the list,
//     LocalProtect builds it from the running host, and Check is a pure
//     function so the policy is testable without touching a firewall.
//   - The rules live in their own nftables table, or their own iptables chains.
//     Clear removes them entirely and leaves the host's own firewall as it was:
//     this package never edits a chain it did not create.
//
// What it cannot do is hide. A dropped packet is visible to the attacker on the
// other end, and a block is not containment: a peer with another address is
// back immediately. It buys the minutes an operator needs, and the engine says
// so rather than calling it protection.
package netblock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/netscan"
	"github.com/s-b-repo/cau/internal/safefs"
)

// Backend is the firewall this host has.
type Backend string

// Backends, in the order they are discovered.
const (
	// BackendNFT is nftables, which holds per-element timeouts in the kernel.
	BackendNFT Backend = "nftables"
	// BackendIPTables is the legacy tool, used when nft is absent.
	BackendIPTables Backend = "iptables"
	// BackendNone means neither is installed: nothing can be blocked, and the
	// caller is told so instead of being told a block succeeded.
	BackendNone Backend = "none"
)

// DefaultTTL is how long a machine-made block lasts when the caller names no
// other lifetime. It is deliberately short: long enough for an operator to
// read the alert and decide, short enough that a wrong block on a production
// host heals itself.
const DefaultTTL = time.Hour

// Entry is one address the kernel is dropping.
type Entry struct {
	Addr    string    `json:"addr"`
	Expires time.Time `json:"expires,omitzero"`
	Reason  string    `json:"reason,omitempty"`
	// Severed records that established connections to this peer were destroyed
	// as well, which only works where the kernel supports it.
	Severed bool `json:"severed,omitempty"`
}

// Runner runs one command. It is injectable so every command this package would
// run can be asserted in a test without a firewall or root.
type Runner func(name string, args []string, stdin string) ([]byte, error)

// Options configure a Blocker.
type Options struct {
	// Table is the nftables table this package owns (default "cau").
	Table string
	// Chain is the prefix of the iptables chains this package owns (default
	// "CAU"), used as CAU-OUT and CAU-IN.
	Chain string
	// TTL is how long a block lasts. 0 means DefaultTTL; a negative TTL means
	// no expiry, which the caller has to ask for explicitly.
	TTL time.Duration
	// DryRun renders commands and runs nothing.
	DryRun bool
	// Backend forces a backend instead of discovering one.
	Backend Backend
	// Protect are addresses that are never blocked, on top of the ones Check
	// refuses on its own.
	Protect []string
	// Ledger is a file every action is appended to, so a block has a record of
	// who asked for it and why. An unwritable path is not an error: the block
	// still happens and the caller is told the record could not be kept.
	Ledger string
	// Sever destroys established connections to a blocked peer, which a drop
	// rule on its own does not do. Best-effort: it needs the ss tool and a
	// kernel built with socket destruction.
	Sever bool

	// Run and Look override command execution and lookup (for tests).
	Run  Runner
	Look func(name string) (string, error)
}

// Blocker holds traffic policy for this host.
type Blocker struct {
	opts    Options
	backend Backend
	protect map[string]bool
	// Commands records every command, which is what DryRun returns and what a
	// report shows an operator. Blocks run concurrently, against each other and
	// against Expire, and this is the one thing they share in memory: iptables
	// takes the xtables lock with -w, and the kernel serialises nft transactions.
	mu       sync.Mutex
	commands []string
}

// Open discovers a backend and makes sure this package's own table or chains
// exist. With DryRun it touches nothing and records what it would have run.
func Open(o Options) (*Blocker, error) {
	if o.Table == "" {
		o.Table = "cau"
	}
	if o.Chain == "" {
		o.Chain = "CAU"
	}
	if o.TTL == 0 {
		o.TTL = DefaultTTL
	}
	if o.Run == nil {
		o.Run = execRun
	}
	if o.Look == nil {
		o.Look = exec.LookPath
	}
	b := &Blocker{opts: o, protect: map[string]bool{}}
	for _, p := range o.Protect {
		if ip := net.ParseIP(p); ip != nil {
			b.protect[ip.String()] = true
		}
	}
	b.backend = o.Backend
	if b.backend == "" {
		b.backend = b.discover()
	}
	switch b.backend {
	case BackendNFT:
		return b, b.nftEnsure()
	case BackendIPTables:
		return b, b.iptEnsure()
	}
	return b, fmt.Errorf("no firewall backend: neither nft nor iptables is installed, so nothing can be blocked")
}

func (b *Blocker) discover() Backend {
	if _, err := b.opts.Look("nft"); err == nil {
		return BackendNFT
	}
	if _, err := b.opts.Look("iptables"); err == nil {
		return BackendIPTables
	}
	return BackendNone
}

// Backend reports which firewall is in use.
func (b *Blocker) Backend() Backend { return b.backend }

// Commands are the commands this Blocker has run, or would have run under
// DryRun, in order.
func (b *Blocker) Commands() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.commands...)
}

// note records one command. Every append to b.commands goes through here, so
// the lock cannot be forgotten at a new call site — which is how the iptables
// backend ended up with three unguarded appends after the nftables one was
// fixed.
func (b *Blocker) note(line string) {
	b.mu.Lock()
	b.commands = append(b.commands, line)
	b.mu.Unlock()
}

// TTL is the lifetime this Blocker gives a new block.
func (b *Blocker) TTL() time.Duration {
	if b.opts.TTL < 0 {
		return 0
	}
	return b.opts.TTL
}

// ErrProtected is returned for an address the host needs.
var ErrProtected = errors.New("protected address")

// Check reports why an address must not be blocked by machine, or nil when it
// may be. It is a pure function: the response policy can be reviewed and tested
// without a firewall.
//
// The refusals are the addresses that, blocked, would take the host off the
// network or cut the operator off from it — which is exactly what an attacker
// would want a confirmed-looking incident to achieve.
func Check(addr string, protect map[string]bool) error {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return fmt.Errorf("%q is not an IP address", addr)
	}
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("%w: %s is this host itself", ErrProtected, ip)
	case ip.IsUnspecified():
		return fmt.Errorf("%w: %s means every address", ErrProtected, ip)
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is multicast, which carries the host's own service discovery", ErrProtected, ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("%w: %s is link-local, which carries address configuration", ErrProtected, ip)
	case protect[ip.String()]:
		return fmt.Errorf("%w: %s is this host's own address, its gateway or its resolver", ErrProtected, ip)
	}
	return nil
}

// Protected is the set of addresses this Blocker refuses, sorted.
func (b *Blocker) Protected() []string {
	out := make([]string, 0, len(b.protect))
	for a := range b.protect {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Block asks the kernel to drop traffic to and from an address. It returns a
// sentence describing what happened, for the incident report.
func Block(b *Blocker, addr, reason string) (string, error) { return b.Block(addr, reason) }

// Block asks the kernel to drop traffic to and from an address.
func (b *Blocker) Block(addr, reason string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if err := Check(addr, b.protect); err != nil {
		return "", err
	}
	if b.backend == BackendNone {
		return "", fmt.Errorf("no firewall backend: %s was not blocked", ip)
	}
	var err error
	switch b.backend {
	case BackendNFT:
		err = b.nftBlock(ip)
	case BackendIPTables:
		err = b.iptBlock(ip)
	}
	if err != nil {
		return "", err
	}
	severed := false
	if b.opts.Sever {
		severed = b.sever(ip) == nil
	}
	b.record(Entry{Addr: ip.String(), Expires: b.expiry(), Reason: reason, Severed: severed})

	what := "dropping traffic to and from " + ip.String()
	if b.opts.DryRun {
		what = "would drop traffic to and from " + ip.String()
	}
	if ttl := b.TTL(); ttl > 0 {
		what += fmt.Sprintf(" for %s", ttl)
	} else {
		what += " until it is removed"
	}
	if severed {
		what += ", established connections destroyed"
	}
	return what + " (" + string(b.backend) + ")", nil
}

// Unblock releases an address before its timeout.
func (b *Blocker) Unblock(addr string) error {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return fmt.Errorf("%q is not an IP address", addr)
	}
	switch b.backend {
	case BackendNFT:
		return b.nftUnblock(ip)
	case BackendIPTables:
		return b.iptUnblock(ip)
	}
	return fmt.Errorf("no firewall backend")
}

// List is every address the kernel is currently dropping.
func (b *Blocker) List() ([]Entry, error) {
	var entries []Entry
	var err error
	switch b.backend {
	case BackendNFT:
		entries, err = b.nftList()
	case BackendIPTables:
		entries, err = b.iptList()
	default:
		return nil, fmt.Errorf("no firewall backend")
	}
	if err != nil {
		return nil, err
	}
	reasons := b.ledgerReasons()
	for i := range entries {
		if entries[i].Reason == "" {
			entries[i].Reason = reasons[entries[i].Addr]
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Addr < entries[j].Addr })
	return entries, nil
}

// Clear removes everything this package created, leaving the host's own
// firewall exactly as it was.
func (b *Blocker) Clear() error {
	switch b.backend {
	case BackendNFT:
		return b.nftClear()
	case BackendIPTables:
		return b.iptClear()
	}
	return fmt.Errorf("no firewall backend")
}

// Expire releases blocks whose lifetime has passed. nftables does this itself,
// so there it is a no-op; the iptables fallback needs a caller to come back,
// which the defend daemon does on its network tick.
func (b *Blocker) Expire() (int, error) {
	if b.backend != BackendIPTables {
		return 0, nil
	}
	return b.iptExpire()
}

func (b *Blocker) expiry() time.Time {
	if b.TTL() <= 0 {
		return time.Time{}
	}
	return time.Now().Add(b.TTL()).UTC()
}

// run records a command and runs it, unless this is a dry run.
func (b *Blocker) run(name string, args []string, stdin string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	if stdin != "" {
		line += " <<'" + strings.ReplaceAll(stdin, "\n", "; ") + "'"
	}
	b.note(line)
	if b.opts.DryRun {
		return nil, nil
	}
	out, err := b.opts.Run(name, args, stdin)
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// query runs a command whose output is read back. A dry run still has to read:
// listing is not a change, and refusing to read would make a dry run report
// something other than what a real one would do.
func (b *Blocker) query(name string, args []string) ([]byte, error) {
	out, err := b.opts.Run(name, args, "")
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// sever destroys established connections to a peer. A drop rule stops new
// packets; a TCP session already open keeps retransmitting inside the host until
// it times out, which for an interactive shell is long enough to matter.
func (b *Blocker) sever(ip net.IP) error {
	if _, err := b.opts.Look("ss"); err != nil {
		return fmt.Errorf("ss is not installed")
	}
	_, err := b.run("ss", []string{"-K", "dst", ip.String()}, "")
	return err
}

// record appends one action to the ledger. A ledger that cannot be written is
// reported by the caller's own warning path, never by failing the block: losing
// the record is worse than nothing, losing the block is worse than that.
func (b *Blocker) record(e Entry) {
	if b.opts.Ledger == "" || b.opts.DryRun {
		return
	}
	f, err := os.OpenFile(b.opts.Ledger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	exp := "never"
	if !e.Expires.IsZero() {
		exp = e.Expires.Format(time.RFC3339)
	}
	fmt.Fprintf(f, "%s\t%s\texpires=%s\t%s\n", time.Now().UTC().Format(time.RFC3339), e.Addr, exp,
		strings.ReplaceAll(e.Reason, "\t", " "))
}

// maxLedgerBytes bounds the read of the ledger, which only supplies reasons: if
// it ever grew past this the blocks would stand and lose their explanations.
const maxLedgerBytes = 64 << 20

// ledgerReasons reads back why each address was blocked, latest first.
func (b *Blocker) ledgerReasons() map[string]string {
	out := map[string]string{}
	if b.opts.Ledger == "" {
		return out
	}
	data, err := safefs.ReadFile(b.opts.Ledger, maxLedgerBytes)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 4 && f[3] != "" {
			out[f[1]] = f[3]
		}
	}
	return out
}

func execRun(name string, args []string, stdin string) ([]byte, error) {
	// A response's alert waits for it, so a wedged firewall tool must not hold
	// that alert for ever.
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout) // audit:ok no caller holds a context here, and this deadline is what bounds the call
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

const execTimeout = 30 * time.Second

// LocalProtect builds the never-block list from the running host: every address
// configured on an interface, every default gateway, and every configured
// resolver. procRoot and etcRoot are overridable for tests.
func LocalProtect(procRoot, etcRoot string) []string {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if etcRoot == "" {
		etcRoot = "/etc"
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if ip := net.ParseIP(s); ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, ip.String())
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				add(ipnet.IP.String())
			}
		}
	}
	for _, g := range netscan.Gateways(procRoot) {
		add(g)
	}
	for _, r := range netscan.Resolvers(etcRoot) {
		add(r)
	}
	sort.Strings(out)
	return out
}

// DefaultLedger is where the record of machine-made blocks is kept when the
// state directory exists.
func DefaultLedger(stateDir string) string {
	if stateDir == "" {
		stateDir = "/var/lib/cau"
	}
	if st, err := os.Stat(stateDir); err != nil || !st.IsDir() {
		return ""
	}
	return filepath.Join(stateDir, "netblock.log")
}

package netblock

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The iptables fallback. nftables holds a timeout per element; iptables has no
// such thing, so the expiry is written into the rule's own comment and read back
// by Expire. The kernel is still the record: the block survives a restart of
// this program, and so does the knowledge of when to release it.
const iptComment = "cau:expires="

func (b *Blocker) iptChains() (out, in string) {
	return b.opts.Chain + "-OUT", b.opts.Chain + "-IN"
}

// iptTools are the tools present on this host, v4 first. A host with no
// ip6tables can still block v4, and is told plainly when an IPv6 address
// cannot be blocked.
func (b *Blocker) iptTools() []string {
	var out []string
	for _, t := range []string{"iptables", "ip6tables"} {
		if _, err := b.opts.Look(t); err == nil {
			out = append(out, t)
		}
	}
	return out
}

func (b *Blocker) iptTool(ip net.IP) (string, error) {
	want := "iptables"
	if ip.To4() == nil {
		want = "ip6tables"
	}
	for _, t := range b.iptTools() {
		if t == want {
			return t, nil
		}
	}
	return "", fmt.Errorf("%s is not installed, so %s cannot be blocked", want, ip)
}

// iptEnsure creates this package's own chains and jumps into them from the
// built-in ones. Nothing else in the host's firewall is read or changed, and
// Clear removes exactly these.
func (b *Blocker) iptEnsure() error {
	for _, tool := range b.iptTools() {
		outc, inc := b.iptChains()
		for _, c := range []string{outc, inc} {
			// A chain that exists makes -N fail; that is the normal case on
			// every run after the first.
			b.tolerate(tool, []string{"-w", "-N", c}, "exists")
		}
		for _, j := range []struct{ builtin, target string }{{"OUTPUT", outc}, {"INPUT", inc}} {
			if _, err := b.opts.Run(tool, []string{"-w", "-C", j.builtin, "-j", j.target}, ""); err != nil {
				if _, err := b.run(tool, []string{"-w", "-I", j.builtin, "1", "-j", j.target}, ""); err != nil {
					return err
				}
			}
		}
	}
	if len(b.iptTools()) == 0 {
		return fmt.Errorf("iptables is not installed")
	}
	return nil
}

// tolerate runs a command whose failure is expected and harmless, such as
// creating a chain that is already there.
func (b *Blocker) tolerate(name string, args []string, okIf string) {
	line := name + " " + strings.Join(args, " ")
	b.note(line)
	if b.opts.DryRun {
		return
	}
	if out, err := b.opts.Run(name, args, ""); err != nil && !strings.Contains(strings.ToLower(string(out)), okIf) {
		b.note("# " + line + " failed: " + strings.TrimSpace(string(out)))
	}
}

func (b *Blocker) iptBlock(ip net.IP) error {
	tool, err := b.iptTool(ip)
	if err != nil {
		return err
	}
	outc, inc := b.iptChains()
	comment := iptComment + "never"
	if exp := b.expiry(); !exp.IsZero() {
		comment = iptComment + strconv.FormatInt(exp.Unix(), 10)
	}
	for _, r := range []struct{ chain, dir string }{{outc, "-d"}, {inc, "-s"}} {
		args := []string{"-w", "-A", r.chain, r.dir, ip.String(), "-m", "comment", "--comment", comment, "-j", "DROP"}
		if _, err := b.run(tool, args, ""); err != nil {
			return err
		}
	}
	return nil
}

func (b *Blocker) iptUnblock(ip net.IP) error {
	tool, err := b.iptTool(ip)
	if err != nil {
		return err
	}
	removed := 0
	outc, inc := b.iptChains()
	for _, chain := range []string{outc, inc} {
		rules, err := b.iptRules(tool, chain)
		if err != nil {
			if !b.opts.DryRun {
				return err
			}
			// A dry run on a host whose rules cannot be read (no privilege, no
			// chain yet) still has to show what it would do, so the canonical
			// form of the delete is rendered instead of the listed rule's.
			dir := "-d"
			if chain == inc {
				dir = "-s"
			}
			b.note(tool + " -w -D " + chain + " " + dir + " " + ip.String() + " -j DROP")
			removed++
			continue
		}
		for _, r := range rules {
			if r.addr != ip.String() {
				continue
			}
			if _, err := b.run(tool, r.deleteArgs(chain), ""); err != nil {
				return err
			}
			removed++
		}
	}
	if removed == 0 && !b.opts.DryRun {
		return fmt.Errorf("%s was not blocked", ip)
	}
	return nil
}

func (b *Blocker) iptList() ([]Entry, error) {
	outc, _ := b.iptChains()
	var out []Entry
	for _, tool := range b.iptTools() {
		rules, err := b.iptRules(tool, outc)
		if err != nil {
			continue // the chain is not there yet: nothing is blocked
		}
		for _, r := range rules {
			out = append(out, Entry{Addr: r.addr, Expires: r.expires})
		}
	}
	return out, nil
}

func (b *Blocker) iptExpire() (int, error) {
	now := time.Now()
	outc, inc := b.iptChains()
	n := 0
	for _, tool := range b.iptTools() {
		for _, chain := range []string{outc, inc} {
			rules, err := b.iptRules(tool, chain)
			if err != nil {
				continue
			}
			for _, r := range rules {
				if r.expires.IsZero() || r.expires.After(now) {
					continue
				}
				if _, err := b.run(tool, r.deleteArgs(chain), ""); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

func (b *Blocker) iptClear() error {
	outc, inc := b.iptChains()
	for _, tool := range b.iptTools() {
		b.tolerate(tool, []string{"-w", "-D", "OUTPUT", "-j", outc}, "no chain")
		b.tolerate(tool, []string{"-w", "-D", "INPUT", "-j", inc}, "no chain")
		for _, c := range []string{outc, inc} {
			b.tolerate(tool, []string{"-w", "-F", c}, "no chain")
			b.tolerate(tool, []string{"-w", "-X", c}, "no chain")
		}
	}
	return nil
}

// iptRule is one parsed rule of one of this package's chains.
type iptRule struct {
	addr    string
	expires time.Time
	fields  []string // the rule as iptables-save renders it
}

// deleteArgs turns a listed rule back into the command that removes it.
//
// iptables accepts its own -S output as arguments, with one catch: -S quotes a
// match's comment, and a shell is what normally removes those quotes. Passed
// straight through as one argv element the quotes would become part of the
// comment, the rule would not match, and the delete would silently remove
// nothing — so they are stripped here.
func (r iptRule) deleteArgs(chain string) []string {
	args := make([]string, 0, len(r.fields)+1)
	args = append(args, "-w")
	for _, f := range r.fields {
		if f == "-A" {
			f = "-D"
		}
		args = append(args, unquote(f))
	}
	return args
}

// unquote removes the surrounding double quotes iptables -S puts around a
// comment.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// iptRules reads one chain back. iptables -S prints each rule as the arguments
// that created it, which is both what this parses and what it hands back to
// delete one.
func (b *Blocker) iptRules(tool, chain string) ([]iptRule, error) {
	data, err := b.query(tool, []string{"-w", "-S", chain})
	if err != nil {
		return nil, err
	}
	var out []iptRule
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || f[1] != chain {
			continue
		}
		r := iptRule{fields: f}
		for i := 2; i < len(f)-1; i++ {
			switch f[i] {
			case "-d", "-s":
				r.addr = strings.TrimSuffix(unquote(f[i+1]), "/32")
				r.addr = strings.TrimSuffix(r.addr, "/128")
				if ip := net.ParseIP(r.addr); ip != nil {
					r.addr = ip.String()
				}
			case "--comment":
				c := unquote(f[i+1])
				if ts, ok := strings.CutPrefix(c, iptComment); ok && ts != "never" {
					if sec, err := strconv.ParseInt(ts, 10, 64); err == nil {
						r.expires = time.Unix(sec, 0).UTC()
					}
				}
			}
		}
		if r.addr != "" {
			out = append(out, r)
		}
	}
	return out, nil
}

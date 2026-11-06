package netblock

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// nftScript is the ruleset this package owns. It is written to be applied again
// and again: `add` on an object that exists is a no-op in nftables, so the table
// and the two sets keep whatever they already hold, and only the chains are
// flushed before their rules go back in — which is what stops a restart from
// stacking duplicate rules while keeping every live block in place.
//
// The rules sit in their own table at the filter hooks, so the host's own
// firewall, whatever it is, is neither read nor changed. forward is included
// because a host that routes (a container host, a gateway) would otherwise
// block only its own traffic and let a container keep talking.
func (b *Blocker) nftScript() string {
	t := b.opts.Table
	var s strings.Builder
	fmt.Fprintf(&s, "add table inet %s\n", t)
	fmt.Fprintf(&s, "add set inet %s blocked4 { type ipv4_addr; flags timeout; }\n", t)
	fmt.Fprintf(&s, "add set inet %s blocked6 { type ipv6_addr; flags timeout; }\n", t)
	for _, c := range []struct{ name, hook string }{{"egress", "output"}, {"ingress", "input"}, {"forward", "forward"}} {
		fmt.Fprintf(&s, "add chain inet %s %s { type filter hook %s priority 0; policy accept; }\n", t, c.name, c.hook)
		fmt.Fprintf(&s, "flush chain inet %s %s\n", t, c.name)
	}
	for _, c := range []string{"egress", "forward"} {
		fmt.Fprintf(&s, "add rule inet %s %s ip daddr @blocked4 counter drop\n", t, c)
		fmt.Fprintf(&s, "add rule inet %s %s ip6 daddr @blocked6 counter drop\n", t, c)
	}
	for _, c := range []string{"ingress", "forward"} {
		fmt.Fprintf(&s, "add rule inet %s %s ip saddr @blocked4 counter drop\n", t, c)
		fmt.Fprintf(&s, "add rule inet %s %s ip6 saddr @blocked6 counter drop\n", t, c)
	}
	return s.String()
}

func (b *Blocker) nftEnsure() error {
	_, err := b.run("nft", []string{"-f", "-"}, b.nftScript())
	return err
}

// nftDuration renders a lifetime the way nftables spells one. Go's own
// formatting is not interchangeable with it: time.Duration prints "1.5s" for
// 1500ms, which nft's grammar rejects, so the timeout is written as whole
// seconds and never less than one.
func nftDuration(d time.Duration) string {
	sec := int64(d / time.Second)
	if sec < 1 {
		sec = 1
	}
	return strconv.FormatInt(sec, 10) + "s"
}

// nftSet picks the set an address belongs in. nftables sets are typed, so a
// mixed set is not possible and the family has to be chosen here.
func nftSet(ip net.IP) string {
	if ip.To4() != nil {
		return "blocked4"
	}
	return "blocked6"
}

func (b *Blocker) nftBlock(ip net.IP) error {
	elem := ip.String()
	if ttl := b.TTL(); ttl > 0 {
		elem += " timeout " + nftDuration(ttl)
	}
	_, err := b.run("nft", []string{"add", "element", "inet", b.opts.Table, nftSet(ip), "{ " + elem + " }"}, "")
	return err
}

func (b *Blocker) nftUnblock(ip net.IP) error {
	_, err := b.run("nft", []string{"delete", "element", "inet", b.opts.Table, nftSet(ip), "{ " + ip.String() + " }"}, "")
	return err
}

func (b *Blocker) nftClear() error {
	// Deleting the table takes its sets, chains and rules with it, so the host
	// is left with exactly the firewall it had before cau touched it.
	_, err := b.run("nft", []string{"delete", "table", "inet", b.opts.Table}, "")
	return err
}

func (b *Blocker) nftList() ([]Entry, error) {
	var out []Entry
	for _, set := range []string{"blocked4", "blocked6"} {
		data, err := b.query("nft", []string{"-j", "list", "set", "inet", b.opts.Table, set})
		if err != nil {
			// A set that is not there holds nothing. That is the state of a host
			// where no block has been made yet, not a failure to report.
			continue
		}
		entries, err := parseNFTSet(data, set)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

// nftJSON is the part of nft -j output this needs.
type nftJSON struct {
	Nftables []struct {
		Set *struct {
			Name string            `json:"name"`
			Elem []json.RawMessage `json:"elem"`
		} `json:"set"`
	} `json:"nftables"`
}

// parseNFTSet reads the elements of one set. An element with a timeout is an
// object carrying how many seconds are left; one without is a bare string,
// which is a block that was asked to be permanent.
func parseNFTSet(data []byte, set string) ([]Entry, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var doc nftJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("reading the nftables set %s: %w", set, err)
	}
	var out []Entry
	for _, node := range doc.Nftables {
		if node.Set == nil || (node.Set.Name != set && set != "") {
			continue
		}
		for _, raw := range node.Set.Elem {
			var plain string
			if err := json.Unmarshal(raw, &plain); err == nil {
				out = append(out, Entry{Addr: plain})
				continue
			}
			var obj struct {
				Elem struct {
					Val     any     `json:"val"`
					Expires float64 `json:"expires"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			addr, ok := obj.Elem.Val.(string)
			if !ok {
				continue
			}
			e := Entry{Addr: addr}
			if obj.Elem.Expires > 0 {
				e.Expires = time.Now().Add(time.Duration(obj.Elem.Expires) * time.Second).UTC()
			}
			out = append(out, e)
		}
	}
	return out, nil
}

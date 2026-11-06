package netscan

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

const maxConfBytes = 1 << 20

// ATT&CK: a host pointed at a nameserver it was never configured to use, and a
// hosts file that answers for a security vendor's domain, are both impairment of
// the host's own defences rather than communication.
const techImpair = "T1562.001" // Impair Defenses: Disable or Modify Tools

// Resolvers are the nameservers /etc/resolv.conf names, in file order. A
// missing or unreadable file returns nothing rather than an error: a host using
// only systemd-resolved's stub, or a container with no resolv.conf, is normal
// and must not fail a scan.
func Resolvers(etc string) []string {
	var out []string
	for _, line := range strings.Split(readLimit(filepath.Join(etc, "resolv.conf"), maxConfBytes), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(strings.TrimSpace(f[1])); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// localAddr reports whether an address is one a host answers for itself or
// reaches without leaving the site: loopback, a private range, a link-local or
// a carrier-grade NAT range. A resolver inside one of those is the site's own.
func localAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10, the shared address space a carrier or a mesh VPN hands out.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// avDomains are the update and telemetry domains malware blackholes so the host
// cannot fetch a signature or report what happened. A hosts-file entry pointing
// one of these at a dead address is the move, and it is one of the few
// configuration changes with no legitimate explanation on a normal host.
var avDomains = []string{
	"clamav.net", "virustotal.com", "virusscan", "sophos.com", "sophosupd.com",
	"avast.com", "avg.com", "avira.com", "bitdefender.com", "eset.com",
	"kaspersky.com", "kaspersky-labs.com", "mcafee.com", "symantec.com",
	"norton.com", "trendmicro.com", "malwarebytes.com", "crowdstrike.com",
	"sentinelone.com", "windowsupdate.com", "update.microsoft.com", "defender",
	"security.ubuntu.com", "security.debian.org", "deb.debian.org",
	"archive.ubuntu.com", "updates.", "virusdefs", "f-secure.com", "drweb.com",
	"emsisoft.com", "sucuri.net", "spamhaus.org", "abuse.ch",
}

// resolverFindings audits the host's name resolution configuration: where
// queries are sent, and what the host answers locally before they are sent at
// all.
func resolverFindings(opts Options) []Finding {
	etc := etcRoot(opts)
	var out []Finding
	for _, ns := range Resolvers(etc) {
		if opts.Intel != nil {
			if hit, ok := opts.Intel.MatchHost(ns); ok {
				out = append(out, Finding{
					Class: "netscan.resolver.intel", Score: 9, Technique: techDNSProto, Definitive: true,
					Detail: fmt.Sprintf("this host resolves names through %s, a known-bad %s in the feed: %s",
						ns, hit.Kind, truncate(hit.Label, 120)),
					Evidence: "resolv.conf nameserver " + ns, Peer: ns,
				})
				continue
			}
		}
		ip := net.ParseIP(ns)
		if localAddr(ip) || publicResolvers[ns] {
			continue
		}
		// No ATT&CK sub-technique covers tampering with a host's resolver
		// configuration, so this row is left unmapped rather than mapped to
		// something adjacent. docs/limitations.md says so.
		out = append(out, Finding{
			Class: "netscan.resolver.unexpected", Score: 5,
			Detail: fmt.Sprintf("this host resolves names through %s, which is neither a local nor a documented public resolver: "+
				"every name it looks up is answered by whoever runs that address", ns),
			Evidence: "resolv.conf nameserver " + ns, Peer: ns,
		})
	}
	return append(out, hostsFindings(etc, opts)...)
}

// hostsFindings reads /etc/hosts. Two things there matter: an entry that points
// a security vendor's or a distribution's update domain at an address that
// cannot serve it, which is how malware stops a host from healing itself, and an
// entry pointing any name at an address the feed knows.
func hostsFindings(etc string, opts Options) []Finding {
	var out []Finding
	for _, line := range strings.Split(readLimit(filepath.Join(etc, "hosts"), maxConfBytes), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil {
			continue
		}
		dead := ip.IsLoopback() || ip.IsUnspecified()
		for _, name := range f[1:] {
			host := strings.ToLower(strings.TrimSuffix(name, "."))
			if opts.Intel != nil && !dead {
				if hit, ok := opts.Intel.MatchHost(f[0]); ok {
					out = append(out, Finding{
						Class: "netscan.hosts.intel", Score: 9, Technique: techDNSProto, Definitive: true,
						Detail: fmt.Sprintf("the hosts file sends %s to %s, a known-bad %s in the feed: %s",
							host, f[0], hit.Kind, truncate(hit.Label, 120)),
						Evidence: strings.TrimSpace(line), Peer: f[0],
					})
					break
				}
			}
			if dead && blackholed(host) {
				out = append(out, Finding{
					Class: "netscan.hosts.sinkholed-defence", Score: 6, Technique: techImpair,
					Detail: fmt.Sprintf("the hosts file answers %s with %s, so this host cannot reach it: "+
						"an update or security domain pointed at a dead address stops the host healing itself", host, f[0]),
					Evidence: strings.TrimSpace(line),
				})
			}
		}
	}
	return out
}

// blackholed reports whether a name is one of the update or security domains a
// host needs. The match is on a suffix or a labelled component, so
// "updates.internal.example.com" does not count merely for containing "updates".
func blackholed(host string) bool {
	for _, d := range avDomains {
		switch {
		case strings.HasSuffix(d, "."): // a prefix pattern like "updates."
			if strings.HasPrefix(host, d) {
				return true
			}
		case strings.Contains(d, "."):
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		default: // a bare label, matched as a whole component
			for _, part := range strings.Split(host, ".") {
				if part == d {
					return true
				}
			}
		}
	}
	return false
}

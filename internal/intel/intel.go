// Package intel is cau's abuse-intelligence feed: a set of network and file
// indicators (IPs, CIDRs, domains, URLs, file hashes) that are known-bad, used
// to flag a package/config/process that references one of them.
//
// It is HYBRID by design. The feed lives as a plain offline file that ships and
// works with no network at all; `cau feed update --url …` is an explicit,
// opt-in refresh that fetches a remote feed and merges it into that offline
// cache. Nothing here reaches the network on its own — loading and matching are
// pure local operations.
//
// Matching is membership-only, which keeps false positives near zero: a domain
// or IP in a script is reported only when it is actually present in the feed, so
// an install script that merely mentions example.com is never flagged unless
// example.com is a listed indicator.
package intel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Kind classifies an indicator.
type Kind string

const (
	KindIP     Kind = "ip"
	KindCIDR   Kind = "cidr"
	KindDomain Kind = "domain"
	KindURL    Kind = "url"
	KindHash   Kind = "hash"
)

// Hit is one matched indicator.
type Hit struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

// Feed is an in-memory set of indicators with fast membership tests.
type Feed struct {
	ips     map[string]string
	domains map[string]string
	urls    map[string]string
	hashes  map[string]string
	cidrs   []cidrEntry
	source  string
	skipped int
}

type cidrEntry struct {
	net   *net.IPNet
	label string
}

// New returns an empty feed.
func New() *Feed {
	return &Feed{
		ips:     map[string]string{},
		domains: map[string]string{},
		urls:    map[string]string{},
		hashes:  map[string]string{},
	}
}

// Load reads a feed file. A missing file is NOT an error — it returns an empty
// feed and false, so callers can run feed-less without special-casing.
func Load(path string) (*Feed, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	feed, err := Parse(f, path)
	return feed, err == nil, err
}

const maxFeedBytes = 128 << 20

// Parse reads indicators from r. Lines are `value`, `value|label`, or
// `type|value|label`; blank lines and `#` comments are skipped. A bare value is
// auto-classified by shape. Malformed lines are counted, never fatal.
func Parse(r io.Reader, source string) (*Feed, error) {
	feed := New()
	feed.source = source
	sc := bufio.NewScanner(io.LimitReader(r, maxFeedBytes))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !feed.Add(line) {
			feed.skipped++
		}
	}
	return feed, sc.Err()
}

// Add inserts one line. Returns false if it could not be classified.
func (f *Feed) Add(line string) bool {
	parts := strings.SplitN(line, "|", 3)
	var value, label string
	var forced Kind
	switch len(parts) {
	case 1:
		value = strings.TrimSpace(parts[0])
	case 2:
		value, label = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	default:
		forced = Kind(strings.ToLower(strings.TrimSpace(parts[0])))
		value, label = strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	}
	if value == "" {
		return false
	}
	k := forced
	if k == "" {
		k = classify(value)
	}
	switch k {
	case KindHash:
		f.hashes[strings.ToLower(value)] = label
	case KindURL:
		f.urls[strings.ToLower(strings.TrimRight(value, "/"))] = label
	case KindCIDR:
		_, n, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		f.cidrs = append(f.cidrs, cidrEntry{n, label})
	case KindIP:
		f.ips[value] = label
	case KindDomain:
		f.domains[strings.ToLower(strings.TrimPrefix(value, "*."))] = label
	default:
		return false
	}
	return true
}

func classify(v string) Kind {
	switch {
	case isHex(v) && (len(v) == 32 || len(v) == 40 || len(v) == 64):
		return KindHash
	case strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		return KindURL
	case strings.Contains(v, "/") && isCIDR(v):
		return KindCIDR
	case net.ParseIP(v) != nil:
		return KindIP
	case isDomain(v):
		return KindDomain
	}
	return ""
}

// Count returns the number of indicators loaded.
func (f *Feed) Count() int {
	if f == nil {
		return 0
	}
	return len(f.ips) + len(f.domains) + len(f.urls) + len(f.hashes) + len(f.cidrs)
}

// Skipped returns how many lines failed to classify.
func (f *Feed) Skipped() int {
	if f == nil {
		return 0
	}
	return f.skipped
}

// Source returns the path the feed was loaded from.
func (f *Feed) Source() string {
	if f == nil {
		return ""
	}
	return f.source
}

// CountByKind returns per-kind counts for reporting.
func (f *Feed) CountByKind() map[string]int {
	if f == nil {
		return nil
	}
	return map[string]int{
		"ip": len(f.ips), "cidr": len(f.cidrs), "domain": len(f.domains),
		"url": len(f.urls), "hash": len(f.hashes),
	}
}

// Merge folds other's indicators into f (used by `feed update` to combine the
// offline cache with a freshly fetched feed). Returns how many new indicators
// were added.
func (f *Feed) Merge(other *Feed) int {
	if other == nil {
		return 0
	}
	before := f.Count()
	for k, v := range other.ips {
		f.ips[k] = v
	}
	for k, v := range other.domains {
		f.domains[k] = v
	}
	for k, v := range other.urls {
		f.urls[k] = v
	}
	for k, v := range other.hashes {
		f.hashes[k] = v
	}
	f.cidrs = append(f.cidrs, other.cidrs...)
	return f.Count() - before
}

// Save writes the feed back to path in the canonical `type|value|label` form,
// sorted, so the offline cache is stable and diff-friendly.
func (f *Feed) Save(path string) error {
	var lines []string
	add := func(k Kind, m map[string]string) {
		for v, lbl := range m {
			lines = append(lines, string(k)+"|"+v+"|"+lbl)
		}
	}
	add(KindIP, f.ips)
	add(KindDomain, f.domains)
	add(KindURL, f.urls)
	add(KindHash, f.hashes)
	for _, c := range f.cidrs {
		lines = append(lines, string(KindCIDR)+"|"+c.net.String()+"|"+c.label)
	}
	sort.Strings(lines)
	var b strings.Builder
	fmt.Fprintf(&b, "# cau abuse-intel feed — %d indicators\n", len(lines))
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// ── matching ─────────────────────────────────────────────────────────────────

var (
	reURL    = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>|\\]+`)
	reIPlit  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
)

// MatchText extracts URLs, IPs and domains from arbitrary text and returns the
// ones present in the feed. Membership-only: unknown indicators are ignored.
func (f *Feed) MatchText(text string) []Hit {
	if f == nil || f.Count() == 0 || text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Hit
	emit := func(h Hit) {
		key := string(h.Kind) + "|" + h.Value
		if !seen[key] {
			seen[key] = true
			out = append(out, h)
		}
	}
	for _, u := range reURL.FindAllString(text, 256) {
		uu := strings.ToLower(strings.TrimRight(u, "/.,)\""))
		if lbl, ok := f.urls[uu]; ok {
			emit(Hit{KindURL, uu, lbl})
		}
		if host := urlHost(uu); host != "" {
			if lbl, k, ok := f.matchHost(host); ok {
				emit(Hit{k, host, lbl})
			}
		}
	}
	for _, ip := range reIPlit.FindAllString(text, 256) {
		if lbl, k, ok := f.matchHost(ip); ok {
			emit(Hit{k, ip, lbl})
		}
	}
	for _, d := range reDomain.FindAllString(text, 512) {
		if lbl, ok := f.matchDomain(strings.ToLower(d)); ok {
			emit(Hit{KindDomain, strings.ToLower(d), lbl})
		}
	}
	return out
}

// MatchHash reports whether a file hash (any supported length) is in the feed.
func (f *Feed) MatchHash(hexHash string) (string, bool) {
	if f == nil {
		return "", false
	}
	lbl, ok := f.hashes[strings.ToLower(strings.TrimSpace(hexHash))]
	return lbl, ok
}

// matchHost matches an IP (exact or CIDR) or a domain name.
func (f *Feed) matchHost(host string) (label string, kind Kind, ok bool) {
	if ip := net.ParseIP(host); ip != nil {
		if lbl, hit := f.ips[host]; hit {
			return lbl, KindIP, true
		}
		for _, c := range f.cidrs {
			if c.net.Contains(ip) {
				return c.label, KindCIDR, true
			}
		}
		return "", "", false
	}
	if lbl, hit := f.matchDomain(host); hit {
		return lbl, KindDomain, true
	}
	return "", "", false
}

// matchDomain matches a domain exactly or as a subdomain of a listed domain.
func (f *Feed) matchDomain(d string) (string, bool) {
	d = strings.TrimSuffix(d, ".")
	for {
		if lbl, ok := f.domains[d]; ok {
			return lbl, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return "", false
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			// Don't match a bare TLD.
			if lbl, ok := f.domains[d]; ok {
				return lbl, true
			}
			return "", false
		}
	}
}

func urlHost(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") { // IPv6 literal
		if j := strings.IndexByte(s, ']'); j >= 0 {
			return s[1:j]
		}
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && net.ParseIP(s) == nil {
		s = s[:i]
	}
	return s
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func isDomain(s string) bool {
	return reDomain.MatchString(s) && !strings.ContainsAny(s, " /\\")
}

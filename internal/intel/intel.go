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

	"github.com/s-b-repo/cau/internal/safefs"
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
	// cidrSet records the canonical networks already in cidrs, so re-applying
	// an overlapping feed cannot grow the slice with duplicates.
	cidrSet map[string]bool
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
		cidrSet: map[string]bool{},
	}
}

// Load reads a feed file. A missing file is NOT an error — it returns an empty
// feed and false, so callers can run feed-less without special-casing.
func Load(path string) (*Feed, bool, error) {
	f, _, err := safefs.Open(path)
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

// maxFeedBytes caps how much of a feed is read. It is a var so a test can lower
// it; a feed longer than the cap is refused rather than returned as a complete
// partial feed whose tail was silently dropped.
var maxFeedBytes = 128 << 20

// Parse reads indicators from r. Lines are `value`, `value|label`, or
// `type|value|label`; blank lines and `#` comments are skipped. A bare value is
// auto-classified by shape. Malformed lines are counted, never fatal.
//
// A feed longer than maxFeedBytes is an error: the limit may have cut the
// stream short, and every indicator after the cut would otherwise be missing
// from a feed that still looked complete.
func Parse(r io.Reader, source string) (*Feed, error) {
	feed := New()
	feed.source = source
	sc := bufio.NewScanner(io.LimitReader(r, int64(maxFeedBytes)))
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
	if err := sc.Err(); err != nil {
		return feed, err
	}
	// The limit may have stopped the scan mid-stream. One more byte from the
	// source proves there is a tail this scan never saw, so refuse the feed
	// instead of saving a truncation as a complete one.
	var probe [1]byte
	if n, _ := io.ReadFull(r, probe[:]); n > 0 {
		return feed, fmt.Errorf("feed %s is larger than the %d byte limit, so it is refused rather than saved as a truncated feed", source, maxFeedBytes)
	}
	return feed, nil
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
		f.addCIDR(n, label)
	case KindIP:
		f.ips[value] = label
	case KindDomain:
		f.domains[strings.ToLower(strings.TrimPrefix(value, "*."))] = label
	default:
		return false
	}
	return true
}

// addCIDR records a network once. Unlike the map-backed indicator kinds, CIDRs
// were appended without deduplication, so re-applying an overlapping feed (a
// repeated `feed update`, or one feed that lists the same range twice) grew the
// saved cache with duplicates, and every IP candidate scanned them all
// linearly. Containment is deliberately not merged: a more-specific range keeps
// its own label, and collapsing it into a broad parent would drop a distinct
// entry. net.ParseCIDR has already masked value, so n.String() is the canonical
// spelling two spellings of the same range collapse onto.
func (f *Feed) addCIDR(n *net.IPNet, label string) {
	if f.cidrSet == nil {
		f.cidrSet = map[string]bool{}
	}
	key := n.String()
	if f.cidrSet[key] {
		return
	}
	f.cidrSet[key] = true
	f.cidrs = append(f.cidrs, cidrEntry{n, label})
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
	// CIDRs are deduplicated through addCIDR, so a range the cache already holds
	// (by its canonical masked spelling) adds nothing. Without this a repeated
	// `feed update`, or one feed listing a range twice, grew the saved cache
	// with duplicates while every IP candidate scanned the whole slice.
	for _, c := range other.cidrs {
		f.addCIDR(c.net, c.label)
	}
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

// Candidate caps for one MatchText pass. A script or command line can carry a
// great many ordinary URLs, IP literals and domains ahead of the one listed
// indicator, so the caps are high enough that a real body never reaches them,
// and never silent: MatchTextReportsTruncation reports when one was reached, so
// an indicator sitting after the cut is a reported gap rather than a clean miss.
const (
	maxURLCandidates    = 4096
	maxIPCandidates     = 4096
	maxDomainCandidates = 16384
)

// capped returns the candidates worth examining for one kind, and whether text
// held more of them than the cap. It reads one match past the cap so a body with
// exactly limit candidates is not reported as truncated; that extra match is
// sliced off and never examined.
func capped(re *regexp.Regexp, text string, limit int) ([]string, bool) {
	got := re.FindAllString(text, limit+1)
	if len(got) > limit {
		return got[:limit], true
	}
	return got, false
}

// MatchText extracts URLs, IPs and domains from arbitrary text and returns the
// ones present in the feed. Membership-only: unknown indicators are ignored.
// Truncation is not reported; use MatchTextReportsTruncation when the caller
// must know that a candidate cap was reached.
func (f *Feed) MatchText(text string) []Hit {
	hits, _ := f.MatchTextReportsTruncation(text)
	return hits
}

// MatchTextReportsTruncation is MatchText plus an honest truncation flag: it
// reports true when text held more URL, IP-literal or domain candidates than
// the scan examined, so a listed indicator after the cut may have been missed.
// Callers surface it instead of treating an empty result as a complete check.
func (f *Feed) MatchTextReportsTruncation(text string) ([]Hit, bool) {
	if f == nil || f.Count() == 0 || text == "" {
		return nil, false
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
	urls, truncURL := capped(reURL, text, maxURLCandidates)
	for _, u := range urls {
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
	ips, truncIP := capped(reIPlit, text, maxIPCandidates)
	for _, ip := range ips {
		if lbl, k, ok := f.matchHost(ip); ok {
			emit(Hit{k, ip, lbl})
		}
	}
	domains, truncDomain := capped(reDomain, text, maxDomainCandidates)
	for _, d := range domains {
		if lbl, ok := f.matchDomain(strings.ToLower(d)); ok {
			emit(Hit{KindDomain, strings.ToLower(d), lbl})
		}
	}
	return out, truncURL || truncIP || truncDomain
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

// MatchHost matches one network indicator: an IP against the listed addresses
// and CIDRs, or a hostname against the listed domains and their subdomains.
//
// It is the membership test the network sensor needs, where MatchText does not
// apply: the kernel hands over an address, not a line of script to search.
func (f *Feed) MatchHost(host string) (Hit, bool) {
	if f == nil {
		return Hit{}, false
	}
	host = strings.TrimSpace(host)
	lbl, kind, ok := f.matchHost(host)
	if !ok {
		return Hit{}, false
	}
	return Hit{Kind: kind, Value: host, Label: lbl}, true
}

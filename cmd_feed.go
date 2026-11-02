package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/intel"
	"github.com/cau-edr/cau/internal/report"
)

// feedEnv is the environment variable that overrides the abuse-feed path.
const feedEnv = "CAU_ABUSE_FEED"

// feedSearchPaths is the ordered list of locations the abuse feed is loaded from
// when no explicit path is given. The first that exists wins.
func feedSearchPaths() []string {
	var paths []string
	if p := os.Getenv(feedEnv); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths,
		filepath.Join("signatures", "abuse-feed.txt"),
		"/usr/local/share/cau/abuse-feed.txt",
		"/usr/share/cau/abuse-feed.txt",
	)
	return paths
}

// resolveFeedPath returns the explicit path, or the first search path that
// exists, or "" if none exists.
func resolveFeedPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range feedSearchPaths() {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadFeedQuiet loads the abuse feed for a scan, returning nil (no feed) rather
// than an error when none is present — feed matching is always optional.
func loadFeedQuiet(explicit string) *intel.Feed {
	path := resolveFeedPath(explicit)
	if path == "" {
		return nil
	}
	f, ok, err := intel.Load(path)
	if err != nil || !ok || f.Count() == 0 {
		return nil
	}
	return f
}

func feedUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau feed <subcommand> [flags]

The abuse-intelligence feed: known-bad IPs, CIDRs, domains, URLs and file
hashes that cau scan / cau installed / cau ps match references against. The feed
is HYBRID: a plain offline file that works with no network, refreshed on demand.

Subcommands:
  list                 show how many indicators of each kind are loaded
  check <indicator>…   test one or more indicators (IP/domain/URL/hash) against the feed
  update               refresh the offline cache (opt-in; the only networked action)

update flags:
  --from <file>   merge indicators from a local file (no network)
  --url <url>     fetch indicators from an http(s) feed and merge them (opt-in network)
  --replace       replace the cache instead of merging into it
  --feed <path>   cache file to write (default: first of $CAU_ABUSE_FEED,
                  ./signatures/abuse-feed.txt, /usr/local/share, /usr/share)

Feed file format (one per line; '#' comments):
  value                      auto-classified by shape
  value|label                value plus a threat label
  type|value|label           type is ip|cidr|domain|url|hash

Exit codes: 0 ok, 1 'check' found a match, 3 failed, 4 usage.
`)
}

func cmdFeed(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		feedUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "list":
		return cmdFeedList(args[1:], stdout, stderr)
	case "check":
		return cmdFeedCheck(args[1:], stdout, stderr)
	case "update":
		return cmdFeedUpdate(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		feedUsage(stdout)
		return report.ExitOK
	default:
		return fail(stderr, report.ExitUsage, "unknown feed subcommand %q", args[0])
	}
}

func cmdFeedList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("feed list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	feedPath := fs.String("feed", "", "feed file (default: search path)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	path := resolveFeedPath(*feedPath)
	if path == "" {
		fmt.Fprintln(stdout, "No abuse feed found. Create one with 'cau feed update --from <file>' or --url.")
		return report.ExitOK
	}
	f, _, err := intel.Load(path)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "Feed source : %s\n", path)
	fmt.Fprintf(stdout, "Indicators  : %d\n", f.Count())
	byKind := f.CountByKind()
	for _, k := range []string{"ip", "cidr", "domain", "url", "hash"} {
		fmt.Fprintf(stdout, "  %-7s: %d\n", k, byKind[k])
	}
	if f.Skipped() > 0 {
		fmt.Fprintf(stdout, "Skipped     : %d unparseable line(s)\n", f.Skipped())
	}
	return report.ExitOK
}

func cmdFeedCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("feed check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	feedPath := fs.String("feed", "", "feed file (default: search path)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() == 0 {
		return fail(stderr, report.ExitUsage, "check needs at least one indicator")
	}
	f := loadFeedQuiet(*feedPath)
	if f == nil {
		fmt.Fprintln(stdout, "No abuse feed loaded; nothing to check against.")
		return report.ExitOK
	}
	anyHit := false
	for _, ind := range fs.Args() {
		if lbl, ok := f.MatchHash(ind); ok {
			anyHit = true
			fmt.Fprintf(stdout, " [HIT] %s  hash  %s\n", ind, lbl)
			continue
		}
		hits := f.MatchText(ind)
		if len(hits) == 0 {
			fmt.Fprintf(stdout, " [ -- ] %s  (not in feed)\n", ind)
			continue
		}
		anyHit = true
		for _, h := range hits {
			fmt.Fprintf(stdout, " [HIT] %s  %s  %s\n", ind, h.Kind, h.Label)
		}
	}
	if anyHit {
		return report.ExitThreat
	}
	return report.ExitOK
}

func cmdFeedUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("feed update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "merge indicators from a local file")
	url := fs.String("url", "", "fetch indicators from an http(s) feed (opt-in network)")
	feedPath := fs.String("feed", "", "cache file to write")
	replace := fs.Bool("replace", false, "replace the cache instead of merging")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *from == "" && *url == "" {
		return fail(stderr, report.ExitUsage, "update needs --from <file> or --url <url>")
	}

	// Destination cache: explicit --feed, else the first writable default.
	dest := *feedPath
	if dest == "" {
		dest = resolveFeedPath("")
		if dest == "" {
			dest = filepath.Join("signatures", "abuse-feed.txt")
		}
	}

	// Start from the existing cache unless --replace.
	cache := intel.New()
	if !*replace {
		if existing, ok, _ := intel.Load(dest); ok {
			cache = existing
		}
	}

	var incoming *intel.Feed
	var err error
	switch {
	case *url != "":
		fmt.Fprintf(stderr, "[*] Fetching abuse feed from %s …\n", *url)
		incoming, err = fetchFeed(*url)
	default:
		incoming, err = loadLocalFeed(*from)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	added := cache.Merge(incoming)
	if err := ensureDir(dest); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := cache.Save(dest); err != nil {
		return fail(stderr, report.ExitRunFailed, "could not write feed cache: %v", err)
	}
	fmt.Fprintf(stdout, "Feed updated: %s\n", dest)
	fmt.Fprintf(stdout, "  fetched   : %d indicator(s)\n", incoming.Count())
	fmt.Fprintf(stdout, "  new       : %d\n", added)
	fmt.Fprintf(stdout, "  total     : %d\n", cache.Count())
	if incoming.Skipped() > 0 {
		fmt.Fprintf(stdout, "  skipped   : %d unparseable line(s) in the source\n", incoming.Skipped())
	}
	return report.ExitOK
}

const maxFeedFetchBytes = 128 << 20

// fetchFeed downloads a feed over http(s). This is the one networked path in the
// feed subsystem and runs only on an explicit `--url`.
func fetchFeed(url string) (*intel.Feed, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("feed url must be http:// or https://")
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch failed: HTTP %d", resp.StatusCode)
	}
	return intel.Parse(io.LimitReader(resp.Body, maxFeedFetchBytes), url)
}

func loadLocalFeed(path string) (*intel.Feed, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return intel.Parse(io.LimitReader(f, maxFeedFetchBytes), path)
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

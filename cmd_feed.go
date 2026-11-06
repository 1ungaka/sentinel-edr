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

	"github.com/s-b-repo/cau/internal/intel"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/selftest"
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
	if err := fs.Parse(interspersed(fs, args)); err != nil {
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
	if err := fs.Parse(interspersed(fs, args)); err != nil {
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
			fmt.Fprintf(stdout, " [HIT] %s  hash  %s\n", report.TermSafe(ind), report.TermSafe(lbl))
			continue
		}
		hits := f.MatchText(ind)
		if len(hits) == 0 {
			fmt.Fprintf(stdout, " [ -- ] %s  (not in feed)\n", report.TermSafe(ind))
			continue
		}
		anyHit = true
		for _, h := range hits {
			fmt.Fprintf(stdout, " [HIT] %s  %s  %s\n", report.TermSafe(ind), h.Kind, report.TermSafe(h.Label))
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
	manifestPath := fs.String("manifest", "", "integrity baseline to keep in step (default: integrity.json next to the signature DB)")
	signKey := fs.String("sign-key", "", "Ed25519 private key (hex) to re-sign the baseline after the update")
	noRebaseline := fs.Bool("no-rebaseline", false, "leave the integrity baseline alone (the daemon will treat the new feed as tampered)")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
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
	if !*noRebaseline {
		rebaselineFeed(dest, *manifestPath, *signKey, stdout, stderr)
	}
	return report.ExitOK
}

// rebaselineFeed records the updated feed's digest in the integrity baseline.
//
// Without this a routine `cau feed update` is indistinguishable from an attack:
// `cau defend` verifies the feed against the baseline, so the new file is
// refused, and because the refusal happens on the load path there is no
// previous feed to fall back to after a restart — one ordinary update would
// leave the host with no threat intel at all. Keeping the baseline in step is
// what makes the integrity check something an operator can live with rather
// than something they switch off.
//
// A signed baseline is never rewritten without a key. Saving it with a
// signature that no longer matches would be worse than leaving it: the daemon
// refuses to start on a baseline whose signature does not verify, so the fix
// for a stale feed digest would become an outage. In that case the operator is
// told exactly what to run.
func rebaselineFeed(dest, manifestPath, signKeyFile string, stdout, stderr io.Writer) {
	mpath := manifestPath
	if mpath == "" {
		dbPath, _ := findResource("", envSignatures, relSignatures)
		if dbPath == "" {
			return
		}
		mpath = filepath.Join(filepath.Dir(dbPath), "integrity.json")
	}
	if _, err := os.Stat(mpath); err != nil {
		return // no baseline on this host: nothing to keep in step
	}
	m, err := selftest.ReadManifest(mpath)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] integrity baseline %s could not be read, so it still describes the old feed: %v\n", mpath, err)
		return
	}
	if m.Signature != "" && signKeyFile == "" {
		fmt.Fprintf(stderr, "[WARN] the integrity baseline %s is signed, so it still describes the old feed.\n", mpath)
		fmt.Fprintf(stderr, "       Until it is re-recorded, `cau defend` will refuse this feed as tampered with. Run:\n")
		fmt.Fprintf(stderr, "         cau selftest --record --sign-key <key> --feed %s\n", dest)
		fmt.Fprintf(stderr, "       or re-run this update with --sign-key to do it here.\n")
		return
	}
	sum, isDir, files, err := selftest.Digest(dest)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] could not digest the new feed: %v\n", err)
		return
	}
	entry := selftest.Entry{Name: selftestResFeed, Path: dest, SHA256: sum, IsDir: isDir}
	if isDir {
		entry.Files = files
	}
	replaced := false
	for i := range m.Entries {
		if m.Entries[i].Name == selftestResFeed {
			m.Entries[i], replaced = entry, true
			break
		}
	}
	if !replaced {
		m.Entries = append(m.Entries, entry)
	}
	if signKeyFile != "" {
		keyData, rerr := os.ReadFile(signKeyFile)
		if rerr != nil {
			fmt.Fprintf(stderr, "[WARN] the baseline was not updated: reading the signing key: %v\n", rerr)
			return
		}
		priv, perr := selftest.ParsePrivateKey(keyData)
		if perr != nil {
			fmt.Fprintf(stderr, "[WARN] the baseline was not updated: %v\n", perr)
			return
		}
		m.Sign(priv)
	}
	if err := selftest.WriteManifest(mpath, m); err != nil {
		fmt.Fprintf(stderr, "[WARN] the baseline was not updated: %v\n", err)
		return
	}
	signed := ""
	if m.Signature != "" {
		signed = ", re-signed"
	}
	fmt.Fprintf(stdout, "  baseline  : %s updated for the new feed%s\n", mpath, signed)
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

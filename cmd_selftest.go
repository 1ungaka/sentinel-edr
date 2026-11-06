package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/selftest"
	"github.com/s-b-repo/cau/internal/trust"
)

// envSelftestKey supplies the Ed25519 public key (hex) that a signed integrity
// manifest is verified against, when --pubkey is not given.
const envSelftestKey = "CAU_SELFTEST_PUBKEY"

// pinnedSelftestKey is the baseline-signing key this build trusts, as hex. It
// is empty in source; a release sets it, exactly as pinnedUpdateKey in
// cmd_update.go is set for the update channel.
//
// It exists to close a downgrade. Without it, "no key configured" and "this
// manifest is unsigned" are indistinguishable, so an attacker who rewrites the
// content can replace the signed baseline with an unsigned one of their own and
// the agent has nothing to object to — the strongest check turns itself off
// quietly. With a key pinned into the binary the agent knows a signature is
// expected, so an unsigned or differently-signed baseline is a failure rather
// than a configuration it accepts. Deleting the operator's key file no longer
// helps either, because the build still carries one.
//
// The honest boundary: an attacker who can replace the binary replaces this
// constant with it. That is what `cau verify-self` and the signed update
// channel are for, and it is why this raises the cost of an attack rather than
// ending it.
const pinnedSelftestKey = ""

// Resource names in the integrity baseline. They are constants because the
// recorder and the daemon that verifies a single one of them at reload time
// have to agree on the spelling, and a typo would silently mean "not covered".
const (
	selftestResSignatures = "signatures"
	selftestResRules      = "rules"
	selftestResFuzzy      = "fuzzy"
	selftestResFeed       = "feed"
	selftestResConfig     = "config"
	selftestResBinary     = "binary"
)

// existingPath returns the first path that exists, or "" so the resource is
// skipped rather than recorded as missing.
func existingPath(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// selfExePath is the agent binary, resolved through any symlink so the baseline
// records the file that actually runs.
func selfExePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

// selftestPins records the settings that are not files but would change where
// the agent sends what it finds. Pinning the SIEM address means an attacker who
// edits the configuration can neither silence the stream nor redirect it to
// themselves: the daemon notices the mismatch and keeps using the signed value.
func selftestPins(configPath string, stderr io.Writer) map[string]string {
	cfg, err := trust.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] configuration not pinned: %v\n", err)
		return nil
	}
	if strings.TrimSpace(cfg.SIEM) == "" {
		return nil
	}
	return map[string]string{selftest.PinSIEM: strings.TrimSpace(cfg.SIEM)}
}

func selftestUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau selftest [flags]

Verifies that nothing the agent relies on has been tampered with. It digests
every resource below, compares them against a recorded baseline, and checks the
settings pinned into it. Gutting signatures or neutering a rule is the classic
"impair defenses" move (ATT&CK T1562.001); this catches it.

  signatures  the hash signature database
  rules       the YARA rules
  fuzzy       the fuzzy signature database
  feed        the threat-intel feed
  config      the agent's configuration file
  binary      the agent binary itself
  pin siem    where incidents are forwarded, signed, so editing the config on
              disk can neither silence the stream nor redirect it elsewhere

Detection content is the obvious target; it is not the cheapest one. Emptying
the feed, or repointing the SIEM address at a collector of the attacker's own,
needs no change to a single rule, so both are baselined here too.

First, record a baseline from a known-good install:
  cau selftest --record                 # writes integrity.json next to the DB
  cau selftest --record --sign-key priv.hex   # signed baseline (tamper-resistant)

Then verify, e.g. from a systemd timer or before a scan:
  cau selftest                          # digest check
  cau selftest --pubkey pub.hex         # also verify the manifest signature

A signed manifest verified against a pinned key also defeats an attacker who
rewrites the content *and* the manifest — the signature is the thing they cannot
forge. Keep the signing key off the host.

Flags:
  --manifest <file>  baseline file (default: integrity.json next to the signature DB)
  --record           compute and write the baseline instead of verifying
  --sign-key <file>  Ed25519 private key (hex) to sign the baseline on --record
  --pubkey <file>    Ed25519 public key (hex) to require + verify a signature
                     (also read from $%s). A key that cannot be
                     read or parsed is an error, never a quiet fall back to a
                     digest-only check: that downgrade is what an attacker who
                     deleted the key would be hoping for
  --db / --rules / --fuzzy-db / --feed / --config <path>   override resource
                     locations; a resource that is absent is skipped, not failed

Exit codes: 0 intact, 1 drift or a bad/missing signature, 3 the run failed,
4 usage.
`, envSelftestKey)
}

func cmdSelftest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "baseline manifest file (default: next to the signature DB)")
	record := fs.Bool("record", false, "write the baseline instead of verifying")
	signKey := fs.String("sign-key", "", "Ed25519 private key (hex) to sign the baseline")
	pubKeyFile := fs.String("pubkey", "", "Ed25519 public key (hex) to require and verify a signature")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	fuzzyDB := fs.String("fuzzy-db", "", "fuzzy signature database (default: auto-discovered)")
	feedFlag := fs.String("feed", "", "threat-intel feed (default: auto-discovered)")
	configFlag := fs.String("config", "", "agent configuration file (default "+trust.DefaultConfigPath+")")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}

	// Resolve the resources to baseline. The signature DB is required; rules and
	// fuzzy DB are optional (absent → skipped, not an error).
	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		return fail(stderr, report.ExitRunFailed, "signature database not found; pass --db (searched: %s)", strings.Join(searched, ", "))
	}
	rulesPath, _ := findResource(*rules, envRules, relRules)
	fuzzyPath, _ := findResource(*fuzzyDB, envFuzzy, relFuzzy)

	// Everything the running agent reads and would act differently without.
	// Detection content is the obvious part, but a baseline that stopped there
	// would leave the cheapest attacks untouched: emptying the threat feed,
	// or repointing the agent's configuration at an attacker's collector,
	// needs no change to a single rule.
	resources := []selftest.Resource{
		{Name: selftestResSignatures, Path: dbPath},
		{Name: selftestResRules, Path: rulesPath},
		{Name: selftestResFuzzy, Path: fuzzyPath},
		{Name: selftestResFeed, Path: resolveFeedPath(*feedFlag)},
		{Name: selftestResConfig, Path: existingPath(*configFlag, trust.DefaultConfigPath)},
		{Name: selftestResBinary, Path: selfExePath()},
	}

	mpath := *manifestPath
	if mpath == "" {
		mpath = filepath.Join(filepath.Dir(dbPath), "integrity.json")
	}

	if *record {
		return selftestRecord(resources, mpath, *signKey, selftestPins(*configFlag, stderr), stdout, stderr)
	}
	pub, err := resolveSelftestPubkey(*pubKeyFile)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return selftestVerify(resources, mpath, pub, stdout, stderr)
}

func selftestRecord(resources []selftest.Resource, mpath, signKeyFile string, pins map[string]string, stdout, stderr io.Writer) int {
	m, err := selftest.Compute(resources)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	m.Pins = pins
	if signKeyFile != "" {
		keyData, rerr := os.ReadFile(signKeyFile)
		if rerr != nil {
			return fail(stderr, report.ExitRunFailed, "reading signing key: %v", rerr)
		}
		priv, perr := selftest.ParsePrivateKey(keyData)
		if perr != nil {
			return fail(stderr, report.ExitRunFailed, "%v", perr)
		}
		m.Sign(priv)
	}
	if err := selftest.WriteManifest(mpath, m); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	signed := ""
	if m.Signature != "" {
		signed = " (signed)"
	}
	fmt.Fprintf(stdout, "[+] recorded integrity baseline for %d resource(s) to %s%s\n", len(m.Entries), mpath, signed)
	for _, e := range m.Entries {
		fmt.Fprintf(stdout, "    %-12s %s\n", e.Name, e.SHA256)
	}
	for k, v := range m.Pins {
		fmt.Fprintf(stdout, "    pin %-8s %s\n", k, report.TermSafe(v))
	}
	return report.ExitOK
}

func selftestVerify(resources []selftest.Resource, mpath string, pubKey selftestKey, stdout, stderr io.Writer) int {
	baseline, err := selftest.ReadManifest(mpath)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v (run `cau selftest --record` on a known-good install first)", err)
	}

	// Signature check first: a required signature that is absent or bad is a
	// tamper finding, not merely a content drift.
	if pubKey.set {
		if err := baseline.VerifySignature(pubKey.key); err != nil {
			return fail(stderr, report.ExitThreat, "manifest signature: %v", err)
		}
		fmt.Fprintln(stdout, "[*] manifest signature verified against the pinned key")
	} else if baseline.Signature != "" {
		fmt.Fprintln(stderr, "[WARN] manifest is signed but no --pubkey/$"+envSelftestKey+" was given; signature not checked")
	}

	drift, err := selftest.Verify(baseline)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if len(drift) == 0 {
		fmt.Fprintf(stdout, "[*] detection content intact: %d resource(s) match the baseline\n", len(baseline.Entries))
		return report.ExitOK
	}
	for _, d := range drift {
		fmt.Fprintf(stderr, "[TAMPER] %s: %s\n", d.Name, d.Reason)
	}
	fmt.Fprintf(stderr, "[TAMPER] %d resource(s) drifted from the baseline — detection content may have been altered\n", len(drift))
	return report.ExitThreat
}

type selftestKey struct {
	key ed25519.PublicKey
	set bool
}

// resolveSelftestPubkey loads the key a signature is verified against.
//
// Asking for a key and not getting one must be an error, never a quiet fall
// back to "no key". A pinned key is the only thing that resists an attacker who
// rewrites the content *and* rebaselines the manifest to match, and the signed
// manifest is also what vouches for the pinned SIEM address. So if an
// unreadable or malformed key silently meant "digest check only", deleting or
// corrupting one file would downgrade the agent from the strong state to the
// weak one, and every log line afterwards would still look healthy. Making it
// loud costs an operator one clear message about a typo; the alternative costs
// them the guarantee they thought they had.
//
// A key that was never asked for and is not pinned into the build is not a
// failure, and returns the zero value.
func resolveSelftestPubkey(file string) (selftestKey, error) {
	var raw []byte
	var origin string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return selftestKey{}, fmt.Errorf("reading the pinned public key %s: %w; refusing to fall back to an unsigned check", file, err)
		}
		raw, origin = b, file
	case os.Getenv(envSelftestKey) != "":
		raw, origin = []byte(os.Getenv(envSelftestKey)), "$"+envSelftestKey
	case pinnedSelftestKey != "":
		raw, origin = []byte(pinnedSelftestKey), "the key pinned into this build"
	default:
		return selftestKey{}, nil
	}
	k, err := selftest.ParsePublicKey(raw)
	if err != nil {
		return selftestKey{}, fmt.Errorf("the pinned public key in %s is not usable: %w; refusing to fall back to an unsigned check", origin, err)
	}
	return selftestKey{key: k, set: true}, nil
}

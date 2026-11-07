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
// is empty in source and set at link time, the same way main.version is:
//
//	make build SELFTEST_PUBKEY=$(cat pub.hex)
//
// It is a var rather than a const for exactly that reason — `-ldflags -X` can
// only write to a variable. A release sets it, and so can anyone building from
// source, which is the point: a self-built binary that pinned nothing would
// leave the downgrade below open on precisely the installs whose owner cared
// enough to compile it.
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
var pinnedSelftestKey = ""

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
	selftestResSIEMCA     = "siem-ca"
	selftestResCanary     = "canary-manifest"
)

// siemCAPath is the CA bundle the configuration points the forwarder at, or ""
// when none is configured.
func siemCAPath(configPath string) string {
	cfg, err := trust.LoadConfig(configPath)
	if err != nil {
		return ""
	}
	return cfg.SIEMCA
}

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
	pins := map[string]string{}
	if v := strings.TrimSpace(cfg.SIEM); v != "" {
		pins[selftest.PinSIEM] = v
	}
	// The certificate pin decides who may answer at that address, so leaving it
	// unsigned would reopen the redirect from the other end: swap the pin on
	// disk for your own collector's and the address check still passes.
	if len(cfg.SIEMCertPins) > 0 {
		pins[selftest.PinSIEMCert] = strings.Join(cfg.SIEMCertPins, ",")
	}
	if len(pins) == 0 {
		return nil
	}
	return pins
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
  siem-ca     the CA bundle that decides whose certificate is accepted
  canary-manifest  the baseline of the planted decoys: replacing it with one
                   that records nothing silences every canary, so its digest is
                   signed with the rest
  pin siem    where incidents are forwarded, signed, so editing the config on
              disk can neither silence the stream nor redirect it elsewhere
  pin siem-cert  which public key may answer at that address, signed for the
              same reason: an attacker able to edit it would substitute their
              own collector's pin

Detection content is the obvious target; it is not the cheapest one. Emptying
the feed, repointing the SIEM address at a collector of the attacker's own, or
emptying the canary manifest needs no change to a single rule, so those are
baselined here too.

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
  --db / --rules / --fuzzy-db / --feed / --config / --canary-manifest <path>
                      override resource locations; an overridden resource is
                      verified where it now lives. An override the baseline does
                      not cover is an error: re-record to cover it

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
	canaryManifest := fs.String("canary-manifest", "", "canary manifest from `cau canary plant` (default: auto-discovered)")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}

	// Which override flags the operator actually set, by resource name. Only
	// those are passed on as overrides: a flag that was not set leaves the
	// baseline's own recorded path in place. See selftestVerify.
	setFlag := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "db":
			setFlag[selftestResSignatures] = true
		case "rules":
			setFlag[selftestResRules] = true
		case "fuzzy-db":
			setFlag[selftestResFuzzy] = true
		case "feed":
			setFlag[selftestResFeed] = true
		case "config":
			setFlag[selftestResConfig] = true
		case "canary-manifest":
			setFlag[selftestResCanary] = true
		}
	})

	// Resolve the resources to baseline. The signature DB is required; rules and
	// fuzzy DB are optional (absent → skipped, not an error).
	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		return fail(stderr, report.ExitRunFailed, "signature database not found; pass --db (searched: %s)", strings.Join(searched, ", "))
	}
	rulesPath, _ := findResource(*rules, envRules, relRules)
	fuzzyPath, _ := findResource(*fuzzyDB, envFuzzy, relFuzzy)

	// The canary manifest is the baseline of the planted decoys, and it sits on
	// the same disk under the same UID as the decoys it describes. Swapping it
	// for one that baselines nothing — it still parses — silences every canary
	// on the host with no alert anywhere, so its digest belongs in this baseline
	// too. It is optional: a host with no decoys has no manifest to record, and
	// Compute skips a resource with no path. It is resolved the way `cau defend`
	// resolves it, so what is recorded is the manifest the daemon actually reads;
	// an explicit path is taken verbatim, so a typo is reported rather than
	// quietly baselining some other file.
	canaryPath := *canaryManifest
	if canaryPath == "" {
		canaryPath = discoverCanaryManifest(func(format string, args ...interface{}) {
			fmt.Fprintf(stderr, format+"\n", args...)
		})
	}

	// Everything the running agent reads and would act differently without.
	// Detection content is the obvious part, but a baseline that stopped there
	// would leave the cheapest attacks untouched: emptying the threat feed,
	// repointing the agent's configuration at an attacker's collector, or
	// emptying the canary manifest so no decoy can trip, needs no change to a
	// single rule.
	resources := []selftest.Resource{
		{Name: selftestResSignatures, Path: dbPath},
		{Name: selftestResRules, Path: rulesPath},
		{Name: selftestResFuzzy, Path: fuzzyPath},
		{Name: selftestResFeed, Path: resolveFeedPath(*feedFlag)},
		{Name: selftestResConfig, Path: existingPath(*configFlag, trust.DefaultConfigPath)},
		{Name: selftestResBinary, Path: selfExePath()},
		// The CA bundle decides who is allowed to answer at the SIEM address.
		// Pinning the address without pinning this would leave the other half
		// of the same redirect open: swap the bundle for one you control and
		// the stream goes to you with TLS verification still "on".
		{Name: selftestResSIEMCA, Path: existingPath(siemCAPath(*configFlag))},
		{Name: selftestResCanary, Path: canaryPath},
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
	return selftestVerify(resources, mpath, pub, setFlag, stdout, stderr)
}

func selftestRecord(resources []selftest.Resource, mpath, signKeyFile string, pins map[string]string, stdout, stderr io.Writer) int {
	m, err := selftest.Compute(resources)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	m.Pins = pins
	if signKeyFile != "" {
		keyData, rerr := readPrivateKey(signKeyFile)
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

func selftestVerify(resources []selftest.Resource, mpath string, pubKey selftestKey, setFlag map[string]bool, stdout, stderr io.Writer) int {
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

	// Only a flag the operator actually set is an override. Deriving them from
	// every resolved resource instead would silently redirect a baseline entry
	// to a discovered path the manifest never named — and error out on a
	// baseline that legitimately does not cover a resource this host happens to
	// have. The verifier is told where the override flags point, so an
	// overridden resource is checked where the operator says it now lives.
	overrides := map[string]string{}
	for _, r := range resources {
		if setFlag[r.Name] && r.Path != "" {
			overrides[r.Name] = r.Path
		}
	}
	drift, err := selftest.VerifyWithOverrides(baseline, overrides)
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
		// readPublicKey, not a stricter local read, so the policy for how a key
		// path may be read lives in one place rather than here as well.
		//
		// This is the read that made the policy matter. `cau defend` resolves
		// the key at startup, before it signals readiness, and a pipe held open
		// by a silent writer used to make it wait 120.1s — past systemd's 90s
		// default TimeoutStartSec, so the unit was killed as a failed start and
		// restarted into the same wall. Anyone able to write to the directory
		// holding the public key had a kill switch for the whole agent, needing
		// no edit to the unit file or the flags. readPublicKey now waits five
		// seconds, because a public key has nothing to prompt a human for,
		// while a private key keeps the long wait for `--sign-key <(pass show
		// cau/key)`. That split belongs with the key reading, not here.
		b, err := readPublicKey(file)
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

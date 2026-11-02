package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/internal/selftest"
)

// envSelftestKey supplies the Ed25519 public key (hex) that a signed integrity
// manifest is verified against, when --pubkey is not given.
const envSelftestKey = "CAU_SELFTEST_PUBKEY"

func selftestUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau selftest [flags]

Verifies that the engine's detection content has not been tampered with:
it digests the signature database, the YARA rules and the fuzzy database and
compares them against a recorded baseline. Gutting signatures or neutering a
rule is the classic "impair defenses" move (ATT&CK T1562.001); this catches it.

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
                     (also read from $%s)
  --db / --rules / --fuzzy-db <path>   override resource locations

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
	if err := fs.Parse(args); err != nil {
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

	resources := []selftest.Resource{
		{Name: "signatures", Path: dbPath},
		{Name: "rules", Path: rulesPath},
		{Name: "fuzzy", Path: fuzzyPath},
	}

	mpath := *manifestPath
	if mpath == "" {
		mpath = filepath.Join(filepath.Dir(dbPath), "integrity.json")
	}

	if *record {
		return selftestRecord(resources, mpath, *signKey, stdout, stderr)
	}
	return selftestVerify(resources, mpath, resolveSelftestPubkey(*pubKeyFile), stdout, stderr)
}

func selftestRecord(resources []selftest.Resource, mpath, signKeyFile string, stdout, stderr io.Writer) int {
	m, err := selftest.Compute(resources)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
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

func resolveSelftestPubkey(file string) selftestKey {
	var raw []byte
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return selftestKey{}
		}
		raw = b
	case os.Getenv(envSelftestKey) != "":
		raw = []byte(os.Getenv(envSelftestKey))
	default:
		return selftestKey{}
	}
	k, err := selftest.ParsePublicKey(raw)
	if err != nil {
		return selftestKey{}
	}
	return selftestKey{key: k, set: true}
}

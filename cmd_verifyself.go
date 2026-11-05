package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/intake"
	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
)

func verifySelfUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau verify-self (--from <dir> | --url <base>) [flags]

Verifies the running binary against a signed release manifest — the secure way
to answer "is this the authoritative build, unmodified". It computes its own
SHA-256, fetches the release's %s and %s (a detached Ed25519 signature over it),
verifies the signature against the trusted key, and only then compares its own
digest to the signed entry. A MITM of the download cannot forge the signature,
so a tampered binary or manifest fails closed.

The trusted key is the same release anchor as 'cau update': --pubkey, else
$%s, else the key pinned in the build. The manifest is fetched over HTTPS
(--url) or read from a local/air-gapped copy (--from).

Flags:
  --from <dir>    read %s and %s from a directory
  --url <base>    fetch <base>/%s and <base>/%s over HTTPS
  --pubkey <file> trusted Ed25519 public key (hex); overrides the pinned key
  --name <name>   the binary's filename as listed in %s (default: the running
                  executable's own name)

Exit codes: 0 verified, 1 verification failed (bad signature, not listed, or
digest mismatch), 3 the run failed, 4 usage.
`, release.SumsName, release.SigName, envUpdateKey,
		release.SumsName, release.SigName, release.SumsName, release.SigName, release.SumsName)
}

func cmdVerifySelf(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-self", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "directory holding SHA256SUMS and SHA256SUMS.sig")
	url := fs.String("url", "", "base URL to fetch the signed manifest from")
	pubkeyFile := fs.String("pubkey", "", "trusted Ed25519 public key file (hex)")
	nameOverride := fs.String("name", "", "the binary's name in SHA256SUMS (default: the running executable)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if (*from == "") == (*url == "") {
		return fail(stderr, report.ExitUsage, "give exactly one of --from or --url")
	}

	key, err := resolveUpdateKey(*pubkeyFile)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if len(key) == 0 {
		return fail(stderr, report.ExitRunFailed, "no trusted public key: pass --pubkey or set %s (fail-closed: cannot verify)", envUpdateKey)
	}

	sumsData, sigData, err := loadChecksums(*from, *url, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	// Signature first, then content — a bad signature is a tamper finding.
	if err := release.VerifySignature(sumsData, sigData, ed25519.PublicKey(key)); err != nil {
		return fail(stderr, report.ExitThreat, "%v", err)
	}
	sums, err := release.Parse(sumsData)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	digest, selfName, err := release.SelfDigest()
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	name := selfName
	if *nameOverride != "" {
		name = *nameOverride
	}
	if err := sums.VerifyFile(name, digest); err != nil {
		return fail(stderr, report.ExitThreat, "%v", err)
	}
	fmt.Fprintf(stdout, "[*] verified: %s (%s) matches the signed release manifest\n", name, digest)
	return report.ExitOK
}

// loadChecksums reads SHA256SUMS + .sig from a directory or an explicit URL.
func loadChecksums(from, url string, stderr io.Writer) (sums, sig []byte, err error) {
	if from != "" {
		if sums, err = os.ReadFile(filepath.Join(from, release.SumsName)); err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", release.SumsName, err)
		}
		if sig, err = os.ReadFile(filepath.Join(from, release.SigName)); err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", release.SigName, err)
		}
		return sums, sig, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	base := strings.TrimRight(url, "/")
	if sums, err = intake.Fetch(ctx, base+"/"+release.SumsName); err != nil {
		return nil, nil, err
	}
	if sig, err = intake.Fetch(ctx, base+"/"+release.SigName); err != nil {
		return nil, nil, err
	}
	return sums, sig, nil
}

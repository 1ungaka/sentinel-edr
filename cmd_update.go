package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/intake"
	"github.com/1ungaka/sentinel-edr/internal/release"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/internal/updater"
)

// pinnedUpdateKey is the release signing key the engine trusts. It is empty in
// source; the release process sets it (and the matching private key signs the
// bundle in CI). It holds a public key in either form release.ParseVerifyKey
// reads: the hex of an Ed25519 key, or the three lines of a hybrid
// (Ed25519 + ML-DSA-65) key, in which case every bundle and every SHA256SUMS
// must carry both signatures. With no key configured here and none passed via
// --pubkey / CAU_UPDATE_PUBKEY, `cau update` refuses to install anything —
// fail-closed by default.
const pinnedUpdateKey = ""

// envUpdateKey overrides the pinned key with the content of a public key, in
// either form (a hybrid key's three lines, newlines included).
const envUpdateKey = "CAU_UPDATE_PUBKEY"

func updateUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau update (--from <dir> | --url <base>) [flags]

Installs a signed signature-database bundle, fail-closed. The engine never
fetches on its own — this is always an explicit command. A bundle is three
files: %s, %s and %s (a detached signature over the manifest). The
manifest carries the payload's SHA-256, so one signature file covers
everything.

Nothing on disk changes unless the signature verifies against the pinned key,
the payload digest matches the signed manifest, the bundle's
min-engine-version is satisfied, and the bundle is not older than the one
installed. On success the live database is replaced atomically, the previous
one is kept as <db>.bak, and the manifest is recorded as <db>%s.

The trusted key decides what the signature must carry. An Ed25519 key (hex)
needs a valid Ed25519 signature. A hybrid key (a cau-hybrid-v1 public-key
file: Ed25519 + %s) needs BOTH signatures to be valid; a bundle
signed with Ed25519 alone is refused, so the post-quantum half cannot be
stripped. An Ed25519 key still verifies a hybrid-signed bundle, on its Ed25519
half, and says the %s signature was not checked. The output names
what was checked ("signature verified: Ed25519 + %s").

Flags:
  --from <dir>    read the bundle from a local directory
  --url <base>    fetch <base>/%s, <base>/%s and <base>/%s over HTTP(S)
  --pubkey <file> trusted public key, Ed25519 (hex) or hybrid; overrides the
                  pinned key and $%s (which holds a key's content, not a
                  path). A key that is named and cannot be read or parsed is
                  an error, never "no key"
  --db <path>     signature database to replace (default: auto-discovered)
  --dry-run       verify only; report what would be installed, change nothing
  --allow-downgrade
                  install a bundle older than the current one, to back out a
                  bad release

Exit codes: 0 ok, 1 verification failed, 3 the run failed, 4 usage.
`, updater.PayloadName, updater.ManifestName, updater.SignatureName, updater.StateSuffix,
		release.PQName, release.PQName, release.PQName,
		updater.PayloadName, updater.ManifestName, updater.SignatureName, envUpdateKey)
}

func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "read the bundle from a local directory")
	url := fs.String("url", "", "fetch the bundle from this base URL")
	pubkeyFile := fs.String("pubkey", "", "trusted public key file: Ed25519 (hex) or hybrid (cau-hybrid-v1)")
	db := fs.String("db", "", "signature database to replace (default: auto-discovered)")
	dryRun := fs.Bool("dry-run", false, "verify only; change nothing")
	allowDowngrade := fs.Bool("allow-downgrade", false, "install a bundle older than the current one")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if (*from == "") == (*url == "") {
		return fail(stderr, report.ExitUsage, "give exactly one of --from or --url")
	}

	key, err := resolveUpdateKey(*pubkeyFile)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
	}
	if key.IsZero() {
		return fail(stderr, report.ExitRunFailed, "no trusted public key: pass --pubkey or set %s (fail-closed: nothing installed)", envUpdateKey)
	}

	bundle, err := loadUpdateBundle(*from, *url, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	v, checked, err := updater.VerifyWithKey(bundle, key, version)
	if err != nil {
		// A verification failure is a finding (exit 1), not a run error. The
		// reason can quote the signature file, so it is made terminal-safe.
		return fail(stderr, report.ExitThreat, "%s", report.TermSafe(err.Error()))
	}
	fmt.Fprintf(stdout, "[*] verified bundle: db_version %s, min-engine %s, %d payload bytes\n",
		report.TermSafe(orDash(v.Manifest.DBVersion)), report.TermSafe(orDash(v.Manifest.MinEngineVersion)), len(v.Payload))
	reportChecked(stdout, stderr, checked)

	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		dbPath = *db // install to the explicit path even if it does not exist yet
	}

	// Before the dry-run return, so a dry run does not promise an install that
	// would be refused.
	if dbPath != "" && !*allowDowngrade {
		if err := updater.CheckRollback(dbPath, v.Manifest); err != nil {
			code := report.ExitRunFailed
			if errors.Is(err, updater.ErrRollback) {
				code = report.ExitThreat // a replayed bundle is a finding, like a bad signature
			}
			return fail(stderr, code, "%v (--allow-downgrade installs it anyway)", err)
		}
	}

	if *dryRun {
		fmt.Fprintln(stdout, "[*] dry-run: signature and digest verified; nothing installed")
		return report.ExitOK
	}

	if dbPath == "" {
		return fail(stderr, report.ExitRunFailed, "signature database not found; pass --db (searched: %s)", strings.Join(searched, ", "))
	}
	rollback, err := updater.Apply(dbPath, v, *allowDowngrade)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if rollback != "" {
		fmt.Fprintf(stdout, "[+] installed %s (previous kept at %s)\n", dbPath, rollback)
	} else {
		fmt.Fprintf(stdout, "[+] installed %s\n", dbPath)
	}
	return report.ExitOK
}

// reportChecked says which signatures a successful verification checked, and
// warns when a post-quantum signature was present and not checked. `cau
// update` and `cau verify-self` share it.
func reportChecked(stdout, stderr io.Writer, c release.Checked) {
	fmt.Fprintf(stdout, "[*] signature verified: %s\n", c)
	if note := c.Note(); note != "" {
		fmt.Fprintf(stderr, "[WARN] %s\n", note)
	}
}

// maxPubkeyFileBytes bounds --pubkey before it is parsed. A hybrid public key
// is about 4 KiB; nothing valid is near this.
const maxPubkeyFileBytes = 64 << 10

// resolveUpdateKey loads the release key `cau update` and `cau verify-self`
// trust: --pubkey, else $CAU_UPDATE_PUBKEY, else the key pinned in the build.
// The key is Ed25519-only or hybrid, by its on-disk form.
//
// A key that was named and cannot be read or parsed is an error, never "no
// key" and never a weaker key: a hybrid key file that is truncated, of an
// unknown version, or loaded by a binary that has no ML-DSA does not fall back
// to its Ed25519 half. The zero value with a nil error means only that no key
// was named anywhere, which both callers refuse.
func resolveUpdateKey(file string) (release.VerifyKey, error) {
	var raw []byte
	var origin string
	switch {
	case file != "":
		data, err := readPublicKey(file)
		if err != nil {
			return release.VerifyKey{}, fmt.Errorf("reading public key: %w", err)
		}
		raw, origin = data, file
	case os.Getenv(envUpdateKey) != "":
		raw, origin = []byte(os.Getenv(envUpdateKey)), "$"+envUpdateKey
	case pinnedUpdateKey != "":
		raw, origin = []byte(pinnedUpdateKey), "the key pinned into this build"
	default:
		return release.VerifyKey{}, nil
	}
	key, err := release.ParseVerifyKey(raw)
	if err != nil {
		return release.VerifyKey{}, fmt.Errorf("the public key in %s is not usable: %w", origin, err)
	}
	return key, nil
}

// How long a key named on the command line may take to arrive through a pipe.
// A private key can wait for a person, because the command behind the pipe may
// stop at a pinentry prompt. A public key is not a secret and has nothing to
// prompt for, and it is what cau defend, cau verify-self and the update timer
// read with nobody watching: a stalled writer must not keep the EDR from
// starting for minutes.
const (
	privateKeyPipeWait = 2 * time.Minute
	publicKeyPipeWait  = 5 * time.Second
)

func readPrivateKey(path string) ([]byte, error) {
	return readKeyFile(path, maxSignKeyFileBytes, privateKeyPipeWait)
}

func readPublicKey(path string) ([]byte, error) {
	return readKeyFile(path, maxPubkeyFileBytes, publicKeyPipeWait)
}

// readKeyFile reads a key file, or a pipe carrying one, and refuses anything
// larger than max, so a key path pointed at something huge is an error and not
// an allocation. See safefs.ReadOperatorFile for what it accepts.
func readKeyFile(path string, max int64, wait time.Duration) ([]byte, error) {
	data, err := safefs.ReadOperatorFile(path, max, wait)
	if errors.Is(err, safefs.ErrTooLarge) {
		return nil, fmt.Errorf("%s is larger than %d bytes, which no key file is", path, max)
	}
	return data, err
}

func loadUpdateBundle(from, url string, stderr io.Writer) (updater.Bundle, error) {
	if from != "" {
		return updater.LoadBundleDir(from)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	base := strings.TrimRight(url, "/")
	var b updater.Bundle
	var err error
	if b.Payload, err = intake.Fetch(ctx, base+"/"+updater.PayloadName); err != nil {
		return updater.Bundle{}, err
	}
	if b.Manifest, err = intake.Fetch(ctx, base+"/"+updater.ManifestName); err != nil {
		return updater.Bundle{}, err
	}
	sig, err := intake.Fetch(ctx, base+"/"+updater.SignatureName)
	if err != nil {
		return updater.Bundle{}, err
	}
	b.Signature = updater.NormalizeSignature(sig)
	return b, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

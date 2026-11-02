package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/intake"
	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/internal/updater"
)

// pinnedUpdateKey is the release signing key the engine trusts, as hex. It is
// empty in source; the release process sets it (and the matching private key
// signs the bundle in CI). With no key configured here and none passed via
// --pubkey / CAU_UPDATE_PUBKEY, `cau update` refuses to install anything —
// fail-closed by default.
const pinnedUpdateKey = ""

// envUpdateKey overrides the pinned key with a hex public key.
const envUpdateKey = "CAU_UPDATE_PUBKEY"

func updateUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau update (--from <dir> | --url <base>) [flags]

Installs a signed signature-database bundle, fail-closed. The engine never
fetches on its own — this is always an explicit command. A bundle is three
files: %s, %s and %s (a detached Ed25519 signature over the manifest). The
manifest carries the payload's SHA-256, so one signature covers everything.

Nothing on disk changes unless the signature verifies against the pinned key,
the payload digest matches the signed manifest, and the bundle's
min-engine-version is satisfied. On success the live database is replaced
atomically and the previous one is kept as <db>.bak.

Flags:
  --from <dir>    read the bundle from a local directory
  --url <base>    fetch <base>/%s, <base>/%s and <base>/%s over HTTP(S)
  --pubkey <file> trusted Ed25519 public key (hex); overrides the pinned key
                  and $%s
  --db <path>     signature database to replace (default: auto-discovered)
  --dry-run       verify only; report what would be installed, change nothing

Exit codes: 0 ok, 1 verification failed, 3 the run failed, 4 usage.
`, updater.PayloadName, updater.ManifestName, updater.SignatureName,
		updater.PayloadName, updater.ManifestName, updater.SignatureName, envUpdateKey)
}

func cmdUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "read the bundle from a local directory")
	url := fs.String("url", "", "fetch the bundle from this base URL")
	pubkeyFile := fs.String("pubkey", "", "trusted Ed25519 public key file (hex)")
	db := fs.String("db", "", "signature database to replace (default: auto-discovered)")
	dryRun := fs.Bool("dry-run", false, "verify only; change nothing")
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
		return fail(stderr, report.ExitRunFailed, "no trusted public key: pass --pubkey or set %s (fail-closed: nothing installed)", envUpdateKey)
	}

	bundle, err := loadUpdateBundle(*from, *url, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	v, err := updater.Verify(bundle, key, version)
	if err != nil {
		// A verification failure is a finding (exit 1), not a run error.
		return fail(stderr, report.ExitThreat, "%v", err)
	}
	fmt.Fprintf(stdout, "[*] verified bundle: db_version %s, min-engine %s, %d payload bytes\n",
		orDash(v.Manifest.DBVersion), orDash(v.Manifest.MinEngineVersion), len(v.Payload))

	if *dryRun {
		fmt.Fprintln(stdout, "[*] dry-run: signature and digest verified; nothing installed")
		return report.ExitOK
	}

	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		if *db != "" {
			dbPath = *db // install to the explicit path even if it does not exist yet
		} else {
			return fail(stderr, report.ExitRunFailed, "signature database not found; pass --db (searched: %s)", strings.Join(searched, ", "))
		}
	}
	rollback, err := updater.Apply(dbPath, v)
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

func resolveUpdateKey(file string) (ed25519.PublicKey, error) {
	switch {
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading public key: %w", err)
		}
		return updater.ParsePublicKey(data)
	case os.Getenv(envUpdateKey) != "":
		return updater.ParsePublicKey([]byte(os.Getenv(envUpdateKey)))
	case pinnedUpdateKey != "":
		return updater.ParsePublicKey([]byte(pinnedUpdateKey))
	}
	return nil, nil
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

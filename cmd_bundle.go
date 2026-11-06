package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/updater"
)

func bundleUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau bundle <subcommand> [flags]

Producer-side signing for releases (run in CI with the signing key from a
secret). Three artifacts:

  update      write a signed signature-DB bundle for 'cau update'
              (hashes.txt + manifest.json + manifest.json.sig)
  checksums   write a signed SHA256SUMS (+ .sig) over release files, which
              'cau verify-self' and users check downloads against
  sbom        write a CycloneDX software bill of materials for a Go binary,
              read from the build information embedded in the binary itself
              (this binary by default, or --binary <path>)

Examples:
  cau bundle update    --db signatures/hashes.txt --sign-key priv.hex --out dist \
                       --db-version 2026.11.02 --min-engine 0.4.0
  cau bundle checksums --sign-key priv.hex --out dist dist/cau-linux-amd64 dist/hashes.txt
  cau bundle sbom      --output dist/cau.cdx.json
  cau bundle sbom      --binary ./cau-mcp --output dist/cau-mcp.cdx.json

Exit codes: 0 ok, 3 failed, 4 usage.
`)
}

func cmdBundle(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		bundleUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "update":
		return bundleUpdate(args[1:], stdout, stderr)
	case "checksums":
		return bundleChecksums(args[1:], stdout, stderr)
	case "sbom":
		return bundleSBOM(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		bundleUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown bundle subcommand %q\n\n", args[0])
		bundleUsage(stderr)
		return report.ExitUsage
	}
}

func loadSigningKey(file string, stderr io.Writer) (ed25519.PrivateKey, int) {
	if file == "" {
		return nil, fail(stderr, report.ExitUsage, "--sign-key is required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fail(stderr, report.ExitRunFailed, "reading signing key: %v", err)
	}
	priv, err := release.ParsePrivateKey(data)
	if err != nil {
		return nil, fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return priv, report.ExitOK
}

func bundleUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "", "signature database payload (hashes.txt)")
	signKey := fs.String("sign-key", "", "Ed25519 private key file (hex)")
	out := fs.String("out", ".", "output directory for the bundle")
	dbVersion := fs.String("db-version", "", "db_version to record in the manifest")
	minEngine := fs.String("min-engine", "", "min_engine_version to record in the manifest")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *db == "" {
		return fail(stderr, report.ExitUsage, "--db is required")
	}
	priv, code := loadSigningKey(*signKey, stderr)
	if code != report.ExitOK {
		return code
	}
	payload, err := os.ReadFile(*db)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "reading %s: %v", *db, err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	manifest := updater.BuildManifest(payload, *dbVersion, *minEngine)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	sig := ed25519.Sign(priv, manifestBytes)
	files := map[string][]byte{
		updater.PayloadName:   payload,
		updater.ManifestName:  manifestBytes,
		updater.SignatureName: []byte(hexEncode(sig)),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v", name, err)
		}
	}
	fmt.Fprintf(stdout, "[+] wrote signed update bundle to %s (%s, %s, %s)\n", *out, updater.PayloadName, updater.ManifestName, updater.SignatureName)
	return report.ExitOK
}

func bundleChecksums(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle checksums", flag.ContinueOnError)
	fs.SetOutput(stderr)
	signKey := fs.String("sign-key", "", "Ed25519 private key file (hex)")
	out := fs.String("out", ".", "output directory for SHA256SUMS and SHA256SUMS.sig")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() == 0 {
		return fail(stderr, report.ExitUsage, "give one or more files to checksum")
	}
	priv, code := loadSigningKey(*signKey, stderr)
	if code != report.ExitOK {
		return code
	}
	sums := map[string]string{}
	for _, f := range fs.Args() {
		d, err := release.DigestFile(f)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		sums[filepath.Base(f)] = d
	}
	sumsData := release.Format(sums)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*out, release.SumsName), sumsData, 0o644); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*out, release.SigName), release.Sign(sumsData, priv), 0o644); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "[+] wrote %s and %s over %d file(s) to %s\n", release.SumsName, release.SigName, fs.NArg(), *out)
	return report.ExitOK
}

func hexEncode(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0x0f]
	}
	return string(out)
}

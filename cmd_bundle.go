package main

import (
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
	fmt.Fprintf(w, `Usage: cau bundle <subcommand> [flags]

Producer-side signing for releases (run in CI with the signing key from a
secret). Three artifacts and the key that signs two of them:

  update      write a signed signature-DB bundle for 'cau update'
              (hashes.txt + manifest.json + manifest.json.sig)
  checksums   write a signed SHA256SUMS (+ .sig) over release files, which
              'cau verify-self' and users check downloads against
  sbom        write a CycloneDX software bill of materials for a Go binary,
              read from the build information embedded in the binary itself
              (this binary by default, or --binary <path>)
  keygen      write a new release signing key and its public key:
              --out <dir> [--hybrid] [--ed25519-key <file>]

--sign-key takes either kind of private key and the kind decides what is
written. An Ed25519 key (hex) writes an Ed25519 signature, as it always has.
A hybrid key (a cau-hybrid-v1 private-key file from 'keygen --hybrid') writes
a cau-hybrid-v1 signature carrying an Ed25519 and an %[1]s signature
over the same bytes. A verifier that trusts the hybrid public key requires
both; one that trusts only the Ed25519 public key still verifies the Ed25519
half.

keygen writes %[2]s (mode 0600) and %[3]s into --out
and refuses to overwrite either. Without --hybrid the pair is Ed25519, in the
hex form. With --hybrid it is Ed25519 + %[1]s. --ed25519-key <file>
(with --hybrid) keeps an existing Ed25519 private key as the classical half
and adds a new %[1]s half to it, so every host that pins today's
Ed25519 public key keeps verifying what the upgraded key signs. Generate the
key on the machine that will hold it, not on a host that verifies with it.

Examples:
  cau bundle update    --db signatures/hashes.txt --sign-key priv.hex --out dist \
                       --db-version 2026.11.02 --min-engine 0.4.0
  cau bundle checksums --sign-key priv.hex --out dist dist/cau-linux-amd64 dist/hashes.txt
  cau bundle sbom      --output dist/cau.cdx.json
  cau bundle sbom      --binary ./cau-mcp --output dist/cau-mcp.cdx.json
  cau bundle keygen    --out keys --hybrid
  cau bundle keygen    --out keys --hybrid --ed25519-key priv.hex

Exit codes: 0 ok, 3 failed, 4 usage.
`, release.PQName, keygenPrivName, keygenPubName)
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
	case "keygen":
		return bundleKeygen(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		bundleUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown bundle subcommand %q\n\n", args[0])
		bundleUsage(stderr)
		return report.ExitUsage
	}
}

// maxSignKeyFileBytes bounds --sign-key before it is parsed. The largest
// valid private key file is under 200 bytes.
const maxSignKeyFileBytes = 64 << 10

// loadSigningKey reads --sign-key in either form: the hex of an Ed25519 key,
// or a hybrid private-key file. A hybrid file that is malformed, or that this
// binary cannot use because it has no ML-DSA, is an error: it never signs with
// the Ed25519 half alone.
func loadSigningKey(file string, stderr io.Writer) (release.SignKey, int) {
	if file == "" {
		return release.SignKey{}, fail(stderr, report.ExitUsage, "--sign-key is required")
	}
	data, err := readPrivateKey(file)
	if err != nil {
		return release.SignKey{}, fail(stderr, report.ExitRunFailed, "reading signing key: %v", err)
	}
	key, err := release.ParseSignKey(data)
	if err != nil {
		return release.SignKey{}, fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
	}
	return key, report.ExitOK
}

// reportSigned adds a line when the signature just written is hybrid. An
// Ed25519 key prints nothing more than it always has.
func reportSigned(stdout io.Writer, key release.SignKey) {
	if key.Hybrid() {
		fmt.Fprintf(stdout, "[+] signed with: %s\n", key.Algorithms())
	}
}

func bundleUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db := fs.String("db", "", "signature database payload (hashes.txt)")
	signKey := fs.String("sign-key", "", "private key file: Ed25519 (hex) or hybrid (cau-hybrid-v1)")
	out := fs.String("out", ".", "output directory for the bundle")
	dbVersion := fs.String("db-version", "", "db_version to record in the manifest")
	minEngine := fs.String("min-engine", "", "min_engine_version to record in the manifest")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *db == "" {
		return fail(stderr, report.ExitUsage, "--db is required")
	}
	key, code := loadSigningKey(*signKey, stderr)
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
	// Ed25519 key: the hex Ed25519 signature, as before. Hybrid key: both
	// signatures over these same bytes, in the hybrid form.
	sig, err := release.SignDetached(manifestBytes, key, release.DomainUpdateManifest)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	files := map[string][]byte{
		updater.PayloadName:   payload,
		updater.ManifestName:  manifestBytes,
		updater.SignatureName: sig,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(*out, name), data, 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v", name, err)
		}
	}
	fmt.Fprintf(stdout, "[+] wrote signed update bundle to %s (%s, %s, %s)\n", *out, updater.PayloadName, updater.ManifestName, updater.SignatureName)
	reportSigned(stdout, key)
	return report.ExitOK
}

func bundleChecksums(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle checksums", flag.ContinueOnError)
	fs.SetOutput(stderr)
	signKey := fs.String("sign-key", "", "private key file: Ed25519 (hex) or hybrid (cau-hybrid-v1)")
	out := fs.String("out", ".", "output directory for SHA256SUMS and SHA256SUMS.sig")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() == 0 {
		return fail(stderr, report.ExitUsage, "give one or more files to checksum")
	}
	key, code := loadSigningKey(*signKey, stderr)
	if code != report.ExitOK {
		return code
	}
	// Keyed by basename, because that is the name a downloader and
	// `cau verify-self --name` look a release file up by. Two inputs sharing a
	// basename would therefore overwrite each other, and the signed manifest
	// would cover fewer files than the success line counts — so the collision
	// is an error, not a silent drop.
	sums := map[string]string{}
	firstSeen := map[string]string{}
	for _, f := range fs.Args() {
		d, err := release.DigestFile(f)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		name := filepath.Base(f)
		if prev, dup := firstSeen[name]; dup {
			return fail(stderr, report.ExitRunFailed,
				"two inputs share the name %s (%s and %s): %s holds one digest per name, so one file would be left out of the signed manifest; give them distinct names",
				name, prev, f, release.SumsName)
		}
		firstSeen[name] = f
		sums[name] = d
	}
	// The counts must agree before anything is written. A manifest covering
	// fewer files than the success line claims is the bug the collision check
	// above exists to prevent, so a run that would write one writes nothing.
	if len(sums) != fs.NArg() {
		return fail(stderr, report.ExitRunFailed, "internal: %d of %d input file(s) recorded", len(sums), fs.NArg())
	}
	sumsData := release.Format(sums)
	sig, err := release.SignChecksums(sumsData, key)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*out, release.SumsName), sumsData, 0o644); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := os.WriteFile(filepath.Join(*out, release.SigName), sig, 0o644); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "[+] wrote %s and %s over %d file(s) to %s\n", release.SumsName, release.SigName, fs.NArg(), *out)
	reportSigned(stdout, key)
	return report.ExitOK
}

// Filenames `cau bundle keygen` writes into --out.
const (
	keygenPrivName = "cau-release.key"
	keygenPubName  = "cau-release.pub"
)

// bundleKeygen writes a new release signing key and its public key. Making
// the keypair was an undocumented ops step; with a hybrid key there is no
// one-line shell equivalent, so the tool that reads the form writes it.
func bundleKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write "+keygenPrivName+" and "+keygenPubName+" into")
	hybrid := fs.Bool("hybrid", false, "make a hybrid key: Ed25519 + "+release.PQName)
	edKey := fs.String("ed25519-key", "", "with --hybrid: keep this existing Ed25519 private key (hex) as the classical half")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *out == "" {
		return fail(stderr, report.ExitUsage, "--out is required")
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "keygen takes no arguments, only flags")
	}
	if *edKey != "" && !*hybrid {
		return fail(stderr, report.ExitUsage, "--ed25519-key only makes sense with --hybrid: it upgrades an existing Ed25519 key")
	}

	var key release.SignKey
	var err error
	if *edKey != "" {
		existing, code := loadSigningKey(*edKey, stderr)
		if code != report.ExitOK {
			return code
		}
		if existing.Hybrid() {
			return fail(stderr, report.ExitRunFailed, "%s is already a hybrid key", report.TermSafe(*edKey))
		}
		key, err = existing.WithNewMLDSA()
	} else {
		key, err = release.GenerateSignKey(*hybrid)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	// 0700: the directory is about to hold a private key. An existing
	// directory keeps the mode its owner gave it.
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	privPath := filepath.Join(*out, keygenPrivName)
	pubPath := filepath.Join(*out, keygenPubName)
	// Look before writing either, so a refusal leaves nothing behind. The
	// exclusive create below is what actually prevents an overwrite.
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fail(stderr, report.ExitRunFailed, "%s already exists; refusing to overwrite a key", report.TermSafe(p))
		}
	}
	if err := writeNewFile(privPath, key.Encode(), 0o600); err != nil {
		return fail(stderr, report.ExitRunFailed, "writing the signing key: %v", err)
	}
	if err := writeNewFile(pubPath, key.Public().Encode(), 0o644); err != nil {
		os.Remove(privPath) // made by this run a moment ago; do not leave half a pair
		return fail(stderr, report.ExitRunFailed, "writing the public key: %v", err)
	}
	fmt.Fprintf(stdout, "[+] wrote %s signing key to %s (mode 0600) and its public key to %s\n",
		key.Algorithms(), report.TermSafe(privPath), report.TermSafe(pubPath))
	fmt.Fprintln(stdout, "[*] the signing key belongs off every host that verifies with it; the public key is what --pubkey takes")
	return report.ExitOK
}

// writeNewFile creates path with exactly mode and writes data. It fails if
// anything, a symlink included, is already there.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chmod(mode); err != nil { // the umask can only have narrowed it; make it exact
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

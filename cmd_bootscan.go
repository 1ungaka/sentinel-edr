package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/bootscan"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/safefs"
)

func bootScanUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau boot-scan [flags]

Reads the boot chain, the part of the host a file scan never reaches, and
reports what it finds. Strictly read-only: disks are opened read-only, no
firmware variable is set, no option ROM is enabled and no flash chip is
touched. The only file this command ever writes is the one named with
--record.

  disks      the MBR, the GPT (both headers, both checksums) and each
             partition's first sector. A wiped or rewritten partition table, a
             boot sector carrying a ransom note, a primary GPT that no longer
             agrees with its backup. Disks are only read when named with
             --disk; reading a live device usually needs root.
  ESP        every EFI binary on the EFI System Partition with its digest, PE
             subsystem and whether it carries a signature, plus queued
             firmware capsules.
  variables  Secure Boot and setup-mode state, the boot entries and their
             order, the platform key, KEK, db, the revocation list (dbx) and
             the shim MOK list (entry counts and a SHA-256 of each), and the
             SBAT level.
  firmware   the ACPI table names and the WPBT table, PCI option ROMs
             (presence and size; the contents are not read) and the firmware
             update resource table (root only).

On Linux the ESP, the firmware variables and sysfs are found automatically.
Pass --offline to examine only the disk images you name, for example an image
taken from another machine.

Flags:
  --disk <path>          disk image or block device (repeatable)
  --esp <dir>            mounted EFI System Partition (default: /boot/efi, /efi
                         or /boot, whichever holds an EFI directory)
  --efivars <dir>        efivarfs mount (default /sys/firmware/efi/efivars)
  --sysfs <dir>          sysfs root for the firmware inventory (default /sys)
  --proc <dir>           proc root for the kernel's own state: the taint word, the
                         module signature enforcement mode and the module count
                         (default /proc)
  --offline              scan only what is named; no host auto-discovery
  --dbx-reference <file> compare the host revocation list against this one (the
                         dbx update the UEFI Forum publishes for the platform)
  --format <fmt>         text or json (default text)
  --threshold <n>        score at which the scan is reported suspicious
                         (default 8)
  --record <file>        write what was scanned as the baseline (JSON, mode
                         0600). Record it on a host you believe is good, as
                         root and with --disk, so every surface is covered
  --sign-key <file>      with --record, sign the baseline with this Ed25519
                         private key (hex seed or key, as cau selftest uses)
  --force                with --record, replace an existing file
  --check <file>         compare this scan with a baseline and list the
                         differences
  --pubkey <file>        with --check, require the baseline to carry a
                         signature that verifies against this Ed25519 public
                         key (hex)

Signatures are reported as present or absent, never verified: the engine
holds no trust store. A scan that could not read something says so under
"Not inspected" instead of reporting it clean.

Baselines. One scan cannot tell whether a boot entry, a loader or the
revocation list is what it was last month; a comparison can. --record saves
the comparable facts of this scan and --check lists how a later scan differs.
A difference has a kind (added, removed, changed, not-reverified,
not-in-baseline) and one of three severities:

  security         sets exit code 1. A boot entry added, or its target, device
                   path, loader arguments or active flag changed; another
                   entry booting first; Secure Boot turned off or setup mode
                   turned on; the platform key gone; PK, KEK, db or the MOK
                   list changed at all (db grew); the dbx SHRANK or was
                   replaced; the SBAT level fell; an EFI binary added to the
                   ESP or its content changed; the MBR boot code or anything
                   in a partition table changed; an ACPI table appeared (WPBT
                   above all) or DMAR/IVRS/TPM2/TCPA went away; an option ROM
                   appeared or changed size; a firmware version went down.
  expected-update  a vendor or OS update produces it; reported, and does not
                   set the exit code: the dbx grew, the SBAT level rose, a
                   firmware version went up. A changed boot loader is never
                   in this class: its signature is seen, not verified, so an
                   update and a replacement look the same. Confirm it and
                   record a new baseline.
  info             a removal that starts nothing new (a boot entry, an EFI
                   binary, an option ROM), a relabelled boot entry, a boot
                   order that changed after its first entry, hardening.

not-reverified means the baseline has the item and this run could not read
it: the ESP without root, a disk not named with --disk (a baseline never
causes a disk to be opened), the firmware resource table without root. It may
be unchanged; it is never reported as removed and never sets the exit code.
not-in-baseline is the reverse. Left out of the comparison because they
change on their own: BootCurrent, the variable count, file times, the ESP's
other files, queued capsules, partition names. Disks are matched by the path
given; device names move between boots, /dev/disk/by-id paths do not.

A baseline that an intruder can rewrite proves little. With --sign-key the
baseline is signed, and with --pubkey a check refuses (exit 3) a baseline
that is unsigned or whose signature does not verify, and refuses a key file
that cannot be read or parsed: it never falls back to an unsigned
comparison. Without --pubkey the comparison runs and says it was unsigned.
Keep the private key off the host.

Exit codes: 0 nothing at or above the threshold (and, with --check, no
security-relevant difference), 1 suspicious or a security-relevant
difference, 3 nothing could be scanned, or the baseline or a key could not be
used or written, 4 usage.
`)
}

// espCandidates are where distributions mount the EFI System Partition, most
// specific first.
var espCandidates = []string{"/boot/efi", "/efi", "/boot"}

// discoverESP returns the first candidate that is a mounted FAT volume,
// read from a mounts table (/proc/self/mounts). The filesystem type is the
// test, not the presence of an EFI directory: /boot holds an "efi" directory
// on every host that mounts the ESP at /boot/efi, and it is not the ESP.
func discoverESP(mountsPath string) string {
	raw, err := safefs.ReadFile(mountsPath, 8<<20)
	if err != nil {
		return "" // no mount table: no ESP is assumed, and the report says so
	}
	fat := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && (f[2] == "vfat" || f[2] == "msdos") {
			fat[f[1]] = true
		}
	}
	for _, c := range espCandidates {
		if fat[c] {
			return c
		}
	}
	return ""
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func cmdBootScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("boot-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { bootScanUsage(stderr) }
	var disks multiFlag
	fs.Var(&disks, "disk", "disk image or block device (repeatable)")
	esp := fs.String("esp", "", "mounted EFI System Partition")
	efivars := fs.String("efivars", "", "efivarfs mount")
	sysfs := fs.String("sysfs", "", "sysfs root for the firmware inventory")
	procRoot := fs.String("proc", "", "proc root for the kernel's own state (taint word, module signature enforcement)")
	offline := fs.Bool("offline", false, "scan only what is named; no host auto-discovery")
	dbxRef := fs.String("dbx-reference", "", "reference revocation list to compare the host dbx against")
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", 0, "score at which the scan is reported suspicious (0 = default)")
	record := fs.String("record", "", "write what was scanned as the baseline")
	signKey := fs.String("sign-key", "", "with --record, Ed25519 private key file (hex) to sign the baseline with")
	force := fs.Bool("force", false, "with --record, replace an existing file")
	check := fs.String("check", "", "compare this scan with a baseline")
	pubkey := fs.String("pubkey", "", "with --check, Ed25519 public key file (hex) the baseline's signature must verify against")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *threshold < 0 {
		return fail(stderr, report.ExitUsage, "--threshold must not be negative")
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "boot-scan takes no positional arguments; name disks with --disk")
	}
	switch {
	case *record != "" && *check != "":
		return fail(stderr, report.ExitUsage, "--record and --check are separate runs: check against the old baseline first, then record a new one")
	case *force && *record == "":
		return fail(stderr, report.ExitUsage, "--force only applies to --record")
	case *signKey != "" && *record == "":
		return fail(stderr, report.ExitUsage, "--sign-key only applies to --record")
	case *pubkey != "" && *check == "":
		return fail(stderr, report.ExitUsage, "--pubkey only applies to --check")
	}

	opts := bootscan.Options{
		Disks: disks, ESP: *esp, EFIVars: *efivars, Sysfs: *sysfs, Proc: *procRoot,
		DBXReference: *dbxRef, Threshold: *threshold,
	}
	if !*offline {
		// Host surfaces. A default that is absent is left empty, so the
		// report notes it as not scanned instead of failing on it.
		if opts.EFIVars == "" && dirExists("/sys/firmware/efi/efivars") {
			opts.EFIVars = "/sys/firmware/efi/efivars"
		}
		if opts.ESP == "" {
			opts.ESP = discoverESP("/proc/self/mounts")
		}
		if opts.Sysfs == "" && dirExists("/sys/firmware") {
			opts.Sysfs = "/sys"
		}
		if opts.Proc == "" && dirExists("/proc/sys/kernel") {
			opts.Proc = "/proc"
		}
	}
	if len(opts.Disks) == 0 && opts.ESP == "" && opts.EFIVars == "" && opts.Sysfs == "" {
		return fail(stderr, report.ExitUsage, "nothing to scan: name a disk with --disk, or an --esp / --efivars / --sysfs directory")
	}

	// The baseline and the keys are settled before the scan: a baseline or a
	// key that cannot be used fails the run without output that could be
	// mistaken for a comparison, and without having read anything.
	var baseline *bootscan.Baseline
	var integrity string
	if *check != "" {
		var pub ed25519.PublicKey
		if *pubkey != "" {
			var err error
			if pub, err = bootLoadPubkey(*pubkey); err != nil {
				return fail(stderr, report.ExitRunFailed, "public key %s: %s; refusing to fall back to an unsigned comparison",
					report.TermSafe(*pubkey), report.TermSafe(err.Error()))
			}
		}
		var err error
		if baseline, err = bootReadBaseline(*check); err != nil {
			return fail(stderr, report.ExitRunFailed, "baseline %s: %s", report.TermSafe(*check), report.TermSafe(err.Error()))
		}
		if integrity, err = bootVerifyBaseline(baseline, pub); err != nil {
			return fail(stderr, report.ExitRunFailed, "baseline %s: %s", report.TermSafe(*check), report.TermSafe(err.Error()))
		}
	}
	var priv ed25519.PrivateKey
	if *record != "" {
		if *signKey != "" {
			var err error
			if priv, err = bootLoadSignKey(*signKey); err != nil {
				return fail(stderr, report.ExitRunFailed, "signing key %s: %s; no baseline was written",
					report.TermSafe(*signKey), report.TermSafe(err.Error()))
			}
		}
		if _, err := os.Lstat(*record); err == nil && !*force {
			return fail(stderr, report.ExitRunFailed, "%s already exists; not overwritten (pass --force to replace it)", report.TermSafe(*record))
		}
	}

	res := bootscan.Run(opts)
	var diffs []bootscan.Difference
	if baseline != nil {
		var err error
		if diffs, err = bootscan.Compare(baseline, bootscan.NewBaseline(res)); err != nil {
			return fail(stderr, report.ExitRunFailed, "baseline %s: %s", report.TermSafe(*check), report.TermSafe(err.Error()))
		}
	}
	changed := bootscan.SecurityRelevant(diffs)

	if *format == "json" {
		var v interface{} = res
		if baseline != nil {
			covers, missing := baseline.Covers()
			v = bootScanCheck{Baseline: *check, BaselineCreatedAt: baseline.CreatedAt, BaselineSignature: integrity,
				BaselineCovers: covers, BaselineNotCovered: missing,
				SecurityRelevant: changed, Differences: diffs, Result: res}
		}
		if err := writeJSON(stdout, v); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		writeBootScanText(stdout, res)
		if baseline != nil {
			writeBootScanCheckText(stdout, *check, baseline, integrity, diffs)
		}
	}

	unscanned := !res.Scanned() || allDisksUnread(res)
	if *record != "" {
		if unscanned {
			return fail(stderr, report.ExitRunFailed, "nothing could be scanned, so there is nothing to record; no baseline was written")
		}
		if code := bootRecordBaseline(res, *record, priv, *force, stderr); code != report.ExitOK {
			return code
		}
	}
	switch {
	case res.Detected() || changed:
		return report.ExitThreat
	case unscanned:
		return report.ExitRunFailed
	}
	return report.ExitOK
}

// bootScanCheck is the JSON printed with --check.
type bootScanCheck struct {
	Baseline          string `json:"baseline"`
	BaselineCreatedAt string `json:"baseline_created_at"`
	// BaselineSignature is verified (it checked out against --pubkey),
	// unsigned, or signed-not-verified (a signature is in the file and no
	// --pubkey was given to check it). Only the first is evidence that the
	// baseline is the one that was recorded.
	BaselineSignature string `json:"baseline_signature"`
	// BaselineCovers and BaselineNotCovered name the surfaces the baseline
	// records and those it does not; the second kind is never compared.
	BaselineCovers     []string              `json:"baseline_covers"`
	BaselineNotCovered []string              `json:"baseline_not_covered,omitempty"`
	SecurityRelevant   bool                  `json:"security_relevant"`
	Differences        []bootscan.Difference `json:"differences"`
	Result             *bootscan.Result      `json:"result"`
}

const (
	bootSigVerified    = "verified"
	bootSigUnsigned    = "unsigned"
	bootSigNotVerified = "signed-not-verified"

	// bootMaxKeyBytes bounds a key file: a hex Ed25519 key is at most 128
	// characters and a newline.
	bootMaxKeyBytes = 4096
)

// bootCause is an error without the path the os package prefixes; the caller
// names the file.
func bootCause(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// bootReadBounded reads a regular file of at most max bytes. The baseline
// and the key files are named by the operator and may be anything: the open
// is non-blocking and the open descriptor is what is checked, so a FIFO or a
// device at the path is refused instead of being read until it ends.
func bootReadBounded(path string, max int64) ([]byte, error) {
	data, err := safefs.ReadFile(path, max)
	switch {
	case errors.Is(err, safefs.ErrNotRegular):
		return nil, errors.New("not a regular file")
	case errors.Is(err, safefs.ErrTooLarge):
		return nil, fmt.Errorf("larger than %d bytes", max)
	case err != nil:
		return nil, bootCause(err)
	}
	return data, nil
}

// bootReadBaseline reads and validates a baseline file, bounded.
func bootReadBaseline(path string) (*bootscan.Baseline, error) {
	data, err := bootReadBounded(path, bootscan.MaxBaselineBytes)
	if err != nil {
		return nil, err
	}
	return bootscan.Parse(data)
}

// bootLoadPubkey reads the key a baseline's signature is checked against.
// Asking for a key and not getting one is an error, never a quiet fall back
// to "no key": otherwise deleting or corrupting one file would turn a signed
// comparison into an unsigned one that still prints a clean result.
func bootLoadPubkey(path string) (ed25519.PublicKey, error) {
	raw, err := bootReadHexKey(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("an Ed25519 public key is %d bytes of hex, this file holds %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// bootLoadSignKey reads the Ed25519 private key a baseline is signed with:
// the hex of a 32-byte seed or of a 64-byte private key, the form `cau
// bundle` and `cau selftest` take. The key file formats are parsed here and
// not through the release package's loader, which also accepts hybrid
// (Ed25519 plus ML-DSA) keys: a baseline signature is Ed25519 only, and
// signing with half of a hybrid key is something that loader promises never
// to do. A hybrid key file is refused as not being hex.
func bootLoadSignKey(path string) (ed25519.PrivateKey, error) {
	raw, err := bootReadHexKey(path)
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("an Ed25519 private key is %d or %d bytes of hex, this file holds %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
}

// bootReadHexKey reads a key file: hex, surrounding whitespace tolerated.
// The error never quotes the file's content.
func bootReadHexKey(path string) ([]byte, error) {
	data, err := bootReadBounded(path, bootMaxKeyBytes)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("not a hex-encoded Ed25519 key")
	}
	return raw, nil
}

// bootVerifyBaseline decides how far the baseline can be trusted. With a
// key, anything but a signature that verifies is an error. Without one the
// comparison is allowed and labelled for what it is.
func bootVerifyBaseline(b *bootscan.Baseline, pub ed25519.PublicKey) (string, error) {
	if pub == nil {
		if b.Signature != "" {
			return bootSigNotVerified, nil
		}
		return bootSigUnsigned, nil
	}
	if b.Signature == "" {
		return "", errors.New("the baseline is not signed and --pubkey requires a signature; refusing an unsigned comparison")
	}
	sig, err := hex.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, b.SigningBytes(), sig) {
		return "", errors.New("the signature does not verify against the given public key: the baseline was altered after it was signed, or it was signed with another key")
	}
	return bootSigVerified, nil
}

// bootRecordBaseline writes the scan as a baseline, signed when a key was
// given, and says on stderr what the baseline does and does not cover.
func bootRecordBaseline(res *bootscan.Result, path string, priv ed25519.PrivateKey, force bool, stderr io.Writer) int {
	b := bootscan.NewBaseline(res)
	b.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	if priv != nil {
		b.Signature = hex.EncodeToString(ed25519.Sign(priv, b.SigningBytes()))
	}
	data, err := bootscan.Marshal(b)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
	}
	if err := bootWriteBaseline(path, data, force); err != nil {
		return fail(stderr, report.ExitRunFailed, "%s", report.TermSafe(err.Error()))
	}
	if priv != nil {
		fmt.Fprintf(stderr, "[*] baseline written to %s (mode 0600, signed with Ed25519; check it with --pubkey)\n", report.TermSafe(path))
	} else {
		fmt.Fprintf(stderr, "[*] baseline written to %s (mode 0600, UNSIGNED: whoever can write this file can rewrite it; pass --sign-key to sign it)\n", report.TermSafe(path))
	}
	recorded, missing := b.Covers()
	if len(recorded) > 0 {
		fmt.Fprintf(stderr, "[*] it covers: %s\n", strings.Join(recorded, ", "))
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "[WARN] it does NOT cover: %s. These were not read in this run and will not be compared; record as root, and name disks with --disk\n", strings.Join(missing, ", "))
	}
	if res.Detected() {
		fmt.Fprintln(stderr, "[WARN] this scan is SUSPICIOUS, and the baseline records the host as it is now: a later check will not report what is already here")
	}
	return report.ExitOK
}

// bootWriteBaseline writes the baseline with mode 0600. Without force an
// existing file is never touched: the create is exclusive, so it also refuses
// a symbolic link. With force the new content is written beside the target
// and renamed over it, so the old baseline is replaced whole or not at all
// and a link at that path is replaced, not followed.
func bootWriteBaseline(path string, data []byte, force bool) error {
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; not overwritten (pass --force to replace it)", path)
		}
		if err != nil {
			return fmt.Errorf("could not create %s: %w", path, bootCause(err))
		}
		_, werr := f.Write(data)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path) // this run created it; do not leave half a baseline
			return fmt.Errorf("could not write %s: %w", path, bootCause(werr))
		}
		return nil
	}
	if fi, err := os.Lstat(path); err == nil && fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".boot-baseline-*")
	if err != nil {
		return fmt.Errorf("could not create %s: %w", path, bootCause(err))
	}
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("could not write %s: %w", path, bootCause(werr))
	}
	return nil
}

// writeBootScanCheckText lists the differences from a baseline, grouped by
// what they mean. Every value comes from a file its author controls, or from
// the firmware, and passes through TermSafe.
func writeBootScanCheckText(w io.Writer, path string, baseline *bootscan.Baseline, integrity string, diffs []bootscan.Difference) {
	safe := report.TermSafe
	created := baseline.CreatedAt
	if created == "" {
		created = "at an unrecorded time"
	}
	fmt.Fprintf(w, "Baseline    : %s (recorded %s)\n", safe(path), safe(created))
	switch integrity {
	case bootSigVerified:
		fmt.Fprintln(w, "  integrity : signature verified against the --pubkey key")
	case bootSigNotVerified:
		fmt.Fprintln(w, "  integrity : UNSIGNED COMPARISON. The baseline carries a signature and no --pubkey was given, so it was not checked: nothing shows this file is the one that was recorded")
	default:
		fmt.Fprintln(w, "  integrity : UNSIGNED COMPARISON. The baseline is not signed: whoever can write the file can make any change below disappear")
	}
	covers, missing := baseline.Covers()
	if len(covers) > 0 {
		fmt.Fprintf(w, "  covers    : %s\n", strings.Join(covers, ", "))
	}
	if len(missing) > 0 {
		fmt.Fprintf(w, "  no record : %s (not read when the baseline was recorded; never compared)\n", strings.Join(missing, ", "))
	}

	groups := []struct {
		title string
		match func(bootscan.Difference) bool
	}{
		{"Security-relevant (sets the exit code)", func(d bootscan.Difference) bool { return d.Severity == bootscan.SeveritySecurity }},
		{"Expected with updates (a vendor or OS update produces these; they do not set the exit code)", func(d bootscan.Difference) bool {
			return d.Severity == bootscan.SeverityExpectedUpdate
		}},
		{"Informational", func(d bootscan.Difference) bool {
			return d.Severity == bootscan.SeverityInfo && d.Kind != bootscan.KindNotReverified && d.Kind != bootscan.KindNotInBaseline
		}},
		{"Could not be re-verified (in the baseline, not readable in this run; may be unchanged)", func(d bootscan.Difference) bool {
			return d.Severity == bootscan.SeverityInfo && d.Kind == bootscan.KindNotReverified
		}},
		{"Not in the baseline (readable in this run, nothing to compare with)", func(d bootscan.Difference) bool {
			return d.Severity == bootscan.SeverityInfo && d.Kind == bootscan.KindNotInBaseline
		}},
	}
	counts := make([]int, len(groups))
	for _, d := range diffs {
		for i, g := range groups {
			if g.match(d) {
				counts[i]++
				break
			}
		}
	}
	fmt.Fprintf(w, "Differences : %d security-relevant, %d expected with updates, %d informational, %d could not be re-verified, %d not in the baseline\n",
		counts[0], counts[1], counts[2], counts[3], counts[4])
	for i, g := range groups {
		if counts[i] == 0 {
			continue
		}
		fmt.Fprintf(w, "%s:\n", g.title)
		for _, d := range diffs {
			if !g.match(d) {
				continue
			}
			fmt.Fprintf(w, "  [%s] %s\n", safe(string(d.Kind)), safe(d.Item))
			switch {
			case d.Old != "" && d.New != "":
				fmt.Fprintf(w, "    baseline: %s\n    now     : %s\n", safe(d.Old), safe(d.New))
			case d.Old != "":
				fmt.Fprintf(w, "    baseline: %s\n", safe(d.Old))
			case d.New != "":
				fmt.Fprintf(w, "    now     : %s\n", safe(d.New))
			}
			fmt.Fprintf(w, "    %s\n", safe(d.Detail))
		}
	}
	if bootscan.SecurityRelevant(diffs) {
		fmt.Fprintln(w, "Comparison  : BOOT CHAIN CHANGED since the baseline")
	} else {
		fmt.Fprintln(w, "Comparison  : no security-relevant change among what could be compared")
	}
	if counts[3] > 0 {
		fmt.Fprintln(w, "              What could not be re-verified was not compared: run as root, and name the baseline's disks with --disk, to cover it.")
	}
}

// allDisksUnread reports a run whose only requested surface was disks, none
// of which could be read: that is a failed run, not a clean one.
func allDisksUnread(res *bootscan.Result) bool {
	if len(res.Disks) == 0 || res.ESP != nil || res.EFI != nil || res.Firmware != nil {
		return false
	}
	for _, d := range res.Disks {
		if d.Error == "" {
			return false
		}
	}
	return true
}

func triState(v *bool, yes, no string) string {
	switch {
	case v == nil:
		return "unknown"
	case *v:
		return yes
	}
	return no
}

func writeBootScanText(w io.Writer, res *bootscan.Result) {
	safe := report.TermSafe

	for _, d := range res.Disks {
		fmt.Fprintf(w, "Disk        : %s\n", safe(d.Path))
		if d.Error != "" {
			fmt.Fprintf(w, "  not read  : %s\n", safe(d.Error))
			continue
		}
		scheme := "MBR"
		if d.GPT != nil {
			scheme = "GPT"
		} else if d.MBR != nil && !d.MBR.SignatureValid {
			scheme = "none (no boot signature)"
		}
		fmt.Fprintf(w, "  layout    : %s, %d-byte sectors", scheme, d.SectorSize)
		if d.Size > 0 {
			fmt.Fprintf(w, ", %d bytes", d.Size)
		}
		fmt.Fprintln(w)
		if m := d.MBR; m != nil && m.BootCodePresent {
			loader := m.Loader
			if loader == "" {
				loader = "unrecognised"
			}
			fmt.Fprintf(w, "  boot code : %s (sha256 %s)\n", loader, m.BootCodeSHA256)
		}
		if g := d.GPT; g != nil {
			backup := "not checked (disk size unknown)"
			if g.BackupChecked {
				backup = map[bool]string{true: "valid", false: "MISSING OR INVALID"}[g.BackupValid]
				if g.BackupValid && !g.BackupConsistent && !g.RecoveredFromBackup {
					backup = "valid but DIFFERENT from the primary"
				}
			}
			primary := map[bool]string{true: "valid", false: "INVALID"}[g.HeaderCRCValid && g.EntriesCRCValid]
			if g.RecoveredFromBackup {
				primary = "DESTROYED (table read from the backup)"
			}
			fmt.Fprintf(w, "  GPT       : disk %s, primary %s, backup %s\n", g.DiskGUID, primary, backup)
		}
		const maxShown = 32
		for i, p := range d.Partitions {
			if i >= maxShown {
				fmt.Fprintf(w, "  ... +%d more partitions\n", len(d.Partitions)-maxShown)
				break
			}
			tags := ""
			if p.ESP {
				tags += " [ESP]"
			}
			if p.Active {
				tags += " [active]"
			}
			name := ""
			if p.Name != "" {
				name = " " + safe(p.Name)
			}
			fmt.Fprintf(w, "  part %-3d  : %s  start %d  sectors %d  %s%s%s\n", p.Index, p.Type, p.StartLBA, p.Sectors, p.BootSector, name, tags)
		}
	}

	if e := res.EFI; e != nil {
		fmt.Fprintf(w, "Firmware variables : %s (%d variables)\n", safe(e.Path), e.Variables)
		fmt.Fprintf(w, "  Secure Boot : %s\n", triState(e.SecureBoot, "enabled", "disabled"))
		fmt.Fprintf(w, "  setup mode  : %s\n", triState(e.SetupMode, "YES (no platform key)", "no"))
		if e.PK != nil {
			fmt.Fprintf(w, "  PK          : enrolled (sha256 %s)\n", e.PK.SHA256)
		}
		if e.KEK != nil {
			fmt.Fprintf(w, "  KEK         : %d certificates, %d hashes (sha256 %s)\n", e.KEK.Certificates, e.KEK.Hashes, e.KEK.SHA256)
		}
		if e.DB != nil {
			fmt.Fprintf(w, "  db          : %d certificates, %d hashes (sha256 %s)\n", e.DB.Certificates, e.DB.Hashes, e.DB.SHA256)
		}
		switch {
		case e.DBX == nil:
			fmt.Fprintln(w, "  dbx         : absent or unreadable")
		case e.DBX.Unparsed:
			fmt.Fprintf(w, "  dbx         : present, not a well-formed signature list (%d bytes, sha256 %s)\n", e.DBX.Bytes, e.DBX.SHA256)
		default:
			fmt.Fprintf(w, "  dbx         : %d SHA-256 revocations, %d certificates (sha256 %s)\n", e.DBX.Hashes, e.DBX.Certificates, e.DBX.SHA256)
		}
		if c := e.DBXReference; c != nil {
			fmt.Fprintf(w, "  dbx vs ref  : %d of %d reference revocations missing on this host\n", c.Missing, c.ReferenceHashes)
		}
		if e.MOK != nil {
			fmt.Fprintf(w, "  shim MOK    : %d certificates, %d hashes (sha256 %s)\n", e.MOK.Certificates, e.MOK.Hashes, e.MOK.SHA256)
		}
		if e.SBATLevel != "" {
			fmt.Fprintf(w, "  SBAT level  : %s\n", safe(e.SBATLevel))
		}
		if len(e.BootOrder) > 0 {
			fmt.Fprintf(w, "  boot order  : %s (current %s)\n", strings.Join(e.BootOrder, ", "), e.BootCurrent)
		}
		for _, b := range e.BootEntries {
			state := ""
			if !b.Active {
				state = " [inactive]"
			}
			if !b.InOrder {
				state += " [not in boot order]"
			}
			target := safe(b.FilePath)
			if target == "" {
				target = "(no file path: a device or firmware entry)"
			}
			fmt.Fprintf(w, "  Boot%s    : %s -> %s%s\n", b.ID, safe(b.Description), target, state)
		}
	}

	if e := res.ESP; e != nil {
		fmt.Fprintf(w, "EFI System Partition : %s (%d files, %d EFI binaries)\n", safe(e.Path), e.Files, len(e.Binaries))
		const maxShown = 40
		for i, b := range e.Binaries {
			if i >= maxShown {
				fmt.Fprintf(w, "  ... +%d more binaries\n", len(e.Binaries)-maxShown)
				break
			}
			kind := "not a PE image"
			if b.PE {
				kind = b.Subsystem + ", " + map[bool]string{true: "signed", false: "UNSIGNED"}[b.Signed]
			}
			fmt.Fprintf(w, "  %s  %s  (%s)\n", b.SHA256, safe(filepath.ToSlash(b.Path)), kind)
		}
	}

	if f := res.Firmware; f != nil {
		fmt.Fprintf(w, "Firmware inventory : %d ACPI tables, %d option ROMs, %d updatable components\n",
			len(f.ACPITables), len(f.OptionROMs), len(f.ESRT))
		for _, r := range f.OptionROMs {
			fmt.Fprintf(w, "  option ROM  : %s vendor %s device %s class %s (%d bytes; not read)\n",
				safe(r.Address), safe(r.Vendor), safe(r.Device), safe(r.Class), r.Size)
		}
		for _, e := range f.ESRT {
			fmt.Fprintf(w, "  firmware    : %s version %s\n", safe(e.Class), safe(e.Version))
		}
	}

	if k := res.Kernel; k != nil {
		mode := "unknown"
		switch {
		case !k.SigEnforceKnown:
			mode = "unreadable"
		case k.SigEnforce == 1:
			mode = "enforcing"
		case k.SigEnforce == 0:
			mode = "permissive"
		}
		fmt.Fprintf(w, "Kernel state      : taint %d, module signatures %s, %d module(s) loaded\n",
			k.Tainted, mode, k.ModuleCount)
		for _, flag := range k.TaintFlags {
			fmt.Fprintf(w, "  taint  : %s\n", safe(flag))
		}
		for _, u := range k.Unreadable {
			fmt.Fprintf(w, "  unreadable : %s\n", safe(u))
		}
	}

	fmt.Fprintf(w, "Score       : %d / %d threshold\n", res.Score, res.Threshold)
	if res.Detected() {
		fmt.Fprintln(w, "Verdict     : SUSPICIOUS")
	}
	for _, f := range res.Findings {
		tag := ""
		if f.Technique != "" {
			tag = "  (" + f.Technique + ")"
		}
		score := fmt.Sprint(f.Score)
		if f.Score == 0 {
			score = "info"
		}
		fmt.Fprintf(w, "  [%s] %s%s\n", f.Class, score, tag)
		detail := f.Detail
		if f.Target != "" {
			detail = safe(f.Target) + ": " + detail
		}
		fmt.Fprintf(w, "    %s\n", detail)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    %s\n", safe(f.Evidence))
		}
	}
	if len(res.Notes) > 0 {
		fmt.Fprintln(w, "Not inspected / limits:")
		for _, n := range res.Notes {
			fmt.Fprintf(w, "  - %s\n", safe(n))
		}
	}
}

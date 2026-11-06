package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/s-b-repo/cau/internal/bootscan"
	"github.com/s-b-repo/cau/internal/report"
)

func bootScanUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau boot-scan [flags]

Reads the boot chain, the part of the host a file scan never reaches, and
reports what it finds. Strictly read-only: disks are opened read-only, no
firmware variable is set, no option ROM is enabled and no flash chip is
touched.

  disks      the MBR, the GPT (both headers, both checksums) and each
             partition's first sector. A wiped or rewritten partition table, a
             boot sector carrying a ransom note, a primary GPT that no longer
             agrees with its backup. Disks are only read when named with
             --disk; reading a live device usually needs root.
  ESP        every EFI binary on the EFI System Partition with its digest, PE
             subsystem and whether it carries a signature, plus queued
             firmware capsules.
  variables  Secure Boot and setup-mode state, the boot entries and their
             order, the size of the revocation list (dbx), the shim MOK list
             and SBAT level.
  firmware   the WPBT ACPI table, PCI option ROMs (presence and size; the
             contents are not read) and the firmware update resource table.

On Linux the ESP, the firmware variables and sysfs are found automatically.
Pass --offline to examine only the disk images you name, for example an image
taken from another machine.

Flags:
  --disk <path>          disk image or block device (repeatable)
  --esp <dir>            mounted EFI System Partition (default: /boot/efi, /efi
                         or /boot, whichever holds an EFI directory)
  --efivars <dir>        efivarfs mount (default /sys/firmware/efi/efivars)
  --sysfs <dir>          sysfs root for the firmware inventory (default /sys)
  --offline              scan only what is named; no host auto-discovery
  --dbx-reference <file> compare the host revocation list against this one (the
                         dbx update the UEFI Forum publishes for the platform)
  --format <fmt>         text or json (default text)
  --threshold <n>        score at which the scan is reported suspicious
                         (default 8)

Signatures are reported as present or absent, never verified: the engine
holds no trust store. A scan that could not read something says so under
"Not inspected" instead of reporting it clean.

Exit codes: 0 nothing at or above the threshold, 1 suspicious, 3 nothing
could be scanned, 4 usage.
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
	raw, err := os.ReadFile(mountsPath)
	if err != nil {
		return ""
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
	offline := fs.Bool("offline", false, "scan only what is named; no host auto-discovery")
	dbxRef := fs.String("dbx-reference", "", "reference revocation list to compare the host dbx against")
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", 0, "score at which the scan is reported suspicious (0 = default)")
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

	opts := bootscan.Options{
		Disks: disks, ESP: *esp, EFIVars: *efivars, Sysfs: *sysfs,
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
	}
	if len(opts.Disks) == 0 && opts.ESP == "" && opts.EFIVars == "" && opts.Sysfs == "" {
		return fail(stderr, report.ExitUsage, "nothing to scan: name a disk with --disk, or an --esp / --efivars / --sysfs directory")
	}

	res := bootscan.Run(opts)
	if *format == "json" {
		if err := writeJSON(stdout, res); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		writeBootScanText(stdout, res)
	}
	switch {
	case res.Detected():
		return report.ExitThreat
	case !res.Scanned() || allDisksUnread(res):
		return report.ExitRunFailed
	}
	return report.ExitOK
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
		if e.DBX != nil {
			fmt.Fprintf(w, "  dbx         : %d SHA-256 revocations, %d certificates\n", e.DBX.Hashes, e.DBX.Certificates)
		} else {
			fmt.Fprintln(w, "  dbx         : absent or unreadable")
		}
		if c := e.DBXReference; c != nil {
			fmt.Fprintf(w, "  dbx vs ref  : %d of %d reference revocations missing on this host\n", c.Missing, c.ReferenceHashes)
		}
		if e.MOK != nil {
			fmt.Fprintf(w, "  shim MOK    : %d certificates, %d hashes\n", e.MOK.Certificates, e.MOK.Hashes)
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

// Package bootscan is the read-only boot-chain scan behind `cau boot-scan`.
//
// Everything `cau scan` looks at lives in a filesystem and stops at the OS
// boundary. A bootkit lives one layer down: in the master boot record, in the
// gap before the first partition, in the EFI System Partition, or in the
// firmware variables that decide what runs before the kernel. This package
// reads those places and reports what it finds:
//
//   - disk structures (disk.go): the MBR, the GPT with both headers and its
//     checksums, and each partition's first sector. A wiped or rewritten
//     partition table, a boot sector carrying a ransom note, a primary GPT
//     that no longer agrees with its backup.
//   - the EFI System Partition (esp.go): every EFI binary with its digest,
//     PE subsystem and whether it carries a signature at all.
//   - firmware variables (efi.go): Secure Boot and setup-mode state, the
//     boot entries and their order, the size of the revocation list.
//   - firmware inventory (firmware.go): the WPBT ACPI table, PCI option ROMs
//     and the firmware-update resource table.
//
// The hard boundary, enforced by a test over this package's source rather
// than by this comment: nothing here writes. Disks and files are opened
// read-only, no variable is set, no option ROM is enabled (sysfs requires a
// write to map one, so ROM contents are inventoried by presence and size and
// never read), and no flash chip is touched. Imaging SPI flash stays with
// operator tooling built for it.
//
// What it cannot see, stated: a signature is reported as present or absent,
// never verified, because the engine holds no trust store; firmware that lies
// about its own variables is below this scan; and a point-in-time read says
// nothing about what happened between two reads.
//
// # Baselines
//
// One scan cannot say whether a boot entry is the one that was there last
// month. A Baseline (baseline.go) is the comparable part of a Result,
// recorded on a host believed good; Compare (compare.go) lists how a later
// scan differs from it. The package builds, encodes, decodes and compares
// baselines; it does not write or sign them. SigningBytes is the canonical
// encoding a caller signs with Ed25519, and the command owns the key and the
// file.
//
// Every difference has a kind (added, removed, changed, not-reverified,
// not-in-baseline) and a severity. Only "security" sets the exit code:
//
//	surface / item          security                          expected-update        info
//	efi.secure_boot         enabled -> disabled                                      disabled -> enabled
//	efi.setup_mode          off -> on                                                on -> off
//	efi.pk, efi.kek,        appeared, gone, or content
//	  efi.db, efi.mok         changed in any way (db grew)
//	efi.dbx                 gone; any count SHRANK; same      a count grew and none
//	                          counts, other content;            shrank; appeared
//	                          unparseable
//	efi.sbat                a component's level fell or it    levels rose only;      bytes differ, same
//	                          is no longer listed; gone;        appeared               levels
//	                          unparseable
//	efi.boot_order          another entry is first, or the                           reordered after the
//	                          entry started first changed                              first entry
//	efi.boot.NNNN           added; file path, active flag,                           removed; label only
//	                          device path, attributes or
//	                          optional data changed
//	esp:<path>              added; content changed                                   removed
//	disk:<p>.mbr.boot_code  any change
//	disk:<p> table, GUID,   any change: scheme, disk GUID,
//	  signature, partition    signature; a partition added,
//	                          removed or changed (type,
//	                          start, length, ESP or active
//	                          flag, boot-sector kind)
//	acpi.table.<NAME>       added (WPBT or any other); WPBT                          removed (any other)
//	                          declared size changed; DMAR,
//	                          IVRS, TPM2 or TCPA removed
//	pci.rom.<address>       added; size changed; another                             removed
//	                          device at the address
//	esrt.<class>            version went down; unparseable    version went up        added; removed
//
// The reasoning behind the columns:
//
//   - Something new that the firmware will run, or a change to what it
//     trusts, is security-relevant even though updates cause it too. A
//     changed boot loader is never "expected": the scan sees that a
//     signature is present, not that it is valid, so it cannot tell an
//     update from a replacement. After an update the operator confirms the
//     change and records a new baseline.
//   - "Expected with updates" is kept for the changes that can only tighten
//     or advance the chain: revocations added, revocation levels raised,
//     firmware versions raised. The reverse direction of each is
//     security-relevant, because rolling one back is an attack.
//   - A removal introduces no code. Whatever runs instead was already in
//     the baseline, or shows up as added or changed, or moves the entry that
//     boots first (which efi.boot_order reports). The exceptions are
//     removals that take protection away: keys, revocations, the IOMMU and
//     TPM tables, and anything in a partition table.
//   - A name is context, not an anchor: a boot entry whose label changed and
//     whose target digest did not is informational.
//   - Unknown never equals and never differs. An item the baseline has and
//     this run could not read is not-reverified; an item this run read and
//     the baseline did not cover is not-in-baseline. Neither is ever
//     reported as removed or added, and neither sets the exit code.
//
// What NewBaseline leaves out, and why, is listed in its comment. Known
// limits of the comparison: whether the dbx grew is judged by entry counts
// (the digest only says that it changed), so a revocation replaced while the
// count grew looks like growth; disks are matched by the path they were named with; option
// ROM and WPBT contents are not read, so a same-size replacement of either
// is invisible; BootNext, a one-shot redirection that updates also use, is
// not part of the baseline.
package bootscan

import (
	"sort"
)

// ATT&CK techniques the finding classes map to.
const (
	techBootkit       = "T1542.003" // Pre-OS Boot: Bootkit
	techFirmware      = "T1542.001" // Pre-OS Boot: System Firmware
	techComponentFW   = "T1542.002" // Pre-OS Boot: Component Firmware
	techStructureWipe = "T1561.002" // Disk Wipe: Disk Structure Wipe
	techEncryptImpact = "T1486"     // Data Encrypted for Impact
	techSigningPolicy = "T1553.006" // Subvert Trust Controls: Code Signing Policy Modification
	techMasqueradeTyp = "T1036.008" // Masquerading: Masquerade File Type
)

// DefaultThreshold is the score at which a scan is reported suspicious. The
// weights are set so that no single structural oddity crosses it: one class
// alone crosses only when it is a boot-area ransom note. Everything else
// needs corroboration, because disks are edited by hand and firmware is odd.
const DefaultThreshold = 8

// Finding is one scored or informational observation.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	// Target is what the finding is about: a disk, a file on the ESP, a
	// firmware variable.
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence,omitempty"`
}

// Options selects what to scan. Every field is optional; an empty Options
// scans nothing and says so.
type Options struct {
	// Disks are disk images or block devices to read the boot structures of.
	Disks []string
	// ESP is a mounted EFI System Partition (for example /boot/efi).
	ESP string
	// EFIVars is the efivarfs mount (normally /sys/firmware/efi/efivars).
	EFIVars string
	// Sysfs is the sysfs root (normally /sys) for the firmware inventory.
	Sysfs string
	// Proc is the proc root (normally /proc) for the kernel's own state: the
	// taint word, the module signature enforcement mode and the module list.
	Proc string
	// DBXReference is a revocation list to compare the host's dbx against:
	// the UEFI Forum's published dbx update for this architecture.
	DBXReference string
	// Threshold overrides DefaultThreshold when positive.
	Threshold int
}

// Result is the whole scan.
type Result struct {
	Findings  []Finding       `json:"findings,omitempty"`
	Score     int             `json:"score"`
	Threshold int             `json:"threshold"`
	Disks     []*DiskReport   `json:"disks,omitempty"`
	ESP       *ESPReport      `json:"esp,omitempty"`
	EFI       *EFIReport      `json:"efi,omitempty"`
	Firmware  *FirmwareReport `json:"firmware,omitempty"`
	// Kernel is the kernel's own state: the taint word, the module signature
	// enforcement mode and the module count. It is state, not a finding.
	Kernel *KernelReport `json:"kernel,omitempty"`
	// Notes say what was not inspected and why. A scan that could not read
	// something reports that, never a clean result for it.
	Notes []string `json:"notes,omitempty"`
}

// Detected reports whether the score reached the threshold.
func (r *Result) Detected() bool { return r != nil && r.Score >= r.Threshold }

// Scanned reports whether anything was actually read.
func (r *Result) Scanned() bool {
	return r != nil && (len(r.Disks) > 0 || r.ESP != nil || r.EFI != nil || r.Firmware != nil || r.Kernel != nil)
}

func (r *Result) add(fs ...Finding) {
	for _, f := range fs {
		r.Findings = append(r.Findings, f)
		r.Score += f.Score
	}
}

func (r *Result) note(n string) {
	for _, have := range r.Notes {
		if have == n {
			return
		}
	}
	r.Notes = append(r.Notes, n)
}

// Run performs the scan the options ask for.
func Run(opts Options) *Result {
	res := &Result{Threshold: opts.Threshold}
	if res.Threshold <= 0 {
		res.Threshold = DefaultThreshold
	}

	for _, path := range opts.Disks {
		rep, fs := ScanDisk(path)
		res.Disks = append(res.Disks, rep)
		res.add(fs...)
		if rep.Error != "" {
			res.note("disk " + path + " could not be read: " + rep.Error)
		}
	}

	// Firmware variables first: whether Secure Boot is on changes what an
	// unsigned binary on the ESP means.
	var secureBoot *bool
	if opts.EFIVars != "" {
		rep, fs, notes := ScanEFIVars(opts.EFIVars, opts.DBXReference)
		res.EFI = rep
		res.add(fs...)
		for _, n := range notes {
			res.note(n)
		}
		if rep != nil {
			secureBoot = rep.SecureBoot
		}
	} else if opts.DBXReference != "" {
		res.note("a dbx reference was given but no firmware variables were scanned; nothing to compare it with")
	}

	if opts.ESP != "" {
		rep, fs, notes := ScanESP(opts.ESP, secureBoot)
		res.ESP = rep
		res.add(fs...)
		for _, n := range notes {
			res.note(n)
		}
		if rep != nil && res.EFI != nil {
			res.add(crossCheckBootEntries(res.EFI, rep)...)
		}
	}

	if opts.Proc != "" {
		rep, notes := ScanKernel(opts.Proc)
		res.Kernel = rep
		for _, n := range notes {
			res.note(n)
		}
	}

	if opts.Sysfs != "" {
		rep, fs, notes := ScanFirmware(opts.Sysfs)
		res.Firmware = rep
		res.add(fs...)
		for _, n := range notes {
			res.note(n)
		}
	}

	if !res.Scanned() {
		res.note("nothing was scanned: no disk, EFI System Partition, firmware variables or sysfs was given or found")
	}
	res.note("signatures are reported as present or absent, never verified: the engine holds no trust store")

	// Scored findings first, strongest first; informational ones after.
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Score > res.Findings[j].Score })
	return res
}

// Class describes one finding class, for documentation and the coverage
// matrix. Field names match the sibling detectors' catalogs.
type Class struct {
	Class       string `json:"class"`
	Technique   string `json:"technique"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
}

// Score weights. A weight of zero is an informational observation: it is
// reported and never moves the verdict.
const (
	scoreRansomText       = 8
	scorePrimaryDestroyed = 6
	scoreSystemDir        = 5
	scoreGPTCRC           = 4
	scoreSetupMode        = 4
	scoreBackupMismatch   = 3
	scoreOverlap          = 3
	scoreOutOfRange       = 3
	scoreESPNotFAT        = 3
	scoreUnsignedSB       = 3
	scoreNonEFIPE         = 3
	scoreDBXBehind        = 3
	scoreNoProtective     = 2
	scoreBootcodeUnknown  = 2
	scoreMultipleActive   = 2
	scoreMBRBeyondDisk    = 2
	scoreNotPE            = 2
	scoreDBXEmpty         = 2
	scoreBackupMissing    = 1
	scoreActiveNoVBR      = 1
	scoreWPBT             = 1
)

// Classes returns the catalog in a stable, report-friendly order.
func Classes() []Class {
	return []Class{
		{"boot.ransom-text", techEncryptImpact, scoreRansomText,
			"the boot sector or the gap before the first partition holds ransom-note vocabulary: code that runs before the OS and demands payment"},
		{"gpt.primary-destroyed", techStructureWipe, scorePrimaryDestroyed,
			"no valid primary GPT, but an intact backup header at the end of the disk: the start of the disk was overwritten"},
		{"gpt.header-crc-invalid", techBootkit, scoreGPTCRC,
			"the GPT header fails its own CRC32: edited without the tooling that maintains it"},
		{"gpt.entries-crc-invalid", techBootkit, scoreGPTCRC,
			"the GPT partition entries fail the CRC32 recorded in the header"},
		{"gpt.backup-mismatch", techBootkit, scoreBackupMismatch,
			"the primary and backup GPT disagree on the disk GUID or the partition entries: one was changed without the other"},
		{"gpt.backup-missing", techStructureWipe, scoreBackupMissing,
			"no valid backup GPT where the primary says it is (also what a truncated or resized image looks like)"},
		{"gpt.no-protective-mbr", techBootkit, scoreNoProtective,
			"a GPT disk whose MBR has no protective 0xEE entry"},
		{"gpt.partition-overlap", techBootkit, scoreOverlap,
			"two GPT partitions claim the same sectors"},
		{"gpt.partition-out-of-range", techBootkit, scoreOutOfRange,
			"a GPT partition lies outside the usable range the header declares"},
		{"mbr.bootcode-unrecognized", techBootkit, scoreBootcodeUnknown,
			"the MBR carries boot code that matches no loader the scan recognises (uncommon loaders are not in the list; this is a prompt to look, not a verdict)"},
		{"mbr.multiple-active", techBootkit, scoreMultipleActive,
			"more than one MBR partition is marked active"},
		{"mbr.partition-overlap", techBootkit, scoreOverlap,
			"two MBR partitions claim the same sectors"},
		{"mbr.partition-beyond-disk", techBootkit, scoreMBRBeyondDisk,
			"an MBR partition extends past the end of the disk"},
		{"vbr.esp-not-fat", techBootkit, scoreESPNotFAT,
			"a partition typed as the EFI System Partition does not begin with a FAT boot sector"},
		{"vbr.active-not-bootable", techBootkit, scoreActiveNoVBR,
			"the active MBR partition's first sector has no boot signature"},
		{"esp.windows-system-dir", techBootkit, scoreSystemDir,
			"a system32 directory at the root of the EFI System Partition: a documented bootkit staging location that no OS installer creates"},
		{"esp.unsigned-efi-binary", techBootkit, scoreUnsignedSB,
			"an EFI binary with no signature on a host with Secure Boot enabled (informational when Secure Boot is off or unknown)"},
		{"esp.non-efi-executable", techBootkit, scoreNonEFIPE,
			"a .efi file that is a PE for an operating-system subsystem, not an EFI application or driver"},
		{"esp.efi-binary-not-pe", techMasqueradeTyp, scoreNotPE,
			"a .efi file that is not a PE image at all"},
		{"esp.pending-capsule", techFirmware, 0,
			"a firmware update capsule is queued on the ESP for the next boot (expected during a vendor update)"},
		{"efi.setup-mode", techSigningPolicy, scoreSetupMode,
			"the platform is in Secure Boot setup mode: no platform key is enrolled, so keys can be enrolled without authorisation"},
		{"efi.secure-boot-disabled", techSigningPolicy, 0,
			"Secure Boot is disabled (posture, reported and never scored)"},
		{"efi.dbx-empty", techSigningPolicy, scoreDBXEmpty,
			"Secure Boot is enabled but the revocation list is empty: every revoked boot loader is still trusted"},
		{"efi.dbx-behind-reference", techSigningPolicy, scoreDBXBehind,
			"the host revocation list lacks entries present in the supplied reference list"},
		{"efi.bootorder-dangling", techBootkit, 0,
			"BootOrder names an entry that does not exist"},
		{"efi.boot-entry-target-missing", techBootkit, 0,
			"a boot entry points at a file that is not on the scanned ESP (stale entries are common)"},
		{"acpi.wpbt-present", techFirmware, scoreWPBT,
			"the firmware publishes a WPBT table: a vendor mechanism that has Windows run a firmware-supplied binary at every boot"},
		{"pci.option-rom", techComponentFW, 0,
			"a PCI device exposes an option ROM (inventory; contents are not read)"},
		{"esrt.last-attempt-failed", techFirmware, 0,
			"the firmware resource table records a failed update attempt"},
	}
}

var classIndex = func() map[string]Class {
	m := map[string]Class{}
	for _, c := range Classes() {
		m[c.Class] = c
	}
	return m
}()

// finding builds a Finding from the catalog, so a class can never be emitted
// with a weight or technique the catalog does not declare.
func finding(class, target, detail, evidence string) Finding {
	c, ok := classIndex[class]
	if !ok {
		panic("bootscan: finding class not in catalog: " + class)
	}
	return Finding{Class: class, Score: c.Weight, Technique: c.Technique, Target: target, Detail: detail, Evidence: evidence}
}

// findingScored is finding with a weight chosen by context (a class whose
// meaning depends on Secure Boot state), never above the catalog weight.
func findingScored(class, target, detail, evidence string, score int) Finding {
	f := finding(class, target, detail, evidence)
	if score < f.Score {
		f.Score = score
	}
	return f
}

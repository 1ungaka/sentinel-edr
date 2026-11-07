package bootscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A Baseline is the part of a Result that should be the same the next time
// the same host is scanned: what boots, from where, under which keys, and
// what the firmware publishes. Recording one on a host believed good and
// comparing later scans with it is what turns the inventories into tamper
// detection (see Compare).
//
// This file only builds, encodes and decodes a Baseline. Writing it to disk
// and signing it are the command's business: this package still never
// writes a file.

const (
	// BaselineSchema is the format version. Parse refuses any other, and the
	// signing bytes begin with it, so a signature never carries over to a
	// format with different meaning.
	BaselineSchema = 1
	// MaxBaselineBytes bounds an encoded baseline. A real one is a few tens
	// of kilobytes; the bound is what the per-list caps below add up to.
	MaxBaselineBytes = 16 << 20

	maxBaselineDisks  = 16
	maxBaselineString = 4096
	maxBaselineLabel  = 256
)

// Tri-state values. "unknown" is a state of its own: it never equals and
// never differs from a value.
const (
	StatePresent = "present"
	StateAbsent  = "absent"
	StateUnknown = "unknown"

	stateEnabled  = "enabled"
	stateDisabled = "disabled"
	stateOn       = "on"
	stateOff      = "off"
)

// Baseline is the comparable record of one host's boot chain.
type Baseline struct {
	Schema int `json:"schema"`
	// CreatedAt is set by whoever records the baseline. It is signed with
	// the rest and never compared.
	CreatedAt string `json:"created_at,omitempty"`
	// A nil surface was not read when the baseline was recorded.
	EFI      *BaselineEFI      `json:"efi,omitempty"`
	ESP      *BaselineESP      `json:"esp,omitempty"`
	Disks    []BaselineDisk    `json:"disks,omitempty"`
	Firmware *BaselineFirmware `json:"firmware,omitempty"`
	// Signature is the hex Ed25519 signature over SigningBytes, or empty.
	Signature string `json:"signature,omitempty"`
}

// BaselineEFI is the firmware-variable state.
type BaselineEFI struct {
	SecureBoot string `json:"secure_boot"` // enabled, disabled, unknown
	SetupMode  string `json:"setup_mode"`  // on, off, unknown

	BootOrderState string   `json:"boot_order_state"` // present, absent, unknown
	BootOrder      []string `json:"boot_order,omitempty"`
	// BootEntriesComplete is false when the entry list hit a bound: an entry
	// missing from it may still exist.
	BootEntriesComplete bool                `json:"boot_entries_complete"`
	BootEntries         []BaselineBootEntry `json:"boot_entries,omitempty"`

	PK   BaselineVar  `json:"pk"`
	KEK  BaselineVar  `json:"kek"`
	DB   BaselineVar  `json:"db"`
	DBX  BaselineVar  `json:"dbx"`
	MOK  BaselineVar  `json:"mok"`
	SBAT BaselineSBAT `json:"sbat"`
}

// BaselineBootEntry is one Boot#### load option.
type BaselineBootEntry struct {
	ID string `json:"id"`
	// Unread is set when the variable exists and could not be read; the
	// other fields are then empty.
	Unread      bool   `json:"unread,omitempty"`
	Description string `json:"description,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	Active      bool   `json:"active"`
	// SHA256 is the digest of the whole load option; TargetSHA256 of all of
	// it except the description and the active bit.
	SHA256       string `json:"sha256,omitempty"`
	TargetSHA256 string `json:"target_sha256,omitempty"`
}

// BaselineVar is one signature-database variable.
type BaselineVar struct {
	State        string `json:"state"` // present, absent, unknown
	SHA256       string `json:"sha256,omitempty"`
	Bytes        int    `json:"bytes,omitempty"`
	Hashes       int    `json:"sha256_hashes,omitempty"`
	Certificates int    `json:"x509_certificates,omitempty"`
	Other        int    `json:"other_entries,omitempty"`
	Unparsed     bool   `json:"unparsed,omitempty"`
}

// BaselineSBAT is the shim revocation level.
type BaselineSBAT struct {
	State    string      `json:"state"` // present, absent, unknown
	SHA256   string      `json:"sha256,omitempty"`
	Entries  []SBATEntry `json:"entries,omitempty"`
	Unparsed bool        `json:"unparsed,omitempty"`
}

// BaselineESP is the EFI binary inventory.
type BaselineESP struct {
	// Complete is false when the walk was partial: a binary missing from the
	// list may still be on the partition.
	Complete bool             `json:"complete"`
	Binaries []BaselineBinary `json:"binaries,omitempty"`
}

// BaselineBinary is one EFI binary.
type BaselineBinary struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// SHA256 is empty for a file too large to hash.
	SHA256    string `json:"sha256,omitempty"`
	Signed    bool   `json:"signed"`
	Subsystem string `json:"subsystem,omitempty"`
}

// BaselineDisk is the boot structure of one disk that was read.
type BaselineDisk struct {
	Path string `json:"path"`
	// Scheme is the partition table in use: gpt, mbr or none.
	Scheme         string              `json:"scheme"`
	BootCodeSHA256 string              `json:"boot_code_sha256,omitempty"` // empty: no boot code
	DiskSignature  string              `json:"disk_signature,omitempty"`
	DiskGUID       string              `json:"disk_guid,omitempty"`
	Partitions     []BaselinePartition `json:"partitions,omitempty"`
}

// BaselinePartition is one partition table entry.
type BaselinePartition struct {
	Index      int    `json:"index"`
	Scheme     string `json:"scheme"`
	Type       string `json:"type"`
	StartLBA   uint64 `json:"start_lba"`
	Sectors    uint64 `json:"sectors"`
	Active     bool   `json:"active,omitempty"`
	ESP        bool   `json:"esp,omitempty"`
	BootSector string `json:"boot_sector,omitempty"`
}

// BaselineFirmware is the sysfs firmware inventory. Each of the three lists
// is comparable only when its Read flag is set.
type BaselineFirmware struct {
	ACPIRead   bool          `json:"acpi_read"`
	ACPITables []string      `json:"acpi_tables,omitempty"`
	WPBT       *BaselineWPBT `json:"wpbt,omitempty"`

	PCIRead    bool          `json:"pci_read"`
	OptionROMs []BaselineROM `json:"option_roms,omitempty"`

	ESRTRead bool           `json:"esrt_read"`
	ESRT     []BaselineESRT `json:"esrt,omitempty"`
}

// BaselineWPBT is the WPBT table. SizeKnown is false when the table was
// there and its content needed root.
type BaselineWPBT struct {
	SizeKnown   bool   `json:"size_known"`
	HandoffSize uint32 `json:"handoff_size,omitempty"`
}

// BaselineROM is one PCI device exposing an option ROM.
type BaselineROM struct {
	Address string `json:"address"`
	Vendor  string `json:"vendor,omitempty"`
	Device  string `json:"device,omitempty"`
	Size    int64  `json:"size"`
}

// BaselineESRT is one updatable firmware component.
type BaselineESRT struct {
	Class   string `json:"fw_class"`
	Version string `json:"fw_version,omitempty"`
}

// cleanString makes a string safe to round-trip through JSON (which replaces
// invalid UTF-8) and bounds it. Both sides of a comparison pass through it,
// so it never creates a difference.
func cleanString(s string, max int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// NewBaseline reduces a scan to its comparable facts. It keeps, per surface:
//
//   - firmware variables: Secure Boot and setup-mode state, the boot order,
//     each boot entry (id, description, file path, active, and two digests),
//     the PK, KEK, db, dbx and shim MOK list (counts and a digest of each)
//     and the SBAT level;
//   - the ESP: each EFI binary's path, size, SHA-256, signature presence and
//     PE subsystem;
//   - each disk that was read: partition scheme, MBR boot-code digest, disk
//     signature, GPT disk GUID and every partition's index, type, start,
//     length, flags and boot-sector kind;
//   - the firmware inventory: ACPI table names, the WPBT table and its
//     declared size, option-ROM devices and ESRT versions.
//
// It leaves out what changes without anyone touching the boot chain:
// BootCurrent (which entry this boot happened to use), the variable count
// (firmware and the OS create and delete unrelated variables), file
// modification times and the ESP's total file count (configuration files are
// rewritten by every kernel update; the binaries are what is compared),
// queued capsules and ESRT last-attempt status (transient states the scan
// itself reports), partition names, disk and sector sizes, the mount points
// the surfaces were read from, and the scan's own findings, score and notes.
func NewBaseline(res *Result) *Baseline {
	b := &Baseline{Schema: BaselineSchema}
	if res == nil {
		return b
	}
	if e := res.EFI; e != nil {
		b.EFI = baselineEFI(e)
	}
	if e := res.ESP; e != nil {
		esp := &BaselineESP{Complete: !e.Truncated}
		seen := map[string]bool{}
		for _, bin := range e.Binaries {
			p := cleanString(bin.Path, maxBaselineString)
			if seen[p] || len(esp.Binaries) >= maxESPFiles {
				// Two names that are the same once made valid UTF-8: the
				// inventory cannot be represented exactly, so it is partial.
				esp.Complete = false
				continue
			}
			seen[p] = true
			esp.Binaries = append(esp.Binaries, BaselineBinary{
				Path: p, Size: bin.Size, SHA256: bin.SHA256, Signed: bin.Signed,
				Subsystem: cleanString(bin.Subsystem, maxBaselineLabel),
			})
		}
		sort.Slice(esp.Binaries, func(i, j int) bool { return esp.Binaries[i].Path < esp.Binaries[j].Path })
		b.ESP = esp
	}
	seenDisk := map[string]bool{}
	for _, d := range res.Disks {
		if d == nil || d.Error != "" {
			continue // not read: nothing to record, and nothing claimed
		}
		p := cleanString(d.Path, maxBaselineString)
		if seenDisk[p] || len(b.Disks) >= maxBaselineDisks {
			continue
		}
		seenDisk[p] = true
		b.Disks = append(b.Disks, baselineDisk(p, d))
	}
	sort.Slice(b.Disks, func(i, j int) bool { return b.Disks[i].Path < b.Disks[j].Path })
	if f := res.Firmware; f != nil {
		b.Firmware = baselineFirmware(f)
	}
	return b
}

func baselineEFI(e *EFIReport) *BaselineEFI {
	unreadable := map[string]bool{}
	for _, n := range e.Unreadable {
		unreadable[n] = true
	}
	state := func(present bool, name string) string {
		switch {
		case present:
			return StatePresent
		case unreadable[name]:
			return StateUnknown
		}
		return StateAbsent
	}
	out := &BaselineEFI{SecureBoot: StateUnknown, SetupMode: StateUnknown, BootEntriesComplete: !e.BootEntriesPartial}
	if e.SecureBoot != nil {
		out.SecureBoot = map[bool]string{true: stateEnabled, false: stateDisabled}[*e.SecureBoot]
	}
	if e.SetupMode != nil {
		out.SetupMode = map[bool]string{true: stateOn, false: stateOff}[*e.SetupMode]
	}

	// BootOrder: the report holds a list or nothing. An empty variable and a
	// missing one both leave the firmware to its default order.
	out.BootOrderState = state(len(e.BootOrder) > 0, "BootOrder")
	for i, id := range e.BootOrder {
		if i >= maxBootEntries {
			break
		}
		out.BootOrder = append(out.BootOrder, cleanString(id, 8))
	}

	seen := map[string]bool{}
	for _, be := range e.BootEntries {
		id := cleanString(be.ID, 8)
		if seen[id] || len(out.BootEntries) >= maxBootEntries {
			out.BootEntriesComplete = false
			continue
		}
		seen[id] = true
		out.BootEntries = append(out.BootEntries, BaselineBootEntry{
			ID: id, Description: cleanString(be.Description, maxBaselineLabel),
			FilePath: cleanString(be.FilePath, maxBaselineString), Active: be.Active,
			SHA256: be.SHA256, TargetSHA256: be.TargetSHA256,
		})
	}
	for _, n := range e.Unreadable {
		id := strings.TrimPrefix(n, "Boot")
		if len(n) != 8 || id == n || seen[id] || len(out.BootEntries) >= maxBootEntries {
			continue
		}
		seen[id] = true
		out.BootEntries = append(out.BootEntries, BaselineBootEntry{ID: id, Unread: true})
	}
	sort.Slice(out.BootEntries, func(i, j int) bool { return out.BootEntries[i].ID < out.BootEntries[j].ID })

	sigVar := func(db *SignatureDB, name string) BaselineVar {
		if db == nil {
			return BaselineVar{State: state(false, name)}
		}
		return BaselineVar{State: StatePresent, SHA256: db.SHA256, Bytes: db.Bytes,
			Hashes: db.Hashes, Certificates: db.Certificates, Other: db.Other, Unparsed: db.Unparsed}
	}
	out.PK = sigVar(e.PK, "PK")
	out.KEK = sigVar(e.KEK, "KEK")
	out.DB = sigVar(e.DB, "db")
	out.DBX = sigVar(e.DBX, "dbx")
	out.MOK = sigVar(e.MOK, "MokListRT")
	out.SBAT = BaselineSBAT{State: state(false, "SbatLevelRT")}
	if s := e.SBAT; s != nil {
		out.SBAT = BaselineSBAT{State: StatePresent, SHA256: s.SHA256, Unparsed: s.Unparsed}
		if !s.Unparsed {
			out.SBAT.Entries = append([]SBATEntry(nil), s.Entries...)
		}
	}
	return out
}

func baselineDisk(path string, d *DiskReport) BaselineDisk {
	out := BaselineDisk{Path: path, Scheme: "none"}
	if m := d.MBR; m != nil {
		out.BootCodeSHA256, out.DiskSignature = m.BootCodeSHA256, cleanString(m.DiskSignature, maxBaselineLabel)
		if m.SignatureValid {
			out.Scheme = "mbr"
		}
	}
	if g := d.GPT; g != nil {
		out.Scheme, out.DiskGUID = "gpt", cleanString(g.DiskGUID, maxBaselineLabel)
	}
	seen := map[string]bool{}
	for _, p := range d.Partitions {
		key := p.Scheme + "." + strconv.Itoa(p.Index)
		if seen[key] || len(out.Partitions) >= maxGPTEntries {
			continue
		}
		seen[key] = true
		out.Partitions = append(out.Partitions, BaselinePartition{
			Index: p.Index, Scheme: cleanString(p.Scheme, 8), Type: cleanString(p.Type, maxBaselineLabel),
			StartLBA: p.StartLBA, Sectors: p.Sectors, Active: p.Active, ESP: p.ESP,
			BootSector: cleanString(p.BootSector, maxBaselineLabel),
		})
	}
	sort.SliceStable(out.Partitions, func(i, j int) bool {
		a, b := out.Partitions[i], out.Partitions[j]
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		return a.Index < b.Index
	})
	return out
}

func baselineFirmware(f *FirmwareReport) *BaselineFirmware {
	out := &BaselineFirmware{ACPIRead: f.ACPIRead, PCIRead: f.PCIRead, ESRTRead: f.ESRTRead}
	seen := map[string]bool{}
	for _, t := range f.ACPITables {
		t = cleanString(t, maxBaselineLabel)
		if seen[t] || len(out.ACPITables) >= maxACPITables {
			out.ACPIRead = false
			continue
		}
		seen[t] = true
		out.ACPITables = append(out.ACPITables, t)
	}
	sort.Strings(out.ACPITables)
	if w := f.WPBT; w != nil {
		out.WPBT = &BaselineWPBT{SizeKnown: w.Readable}
		if w.Readable {
			out.WPBT.HandoffSize = w.HandoffSize
		}
	}

	seen = map[string]bool{}
	for _, r := range f.OptionROMs {
		addr := cleanString(r.Address, maxBaselineLabel)
		if seen[addr] || len(out.OptionROMs) >= maxPCIDevices {
			out.PCIRead = false
			continue
		}
		seen[addr] = true
		out.OptionROMs = append(out.OptionROMs, BaselineROM{Address: addr, Size: r.Size,
			Vendor: cleanString(r.Vendor, maxBaselineLabel), Device: cleanString(r.Device, maxBaselineLabel)})
	}
	sort.Slice(out.OptionROMs, func(i, j int) bool { return out.OptionROMs[i].Address < out.OptionROMs[j].Address })

	seen = map[string]bool{}
	for _, e := range f.ESRT {
		class := cleanString(e.Class, maxBaselineLabel)
		if seen[class] || len(out.ESRT) >= maxESRTEntries {
			// Two resources with one class cannot be told apart later.
			out.ESRTRead = false
			continue
		}
		seen[class] = true
		out.ESRT = append(out.ESRT, BaselineESRT{Class: class, Version: cleanString(e.Version, maxBaselineLabel)})
	}
	sort.Slice(out.ESRT, func(i, j int) bool { return out.ESRT[i].Class < out.ESRT[j].Class })
	return out
}

// ── validation ───────────────────────────────────────────────────────────────

func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validate checks everything Parse promises about a decoded baseline, and
// everything Marshal promises to produce: the schema, every enumerated
// state, every list and string bound, every digest's form, and that no list
// names the same item twice (a duplicate would make "which one" a matter of
// order, in a file its author controls).
func (b *Baseline) validate() error {
	if b.Schema != BaselineSchema {
		return fmt.Errorf("bootscan: baseline schema %d is not supported (this build reads schema %d)", b.Schema, BaselineSchema)
	}
	str := func(what, s string, max int) error {
		if len(s) > max {
			return fmt.Errorf("bootscan: baseline %s is longer than %d bytes", what, max)
		}
		if !utf8.ValidString(s) {
			return fmt.Errorf("bootscan: baseline %s is not valid UTF-8", what)
		}
		return nil
	}
	digest := func(what, s string, optional bool) error {
		if s == "" && optional {
			return nil
		}
		if !isHexDigest(s) {
			return fmt.Errorf("bootscan: baseline %s is not a SHA-256 digest", what)
		}
		return nil
	}
	oneOf := func(what, s string, allowed ...string) error {
		for _, a := range allowed {
			if s == a {
				return nil
			}
		}
		return fmt.Errorf("bootscan: baseline %s has unknown state %q", what, cleanString(s, 32))
	}
	var first error
	try := func(err error) {
		if first == nil {
			first = err
		}
	}

	try(str("created_at", b.CreatedAt, maxBaselineLabel))
	if len(b.Signature) > 2*64 {
		try(errors.New("bootscan: baseline signature is longer than an Ed25519 signature"))
	}
	if b.EFI == nil && b.ESP == nil && len(b.Disks) == 0 && b.Firmware == nil {
		try(errors.New("bootscan: the baseline records no surface at all; there is nothing to compare with"))
	}

	if e := b.EFI; e != nil {
		try(oneOf("efi.secure_boot", e.SecureBoot, stateEnabled, stateDisabled, StateUnknown))
		try(oneOf("efi.setup_mode", e.SetupMode, stateOn, stateOff, StateUnknown))
		try(oneOf("efi.boot_order_state", e.BootOrderState, StatePresent, StateAbsent, StateUnknown))
		if len(e.BootOrder) > maxBootEntries || len(e.BootEntries) > maxBootEntries {
			try(fmt.Errorf("bootscan: baseline lists more than %d boot entries", maxBootEntries))
		}
		if (e.BootOrderState == StatePresent) != (len(e.BootOrder) > 0) {
			try(errors.New("bootscan: baseline boot_order_state does not agree with boot_order"))
		}
		for _, id := range e.BootOrder {
			try(str("efi.boot_order entry", id, 8))
		}
		seen := map[string]bool{}
		for _, be := range e.BootEntries {
			if be.ID == "" || seen[be.ID] {
				try(fmt.Errorf("bootscan: baseline boot entry id %q is empty or listed twice", cleanString(be.ID, 8)))
			}
			seen[be.ID] = true
			try(str("efi.boot id", be.ID, 8))
			try(str("efi.boot description", be.Description, maxBaselineLabel))
			try(str("efi.boot file_path", be.FilePath, maxBaselineString))
			try(digest("efi.boot sha256", be.SHA256, be.Unread))
			try(digest("efi.boot target_sha256", be.TargetSHA256, true))
		}
		for _, v := range []struct {
			name string
			v    BaselineVar
		}{{"pk", e.PK}, {"kek", e.KEK}, {"db", e.DB}, {"dbx", e.DBX}, {"mok", e.MOK}} {
			try(oneOf("efi."+v.name+".state", v.v.State, StatePresent, StateAbsent, StateUnknown))
			try(digest("efi."+v.name+".sha256", v.v.SHA256, v.v.State != StatePresent))
			if v.v.Bytes < 0 || v.v.Bytes > maxEFIVarBytes || v.v.Hashes < 0 || v.v.Certificates < 0 || v.v.Other < 0 ||
				v.v.Hashes > maxEFIVarBytes || v.v.Certificates > maxEFIVarBytes || v.v.Other > maxEFIVarBytes {
				try(fmt.Errorf("bootscan: baseline efi.%s holds a count no firmware variable can have", v.name))
			}
		}
		try(oneOf("efi.sbat.state", e.SBAT.State, StatePresent, StateAbsent, StateUnknown))
		try(digest("efi.sbat.sha256", e.SBAT.SHA256, e.SBAT.State != StatePresent))
		if len(e.SBAT.Entries) > maxSBATEntries {
			try(fmt.Errorf("bootscan: baseline lists more than %d SBAT components", maxSBATEntries))
		}
		seen = map[string]bool{}
		for _, s := range e.SBAT.Entries {
			if !sbatName(s.Component) || len(s.Component) > maxSBATLine || seen[s.Component] || len(s.Date) > maxSBATLine || (s.Date != "" && !sbatName(s.Date)) {
				try(errors.New("bootscan: baseline SBAT component is malformed or listed twice"))
			}
			seen[s.Component] = true
		}
	}

	if e := b.ESP; e != nil {
		if len(e.Binaries) > maxESPFiles {
			try(fmt.Errorf("bootscan: baseline lists more than %d EFI binaries", maxESPFiles))
		}
		seen := map[string]bool{}
		for _, bin := range e.Binaries {
			if bin.Path == "" || seen[bin.Path] {
				try(errors.New("bootscan: baseline EFI binary path is empty or listed twice"))
			}
			seen[bin.Path] = true
			try(str("esp path", bin.Path, maxBaselineString))
			try(str("esp subsystem", bin.Subsystem, maxBaselineLabel))
			try(digest("esp sha256", bin.SHA256, true))
			if bin.Size < 0 {
				try(errors.New("bootscan: baseline EFI binary size is negative"))
			}
		}
	}

	if len(b.Disks) > maxBaselineDisks {
		try(fmt.Errorf("bootscan: baseline lists more than %d disks", maxBaselineDisks))
	}
	seenDisk := map[string]bool{}
	for _, d := range b.Disks {
		if d.Path == "" || seenDisk[d.Path] {
			try(errors.New("bootscan: baseline disk path is empty or listed twice"))
		}
		seenDisk[d.Path] = true
		try(str("disk path", d.Path, maxBaselineString))
		try(oneOf("disk scheme", d.Scheme, "gpt", "mbr", "none"))
		try(digest("disk boot_code_sha256", d.BootCodeSHA256, true))
		try(str("disk signature", d.DiskSignature, maxBaselineLabel))
		try(str("disk guid", d.DiskGUID, maxBaselineLabel))
		if len(d.Partitions) > maxGPTEntries {
			try(fmt.Errorf("bootscan: baseline disk lists more than %d partitions", maxGPTEntries))
		}
		seen := map[string]bool{}
		for _, p := range d.Partitions {
			key := p.Scheme + "." + strconv.Itoa(p.Index)
			if seen[key] || p.Index < 1 || p.Index > maxGPTEntries {
				try(errors.New("bootscan: baseline partition index is out of range or listed twice"))
			}
			seen[key] = true
			try(oneOf("partition scheme", p.Scheme, "gpt", "mbr"))
			try(str("partition type", p.Type, maxBaselineLabel))
			try(str("partition boot_sector", p.BootSector, maxBaselineLabel))
		}
	}

	if f := b.Firmware; f != nil {
		if len(f.ACPITables) > maxACPITables || len(f.OptionROMs) > maxPCIDevices || len(f.ESRT) > maxESRTEntries {
			try(errors.New("bootscan: baseline firmware inventory is larger than any the scan produces"))
		}
		seen := map[string]bool{}
		for _, t := range f.ACPITables {
			if t == "" || seen[t] {
				try(errors.New("bootscan: baseline ACPI table name is empty or listed twice"))
			}
			seen[t] = true
			try(str("acpi table", t, maxBaselineLabel))
		}
		if (f.WPBT != nil) != seen["WPBT"] {
			try(errors.New("bootscan: baseline wpbt does not agree with acpi_tables"))
		}
		seen = map[string]bool{}
		for _, r := range f.OptionROMs {
			if r.Address == "" || seen[r.Address] {
				try(errors.New("bootscan: baseline option ROM address is empty or listed twice"))
			}
			seen[r.Address] = true
			try(str("option rom address", r.Address, maxBaselineLabel))
			try(str("option rom vendor", r.Vendor, maxBaselineLabel))
			try(str("option rom device", r.Device, maxBaselineLabel))
			if r.Size < 0 {
				try(errors.New("bootscan: baseline option ROM size is negative"))
			}
		}
		seen = map[string]bool{}
		for _, e := range f.ESRT {
			if e.Class == "" || seen[e.Class] {
				try(errors.New("bootscan: baseline ESRT class is empty or listed twice"))
			}
			seen[e.Class] = true
			try(str("esrt class", e.Class, maxBaselineLabel))
			try(str("esrt version", e.Version, maxBaselineLabel))
		}
	}
	return first
}

// ── encoding ─────────────────────────────────────────────────────────────────

// Marshal encodes a baseline as indented JSON with a trailing newline: the
// file format, and what Parse reads back. It refuses a baseline Parse would
// refuse. Writing the bytes anywhere is the caller's decision.
func Marshal(b *Baseline) ([]byte, error) {
	if b == nil {
		return nil, errors.New("bootscan: no baseline to encode")
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	if buf.Len() > MaxBaselineBytes {
		return nil, fmt.Errorf("bootscan: the baseline encodes to %d bytes, over the %d-byte bound", buf.Len(), MaxBaselineBytes)
	}
	return buf.Bytes(), nil
}

// Parse decodes a baseline file. The file is untrusted: whoever can write it
// chooses every byte. Parse bounds the input, refuses unknown fields and
// trailing data (bytes a signature would not cover), and validates what it
// decoded. It does not check the signature; see SigningBytes.
func Parse(data []byte) (*Baseline, error) {
	if len(data) > MaxBaselineBytes {
		return nil, fmt.Errorf("bootscan: baseline is %d bytes, over the %d-byte bound", len(data), MaxBaselineBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bootscan: not a baseline: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("bootscan: not a baseline: data follows the JSON document")
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// canon builds the signing bytes: one record per line, a tag followed by
// fields, strings quoted with strconv.Quote and every list preceded by its
// length. Two baselines that differ in any field differ in these bytes, and
// the encoding depends on nothing but this file (not on a JSON encoder's
// choices about escaping or field order). Every field goes through one of
// the typed methods below, so there is no value it cannot encode.
type canon struct{ sb strings.Builder }

// rec starts a record; end finishes it.
func (c *canon) rec(tag string) *canon { c.sb.WriteString(tag); return c }
func (c *canon) end()                  { c.sb.WriteByte('\n') }

func (c *canon) str(v string) *canon {
	c.sb.WriteByte(' ')
	c.sb.WriteString(strconv.Quote(v))
	return c
}

func (c *canon) flag(v bool) *canon {
	c.sb.WriteByte(' ')
	c.sb.WriteString(strconv.FormatBool(v))
	return c
}

func (c *canon) num(v int64) *canon {
	c.sb.WriteByte(' ')
	c.sb.WriteString(strconv.FormatInt(v, 10))
	return c
}

func (c *canon) unum(v uint64) *canon {
	c.sb.WriteByte(' ')
	c.sb.WriteString(strconv.FormatUint(v, 10))
	return c
}

// SigningBytes is the canonical serialisation an Ed25519 signature covers:
// every field of the baseline except the signature itself, the schema
// version first. A caller signs these bytes and stores the signature, hex
// encoded, in Signature; a verifier recomputes them from the parsed file.
func (b *Baseline) SigningBytes() []byte {
	var c canon
	c.rec("cau-boot-baseline/v" + strconv.Itoa(b.Schema)).end()
	c.rec("created_at").str(b.CreatedAt).end()

	if e := b.EFI; e == nil {
		c.rec("efi").flag(false).end()
	} else {
		c.rec("efi").flag(true).str(e.SecureBoot).str(e.SetupMode).str(e.BootOrderState).flag(e.BootEntriesComplete).end()
		c.rec("boot_order").num(int64(len(e.BootOrder))).end()
		for _, id := range e.BootOrder {
			c.rec("order").str(id).end()
		}
		c.rec("boot_entries").num(int64(len(e.BootEntries))).end()
		for _, be := range e.BootEntries {
			c.rec("boot").str(be.ID).flag(be.Unread).str(be.Description).str(be.FilePath).flag(be.Active).str(be.SHA256).str(be.TargetSHA256).end()
		}
		for _, v := range []struct {
			name string
			v    BaselineVar
		}{{"pk", e.PK}, {"kek", e.KEK}, {"db", e.DB}, {"dbx", e.DBX}, {"mok", e.MOK}} {
			c.rec("var").str(v.name).str(v.v.State).str(v.v.SHA256).num(int64(v.v.Bytes)).
				num(int64(v.v.Hashes)).num(int64(v.v.Certificates)).num(int64(v.v.Other)).flag(v.v.Unparsed).end()
		}
		c.rec("sbat").str(e.SBAT.State).str(e.SBAT.SHA256).flag(e.SBAT.Unparsed).num(int64(len(e.SBAT.Entries))).end()
		for _, s := range e.SBAT.Entries {
			c.rec("sbat_entry").str(s.Component).unum(s.Generation).str(s.Date).end()
		}
	}

	if e := b.ESP; e == nil {
		c.rec("esp").flag(false).end()
	} else {
		c.rec("esp").flag(true).flag(e.Complete).num(int64(len(e.Binaries))).end()
		for _, bin := range e.Binaries {
			c.rec("binary").str(bin.Path).num(bin.Size).str(bin.SHA256).flag(bin.Signed).str(bin.Subsystem).end()
		}
	}

	c.rec("disks").num(int64(len(b.Disks))).end()
	for _, d := range b.Disks {
		c.rec("disk").str(d.Path).str(d.Scheme).str(d.BootCodeSHA256).str(d.DiskSignature).str(d.DiskGUID).num(int64(len(d.Partitions))).end()
		for _, p := range d.Partitions {
			c.rec("partition").num(int64(p.Index)).str(p.Scheme).str(p.Type).unum(p.StartLBA).unum(p.Sectors).
				flag(p.Active).flag(p.ESP).str(p.BootSector).end()
		}
	}

	if f := b.Firmware; f == nil {
		c.rec("firmware").flag(false).end()
	} else {
		c.rec("firmware").flag(true).flag(f.ACPIRead).flag(f.PCIRead).flag(f.ESRTRead).end()
		c.rec("acpi_tables").num(int64(len(f.ACPITables))).end()
		for _, t := range f.ACPITables {
			c.rec("acpi").str(t).end()
		}
		if w := f.WPBT; w == nil {
			c.rec("wpbt").flag(false).end()
		} else {
			c.rec("wpbt").flag(true).flag(w.SizeKnown).unum(uint64(w.HandoffSize)).end()
		}
		c.rec("option_roms").num(int64(len(f.OptionROMs))).end()
		for _, r := range f.OptionROMs {
			c.rec("rom").str(r.Address).str(r.Vendor).str(r.Device).num(r.Size).end()
		}
		c.rec("esrt").num(int64(len(f.ESRT))).end()
		for _, e := range f.ESRT {
			c.rec("esrt_entry").str(e.Class).str(e.Version).end()
		}
	}
	return []byte(c.sb.String())
}

// Covers lists, for a human, which surfaces the baseline records and which
// it does not. A surface that is not recorded is never compared.
func (b *Baseline) Covers() (recorded, missing []string) {
	add := func(ok bool, name string) {
		if ok {
			recorded = append(recorded, name)
		} else {
			missing = append(missing, name)
		}
	}
	add(b.EFI != nil, "firmware variables")
	add(b.ESP != nil, "EFI System Partition")
	add(len(b.Disks) > 0, "disks")
	f := b.Firmware
	add(f != nil && f.ACPIRead, "ACPI tables")
	add(f != nil && f.PCIRead, "option ROMs")
	add(f != nil && f.ESRTRead, "firmware resource table")
	return recorded, missing
}

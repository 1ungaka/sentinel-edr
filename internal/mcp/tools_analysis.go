package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/s-b-repo/cau/internal/bootscan"
	"github.com/s-b-repo/cau/internal/hwanchor"
	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/safefs"
	"github.com/s-b-repo/cau/scanner/uefi"
)

// The analysis tools: read-only views over one sandboxed path (peel_file,
// firmware_image), over explicitly named boot surfaces (boot_scan) or over a
// sysfs tree (hardware_identity). Each follows scan_file's discipline: the
// sandbox resolves every path, the file-size cap applies before a read, every
// list is capped with the cut reported, and every file-derived string goes
// through boundStr. Nothing here executes, writes, quarantines or blocks.

// ── peel_file ────────────────────────────────────────────────────────────────

// peelDeadline caps one peel_file call above the peeler's own 5 s wall clock.
const peelDeadline = 30 * time.Second

type peelFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	Detail    string `json:"detail"`
}

type peelChain struct {
	Signature string `json:"signature"`
	Terminal  string `json:"terminal"`
	Depth     int    `json:"depth"`
}

func (s *Server) toolPeelFile(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path string `json:"path"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, _, err := s.deps.Sandbox.ResolveFile(args.Path)
	if err != nil {
		return toolErr("peel_file: %v", err)
	}
	data, _, err := safefs.ReadFileNoFollow(real, s.deps.Sandbox.MaxBytes())
	if err != nil {
		return toolErr("peel_file: %v", err)
	}
	// The peeler's own budget (depth, nodes, output bytes, a 5 s wall clock)
	// bounds the walk; the context is a backstop above that budget so a
	// stalled peel can never hold the serial request loop. No leaves are
	// kept, so no decoded bytes exist to return.
	ctx, cancel := context.WithTimeout(context.Background(), peelDeadline) // audit:ok a tool call has no caller context (one serial JSON-RPC request); the deadline and the peeler's own 5 s wall clock bound it
	defer cancel()
	r := peeler.New().Peel(ctx, data)

	out := map[string]interface{}{
		"path":          args.Path,
		"size":          len(data),
		"outcome":       string(r.Outcome),
		"score":         r.Score,
		"threshold":     r.EffectiveThreshold(),
		"detected":      r.Score >= r.EffectiveThreshold(),
		"max_depth":     r.MaxDepth,
		"exhausted":     r.Exhausted,
		"nodes_visited": r.NodesVisited,
		"output_bytes":  r.OutputBytes,
		"root_entropy":  r.RootEntropy,
		"truncated":     false,
		"note":          "layer signatures and counts only; decoded bytes are never returned",
	}
	if r.ExhaustReason != "" {
		out["exhaust_reason"] = boundStr(r.ExhaustReason)
		out["exhaust_soft"] = r.ExhaustSoft
	}
	if r.PrimarySignature != "" {
		out["primary_signature"] = boundStr(r.PrimarySignature)
	}
	if r.DeepestSignature != "" {
		out["deepest_signature"] = boundStr(r.DeepestSignature)
	}
	var chains []peelChain
	for i, c := range r.Chains {
		if i >= maxListItems {
			out["chains_omitted"] = len(r.Chains) - maxListItems
			out["truncated"] = true
			break
		}
		chains = append(chains, peelChain{Signature: boundStr(c.Signature()), Terminal: string(c.Terminal), Depth: c.Depth})
	}
	if len(chains) > 0 {
		out["chains"] = chains
	}
	var findings []peelFinding
	for i, f := range r.Findings {
		if i >= maxListItems {
			out["findings_omitted"] = len(r.Findings) - maxListItems
			out["truncated"] = true
			break
		}
		findings = append(findings, peelFinding{Class: f.Class, Score: f.Score, Technique: f.Technique, Novel: f.Novel, Detail: boundStr(f.Detail)})
	}
	if len(findings) > 0 {
		out["findings"] = findings
	}
	if r.Archive != nil {
		out["archive"] = r.Archive
	}
	if len(r.Opaque) > 0 {
		opaque, omitted := boundStrs(r.Opaque)
		out["opaque"] = opaque
		if omitted > 0 {
			out["opaque_omitted"] = omitted
			out["truncated"] = true
		}
	}
	return jsonResult(out)
}

// ── firmware_image ───────────────────────────────────────────────────────────

type firmwareModule struct {
	GUID  string `json:"guid"`
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`
	Size  int    `json:"size"`
	HasPE bool   `json:"has_pe,omitempty"`
	Depth int    `json:"depth,omitempty"`
}

type firmwareFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

func (s *Server) toolFirmwareImage(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path string `json:"path"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, size, err := s.deps.Sandbox.ResolveFile(args.Path)
	if err != nil {
		return toolErr("firmware_image: %v", err)
	}
	// The firmware analyser's own cap applies on top of the sandbox cap: a
	// flash dump is parsed in memory, with LZMA sections opened.
	limit := s.deps.Sandbox.MaxBytes()
	if limit > uefi.DefaultMaxSize {
		limit = uefi.DefaultMaxSize
	}
	if size > limit {
		return toolErr("firmware_image: file is %d bytes, over the %d-byte firmware cap", size, limit)
	}
	data, _, err := safefs.ReadFileNoFollow(real, limit)
	if err != nil {
		return toolErr("firmware_image: %v", err)
	}
	r := uefi.Analyze(data, uefi.Options{})

	out := map[string]interface{}{
		"path":        args.Path,
		"size":        r.Size,
		"is_firmware": r.Parsed != nil,
		"score":       r.Score,
		"threshold":   r.EffectiveThreshold(),
		"truncated":   false,
	}
	if r.Parsed == nil {
		out["detected"] = false
		out["note"] = "not a UEFI firmware image: no firmware volume header or Intel flash descriptor found"
		return jsonResult(out)
	}

	// Rule scan over the executable module bodies, with the ruleset the
	// server already holds. Absence of a hit is only meaningful when rules
	// ran over everything, so the note says when they did not.
	var ruleNotes []string
	sections, cut := r.ExecutableSections()
	out["executable_sections"] = len(sections)
	switch {
	case s.deps.Yara == nil:
		ruleNotes = append(ruleNotes, "detection rules were not run over module bodies: no ruleset is loaded")
	case len(sections) == 0:
	default:
		var matches []uefi.RuleMatch
		failed := 0
		for _, sec := range sections {
			hits, err := s.deps.Yara.ScanMemYara(sec.Data)
			if err != nil {
				failed++
				continue
			}
			for _, h := range hits {
				matches = append(matches, uefi.RuleMatch{Rule: h.RuleName, Section: sec})
			}
		}
		r.AddRuleMatches(matches)
		out["rules_scanned"] = true
		if cut {
			ruleNotes = append(ruleNotes, "the image holds more executable-section bytes than are kept for rule scanning, so some module bodies were not scanned")
		}
		if failed > 0 {
			ruleNotes = append(ruleNotes, fmt.Sprintf("the rule scan failed on %d of %d module bodies", failed, len(sections)))
		}
	}
	if _, ok := out["rules_scanned"]; !ok {
		out["rules_scanned"] = false
	}
	out["detected"] = r.Detected()
	out["score"] = r.Score

	p := r.Parsed
	out["volumes"] = p.Volumes
	out["modules"] = p.Modules
	out["intel_flash"] = p.IntelFlash
	out["fv_checksum_valid"] = p.ChecksumValid
	out["decompressed_sections"] = p.Decompressed
	out["decompress_failed"] = p.DecompressFailed
	notes := []string{p.NotInspected}
	notes = append(notes, ruleNotes...)
	out["not_inspected"] = notes

	var inv []firmwareModule
	for i, m := range p.Inventory {
		if i >= maxListItems {
			out["inventory_omitted"] = len(p.Inventory) - maxListItems
			out["truncated"] = true
			break
		}
		inv = append(inv, firmwareModule{GUID: boundStr(m.GUID), Type: boundStr(m.Type), Name: boundStr(m.Name), Size: m.Size, HasPE: m.HasPE, Depth: m.Depth})
	}
	out["inventory"] = inv

	var findings []firmwareFinding
	for i, f := range r.Findings {
		if i >= maxListItems {
			out["findings_omitted"] = len(r.Findings) - maxListItems
			out["truncated"] = true
			break
		}
		findings = append(findings, firmwareFinding{Class: f.Class, Score: f.Score, Technique: f.Technique, Detail: boundStr(f.Detail), Evidence: boundStr(f.Evidence)})
	}
	if len(findings) > 0 {
		out["findings"] = findings
	}
	return jsonResult(out)
}

// ── boot_scan ────────────────────────────────────────────────────────────────

type bootFinding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Target    string `json:"target,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

type bootPartition struct {
	Index      int    `json:"index"`
	Scheme     string `json:"scheme"`
	Type       string `json:"type"`
	Name       string `json:"name,omitempty"`
	StartLBA   uint64 `json:"start_lba"`
	Sectors    uint64 `json:"sectors"`
	Active     bool   `json:"active,omitempty"`
	ESP        bool   `json:"esp,omitempty"`
	BootSector string `json:"boot_sector,omitempty"`
}

type bootDisk struct {
	Path              string            `json:"path"`
	Size              int64             `json:"size,omitempty"`
	SectorSize        int               `json:"sector_size,omitempty"`
	MBR               *bootscan.MBRInfo `json:"mbr,omitempty"`
	GPT               *bootscan.GPTInfo `json:"gpt,omitempty"`
	Partitions        []bootPartition   `json:"partitions,omitempty"`
	PartitionsOmitted int               `json:"partitions_omitted,omitempty"`
	Error             string            `json:"error,omitempty"`
}

type bootEFIBinary struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	PE        bool   `json:"pe"`
	Machine   string `json:"machine,omitempty"`
	Subsystem string `json:"subsystem,omitempty"`
	EFI       bool   `json:"efi_subsystem"`
	Signed    bool   `json:"signed"`
	Modified  string `json:"modified,omitempty"`
}

type bootEntry struct {
	ID           string `json:"id"`
	Description  string `json:"description,omitempty"`
	FilePath     string `json:"file_path,omitempty"`
	Active       bool   `json:"active"`
	InOrder      bool   `json:"in_boot_order"`
	TargetSHA256 string `json:"target_sha256,omitempty"`
}

func (s *Server) toolBootScan(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Disks        []string `json:"disks"`
		ESP          string   `json:"esp"`
		EFIVars      string   `json:"efivars"`
		Sysfs        string   `json:"sysfs"`
		DBXReference string   `json:"dbx_reference"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if len(args.Disks) == 0 && args.ESP == "" && args.EFIVars == "" && args.Sysfs == "" {
		return toolErr("boot_scan: nothing to scan; give at least one of disks, esp, efivars or sysfs (all inside a scan root)")
	}

	// Every input is resolved before anything is read: a request with one
	// bad path is refused whole, so a partial result cannot be mistaken for
	// a scan of everything that was asked for.
	var opts bootscan.Options
	if len(args.Disks) > maxListItems {
		return toolErr("boot_scan: %d disks given; at most %d per call", len(args.Disks), maxListItems)
	}
	given := make(map[string]string, len(args.Disks)) // real -> as given
	for _, d := range args.Disks {
		real, _, err := s.deps.Sandbox.ResolveRegular(d)
		if err != nil {
			return toolErr("boot_scan: disk %q: %v", d, err)
		}
		opts.Disks = append(opts.Disks, real)
		given[real] = d
	}
	if args.ESP != "" {
		real, _, err := s.deps.Sandbox.ResolveDir(args.ESP)
		if err != nil {
			return toolErr("boot_scan: esp: %v", err)
		}
		opts.ESP = real
	}
	if args.EFIVars != "" {
		real, err := s.deps.Sandbox.ResolveDirEntry(args.EFIVars)
		if err != nil {
			return toolErr("boot_scan: efivars: %v", err)
		}
		opts.EFIVars = real
	}
	if args.Sysfs != "" {
		real, err := s.deps.Sandbox.ResolveDirEntry(args.Sysfs)
		if err != nil {
			return toolErr("boot_scan: sysfs: %v", err)
		}
		opts.Sysfs = real
	}
	if args.DBXReference != "" {
		real, _, err := s.deps.Sandbox.ResolveFile(args.DBXReference)
		if err != nil {
			return toolErr("boot_scan: dbx_reference: %v", err)
		}
		opts.DBXReference = real
	}

	r := bootscan.Run(opts)
	out := map[string]interface{}{
		"score":     r.Score,
		"threshold": r.Threshold,
		"detected":  r.Detected(),
		"scanned":   r.Scanned(),
		"truncated": false,
	}
	cut := func(name string, n int) {
		if n > 0 {
			out[name+"_omitted"] = n
			out["truncated"] = true
		}
	}

	var findings []bootFinding
	for i, f := range r.Findings {
		if i >= maxListItems {
			cut("findings", len(r.Findings)-maxListItems)
			break
		}
		findings = append(findings, bootFinding{
			Class: f.Class, Score: f.Score, Technique: f.Technique,
			Target: boundStr(f.Target), Detail: boundStr(f.Detail), Evidence: boundStr(f.Evidence),
		})
	}
	if len(findings) > 0 {
		out["findings"] = findings
	}
	notes, omitted := boundStrs(r.Notes)
	out["notes"] = notes
	cut("notes", omitted)

	if len(r.Disks) > 0 {
		var disks []bootDisk
		for _, d := range r.Disks {
			if d == nil {
				continue
			}
			bd := bootDisk{
				Path: boundStr(given[d.Path]), Size: d.Size, SectorSize: d.SectorSize,
				MBR: d.MBR, GPT: d.GPT, Error: boundStr(d.Error),
			}
			if bd.Path == "" {
				bd.Path = boundStr(d.Path)
			}
			if d.MBR != nil {
				m := *d.MBR
				m.Loader = boundStr(m.Loader)
				bd.MBR = &m
			}
			for i, p := range d.Partitions {
				if i >= maxListItems {
					bd.PartitionsOmitted = len(d.Partitions) - maxListItems
					out["truncated"] = true
					break
				}
				bd.Partitions = append(bd.Partitions, bootPartition{
					Index: p.Index, Scheme: p.Scheme, Type: boundStr(p.Type), Name: boundStr(p.Name),
					StartLBA: p.StartLBA, Sectors: p.Sectors, Active: p.Active, ESP: p.ESP, BootSector: p.BootSector,
				})
			}
			disks = append(disks, bd)
		}
		out["disks"] = disks
	}

	if r.ESP != nil {
		esp := map[string]interface{}{
			"path":             args.ESP,
			"files":            r.ESP.Files,
			"pending_capsules": len(r.ESP.Capsules),
			"walk_truncated":   r.ESP.Truncated,
		}
		var bins []bootEFIBinary
		for i, b := range r.ESP.Binaries {
			if i >= maxListItems {
				esp["binaries_omitted"] = len(r.ESP.Binaries) - maxListItems
				out["truncated"] = true
				break
			}
			bins = append(bins, bootEFIBinary{
				Path: boundStr(b.Path), Size: b.Size, SHA256: b.SHA256, PE: b.PE,
				Machine: boundStr(b.Machine), Subsystem: boundStr(b.Subsystem), EFI: b.EFI, Signed: b.Signed, Modified: b.Modified,
			})
		}
		esp["binaries"] = bins
		if r.ESP.Truncated {
			out["truncated"] = true
		}
		out["esp"] = esp
	}

	if r.EFI != nil {
		e := r.EFI
		efi := map[string]interface{}{
			"path":                  args.EFIVars,
			"variables":             e.Variables,
			"secure_boot":           e.SecureBoot,
			"setup_mode":            e.SetupMode,
			"boot_current":          boundStr(e.BootCurrent),
			"platform_key_enrolled": e.PlatformKey,
			"boot_entries_partial":  e.BootEntriesPartial,
		}
		order, omitted := boundStrs(e.BootOrder)
		efi["boot_order"] = order
		if omitted > 0 {
			efi["boot_order_omitted"] = omitted
			out["truncated"] = true
		}
		var entries []bootEntry
		for i, be := range e.BootEntries {
			if i >= maxListItems {
				efi["boot_entries_omitted"] = len(e.BootEntries) - maxListItems
				out["truncated"] = true
				break
			}
			entries = append(entries, bootEntry{
				ID: boundStr(be.ID), Description: boundStr(be.Description), FilePath: boundStr(be.FilePath),
				Active: be.Active, InOrder: be.InOrder, TargetSHA256: be.TargetSHA256,
			})
		}
		efi["boot_entries"] = entries
		if e.BootEntriesPartial {
			out["truncated"] = true
		}
		for name, db := range map[string]*bootscan.SignatureDB{"pk": e.PK, "kek": e.KEK, "db": e.DB, "dbx": e.DBX, "mok": e.MOK} {
			if db != nil {
				efi[name] = db
			}
		}
		if e.SBATLevel != "" {
			efi["sbat_level"] = boundStr(e.SBATLevel)
		}
		if len(e.Unreadable) > 0 {
			unread, omitted := boundStrs(e.Unreadable)
			efi["unreadable_variables"] = unread
			if omitted > 0 {
				efi["unreadable_variables_omitted"] = omitted
				out["truncated"] = true
			}
		}
		if e.DBXReference != nil {
			efi["dbx_reference"] = e.DBXReference
		}
		out["efi"] = efi
	}

	if r.Firmware != nil {
		f := r.Firmware
		fw := map[string]interface{}{
			"path":      args.Sysfs,
			"acpi_read": f.ACPIRead,
			"pci_read":  f.PCIRead,
			"esrt_read": f.ESRTRead,
		}
		tables, omitted := boundStrs(f.ACPITables)
		fw["acpi_tables"] = tables
		fw["acpi_table_count"] = len(f.ACPITables)
		if omitted > 0 {
			fw["acpi_tables_omitted"] = omitted
			out["truncated"] = true
		}
		if f.WPBT != nil {
			fw["wpbt"] = f.WPBT
		}
		var roms []bootscan.OptionROM
		for i, rom := range f.OptionROMs {
			if i >= maxListItems {
				fw["option_roms_omitted"] = len(f.OptionROMs) - maxListItems
				out["truncated"] = true
				break
			}
			rom.Address, rom.Vendor, rom.Device, rom.Class = boundStr(rom.Address), boundStr(rom.Vendor), boundStr(rom.Device), boundStr(rom.Class)
			roms = append(roms, rom)
		}
		fw["option_roms"] = roms
		fw["option_rom_count"] = len(f.OptionROMs)
		var esrt []bootscan.ESRTEntry
		for i, e := range f.ESRT {
			if i >= maxListItems {
				fw["esrt_omitted"] = len(f.ESRT) - maxListItems
				out["truncated"] = true
				break
			}
			e.Class, e.Type, e.Version = boundStr(e.Class), boundStr(e.Type), boundStr(e.Version)
			e.LastAttempt, e.LastAttemptStatus = boundStr(e.LastAttempt), boundStr(e.LastAttemptStatus)
			esrt = append(esrt, e)
		}
		fw["esrt"] = esrt
		fw["esrt_count"] = len(f.ESRT)
		out["firmware"] = fw
	}
	return jsonResult(out)
}

// ── hardware_identity ────────────────────────────────────────────────────────

func (s *Server) toolHardwareIdentity(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Sysfs  string `json:"sysfs"`
		Redact *bool  `json:"redact"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	if args.Sysfs == "" {
		// Never default to the live /sys: an explicit, sandboxed root only.
		return toolErr("hardware_identity: sysfs is required (a sysfs root inside a scan root)")
	}
	real, err := s.deps.Sandbox.ResolveDirEntry(args.Sysfs)
	if err != nil {
		return toolErr("hardware_identity: %v", err)
	}
	snap, err := hwanchor.Capture(hwanchor.Options{Sysfs: real})
	if err != nil {
		return toolErr("hardware_identity: %v", err)
	}
	redact := args.Redact == nil || *args.Redact
	if redact {
		snap = hwanchor.Redact(snap)
	}

	out := map[string]interface{}{
		"schema":      snap.Schema,
		"captured_at": snap.CapturedAt,
		"sysfs":       args.Sysfs,
		"redacted":    snap.Redacted,
		"truncated":   false,
		"note":        "a read-only snapshot; the TPM quote is never captured, so tpm.quote is always unverifiable",
	}
	if !redact {
		out["warning"] = "redact=false: the values below identify one physical machine"
	}
	dmi := make(map[string]hwanchor.Field, len(snap.DMI))
	for k, f := range snap.DMI {
		f.Value, f.Reason = boundStr(f.Value), boundStr(f.Reason)
		dmi[boundStr(k)] = f
	}
	out["dmi"] = dmi

	var ifaces []hwanchor.Interface
	for i, in := range snap.Interfaces {
		if i >= maxListItems {
			out["interfaces_omitted"] = len(snap.Interfaces) - maxListItems
			out["truncated"] = true
			break
		}
		in.Name = boundStr(in.Name)
		in.Address.Value, in.Address.Reason = boundStr(in.Address.Value), boundStr(in.Address.Reason)
		in.AssignType.Value, in.AssignType.Reason = boundStr(in.AssignType.Value), boundStr(in.AssignType.Reason)
		in.PermanentAddress.Value, in.PermanentAddress.Reason = boundStr(in.PermanentAddress.Value), boundStr(in.PermanentAddress.Reason)
		ifaces = append(ifaces, in)
	}
	out["interfaces"] = ifaces
	out["interface_count"] = len(snap.Interfaces)

	var virt []hwanchor.VirtualInterface
	for i, v := range snap.VirtualInterfaces {
		if i >= maxListItems {
			out["virtual_interfaces_omitted"] = len(snap.VirtualInterfaces) - maxListItems
			out["truncated"] = true
			break
		}
		v.Name, v.Why = boundStr(v.Name), boundStr(v.Why)
		virt = append(virt, v)
	}
	out["virtual_interfaces"] = virt
	out["virtual_interface_count"] = len(snap.VirtualInterfaces)

	tpm := snap.TPM
	tpm.Reason = boundStr(tpm.Reason)
	tpm.VersionMajor.Value, tpm.VersionMajor.Reason = boundStr(tpm.VersionMajor.Value), boundStr(tpm.VersionMajor.Reason)
	for i := range tpm.PCRs {
		tpm.PCRs[i].Value, tpm.PCRs[i].Reason = boundStr(tpm.PCRs[i].Value), boundStr(tpm.PCRs[i].Reason)
	}
	out["tpm"] = tpm

	rng := snap.RNG
	rng.Current, rng.Reason = boundStr(rng.Current), boundStr(rng.Reason)
	rng.Available, _ = boundStrs(rng.Available)
	out["rng"] = rng

	var unv []hwanchor.Unverifiable
	for i, u := range snap.Unverifiable {
		if i >= maxListItems {
			out["unverifiable_omitted"] = len(snap.Unverifiable) - maxListItems
			out["truncated"] = true
			break
		}
		u.Anchor, u.Reason = boundStr(u.Anchor), boundStr(u.Reason)
		unv = append(unv, u)
	}
	out["unverifiable"] = unv

	notes, omitted := boundStrs(snap.Notes)
	out["notes"] = notes
	if omitted > 0 {
		out["notes_omitted"] = omitted
		out["truncated"] = true
	}
	return jsonResult(out)
}

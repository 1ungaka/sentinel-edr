package bootscan

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Firmware inventory from sysfs: ACPI tables (WPBT), PCI option ROMs and the
// EFI System Resource Table. Inventory, with one low-weight finding; the
// point is that these are listed at all, so a change between two scans is
// visible to whoever diffs the JSON.

const (
	maxPCIDevices  = 4096
	maxESRTEntries = 256
	maxACPITables  = 512
)

// FirmwareReport is the sysfs firmware inventory.
type FirmwareReport struct {
	// ACPITables are the table signatures the firmware publishes.
	ACPITables []string `json:"acpi_tables,omitempty"`
	// WPBT describes the Windows Platform Binary Table, when present.
	WPBT *WPBTInfo `json:"wpbt,omitempty"`
	// OptionROMs are PCI devices exposing an expansion ROM.
	OptionROMs []OptionROM `json:"option_roms,omitempty"`
	// ESRT lists the firmware components the platform can update.
	ESRT []ESRTEntry `json:"esrt,omitempty"`
}

// WPBTInfo is what could be read of the WPBT table.
type WPBTInfo struct {
	// Readable is false when the table exists but its content needs root.
	Readable    bool   `json:"readable"`
	HandoffSize uint32 `json:"handoff_size,omitempty"`
}

// OptionROM is one PCI device with an expansion ROM.
type OptionROM struct {
	Address string `json:"address"`
	Vendor  string `json:"vendor,omitempty"`
	Device  string `json:"device,omitempty"`
	Class   string `json:"class,omitempty"`
	// Size is the ROM resource size sysfs reports. The contents are not
	// read: sysfs only maps a ROM after a write to the file, and this scan
	// does not write.
	Size int64 `json:"size"`
}

// ESRTEntry is one firmware resource.
type ESRTEntry struct {
	Class             string `json:"fw_class"`
	Type              string `json:"fw_type,omitempty"`
	Version           string `json:"fw_version,omitempty"`
	LastAttempt       string `json:"last_attempt_version,omitempty"`
	LastAttemptStatus string `json:"last_attempt_status,omitempty"`
}

// sysText reads a small sysfs attribute as trimmed text.
func sysText(path string) string {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// ScanFirmware inventories the firmware surfaces sysfs exposes under root
// (normally /sys).
func ScanFirmware(root string) (*FirmwareReport, []Finding, []string) {
	rep := &FirmwareReport{}
	var out []Finding
	var notes []string
	seen := false

	// ── ACPI tables ──
	tables := filepath.Join(root, "firmware", "acpi", "tables")
	if entries, err := os.ReadDir(tables); err == nil {
		seen = true
		for _, e := range entries {
			if e.IsDir() || len(rep.ACPITables) >= maxACPITables {
				continue
			}
			rep.ACPITables = append(rep.ACPITables, e.Name())
		}
		sort.Strings(rep.ACPITables)
		for _, name := range rep.ACPITables {
			if name != "WPBT" {
				continue
			}
			rep.WPBT = &WPBTInfo{}
			evidence := "the table content needs root to read"
			// ACPI header (36 bytes), then the handoff size the firmware
			// declares for the binary it wants run.
			if raw, rerr := os.ReadFile(filepath.Join(tables, name)); rerr == nil && len(raw) >= 40 && len(raw) < 1<<20 {
				rep.WPBT.Readable = true
				rep.WPBT.HandoffSize = binary.LittleEndian.Uint32(raw[36:40])
				evidence = fmt.Sprintf("declared platform binary size %d bytes", rep.WPBT.HandoffSize)
			}
			out = append(out, finding("acpi.wpbt-present", "WPBT",
				"the firmware publishes a WPBT table, which has Windows run a firmware-supplied binary at every boot (inert under Linux; it matters on a host that also boots Windows)",
				evidence))
		}
	}

	// ── PCI option ROMs ──
	devices := filepath.Join(root, "bus", "pci", "devices")
	if entries, err := os.ReadDir(devices); err == nil {
		seen = true
		for i, e := range entries {
			if i >= maxPCIDevices {
				notes = append(notes, fmt.Sprintf("more than %d PCI devices; the rest were not inventoried", maxPCIDevices))
				break
			}
			dev := filepath.Join(devices, e.Name())
			fi, err := os.Stat(filepath.Join(dev, "rom")) // stat only: never opened
			if err != nil {
				continue
			}
			rep.OptionROMs = append(rep.OptionROMs, OptionROM{
				Address: e.Name(), Size: fi.Size(),
				Vendor: sysText(filepath.Join(dev, "vendor")),
				Device: sysText(filepath.Join(dev, "device")),
				Class:  sysText(filepath.Join(dev, "class")),
			})
		}
		if n := len(rep.OptionROMs); n > 0 {
			var addrs []string
			for _, r := range rep.OptionROMs {
				addrs = append(addrs, r.Address)
			}
			out = append(out, finding("pci.option-rom", "",
				fmt.Sprintf("%d PCI device(s) expose an option ROM; contents are not read", n),
				strings.Join(firstN(addrs, 8), ", ")))
		}
	}

	// ── EFI System Resource Table ──
	esrt := filepath.Join(root, "firmware", "efi", "esrt", "entries")
	if entries, err := os.ReadDir(esrt); err == nil {
		seen = true
		for i, e := range entries {
			if i >= maxESRTEntries {
				break
			}
			dir := filepath.Join(esrt, e.Name())
			ent := ESRTEntry{
				Class:             sysText(filepath.Join(dir, "fw_class")),
				Type:              sysText(filepath.Join(dir, "fw_type")),
				Version:           sysText(filepath.Join(dir, "fw_version")),
				LastAttempt:       sysText(filepath.Join(dir, "last_attempt_version")),
				LastAttemptStatus: sysText(filepath.Join(dir, "last_attempt_status")),
			}
			if ent.Class == "" {
				continue
			}
			rep.ESRT = append(rep.ESRT, ent)
			if ent.LastAttemptStatus != "" && ent.LastAttemptStatus != "0" {
				out = append(out, finding("esrt.last-attempt-failed", ent.Class,
					"the last firmware update attempt for this component did not succeed",
					"last_attempt_status "+ent.LastAttemptStatus+", attempted version "+ent.LastAttempt))
			}
		}
	}

	if !seen {
		return nil, nil, []string{"no firmware inventory under " + root + ": ACPI tables, PCI devices and the ESRT are all absent or unreadable"}
	}
	return rep, out, notes
}

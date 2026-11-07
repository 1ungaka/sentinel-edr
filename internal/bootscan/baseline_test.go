package bootscan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── a synthetic host ─────────────────────────────────────────────────────────
//
// Every comparison test starts from the same generated host: firmware
// variables, an ESP, one GPT disk and a sysfs tree, all written at test time.

type host struct {
	t                      *testing.T
	vars, esp, sysfs, disk string
}

const esrtClass = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{t: t}
	h.vars = efivars(t, true, false, append(sigList(0xAA, 0xBB), certList(100)...))
	writeVar(t, h.vars, "KEK", guidGlobal, certList(700))
	writeVar(t, h.vars, "MokListRT", guidShim, certList(800))
	h.esp = writeESP(t, map[string][]byte{
		"EFI/debian/shimx64.efi": pe(10, true, true),
		"EFI/debian/grubx64.efi": append(pe(10, true, true), "grub"...),
		"EFI/BOOT/BOOTX64.EFI":   append(pe(10, true, true), "fallback"...),
		"EFI/debian/grub.cfg":    []byte("search.fs_uuid 1234 root\n"),
	})
	h.sysfs = writeESP(t, map[string][]byte{
		"firmware/acpi/tables/DSDT":                                []byte("DSDT"),
		"firmware/acpi/tables/DMAR":                                []byte("DMAR"),
		"firmware/acpi/tables/FACP":                                []byte("FACP"),
		"bus/pci/devices/0000:01:00.0/rom":                         make([]byte, 4096),
		"bus/pci/devices/0000:01:00.0/vendor":                      []byte("0x10de\n"),
		"bus/pci/devices/0000:01:00.0/device":                      []byte("0x1c82\n"),
		"bus/pci/devices/0000:00:1f.0/vendor":                      []byte("0x8086\n"),
		"firmware/efi/esrt/entries/entry0/fw_class":                []byte(esrtClass + "\n"),
		"firmware/efi/esrt/entries/entry0/fw_version":              []byte("65539\n"),
		"firmware/efi/esrt/entries/entry0/last_attempt_status":     []byte("0\n"),
		"firmware/efi/esrt/entries/entry0/last_attempt_version":    []byte("65539\n"),
		"firmware/acpi/tables/data/BERT":                           []byte("a subdirectory is not a table"),
		"firmware/acpi/tables/dynamic/SSDT1":                       []byte("neither is a dynamic one"),
		"bus/pci/devices/0000:00:1f.0/class":                       []byte("0x060100\n"),
		"firmware/efi/esrt/entries/entry0/fw_type":                 []byte("1\n"),
		"firmware/efi/esrt/entries/entry0/lowest_supported_fw_ver": []byte("1\n"),
	})
	h.disk = filepath.Join(t.TempDir(), "disk.img")
	h.write(h.disk, standardGPT())
	return h
}

func (h *host) write(path string, data []byte) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (h *host) remove(path string) {
	h.t.Helper()
	if err := os.RemoveAll(path); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) setVar(name, guid string, data []byte) { writeVar(h.t, h.vars, name, guid, data) }
func (h *host) delVar(name, guid string)              { h.remove(filepath.Join(h.vars, name+"-"+guid)) }
func (h *host) espFile(rel string) string             { return filepath.Join(h.esp, filepath.FromSlash(rel)) }
func (h *host) sys(rel string) string                 { return filepath.Join(h.sysfs, filepath.FromSlash(rel)) }

func (h *host) options() Options {
	return Options{Disks: []string{h.disk}, ESP: h.esp, EFIVars: h.vars, Sysfs: h.sysfs}
}

func (h *host) baseline() *Baseline { return NewBaseline(Run(h.options())) }

// want is one expected difference.
type want struct {
	item string
	kind DiffKind
	sev  Severity
}

func describeDiffs(diffs []Difference) string {
	var sb strings.Builder
	for _, d := range diffs {
		fmt.Fprintf(&sb, "\n  [%s/%s] %s: %q -> %q (%s)", d.Kind, d.Severity, d.Item, d.Old, d.New, d.Detail)
	}
	return sb.String()
}

// expectDiffs requires exactly the listed differences, in any order.
func expectDiffs(t *testing.T, diffs []Difference, wants ...want) {
	t.Helper()
	if len(diffs) != len(wants) {
		t.Fatalf("got %d differences, want %d:%s", len(diffs), len(wants), describeDiffs(diffs))
	}
	for _, w := range wants {
		found := false
		for _, d := range diffs {
			if d.Item == w.item && d.Kind == w.kind && d.Severity == w.sev {
				found = true
				if d.Detail == "" || d.Surface == "" {
					t.Errorf("%s: a difference needs a surface and a detail: %+v", w.item, d)
				}
				if w.sev == SeverityExpectedUpdate && !strings.Contains(d.Detail, "vendor or OS update") {
					t.Errorf("%s: an expected-update difference must say an update produces it: %q", w.item, d.Detail)
				}
			}
		}
		if !found {
			t.Errorf("missing [%s/%s] %s in:%s", w.kind, w.sev, w.item, describeDiffs(diffs))
		}
	}
	security := false
	for _, w := range wants {
		security = security || w.sev == SeveritySecurity
	}
	if SecurityRelevant(diffs) != security {
		t.Errorf("SecurityRelevant = %v, want %v:%s", SecurityRelevant(diffs), security, describeDiffs(diffs))
	}
}

func compare(t *testing.T, b, c *Baseline) []Difference {
	t.Helper()
	diffs, err := Compare(b, c)
	if err != nil {
		t.Fatal(err)
	}
	if diffs == nil {
		t.Fatal("Compare must return an empty list, not nil")
	}
	return diffs
}

// loadOptionWith is loadOption with a chosen byte in the hard-drive node (the
// partition the file is on) and trailing optional data (loader arguments).
func loadOptionWith(active bool, desc, file string, hdByte byte, optional string) []byte {
	opt := loadOption(active, desc, file)
	hd := 6 + len(utf16le(desc)) + 2 // attributes, path length, description, terminator
	opt[hd+10] = hdByte
	return append(opt, optional...)
}

// ── the table, row by row ────────────────────────────────────────────────────

func TestCompareUnchangedHostHasNoDifferences(t *testing.T) {
	h := newHost(t)
	b := h.baseline()
	if b.EFI == nil || b.ESP == nil || len(b.Disks) != 1 || b.Firmware == nil {
		t.Fatalf("the fixture should cover every surface: %+v", b)
	}
	if !b.ESP.Complete || !b.EFI.BootEntriesComplete || !b.Firmware.ACPIRead || !b.Firmware.PCIRead || !b.Firmware.ESRTRead {
		t.Fatalf("the fixture should be read completely: %+v %+v %+v", b.ESP, b.EFI, b.Firmware)
	}
	if strings.Join(b.Firmware.ACPITables, ",") != "DMAR,DSDT,FACP" {
		t.Errorf("only top-level ACPI tables are recorded: %v", b.Firmware.ACPITables)
	}
	expectDiffs(t, compare(t, b, h.baseline()))

	// What changes on its own must not show: which entry booted, unrelated
	// variables, file times, other files on the ESP, a queued capsule, the
	// ESRT's last-attempt status.
	h.setVar("BootCurrent", guidGlobal, []byte{3, 0})
	h.setVar("SomeVendorCounter", guidShim, []byte{9, 9, 9})
	h.write(h.espFile("EFI/debian/grub.cfg"), []byte("a new kernel entry\n"))
	h.write(h.espFile("EFI/UpdateCapsule/fw.cap"), []byte("capsule"))
	h.write(h.sys("firmware/efi/esrt/entries/entry0/last_attempt_status"), []byte("3\n"))
	old := mustReadFile(t, h.espFile("EFI/debian/shimx64.efi"))
	h.write(h.espFile("EFI/debian/shimx64.efi"), old) // same bytes, new mtime
	expectDiffs(t, compare(t, b, h.baseline()))
}

func TestCompareFirmwareVariables(t *testing.T) {
	dbx := func(hashes ...byte) []byte { return append(sigList(hashes...), certList(100)...) }
	rows := []struct {
		name   string
		before func(h *host) // applied before the baseline is recorded
		change func(h *host)
		wants  []want
	}{
		{"secure boot turned off", nil,
			func(h *host) { h.setVar("SecureBoot", guidGlobal, []byte{0}) },
			[]want{{"efi.secure_boot", KindChanged, SeveritySecurity}}},
		{"secure boot turned on",
			func(h *host) { h.setVar("SecureBoot", guidGlobal, []byte{0}) },
			func(h *host) { h.setVar("SecureBoot", guidGlobal, []byte{1}) },
			[]want{{"efi.secure_boot", KindChanged, SeverityInfo}}},
		{"setup mode turned on", nil,
			func(h *host) { h.setVar("SetupMode", guidGlobal, []byte{1}) },
			[]want{{"efi.setup_mode", KindChanged, SeveritySecurity}}},
		{"setup mode turned off",
			func(h *host) { h.setVar("SetupMode", guidGlobal, []byte{1}) },
			func(h *host) { h.setVar("SetupMode", guidGlobal, []byte{0}) },
			[]want{{"efi.setup_mode", KindChanged, SeverityInfo}}},

		{"platform key gone", nil,
			func(h *host) { h.delVar("PK", guidGlobal) },
			[]want{{"efi.pk", KindRemoved, SeveritySecurity}}},
		{"platform key enrolled",
			func(h *host) { h.delVar("PK", guidGlobal) },
			func(h *host) { h.setVar("PK", guidGlobal, certList(64)) },
			[]want{{"efi.pk", KindAdded, SeveritySecurity}}},
		{"platform key replaced", nil,
			func(h *host) { h.setVar("PK", guidGlobal, append(certList(64)[:91], 1)) },
			[]want{{"efi.pk", KindChanged, SeveritySecurity}}},
		{"KEK changed", nil,
			func(h *host) { h.setVar("KEK", guidGlobal, append(certList(700), certList(300)...)) },
			[]want{{"efi.kek", KindChanged, SeveritySecurity}}},
		{"db grew", nil,
			func(h *host) { h.setVar("db", guidSecurity, append(certList(900), certList(901)...)) },
			[]want{{"efi.db", KindChanged, SeveritySecurity}}},
		{"db shrank",
			func(h *host) { h.setVar("db", guidSecurity, append(certList(900), certList(901)...)) },
			func(h *host) { h.setVar("db", guidSecurity, certList(900)) },
			[]want{{"efi.db", KindChanged, SeveritySecurity}}},
		{"db gone", nil,
			func(h *host) { h.delVar("db", guidSecurity) },
			[]want{{"efi.db", KindRemoved, SeveritySecurity}}},
		{"MOK enrolled",
			func(h *host) { h.delVar("MokListRT", guidShim) },
			func(h *host) { h.setVar("MokListRT", guidShim, certList(800)) },
			[]want{{"efi.mok", KindAdded, SeveritySecurity}}},
		{"MOK list grew", nil,
			func(h *host) { h.setVar("MokListRT", guidShim, append(certList(800), certList(500)...)) },
			[]want{{"efi.mok", KindChanged, SeveritySecurity}}},

		{"dbx shrank", nil,
			func(h *host) { h.setVar("dbx", guidSecurity, dbx(0xAA)) },
			[]want{{"efi.dbx", KindChanged, SeveritySecurity}}},
		{"dbx lost a certificate while gaining hashes", nil,
			func(h *host) { h.setVar("dbx", guidSecurity, sigList(0xAA, 0xBB, 0xCC, 0xDD)) },
			[]want{{"efi.dbx", KindChanged, SeveritySecurity}}},
		{"dbx grew", nil,
			func(h *host) { h.setVar("dbx", guidSecurity, dbx(0xAA, 0xBB, 0xCC)) },
			[]want{{"efi.dbx", KindChanged, SeverityExpectedUpdate}}},
		{"dbx same size, other entries", nil,
			func(h *host) { h.setVar("dbx", guidSecurity, dbx(0xAA, 0xEE)) },
			[]want{{"efi.dbx", KindChanged, SeveritySecurity}}},
		{"dbx gone", nil,
			func(h *host) { h.delVar("dbx", guidSecurity) },
			[]want{{"efi.dbx", KindRemoved, SeveritySecurity}}},
		{"dbx appeared",
			func(h *host) { h.delVar("dbx", guidSecurity) },
			func(h *host) { h.setVar("dbx", guidSecurity, dbx(0xAA)) },
			[]want{{"efi.dbx", KindAdded, SeverityExpectedUpdate}}},
		{"dbx no longer a signature list", nil,
			func(h *host) {
				h.setVar("dbx", guidSecurity, []byte("not a signature list at all, but longer than one header"))
			},
			[]want{{"efi.dbx", KindChanged, SeveritySecurity}}},

		{"SBAT level rose", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2024010900\nshim,5\n")) },
			[]want{{"efi.sbat", KindChanged, SeverityExpectedUpdate}}},
		{"SBAT datestamp rose and a component was added", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2025010100\nshim,4\ngrub,3\n")) },
			[]want{{"efi.sbat", KindChanged, SeverityExpectedUpdate}}},
		{"SBAT level fell", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2024010900\nshim,3\n")) },
			[]want{{"efi.sbat", KindChanged, SeveritySecurity}}},
		{"SBAT datestamp fell", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2021030218\nshim,4\n")) },
			[]want{{"efi.sbat", KindChanged, SeveritySecurity}}},
		{"SBAT rose for one component and fell for another", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2025010100\nshim,1\n")) },
			[]want{{"efi.sbat", KindChanged, SeveritySecurity}}},
		{"SBAT component no longer listed", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2024010900\n")) },
			[]want{{"efi.sbat", KindChanged, SeveritySecurity}}},
		{"SBAT not in shim's format", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("garbage\n")) },
			[]want{{"efi.sbat", KindChanged, SeveritySecurity}}},
		{"SBAT gone", nil,
			func(h *host) { h.delVar("SbatLevelRT", guidShim) },
			[]want{{"efi.sbat", KindRemoved, SeveritySecurity}}},
		{"SBAT appeared",
			func(h *host) { h.delVar("SbatLevelRT", guidShim) },
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2024010900\n")) },
			[]want{{"efi.sbat", KindAdded, SeverityExpectedUpdate}}},
		{"SBAT same levels, other bytes", nil,
			func(h *host) { h.setVar("SbatLevelRT", guidShim, []byte("sbat,1,2024010900\r\nshim,4\r\n\x00")) },
			[]want{{"efi.sbat", KindChanged, SeverityInfo}}},

		{"another entry first in the boot order", nil,
			func(h *host) { h.setVar("BootOrder", guidGlobal, []byte{3, 0, 1, 0}) },
			[]want{{"efi.boot_order", KindChanged, SeveritySecurity}}},
		{"boot order changed after the first entry", nil,
			func(h *host) { h.setVar("BootOrder", guidGlobal, []byte{1, 0}) },
			[]want{{"efi.boot_order", KindChanged, SeverityInfo}}},
		{"boot order gone", nil,
			func(h *host) { h.delVar("BootOrder", guidGlobal) },
			[]want{{"efi.boot_order", KindChanged, SeveritySecurity}}},
		{"first entry made inactive, same order", nil,
			func(h *host) {
				h.setVar("Boot0001", guidGlobal, loadOption(false, "debian", `\EFI\debian\shimx64.efi`))
			},
			[]want{{"efi.boot_order", KindChanged, SeveritySecurity}, {"efi.boot.0001", KindChanged, SeveritySecurity}}},
		{"first entry deleted, same order", nil,
			func(h *host) { h.delVar("Boot0001", guidGlobal) },
			[]want{{"efi.boot_order", KindChanged, SeveritySecurity}, {"efi.boot.0001", KindRemoved, SeverityInfo}}},

		{"boot entry added", nil,
			func(h *host) { h.setVar("Boot0005", guidGlobal, loadOption(true, "Linux", `\EFI\BOOT\BOOTX64.EFI`)) },
			[]want{{"efi.boot.0005", KindAdded, SeveritySecurity}}},
		{"boot entry target changed", nil,
			func(h *host) { h.setVar("Boot0001", guidGlobal, loadOption(true, "debian", `\EFI\debian\grubx64.efi`)) },
			[]want{{"efi.boot.0001", KindChanged, SeveritySecurity}}},
		{"boot entry points at another partition, same file name", nil,
			func(h *host) {
				h.setVar("Boot0001", guidGlobal, loadOptionWith(true, "debian", `\EFI\debian\shimx64.efi`, 7, ""))
			},
			[]want{{"efi.boot.0001", KindChanged, SeveritySecurity}}},
		{"boot entry gained loader arguments", nil,
			func(h *host) {
				h.setVar("Boot0001", guidGlobal, loadOptionWith(true, "debian", `\EFI\debian\shimx64.efi`, 0, "init=/bin/sh"))
			},
			[]want{{"efi.boot.0001", KindChanged, SeveritySecurity}}},
		{"inactive entry activated", nil,
			func(h *host) { h.setVar("Boot0003", guidGlobal, loadOption(true, "Old Entry", `\EFI\gone\loader.efi`)) },
			[]want{{"efi.boot.0003", KindChanged, SeveritySecurity}}},
		{"boot entry relabelled", nil,
			func(h *host) {
				h.setVar("Boot0001", guidGlobal, loadOption(true, "Debian GNU/Linux", `\EFI\debian\shimx64.efi`))
			},
			[]want{{"efi.boot.0001", KindChanged, SeverityInfo}}},
		{"boot entry removed, not the one that boots", nil,
			func(h *host) { h.delVar("Boot0003", guidGlobal) },
			[]want{{"efi.boot.0003", KindRemoved, SeverityInfo}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHost(t)
			if row.before != nil {
				row.before(h)
			}
			b := h.baseline()
			row.change(h)
			expectDiffs(t, compare(t, b, h.baseline()), row.wants...)
		})
	}
}

func TestCompareESP(t *testing.T) {
	rows := []struct {
		name   string
		change func(h *host)
		wants  []want
	}{
		{"binary added",
			func(h *host) {
				h.write(h.espFile("EFI/systemd/systemd-bootx64.efi"), append(pe(10, true, true), "new"...))
			},
			[]want{{"esp:EFI/systemd/systemd-bootx64.efi", KindAdded, SeveritySecurity}}},
		// A replaced loader that still carries a signature is NOT an
		// expected update: the signature is seen, never verified.
		{"signed loader replaced by another signed binary",
			func(h *host) { h.write(h.espFile("EFI/debian/shimx64.efi"), append(pe(10, true, true), "other"...)) },
			[]want{{"esp:EFI/debian/shimx64.efi", KindChanged, SeveritySecurity}}},
		{"signature stripped",
			func(h *host) { h.write(h.espFile("EFI/debian/shimx64.efi"), pe(10, true, false)) },
			[]want{{"esp:EFI/debian/shimx64.efi", KindChanged, SeveritySecurity}}},
		{"binary removed",
			func(h *host) { h.remove(h.espFile("EFI/debian/grubx64.efi")) },
			[]want{{"esp:EFI/debian/grubx64.efi", KindRemoved, SeverityInfo}}},
		{"loader copied to a new path",
			func(h *host) { h.write(h.espFile("EFI/evil/shimx64.efi"), pe(10, true, true)) },
			[]want{{"esp:EFI/evil/shimx64.efi", KindAdded, SeveritySecurity}}},
		// FAT does not distinguish case: BOOT recreated as Boot is the same file.
		{"directory case changed, same content",
			func(h *host) {
				if err := os.Rename(h.espFile("EFI/BOOT"), h.espFile("EFI/Boot")); err != nil {
					h.t.Skip(err)
				}
			}, nil},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHost(t)
			b := h.baseline()
			row.change(h)
			diffs := compare(t, b, h.baseline())
			expectDiffs(t, diffs, row.wants...)
			for _, d := range diffs {
				if d.Item == "esp:EFI/evil/shimx64.efi" && !strings.Contains(d.Detail, "identical to EFI/debian/shimx64.efi") {
					t.Errorf("a copy should name what it is a copy of: %q", d.Detail)
				}
				if d.Kind == KindChanged && strings.Contains(row.name, "signed loader") && !strings.Contains(d.Detail, "cannot verify") {
					t.Errorf("the detail should say why a signed change is not an update: %q", d.Detail)
				}
			}
		})
	}
}

func TestCompareDisks(t *testing.T) {
	two := []gptPart{{espTypeGUID, 64, 1087, "EFI System Partition"}, {linuxTypeGUID, 1088, 3000, "root"}}
	rows := []struct {
		name   string
		before []byte
		after  []byte
		wants  []want
	}{
		{"partition added", standardGPT(),
			gptDisk(512, append(append([]gptPart(nil), two...), gptPart{linuxTypeGUID, 3001, 3500, "extra"})...),
			[]want{{".gpt.partition.3", KindAdded, SeveritySecurity}}},
		{"partition removed", standardGPT(), gptDisk(512, two[0]),
			[]want{{".gpt.partition.2", KindRemoved, SeveritySecurity}}},
		{"partition resized", standardGPT(),
			gptDisk(512, two[0], gptPart{linuxTypeGUID, 1088, 3500, "root"}),
			[]want{{".gpt.partition.2", KindChanged, SeveritySecurity}}},
		{"partition retyped as a second ESP", standardGPT(),
			gptDisk(512, two[0], gptPart{espTypeGUID, 1088, 3000, "root"}),
			[]want{{".gpt.partition.2", KindChanged, SeveritySecurity}}},
		// A partition renamed and nothing else: names are not compared.
		{"partition renamed", standardGPT(),
			gptDisk(512, two[0], gptPart{linuxTypeGUID, 1088, 3000, "renamed"}), nil},
		{"boot sector overwritten", standardGPT(),
			func() []byte { img := standardGPT(); clear(img[64*512 : 65*512]); return img }(),
			[]want{{".gpt.partition.1", KindChanged, SeveritySecurity}}},
		{"disk GUID changed", standardGPT(),
			func() []byte {
				img := standardGPT()
				for _, lba := range []uint64{1, testSectors - 1} {
					img[int(lba)*512+56] ^= 0xFF
					fixHeaderCRC(img, 512, lba)
				}
				return img
			}(),
			[]want{{".gpt.disk_guid", KindChanged, SeveritySecurity}}},
		{"MBR boot code changed",
			mbrDisk("\xeb\x63\x90GRUB \x00Geom", mbrPart{0x80, 0x0c, 2048, 1000}),
			mbrDisk("\xeb\x63\x90GRUB \x00Geom\x90\x90\xcd\x13", mbrPart{0x80, 0x0c, 2048, 1000}),
			[]want{{".mbr.boot_code", KindChanged, SeveritySecurity}}},
		{"MBR boot code appeared on a GPT disk", standardGPT(),
			func() []byte { img := standardGPT(); copy(img, "\xfa\x31\xc0\x8e\xd8"); return img }(),
			[]want{{".mbr.boot_code", KindChanged, SeveritySecurity}}},
		{"MBR partition activated",
			mbrDisk("GRUB ", mbrPart{0x80, 0x0c, 2048, 500}, mbrPart{0, 0x0c, 2548, 500}),
			mbrDisk("GRUB ", mbrPart{0, 0x0c, 2048, 500}, mbrPart{0x80, 0x0c, 2548, 500}),
			[]want{{".mbr.partition.1", KindChanged, SeveritySecurity}, {".mbr.partition.2", KindChanged, SeveritySecurity}}},
		{"MBR disk signature changed",
			func() []byte { img := mbrDisk("GRUB ", mbrPart{0x80, 0x0c, 2048, 500}); img[440] = 1; return img }(),
			func() []byte { img := mbrDisk("GRUB ", mbrPart{0x80, 0x0c, 2048, 500}); img[440] = 2; return img }(),
			[]want{{".mbr.disk_signature", KindChanged, SeveritySecurity}}},
		{"GPT replaced by an MBR table", standardGPT(),
			mbrDisk("", mbrPart{0x80, 0x0c, 64, 1024}),
			[]want{{".partition_table", KindChanged, SeveritySecurity}, {".gpt.disk_guid", KindChanged, SeveritySecurity},
				{".gpt.partition.1", KindRemoved, SeveritySecurity}, {".gpt.partition.2", KindRemoved, SeveritySecurity},
				{".mbr.partition.1", KindAdded, SeveritySecurity}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk.img")
			os.WriteFile(path, row.before, 0o644)
			b := NewBaseline(Run(Options{Disks: []string{path}}))
			os.WriteFile(path, row.after, 0o644)
			wants := append([]want(nil), row.wants...)
			for i := range wants {
				wants[i].item = "disk:" + path + wants[i].item
			}
			expectDiffs(t, compare(t, b, NewBaseline(Run(Options{Disks: []string{path}}))), wants...)
		})
	}
}

func TestCompareFirmwareInventory(t *testing.T) {
	wpbt := func(size uint32) []byte {
		raw := make([]byte, 52)
		copy(raw, "WPBT")
		binary.LittleEndian.PutUint32(raw[36:], size)
		return raw
	}
	const esrt = "firmware/efi/esrt/entries/"
	rows := []struct {
		name   string
		before func(h *host)
		change func(h *host)
		wants  []want
	}{
		{"WPBT table appeared", nil,
			func(h *host) { h.write(h.sys("firmware/acpi/tables/WPBT"), wpbt(4096)) },
			[]want{{"acpi.table.WPBT", KindAdded, SeveritySecurity}}},
		{"WPBT declared size changed",
			func(h *host) { h.write(h.sys("firmware/acpi/tables/WPBT"), wpbt(4096)) },
			func(h *host) { h.write(h.sys("firmware/acpi/tables/WPBT"), wpbt(8192)) },
			[]want{{"acpi.table.WPBT", KindChanged, SeveritySecurity}}},
		{"WPBT table gone",
			func(h *host) { h.write(h.sys("firmware/acpi/tables/WPBT"), wpbt(4096)) },
			func(h *host) { h.remove(h.sys("firmware/acpi/tables/WPBT")) },
			[]want{{"acpi.table.WPBT", KindRemoved, SeverityInfo}}},
		{"another ACPI table appeared", nil,
			func(h *host) { h.write(h.sys("firmware/acpi/tables/SSDT9"), []byte("SSDT")) },
			[]want{{"acpi.table.SSDT9", KindAdded, SeveritySecurity}}},
		{"DMA-remapping table gone", nil,
			func(h *host) { h.remove(h.sys("firmware/acpi/tables/DMAR")) },
			[]want{{"acpi.table.DMAR", KindRemoved, SeveritySecurity}}},
		{"ordinary ACPI table gone", nil,
			func(h *host) { h.remove(h.sys("firmware/acpi/tables/FACP")) },
			[]want{{"acpi.table.FACP", KindRemoved, SeverityInfo}}},

		{"option ROM appeared", nil,
			func(h *host) { h.write(h.sys("bus/pci/devices/0000:00:1f.0/rom"), make([]byte, 512)) },
			[]want{{"pci.rom.0000:00:1f.0", KindAdded, SeveritySecurity}}},
		{"option ROM changed size", nil,
			func(h *host) { h.write(h.sys("bus/pci/devices/0000:01:00.0/rom"), make([]byte, 8192)) },
			[]want{{"pci.rom.0000:01:00.0", KindChanged, SeveritySecurity}}},
		{"another device at the address", nil,
			func(h *host) { h.write(h.sys("bus/pci/devices/0000:01:00.0/device"), []byte("0xbeef\n")) },
			[]want{{"pci.rom.0000:01:00.0", KindChanged, SeveritySecurity}}},
		{"option ROM gone", nil,
			func(h *host) { h.remove(h.sys("bus/pci/devices/0000:01:00.0")) },
			[]want{{"pci.rom.0000:01:00.0", KindRemoved, SeverityInfo}}},

		{"firmware version went up", nil,
			func(h *host) { h.write(h.sys(esrt+"entry0/fw_version"), []byte("65540\n")) },
			[]want{{"esrt." + esrtClass, KindChanged, SeverityExpectedUpdate}}},
		{"firmware version went down", nil,
			func(h *host) { h.write(h.sys(esrt+"entry0/fw_version"), []byte("65538\n")) },
			[]want{{"esrt." + esrtClass, KindChanged, SeveritySecurity}}},
		{"firmware version is not a number", nil,
			func(h *host) { h.write(h.sys(esrt+"entry0/fw_version"), []byte("v2\n")) },
			[]want{{"esrt." + esrtClass, KindChanged, SeveritySecurity}}},
		{"firmware component added", nil,
			func(h *host) {
				h.write(h.sys(esrt+"entry1/fw_class"), []byte("11111111-2222-3333-4444-555555555555\n"))
				h.write(h.sys(esrt+"entry1/fw_version"), []byte("7\n"))
			},
			[]want{{"esrt.11111111-2222-3333-4444-555555555555", KindAdded, SeverityInfo}}},
		{"firmware component gone", nil,
			func(h *host) { h.remove(h.sys(esrt + "entry0")) },
			[]want{{"esrt." + esrtClass, KindRemoved, SeverityInfo}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newHost(t)
			if row.before != nil {
				row.before(h)
			}
			b := h.baseline()
			row.change(h)
			expectDiffs(t, compare(t, b, h.baseline()), row.wants...)
		})
	}
}

// ── what was not read is never "removed" ─────────────────────────────────────

func TestCompareSurfaceNotReadIsNotReverified(t *testing.T) {
	h := newHost(t)
	b := h.baseline()

	// Each surface left out of the run in turn: one not-reverified
	// difference for the surface, nothing removed, exit code untouched.
	for name, tc := range map[string]struct {
		opts  func(o *Options)
		wants []want
	}{
		"no disk named":     {func(o *Options) { o.Disks = nil }, []want{{"disk:" + h.disk, KindNotReverified, SeverityInfo}}},
		"disk unreadable":   {func(o *Options) { o.Disks = []string{filepath.Join(h.t.TempDir(), "gone.img")} }, []want{{"disk:" + h.disk, KindNotReverified, SeverityInfo}}},
		"no ESP":            {func(o *Options) { o.ESP = "" }, []want{{"esp", KindNotReverified, SeverityInfo}}},
		"no efivars":        {func(o *Options) { o.EFIVars = "" }, []want{{"efi", KindNotReverified, SeverityInfo}}},
		"efivars not there": {func(o *Options) { o.EFIVars = filepath.Join(h.t.TempDir(), "none") }, []want{{"efi", KindNotReverified, SeverityInfo}}},
		"no sysfs": {func(o *Options) { o.Sysfs = "" }, []want{
			{"acpi", KindNotReverified, SeverityInfo}, {"pci", KindNotReverified, SeverityInfo}, {"esrt", KindNotReverified, SeverityInfo}}},
	} {
		t.Run(name, func(t *testing.T) {
			opts := h.options()
			tc.opts(&opts)
			diffs := compare(t, b, NewBaseline(Run(opts)))
			expectDiffs(t, diffs, tc.wants...)
			for _, d := range diffs {
				if d.Kind == KindRemoved {
					t.Errorf("an unread surface was reported as removed: %+v", d)
				}
			}
		})
	}

	// And the reverse: a surface read now that the baseline did not cover
	// is not a list of additions.
	opts := h.options()
	opts.ESP, opts.Disks = "", nil
	partial := NewBaseline(Run(opts))
	expectDiffs(t, compare(t, partial, b),
		want{"esp", KindNotInBaseline, SeverityInfo}, want{"disk:" + h.disk, KindNotInBaseline, SeverityInfo})
}

func TestCompareUnreadableItems(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	lock := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(path, 0o755) })
	}

	t.Run("ESP closed to this user", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, h.esp)
		expectDiffs(t, compare(t, b, h.baseline()), want{"esp", KindNotReverified, SeverityInfo})
	})
	t.Run("part of the ESP closed", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, h.espFile("EFI/BOOT"))
		expectDiffs(t, compare(t, b, h.baseline()), want{"esp:EFI/BOOT/BOOTX64.EFI", KindNotReverified, SeverityInfo})
	})
	t.Run("one EFI binary unreadable", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, h.espFile("EFI/debian/shimx64.efi"))
		expectDiffs(t, compare(t, b, h.baseline()), want{"esp:EFI/debian/shimx64.efi", KindNotReverified, SeverityInfo})
	})
	t.Run("variables unreadable", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		for _, name := range []string{"SecureBoot-" + guidGlobal, "dbx-" + guidSecurity, "Boot0001-" + guidGlobal, "PK-" + guidGlobal, "SbatLevelRT-" + guidShim} {
			lock(t, filepath.Join(h.vars, name))
		}
		cur := h.baseline()
		expectDiffs(t, compare(t, b, cur),
			want{"efi.secure_boot", KindNotReverified, SeverityInfo}, want{"efi.dbx", KindNotReverified, SeverityInfo},
			want{"efi.boot.0001", KindNotReverified, SeverityInfo}, want{"efi.pk", KindNotReverified, SeverityInfo},
			want{"efi.sbat", KindNotReverified, SeverityInfo})
		// Read the other way round, the same items are not in the baseline.
		expectDiffs(t, compare(t, cur, b),
			want{"efi.secure_boot", KindNotInBaseline, SeverityInfo}, want{"efi.dbx", KindNotInBaseline, SeverityInfo},
			want{"efi.boot.0001", KindNotInBaseline, SeverityInfo}, want{"efi.pk", KindNotInBaseline, SeverityInfo},
			want{"efi.sbat", KindNotInBaseline, SeverityInfo})
	})
	t.Run("boot order unreadable hides nothing else", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, filepath.Join(h.vars, "BootOrder-"+guidGlobal))
		h.setVar("Boot0005", guidGlobal, loadOption(true, "new", `\EFI\x.efi`))
		expectDiffs(t, compare(t, b, h.baseline()),
			want{"efi.boot_order", KindNotReverified, SeverityInfo}, want{"efi.boot.0005", KindAdded, SeveritySecurity})
	})
	t.Run("firmware resource table is root only", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, h.sys("firmware/efi/esrt/entries/entry0/fw_class"))
		cur := h.baseline()
		if cur.Firmware.ESRTRead || len(cur.Firmware.ESRT) != 0 {
			t.Fatalf("an unreadable ESRT entry leaves the table unread: %+v", cur.Firmware)
		}
		expectDiffs(t, compare(t, b, cur), want{"esrt", KindNotReverified, SeverityInfo})
		expectDiffs(t, compare(t, cur, b), want{"esrt", KindNotInBaseline, SeverityInfo})
	})
	t.Run("option ROM ids and a firmware version unreadable", func(t *testing.T) {
		h := newHost(t)
		b := h.baseline()
		lock(t, h.sys("bus/pci/devices/0000:01:00.0/vendor"))
		lock(t, h.sys("firmware/efi/esrt/entries/entry0/fw_version"))
		cur := h.baseline()
		// Unknown is not a different device and not a version that is "not a number".
		expectDiffs(t, compare(t, b, cur),
			want{"pci.rom.0000:01:00.0", KindNotReverified, SeverityInfo}, want{"esrt." + esrtClass, KindNotReverified, SeverityInfo})
		expectDiffs(t, compare(t, cur, b), want{"esrt." + esrtClass, KindNotInBaseline, SeverityInfo})
	})
	t.Run("WPBT content needs root", func(t *testing.T) {
		h := newHost(t)
		raw := make([]byte, 52)
		binary.LittleEndian.PutUint32(raw[36:], 4096)
		h.write(h.sys("firmware/acpi/tables/WPBT"), raw)
		b := h.baseline()
		lock(t, h.sys("firmware/acpi/tables/WPBT"))
		expectDiffs(t, compare(t, b, h.baseline()), want{"acpi.table.WPBT", KindNotReverified, SeverityInfo})
	})
}

// A partial list on either side turns "added" and "removed" into the two
// kinds that claim nothing.
func TestComparePartialLists(t *testing.T) {
	entry := func(id string) BaselineBootEntry {
		return BaselineBootEntry{ID: id, Active: true, FilePath: "/EFI/a.efi", SHA256: strings.Repeat("a", 64), TargetSHA256: strings.Repeat("b", 64)}
	}
	efi := func(complete bool, ids ...string) *Baseline {
		e := &BaselineEFI{SecureBoot: StateUnknown, SetupMode: StateUnknown, BootOrderState: StateUnknown, BootEntriesComplete: complete,
			PK: BaselineVar{State: StateUnknown}, KEK: BaselineVar{State: StateUnknown}, DB: BaselineVar{State: StateUnknown},
			DBX: BaselineVar{State: StateUnknown}, MOK: BaselineVar{State: StateUnknown}, SBAT: BaselineSBAT{State: StateUnknown}}
		for _, id := range ids {
			e.BootEntries = append(e.BootEntries, entry(id))
		}
		return &Baseline{Schema: BaselineSchema, EFI: e}
	}
	expectDiffs(t, compare(t, efi(true, "0001", "0002"), efi(false, "0001")), want{"efi.boot.0002", KindNotReverified, SeverityInfo})
	expectDiffs(t, compare(t, efi(false, "0001"), efi(true, "0001", "0002")), want{"efi.boot.0002", KindNotInBaseline, SeverityInfo})
	expectDiffs(t, compare(t, efi(true, "0001", "0002"), efi(true, "0001")), want{"efi.boot.0002", KindRemoved, SeverityInfo})
	expectDiffs(t, compare(t, efi(true, "0001"), efi(true, "0001", "0002")), want{"efi.boot.0002", KindAdded, SeveritySecurity})

	esp := func(complete bool, paths ...string) *Baseline {
		e := &BaselineESP{Complete: complete}
		for _, p := range paths {
			e.Binaries = append(e.Binaries, BaselineBinary{Path: p, Size: 10, SHA256: strings.Repeat("c", 64)})
		}
		return &Baseline{Schema: BaselineSchema, ESP: e}
	}
	expectDiffs(t, compare(t, esp(false, "a.efi"), esp(true, "a.efi", "b.efi")), want{"esp:b.efi", KindNotInBaseline, SeverityInfo})
	expectDiffs(t, compare(t, esp(true, "a.efi", "b.efi"), esp(false, "a.efi")), want{"esp:b.efi", KindNotReverified, SeverityInfo})

	// A file too large to hash: the size is all there is to compare.
	big := func(size int64) *Baseline {
		return &Baseline{Schema: BaselineSchema, ESP: &BaselineESP{Complete: true, Binaries: []BaselineBinary{{Path: "uki.efi", Size: size}}}}
	}
	expectDiffs(t, compare(t, big(300<<20), big(301<<20)), want{"esp:uki.efi", KindChanged, SeveritySecurity})
	expectDiffs(t, compare(t, big(300<<20), big(300<<20)), want{"esp:uki.efi", KindNotReverified, SeverityInfo})
}

func TestCompareRefusesWhatItCannotCompare(t *testing.T) {
	b := &Baseline{Schema: BaselineSchema}
	if _, err := Compare(nil, b); err == nil {
		t.Error("a nil baseline must be refused")
	}
	if _, err := Compare(b, nil); err == nil {
		t.Error("a nil scan must be refused")
	}
	if _, err := Compare(&Baseline{Schema: BaselineSchema + 1}, b); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("another schema must be refused: %v", err)
	}
	// The most serious differences come first.
	h := newHost(t)
	base := h.baseline()
	h.setVar("dbx", guidSecurity, append(sigList(0xAA, 0xBB, 0xCC), certList(100)...)) // expected-update
	h.remove(h.espFile("EFI/debian/grubx64.efi"))                                      // info
	h.setVar("SecureBoot", guidGlobal, []byte{0})                                      // security
	opts := h.options()
	opts.Disks = nil // not-reverified
	diffs := compare(t, base, NewBaseline(Run(opts)))
	var order []string
	for _, d := range diffs {
		order = append(order, string(d.Severity)+"/"+string(d.Kind))
	}
	if got := strings.Join(order, " "); got != "security/changed expected-update/changed info/removed info/not-reverified" {
		t.Errorf("order: %s", got)
	}
}

// ── encoding, bounds and the signature ───────────────────────────────────────

func TestBaselineRoundTrip(t *testing.T) {
	h := newHost(t)
	h.write(h.sys("firmware/acpi/tables/WPBT"), make([]byte, 52))
	b := h.baseline()
	b.CreatedAt = "2026-11-06T12:00:00Z"
	data, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("}\n")) || len(data) > 64<<10 {
		t.Errorf("encoding: %d bytes", len(data))
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.SigningBytes(), back.SigningBytes()) {
		t.Errorf("the round trip changed the baseline:\n%s\n---\n%s", b.SigningBytes(), back.SigningBytes())
	}
	expectDiffs(t, compare(t, b, back))

	// What is deliberately not in a baseline.
	for _, absent := range []string{"boot_current", "modified", "variables", "findings", "score", "notes", "last_attempt", h.esp, h.vars, "EFI System Partition\""} {
		if strings.Contains(string(data), absent) {
			t.Errorf("the baseline should not hold %q", absent)
		}
	}
	rec, missing := b.Covers()
	if len(rec) != 6 || len(missing) != 0 {
		t.Errorf("covers %v, missing %v", rec, missing)
	}
	rec, missing = NewBaseline(Run(Options{EFIVars: h.vars})).Covers()
	if len(rec) != 1 || len(missing) != 5 {
		t.Errorf("covers %v, missing %v", rec, missing)
	}
}

// Hostile names survive the round trip unchanged on both sides, so they
// never create a difference and never break a signature.
func TestBaselineStringsAreCleanedOnce(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "EFI", "x\xff\xfey")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Skipf("filesystem refuses the name: %v", err)
	}
	os.WriteFile(filepath.Join(bad, "a.efi"), pe(10, true, true), 0o644)
	b := NewBaseline(Run(Options{ESP: root}))
	data, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.SigningBytes(), back.SigningBytes()) {
		t.Error("invalid UTF-8 in a path changed across the round trip")
	}
	expectDiffs(t, compare(t, back, NewBaseline(Run(Options{ESP: root}))))

	if got := cleanString(strings.Repeat("é", 10), 5); got != "éé" {
		t.Errorf("truncation must not split a rune: %q", got)
	}
}

// Every field of a baseline is covered by the signing bytes: changing any
// one of them changes what is signed.
func TestSigningBytesCoverEveryField(t *testing.T) {
	h := newHost(t)
	raw := make([]byte, 52)
	binary.LittleEndian.PutUint32(raw[36:], 4096)
	h.write(h.sys("firmware/acpi/tables/WPBT"), raw)
	img := mbrDisk("GRUB ", mbrPart{0x80, 0x0c, 2048, 500})
	img[440] = 9
	mbr := filepath.Join(t.TempDir(), "mbr.img")
	h.write(mbr, img)
	opts := h.options()
	opts.Disks = append(opts.Disks, mbr)
	b := NewBaseline(Run(opts))
	b.CreatedAt = "2026-11-06T12:00:00Z"
	// Fields the fixture leaves at their zero value are set, so that every
	// one of them is present in the JSON to be mutated.
	b.EFI.BootEntries = append(b.EFI.BootEntries, BaselineBootEntry{ID: "0009", Unread: true})
	b.EFI.DBX.Other, b.EFI.DBX.Unparsed = 1, true
	b.EFI.SBAT.Unparsed = true
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var tree interface{}
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	original := string(b.SigningBytes())

	leaves := 0
	var walk func(node interface{}, path string, set func(interface{}))
	check := func(path string) {
		leaves++
		mutated, err := json.Marshal(tree)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var m Baseline
		if err := json.Unmarshal(mutated, &m); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(m.SigningBytes()) == original {
			t.Errorf("changing %s does not change the signing bytes: the field is not signed", path)
		}
	}
	walk = func(node interface{}, path string, set func(interface{})) {
		switch v := node.(type) {
		case map[string]interface{}:
			for k, child := range v {
				k := k
				walk(child, path+"."+k, func(x interface{}) { v[k] = x })
			}
		case []interface{}:
			for i, child := range v {
				i := i
				walk(child, fmt.Sprintf("%s[%d]", path, i), func(x interface{}) { v[i] = x })
			}
		case string:
			set(v + "x")
			check(path)
			set(v)
		case float64:
			set(v + 1)
			check(path)
			set(v)
		case bool:
			set(!v)
			check(path)
			set(v)
		}
	}
	// The signature is the one field the signing bytes must not cover.
	delete(tree.(map[string]interface{}), "signature")
	walk(tree, "baseline", func(interface{}) {})
	if leaves < 100 {
		t.Fatalf("only %d fields were checked; the walk is not seeing the baseline", leaves)
	}

	// Every field the types declare is in that JSON, so none escaped the walk.
	for _, field := range []string{`"unread"`, `"other_entries"`, `"unparsed"`, `"active"`, `"esp"`, `"size_known"`, `"handoff_size"`,
		`"disk_signature"`, `"disk_guid"`, `"boot_code_sha256"`, `"date"`, `"target_sha256"`, `"complete"`, `"created_at"`} {
		if !strings.Contains(string(data), field) {
			t.Errorf("the fixture does not exercise %s", field)
		}
	}

	// A signature made over these bytes verifies after a round trip through
	// the file format, and not after any edit.
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(priv, b.SigningBytes())
	file, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, back.SigningBytes(), sig) {
		t.Error("the signature does not survive the file format")
	}
	back.EFI.BootEntries[0].FilePath = "/EFI/evil/shimx64.efi"
	if ed25519.Verify(pub, back.SigningBytes(), sig) {
		t.Error("an edited baseline still verifies")
	}
}

// Two different baselines never share signing bytes because of how fields
// are joined: a quote or a newline inside a string stays inside it.
func TestSigningBytesAreUnambiguous(t *testing.T) {
	a := &Baseline{Schema: BaselineSchema, ESP: &BaselineESP{Complete: true, Binaries: []BaselineBinary{
		{Path: "a.efi", Subsystem: "x"}, {Path: "b.efi", Subsystem: "y"}}}}
	b := &Baseline{Schema: BaselineSchema, ESP: &BaselineESP{Complete: true, Binaries: []BaselineBinary{
		{Path: "a.efi", Subsystem: "x\"\nbinary \"b.efi\" 0 \"\" false \"y"}}}}
	if bytes.Equal(a.SigningBytes(), b.SigningBytes()) {
		t.Error("a crafted string reproduces another baseline's signing bytes")
	}
	if n := bytes.Count(b.SigningBytes(), []byte("\n")); n != 7 {
		t.Errorf("a newline inside a field must not start a record: %d lines\n%s", n, b.SigningBytes())
	}
	if !bytes.HasPrefix(a.SigningBytes(), []byte("cau-boot-baseline/v1\n")) {
		t.Errorf("the signing bytes must begin with the format and its version: %q", a.SigningBytes()[:24])
	}
}

func TestParseRejectsWhatIsNotABaseline(t *testing.T) {
	h := newHost(t)
	good, err := Marshal(h.baseline())
	if err != nil {
		t.Fatal(err)
	}
	edit := func(old, new string) []byte {
		if !strings.Contains(string(good), old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return []byte(strings.Replace(string(good), old, new, 1))
	}
	digest := NewBaseline(Run(h.options())).EFI.DBX.SHA256
	cases := map[string][]byte{
		"empty":                  nil,
		"not JSON":               []byte("EFI PART"),
		"JSON null":              []byte("null"),
		"an array":               []byte("[]"),
		"no schema":              []byte(`{"efi":null}`),
		"future schema":          edit(`"schema": 1`, `"schema": 2`),
		"no surface":             []byte(`{"schema":1}`),
		"unknown field":          edit(`"schema": 1`, `"schema": 1, "trusted": true`),
		"trailing data":          append(append([]byte(nil), good...), "{}"...),
		"unknown secure boot":    edit(`"secure_boot": "enabled"`, `"secure_boot": "probably"`),
		"unknown variable state": edit(`"state": "present"`, `"state": "there"`),
		"digest not hex":         edit(digest, strings.Repeat("z", 64)),
		"digest too short":       edit(digest, "abcd"),
		"duplicate boot entry":   edit(`"id": "0003"`, `"id": "0001"`),
		"duplicate binary":       edit(`"path": "EFI/debian/grubx64.efi"`, `"path": "EFI/BOOT/BOOTX64.EFI"`),
		"duplicate ACPI table":   edit(`"DSDT"`, `"DMAR"`),
		"partition index zero":   edit(`"index": 1`, `"index": 0`),
		"unknown partition scheme": edit(`"scheme": "gpt",
          "type"`, `"scheme": "zfs",
          "type"`),
		"order without state": edit(`"boot_order_state": "present"`, `"boot_order_state": "absent"`),
		"negative size":       edit(`"size": 8192`, `"size": -1`),
		"overlong string":     edit(`"description": "debian"`, `"description": "`+strings.Repeat("A", maxBaselineLabel+1)+`"`),
		"overlong signature":  edit(`"schema": 1`, `"schema": 1, "signature": "`+strings.Repeat("0", 200)+`"`),
		"wpbt without table":  edit(`"pci_read": true`, `"pci_read": true, "wpbt": {"size_known": false}`),
		"too many boot ids":   edit(`"boot_order": [`, `"boot_order": [`+strings.Repeat(`"0001",`, maxBootEntries)),
		"over the size bound": append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), MaxBaselineBytes)...),
	}
	for name, data := range cases {
		if b, err := Parse(data); err == nil {
			t.Errorf("%s: accepted: %+v", name, b)
		} else if !strings.HasPrefix(err.Error(), "bootscan: ") || len(err.Error()) > 400 {
			t.Errorf("%s: error %q", name, err)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("the unedited baseline must parse: %v", err)
	}
	if _, err := Marshal(nil); err == nil {
		t.Error("Marshal(nil) must fail")
	}
	if _, err := Marshal(&Baseline{Schema: BaselineSchema}); err == nil {
		t.Error("a baseline with no surface must not be written")
	}
}

func TestSBATLevelParsing(t *testing.T) {
	info := parseSBATLevel([]byte("sbat,1,2024010900\nshim,4\ngrub.debian,5\n\x00"))
	if info.Unparsed || len(info.Entries) != 3 || info.Entries[0] != (SBATEntry{"sbat", 1, "2024010900"}) || info.Entries[2] != (SBATEntry{"grub.debian", 5, ""}) || len(info.SHA256) != 64 {
		t.Errorf("%+v", info)
	}
	for _, bad := range []string{"sbat", "sbat,x", ",1", "a,1\na,2", "a,1,2,3", "a b,1", "a,-1", strings.Repeat("a", 300) + ",1",
		strings.Repeat("c,1\n", 1) + strings.Repeat("d,1\n", 2), "a,1,\x1b[2J"} {
		if got := parseSBATLevel([]byte(bad)); !got.Unparsed || got.Entries != nil {
			t.Errorf("%q should not parse: %+v", bad, got)
		}
	}
	var many strings.Builder
	for i := 0; i <= maxSBATEntries; i++ {
		fmt.Fprintf(&many, "c%d,1\n", i)
	}
	if got := parseSBATLevel([]byte(many.String())); !got.Unparsed {
		t.Errorf("more than %d components must not parse", maxSBATEntries)
	}
	if got := parseSBATLevel(nil); got.Unparsed || len(got.Entries) != 0 {
		t.Errorf("an empty level is empty, not malformed: %+v", got)
	}
}

// The report carries the digests the baseline is built from.
func TestEFIReportDigests(t *testing.T) {
	h := newHost(t)
	rep, _, _ := ScanEFIVars(h.vars, "")
	for name, db := range map[string]*SignatureDB{"PK": rep.PK, "KEK": rep.KEK, "db": rep.DB, "dbx": rep.DBX, "MOK": rep.MOK} {
		if db == nil || len(db.SHA256) != 64 || db.Bytes == 0 || db.Unparsed {
			t.Errorf("%s: %+v", name, db)
		}
	}
	if rep.DBX.SHA256 == rep.DB.SHA256 || rep.DBX.Bytes != len(sigList(0xAA, 0xBB))+len(certList(100)) {
		t.Errorf("dbx digest/size: %+v", rep.DBX)
	}
	e := rep.BootEntries[0]
	if len(e.SHA256) != 64 || len(e.TargetSHA256) != 64 || e.SHA256 == e.TargetSHA256 {
		t.Errorf("boot entry digests: %+v", e)
	}
	// The target digest ignores the label and the active bit, nothing else.
	base := parseLoadOption(loadOption(true, "debian", `\EFI\debian\shimx64.efi`)).TargetSHA256
	for name, opt := range map[string][]byte{
		"relabelled": loadOption(true, "Debian", `\EFI\debian\shimx64.efi`),
		"inactive":   loadOption(false, "debian", `\EFI\debian\shimx64.efi`),
	} {
		if got := parseLoadOption(opt).TargetSHA256; got != base {
			t.Errorf("%s: the target digest changed", name)
		}
	}
	hidden := loadOption(true, "debian", `\EFI\debian\shimx64.efi`)
	hidden[0] |= 8 // LOAD_OPTION_HIDDEN
	for name, opt := range map[string][]byte{
		"other file":      loadOption(true, "debian", `\EFI\debian\grubx64.efi`),
		"other partition": loadOptionWith(true, "debian", `\EFI\debian\shimx64.efi`, 1, ""),
		"arguments":       loadOptionWith(true, "debian", `\EFI\debian\shimx64.efi`, 0, "x"),
		"attribute bit":   hidden,
	} {
		if got := parseLoadOption(opt).TargetSHA256; got == base || got == "" {
			t.Errorf("%s: the target digest did not change", name)
		}
	}
	if parseLoadOption([]byte{1, 0, 0, 0, 8, 0, 'a', 0}).TargetSHA256 != "" {
		t.Error("a malformed load option has no target digest")
	}

	// A malformed dbx is present, digested and said to be malformed.
	h.setVar("dbx", guidSecurity, []byte{1, 2, 3})
	rep, fs, notes := ScanEFIVars(h.vars, "")
	if rep.DBX == nil || !rep.DBX.Unparsed || rep.DBX.Bytes != 3 || len(rep.DBX.SHA256) != 64 || !hasClass(fs, "efi.dbx-empty") ||
		!strings.Contains(strings.Join(notes, " "), "not a well-formed") {
		t.Errorf("malformed dbx: %+v %v %v", rep.DBX, classes(fs), notes)
	}
}

// ── fuzzing the decoder ──────────────────────────────────────────────────────

func fuzzSeedBaseline() *Baseline {
	sum := strings.Repeat("ab", 32)
	return &Baseline{Schema: BaselineSchema, CreatedAt: "2026-11-06T12:00:00Z",
		EFI: &BaselineEFI{SecureBoot: stateEnabled, SetupMode: stateOff, BootOrderState: StatePresent, BootOrder: []string{"0001", "0003"},
			BootEntriesComplete: true,
			BootEntries: []BaselineBootEntry{{ID: "0001", Description: "debian", FilePath: "/EFI/debian/shimx64.efi", Active: true, SHA256: sum, TargetSHA256: sum},
				{ID: "0003", Unread: true}},
			PK: BaselineVar{State: StatePresent, SHA256: sum, Bytes: 900, Certificates: 1}, KEK: BaselineVar{State: StateAbsent},
			DB: BaselineVar{State: StateUnknown}, DBX: BaselineVar{State: StatePresent, SHA256: sum, Bytes: 100, Hashes: 2},
			MOK:  BaselineVar{State: StateAbsent},
			SBAT: BaselineSBAT{State: StatePresent, SHA256: sum, Entries: []SBATEntry{{"sbat", 1, "2024010900"}, {"shim", 4, ""}}}},
		ESP: &BaselineESP{Complete: true, Binaries: []BaselineBinary{{Path: "EFI/debian/shimx64.efi", Size: 512, SHA256: sum, Signed: true, Subsystem: "EFI application"}}},
		Disks: []BaselineDisk{{Path: "/dev/sda", Scheme: "gpt", DiskGUID: "11111111-2222-3333-4444-555555555555",
			Partitions: []BaselinePartition{{Index: 1, Scheme: "gpt", Type: gptESPType, StartLBA: 64, Sectors: 1024, ESP: true, BootSector: "fat"}}}},
		Firmware: &BaselineFirmware{ACPIRead: true, ACPITables: []string{"DSDT", "WPBT"}, WPBT: &BaselineWPBT{SizeKnown: true, HandoffSize: 4096},
			PCIRead: true, OptionROMs: []BaselineROM{{Address: "0000:01:00.0", Vendor: "0x10de", Device: "0x1c82", Size: 4096}},
			ESRTRead: true, ESRT: []BaselineESRT{{Class: esrtClass, Version: "65539"}}},
	}
}

// FuzzParseBaseline: the baseline is a file an attacker may have written.
// Parse never panics and never accepts more than the bound; whatever it
// accepts can be compared, signed and written back without a panic, equals
// itself, and survives its own round trip.
func FuzzParseBaseline(f *testing.F) {
	seed := fuzzSeedBaseline()
	data, err := Marshal(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"schema":1,"esp":{"complete":false}}`))
	f.Add([]byte(`{"schema":1,"disks":[{"path":"d","scheme":"none"}]}`))
	f.Add([]byte(`{"schema":1,"firmware":{"acpi_read":true,"pci_read":false,"esrt_read":true,"esrt":[{"fw_class":"a","fw_version":"x"}]}}`))
	f.Add([]byte(`{"schema":1,"efi":{"secure_boot":"unknown","setup_mode":"unknown","boot_order_state":"absent","boot_entries_complete":false,` +
		`"pk":{"state":"unknown"},"kek":{"state":"unknown"},"db":{"state":"unknown"},"dbx":{"state":"unknown"},"mok":{"state":"unknown"},"sbat":{"state":"unknown"}}}`))
	f.Add([]byte(`{"schema":1,"signature":"00"}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := Parse(data)
		if err != nil {
			if b != nil {
				t.Fatal("a refused baseline was returned anyway")
			}
			return
		}
		if len(data) > MaxBaselineBytes {
			t.Fatalf("accepted %d bytes, over the bound", len(data))
		}
		if b.EFI != nil && (len(b.EFI.BootEntries) > maxBootEntries || len(b.EFI.BootOrder) > maxBootEntries || len(b.EFI.SBAT.Entries) > maxSBATEntries) {
			t.Fatal("firmware-variable lists exceed their bounds")
		}
		if (b.ESP != nil && len(b.ESP.Binaries) > maxESPFiles) || len(b.Disks) > maxBaselineDisks {
			t.Fatal("ESP or disk lists exceed their bounds")
		}
		signing := b.SigningBytes()
		if len(signing) == 0 {
			t.Fatal("empty signing bytes")
		}
		for _, pair := range [][2]*Baseline{{b, b}, {b, seed}, {seed, b}} {
			diffs, err := Compare(pair[0], pair[1])
			if err != nil {
				t.Fatalf("an accepted baseline cannot be compared: %v", err)
			}
			if pair[0] == pair[1] && len(diffs) != 0 {
				t.Fatalf("a baseline differs from itself: %+v", diffs)
			}
			for _, d := range diffs {
				if d.Kind == "" || d.Severity == "" || d.Item == "" || d.Surface == "" || d.Detail == "" {
					t.Fatalf("incomplete difference: %+v", d)
				}
				if (d.Kind == KindNotReverified || d.Kind == KindNotInBaseline) && d.Severity != SeverityInfo {
					t.Fatalf("something that was not compared carries a verdict: %+v", d)
				}
			}
		}
		b.Covers()
		out, err := Marshal(b)
		if err != nil {
			t.Fatalf("an accepted baseline cannot be written back: %v", err)
		}
		back, err := Parse(out)
		if err != nil {
			t.Fatalf("the written form is refused: %v", err)
		}
		if !bytes.Equal(back.SigningBytes(), signing) || back.Signature != b.Signature {
			t.Fatal("the round trip changed the baseline")
		}
	})
}

package bootscan

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── synthetic firmware variables ─────────────────────────────────────────────

func writeVar(t *testing.T, dir, name, guid string, data []byte) {
	t.Helper()
	raw := append([]byte{0x07, 0, 0, 0}, data...) // attributes, then data
	if err := os.WriteFile(filepath.Join(dir, name+"-"+guid), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// loadOption builds an EFI_LOAD_OPTION with one hard-drive node and one
// file-path node.
func loadOption(active bool, desc, file string) []byte {
	hd := make([]byte, 42) // media / hard drive
	hd[0], hd[1] = 0x04, 0x01
	binary.LittleEndian.PutUint16(hd[2:], 42)
	fp := append(utf16le(file), 0, 0)
	node := make([]byte, 4, 4+len(fp))
	node[0], node[1] = 0x04, 0x04
	binary.LittleEndian.PutUint16(node[2:], uint16(4+len(fp)))
	node = append(node, fp...)
	end := []byte{0x7f, 0xff, 4, 0}
	path := append(append(hd, node...), end...)

	out := make([]byte, 6)
	if active {
		out[0] = 1
	}
	binary.LittleEndian.PutUint16(out[4:], uint16(len(path)))
	out = append(out, append(utf16le(desc), 0, 0)...)
	return append(out, path...)
}

var (
	sha256ListGUID = guidBytes(0xc1c41626, 0x504c, 0x4092, [8]byte{0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28})
	x509ListGUID   = guidBytes(0xa5c059a1, 0x94e4, 0x4aa7, [8]byte{0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72})
)

// sigList builds one EFI_SIGNATURE_LIST of SHA-256 entries.
func sigList(hashes ...byte) []byte {
	body := []byte{}
	for _, h := range hashes {
		entry := make([]byte, 48) // 16-byte owner GUID + 32-byte digest
		for i := 16; i < 48; i++ {
			entry[i] = h
		}
		body = append(body, entry...)
	}
	out := make([]byte, 28)
	copy(out, sha256ListGUID)
	binary.LittleEndian.PutUint32(out[16:], uint32(28+len(body)))
	binary.LittleEndian.PutUint32(out[24:], 48)
	return append(out, body...)
}

func certList(certLen int) []byte {
	out := make([]byte, 28)
	copy(out, x509ListGUID)
	binary.LittleEndian.PutUint32(out[16:], uint32(28+16+certLen))
	binary.LittleEndian.PutUint32(out[24:], uint32(16+certLen))
	return append(out, make([]byte, 16+certLen)...)
}

func efivars(t *testing.T, secureBoot, setupMode bool, dbx []byte) string {
	t.Helper()
	dir := t.TempDir()
	b := func(v bool) []byte {
		if v {
			return []byte{1}
		}
		return []byte{0}
	}
	writeVar(t, dir, "SecureBoot", guidGlobal, b(secureBoot))
	writeVar(t, dir, "SetupMode", guidGlobal, b(setupMode))
	writeVar(t, dir, "PK", guidGlobal, certList(64))
	writeVar(t, dir, "BootCurrent", guidGlobal, []byte{1, 0})
	writeVar(t, dir, "BootOrder", guidGlobal, []byte{1, 0, 3, 0})
	writeVar(t, dir, "Boot0001", guidGlobal, loadOption(true, "debian", `\EFI\debian\shimx64.efi`))
	writeVar(t, dir, "Boot0003", guidGlobal, loadOption(false, "Old Entry", `\EFI\gone\loader.efi`))
	writeVar(t, dir, "db", guidSecurity, certList(900))
	if dbx != nil {
		writeVar(t, dir, "dbx", guidSecurity, dbx)
	}
	writeVar(t, dir, "SbatLevelRT", guidShim, []byte("sbat,1,2024010900\nshim,4\n"))
	return dir
}

func TestEFIVarsInventory(t *testing.T) {
	dir := efivars(t, true, false, append(sigList(0xAA, 0xBB), certList(100)...))
	rep, fs, notes := ScanEFIVars(dir, "")
	if rep == nil || len(notes) != 0 {
		t.Fatalf("report %+v notes %v", rep, notes)
	}
	if rep.SecureBoot == nil || !*rep.SecureBoot || rep.SetupMode == nil || *rep.SetupMode || !rep.PlatformKey {
		t.Errorf("secure boot state: %+v", rep)
	}
	if rep.BootCurrent != "0001" || strings.Join(rep.BootOrder, ",") != "0001,0003" || len(rep.BootEntries) != 2 {
		t.Fatalf("boot: current %q order %v entries %+v", rep.BootCurrent, rep.BootOrder, rep.BootEntries)
	}
	e := rep.BootEntries[0]
	if e.ID != "0001" || e.Description != "debian" || e.FilePath != "/EFI/debian/shimx64.efi" || !e.Active || !e.InOrder {
		t.Errorf("boot entry: %+v", e)
	}
	if rep.BootEntries[1].Active {
		t.Errorf("Boot0003 is inactive: %+v", rep.BootEntries[1])
	}
	if rep.DBX == nil || rep.DBX.Hashes != 2 || rep.DBX.Certificates != 1 || rep.DB == nil || rep.DB.Certificates != 1 {
		t.Errorf("signature databases: dbx %+v db %+v", rep.DBX, rep.DB)
	}
	if rep.SBATLevel != "sbat,1,2024010900; shim,4" {
		t.Errorf("sbat level %q", rep.SBATLevel)
	}
	if len(fs) != 0 {
		t.Errorf("a healthy Secure Boot host produced findings: %v", classes(fs))
	}
}

func TestEFIPostureFindings(t *testing.T) {
	// Setup mode: scored. Secure Boot off: reported, never scored.
	_, fs, _ := ScanEFIVars(efivars(t, false, true, sigList(1)), "")
	if !hasClass(fs, "efi.setup-mode") || !hasClass(fs, "efi.secure-boot-disabled") {
		t.Fatalf("got %v", classes(fs))
	}
	for _, f := range fs {
		if f.Class == "efi.secure-boot-disabled" && f.Score != 0 {
			t.Errorf("Secure Boot being off is posture and must not score: %+v", f)
		}
	}
	// Secure Boot on with no revocations at all.
	_, fs, _ = ScanEFIVars(efivars(t, true, false, nil), "")
	if !hasClass(fs, "efi.dbx-empty") {
		t.Errorf("want efi.dbx-empty, got %v", classes(fs))
	}
	// Secure Boot off: an empty dbx is not a finding, the state already says it.
	if _, fs, _ = ScanEFIVars(efivars(t, false, false, nil), ""); hasClass(fs, "efi.dbx-empty") {
		t.Errorf("dbx-empty only means something with Secure Boot on: %v", classes(fs))
	}
}

func TestEFIUnknownIsNotOff(t *testing.T) {
	dir := t.TempDir()
	writeVar(t, dir, "BootOrder", guidGlobal, []byte{7, 0})
	rep, fs, notes := ScanEFIVars(dir, "")
	if rep.SecureBoot != nil || hasClass(fs, "efi.secure-boot-disabled") {
		t.Errorf("an absent SecureBoot variable is unknown, not disabled: %+v %v", rep, classes(fs))
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "unknown") {
		t.Errorf("the unknown state must be noted: %v", notes)
	}
	if !hasClass(fs, "efi.bootorder-dangling") {
		t.Errorf("BootOrder names Boot0007, which does not exist: %v", classes(fs))
	}
}

func TestEFIVarsAbsent(t *testing.T) {
	rep, fs, notes := ScanEFIVars(filepath.Join(t.TempDir(), "nope"), "")
	if rep != nil || len(fs) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "UEFI") {
		t.Errorf("absent efivarfs: %+v %v %v", rep, fs, notes)
	}
}

func TestDBXReferenceComparison(t *testing.T) {
	dir := efivars(t, true, false, sigList(0xAA, 0xBB))
	ref := filepath.Join(t.TempDir(), "dbxupdate.bin")

	// The reference in its signed wrapper: EFI_TIME, WIN_CERTIFICATE, lists.
	auth := make([]byte, 16)
	cert := make([]byte, 40)
	binary.LittleEndian.PutUint32(cert, 40) // dwLength covers the whole certificate
	wrapped := append(append(auth, cert...), sigList(0xAA, 0xBB, 0xCC, 0xDD)...)
	os.WriteFile(ref, wrapped, 0o644)
	rep, fs, notes := ScanEFIVars(dir, ref)
	if rep.DBXReference == nil || rep.DBXReference.ReferenceHashes != 4 || rep.DBXReference.Missing != 2 || len(notes) != 0 {
		t.Fatalf("wrapped reference: %+v notes %v", rep.DBXReference, notes)
	}
	if !hasClass(fs, "efi.dbx-behind-reference") {
		t.Errorf("want efi.dbx-behind-reference, got %v", classes(fs))
	}

	// A bare list the host fully covers.
	os.WriteFile(ref, sigList(0xAA), 0o644)
	rep, fs, _ = ScanEFIVars(dir, ref)
	if rep.DBXReference.Missing != 0 || hasClass(fs, "efi.dbx-behind-reference") {
		t.Errorf("covered reference: %+v %v", rep.DBXReference, classes(fs))
	}

	// Garbage is a note, never a finding and never a silent pass.
	os.WriteFile(ref, []byte("not a signature list"), 0o644)
	rep, fs, notes = ScanEFIVars(dir, ref)
	if rep.DBXReference != nil || hasClass(fs, "efi.dbx-behind-reference") || len(notes) == 0 {
		t.Errorf("unusable reference: %+v %v %v", rep.DBXReference, classes(fs), notes)
	}
}

func TestHostileFirmwareStructures(t *testing.T) {
	// Signature lists with lying sizes.
	for name, mutate := range map[string]func(b []byte){
		"list size past end": func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xFFFFFFFF) },
		"list size tiny":     func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 4) },
		"header size huge":   func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0x7FFFFFFF) },
		"signature size 0":   func(b []byte) { binary.LittleEndian.PutUint32(b[24:], 0) },
		"wrong hash size":    func(b []byte) { binary.LittleEndian.PutUint32(b[24:], 40) },
	} {
		l := sigList(1, 2, 3)
		mutate(l)
		if db := parseSignatureLists(l); db != nil {
			t.Errorf("%s: a malformed list must be rejected, got %+v", name, db)
		}
	}
	if parseSignatureLists([]byte{1, 2, 3}) != nil {
		t.Error("a truncated list must be rejected")
	}
	// Load options: truncated, unterminated description, lying node length.
	for _, data := range [][]byte{nil, {1}, {1, 0, 0, 0, 0xFF, 0xFF}, append([]byte{1, 0, 0, 0, 8, 0}, utf16le("never ends")...),
		append(loadOption(true, "x", `\a`)[:20], 0xFF, 0xFF, 0xFF, 0xFF)} {
		parseLoadOption(data) // must not panic
	}
	opt := loadOption(true, "x", `\EFI\a.efi`)
	binary.LittleEndian.PutUint16(opt[4:], 0xFFFF) // path length beyond the data
	if e := parseLoadOption(opt); e.FilePath != "/EFI/a.efi" {
		t.Errorf("an over-long path length should be clamped to the data: %+v", e)
	}
}

func FuzzFirmwareStructures(f *testing.F) {
	f.Add(sigList(1, 2))
	f.Add(loadOption(true, "debian", `\EFI\debian\shimx64.efi`))
	f.Add(pe(10, true, true))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseSignatureLists(data)
		parseLoadOption(data)
		var bin EFIBinary
		parsePEHeader(bytes.NewReader(data), int64(len(data)), &bin)
	})
}

// ── synthetic ESP ────────────────────────────────────────────────────────────

// pe builds a minimal PE image: a DOS header, a PE header and an optional
// header with the given subsystem, optionally PE32+ and optionally declaring
// a certificate table.
func pe(subsystem uint16, plus, signed bool) []byte {
	b := make([]byte, 0x200)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	opt := 0x80 + 24
	dirs := opt + 96
	magic := uint16(0x10b)
	if plus {
		magic, dirs = 0x20b, opt+112
	}
	binary.LittleEndian.PutUint16(b[0x80+20:], uint16(dirs-opt+16*8))
	binary.LittleEndian.PutUint16(b[opt:], magic)
	binary.LittleEndian.PutUint16(b[opt+68:], subsystem)
	binary.LittleEndian.PutUint32(b[dirs-4:], 16)
	if signed {
		binary.LittleEndian.PutUint32(b[dirs+4*8:], 0x1000)
		binary.LittleEndian.PutUint32(b[dirs+4*8+4:], 0x600)
	}
	return b
}

func writeESP(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	for rel, data := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

func TestESPInventory(t *testing.T) {
	root := writeESP(t, map[string][]byte{
		"EFI/debian/shimx64.efi": pe(10, true, true),
		"EFI/debian/grubx64.efi": pe(10, true, true),
		"EFI/BOOT/BOOTX64.EFI":   pe(10, true, true),
		"EFI/debian/grub.cfg":    []byte("search.fs_uuid 1234 root\n"),
	})
	rep, fs, notes := ScanESP(root, yes())
	if len(fs) != 0 || len(notes) != 0 {
		t.Fatalf("a signed, ordinary ESP: findings %v notes %v", classes(fs), notes)
	}
	if rep.Files != 4 || len(rep.Binaries) != 3 {
		t.Fatalf("inventory: %+v", rep)
	}
	for _, b := range rep.Binaries {
		if !b.PE || !b.EFI || !b.Signed || b.Machine != "x86-64" || b.Subsystem != "EFI application" || len(b.SHA256) != 64 || b.Modified == "" {
			t.Errorf("binary: %+v", b)
		}
	}
}

func TestESPUnsignedDependsOnSecureBoot(t *testing.T) {
	files := map[string][]byte{
		"EFI/systemd/systemd-bootx64.efi": pe(10, true, false),
		"EFI/tools/memtest.efi":           pe(10, false, false), // PE32
		"EFI/debian/shimx64.efi":          pe(10, true, true),
	}
	for name, tc := range map[string]struct {
		sb    *bool
		score int
	}{"enabled": {yes(), scoreUnsignedSB}, "disabled": {no(), 0}, "unknown": {nil, 0}} {
		_, fs, _ := ScanESP(writeESP(t, files), tc.sb)
		if len(fs) != 1 || fs[0].Class != "esp.unsigned-efi-binary" || fs[0].Score != tc.score {
			t.Errorf("secure boot %s: %+v", name, fs)
			continue
		}
		// One finding for the set, naming both files.
		if !strings.Contains(fs[0].Evidence, "systemd-bootx64.efi") || !strings.Contains(fs[0].Evidence, "memtest.efi") || !strings.Contains(fs[0].Detail, "2 EFI binaries") {
			t.Errorf("secure boot %s: evidence %q detail %q", name, fs[0].Evidence, fs[0].Detail)
		}
	}
}

func TestESPAnomalies(t *testing.T) {
	root := writeESP(t, map[string][]byte{
		"EFI/Microsoft/Boot/bootmgfw.efi": pe(10, true, true),
		"EFI/Microsoft/Boot/helper.efi":   pe(3, true, true), // a Windows console program
		"EFI/BOOT/notreally.efi":          []byte("#!/bin/sh\necho hi\n"),
		"system32/payload.bin":            []byte("x"),
		"EFI/UpdateCapsule/fw-1.2.3.cap":  []byte("capsule"),
	})
	rep, fs, _ := ScanESP(root, yes())
	for _, want := range []string{"esp.non-efi-executable", "esp.efi-binary-not-pe", "esp.windows-system-dir", "esp.pending-capsule"} {
		if !hasClass(fs, want) {
			t.Errorf("missing %s in %v", want, classes(fs))
		}
	}
	if len(rep.Capsules) != 1 || rep.Capsules[0] != "EFI/UpdateCapsule/fw-1.2.3.cap" {
		t.Errorf("capsules: %v", rep.Capsules)
	}
	for _, f := range fs {
		if f.Class == "esp.pending-capsule" && f.Score != 0 {
			t.Errorf("a queued capsule is inventory: %+v", f)
		}
	}
	// A nested directory named system32 is not the root one.
	_, fs, _ = ScanESP(writeESP(t, map[string][]byte{"EFI/vendor/system32/readme.txt": []byte("x")}), yes())
	if hasClass(fs, "esp.windows-system-dir") {
		t.Errorf("only a root-level system32 counts: %v", classes(fs))
	}
}

func TestESPDoesNotFollowSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.efi")
	os.WriteFile(outside, []byte("not a PE"), 0o644)
	root := writeESP(t, map[string][]byte{"EFI/BOOT/BOOTX64.EFI": pe(10, true, true)})
	if err := os.Symlink(outside, filepath.Join(root, "EFI", "BOOT", "link.efi")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, "EFI", "linkdir")); err != nil {
		t.Skip(err)
	}
	rep, fs, _ := ScanESP(root, yes())
	if len(rep.Binaries) != 1 || len(fs) != 0 {
		t.Errorf("a symlink must be neither followed nor inventoried: %+v %v", rep.Binaries, classes(fs))
	}
}

func TestESPBadPath(t *testing.T) {
	if rep, _, notes := ScanESP(filepath.Join(t.TempDir(), "missing"), nil); rep != nil || len(notes) != 1 {
		t.Errorf("missing ESP: %+v %v", rep, notes)
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o644)
	if rep, _, notes := ScanESP(file, nil); rep != nil || len(notes) != 1 {
		t.Errorf("ESP given as a file: %+v %v", rep, notes)
	}
}

func TestPEHeaderFarFromStart(t *testing.T) {
	// A PE header at 128 KiB: legal, and beyond any fixed-size prefix read.
	img := make([]byte, 128<<10)
	img[0], img[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(img[0x3c:], uint32(len(img)))
	img = append(img, pe(10, true, true)[0x80:]...)
	var bin EFIBinary
	parsePEHeader(bytes.NewReader(img), int64(len(img)), &bin)
	if !bin.PE || !bin.EFI || !bin.Signed {
		t.Errorf("far header: %+v", bin)
	}
	// A header offset pointing past the file is simply not a PE.
	binary.LittleEndian.PutUint32(img[0x3c:], 0xFFFFFFF0)
	bin = EFIBinary{}
	parsePEHeader(bytes.NewReader(img), int64(len(img)), &bin)
	if bin.PE {
		t.Errorf("out-of-range header offset: %+v", bin)
	}
}

// ── synthetic sysfs ──────────────────────────────────────────────────────────

func TestFirmwareInventory(t *testing.T) {
	wpbt := make([]byte, 52)
	copy(wpbt, "WPBT")
	binary.LittleEndian.PutUint32(wpbt[36:], 123456)
	root := writeESP(t, map[string][]byte{
		"firmware/acpi/tables/DSDT":                             []byte("DSDT"),
		"firmware/acpi/tables/WPBT":                             wpbt,
		"bus/pci/devices/0000:01:00.0/rom":                      nil,
		"bus/pci/devices/0000:01:00.0/vendor":                   []byte("0x10de\n"),
		"bus/pci/devices/0000:01:00.0/device":                   []byte("0x1c82\n"),
		"bus/pci/devices/0000:01:00.0/class":                    []byte("0x030000\n"),
		"bus/pci/devices/0000:00:1f.0/vendor":                   []byte("0x8086\n"),
		"firmware/efi/esrt/entries/entry0/fw_class":             []byte("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"),
		"firmware/efi/esrt/entries/entry0/fw_version":           []byte("65539\n"),
		"firmware/efi/esrt/entries/entry0/last_attempt_status":  []byte("0\n"),
		"firmware/efi/esrt/entries/entry1/fw_class":             []byte("11111111-2222-3333-4444-555555555555\n"),
		"firmware/efi/esrt/entries/entry1/last_attempt_status":  []byte("3\n"),
		"firmware/efi/esrt/entries/entry1/last_attempt_version": []byte("70000\n"),
	})
	rep, fs, notes := ScanFirmware(root)
	if rep == nil || len(notes) != 0 {
		t.Fatalf("report %+v notes %v", rep, notes)
	}
	if strings.Join(rep.ACPITables, ",") != "DSDT,WPBT" || rep.WPBT == nil || !rep.WPBT.Readable || rep.WPBT.HandoffSize != 123456 {
		t.Errorf("acpi: %v %+v", rep.ACPITables, rep.WPBT)
	}
	if len(rep.OptionROMs) != 1 || rep.OptionROMs[0].Address != "0000:01:00.0" || rep.OptionROMs[0].Vendor != "0x10de" || rep.OptionROMs[0].Class != "0x030000" {
		t.Errorf("option roms: %+v", rep.OptionROMs)
	}
	if len(rep.ESRT) != 2 || rep.ESRT[0].Version != "65539" {
		t.Errorf("esrt: %+v", rep.ESRT)
	}
	for _, want := range []string{"acpi.wpbt-present", "pci.option-rom", "esrt.last-attempt-failed"} {
		if !hasClass(fs, want) {
			t.Errorf("missing %s in %v", want, classes(fs))
		}
	}
	if total(fs) != scoreWPBT {
		t.Errorf("only the WPBT table is scored, got total %d", total(fs))
	}
	if rep, _, notes := ScanFirmware(t.TempDir()); rep != nil || len(notes) != 1 {
		t.Errorf("an empty sysfs is a note, not an empty report: %+v %v", rep, notes)
	}
}

// ── the whole scan ───────────────────────────────────────────────────────────

func TestRunCombinesSurfaces(t *testing.T) {
	disk := filepath.Join(t.TempDir(), "disk.img")
	os.WriteFile(disk, standardGPT(), 0o644)
	vars := efivars(t, true, false, sigList(1))
	esp := writeESP(t, map[string][]byte{
		"EFI/debian/shimx64.efi": pe(10, true, true),
		"EFI/tools/unsigned.efi": pe(10, true, false),
	})
	res := Run(Options{Disks: []string{disk}, ESP: esp, EFIVars: vars})
	if !res.Scanned() || len(res.Disks) != 1 || res.ESP == nil || res.EFI == nil || res.Firmware != nil {
		t.Fatalf("surfaces: %+v", res)
	}
	// Secure Boot state from the variables decides the weight of the
	// unsigned binary; the stale Boot0003 is reported and not scored.
	if !hasClass(res.Findings, "esp.unsigned-efi-binary") || !hasClass(res.Findings, "efi.boot-entry-target-missing") {
		t.Fatalf("findings: %v", classes(res.Findings))
	}
	if res.Score != scoreUnsignedSB || res.Detected() {
		t.Errorf("score %d detected %v", res.Score, res.Detected())
	}
	if res.Findings[0].Score < res.Findings[len(res.Findings)-1].Score {
		t.Errorf("findings should be strongest first: %+v", res.Findings)
	}
	if res.Disks[0].Path != disk {
		t.Errorf("disk path: %q", res.Disks[0].Path)
	}

	// A wiped disk start plus a bootkit staging directory crosses.
	wiped := standardGPT()
	clear(wiped[:34*512])
	os.WriteFile(disk, wiped, 0o644)
	os.MkdirAll(filepath.Join(esp, "system32"), 0o755)
	res = Run(Options{Disks: []string{disk}, ESP: esp, EFIVars: vars})
	if !res.Detected() {
		t.Errorf("corroborated findings should cross the threshold: score %d %v", res.Score, classes(res.Findings))
	}
}

func TestRunNothingAndUnreadable(t *testing.T) {
	res := Run(Options{})
	if res.Scanned() || res.Detected() || res.Threshold != DefaultThreshold || len(res.Notes) < 2 {
		t.Errorf("empty options: %+v", res)
	}
	res = Run(Options{Disks: []string{filepath.Join(t.TempDir(), "missing.img")}, Threshold: 3})
	if res.Threshold != 3 || len(res.Disks) != 1 || res.Disks[0].Error == "" || !strings.Contains(strings.Join(res.Notes, " "), "could not be read") {
		t.Errorf("an unreadable disk must be reported as unread: %+v", res)
	}
	if res.Detected() {
		t.Error("an unreadable disk is not a detection")
	}
}

// ── catalog and the read-only boundary ───────────────────────────────────────

func TestCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Classes() {
		if seen[c.Class] {
			t.Errorf("duplicate class %s", c.Class)
		}
		seen[c.Class] = true
		if c.Technique == "" || c.Description == "" || c.Weight < 0 {
			t.Errorf("incomplete class: %+v", c)
		}
		// One class alone crosses the threshold only if it is the ransom note.
		if c.Weight >= DefaultThreshold && c.Class != "boot.ransom-text" {
			t.Errorf("%s alone would cross the threshold (weight %d)", c.Class, c.Weight)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("a class missing from the catalog must not be emittable")
		}
	}()
	finding("not.a-class", "", "", "")
}

// The package's promise is that it never writes. This test reads the package
// source and fails on any call that could: the boundary is enforced by the
// build, not by a comment.
func TestPackageNeverWrites(t *testing.T) {
	forbidden := map[string]bool{
		"os.Create": true, "os.OpenFile": true, "os.WriteFile": true, "os.Remove": true, "os.RemoveAll": true,
		"os.Rename": true, "os.Mkdir": true, "os.MkdirAll": true, "os.MkdirTemp": true, "os.CreateTemp": true,
		"os.Truncate": true, "os.Chmod": true, "os.Chown": true, "os.Chtimes": true, "os.Symlink": true, "os.Link": true,
	}
	forbiddenImports := map[string]bool{"os/exec": true, "syscall": true, "unsafe": true, "net": true, "net/http": true}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			files++
			for _, imp := range file.Imports {
				if path := strings.Trim(imp.Path.Value, `"`); forbiddenImports[path] {
					t.Errorf("%s imports %s: the boot scan reads files and nothing else", name, path)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && forbidden[id.Name+"."+sel.Sel.Name] {
					t.Errorf("%s: %s.%s can modify the filesystem; this package is read-only by construction",
						fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
				}
				// Methods that write through an open handle.
				switch sel.Sel.Name {
				case "Write", "WriteString", "WriteAt", "Truncate", "Sync":
					if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "f" || id.Name == "file") {
						t.Errorf("%s: %s.%s writes through a file handle", fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if files < 5 {
		t.Fatalf("only %d source files were checked; the gate is not looking at the package", files)
	}
}

// An ESP the scan cannot read is "not inspected". It must never become an
// empty inventory, which would make every boot entry look stale.
func TestUnreadableESPIsNotAnEmptyInventory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := writeESP(t, map[string][]byte{"EFI/debian/shimx64.efi": pe(10, true, true)})
	os.Chmod(root, 0o000)
	defer os.Chmod(root, 0o755)
	rep, fs, notes := ScanESP(root, yes())
	if rep != nil || len(fs) != 0 || len(notes) != 1 || !strings.Contains(notes[0], "run as root") {
		t.Fatalf("unreadable ESP: %+v %v %v", rep, classes(fs), notes)
	}
	res := Run(Options{ESP: root, EFIVars: efivars(t, true, false, sigList(1))})
	if hasClass(res.Findings, "efi.boot-entry-target-missing") {
		t.Errorf("nothing may be inferred from an ESP that was not read: %v", classes(res.Findings))
	}

	// A partly unreadable ESP is partial: inventoried, but no absence claims.
	os.Chmod(root, 0o755)
	locked := filepath.Join(root, "EFI", "locked")
	os.MkdirAll(locked, 0o755)
	os.Chmod(locked, 0o000)
	defer os.Chmod(locked, 0o755)
	rep, _, notes = ScanESP(root, yes())
	if rep == nil || !rep.Truncated || len(rep.Binaries) != 1 || len(notes) == 0 {
		t.Fatalf("partly unreadable ESP: %+v %v", rep, notes)
	}
	res = Run(Options{ESP: root, EFIVars: efivars(t, true, false, sigList(1))})
	if hasClass(res.Findings, "efi.boot-entry-target-missing") {
		t.Errorf("a partial inventory must not report missing targets: %v", classes(res.Findings))
	}
}

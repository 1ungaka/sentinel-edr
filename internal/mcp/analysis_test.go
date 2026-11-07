package mcp

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/internal/selftest"
	"github.com/s-b-repo/cau/scanner"
)

// End-to-end tests for the analysis tools, driven through the JSON-RPC
// harness with synthetic inputs under a temp root. Every fixture is built
// here (the builders are copied from the owning packages' tests, which cannot
// be imported); none is taken from a real disk, firmware or host.

// call drives one tools/call and returns the decoded payload and the raw
// tool result (for isError).
func call(t *testing.T, srv *Server, tool, args string) (map[string]interface{}, toolResult) {
	t.Helper()
	resp := drive(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`)
	r, ok := resp[1]
	if !ok {
		t.Fatalf("%s: no response", tool)
	}
	if r.Error != nil {
		t.Fatalf("%s: rpc error %+v", tool, r.Error)
	}
	b, _ := json.Marshal(r.Result)
	var tr toolResult
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	if len(tr.Content) == 0 {
		t.Fatalf("%s: empty content", tool)
	}
	var out map[string]interface{}
	if !tr.IsError {
		if err := json.Unmarshal([]byte(tr.Content[0].Text), &out); err != nil {
			t.Fatalf("%s: payload is not JSON: %v\n%s", tool, err, tr.Content[0].Text)
		}
	}
	return out, tr
}

func mustErr(t *testing.T, srv *Server, tool, args, want string) {
	t.Helper()
	_, tr := call(t, srv, tool, args)
	if !tr.IsError {
		t.Fatalf("%s %s: expected a tool error, got %s", tool, args, tr.Content[0].Text)
	}
	if want != "" && !strings.Contains(tr.Content[0].Text, want) {
		t.Errorf("%s: error %q does not mention %q", tool, tr.Content[0].Text, want)
	}
}

func q(s string) string { b, _ := json.Marshal(s); return string(b) }

// ── fixture builders ─────────────────────────────────────────────────────────

// mbrDisk builds a 2 MiB MBR disk image with the given boot code and one
// active FAT partition (from internal/bootscan's disk_test.go).
func mbrDisk(code string) []byte {
	const sectors = 4096
	img := make([]byte, sectors*512)
	copy(img, code)
	e := img[446:]
	e[0], e[4] = 0x80, 0x0c
	binary.LittleEndian.PutUint32(e[8:], 2048)
	binary.LittleEndian.PutUint32(e[12:], 1000)
	s := img[2048*512:]
	s[0], s[1], s[2] = 0xEB, 0x58, 0x90
	copy(s[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(s[11:], 512)
	s[16] = 2
	copy(s[82:], "FAT32   ")
	s[510], s[511] = 0x55, 0xAA
	img[510], img[511] = 0x55, 0xAA
	return img
}

const guidGlobal = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

func writeVar(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	raw := append([]byte{0x07, 0, 0, 0}, data...)
	if err := os.WriteFile(filepath.Join(dir, name+"-"+guidGlobal), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// pe builds a minimal PE32+ image with the EFI application subsystem (from
// internal/bootscan's host_test.go).
func pe(signed bool) []byte {
	b := make([]byte, 0x2000)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	opt := 0x80 + 24
	dirs := opt + 112
	binary.LittleEndian.PutUint16(b[0x80+20:], uint16(dirs-opt+16*8))
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint16(b[opt+68:], 10) // EFI application
	binary.LittleEndian.PutUint32(b[dirs-4:], 16)
	if signed {
		// A certificate table that really is at the declared offset: a
		// WIN_CERTIFICATE header, dwLength covering header plus certificate.
		const certOff, certSize = 0x1000, 0x600
		binary.LittleEndian.PutUint32(b[dirs+4*8:], certOff)
		binary.LittleEndian.PutUint32(b[dirs+4*8+4:], certSize)
		const certLen = 0x40
		binary.LittleEndian.PutUint32(b[certOff:], 8+certLen)
		binary.LittleEndian.PutUint16(b[certOff+4:], 0x0200)
		binary.LittleEndian.PutUint16(b[certOff+6:], 0x0002)
		for i := 0; i < certLen; i++ {
			b[certOff+8+i] = byte(i + 1)
		}
	}
	return b
}

// Firmware builders (from scanner/uefi's uefi_test.go).
const fvSignature = 0x4856465F

func put24(b []byte, off, v int) { b[off], b[off+1], b[off+2] = byte(v), byte(v>>8), byte(v>>16) }

func ucs2le(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return append(out, 0, 0)
}

func section(typ uint8, body []byte) []byte {
	s := make([]byte, 4)
	put24(s, 0, 4+len(body))
	s[3] = typ
	s = append(s, body...)
	for len(s)%4 != 0 {
		s = append(s, 0xff)
	}
	return s
}

func ffsFile(guidByte byte, typ uint8, sections []byte) []byte {
	f := make([]byte, 24)
	for i := 0; i < 16; i++ {
		f[i] = guidByte
	}
	f[0x12] = typ
	f[0x17] = 0xf8
	put24(f, 0x14, 24+len(sections))
	f = append(f, sections...)
	for len(f)%8 != 0 {
		f = append(f, 0xff)
	}
	return f
}

func buildFirmware(files ...[]byte) []byte {
	var body []byte
	for _, f := range files {
		body = append(body, f...)
	}
	const hdrLen = 0x48
	fvLen := hdrLen + len(body)
	h := make([]byte, hdrLen)
	copy(h[0x10:0x20], []byte{0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3})
	binary.LittleEndian.PutUint64(h[0x20:], uint64(fvLen))
	binary.LittleEndian.PutUint32(h[0x28:], fvSignature)
	binary.LittleEndian.PutUint16(h[0x30:], hdrLen)
	h[0x37] = 2
	binary.LittleEndian.PutUint32(h[0x38:], 1)
	binary.LittleEndian.PutUint32(h[0x3c:], uint32(fvLen))
	var sum uint16
	for p := 0; p+2 <= hdrLen; p += 2 {
		sum += binary.LittleEndian.Uint16(h[p:])
	}
	binary.LittleEndian.PutUint16(h[0x32:], uint16(0)-sum)
	return append(h, body...)
}

// sysfsTree lays out a synthetic sysfs the way internal/hwanchor's tests do:
// class entries are relative links into devices/.
func sysfsTree(t *testing.T, root string) {
	t.Helper()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(rel, target string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	const (
		dmiDir  = "devices/virtual/dmi/id/"
		eth0Dir = "devices/pci0000:00/0000:00:1c.7/0000:04:00.0/net/eth0/"
	)
	for name, v := range map[string]string{
		"sys_vendor": "ACME", "product_name": "Box 1", "product_uuid": "4c4c4544-0042-3510-8052-b4c04f4a4b32",
		"product_serial": "SER1\x1b[31mIAL", "board_vendor": "ACME", "board_name": "B1",
		"board_serial": "BSER1", "chassis_serial": "CSER1",
		"bios_vendor": "ACME", "bios_version": "1.0", "bios_date": "01/01/2026",
	} {
		write(dmiDir+name, v+"\n")
	}
	link("class/dmi/id", "../../devices/virtual/dmi/id")
	write(eth0Dir+"address", "30:13:8b:8d:37:0e\n")
	write(eth0Dir+"addr_assign_type", "0\n")
	link(eth0Dir+"device", "../../../0000:04:00.0")
	link("class/net/eth0", "../../"+strings.TrimSuffix(eth0Dir, "/"))
	write("devices/virtual/net/lo/address", "00:00:00:00:00:00\n")
	link("class/net/lo", "../../devices/virtual/net/lo")
	// ACPI tables for the boot_scan firmware inventory.
	write("firmware/acpi/tables/DSDT", "DSDT")
	write("firmware/acpi/tables/FACP", "FACP")
}

// syntheticReport writes an evaluation report built with the harness's own
// code, so its totals follow from its samples.
func syntheticReport(t *testing.T, path string, samples int) {
	t.Helper()
	run := &eval.Run{
		SchemaVersion: eval.ReportSchemaVersion,
		Info: eval.RunInfo{
			Tool: "cau test", GeneratedAt: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
			Corpus: "corpus/smoke/manifest.json", CorpusName: "smoke", Detectors: []string{"yara", "heuristics"},
		},
	}
	for i := 0; i < samples; i++ {
		s := eval.SampleResult{ID: "s" + string(rune('a'+i%26)), Path: "x/sample\x07" + string(rune('a'+i%26)), Scored: true, Expected: "clean", Verdict: "clean"}
		if i%2 == 0 {
			s.Expected, s.Detected, s.Verdict, s.Detectors = "malicious", true, "malicious", []string{"yara"}
		}
		run.Samples = append(run.Samples, s)
	}
	rep := eval.NewReport(run)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := rep.WriteJSON(f, true); err != nil {
		t.Fatal(err)
	}
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestPeelFileEndToEnd(t *testing.T) {
	root := t.TempDir()
	payload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("inert-sample-body."), 8)...)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(payload)
	w.Close()
	blob := []byte(base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(gz.Bytes()))))
	f := filepath.Join(root, "chain.txt")
	if err := os.WriteFile(f, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := testServer(t, root)
	out, _ := call(t, srv, "peel_file", `{"path":`+q(f)+`}`)
	if out["outcome"] != "revealed-executable" {
		t.Errorf("outcome = %v, want revealed-executable: %v", out["outcome"], out)
	}
	if out["max_depth"].(float64) != 3 {
		t.Errorf("max_depth = %v, want 3", out["max_depth"])
	}
	if out["primary_signature"] != "base64>base64>gzip" {
		t.Errorf("primary_signature = %v", out["primary_signature"])
	}
	if _, has := out["leaves"]; has {
		t.Error("decoded leaf bytes must never be returned")
	}
	text, _ := json.Marshal(out)
	if bytes.Contains(text, []byte("inert-sample-body")) {
		t.Error("decoded payload bytes leaked into the result")
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v", out["truncated"])
	}
	mustErr(t, srv, "peel_file", `{"path":"/etc/hostname"}`, "outside the allowed scan roots")
}

func TestFirmwareImageEndToEnd(t *testing.T) {
	root := t.TempDir()
	driver := ffsFile(0x11, 0x07, append(
		section(0x15, ucs2le("DxeMain\x1b[0m")),
		section(0x10, []byte("MZ\x00\x00 fake pe body with marker_fw_xyz"))...,
	))
	fw := buildFirmware(driver)
	f := filepath.Join(root, "fw.bin")
	if err := os.WriteFile(f, fw, 0o644); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "plain.bin")
	if err := os.WriteFile(plain, []byte("not firmware at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := testServer(t, root)
	ys, _, err := scanner.LoadYaraRuleFiles([]scanner.RuleSource{{Text: `rule fw_marker { strings: $a = "marker_fw_xyz" condition: $a }`, Name: "inline"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()
	srv.deps.Yara = ys

	out, _ := call(t, srv, "firmware_image", `{"path":`+q(f)+`}`)
	if out["is_firmware"] != true || out["modules"].(float64) != 1 || out["volumes"].(float64) != 1 {
		t.Fatalf("inventory: %v", out)
	}
	inv := out["inventory"].([]interface{})
	m := inv[0].(map[string]interface{})
	if m["type"] != "DRIVER" || m["has_pe"] != true {
		t.Errorf("module = %v", m)
	}
	// The UCS-2 decoder already maps non-printables to '?'; the bounding
	// helper is a second line, so no raw control character can be here.
	if name := m["name"].(string); strings.ContainsRune(name, 0x1b) || !strings.HasPrefix(name, "DxeMain") {
		t.Errorf("module name not bounded: %q", name)
	}
	if out["rules_scanned"] != true {
		t.Errorf("rules_scanned = %v", out["rules_scanned"])
	}
	found := false
	if fs, ok := out["findings"].([]interface{}); ok {
		for _, fi := range fs {
			if fi.(map[string]interface{})["class"] == "uefi.module-rule-match" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected a uefi.module-rule-match finding: %v", out["findings"])
	}
	if out["fv_checksum_valid"] != true {
		t.Error("checksum should validate")
	}

	out, _ = call(t, srv, "firmware_image", `{"path":`+q(plain)+`}`)
	if out["is_firmware"] != false {
		t.Errorf("plain file reported as firmware: %v", out)
	}
	mustErr(t, srv, "firmware_image", `{"path":"/etc/hostname"}`, "outside the allowed scan roots")
}

func TestFirmwareImageOversizeRefused(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "big.bin")
	if err := os.WriteFile(f, buildFirmware(), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}, MaxBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	srv := testServer(t, root)
	srv.deps.Sandbox = sb
	mustErr(t, srv, "firmware_image", `{"path":`+q(f)+`}`, "sandbox cap")
}

func TestBootScanEndToEnd(t *testing.T) {
	root := t.TempDir()
	disk := filepath.Join(root, "disk.img")
	if err := os.WriteFile(disk, mbrDisk("\xeb\x63\x90GRUB \x00Geom\x00Hard Disk\x00Read\x00 Error"), 0o644); err != nil {
		t.Fatal(err)
	}
	efivars := filepath.Join(root, "efivars")
	if err := os.Mkdir(efivars, 0o755); err != nil {
		t.Fatal(err)
	}
	writeVar(t, efivars, "SecureBoot", []byte{1})
	writeVar(t, efivars, "SetupMode", []byte{0})
	esp := filepath.Join(root, "esp")
	if err := os.MkdirAll(filepath.Join(esp, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(esp, "EFI", "BOOT", "BOOTX64.EFI"), pe(true), 0o644); err != nil {
		t.Fatal(err)
	}
	sysfs := filepath.Join(root, "sys")
	sysfsTree(t, sysfs)

	srv := testServer(t, root)
	out, _ := call(t, srv, "boot_scan", `{"disks":[`+q(disk)+`],"esp":`+q(esp)+`,"efivars":`+q(efivars)+`,"sysfs":`+q(sysfs)+`}`)
	if out["scanned"] != true {
		t.Fatalf("scanned = %v: %v", out["scanned"], out)
	}
	disks := out["disks"].([]interface{})
	d := disks[0].(map[string]interface{})
	if d["path"] != disk || d["mbr"].(map[string]interface{})["loader"] != "grub" {
		t.Errorf("disk = %v", d)
	}
	efi := out["efi"].(map[string]interface{})
	if efi["secure_boot"] != true || efi["setup_mode"] != false {
		t.Errorf("efi = %v", efi)
	}
	e := out["esp"].(map[string]interface{})
	bins := e["binaries"].([]interface{})
	if len(bins) != 1 || bins[0].(map[string]interface{})["signed"] != true || bins[0].(map[string]interface{})["efi_subsystem"] != true {
		t.Errorf("esp = %v", e)
	}
	fw := out["firmware"].(map[string]interface{})
	if fw["acpi_read"] != true || fw["acpi_table_count"].(float64) != 2 {
		t.Errorf("firmware = %v", fw)
	}
	if _, has := out["truncated"]; !has {
		t.Error("missing truncated indicator")
	}

	// Every input is confined; one bad path refuses the whole call.
	mustErr(t, srv, "boot_scan", `{"disks":["/dev/null"]}`, "")
	mustErr(t, srv, "boot_scan", `{"disks":["/etc/hostname"]}`, "outside the allowed scan roots")
	mustErr(t, srv, "boot_scan", `{"esp":"/etc"}`, "outside the allowed scan roots")
	mustErr(t, srv, "boot_scan", `{"efivars":"/sys/firmware/efi/efivars"}`, "")
	mustErr(t, srv, "boot_scan", `{"sysfs":"/sys"}`, "")
	mustErr(t, srv, "boot_scan", `{"disks":[`+q(disk)+`],"sysfs":"/sys"}`, "")
	mustErr(t, srv, "boot_scan", `{}`, "nothing to scan")
}

func TestBootScanDiskImageMayExceedTheInMemoryCap(t *testing.T) {
	root := t.TempDir()
	disk := filepath.Join(root, "disk.img")
	if err := os.WriteFile(disk, mbrDisk("\xeb\x63\x90GRUB \x00Geom\x00Hard Disk\x00Read\x00 Error"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	srv := testServer(t, root)
	srv.deps.Sandbox = sb
	// A disk image is read by offset (boot sectors, partition tables), never
	// loaded, so the in-memory cap does not apply to it...
	out, _ := call(t, srv, "boot_scan", `{"disks":[`+q(disk)+`]}`)
	if out["scanned"] != true {
		t.Errorf("disk over the in-memory cap should still be scanned by offset: %v", out)
	}
	// ...while the tools that load a file keep refusing it.
	mustErr(t, srv, "peel_file", `{"path":`+q(disk)+`}`, "sandbox cap")
	mustErr(t, srv, "scan_file", `{"path":`+q(disk)+`}`, "sandbox cap")
}

func TestHardwareIdentityEndToEnd(t *testing.T) {
	root := t.TempDir()
	sysfs := filepath.Join(root, "sys")
	sysfsTree(t, sysfs)
	srv := testServer(t, root)

	// Default: redacted.
	out, _ := call(t, srv, "hardware_identity", `{"sysfs":`+q(sysfs)+`}`)
	if out["redacted"] != true {
		t.Fatalf("redact must default to true: %v", out)
	}
	dmi := out["dmi"].(map[string]interface{})
	serial := dmi["product_serial"].(map[string]interface{})["value"].(string)
	if !strings.HasPrefix(serial, "sha256:") {
		t.Errorf("product_serial not redacted: %q", serial)
	}
	ifaces := out["interfaces"].([]interface{})
	if len(ifaces) != 1 {
		t.Fatalf("interfaces = %v", ifaces)
	}
	addr := ifaces[0].(map[string]interface{})["address"].(map[string]interface{})["value"].(string)
	if !strings.HasPrefix(addr, "sha256:") {
		t.Errorf("MAC not redacted: %q", addr)
	}
	text, _ := json.Marshal(out)
	if bytes.Contains(text, []byte("30:13:8b:8d:37:0e")) || bytes.Contains(text, []byte("BSER1")) {
		t.Error("identity values leaked through a redacted snapshot")
	}

	// Explicit redact=false returns the values, bounded: the escape in the
	// serial is shown as a visible escape, never raw.
	out, _ = call(t, srv, "hardware_identity", `{"sysfs":`+q(sysfs)+`,"redact":false}`)
	if out["redacted"] != false || out["warning"] == nil {
		t.Errorf("redact=false: %v %v", out["redacted"], out["warning"])
	}
	serial = out["dmi"].(map[string]interface{})["product_serial"].(map[string]interface{})["value"].(string)
	if strings.ContainsRune(serial, 0x1b) || !strings.Contains(serial, `\x1b`) {
		t.Errorf("raw control character in serial: %q", serial)
	}

	mustErr(t, srv, "hardware_identity", `{"sysfs":"/sys"}`, "")
	mustErr(t, srv, "hardware_identity", `{}`, "sysfs is required")
	mustErr(t, srv, "hardware_identity", `{"sysfs":`+q(filepath.Join(root, "missing"))+`}`, "")
}

func TestEvalReportEndToEnd(t *testing.T) {
	root := t.TempDir()
	rep := filepath.Join(root, "report.json")
	syntheticReport(t, rep, maxListItems+5)
	srv := testServer(t, root)

	out, _ := call(t, srv, "eval_report", `{"path":`+q(rep)+`}`)
	if out["corpus_class"] != "synthetic" || out["totals_consistent"] != true {
		t.Errorf("report summary: class=%v consistent=%v", out["corpus_class"], out["totals_consistent"])
	}
	smp := out["samples"].(map[string]interface{})
	if smp["total"].(float64) != float64(maxListItems+5) {
		t.Errorf("samples = %v", smp)
	}
	if out["sample_rows"] != nil {
		t.Error("per-sample rows must be omitted unless include_samples is set")
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v", out["truncated"])
	}

	out, _ = call(t, srv, "eval_report", `{"path":`+q(rep)+`,"include_samples":true,"limit":10000}`)
	rows := out["sample_rows"].([]interface{})
	if len(rows) != maxListItems || out["samples_omitted"].(float64) != 5 || out["truncated"] != true {
		t.Errorf("rows=%d omitted=%v truncated=%v", len(rows), out["samples_omitted"], out["truncated"])
	}
	p := rows[0].(map[string]interface{})["path"].(string)
	if strings.ContainsRune(p, 0x07) || !strings.Contains(p, `\x07`) {
		t.Errorf("sample path not bounded: %q", p)
	}

	// A report whose totals were edited is reported as inconsistent.
	data, _ := os.ReadFile(rep)
	var doc map[string]interface{}
	json.Unmarshal(data, &doc)
	doc["totals"].(map[string]interface{})["tp"] = 999
	edited, _ := json.Marshal(doc)
	bad := filepath.Join(root, "edited.json")
	os.WriteFile(bad, edited, 0o644)
	out, _ = call(t, srv, "eval_report", `{"path":`+q(bad)+`}`)
	if out["totals_consistent"] != false {
		t.Error("edited totals must be reported as inconsistent")
	}

	mustErr(t, srv, "eval_report", `{"path":"/etc/hostname"}`, "outside the allowed scan roots")
	junk := filepath.Join(root, "junk.json")
	os.WriteFile(junk, []byte("{not json"), 0o644)
	mustErr(t, srv, "eval_report", `{"path":`+q(junk)+`}`, "")
}

func TestHonestyIndexEndToEnd(t *testing.T) {
	root := t.TempDir()
	srv := testServer(t)

	// Nothing configured: every section says so, nothing reports zeros.
	out, _ := call(t, srv, "honesty_index", `{}`)
	if out["coverage"].(map[string]interface{})["state"] != "no-baseline" {
		t.Errorf("coverage state = %v", out["coverage"].(map[string]interface{})["state"])
	}
	if out["evaluation"].(map[string]interface{})["state"] != "not-measured" {
		t.Errorf("evaluation state = %v", out["evaluation"].(map[string]interface{})["state"])
	}
	if out["selftest"].(map[string]interface{})["state"] != "no-baseline" {
		t.Errorf("selftest state = %v", out["selftest"].(map[string]interface{})["state"])
	}
	if _, has := out["score"]; has {
		t.Error("the index must carry no overall score")
	}

	// A report, and a baseline recorded over a signature file: measured.
	rep := filepath.Join(root, "report.json")
	syntheticReport(t, rep, 4)
	sigs := filepath.Join(root, "hashes.txt")
	os.WriteFile(sigs, []byte("# empty\n"), 0o644)
	m, err := selftest.Compute([]selftest.Resource{{Name: "signatures", Path: sigs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := selftest.WriteManifest(filepath.Join(root, "integrity.json"), m); err != nil {
		t.Fatal(err)
	}
	srv.deps.EvalPath = rep
	srv.deps.SigDBPath = sigs
	out, _ = call(t, srv, "honesty_index", `{}`)
	ev := out["evaluation"].(map[string]interface{})
	if ev["state"] != "measured" || *strPtrOf(ev["corpus_class"]) != "synthetic" {
		t.Errorf("evaluation = %v", ev)
	}
	st := out["selftest"].(map[string]interface{})
	if st["state"] != "measured" || st["intact"] != true || st["signature"] != "unsigned" {
		t.Errorf("selftest = %v", st)
	}
	if out["truncated"] != false {
		t.Errorf("truncated = %v", out["truncated"])
	}

	// Drift is tampered.
	os.WriteFile(sigs, []byte("# changed\n"), 0o644)
	out, _ = call(t, srv, "honesty_index", `{}`)
	if out["selftest"].(map[string]interface{})["state"] != "tampered" {
		t.Errorf("selftest after drift = %v", out["selftest"])
	}

	// The resource is the same document.
	resp := drive(t, srv, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"cau://honesty"}}`)
	b, _ := json.Marshal(resp[1].Result)
	var rc struct {
		Contents []resourceContent `json:"contents"`
	}
	json.Unmarshal(b, &rc)
	if len(rc.Contents) == 0 || !strings.Contains(rc.Contents[0].Text, `"not_claimed"`) {
		t.Errorf("cau://honesty: %+v", rc.Contents)
	}
}

func strPtrOf(v interface{}) *string {
	s, _ := v.(string)
	return &s
}

func TestMitreCoverageFrameworks(t *testing.T) {
	srv := testServer(t)
	out, _ := call(t, srv, "mitre_coverage", `{"frameworks":true}`)
	ukc, ok := out["ukc"].(map[string]interface{})
	if !ok {
		t.Fatalf("no ukc view: %v", out)
	}
	phases := ukc["phases"].([]interface{})
	if len(phases) == 0 || ukc["phases_total"].(float64) != float64(len(phases)) {
		t.Errorf("phases = %d total = %v", len(phases), ukc["phases_total"])
	}
	if ukc["phases_with_content"].(float64) == 0 {
		t.Error("built-in catalogs should land in at least one UKC phase")
	}
	out, _ = call(t, srv, "mitre_coverage", `{}`)
	if _, has := out["ukc"]; has {
		t.Error("ukc view must be opt-in")
	}
}

func TestBootChainReviewPrompt(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv, `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"boot_chain_review","arguments":{"disks":"/srv/a.img, /srv/b.img","efivars":"/srv/efivars"}}}`)
	b, _ := json.Marshal(resp[1].Result)
	text := string(b)
	for _, want := range []string{"boot_scan", "hardware_identity", `\"/srv/a.img\"`, `\"/srv/b.img\"`, "efivars: \\\"/srv/efivars\\\"", "never verified"} {
		if !strings.Contains(text, want) {
			t.Errorf("prompt missing %q:\n%s", want, text)
		}
	}
}

func TestNoRootDisablesEveryFileTool(t *testing.T) {
	srv := testServer(t)
	for tool, args := range map[string]string{
		"peel_file":         `{"path":"/etc/hostname"}`,
		"firmware_image":    `{"path":"/etc/hostname"}`,
		"eval_report":       `{"path":"/etc/hostname"}`,
		"boot_scan":         `{"efivars":"/sys/firmware/efi/efivars"}`,
		"hardware_identity": `{"sysfs":"/sys"}`,
	} {
		mustErr(t, srv, tool, args, "no scan root is configured")
	}
}

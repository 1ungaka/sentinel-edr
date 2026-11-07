package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/report"
)

// bootDisk writes a small MBR disk image: GRUB-marked boot code and one
// active FAT partition. ransom adds a note to the pre-partition gap.
func bootDisk(t *testing.T, ransom bool) string {
	t.Helper()
	img := make([]byte, 4096*512)
	copy(img, "\xeb\x63\x90GRUB \x00")
	e := img[446:]
	e[0], e[4] = 0x80, 0x0c
	binary.LittleEndian.PutUint32(e[8:], 2048)
	binary.LittleEndian.PutUint32(e[12:], 1000)
	img[510], img[511] = 0x55, 0xAA
	vbr := img[2048*512:]
	vbr[0], vbr[1], vbr[2] = 0xEB, 0x58, 0x90
	binary.LittleEndian.PutUint16(vbr[11:], 512)
	vbr[16] = 2
	copy(vbr[82:], "FAT32   ")
	vbr[510], vbr[511] = 0x55, 0xAA
	if ransom {
		copy(img[4*512:], "Your hard disk is ENCRYPTED. Send bitcoin payment to decrypt.")
	}
	path := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(path, img, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIBootScanCleanImage(t *testing.T) {
	disk := bootDisk(t, false)
	code, out, errOut := runCLI(t, "boot-scan", "--offline", "--disk", disk)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"layout    : MBR, 512-byte sectors", "boot code : grub", "[active]", "Score       : 0 / 8", "never verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SUSPICIOUS") {
		t.Errorf("a clean image was reported suspicious:\n%s", out)
	}
}

func TestCLIBootScanRansomNoteJSON(t *testing.T) {
	disk := bootDisk(t, true)
	code, out, errOut := runCLI(t, "boot-scan", "--offline", "--disk", disk, "--format", "json")
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitThreat, errOut)
	}
	var res struct {
		Score     int `json:"score"`
		Threshold int `json:"threshold"`
		Findings  []struct {
			Class, Technique, Target, Evidence string
			Score                              int
		} `json:"findings"`
		Disks []struct {
			Path       string `json:"path"`
			Partitions []struct {
				BootSector string `json:"boot_sector"`
			} `json:"partitions"`
		} `json:"disks"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if res.Score < res.Threshold || len(res.Findings) == 0 || res.Findings[0].Class != "boot.ransom-text" || res.Findings[0].Technique != "T1486" || res.Findings[0].Target != disk {
		t.Errorf("findings: %+v", res)
	}
	if len(res.Disks) != 1 || len(res.Disks[0].Partitions) != 1 || res.Disks[0].Partitions[0].BootSector != "fat" {
		t.Errorf("disks: %+v", res.Disks)
	}
}

func TestCLIBootScanExitsAndUsage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.img")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"nothing offline", []string{"boot-scan", "--offline"}, report.ExitUsage},
		{"bad format", []string{"boot-scan", "--offline", "--disk", "x", "--format", "yaml"}, report.ExitUsage},
		{"positional", []string{"boot-scan", "--offline", "disk.img"}, report.ExitUsage},
		{"negative threshold", []string{"boot-scan", "--offline", "--disk", "x", "--threshold", "-1"}, report.ExitUsage},
		// A disk that cannot be read is a failed run, never a clean one.
		{"unreadable disk", []string{"boot-scan", "--offline", "--disk", missing}, report.ExitRunFailed},
		// An empty directory given as every host surface scans nothing.
		{"empty surfaces", []string{"boot-scan", "--offline", "--efivars", filepath.Join(t.TempDir(), "none")}, report.ExitRunFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, out, errOut := runCLI(t, tc.args...); code != tc.want {
				t.Errorf("exit %d, want %d\n%s\n%s", code, tc.want, out, errOut)
			}
		})
	}
}

// A hostile partition name must not reach the terminal raw.
func TestCLIBootScanTextIsTerminalSafe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "EFI", "x\x1b[2Jy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("filesystem refuses the name: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "a.efi"), []byte("not a pe"), 0o644)
	code, out, _ := runCLI(t, "boot-scan", "--offline", "--esp", root)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.ContainsRune(out, 0x1b) || !strings.Contains(out, `x\x1b[2Jy`) {
		t.Errorf("an escape sequence in a path reached the output raw:\n%q", out)
	}
	if !strings.Contains(out, "esp.efi-binary-not-pe") {
		t.Errorf("finding missing:\n%s", out)
	}
}

// /boot holds an "efi" directory on every host that mounts the ESP at
// /boot/efi; only the FAT mount is the ESP.
func TestDiscoverESPUsesTheMountTable(t *testing.T) {
	mounts := filepath.Join(t.TempDir(), "mounts")
	write := func(s string) { os.WriteFile(mounts, []byte(s), 0o644) }

	write("/dev/sda2 / ext4 rw 0 0\n/dev/sda3 /boot ext4 rw 0 0\n/dev/sda1 /boot/efi vfat rw,fmask=0077 0 0\n")
	if got := discoverESP(mounts); got != "/boot/efi" {
		t.Errorf("got %q, want /boot/efi", got)
	}
	write("/dev/sda2 / ext4 rw 0 0\n/dev/sda1 /boot vfat rw 0 0\n")
	if got := discoverESP(mounts); got != "/boot" {
		t.Errorf("systemd-boot layout: got %q, want /boot", got)
	}
	write("/dev/sda2 / ext4 rw 0 0\n/dev/sda3 /boot ext4 rw 0 0\n")
	if got := discoverESP(mounts); got != "" {
		t.Errorf("a BIOS host has no ESP, got %q", got)
	}
	if got := discoverESP(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Errorf("unreadable mount table: got %q", got)
	}
}

// ── baselines: --record and --check ──────────────────────────────────────────

const (
	bootTestGlobalGUID   = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	bootTestSecurityGUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

func bootTestVar(t *testing.T, dir, name, guid string, data []byte) {
	t.Helper()
	raw := append([]byte{0x07, 0, 0, 0}, data...) // attributes, then data
	if err := os.WriteFile(filepath.Join(dir, name+"-"+guid), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func bootTestUTF16(s string) []byte {
	var out []byte
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, 0, 0)
}

// bootTestLoadOption builds an EFI_LOAD_OPTION with one file-path node.
func bootTestLoadOption(active bool, desc, file string) []byte {
	fp := bootTestUTF16(file)
	node := []byte{0x04, 0x04, 0, 0}
	binary.LittleEndian.PutUint16(node[2:], uint16(4+len(fp)))
	path := append(append(node, fp...), 0x7f, 0xff, 4, 0)
	out := make([]byte, 6)
	if active {
		out[0] = 1
	}
	binary.LittleEndian.PutUint16(out[4:], uint16(len(path)))
	return append(append(out, bootTestUTF16(desc)...), path...)
}

// bootTestSigList builds one EFI_SIGNATURE_LIST of SHA-256 entries.
func bootTestSigList(hashes ...byte) []byte {
	out := make([]byte, 28)
	copy(out, []byte{0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28})
	binary.LittleEndian.PutUint32(out[16:], uint32(28+48*len(hashes)))
	binary.LittleEndian.PutUint32(out[24:], 48)
	for _, h := range hashes {
		entry := make([]byte, 48)
		for i := 16; i < 48; i++ {
			entry[i] = h
		}
		out = append(out, entry...)
	}
	return out
}

// bootTestPE builds a minimal signed PE32+ EFI application; tail makes two
// of them differ.
func bootTestPE(tail string) []byte {
	b := make([]byte, 0x200)
	b[0], b[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	opt := 0x80 + 24
	dirs := opt + 112
	binary.LittleEndian.PutUint16(b[0x80+20:], uint16(dirs-opt+16*8))
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint16(b[opt+68:], 10)
	binary.LittleEndian.PutUint32(b[dirs-4:], 16)
	binary.LittleEndian.PutUint32(b[dirs+4*8:], 0x1000)
	binary.LittleEndian.PutUint32(b[dirs+4*8+4:], 0x600)
	return append(b, tail...)
}

// bootHost is a generated host: firmware variables, an ESP and a sysfs tree.
type bootHost struct {
	t                *testing.T
	vars, esp, sysfs string
}

func newBootHost(t *testing.T) *bootHost {
	t.Helper()
	h := &bootHost{t: t, vars: t.TempDir(), esp: t.TempDir(), sysfs: t.TempDir()}
	h.setVar("SecureBoot", []byte{1})
	h.setVar("SetupMode", []byte{0})
	h.setVar("PK", bootTestSigList(0x01))
	h.setVar("BootOrder", []byte{1, 0})
	h.setVar("Boot0001", bootTestLoadOption(true, "debian", `\EFI\debian\shimx64.efi`))
	bootTestVar(t, h.vars, "db", bootTestSecurityGUID, bootTestSigList(0x10))
	h.setDBX(0xAA, 0xBB)
	h.write(filepath.Join(h.esp, "EFI", "debian", "shimx64.efi"), bootTestPE("shim"))
	h.write(filepath.Join(h.esp, "EFI", "BOOT", "BOOTX64.EFI"), bootTestPE("fallback"))
	h.write(filepath.Join(h.sysfs, "firmware", "acpi", "tables", "DSDT"), []byte("DSDT"))
	h.write(filepath.Join(h.sysfs, "bus", "pci", "devices", "0000:00:1f.0", "vendor"), []byte("0x8086\n"))
	return h
}

func (h *bootHost) write(path string, data []byte) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *bootHost) setVar(name string, data []byte) {
	bootTestVar(h.t, h.vars, name, bootTestGlobalGUID, data)
}
func (h *bootHost) setDBX(hashes ...byte) {
	bootTestVar(h.t, h.vars, "dbx", bootTestSecurityGUID, bootTestSigList(hashes...))
}

// scan runs boot-scan against the generated host with extra arguments.
func (h *bootHost) scan(extra ...string) (int, string, string) {
	h.t.Helper()
	args := append([]string{"boot-scan", "--offline", "--efivars", h.vars, "--esp", h.esp, "--sysfs", h.sysfs}, extra...)
	return runCLI(h.t, args...)
}

// record writes a baseline of the host as it is now and returns its path.
func (h *bootHost) record(extra ...string) string {
	h.t.Helper()
	path := filepath.Join(h.t.TempDir(), "boot-baseline.json")
	code, out, errOut := h.scan(append([]string{"--record", path}, extra...)...)
	if code != report.ExitOK {
		h.t.Fatalf("record: exit %d\n%s\n%s", code, out, errOut)
	}
	return path
}

// bootTestKeys writes an Ed25519 key pair as hex files.
func bootTestKeys(t *testing.T) (privFile, pubFile string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privFile, pubFile = filepath.Join(dir, "priv.hex"), filepath.Join(dir, "pub.hex")
	os.WriteFile(privFile, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
	os.WriteFile(pubFile, []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	return privFile, pubFile
}

func bootTestRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func wantAll(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

func TestCLIBootScanRecordCheckRoundTrip(t *testing.T) {
	h := newBootHost(t)
	path := filepath.Join(t.TempDir(), "baseline.json")
	code, out, errOut := h.scan("--record", path)
	if code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s\n%s", code, out, errOut)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the baseline must be written with mode 0600: %v %v", fi, err)
	}
	// Recording says what it wrote, that it is unsigned, and what it lacks.
	wantAll(t, errOut, "baseline written to", "UNSIGNED", "it covers: firmware variables, EFI System Partition", "does NOT cover: disks")
	wantAll(t, out, "Score       : 0 / 8", "dbx         : 2 SHA-256 revocations", "(sha256 ")

	code, out, errOut = h.scan("--check", path)
	if code != report.ExitOK {
		t.Fatalf("check of an unchanged host: exit %d\n%s\n%s", code, out, errOut)
	}
	wantAll(t, out, "Baseline    : "+path, "UNSIGNED COMPARISON",
		"Differences : 0 security-relevant, 0 expected with updates, 0 informational, 0 could not be re-verified, 0 not in the baseline",
		"no security-relevant change among what could be compared", "no record : disks")
	if strings.Contains(out, "BOOT CHAIN CHANGED") {
		t.Errorf("an unchanged host was reported changed:\n%s", out)
	}
}

func TestCLIBootScanCheckSeverities(t *testing.T) {
	cases := []struct {
		name   string
		change func(h *bootHost)
		code   int
		wants  []string
		absent []string
	}{
		{"changed boot entry",
			func(h *bootHost) {
				h.setVar("Boot0001", bootTestLoadOption(true, "debian", `\EFI\BOOT\BOOTX64.EFI`))
			},
			report.ExitThreat,
			[]string{"Security-relevant (sets the exit code):", "[changed] efi.boot.0001", `baseline: "debian" -> /EFI/debian/shimx64.efi (active)`,
				`now     : "debian" -> /EFI/BOOT/BOOTX64.EFI (active)`, "BOOT CHAIN CHANGED", "1 security-relevant"},
			nil},
		{"added boot entry first in the order",
			func(h *bootHost) {
				h.setVar("Boot0007", bootTestLoadOption(true, "updater", `\EFI\BOOT\BOOTX64.EFI`))
				h.setVar("BootOrder", []byte{7, 0, 1, 0})
			},
			report.ExitThreat,
			[]string{"[added] efi.boot.0007", "[changed] efi.boot_order", "baseline: 0001", "now     : 0007,0001", "2 security-relevant"},
			nil},
		{"dbx shrank",
			func(h *bootHost) { h.setDBX(0xAA) },
			report.ExitThreat,
			[]string{"[changed] efi.dbx", "SHRANK", "baseline: 2 SHA-256 hashes", "now     : 1 SHA-256 hashes", "BOOT CHAIN CHANGED"},
			[]string{"Expected with updates"}},
		{"dbx grew",
			func(h *bootHost) { h.setDBX(0xAA, 0xBB, 0xCC) },
			report.ExitOK,
			[]string{"Expected with updates (a vendor or OS update produces these; they do not set the exit code):", "[changed] efi.dbx",
				"A vendor or OS update produces this", "0 security-relevant, 1 expected with updates", "no security-relevant change"},
			[]string{"BOOT CHAIN CHANGED", "Security-relevant (sets"}},
		{"replaced loader, still signed",
			func(h *bootHost) { h.write(filepath.Join(h.esp, "EFI", "debian", "shimx64.efi"), bootTestPE("other")) },
			report.ExitThreat,
			[]string{"[changed] esp:EFI/debian/shimx64.efi", "cannot verify", "BOOT CHAIN CHANGED"},
			[]string{"Expected with updates"}},
		{"secure boot turned off",
			func(h *bootHost) { h.setVar("SecureBoot", []byte{0}) },
			report.ExitThreat,
			[]string{"[changed] efi.secure_boot", "baseline: enabled", "now     : disabled"},
			nil},
		{"loader removed",
			func(h *bootHost) { os.Remove(filepath.Join(h.esp, "EFI", "BOOT", "BOOTX64.EFI")) },
			report.ExitOK,
			[]string{"Informational:", "[removed] esp:EFI/BOOT/BOOTX64.EFI", "1 informational"},
			[]string{"BOOT CHAIN CHANGED"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newBootHost(t)
			path := h.record()
			tc.change(h)
			code, out, errOut := h.scan("--check", path)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tc.code, out, errOut)
			}
			wantAll(t, out, tc.wants...)
			for _, a := range tc.absent {
				if strings.Contains(out, a) {
					t.Errorf("output should not contain %q:\n%s", a, out)
				}
			}
		})
	}
}

// What cannot be read on a check is "not re-verified": never removed, and
// never an exit code.
func TestCLIBootScanCheckNotReverified(t *testing.T) {
	h := newBootHost(t)
	disk := bootDisk(t, false)
	path := h.record("--disk", disk)

	// The disk is in the baseline and not named now. It is not opened
	// because the baseline names it.
	code, out, errOut := h.scan("--check", path)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	wantAll(t, out, "Could not be re-verified", "[not-reverified] disk:"+disk, "1 could not be re-verified", "name the baseline's disks with --disk")
	if strings.Contains(out, "[removed]") || strings.Contains(out, "Disk        :") {
		t.Errorf("an unnamed disk must be neither removed nor read:\n%s", out)
	}

	// Named again, it compares clean.
	if code, out, _ = h.scan("--check", path, "--disk", disk); code != report.ExitOK || !strings.Contains(out, "0 could not be re-verified") {
		t.Errorf("exit %d\n%s", code, out)
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	// The ESP closed to this user, as it is on a real host without root.
	os.Chmod(h.esp, 0o000)
	defer os.Chmod(h.esp, 0o755)
	code, out, errOut = h.scan("--check", path, "--disk", disk)
	if code != report.ExitOK {
		t.Fatalf("an unreadable ESP must not fail the check: exit %d\n%s\n%s", code, out, errOut)
	}
	wantAll(t, out, "[not-reverified] esp", "baseline: 2 EFI binaries", "run as root to inventory it", "no security-relevant change")
	if strings.Contains(out, "[removed]") || strings.Contains(out, "BOOT CHAIN CHANGED") {
		t.Errorf("an unreadable ESP was reported as a change:\n%s", out)
	}
}

func TestCLIBootScanSignedBaseline(t *testing.T) {
	h := newBootHost(t)
	priv, pub := bootTestKeys(t)
	path := filepath.Join(t.TempDir(), "signed.json")
	code, _, errOut := h.scan("--record", path, "--sign-key", priv)
	if code != report.ExitOK || !strings.Contains(errOut, "signed with Ed25519") || strings.Contains(errOut, "UNSIGNED") {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}

	code, out, errOut := h.scan("--check", path, "--pubkey", pub)
	if code != report.ExitOK {
		t.Fatalf("a signed baseline with its key: exit %d\n%s\n%s", code, out, errOut)
	}
	wantAll(t, out, "integrity : signature verified", "0 security-relevant")
	if strings.Contains(out, "UNSIGNED") {
		t.Errorf("a verified comparison was called unsigned:\n%s", out)
	}

	// Without --pubkey the comparison runs and says what it was.
	code, out, _ = h.scan("--check", path)
	if code != report.ExitOK || !strings.Contains(out, "UNSIGNED COMPARISON") || !strings.Contains(out, "no --pubkey was given") {
		t.Errorf("exit %d\n%s", code, out)
	}

	// A change is still found through a verified baseline.
	h.setVar("Boot0001", bootTestLoadOption(true, "debian", `\EFI\BOOT\BOOTX64.EFI`))
	if code, out, _ = h.scan("--check", path, "--pubkey", pub); code != report.ExitThreat || !strings.Contains(out, "efi.boot.0001") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// With --pubkey, anything short of a verified signature fails the run. It
// never becomes an unsigned comparison.
func TestCLIBootScanPubkeyNeverDowngrades(t *testing.T) {
	h := newBootHost(t)
	priv, pub := bootTestKeys(t)
	_, otherPub := bootTestKeys(t)
	signed := filepath.Join(t.TempDir(), "signed.json")
	if code, _, errOut := h.scan("--record", signed, "--sign-key", priv); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	unsigned := h.record()

	// The attacker's edit: the baseline now "expects" the loader they will
	// point the entry at. The signature is left as it was.
	raw := bootTestRead(t, signed)
	if !strings.Contains(string(raw), `"file_path": "/EFI/debian/shimx64.efi"`) {
		t.Fatalf("fixture: %s", raw)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	os.WriteFile(tampered, []byte(strings.Replace(string(raw), `"file_path": "/EFI/debian/shimx64.efi"`, `"file_path": "/EFI/BOOT/BOOTX64.EFI"`, 1)), 0o600)
	// And one whose signature was simply cut out.
	var doc map[string]interface{}
	json.Unmarshal(raw, &doc)
	delete(doc, "signature")
	stripped := filepath.Join(t.TempDir(), "stripped.json")
	strippedRaw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(stripped, strippedRaw, 0o600)

	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.hex")
	os.WriteFile(garbage, []byte("this is not a key\n"), 0o644)
	short := filepath.Join(dir, "short.hex")
	os.WriteFile(short, []byte("abcd\n"), 0o644)
	empty := filepath.Join(dir, "empty.hex")
	os.WriteFile(empty, nil, 0o644)

	cases := []struct {
		name     string
		baseline string
		pubkey   string
		wantErr  string
	}{
		{"tampered baseline", tampered, pub, "does not verify"},
		{"signature stripped", stripped, pub, "not signed"},
		{"unsigned baseline", unsigned, pub, "not signed"},
		{"another key", signed, otherPub, "does not verify"},
		{"missing key file", signed, filepath.Join(dir, "nope.hex"), "refusing to fall back"},
		{"key file is a directory", signed, dir, "refusing to fall back"},
		{"key is not hex", signed, garbage, "refusing to fall back"},
		{"key has the wrong length", signed, short, "refusing to fall back"},
		{"key file is empty", signed, empty, "refusing to fall back"},
		{"private key given as the public key", signed, priv, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := h.scan("--check", tc.baseline, "--pubkey", tc.pubkey)
			if tc.name == "private key given as the public key" {
				// A 32-byte seed is the same length as a public key: it
				// parses, and then nothing verifies against it.
				if code != report.ExitRunFailed {
					t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
				}
				return
			}
			if code != report.ExitRunFailed {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, report.ExitRunFailed, out, errOut)
			}
			if out != "" {
				t.Errorf("a refused baseline must produce no comparison at all:\n%s", out)
			}
			if !strings.Contains(errOut, tc.wantErr) {
				t.Errorf("stderr lacks %q: %s", tc.wantErr, errOut)
			}
		})
	}

	// The tampered file without --pubkey is compared, and labelled.
	code, out, _ := h.scan("--check", tampered)
	if code != report.ExitThreat || !strings.Contains(out, "UNSIGNED COMPARISON") {
		t.Errorf("exit %d\n%s", code, out)
	}

	// A signing key that cannot be used writes nothing.
	target := filepath.Join(t.TempDir(), "never.json")
	for name, key := range map[string]string{"missing": filepath.Join(dir, "nope.hex"), "garbage": garbage, "short": short, "a public key is not 64 hex bytes of seed": dir} {
		code, out, errOut := h.scan("--record", target, "--sign-key", key)
		if code != report.ExitRunFailed || out != "" || !strings.Contains(errOut, "no baseline was written") {
			t.Errorf("sign key %s: exit %d\n%s\n%s", name, code, out, errOut)
		}
		if _, err := os.Lstat(target); err == nil {
			t.Fatalf("sign key %s: an unsigned baseline was written in place of a signed one", name)
		}
	}
}

func TestCLIBootScanRecordDoesNotOverwrite(t *testing.T) {
	h := newBootHost(t)
	path := h.record()
	before := bootTestRead(t, path)

	h.setDBX(0xAA, 0xBB, 0xCC)
	code, out, errOut := h.scan("--record", path)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "already exists") || !strings.Contains(errOut, "--force") || out != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the existing baseline was modified without --force")
	}

	// A symbolic link at the path is refused too, and its target untouched.
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o644)
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(victim, link); err == nil {
		if code, _, _ := h.scan("--record", link); code != report.ExitRunFailed {
			t.Errorf("a symlink was accepted: exit %d", code)
		}
		if got, _ := os.ReadFile(victim); string(got) != "keep" {
			t.Errorf("the link's target was written: %q", got)
		}
		// With --force the link is replaced, not followed.
		if code, _, errOut := h.scan("--record", link, "--force"); code != report.ExitOK {
			t.Errorf("exit %d\n%s", code, errOut)
		}
		if got, _ := os.ReadFile(victim); string(got) != "keep" {
			t.Errorf("--force followed the link: %q", got)
		}
		if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Errorf("the link should have been replaced by a 0600 file: %v %v", fi, err)
		}
	}

	if code, _, errOut = h.scan("--record", path, "--force"); code != report.ExitOK {
		t.Fatalf("--force: exit %d\n%s", code, errOut)
	}
	after := bootTestRead(t, path)
	if string(after) == string(before) {
		t.Error("--force did not replace the baseline")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode after --force: %v", fi.Mode())
	}
	if code, out, _ := h.scan("--check", path); code != report.ExitOK || !strings.Contains(out, "0 expected with updates") {
		t.Errorf("the new baseline should match the host: exit %d\n%s", code, out)
	}
	// Nothing is left beside the baseline.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}

	// A run that scanned nothing records nothing.
	none := filepath.Join(t.TempDir(), "none.json")
	code, _, errOut = runCLI(t, "boot-scan", "--offline", "--efivars", filepath.Join(t.TempDir(), "absent"), "--record", none)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "no baseline was written") {
		t.Errorf("exit %d\n%s", code, errOut)
	}
	if _, err := os.Lstat(none); err == nil {
		t.Error("an empty baseline was written")
	}
}

func TestCLIBootScanCheckJSON(t *testing.T) {
	h := newBootHost(t)
	path := h.record()
	h.setVar("Boot0001", bootTestLoadOption(true, "debian", `\EFI\BOOT\BOOTX64.EFI`))
	h.setDBX(0xAA, 0xBB, 0xCC)
	code, out, errOut := h.scan("--check", path, "--format", "json")
	if code != report.ExitThreat {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	var res struct {
		Baseline           string   `json:"baseline"`
		BaselineCreatedAt  string   `json:"baseline_created_at"`
		BaselineSignature  string   `json:"baseline_signature"`
		BaselineCovers     []string `json:"baseline_covers"`
		BaselineNotCovered []string `json:"baseline_not_covered"`
		SecurityRelevant   bool     `json:"security_relevant"`
		Differences        []struct {
			Kind, Severity, Surface, Item, Old, New, Detail string
		} `json:"differences"`
		Result struct {
			Score     int `json:"score"`
			Threshold int `json:"threshold"`
			EFI       struct {
				DBX struct {
					SHA256 string `json:"sha256"`
					Bytes  int    `json:"bytes"`
				} `json:"dbx"`
				BootEntries []struct {
					SHA256       string `json:"sha256"`
					TargetSHA256 string `json:"target_sha256"`
				} `json:"boot_entries"`
			} `json:"efi"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if res.Baseline != path || res.BaselineCreatedAt == "" || res.BaselineSignature != "unsigned" || !res.SecurityRelevant ||
		len(res.BaselineCovers) == 0 || len(res.BaselineNotCovered) == 0 {
		t.Errorf("header: %+v", res)
	}
	if len(res.Differences) != 2 || res.Differences[0].Item != "efi.boot.0001" || res.Differences[0].Severity != "security" ||
		res.Differences[0].Kind != "changed" || res.Differences[0].Surface != "efi" ||
		res.Differences[1].Item != "efi.dbx" || res.Differences[1].Severity != "expected-update" {
		t.Errorf("differences: %+v", res.Differences)
	}
	if res.Result.Threshold != 8 || len(res.Result.EFI.DBX.SHA256) != 64 || res.Result.EFI.DBX.Bytes == 0 ||
		len(res.Result.EFI.BootEntries) != 1 || len(res.Result.EFI.BootEntries[0].TargetSHA256) != 64 {
		t.Errorf("result: %+v", res.Result)
	}

	// No differences is an empty list, not null; without --check the output
	// is the result itself, as before.
	h2 := newBootHost(t)
	_, out, _ = h2.scan("--check", h2.record(), "--format", "json")
	if !strings.Contains(out, `"differences": []`) || !strings.Contains(out, `"security_relevant": false`) {
		t.Errorf("an unchanged host:\n%s", out)
	}
	_, out, _ = h2.scan("--format", "json")
	if strings.Contains(out, `"differences"`) || !strings.Contains(out, `"threshold": 8`) {
		t.Errorf("plain JSON output changed shape:\n%s", out)
	}
}

func TestCLIBootScanBaselineUsageAndBadFiles(t *testing.T) {
	h := newBootHost(t)
	path := h.record()
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.json")
	os.WriteFile(garbage, []byte("{not json"), 0o644)
	future := filepath.Join(dir, "future.json")
	raw := bootTestRead(t, path)
	os.WriteFile(future, []byte(strings.Replace(string(raw), `"schema": 1`, `"schema": 99`, 1)), 0o644)
	_, pub := bootTestKeys(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"record and check", []string{"--record", filepath.Join(dir, "a.json"), "--check", path}, report.ExitUsage},
		{"force without record", []string{"--force"}, report.ExitUsage},
		{"force with check", []string{"--check", path, "--force"}, report.ExitUsage},
		{"sign-key without record", []string{"--check", path, "--sign-key", pub}, report.ExitUsage},
		{"pubkey without check", []string{"--pubkey", pub}, report.ExitUsage},
		{"pubkey with record", []string{"--record", filepath.Join(dir, "b.json"), "--pubkey", pub}, report.ExitUsage},
		{"missing baseline", []string{"--check", filepath.Join(dir, "nope.json")}, report.ExitRunFailed},
		{"baseline is a directory", []string{"--check", dir}, report.ExitRunFailed},
		{"baseline is not JSON", []string{"--check", garbage}, report.ExitRunFailed},
		{"baseline from a newer schema", []string{"--check", future}, report.ExitRunFailed},
		{"record into a missing directory", []string{"--record", filepath.Join(dir, "no", "such", "dir.json")}, report.ExitRunFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := h.scan(tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d\n%s\n%s", code, tc.want, out, errOut)
			}
			if tc.want == report.ExitUsage && out != "" {
				t.Errorf("a usage error printed a scan:\n%s", out)
			}
			if strings.Contains(out, "Differences :") {
				t.Errorf("a failed baseline produced a comparison:\n%s", out)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(dir, "a.json")); err == nil {
		t.Error("a usage error wrote a baseline")
	}

	// A suspicious scan still exits 1 with --check, whatever the baseline says.
	disk := bootDisk(t, true)
	clean := newBootHost(t)
	base := clean.record()
	if code, _, _ := clean.scan("--check", base, "--disk", disk); code != report.ExitThreat {
		t.Errorf("a ransom note in the boot area with a matching baseline: exit %d", code)
	}
	// And recording one warns that the baseline now contains it.
	code, _, errOut := clean.scan("--record", filepath.Join(dir, "sus.json"), "--disk", disk)
	if code != report.ExitThreat || !strings.Contains(errOut, "SUSPICIOUS") {
		t.Errorf("exit %d\n%s", code, errOut)
	}

	// The usage text names every new flag.
	_, _, help := runCLI(t, "boot-scan", "--help")
	wantAll(t, help, "--record <file>", "--check <file>", "--sign-key <file>", "--pubkey <file>", "--force", "not-reverified", "expected-update", "unsigned")
}

// A baseline is a file its author controls: nothing in it reaches the
// terminal raw.
func TestCLIBootScanCheckTextIsTerminalSafe(t *testing.T) {
	h := newBootHost(t)
	path := h.record()
	raw := bootTestRead(t, path)
	hostile := strings.Replace(string(raw), `"description": "debian"`, `"description": "deb\u001b[2Jian\u202e"`, 1)
	hostile = strings.Replace(hostile, `"created_at": "`, `"created_at": "\u001b]0;owned\u0007`, 1)
	if hostile == string(raw) {
		t.Fatalf("fixture: %s", raw)
	}
	os.WriteFile(path, []byte(hostile), 0o600)
	code, out, errOut := h.scan("--check", path)
	if code != report.ExitOK {
		t.Fatalf("a relabelled entry is informational: exit %d\n%s\n%s", code, out, errOut)
	}
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) || strings.ContainsRune(out, 0x202e) {
		t.Errorf("a control sequence from the baseline reached the output raw:\n%q", out)
	}
	wantAll(t, out, "[changed] efi.boot.0001", "only the entry's label changed", `\x1b[2J`)
}

// A FIFO given as the baseline or as a key must be refused at once. Opening
// one for reading waits for a writer; a size check does not help, because a
// FIFO reports size zero.
func TestCLIBootScanFIFOArgumentsDoNotBlock(t *testing.T) {
	h := newBootHost(t)
	priv, _ := bootTestKeys(t)
	signed := filepath.Join(t.TempDir(), "signed.json")
	if code, _, errOut := h.scan("--record", signed, "--sign-key", priv); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	fifo := filepath.Join(t.TempDir(), "pipe")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Skipf("mkfifo: %v %s", err, out)
	}
	target := filepath.Join(t.TempDir(), "never.json")
	for name, args := range map[string][]string{
		"baseline":      {"--check", fifo},
		"public key":    {"--check", signed, "--pubkey", fifo},
		"signing key":   {"--record", target, "--sign-key", fifo},
		"dbx reference": {"--dbx-reference", fifo},
		"record target": {"--record", fifo},
	} {
		t.Run(name, func(t *testing.T) {
			type result struct {
				code        int
				out, errOut string
			}
			done := make(chan result, 1)
			go func() {
				code, out, errOut := h.scan(args...)
				done <- result{code, out, errOut}
			}()
			select {
			case r := <-done:
				switch name {
				case "dbx reference":
					// Not a baseline input: the scan runs and notes it.
					if r.code != report.ExitOK || !strings.Contains(r.out, "not a regular file") {
						t.Errorf("exit %d\n%s\n%s", r.code, r.out, r.errOut)
					}
				default:
					if r.code != report.ExitRunFailed || r.out != "" {
						t.Errorf("exit %d, want %d and no output\n%s\n%s", r.code, report.ExitRunFailed, r.out, r.errOut)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("boot-scan blocked on a FIFO given as the %s", name)
			}
		})
	}
	if _, err := os.Lstat(target); err == nil {
		t.Error("a baseline was written although the signing key could not be read")
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the FIFO was replaced or removed: %v %v", fi, err)
	}
}

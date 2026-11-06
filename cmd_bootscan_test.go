package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

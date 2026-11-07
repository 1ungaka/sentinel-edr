package bootscan

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO for reading blocks until a writer appears, and a FIFO
// reports size zero, so a size check before the read does not stop it. Every
// path this package reads must refuse one promptly: a planted pipe, or a
// mistyped --dbx-reference, must not hang the scan.

func mkfifo(t *testing.T, path string) {
	t.Helper()
	os.Remove(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// promptly fails the test when fn has not returned within ten seconds.
func promptly(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s blocked on a FIFO", what)
	}
}

func TestFIFOAsDBXReferenceIsRefused(t *testing.T) {
	dir := efivars(t, true, false, sigList(0xAA))
	ref := filepath.Join(t.TempDir(), "dbxupdate.bin")
	mkfifo(t, ref)
	promptly(t, "the dbx reference", func() {
		if _, err := compareDBX(&SignatureDB{}, ref); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a FIFO as the reference: %v", err)
		}
		rep, fs, notes := ScanEFIVars(dir, ref)
		if rep == nil || rep.DBXReference != nil || hasClass(fs, "efi.dbx-behind-reference") ||
			!strings.Contains(strings.Join(notes, " "), "not a regular file") {
			t.Errorf("a FIFO as the reference must be a note, never a comparison: %+v %v %v", rep, classes(fs), notes)
		}
	})
	// A directory and a missing file are refused the same way.
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := compareDBX(&SignatureDB{}, path); err == nil {
			t.Errorf("%s was accepted as a reference", path)
		}
	}
}

func TestFIFOsInScannedTreesDoNotBlock(t *testing.T) {
	h := newHost(t)
	base := h.baseline()

	// A firmware variable, a boot entry, sysfs attributes, the WPBT table,
	// an EFI binary and the disk itself, each replaced by a FIFO.
	mkfifo(t, filepath.Join(h.vars, "SecureBoot-"+guidGlobal))
	mkfifo(t, filepath.Join(h.vars, "dbx-"+guidSecurity))
	mkfifo(t, filepath.Join(h.vars, "Boot0001-"+guidGlobal))
	mkfifo(t, h.sys("bus/pci/devices/0000:01:00.0/vendor"))
	mkfifo(t, h.sys("firmware/efi/esrt/entries/entry0/fw_class"))
	mkfifo(t, h.sys("firmware/acpi/tables/WPBT"))
	mkfifo(t, h.espFile("EFI/debian/shimx64.efi"))
	mkfifo(t, h.disk)

	var res *Result
	promptly(t, "the scan", func() { res = Run(h.options()) })
	if res == nil {
		return
	}
	if res.EFI.SecureBoot != nil || res.EFI.DBX != nil || len(res.EFI.BootEntries) != 1 {
		t.Errorf("FIFO variables must read as unknown: %+v", res.EFI)
	}
	if got := strings.Join(res.EFI.Unreadable, ","); got != "Boot0001,SecureBoot,dbx" {
		t.Errorf("unreadable variables: %s", got)
	}
	if res.Firmware.WPBT == nil || res.Firmware.WPBT.Readable || res.Firmware.ESRTRead || res.Firmware.OptionROMs[0].Vendor != "" {
		t.Errorf("FIFO sysfs attributes must read as unreadable: %+v", res.Firmware)
	}
	if len(res.Disks) != 1 || !strings.Contains(res.Disks[0].Error, "not a disk image") {
		t.Errorf("a FIFO as the disk: %+v", res.Disks[0])
	}
	for _, b := range res.ESP.Binaries {
		if strings.HasSuffix(b.Path, "shimx64.efi") {
			t.Errorf("a FIFO was inventoried as an EFI binary: %+v", b)
		}
	}

	// Against the baseline, what became a FIFO is not re-verified (or, for
	// the EFI binary, which is simply no longer a file, removed); nothing
	// that was not read is called changed.
	diffs := compare(t, base, NewBaseline(res))
	for _, d := range diffs {
		switch d.Item {
		case "efi.secure_boot", "efi.dbx", "efi.boot.0001", "esrt", "pci.rom.0000:01:00.0", "disk:" + h.disk:
			if d.Kind != KindNotReverified {
				t.Errorf("%s: %+v", d.Item, d)
			}
		}
	}
	// The table that appeared and the entry that boots first being unknown
	// aside, nothing here is a verdict: the FIFOs are unknowns.
	expectDiffs(t, diffs,
		want{"efi.secure_boot", KindNotReverified, SeverityInfo}, want{"efi.dbx", KindNotReverified, SeverityInfo},
		want{"efi.boot.0001", KindNotReverified, SeverityInfo}, want{"esrt", KindNotReverified, SeverityInfo},
		want{"pci.rom.0000:01:00.0", KindNotReverified, SeverityInfo}, want{"disk:" + h.disk, KindNotReverified, SeverityInfo},
		want{"esp:EFI/debian/shimx64.efi", KindRemoved, SeverityInfo}, want{"acpi.table.WPBT", KindAdded, SeveritySecurity})
}

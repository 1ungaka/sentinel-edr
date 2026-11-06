package hwanchor

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO for reading blocks until a writer appears. An attribute that
// is one must be refused before it is opened, or a planted pipe hangs the
// scan.
func TestFIFOAttributeDoesNotBlock(t *testing.T) {
	tr := fullTree(t)
	for _, rel := range []string{dmiDir + "product_serial", eth0Dir + "address", tpmDir + "pcr-sha256/0", rngDir + "rng_current"} {
		tr.remove(rel)
		if err := syscall.Mkfifo(tr.path(rel), 0o644); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
	}
	done := make(chan *Snapshot, 1)
	go func() {
		s, err := Capture(Options{Sysfs: tr.root, Now: fixedNow})
		if err != nil {
			t.Errorf("Capture: %v", err)
		}
		done <- s
	}()
	select {
	case s := <-done:
		if s == nil {
			return
		}
		if f := s.DMI["product_serial"]; f.State != StateUnreadable || !strings.Contains(f.Reason, "not a regular file") {
			t.Errorf("FIFO as product_serial: %+v", f)
		}
		if s.TPM.PCRs[0].State != StateUnreadable || s.RNG.State != StateUnreadable || iface(t, s, "eth0").Address.State != StateUnreadable {
			t.Errorf("FIFO attributes: pcr %+v, rng %+v", s.TPM.PCRs[0], s.RNG)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Capture blocked on a FIFO")
	}
}

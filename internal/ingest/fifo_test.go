package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAFIFOCannotHangTheLayer: an ingest directory is somewhere an operator
// points at another program's output, so a named pipe is a plausible thing to
// find there — and a blocking open would hang the ingest layer, then shutdown,
// then `cau defend --once` outright, because that layer runs first. The pipe is
// left with no writer, which is exactly the case that blocks for ever.
func TestAFIFOCannotHangTheLayer(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "sensor.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	// A real file beside it, so the test also proves the rest of the directory
	// is still read rather than the whole pass being abandoned.
	good := filepath.Join(dir, "fw-1.jsonl")
	if err := os.WriteFile(good, []byte(`{"class":"ok","detail":"read me","peer":"203.0.113.9"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var signals int
	var warnings []string
	go func() {
		defer close(done)
		s, w := NewReader(Options{}).Collect([]string{dir})
		signals, warnings = len(s), w
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Collect blocked on a FIFO: the ingest layer, shutdown and --once would all hang")
	}

	if signals != 1 {
		t.Errorf("read %d signals, want the one real file's", signals)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not a regular file") {
		t.Errorf("warnings = %v, want one naming the FIFO so an operator learns why nothing was read", warnings)
	}
}

// Note on coverage: the test above is caught by the listing filter, so it does
// not prove the open is safe. TestAFIFONamedDirectlyIsRefused is the one that
// reaches the open, and it hangs for its full timeout without safefs. Both
// matter: the filter is racy by nature on a directory somebody else can write
// to, so the open is the real guarantee.

// A FIFO named outright on the command line must fail the same way: safefs
// refuses it at open rather than blocking, and the operator is told.
func TestAFIFONamedDirectlyIsRefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan struct{})
	var warnings []string
	go func() {
		defer close(done)
		_, warnings = NewReader(Options{}).Collect([]string{fifo})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Collect blocked on a FIFO named directly")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not a regular file") {
		t.Errorf("warnings = %v", warnings)
	}
}

// A directory with a telemetry name is skipped with a reason, not queued.
func TestADirectoryNamedLikeTelemetryIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested.jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, warnings := NewReader(Options{}).Collect([]string{dir})
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not a regular file") {
		t.Errorf("warnings = %v", warnings)
	}
}

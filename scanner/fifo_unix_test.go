//go:build unix

package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s blocked on a FIFO", what)
	}
}

func TestLoadSignaturesRefusesAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "hashes.txt")
	mkfifo(t, fifo)
	within(t, "LoadSignatures", func() {
		if _, err := LoadSignatures(fifo); !errors.Is(err, safefs.ErrNotRegular) {
			t.Errorf("got %v", err)
		}
	})
}

// One planted file in the rules directory costs that file, not the ruleset. If
// it cost the ruleset, a FIFO would be a way to switch off every YARA rule.
func TestAPlantedRuleFileCostsOnlyItself(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.yar"), []byte("rule ok { condition: true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mkfifo(t, filepath.Join(dir, "planted.yar"))
	within(t, "LoadYaraRules", func() {
		ys, _, err := LoadYaraRules(dir)
		if err != nil {
			t.Errorf("a planted file failed the whole ruleset: %v", err)
			return
		}
		defer ys.Close()
		if ys.ruleCount != 1 {
			t.Errorf("rules = %d, want the good one", ys.ruleCount)
		}
	})
}

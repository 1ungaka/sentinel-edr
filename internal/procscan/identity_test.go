package procscan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func statLine(comm string, start uint64) string {
	return fmt.Sprintf("600 (%s) S 1 600 600 0 -1 4194560 100 0 0 0 1 1 0 0 20 0 1 0 %d 1000 100\n", comm, start)
}

// Comm and exe are not identity. A reverse shell is usually /usr/bin/bash, so a
// PID recycled by another bash passed the check and the innocent one took the
// signal. A start time cannot repeat on a PID.
func TestRespondRefusesARecycledPIDRunningTheSameProgram(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "600")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"comm":   "bash\n",
		"status": "PPid:\t1\n",
		"stat":   statLine("bash", 5000),
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/usr/bin/bash", filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	flagged := func(start uint64) *Result {
		return &Result{Flagged: []Process{{PID: 600, Comm: "bash", Exe: "/usr/bin/bash", startTicks: start,
			Findings: []Finding{{Class: "procscan.netshell.socket-stdio", Score: 9}}}}}
	}
	hits := 0
	opts := RespondOptions{Action: ActionKill, ProcRoot: root,
		signal: func(int, Action) error { hits++; return nil }}

	rs := Respond(flagged(4000), opts)
	if hits != 0 {
		t.Fatalf("signalled a recycled pid: %+v", rs)
	}
	if rs[0].Applied || rs[0].Reason == "" {
		t.Fatalf("response = %+v", rs[0])
	}
	if Respond(flagged(5000), opts); hits != 1 {
		t.Fatalf("the original process was not signalled, hits = %d", hits)
	}
}

func TestParseStartTicks(t *testing.T) {
	for line, want := range map[string]uint64{
		statLine("bash", 5000):           5000,
		statLine("a) b (c", 77):          77, // a program picks its own comm
		statLine(") R 1 2 3 4 5 6 7", 9): 9,
		"":                               0,
		"600 (bash) S 1":                 0,
		"no parens here at all":          0,
	} {
		if got := parseStartTicks(line); got != want {
			t.Errorf("parseStartTicks(%q) = %d, want %d", line, got, want)
		}
	}
}

func TestReadProcReadsARealStartTime(t *testing.T) {
	rp, ok := readProc("/proc", os.Getpid())
	if !ok {
		t.Skip("no /proc")
	}
	if rp.startTicks == 0 {
		t.Fatal("no start time read for this process")
	}
}

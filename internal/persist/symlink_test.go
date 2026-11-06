package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func link(t *testing.T, root, rel, target string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Skip(err)
	}
}

// ld.so follows a symlink, so a link at an audited path used to run its target
// while the audit saw neither: 1 detection on the plain file, 0 through a link.
func TestSymlinksCannotHidePersistence(t *testing.T) {
	cases := []struct {
		name, rel, target, class string
	}{
		{"preload into tmp", "etc/ld.so.preload", "/var/tmp/.x", "persist.symlink.writable-target"},
		{"preload anywhere", "etc/ld.so.preload", "/usr/lib/libhide.conf", "persist.symlink.critical-file"},
		{"sudoers", "etc/sudoers", "/opt/app/sudoers", "persist.symlink.critical-file"},
		{"listed dir", "etc/profile.d/update.sh", "/dev/shm/u.sh", "persist.symlink.writable-target"},
		{"relative escape", "etc/profile.d/update.sh", "../../tmp/u.sh", "persist.symlink.writable-target"},
		{"hidden system dir", "etc/cron.d/job", "/usr/lib/.cache/job", "persist.symlink.writable-target"},
		{"user dotfile", "home/alice/.bashrc", "/tmp/rc", "persist.symlink.writable-target"},
		{"systemd unit", "etc/systemd/system/net.service", "/var/tmp/net.service", "persist.symlink.writable-target"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := tree(t, map[string]string{"etc/passwd": passwd})
			link(t, root, c.rel, c.target)
			f, ok := classes(Scan(Options{Root: root}))[c.class]
			if !ok {
				t.Fatalf("no %s for %s -> %s", c.class, c.rel, c.target)
			}
			if !strings.Contains(f.Evidence, filepath.Base(c.target)) {
				t.Errorf("evidence %q does not name the target", f.Evidence)
			}
		})
	}
}

// All 100 links at audited paths on the development host are one of these.
func TestSymlinksPackagesCreateStayQuiet(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd})
	link(t, root, "etc/systemd/system/sshd.service", "/usr/lib/systemd/system/ssh.service")
	link(t, root, "etc/systemd/system/getty.service", "/lib/systemd/system/getty.service")
	link(t, root, "etc/systemd/system/masked.service", "/dev/null")
	link(t, root, "etc/udev/rules.d/80-net.rules", "/dev/null")
	link(t, root, "etc/ld.so.conf.d/fakeroot.conf", "/etc/alternatives/fakeroot.conf")
	link(t, root, "etc/rc.local", "rc.d/rc.local")
	link(t, root, "etc/pam.d/system-auth", "system-auth-ac")
	if r := Scan(Options{Root: root}); len(r.Findings) != 0 {
		t.Fatalf("packaged links reported: %+v", r.Findings)
	}
}

// A dotfile manager and a vendor in /opt do this legitimately, so the link is on
// the record without failing the audit.
func TestSymlinkOutsideASystemTreeIsAnObservation(t *testing.T) {
	root := tree(t, map[string]string{"etc/passwd": passwd})
	link(t, root, "home/alice/.bashrc", "/home/alice/dotfiles/bashrc")
	link(t, root, "etc/systemd/system/app.service", "/opt/app/app.service")
	r := Scan(Options{Root: root})
	if len(r.Flagged()) != 0 {
		t.Fatalf("a legitimate link failed the audit: %+v", r.Flagged())
	}
	if len(r.Findings) != 2 {
		t.Fatalf("want 2 observations, got %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.Class != "persist.symlink.unaudited" {
			t.Errorf("class = %s", f.Class)
		}
	}
}

// The reason links are not followed: a user must not be able to point a dotfile
// at a secret and have a root audit quote it into a report.
func TestSymlinkTargetsAreNeverRead(t *testing.T) {
	const secret = "s3cret-hash-value"
	root := tree(t, map[string]string{"etc/passwd": passwd, "etc/shadow": "root:" + secret + ":1:0:::::\n"})
	for _, rel := range []string{"home/alice/.bashrc", "home/alice/.ssh/authorized_keys"} {
		link(t, root, rel, "/etc/shadow")
		link(t, root, rel+".2", filepath.Join(root, "etc/shadow"))
	}
	for _, f := range Scan(Options{Root: root}).Findings {
		if strings.Contains(f.Evidence, secret) || strings.Contains(f.Detail, secret) {
			t.Fatalf("a link target's content reached the report: %+v", f)
		}
	}
}

func TestAFIFOAtAnAuditedPathDoesNotHang(t *testing.T) {
	testFIFO(t)
}

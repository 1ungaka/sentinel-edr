package static

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"strings"
	"testing"
)

// The content classes are combinations, so every test here is a pair: the
// combination fires, the nearest benign shape (one half of it, or the same
// bytes in an image the rule does not apply to) does not. All fixtures are
// synthetic and assembled by buildELF.

// stubAMD64 is "mov eax, nr; syscall; ret", the shape decodeSyscallAMD64 reads.
func stubAMD64(nr uint32) []byte {
	b := []byte{0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xc3}
	binary.LittleEndian.PutUint32(b[1:], nr)
	return b
}

func stubsAMD64(nrs ...uint32) []byte {
	var out []byte
	for _, nr := range nrs {
		out = append(out, stubAMD64(nr)...)
	}
	return append(out, bytes.Repeat([]byte{0x90}, 64)...)
}

// contentSpec is the benign dynamically linked image with its code and its
// read-only data replaced. Strings are NUL-terminated, as a C compiler lays
// them out.
func contentSpec(text []byte, rodata ...string) elfSpec {
	s := benignELFSpec()
	if text != nil {
		s.sections[0].data = text
	}
	if len(rodata) > 0 {
		s.sections[1].data = []byte(strings.Join(rodata, "\x00") + "\x00")
	}
	return s
}

func contentClasses(t *testing.T, spec elfSpec) map[string]int {
	t.Helper()
	r := Analyze(buildELF(t, spec), Options{NoFuzzy: true})
	if !r.IsELF {
		t.Fatalf("fixture did not parse as ELF: %s", r.ParseError)
	}
	out := map[string]int{}
	for _, a := range r.Anomalies {
		if strings.HasPrefix(a.Class, "content.") {
			out[a.Class] = a.Score
		}
	}
	return out
}

func wantOnly(t *testing.T, name string, got map[string]int, want ...string) {
	t.Helper()
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("%s: expected %s, got %v", name, w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: content classes = %v, want exactly %v", name, got, want)
	}
}

const (
	testEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHN5bnRoZXRpYy1maXh0dXJlLWtleS1ub3QtYS1yZWFsLW9uZQ fixture@example"
	testUnit    = "[Unit]\nDescription=fixture\n\n[Service]\nExecStart=%s\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n"
)

func TestContentDirectSyscalls(t *testing.T) {
	// Red: a dynamically linked image whose code traps directly for a
	// fileless-exec pair, and one assembling a socket-to-shell sequence.
	wantOnly(t, "memfd_create+execve", contentClasses(t, contentSpec(stubsAMD64(319, 59))), "content.direct-syscalls")
	wantOnly(t, "socket+connect+dup2+execve", contentClasses(t, contentSpec(stubsAMD64(41, 42, 33, 59))), "content.direct-syscalls")

	// The "mov rax, imm32" encoding decodes too.
	movRax := []byte{0x48, 0xc7, 0xc0, 0x3b, 0, 0, 0, 0x0f, 0x05, 0xc3, 0x48, 0xc7, 0xc0, 0x37, 0x01, 0, 0, 0x0f, 0x05, 0xc3}
	wantOnly(t, "mov rax form (execve+process_vm_writev)", contentClasses(t, contentSpec(movRax)), "content.direct-syscalls")

	// What gcc and clang emit at -O1 and above for an inline system call:
	// the number, then register-only argument set-up, then the trap.
	compiled := []byte{
		0xb8, 0x3f, 0x01, 0, 0, 0x31, 0xd2, 0x0f, 0x05, 0xc3, // mov eax,319; xor edx,edx; syscall
		0x48, 0x63, 0xff, 0xb8, 0x3b, 0, 0, 0, 0x0f, 0x05, 0xc3, // movsxd rdi,edi; mov eax,59; syscall
	}
	wantOnly(t, "compiler-shaped stubs", contentClasses(t, contentSpec(append(compiled, bytes.Repeat([]byte{0x90}, 64)...))), "content.direct-syscalls")
	setup := []byte{
		0xb8, 0x37, 0x01, 0, 0, 0x31, 0xff, 0x31, 0xf6, 0xba, 0x10, 0, 0, 0, 0x0f, 0x05, // process_vm_writev: xor edi; xor esi; mov edx,16
		0xb8, 0x29, 0, 0, 0, 0x49, 0x89, 0xca, 0x0f, 0x05, // socket: mov r10,rcx
	}
	wantOnly(t, "argument set-up between number and trap", contentClasses(t, contentSpec(append(setup, bytes.Repeat([]byte{0x90}, 64)...))), "content.direct-syscalls")

	// Blue: the same stubs in a statically linked image. A static binary has
	// no libc to bypass; Go, musl-Rust and busybox all look like this.
	static := contentSpec(stubsAMD64(319, 59, 41, 42, 33, 101, 217))
	static.interp, static.needed, static.imports, static.pie = "", nil, nil, false
	e := parseSpec(t, static)
	if !e.Static {
		t.Fatal("fixture is not statically linked")
	}
	if e.Content == nil || len(e.Content.Syscalls) != 7 {
		t.Errorf("static image: decoded syscalls = %+v, want the 7 stubs recorded", e.Content)
	}
	wantOnly(t, "static image full of stubs", contentClasses(t, static))

	// Blue: what the Go runtime carries inside a cgo (dynamically linked)
	// binary: read, write, close, mmap, munmap, clone, exit, kill, futex ...
	goRuntime := stubsAMD64(0, 1, 3, 9, 11, 13, 14, 15, 24, 27, 28, 35, 39, 56, 60, 62, 131, 158, 186, 202, 204, 231, 234, 257)
	wantOnly(t, "Go runtime stub set", contentClasses(t, contentSpec(goRuntime)))

	// Red: ptrace beside process_vm_writev; a module loader beside execve.
	wantOnly(t, "ptrace+process_vm_writev", contentClasses(t, contentSpec(stubsAMD64(101, 311))), "content.direct-syscalls")
	wantOnly(t, "finit_module+execve", contentClasses(t, contentSpec(stubsAMD64(313, 59))), "content.direct-syscalls")

	// Blue: a sanitizer runtime. Its own system-call layer carries execve,
	// dup3 and getdents64 among a few dozen ordinary calls: enough weight,
	// but neither a call no runtime issues nor a small stub set.
	sanitizer := append([]uint32{59, 292, 217}, 0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 13, 14, 15, 16, 24, 28, 35, 39, 56, 60, 61, 62, 72, 87, 89, 186, 202, 231, 234, 257, 302)
	e = parseSpec(t, contentSpec(stubsAMD64(sanitizer...)))
	if w, strong, _ := directSyscallWeight(e.Content); w != 3 || strong || e.Content.DecodedSyscalls != len(sanitizer) {
		t.Errorf("sanitizer fixture: weight %d strong %v decoded %d", w, strong, e.Content.DecodedSyscalls)
	}
	wantOnly(t, "sanitizer-like syscall layer", contentClasses(t, contentSpec(stubsAMD64(sanitizer...))))
	// Blue: a crash reporter (ptrace and getdents, a dozen ordinary calls).
	wantOnly(t, "crash-reporter-like", contentClasses(t, contentSpec(stubsAMD64(101, 78, 1, 3, 4, 11, 22, 39, 60, 89, 186, 234))))
	// Blue: two common calls in a small set are below the bar.
	wantOnly(t, "execve+getdents64 only", contentClasses(t, contentSpec(stubsAMD64(59, 217))))

	// Blue: a libc. It carries every stub and exports every wrapper.
	libc := contentSpec(stubsAMD64(59, 322, 319, 101, 41, 42, 33))
	libc.interp, libc.pie = "", false
	libc.soname = "libfixture.so.1"
	libc.exports = []string{"execve", "execveat", "memfd_create", "ptrace", "socket", "connect", "dup2"}
	wantOnly(t, "image exporting the wrappers", contentClasses(t, libc))

	// Blue: the number is not next to the instruction. "mov eax, 59" followed
	// by other code and a later syscall is not a stub template.
	far := append([]byte{0xb8, 59, 0, 0, 0, 0x48, 0x89, 0xc7}, 0x0f, 0x05, 0xb8, 0x3f, 0x01, 0, 0, 0x90, 0x0f, 0x05)
	e = parseSpec(t, contentSpec(append(far, bytes.Repeat([]byte{0x90}, 64)...)))
	if e.SyscallStubs != 2 {
		t.Errorf("SyscallStubs = %d, want 2", e.SyscallStubs)
	}
	if e.Content != nil && len(e.Content.Syscalls) != 0 {
		t.Errorf("non-adjacent numbers were decoded: %+v", e.Content.Syscalls)
	}

	// Blue: the number is overwritten before the trap (xor eax, eax), or sits
	// behind more set-up than a stub has.
	for name, code := range map[string][]byte{
		"rax overwritten": {0xb8, 0x3f, 0x01, 0, 0, 0x31, 0xc0, 0x0f, 0x05, 0xb8, 0x3b, 0, 0, 0, 0x89, 0xd8, 0x0f, 0x05},
		"four set-up instructions": {0xb8, 0x3f, 0x01, 0, 0, 0x31, 0xd2, 0x31, 0xf6, 0x31, 0xff, 0x31, 0xdb, 0x0f, 0x05,
			0xb8, 0x3b, 0, 0, 0, 0x31, 0xd2, 0x31, 0xf6, 0x31, 0xff, 0x31, 0xdb, 0x0f, 0x05},
	} {
		e = parseSpec(t, contentSpec(append(code, bytes.Repeat([]byte{0x90}, 64)...)))
		if e.Content != nil && len(e.Content.Syscalls) != 0 {
			t.Errorf("%s: decoded %+v", name, e.Content.Syscalls)
		}
	}

	// Other machines are counted (SyscallStubs) but not decoded: there was no
	// benign population to measure a number table against.
	arm := contentSpec(stubsAMD64(319, 59))
	arm.machine = 183
	wantOnly(t, "aarch64 image with x86 bytes", contentClasses(t, arm))
}

func TestContentSSHAuthorizedKey(t *testing.T) {
	// Red: the path and a complete key.
	got := contentClasses(t, contentSpec(nil, "/root/.ssh/authorized_keys", testEd25519, "a"))
	wantOnly(t, "authorized_keys + key", got, "content.ssh-authorized-key")
	// Red: as one shell command.
	got = contentClasses(t, contentSpec(nil, "mkdir -p ~/.ssh; echo '"+testEd25519+"' >> ~/.ssh/authorized_keys"))
	wantOnly(t, "echo key >> authorized_keys", got, "content.ssh-authorized-key")

	// Blue: a path string alone is never enough.
	wantOnly(t, "authorized_keys alone", contentClasses(t, contentSpec(nil, "/root/.ssh/authorized_keys", "%s/.ssh/authorized_keys2")))
	// Blue: what sshd carries: the file names, the keyword table, key type
	// names, and no key.
	sshd := contentSpec(nil, ".ssh/authorized_keys", ".ssh/authorized_keys2", "/etc/ssh/sshd_config", "authorizedkeysfile",
		"AuthorizedKeysFile", "PermitRootLogin", "PermitEmptyPasswords", "PasswordAuthentication", "permitrootlogin",
		"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "yes", "no", "prohibit-password")
	wantOnly(t, "sshd-like string set", contentClasses(t, sshd))
	// Blue: a file-carving signature ("ssh-rsa AAAAB3") is a header, not a key.
	wantOnly(t, "key header without a body", contentClasses(t, contentSpec(nil, "authorized_keys", "ssh-rsa AAAAB3", "ssh-dss AAAAB3")))
	// Blue: a key with no authorized_keys path (a pinned known-hosts entry).
	wantOnly(t, "key alone", contentClasses(t, contentSpec(nil, "example.com "+testEd25519, "known_hosts")))
}

func TestContentSSHDConfigEdit(t *testing.T) {
	got := contentClasses(t, contentSpec(nil, "/etc/ssh/sshd_config", "PermitRootLogin yes\n"))
	wantOnly(t, "sshd_config + PermitRootLogin yes", got, "content.sshd-config-edit")
	got = contentClasses(t, contentSpec(nil, "sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords\tyes/' /etc/ssh/sshd_config"))
	wantOnly(t, "sed rewrite", got, "content.sshd-config-edit")

	// Blue: the directive with a value but no configuration path (client help
	// text), and the path with bare keywords (the server's parser).
	wantOnly(t, "directive alone", contentClasses(t, contentSpec(nil, "set PasswordAuthentication yes on the server")))
	wantOnly(t, "path + bare keywords", contentClasses(t, contentSpec(nil, "/etc/ssh/sshd_config", "PermitRootLogin", "PermitRootLogin no", "PermitRootLogin yesterday", "PasswordAuthentication")))
}

func TestContentCronJob(t *testing.T) {
	for name, strs := range map[string][]string{
		"cron.d + system crontab line": {"/etc/cron.d/%s", "*/5 * * * * root %s\n"},
		"crontab pipe + @reboot":       {"(crontab -l 2>/dev/null; echo \"@reboot %s\") | crontab -"},
		"spool + numeric minute":       {"/var/spool/cron/crontabs/root", "0 */2 * * * /usr/bin/.cache >/dev/null 2>&1\n"},
		// Go packs constants back to back: no terminator before the line, so
		// only a command that starts like a path or a verb is accepted.
		"no terminator before the line": {"/etc/crontabgarbage/etc/cron.hourly/xx*/10 * * * * /tmp/.x\n"},
	} {
		wantOnly(t, name, contentClasses(t, contentSpec(nil, strs...)), "content.cron-job")
	}

	for name, strs := range map[string][]string{
		// The cron daemon: every location, and @reboot only in prose.
		"cron daemon": {"/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/etc/cron.allow", "Running @reboot jobs", "Skipping @reboot jobs -- not system startup", "crontabs"},
		// A location alone, and a line alone.
		"location alone": {"/etc/cron.daily", "/etc/crontab"},
		"line alone":     {"*/5 * * * * root /usr/bin/true\n"},
		// git maintenance: a schedule template with ranges and a quoted
		// command, and the bare program name.
		"git-like": {"crontab", "%d 1-23 * * * \"%s/git\" --exec-path=\"%s\" for-each-repo\n", "'crontab' died"},
		// Star tables and prose that only look like schedules.
		"star table":      {"/etc/crontab", "%10s %6s %6u %6llu %4s %3 * * * * * * * *", "\t<* * * * * *>", "* * * * * "},
		"prose":           {"/etc/crontab", "cron * * * * * OID = value", "at   * * * * * OID = value"},
		"other cron path": {"/etc/cron.allow", "/etc/cron.deny", "*/5 * * * * root %s\n"},
	} {
		wantOnly(t, name, contentClasses(t, contentSpec(nil, strs...)))
	}
}

func TestContentSystemdUnit(t *testing.T) {
	wantOnly(t, "unit dir + body", contentClasses(t, contentSpec(nil, "/etc/systemd/system/%s.service", testUnit)), "content.systemd-unit")
	wantOnly(t, "user unit dir + body written in pieces",
		contentClasses(t, contentSpec(nil, "%s/.config/systemd/user/%s.service", "[Service]\n", "ExecStart=%s\n", "WantedBy=default.target\n")),
		"content.systemd-unit")

	// Blue: a unit body with no persistent directory (git writes its timer
	// under XDG_CONFIG_HOME; generators write under /run).
	wantOnly(t, "body alone", contentClasses(t, contentSpec(nil, testUnit, "/run/systemd/generator")))
	// Blue: the directory with prose about units, and neighbouring paths.
	wantOnly(t, "systemctl-like", contentClasses(t, contentSpec(nil, "/etc/systemd/system",
		"The unit files have no installation config (WantedBy=, RequiredBy=, UpheldBy=,\nAlso=, or Alias= settings in the [Install] section",
		"Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.", "the [Service] section")))
	wantOnly(t, "neighbouring paths", contentClasses(t, contentSpec(nil, "/etc/systemd/system-generators", "/etc/systemd/system.conf.d/x.conf",
		"/usr/lib/systemd/systemd-logind", "/usr/lib/systemd/system-sleep", ".config/systemd/user.conf", testUnit)))
	// Red: the Go linker packs constants back to back, so the directory is
	// followed by the first byte of an unrelated string.
	wantOnly(t, "unit dir with no terminator", contentClasses(t, contentSpec(nil, "/etc/systemd/systemapplication/json"+testUnit)), "content.systemd-unit")
}

func TestContentAutostartMulti(t *testing.T) {
	// Red: three mechanisms, one with its body.
	got := contentClasses(t, contentSpec(nil, "/etc/systemd/system/%s.service", testUnit, "%s/.bashrc", "%s/.config/autostart/%s.desktop"))
	wantOnly(t, "systemd(body) + shell rc + XDG", got, "content.systemd-unit", "content.autostart-multi")
	got = contentClasses(t, contentSpec(nil, "/etc/rc.local", "/etc/ld.so.preload", "/etc/xdg/autostart/%s.desktop", "[Desktop Entry]\nType=Application\nExec=%s\n"))
	wantOnly(t, "rc.local + preload + XDG(body)", got, "content.autostart-multi")

	// Blue: busybox names three mechanisms it reads, with no body for any.
	wantOnly(t, "busybox-like", contentClasses(t, contentSpec(nil, "/etc/profile", "/etc/init.d/rcS", "/var/spool/cron/crontabs", "reloading /etc/inittab")))
	// Blue: podman installs user units and mentions shell files: two
	// mechanisms. The single-mechanism class says what it does.
	got = contentClasses(t, contentSpec(nil, ".config/systemd/user", testUnit, "/etc/profile.d/podman.sh", "echo \"autoload -U compinit; compinit\" >> ~/.zshrc"))
	wantOnly(t, "podman-like", got, "content.systemd-unit")
	// Blue: one mechanism with its body (an application that autostarts).
	wantOnly(t, "XDG alone", contentClasses(t, contentSpec(nil, "/etc/xdg/autostart/", "[Desktop Entry]\n")))
	// Blue: a shell, a loader.
	wantOnly(t, "shell-like", contentClasses(t, contentSpec(nil, "/etc/profile", "~/.bash_profile", "~/.bashrc", "/etc/bash.bashrc")))
	wantOnly(t, "loader-like", contentClasses(t, contentSpec(nil, "/etc/ld.so.preload", "/etc/ld.so.cache")))
}

// No single content class, and not the whole persistence category together,
// reaches the threshold. It takes a second, independent kind of evidence: the
// direct-syscall stubs, or a structural finding.
func TestContentAloneStaysBelowThreshold(t *testing.T) {
	persistence := []string{"/root/.ssh/authorized_keys", testEd25519, "/etc/ssh/sshd_config", "PermitRootLogin yes\n",
		"/etc/cron.d/%s", "*/5 * * * * root %s\n", "/etc/systemd/system/%s.service", testUnit,
		"/etc/rc.local", "%s/.bashrc", "/etc/ld.so.preload"}
	r := Analyze(buildELF(t, contentSpec(nil, persistence...)), Options{NoFuzzy: true})
	for _, want := range []string{"content.ssh-authorized-key", "content.sshd-config-edit",
		"content.cron-job", "content.systemd-unit", "content.autostart-multi"} {
		if _, ok := classesOf(r)[want]; !ok {
			t.Errorf("missing %s in %v", want, classesOf(r))
		}
	}
	if r.Detected() || r.Score != categoryCaps[CatPersist] {
		t.Errorf("every persistence class at once: score %d (want the %s cap, %d), detected=%v", r.Score, CatPersist, categoryCaps[CatPersist], r.Detected())
	}
	for _, c := range Classes() {
		if strings.HasPrefix(c.Class, "content.") && c.Weight >= DefaultThreshold/2 {
			t.Errorf("%s has weight %d: a single content class must stay well below the threshold of %d", c.Class, c.Weight, DefaultThreshold)
		}
	}
	if categoryCaps[CatPersist] >= DefaultThreshold {
		t.Errorf("the %s cap (%d) reaches the threshold", CatPersist, categoryCaps[CatPersist])
	}
	// One class alone, with nothing else, is an observation.
	one := Analyze(buildELF(t, contentSpec(nil, "/root/.ssh/authorized_keys", testEd25519)), Options{NoFuzzy: true})
	if one.Detected() || one.Score != 3 {
		t.Errorf("one content class: score %d, detected=%v", one.Score, one.Detected())
	}

	// With direct-syscall stubs as well: two kinds of content evidence.
	both := Analyze(buildELF(t, contentSpec(stubsAMD64(319, 59, 41, 42, 33), persistence...)), Options{NoFuzzy: true})
	if !both.Detected() {
		t.Errorf("persistence content plus direct syscalls not detected: score %d, %v", both.Score, classesOf(both))
	}
	// Or in an image that is also built like a dropper.
	rwx := contentSpec(nil, persistence...)
	rwx.sections[0].pflags = pfR | pfW | pfX
	if r := Analyze(buildELF(t, rwx), Options{NoFuzzy: true}); !r.Detected() {
		t.Errorf("persistence content plus a writable+executable segment not detected: score %d, %v", r.Score, classesOf(r))
	}
}

// The findings come from the loadable bytes, so nothing appended to the file
// or wrapped around the strings inside it makes them go away.
func TestContentRobustness(t *testing.T) {
	spec := contentSpec(stubsAMD64(319, 59), "/root/.ssh/authorized_keys", testEd25519, "/etc/cron.d/%s", "*/5 * * * * root %s\n")
	want := []string{"content.direct-syscalls", "content.ssh-authorized-key", "content.cron-job"}
	wantOnly(t, "baseline", contentClasses(t, spec), want...)

	padded := spec
	padded.overlay = bytes.Repeat([]byte("benign license text. "), 4000)
	wantOnly(t, "overlay appended", contentClasses(t, padded), want...)

	// No section table (sstrip): the pass reads segments, not sections.
	stripped := spec
	stripped.noSections = true
	wantOnly(t, "section table removed", contentClasses(t, stripped), want...)

	// Megabytes of filler between the strings.
	filler := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40000)
	far := contentSpec(stubsAMD64(319, 59), "/root/.ssh/authorized_keys", filler, testEd25519, filler, "/etc/cron.d/%s", filler, "*/5 * * * * root %s\n")
	wantOnly(t, "strings far apart", contentClasses(t, far), want...)

	// The markers in a writable data segment instead of read-only data.
	inData := spec
	inData.sections[2].data = inData.sections[1].data
	inData.sections[1].data = bytes.Repeat([]byte("Hello, world\x00"), 64)
	wantOnly(t, "strings in .data", contentClasses(t, inData), want...)
}

// Bounds: overlapping segments are read once, the excerpt quoted from the
// file is short and printable, and the scan stops at maxContentScan.
func TestContentBounds(t *testing.T) {
	spec := contentSpec(nil, "/etc/cron.d/x", "*/5 * * * * root \x1b[31m"+strings.Repeat("A", 500)+"\n")
	data := buildELF(t, spec)
	// Turn the PT_NOTE program header into a second PT_LOAD over the same
	// file range as the read-only data.
	e, err := ParseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	if e.Content == nil || e.Content.ScannedBytes <= 0 || e.Content.ScannedBytes > len(data) {
		t.Fatalf("ScannedBytes = %+v, file is %d bytes", e.Content, len(data))
	}
	for i, s := range e.Segments {
		if s.TypeNum != ptNote {
			continue
		}
		ph := data[64+i*56:]
		ro := e.Segments[1]
		binary.LittleEndian.PutUint32(ph[0:], ptLoad)
		binary.LittleEndian.PutUint64(ph[8:], ro.Offset)
		binary.LittleEndian.PutUint64(ph[32:], ro.FileSize)
		binary.LittleEndian.PutUint64(ph[40:], ro.FileSize)
	}
	e2, err := ParseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Content.ScannedBytes != e.Content.ScannedBytes {
		t.Errorf("an overlapping segment was read twice: %d bytes scanned, %d without it", e2.Content.ScannedBytes, e.Content.ScannedBytes)
	}
	var detail string
	for _, a := range elfAnomalies(e2) {
		if a.Class == "content.cron-job" {
			detail = a.Detail
		}
	}
	if detail == "" {
		t.Fatal("content.cron-job missing")
	}
	if len(detail) > 400 {
		t.Errorf("detail quotes %d bytes of file content", len(detail))
	}
	for i := 0; i < len(detail); i++ {
		if detail[i] < 0x20 || detail[i] > 0x7e {
			t.Fatalf("detail carries a raw control byte 0x%02x: %q", detail[i], detail)
		}
	}
}

func TestContentScanCap(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a 64 MiB image")
	}
	// One PT_LOAD larger than the cap; the markers sit past it.
	big := make([]byte, maxContentScan+4096)
	copy(big[maxContentScan+64:], "/etc/cron.d/x\x00*/5 * * * * root /bin/true\n\x00")
	spec := contentSpec(nil)
	spec.sections = nil
	spec.rawSegments = []elfSecSpec{{pflags: pfR, data: big}}
	e, err := ParseELF(buildELF(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	if e.Content == nil || !e.Content.Truncated || e.Content.ScannedBytes != maxContentScan {
		t.Fatalf("scan not capped: %+v", e.Content)
	}
	if e.Content.has(mkCronLoc) {
		t.Error("a marker past the cap was read")
	}
}

func TestScanMarkersValidators(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"\x00/etc/crontab\x00", []int{mkCronLoc}},
		{"/etc/cron.daily/x", []int{mkCronLoc}},
		{"/etc/cron.deny", nil},
		{"/etc/profile.d/x.sh", []int{mkShellRC}},
		{"/etc/systemd/system/x.service", []int{mkSystemdLoc}},
		{"/etc/systemd/systemnextstring", []int{mkSystemdLoc}}, // Go: no terminator
		{"/etc/systemd/system-generators", nil},
		{"/etc/systemd/system.conf.d", nil},
		{"/usr/lib/systemd/systemd-logind", nil},
		{"/usr/lib/systemd/system/x.service", []int{mkSystemdLoc}},
		{".config/systemd/user.conf", nil},
		{"ExecStart=/bin/x", []int{mkUnitExec}},
		{"ExecStart=, ExecStop=", nil},
		{"[Service]\nType=simple", []int{mkUnitService}},
		{"the [Service] section", nil},
		{"\x00@reboot /bin/x", []int{mkCronJob}},
		{"x@reboot /bin/x", []int{mkCronJob}},
		{"x@reboot jobs", nil},
		{"\x000 0 * * 0 root x", []int{mkCronJob}},
		{"\x001 2 3 4 5 root x", nil}, // no pair of adjacent stars: not anchored
		{"\x00* * * * * * x", nil},
		{"\x00* * * * *", nil},
		{"ssh-ed25519 AAAA", nil},
		{"PermitRootLogin yes", []int{mkSSHDDirective}},
		{"PermitRootLogin  \tyes\n", []int{mkSSHDDirective}},
		{"PermitRootLogin yesno", nil},
		{"PermitRootLoginyes", nil},
		{"", nil}, {"/", nil}, {"* * ", nil}, {"@reboot ", nil},
	}
	for _, tc := range cases {
		var c ELFContent
		scanMarkers([]byte(tc.in), &c)
		var want uint32
		for _, m := range tc.want {
			want |= 1 << uint(m)
		}
		if c.marks != want {
			t.Errorf("scanMarkers(%q) = %#x, want %#x", tc.in, c.marks, want)
		}
	}
}

// Every token must be reachable through the two-byte dispatch, and the
// dispatch must be exact: the masks select a class only for its own pair.
func TestContentIndexComplete(t *testing.T) {
	for _, tok := range contentTokens {
		if len(tok.tok) < 2 {
			t.Fatalf("token %q is shorter than the dispatch key", tok.tok)
		}
		m := contentFirst[tok.tok[0]] & contentSecond[tok.tok[1]]
		found := false
		for ; m != 0; m &= m - 1 {
			for _, pr := range contentBuckets[bits.TrailingZeros32(m)] {
				if contentTokens[pr.token].tok == tok.tok && int(pr.at) < len(tok.tok) && tok.tok[pr.at] == pr.want {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("token %q is not reachable through the dispatch masks", tok.tok)
		}
		var c ELFContent
		scanMarkers([]byte(tok.tok), &c) // must not panic at the end of the buffer
	}
	if len(contentTokens) > 255 || len(contentBuckets) > 32 {
		t.Fatal("token count overflows the uint8 index or the 32-bit class mask")
	}
	for m, name := range markerNames {
		if name == "" {
			t.Errorf("marker %d has no name", m)
		}
	}
	if mkCount > 32 {
		t.Fatal("marker groups overflow the 32-bit mark set")
	}
}

// BenchmarkScanMarkers reports the marker pass beside the whole-file entropy
// pass the engine already runs on the same bytes, so the added cost can be
// read as a ratio on a machine whose absolute timings are noisy.
func BenchmarkScanMarkers(b *testing.B) {
	buf := bytes.Repeat([]byte("/usr/lib/x86_64-linux-gnu/libexample.so.1\x00error: %s: cannot open /etc/passwd\x00\x48\x89\xe5\x0f\x1f\x40\x00"), 16384)
	b.Run("markers", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		for b.Loop() {
			var c ELFContent
			scanMarkers(buf, &c)
		}
	})
	b.Run("entropy-reference", func(b *testing.B) {
		b.SetBytes(int64(len(buf)))
		for b.Loop() {
			Entropy(buf)
		}
	})
}

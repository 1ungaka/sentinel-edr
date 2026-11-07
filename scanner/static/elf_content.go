package static

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

// This file is the content half of the ELF pass. The structural rules ask how
// an image is built; these ask what a compiled binary carries in the bytes the
// kernel maps: which system calls its code enters the kernel for without
// libc, and which persistence locations sit beside the body that would be
// written there (a public key next to an authorized_keys path, a crontab line
// next to a cron directory, a unit file next to a unit directory).
//
// Every rule is a combination. A path on its own is what sshd, cron, systemd,
// every shell and every installer contain, so no single string scores; the
// location has to meet the payload. The text passes (scanner/tradecraft,
// scanner/linuxpkg) read the same ideas in scripts; nothing there looks inside
// a linked binary.

// CatPersist is the category of the persistence-content classes. Its cap
// keeps all of them together below the threshold: persistence content needs
// a second, independent kind of evidence (direct-syscall stubs, a structural
// finding, another detector through fusion) before a file is reported.
const CatPersist = "Persistence"

// ATT&CK techniques used only by the content rules.
const (
	techNativeAPI   = "T1106"     // Native API
	techSSHKeys     = "T1098.004" // Account Manipulation: SSH Authorized Keys
	techCron        = "T1053.003" // Scheduled Task/Job: Cron
	techSystemdUnit = "T1543.002" // Create or Modify System Process: Systemd Service
	techAutostart   = "T1547"     // Boot or Logon Autostart Execution
)

// Bounds of the content pass.
const (
	// maxContentScan is the most loadable bytes the marker pass reads. It
	// equals DefaultMaxSize on purpose: a cap below the largest file the
	// engine analyses would let padding hide a marker.
	maxContentScan = 64 << 20
	// maxSyscallNr bounds the decoded system-call numbers that are kept.
	maxSyscallNr = 512
	// maxContentExcerpt bounds the bytes of file content quoted as evidence.
	maxContentExcerpt = 64
	// minKeyBlob is the shortest base64 run accepted as a public key: an
	// Ed25519 key, the shortest OpenSSH type, encodes to 68 characters.
	minKeyBlob = 64
	// maxCronLead is how far back a crontab line may start from its first
	// pair of adjacent "*" fields ("59 23 */2 * * " is 13 bytes).
	maxCronLead = 24
	// autostartFamilies is how many distinct autostart mechanisms an image
	// must name, one of them with the body it would install, before the
	// multi-mechanism class fires. busybox names three with no body; podman
	// names two with one.
	autostartFamilies = 3
	// syscallStubWeight is the weight of decoded sensitive stubs at which
	// content.direct-syscalls fires.
	syscallStubWeight = 3
	// maxStubTemplate is the most distinct decoded system calls an image may
	// carry and still be judged on the common calls alone. A stub template is
	// a handful of calls; a general-purpose system-call layer (the sanitizer
	// runtimes, the Go runtime inside a cgo binary) decodes dozens, among them
	// execve, dup3 and getdents64, and is not this shape.
	maxStubTemplate = 16
)

// ELFSyscall is one system call the image's code enters the kernel for
// directly: the number was loaded as an immediate next to the kernel-entry
// instruction (see decodeSyscallAMD64).
type ELFSyscall struct {
	Name   string `json:"name"`
	Number int    `json:"number"`
	// Stubs is how many such instruction pairs were found.
	Stubs int `json:"stubs"`
	// Exported is true when the image itself defines the libc wrapper of the
	// same name (a libc, or an interposer the dynamic-linking rules cover).
	Exported bool `json:"exported,omitempty"`
}

// ELFContent is what the content pass read out of the loadable image.
type ELFContent struct {
	// ScannedBytes is how much of the PT_LOAD file data the marker pass
	// read; Truncated is set when maxContentScan cut it short.
	ScannedBytes int  `json:"scanned_bytes"`
	Truncated    bool `json:"truncated,omitempty"`
	// Markers names the marker groups present ("cron.location", "ssh.key").
	Markers []string `json:"markers,omitempty"`
	// Syscalls lists the sensitive system calls with a decoded stub;
	// DecodedSyscalls is how many distinct call numbers were decoded in all.
	Syscalls        []ELFSyscall `json:"syscalls,omitempty"`
	DecodedSyscalls int          `json:"decoded_syscalls,omitempty"`

	marks uint32
	// first holds one bounded, printable excerpt per marker for the report.
	first [mkCount]string
}

func (c *ELFContent) has(m int) bool { return c != nil && c.marks&(1<<uint(m)) != 0 }

// Marker groups. Each is one kind of evidence; the rules combine them.
const (
	mkAuthKeys      = iota // an authorized_keys file name
	mkSSHKey               // an OpenSSH public key with its base64 body
	mkSSHDConfig           // the sshd_config file name
	mkSSHDDirective        // a login-widening sshd directive written with its value
	mkCronLoc              // a crontab location or a "crontab -" invocation
	mkCronJob              // a crontab line: five schedule fields and a command
	mkSystemdLoc           // a persistent systemd unit directory
	mkUnitService          // "[Service]" as a unit-file section header
	mkUnitExec             // "ExecStart=" with a value
	mkUnitInstall          // "[Install]" as a header, or "WantedBy=" with a value
	mkSysVLoc              // /etc/init.d/, /etc/rc.d/ or /etc/rc.local
	mkSysVBody             // the LSB init-script header
	mkXDGLoc               // an XDG autostart directory
	mkDesktopEntry         // "[Desktop Entry]"
	mkShellRC              // a shell start-up file
	mkPreload              // /etc/ld.so.preload
	mkCount
)

var markerNames = [mkCount]string{
	mkAuthKeys: "ssh.authorized-keys", mkSSHKey: "ssh.key", mkSSHDConfig: "ssh.sshd-config",
	mkSSHDDirective: "ssh.sshd-directive", mkCronLoc: "cron.location", mkCronJob: "cron.job",
	mkSystemdLoc: "systemd.location", mkUnitService: "systemd.unit-service", mkUnitExec: "systemd.unit-exec",
	mkUnitInstall: "systemd.unit-install", mkSysVLoc: "sysv.location", mkSysVBody: "sysv.init-info",
	mkXDGLoc: "xdg.location", mkDesktopEntry: "xdg.desktop-entry", mkShellRC: "shell.rc", mkPreload: "preload.location",
}

// How a token is validated once its bytes match.
const (
	ckNone      = iota // the token is the evidence
	ckNotBefore        // the token must not run on into one of its "not" continuations
	ckValue            // the next byte must start a value ("ExecStart=/...")
	ckNewline          // the next byte must end the line ("[Service]\n")
	ckKeyBlob          // the token ends in "AAAA": a base64 key body must follow
	ckYes              // an sshd directive: blanks, then "yes"
	ckCronStars        // "* * ": must sit in a five-field crontab line
	ckCronNick         // "@reboot ": must start a crontab line
)

type contentToken struct {
	tok    string
	marker int
	check  int
	// not lists continuations that make the token a different path:
	// "/etc/systemd/system" followed by "-generators" is not a unit
	// directory. A plain "next byte ends the name" test would be simpler and
	// wrong: the Go linker packs string constants back to back, so the byte
	// after a path is the first byte of an unrelated string.
	not []string
}

var (
	notUnitDir     = []string{"-generators", "-environment-generators", "-preset", "-shutdown", "-sleep", ".control", ".attached", ".conf"}
	notUnitLibDir  = append([]string{"d"}, notUnitDir...) // /lib/systemd/systemd, /lib/systemd/systemd-*
	notCronDropDir = []string{"eny"}                      // /etc/cron.deny
)

// contentTokens is the whole vocabulary of the marker pass. Every token is at
// least two bytes; the scan dispatches on the first two.
var contentTokens = []contentToken{
	{tok: "authorized_keys", marker: mkAuthKeys},
	{tok: "ssh-rsa AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "ssh-ed25519 AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "ssh-dss AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "ecdsa-sha2-nistp256 AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "ecdsa-sha2-nistp384 AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "ecdsa-sha2-nistp521 AAAA", marker: mkSSHKey, check: ckKeyBlob},
	{tok: "sshd_config", marker: mkSSHDConfig},
	{tok: "PermitRootLogin", marker: mkSSHDDirective, check: ckYes},
	{tok: "PermitEmptyPasswords", marker: mkSSHDDirective, check: ckYes},
	{tok: "PasswordAuthentication", marker: mkSSHDDirective, check: ckYes},
	{tok: "PubkeyAuthentication", marker: mkSSHDDirective, check: ckYes},
	{tok: "RSAAuthentication", marker: mkSSHDDirective, check: ckYes},

	{tok: "/etc/crontab", marker: mkCronLoc},
	{tok: "/etc/cron.d", marker: mkCronLoc, check: ckNotBefore, not: notCronDropDir},
	{tok: "/etc/cron.hourly", marker: mkCronLoc},
	{tok: "/etc/cron.weekly", marker: mkCronLoc},
	{tok: "/etc/cron.monthly", marker: mkCronLoc},
	{tok: "/var/spool/cron", marker: mkCronLoc},
	{tok: "crontab -", marker: mkCronLoc},
	{tok: "* * ", marker: mkCronJob, check: ckCronStars},
	{tok: "@reboot ", marker: mkCronJob, check: ckCronNick},

	{tok: "/etc/systemd/system", marker: mkSystemdLoc, check: ckNotBefore, not: notUnitDir},
	{tok: "/lib/systemd/system", marker: mkSystemdLoc, check: ckNotBefore, not: notUnitLibDir},
	{tok: ".config/systemd/user", marker: mkSystemdLoc, check: ckNotBefore, not: notUnitDir},
	{tok: "[Service]", marker: mkUnitService, check: ckNewline},
	{tok: "ExecStart=", marker: mkUnitExec, check: ckValue},
	{tok: "[Install]", marker: mkUnitInstall, check: ckNewline},
	{tok: "WantedBy=", marker: mkUnitInstall, check: ckValue},

	{tok: "/etc/init.d/", marker: mkSysVLoc},
	{tok: "/etc/rc.d/", marker: mkSysVLoc},
	{tok: "/etc/rc.local", marker: mkSysVLoc},
	{tok: "### BEGIN INIT INFO", marker: mkSysVBody},

	{tok: ".config/autostart", marker: mkXDGLoc},
	{tok: "/etc/xdg/autostart", marker: mkXDGLoc},
	{tok: "[Desktop Entry]", marker: mkDesktopEntry},

	{tok: ".bashrc", marker: mkShellRC},
	{tok: ".bash_profile", marker: mkShellRC},
	{tok: ".zshrc", marker: mkShellRC},
	{tok: "/etc/profile", marker: mkShellRC},

	{tok: "/etc/ld.so.preload", marker: mkPreload},
}

// The scan dispatches on a token's first two bytes. Each distinct pair is a
// class with one bit: contentFirst[b] has the bits of the classes whose first
// byte is b, contentSecond[b] those whose second byte is b, so the AND of the
// two lookups is non-zero exactly where some token can start. Two 1 KiB
// tables stay in the first-level cache, which a 64 KiB pair table does not.
// contentBuckets[class] lists the tokens of that class, each with one more
// byte to test before the full comparison (most tokens of the "/e" class
// differ at "/etc/?"). All three are written once, here, and only read
// afterwards.
var contentFirst, contentSecond, contentBuckets = buildContentIndex()

// tokenProbe is a bucket entry: token index, and the offset and value of the
// byte checked before the token is compared in full.
type tokenProbe struct {
	token uint8
	at    uint8
	want  byte
}

func buildContentIndex() (*[256]uint32, *[256]uint32, [][]tokenProbe) {
	var first, second [256]uint32
	var buckets [][]tokenProbe
	class := map[[2]byte]int{}
	for i, t := range contentTokens {
		k := [2]byte{t.tok[0], t.tok[1]}
		c, ok := class[k]
		if !ok {
			c = len(buckets)
			if c >= 32 {
				panic("static: more than 32 distinct token prefixes; widen the dispatch masks") // audit:ok runs once at package init over the constant contentTokens table, never on scanned input; without it tokens past the limit would silently stop matching
			}
			class[k] = c
			buckets = append(buckets, nil)
			first[k[0]] |= 1 << uint(c)
			second[k[1]] |= 1 << uint(c)
		}
		at := len(t.tok) - 1
		if at > 5 {
			at = 5
		}
		buckets[c] = append(buckets[c], tokenProbe{token: uint8(i), at: uint8(at), want: t.tok[at]})
	}
	return &first, &second, buckets
}

// scanContent runs the marker pass over the file data of the PT_LOAD
// segments: the bytes a running process would have, whatever the section
// table says about them. Overlapping segments are merged so a hostile program
// table cannot make the pass read the same bytes repeatedly, and the total is
// capped at maxContentScan.
func (e *ELF) scanContent(data []byte) {
	if e.Type != etExec && e.Type != etDyn {
		return
	}
	type span struct{ off, end int }
	var spans []span
	for _, s := range e.Segments {
		if !s.Load() || s.FileSize == 0 {
			continue
		}
		off, sz, ok := e.fileRange(s.Offset, s.FileSize)
		if !ok {
			continue
		}
		spans = append(spans, span{off, off + sz})
	}
	if len(spans) == 0 {
		return
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
	c := &ELFContent{}
	pos := 0 // first byte not yet read
	for _, sp := range spans {
		if sp.off < pos {
			sp.off = pos
		}
		if sp.off >= sp.end {
			continue
		}
		if room := maxContentScan - c.ScannedBytes; sp.end-sp.off > room {
			sp.end = sp.off + room
			c.Truncated = true
		}
		if sp.end > sp.off {
			scanMarkers(data[sp.off:sp.end], c)
			c.ScannedBytes += sp.end - sp.off
			pos = sp.end
		}
		if c.Truncated {
			break
		}
	}
	for m := 0; m < mkCount; m++ {
		if c.has(m) {
			c.Markers = append(c.Markers, markerNames[m])
		}
	}
	sort.Strings(c.Markers)
	e.Content = c
}

// scanMarkers records which marker groups occur in buf. It is one forward
// pass with a two-byte dispatch; a token is compared only where its first two
// bytes already match, and every validator reads a bounded window.
func scanMarkers(buf []byte, c *ELFContent) {
	if len(buf) < 2 {
		return
	}
	first, second := contentFirst, contentSecond
	prev := first[buf[0]]
	for j, b := range buf[1:] {
		m := prev & second[b]
		prev = first[b]
		if m == 0 {
			continue
		}
		i := j // buf[i] and buf[i+1] are the matching pair
		for ; m != 0; m &= m - 1 {
			for _, pr := range contentBuckets[bits.TrailingZeros32(m)] {
				if at := i + int(pr.at); at >= len(buf) || buf[at] != pr.want {
					continue
				}
				t := &contentTokens[pr.token]
				end := i + len(t.tok)
				if end > len(buf) || string(buf[i:end]) != t.tok {
					continue
				}
				if c.marks&(1<<uint(t.marker)) != 0 {
					continue // the group is already present; nothing further to learn
				}
				if t.check == ckCronStars && i >= 2 && buf[i-2] == '*' && buf[i-1] == ' ' {
					continue // same line as the "* * " two bytes back, already judged
				}
				if excerpt, ok := checkToken(buf, i, end, t); ok {
					c.marks |= 1 << uint(t.marker)
					c.first[t.marker] = excerpt
				}
			}
		}
	}
}

// checkToken applies a token's validator. The excerpt is what the report
// quotes: the token itself, or a bounded printable slice of the line.
func checkToken(buf []byte, i, end int, t *contentToken) (string, bool) {
	next := byte(0)
	if end < len(buf) {
		next = buf[end]
	}
	switch t.check {
	case ckNotBefore:
		for _, n := range t.not {
			if end+len(n) <= len(buf) && string(buf[end:end+len(n)]) == n {
				return "", false
			}
		}
		return t.tok, true
	case ckValue:
		return t.tok, valueStart(next)
	case ckNewline:
		return t.tok, next == '\n' || next == '\r'
	case ckKeyBlob:
		// The token ends in "AAAA", the start of every OpenSSH key body.
		start := end - 4
		n := 0
		for start+n < len(buf) && n < minKeyBlob && base64Byte(buf[start+n]) {
			n++
		}
		if n < minKeyBlob {
			return "", false
		}
		return t.tok[:len(t.tok)-5] + " " + printable(buf[start:start+16]) + "...", true
	case ckYes:
		p := end
		for p < len(buf) && p-end < 4 && (buf[p] == ' ' || buf[p] == '\t') {
			p++
		}
		if p == end || p+3 > len(buf) || string(buf[p:p+3]) != "yes" {
			return "", false
		}
		if p+3 < len(buf) && nameByte(buf[p+3]) {
			return "", false
		}
		return t.tok + " yes", true
	case ckCronStars:
		return cronLine(buf, i)
	case ckCronNick:
		// "@reboot " at the start of a line, followed by a command.
		if end >= len(buf) {
			return "", false
		}
		strict := i == 0 || lineStart(buf[i-1])
		if !commandStart(buf[end], strict) {
			return "", false
		}
		return excerptLine(buf, i), true
	}
	return t.tok, true
}

// cronLine decides whether the "* * " at buf[at] belongs to a crontab line:
// exactly five schedule fields (digits, "*", "/", "," and "-") and then the
// start of a command or of the user column. It walks back at most maxCronLead
// bytes to the start of the line and forward over the five fields, so the
// work per candidate is constant.
func cronLine(buf []byte, at int) (string, bool) {
	start := at
	for start > 0 && at-start < maxCronLead && (cronFieldByte(buf[start-1]) || buf[start-1] == ' ' || buf[start-1] == '\t') {
		start--
	}
	if at-start >= maxCronLead {
		return "", false // a longer run of field characters is a table, not a line
	}
	strict := start == 0 || lineStart(buf[start-1])
	p := start
	for p < len(buf) && (buf[p] == ' ' || buf[p] == '\t') {
		p++
	}
	lineAt := p
	fields := 0
	for fields < 5 {
		f := p
		for p < len(buf) && p-f < 16 && cronFieldByte(buf[p]) {
			p++
		}
		if p == f || p >= len(buf) || (buf[p] != ' ' && buf[p] != '\t') {
			return "", false
		}
		fields++
		for p < len(buf) && p-f < 24 && (buf[p] == ' ' || buf[p] == '\t') {
			p++
		}
	}
	if p >= len(buf) || !commandStart(buf[p], strict) {
		return "", false // a sixth schedule-like field, or nothing to run
	}
	return excerptLine(buf, lineAt), true
}

// excerptLine quotes the line starting at buf[at], bounded and printable.
func excerptLine(buf []byte, at int) string {
	end := at
	for end < len(buf) && end-at < maxContentExcerpt && buf[end] != 0 && buf[end] != '\n' {
		end++
	}
	return printable(buf[at:end])
}

func cronFieldByte(b byte) bool {
	return b >= '0' && b <= '9' || b == '*' || b == '/' || b == ',' || b == '-'
}

// lineStart reports whether b is something a crontab line legitimately
// follows: the end of the previous string or line, or an opening quote (the
// line as an argument of echo or printf).
func lineStart(b byte) bool {
	return b == 0 || b == '\n' || b == '"' || b == '\''
}

// commandStart reports whether b can begin the command (or user column) of a
// crontab line. After a clean line start any word will do. Without one (Go
// packs string constants back to back, with no terminator) only a path, a
// format verb, a variable or a subshell is accepted, so prose such as
// "Running @reboot jobs" and "cron * * * * * OID = value" stays out.
func commandStart(b byte, strict bool) bool {
	switch b {
	case '/', '%', '$', '~', '(', '{':
		return true
	case '"', '\'', '.', '\\':
		return strict
	}
	return strict && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z')
}

// nameByte reports whether b would continue a word ("yes" in "yesterday").
func nameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_'
}

// valueStart reports whether b begins a unit-file value, as opposed to the
// punctuation that follows a directive when prose mentions it ("WantedBy=,").
func valueStart(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '/', '%', '{', '$', '-', '@', ':', '+', '!', '~':
		return true
	}
	return false
}

func base64Byte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '='
}

// ── direct system calls ──────────────────────────────────────────────────────

// sensitiveSyscall is one x86-64 system call whose direct use is worth
// noting. Weight 2 marks the calls no general-purpose runtime issues itself
// (fileless execution, writing another process's memory, module and BPF
// loading); weight 1 the common ones a network or hiding stub is assembled
// from, which the sanitizer runtimes (execve, dup3, getdents64) and crash
// reporters (ptrace, getdents) also carry and which therefore count only
// beside a weight-2 call or in an image with a small stub set. Calls every
// runtime issues directly (read, write, mmap, clone, kill, futex, openat,
// mprotect) are absent: they say nothing.
type sensitiveSyscall struct {
	nr     int
	name   string
	weight int
}

var sensitiveSyscallsAMD64 = []sensitiveSyscall{
	{322, "execveat", 2}, {319, "memfd_create", 2},
	{310, "process_vm_readv", 2}, {311, "process_vm_writev", 2},
	{175, "init_module", 2}, {313, "finit_module", 2}, {176, "delete_module", 2}, {321, "bpf", 2},
	{59, "execve", 1}, {101, "ptrace", 1},
	{41, "socket", 1}, {42, "connect", 1}, {49, "bind", 1}, {50, "listen", 1}, {43, "accept", 1}, {288, "accept4", 1},
	{33, "dup2", 1}, {292, "dup3", 1},
	{105, "setuid", 1}, {106, "setgid", 1}, {113, "setreuid", 1}, {117, "setresuid", 1},
	{78, "getdents", 1}, {217, "getdents64", 1},
}

// noteSyscallNumber records one decoded system-call number.
func (e *ELF) noteSyscallNumber(nr uint32) {
	if nr >= maxSyscallNr {
		return
	}
	if e.syscallNrs == nil {
		e.syscallNrs = new([maxSyscallNr]uint16)
	}
	if e.syscallNrs[nr] < 0xffff {
		e.syscallNrs[nr]++
	}
}

// maxStubSetup is how many argument-setup instructions may sit between the
// instruction that loads the call number and the kernel-entry instruction.
const maxStubSetup = 3

// decodeSyscallAMD64 reads the system-call number of the "syscall"
// instruction at buf[i] when it was loaded as an immediate next to it:
// "mov eax, imm32" (b8 id) or "mov rax, imm32" (48 c7 c0 id), directly before
// the instruction or separated from it only by up to maxStubSetup
// register-only argument-setup instructions (see stubSetupLens). That is the
// shape of a hand-written stub and of what a compiler emits for an inline
// system call ("mov eax, 319; xor edx, edx; syscall"). A number that reaches
// rax any other way is not decoded. x86 cannot be decoded backwards in
// general, so every alternative is tried; the search reads at most 7 +
// 6*maxStubSetup bytes before the instruction.
func decodeSyscallAMD64(buf []byte, i int) (uint32, bool) {
	return stubNumberAMD64(buf, i, 0)
}

func stubNumberAMD64(buf []byte, p, depth int) (uint32, bool) {
	if p >= 5 && (buf[p-5] == 0xb8 || p >= 7 && buf[p-5] == 0xc0 && buf[p-6] == 0xc7 && buf[p-7] == 0x48) {
		nr := uint32(buf[p-4]) | uint32(buf[p-3])<<8 | uint32(buf[p-2])<<16 | uint32(buf[p-1])<<24
		if nr < maxSyscallNr {
			return nr, true
		}
	}
	if depth == maxStubSetup {
		return 0, false
	}
	for _, n := range stubSetupLens(buf, p) {
		if n == 0 {
			break
		}
		if nr, ok := stubNumberAMD64(buf, p-n, depth+1); ok {
			return nr, true
		}
	}
	return 0, false
}

// stubSetupLens returns the lengths of the argument-setup instructions that
// could end at buf[p] (0 = unused slot): a register-to-register xor, mov or
// movsxd, with or without a REX prefix, that touches neither rax nor r8 (so
// the loaded call number survives it), or an immediate load into edx, esi,
// edi, r9d or r10d.
func stubSetupLens(buf []byte, p int) [4]int {
	var out [4]int
	n := 0
	if p >= 2 {
		op, modrm := buf[p-2], buf[p-1]
		regOnly := modrm >= 0xc0 && modrm&0x07 != 0 && modrm&0x38 != 0
		if regOnly && (op == 0x31 || op == 0x33 || op == 0x89 || op == 0x8b) {
			out[n] = 2
			n++
		}
		if regOnly && p >= 3 && buf[p-3]&0xf0 == 0x40 && (op == 0x31 || op == 0x33 || op == 0x89 || op == 0x8b || op == 0x63) {
			out[n] = 3
			n++
		}
	}
	if p >= 5 && (buf[p-5] == 0xba || buf[p-5] == 0xbe || buf[p-5] == 0xbf) {
		out[n] = 5
		n++
	}
	if p >= 6 && buf[p-6] == 0x41 && (buf[p-5] == 0xb9 || buf[p-5] == 0xba) {
		out[n] = 6
	}
	return out
}

// resolveSyscalls turns the decoded numbers into the named, sensitive calls
// and marks the ones whose libc wrapper the image itself exports.
func (e *ELF) resolveSyscalls() {
	if e.syscallNrs == nil || e.Machine != 62 {
		return
	}
	distinct := 0
	for _, n := range e.syscallNrs {
		if n > 0 {
			distinct++
		}
	}
	var out []ELFSyscall
	for _, s := range sensitiveSyscallsAMD64 {
		if n := e.syscallNrs[s.nr]; n > 0 {
			out = append(out, ELFSyscall{Name: s.name, Number: s.nr, Stubs: int(n)})
		}
	}
	if len(out) > 0 {
		exported := map[string]bool{}
		for _, n := range e.Exports {
			exported[n] = true
		}
		for i := range out {
			out[i].Exported = exported[out[i].Name]
		}
	}
	if e.Content == nil {
		e.Content = &ELFContent{}
	}
	e.Content.Syscalls = out
	e.Content.DecodedSyscalls = distinct
}

// directSyscallWeight sums the weights of the sensitive calls the image
// enters the kernel for directly, leaving out the ones it exports a wrapper
// for, and names them. strong reports whether a weight-2 call is among them.
func directSyscallWeight(c *ELFContent) (w int, strong bool, names []string) {
	if c == nil {
		return 0, false, nil
	}
	for _, s := range c.Syscalls {
		if s.Exported {
			continue
		}
		for _, t := range sensitiveSyscallsAMD64 {
			if t.nr == s.Number {
				w += t.weight
				strong = strong || t.weight >= 2
			}
		}
		names = append(names, fmt.Sprintf("%s(%d)", s.Name, s.Number))
	}
	return w, strong, names
}

// directSyscallsFire is the content.direct-syscalls rule: enough weight, and
// either a call no runtime issues or a stub set small enough to be a template
// rather than a system-call layer.
func directSyscallsFire(c *ELFContent) ([]string, bool) {
	w, strong, names := directSyscallWeight(c)
	if w < syscallStubWeight {
		return nil, false
	}
	return names, strong || c.DecodedSyscalls <= maxStubTemplate
}

// ── rules ────────────────────────────────────────────────────────────────────

// elfContentAnomalies derives the content findings from a parsed ELF.
func elfContentAnomalies(e *ELF) []Anomaly {
	c := e.Content
	if c == nil {
		return nil
	}
	var out []Anomaly
	add := func(class, cat string, score int, tech, format string, a ...interface{}) {
		out = append(out, Anomaly{Class: class, Category: cat, Score: score, Technique: tech, Detail: fmt.Sprintf(format, a...)})
	}

	// Direct system calls in an image that links shared libraries. A static
	// binary (Go, Rust with musl, busybox, anything -static) has no libc to
	// go through and is not this shape.
	if e.Interp != "" || len(e.Needed) > 0 {
		if names, ok := directSyscallsFire(c); ok {
			add("content.direct-syscalls", CatImports, 2, techNativeAPI,
				"dynamically linked image enters the kernel directly for %s (%d distinct call numbers decoded): stubs that load the number and trap, where the libc wrapper (and anything hooking it) is bypassed",
				strings.Join(boundList(names, 8), ", "), c.DecodedSyscalls)
		}
	}

	// An authorized_keys path next to a complete public key.
	if c.has(mkAuthKeys) && c.has(mkSSHKey) {
		add("content.ssh-authorized-key", CatPersist, 3, techSSHKeys,
			"carries an authorized_keys path together with an embedded public key (%s): the key is there to be installed", c.first[mkSSHKey])
	}
	// sshd_config next to a login-widening directive written with its value.
	if c.has(mkSSHDConfig) && c.has(mkSSHDDirective) {
		add("content.sshd-config-edit", CatPersist, 3, techSSHKeys,
			"carries the sshd_config path together with the directive line %q: the server configuration is rewritten to admit a login", c.first[mkSSHDDirective])
	}
	// A crontab location next to a crontab line.
	if c.has(mkCronLoc) && c.has(mkCronJob) {
		add("content.cron-job", CatPersist, 3, techCron,
			"carries a crontab location (%s) together with a crontab line (%q): a scheduled job is installed", c.first[mkCronLoc], c.first[mkCronJob])
	}
	// A persistent unit directory next to a whole unit file.
	unitBody := c.has(mkUnitService) && c.has(mkUnitExec) && c.has(mkUnitInstall)
	if c.has(mkSystemdLoc) && unitBody {
		add("content.systemd-unit", CatPersist, 2, techSystemdUnit,
			"carries a systemd unit directory (%s) together with a unit-file body ([Service], ExecStart=, [Install]/WantedBy=): a service is installed", c.first[mkSystemdLoc])
	}

	// Several autostart mechanisms at once, at least one with its body.
	var families, bodies []string
	family := func(name string, loc, body bool) {
		if !loc {
			return
		}
		families = append(families, name)
		if body {
			bodies = append(bodies, name)
		}
	}
	family("systemd unit", c.has(mkSystemdLoc), unitBody)
	family("cron", c.has(mkCronLoc), c.has(mkCronJob))
	family("init script", c.has(mkSysVLoc), c.has(mkSysVBody))
	family("XDG autostart", c.has(mkXDGLoc), c.has(mkDesktopEntry))
	family("shell start-up file", c.has(mkShellRC), false)
	family("ld.so.preload", c.has(mkPreload), false)
	if len(families) >= autostartFamilies && len(bodies) > 0 {
		add("content.autostart-multi", CatPersist, 3, techAutostart,
			"names %d autostart mechanisms (%s) and carries the body to install for %s: a persistence installer rather than a program that reads one of them",
			len(families), strings.Join(families, ", "), strings.Join(bodies, ", "))
	}
	return out
}

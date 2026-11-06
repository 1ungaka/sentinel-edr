//go:build linux

package harden

import (
	"crypto/rand"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// This file adds the self-concealment and anti-hook half of the hardening:
// a randomised process name (so malware that hunts the scanner by a known name
// — pgrep/pkill, a kill-by-name loop, a /proc sweep — cannot find it), the
// stripping of library-injection vectors from the environment (so a child the
// scanner spawns cannot be hooked through LD_PRELOAD and friends), and a
// read-only check for an attached tracer. It is defensive, not a rootkit: the
// name is a neutral random token, never an impersonation of a real daemon
// (that would deceive the operator and trip the engine's own T1036 rule), and
// the real → random mapping is logged in the daemon banner so the administrator
// always knows what the process is. Signals that cannot be caught in user space
// (SIGKILL, SIGSTOP) and kill-resistance proper belong to the kernel sensor
// (cau-kernel); this layer only removes the easy, name-based ways in.

// Linux prctl option for the thread/process comm name.
const prSetName = 15 // PR_SET_NAME

// ldInjectionVars are the dynamic-loader environment variables an attacker uses
// to inject or redirect code into a process and its children. The scanner does
// not need any of them, so it clears them from its own environment; a static
// Go binary is largely immune in-process, but anything it execs would inherit
// them, and their mere presence is a tamper signal worth recording.
var ldInjectionVars = []string{
	"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PROFILE",
	"LD_DEBUG", "LD_DEBUG_OUTPUT", "LD_ORIGIN_PATH", "GCONV_PATH",
}

const nameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// randName returns a neutral random token of 6–12 chars from [a-z0-9]. It never
// resembles a specific real process on purpose: concealment from malware, not
// masquerade against the operator.
func randName() string {
	b := make([]byte, 1)
	_, _ = rand.Read(b)
	n := 6 + int(b[0]%7) // 6..12
	out := make([]byte, n)
	r := make([]byte, n)
	_, _ = rand.Read(r)
	for i := 0; i < n; i++ {
		out[i] = nameAlphabet[int(r[i])%len(nameAlphabet)]
	}
	return string(out)
}

// setComm sets the process comm via PR_SET_NAME. comm is capped at 16 bytes
// including the terminator, so the name is truncated to 15. This is what
// pgrep/pkill, top, and /proc/<pid>/comm read.
func setComm(name string) error {
	b := make([]byte, 0, 16)
	if len(name) > 15 {
		name = name[:15]
	}
	b = append(b, name...)
	b = append(b, 0)
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetName, uintptr(unsafe.Pointer(&b[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// argvRegion is the block of memory the kernel handed the process its arguments
// in, recorded before os.Args stops pointing at it.
var argvRegion []byte

// init separates the program's arguments from the memory overwriteArgv0 blanks.
// Go's os.Args strings alias that block, and so does every value the flag package
// parses out of them, so blanking it without this turned a daemon's --dir into
// NUL bytes: `cau scan --interval` scanned nothing, on every cycle, while
// reporting that it had run. It has to happen in init, before anything parses.
func init() {
	if len(os.Args) == 0 || len(os.Args[0]) == 0 {
		return
	}
	first := unsafe.StringData(os.Args[0])
	last := os.Args[len(os.Args)-1]
	start := uintptr(unsafe.Pointer(first))
	end := uintptr(unsafe.Pointer(unsafe.StringData(last))) + uintptr(len(last)) + 1 // include NUL
	if span := int(end - start); span > 1 && span <= 1<<16 {
		argvRegion = unsafe.Slice(first, span)
	}
	for i, a := range os.Args {
		os.Args[i] = strings.Clone(a)
	}
}

// overwriteArgv0 rewrites the process command line (argv), which is what
// `ps aux` and /proc/<pid>/cmdline show, so the arguments ("scan --interval …")
// that would reveal the scanner are blanked along with the name. It overwrites
// ONLY the contiguous argv region — never the environment block that follows
// it, because Go's os.Getenv aliases that same memory and corrupting it would
// break the running program. Best-effort: when the layout was implausible at
// init it does nothing, which the caller verifies by re-reading
// /proc/self/cmdline.
func overwriteArgv0(name string) {
	if len(argvRegion) <= 1 {
		return
	}
	for i := range argvRegion {
		argvRegion[i] = 0
	}
	copy(argvRegion[:len(argvRegion)-1], name) // leave a trailing NUL
}

// cmdlineMasked reports whether /proc/self/cmdline now begins with name, i.e.
// whether the argv overwrite actually took on this runtime.
func cmdlineMasked(name string) bool {
	data, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return false
	}
	first := data
	if i := indexByte(data, 0); i >= 0 {
		first = data[:i]
	}
	return string(first) == name
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// obscureName applies a randomised (or supplied) process name to both comm and
// the command line, and reports the chosen name and whether each took.
func obscureName(name string) (chosen string, commSet, cmdline bool) {
	if name == "" {
		name = randName()
	}
	commSet = setComm(name) == nil
	overwriteArgv0(name)
	cmdline = cmdlineMasked(name)
	return name, commSet, cmdline
}

// sanitizeEnv clears the dynamic-loader injection variables from the process
// environment and returns the names it actually removed, so the daemon banner
// can report tampering that was present at launch.
func sanitizeEnv() []string {
	var stripped []string
	for _, v := range ldInjectionVars {
		if _, ok := os.LookupEnv(v); ok {
			_ = os.Unsetenv(v)
			stripped = append(stripped, v)
		}
	}
	return stripped
}

// detectTracer returns the PID of a process tracing this one (ptrace), or 0 if
// none — a non-zero value means a debugger/injector is attached, which with
// PR_SET_DUMPABLE already cleared should only be possible for the owner.
func detectTracer() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:")))
			return n
		}
	}
	return 0
}

// ConcealProcess randomises the process name, strips loader-injection vars, and
// checks for a tracer. It is the Linux implementation behind Apply()'s
// concealment step; off Linux it is a no-op.
func ConcealProcess() Concealment {
	name, comm, cmdline := obscureName("")
	return Concealment{
		Applied:       comm || cmdline,
		ProcessName:   name,
		CommSet:       comm,
		CmdlineMasked: cmdline,
		EnvStripped:   sanitizeEnv(),
		TracerPID:     detectTracer(),
	}
}

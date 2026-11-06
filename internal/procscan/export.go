package procscan

import "strings"

// SystemPath reports whether a path is a normal location for a system binary.
func SystemPath(p string) bool { return systemExePath(p) }

// liveClasses are states of the host rather than text about one: a shell's
// stdio really is a socket, a process really runs from a memfd. Masquerades are
// absent because a renamed tool is odd, not proof, and argv never counts.
var liveClasses = map[string]bool{
	"procscan.netshell.socket-stdio": true,
	"procscan.netshell.pipe-relay":   true,
	"procscan.privesc.setuid-shell":  true,
	"procscan.fileless.memfd":        true,
	"procscan.fileless.tmpfs":        true,
	"procscan.kernel.netshell":       true,
	"procscan.kernel.memfd-exec":     true,
}

// LiveEvidence reports whether a finding class is a live state of the host.
func LiveEvidence(class string) bool { return liveClasses[class] }

// KernelClass reports whether a finding came from the kernel guard's log.
func KernelClass(class string) bool { return strings.HasPrefix(class, "procscan.kernel.") }

// IsInterpreter reports whether a process name is a program a remote operator
// drives: a shell or a scripting language runtime. Exported so the network
// sensor asks the same question of a socket's holder that this package asks of
// a process's stdio, from one definition.
func IsInterpreter(comm string) bool { return isInterpreter(comm) }

// IsRelayTool reports whether a process name is a program that carries another
// program's bytes across the network.
func IsRelayTool(comm string) bool { return isRelayTool(comm) }

// IsShellRelay reports whether a process name is a relay a shell is driven
// through, as opposed to any program that happens to speak the network. curl,
// openssl and busybox carry bytes too, but they also run on every host all day
// for legitimate reasons, so an outbound connection from one is not a signal.
func IsShellRelay(comm string) bool { return shellRelays[comm] }

var shellRelays = map[string]bool{
	"nc": true, "ncat": true, "netcat": true, "nc.openbsd": true, "nc.traditional": true,
	"socat": true, "telnet": true, "rcat": true,
}

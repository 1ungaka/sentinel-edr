// Package sdnotify is a dependency-free client for the systemd service
// readiness/watchdog protocol (sd_notify(3)). It lets the scan daemon tell its
// supervisor "I am up" and "I am still alive", so systemd can restart the
// process if it hangs or dies — the crash/hang auto-recovery path. Everything
// here is a no-op when the process is not running under a notify-enabled unit
// (the NOTIFY_SOCKET environment variable is unset), so the same binary runs
// identically by hand.
//
// Pure standard library: it writes newline-separated assignments to the
// AF_UNIX datagram socket named by $NOTIFY_SOCKET, exactly as the protocol
// specifies. No cgo, no third-party module, so it does not disturb the default
// build's dependency-free property.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// envSocket is the systemd-set path (or "@"-prefixed abstract address) of the
// notify datagram socket.
const envSocket = "NOTIFY_SOCKET"

// envWatchdog is the watchdog timeout in microseconds, set by systemd when the
// unit has WatchdogSec=.
const envWatchdog = "WATCHDOG_USEC"

// Enabled reports whether a notify socket is configured. When false, every
// send is a harmless no-op.
func Enabled() bool { return os.Getenv(envSocket) != "" }

// notify sends one message to the socket. A missing socket is success (no-op);
// a present-but-broken socket returns the error so the caller can log it once.
func notify(state string) error {
	addr := os.Getenv(envSocket)
	if addr == "" {
		return nil
	}
	// systemd uses a leading '@' for the abstract namespace, encoded to Go's
	// net package as a leading NUL.
	name := addr
	if strings.HasPrefix(addr, "@") {
		name = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Ready tells the supervisor the service has finished starting. Paired with
// Type=notify in the unit, systemd treats the service as "active" only after
// this, so a dependency ordered After= it starts against a genuinely-ready
// scanner.
func Ready() error { return notify("READY=1") }

// Watchdog sends a keep-alive ping. With WatchdogSec= set, systemd restarts the
// service if a ping does not arrive within the window — turning a deadlock, a
// wedged cgo call, or a silent hang into an automatic restart.
func Watchdog() error { return notify("WATCHDOG=1") }

// Status publishes a short human-readable status line (shown by
// `systemctl status`). Newlines are stripped so one call is one assignment.
func Status(s string) error {
	return notify("STATUS=" + strings.ReplaceAll(s, "\n", " "))
}

// Stopping announces a clean shutdown in progress.
func Stopping() error { return notify("STOPPING=1") }

// WatchdogInterval returns how often to ping: half the configured watchdog
// window (the interval systemd recommends so a single missed ping is tolerated),
// or 0 when no watchdog is configured. The daemon pings on this cadence
// independently of its scan interval, so a long gap between scans never looks
// like a hang.
func WatchdogInterval() time.Duration {
	usec := os.Getenv(envWatchdog)
	if usec == "" {
		return 0
	}
	n, err := strconv.ParseInt(usec, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	d := time.Duration(n) * time.Microsecond / 2
	if d < time.Second {
		d = time.Second
	}
	return d
}

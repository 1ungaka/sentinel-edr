package sdnotify

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// listen binds a unixgram socket in a temp dir and points NOTIFY_SOCKET at it,
// returning the connection to read datagrams from.
func listen(t *testing.T) *net.UnixConn {
	t.Helper()
	// A short path: unix socket paths are capped near 108 bytes, and t.TempDir()
	// can be long, so use a short name within it.
	sock := filepath.Join(t.TempDir(), "n.sock")
	addr := &net.UnixAddr{Name: sock, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Skipf("cannot bind unixgram socket (sandbox?): %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	t.Setenv(envSocket, sock)
	return conn
}

func recvOne(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func TestEnabled(t *testing.T) {
	t.Setenv(envSocket, "")
	if Enabled() {
		t.Error("Enabled() true with NOTIFY_SOCKET unset")
	}
	t.Setenv(envSocket, "/run/x")
	if !Enabled() {
		t.Error("Enabled() false with NOTIFY_SOCKET set")
	}
}

func TestNoopWhenDisabled(t *testing.T) {
	t.Setenv(envSocket, "")
	// None of these should error or block when there is no supervisor.
	for _, err := range []error{Ready(), Watchdog(), Status("hi"), Stopping()} {
		if err != nil {
			t.Errorf("send with no socket returned error: %v", err)
		}
	}
}

func TestReadyWatchdogStatus(t *testing.T) {
	conn := listen(t)
	cases := []struct {
		send func() error
		want string
	}{
		{Ready, "READY=1"},
		{Watchdog, "WATCHDOG=1"},
		{func() error { return Status("scanning\nnow") }, "STATUS=scanning now"},
		{Stopping, "STOPPING=1"},
	}
	for _, c := range cases {
		if err := c.send(); err != nil {
			t.Fatalf("send %q: %v", c.want, err)
		}
		if got := recvOne(t, conn); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestWatchdogInterval(t *testing.T) {
	t.Setenv(envWatchdog, "")
	if d := WatchdogInterval(); d != 0 {
		t.Errorf("no WATCHDOG_USEC: got %v, want 0", d)
	}
	// 10s window -> ping every 5s (half).
	t.Setenv(envWatchdog, "10000000")
	if d := WatchdogInterval(); d != 5*time.Second {
		t.Errorf("10s window: got %v, want 5s", d)
	}
	// Garbage and non-positive are treated as "no watchdog".
	t.Setenv(envWatchdog, "nope")
	if d := WatchdogInterval(); d != 0 {
		t.Errorf("garbage WATCHDOG_USEC: got %v, want 0", d)
	}
	// A tiny window floors at 1s so we never busy-ping.
	t.Setenv(envWatchdog, "100")
	if d := WatchdogInterval(); d != time.Second {
		t.Errorf("tiny window: got %v, want 1s floor", d)
	}
}

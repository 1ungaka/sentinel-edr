package trust

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A signing key left beside the manifest it signed makes the signature worth no
// more than a digest, and that is invisible unless somebody looks.
func TestSigningKeysNearbyFindsAKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "priv.hex")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found := SigningKeysNearby(dir)
	if len(found) != 1 || found[0] != key {
		t.Errorf("SigningKeysNearby = %v, want [%s]", found, key)
	}
}

func TestSigningKeysNearbyFindsFullLengthKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "signing.key")
	if err := os.WriteFile(key, []byte(strings.Repeat("cd", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(SigningKeysNearby(dir)) != 1 {
		t.Error("a 64-byte hex private key should be found")
	}
}

// It must not cry wolf over the ordinary contents of /etc/cau, or an operator
// learns to ignore it.
func TestSigningKeysNearbyIgnoresOrdinaryFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cau.conf", "siem = 10.0.0.5\nrespond = stop\n")
	write("integrity.json", `{"schema":2,"entries":[]}`)
	write("ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	write("notes.txt", "remember to rotate the key")
	write("empty", "")
	// Hex, but the wrong length for either key form.
	write("short.hex", "abcdef")
	if found := SigningKeysNearby(dir); len(found) != 0 {
		t.Errorf("SigningKeysNearby flagged ordinary files: %v", found)
	}
}

// A large file is never read, so the scan cannot be turned into a way to make
// the agent read something expensive.
func TestSigningKeysNearbyIgnoresLargeFiles(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.hex")
	if err := os.WriteFile(big, []byte(strings.Repeat("ab", maxKeyFileSize)), 0o644); err != nil {
		t.Fatal(err)
	}
	if found := SigningKeysNearby(dir); len(found) != 0 {
		t.Errorf("a file over the size bound should be skipped: %v", found)
	}
}

func TestSigningKeysNearbyToleratesMissingDir(t *testing.T) {
	if found := SigningKeysNearby("", filepath.Join(t.TempDir(), "absent")); len(found) != 0 {
		t.Errorf("a missing directory is not a finding: %v", found)
	}
}

// A FIFO reports a size of zero, so it passes a stat-based size check; an
// unbounded read then blocks forever on a writer that never comes. A named pipe
// called priv.hex in /etc/cau would hang the daemon at startup.
func TestSigningKeysNearbyDoesNotHangOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "priv.hex"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan []string, 1)
	go func() { done <- SigningKeysNearby(dir) }()
	select {
	case found := <-done:
		if len(found) != 0 {
			t.Errorf("a FIFO is not a signing key: %v", found)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SigningKeysNearby blocked on a FIFO: a named pipe in /etc/cau would hang the daemon at startup")
	}
}

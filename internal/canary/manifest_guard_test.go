package canary

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A manifest that parses is not a manifest that baselines anything: the same UID
// that owns the decoys owns this file, so an emptied one would silence every
// canary with no alert.
func TestReadManifestRejectsEmptyCanaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"canaries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path); err == nil {
		t.Error("accepted a manifest with an empty canaries list")
	}
	// The same JSON with the field absent is the same refusal.
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path); err == nil {
		t.Error("accepted a manifest with no canaries field")
	}
}

// The recorded modification time is part of the baseline, and the package
// documentation has always said Check detects a timestamp-only change.
func TestCheckDetectsTimestampOnlyChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, err := Plant(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	target := m.Canaries[0].Path
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	// Content and mode are untouched; only the timestamp moves.
	moved := before.ModTime().Add(-90 * time.Minute).UTC()
	if err := os.Chtimes(target, moved, moved); err != nil {
		t.Fatal(err)
	}
	r := Check(m)[0]
	if r.Status != StatusTimestampChanged {
		t.Fatalf("status = %s (%s), want timestamp-changed", r.Status, r.Detail)
	}
	if r.Detail == "" {
		t.Error("a timestamp change reported no detail")
	}
}

// The manifest is written by a privileged plant into a directory an attacker may
// reach, so the write must not follow a symlink planted at the destination.
func TestWriteManifestRefusesSymlinkDestination(t *testing.T) {
	work := t.TempDir()
	dest := filepath.Join(work, "canary.json")
	target := filepath.Join(work, "payload.txt")
	if err := os.WriteFile(target, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dest); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Version: manifestVersion, Canaries: []Canary{{Path: "/x", SHA256: "aa"}}}
	if err := WriteManifest(dest, m); err == nil {
		t.Fatal("wrote the manifest through a symlink")
	}
	// The link's target must be untouched, and the link must still be a link.
	if b, err := os.ReadFile(target); err != nil || string(b) != "precious\n" {
		t.Errorf("symlink target was modified: %q (%v)", b, err)
	}
	if fi, err := os.Lstat(dest); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("destination is no longer the symlink that was planted: %v", err)
	}
}

// The 0600 contract applies to an existing manifest too: a plain write's mode
// argument only takes effect when the file is created.
func TestWriteManifestFixesModeOfExistingFile(t *testing.T) {
	work := t.TempDir()
	dest := filepath.Join(work, "canary.json")
	if err := os.WriteFile(dest, []byte("old baseline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Version: manifestVersion, CreatedAt: time.Now().UTC(), Canaries: []Canary{{Path: "/x", SHA256: "aa"}}}
	if err := WriteManifest(dest, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
	got, err := ReadManifest(dest)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got.Canaries) != 1 || got.Canaries[0].Path != "/x" {
		t.Errorf("round-trip lost the entry: %+v", got)
	}
}

// A fresh write must land with the documented mode even under a permissive umask.
func TestWriteManifestCreatesMode0600(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "canary.json")
	m := &Manifest{Version: manifestVersion, Canaries: []Canary{{Path: "/x", SHA256: "aa"}}}
	if err := WriteManifest(dest, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
}

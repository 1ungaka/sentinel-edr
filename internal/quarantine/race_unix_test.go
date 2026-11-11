//go:build unix

package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// swapToSymlink is the attack the identity check refuses: the path named a
// regular file when it was read, and a link to a file the response may remove
// (a log, an index, a service's data) when the unlink lands.
func TestRemoveOriginalRefusesASwappedSymlink(t *testing.T) {
	work := t.TempDir()
	precious := writeSample(t, work, "precious.log", []byte("service log nobody may delete\n"), 0o644)
	suspect := writeSample(t, work, "suspect.bin", []byte("flagged bytes"), 0o644)

	data, info, err := safefs.ReadFileNoFollow(suspect, maxEntrySize)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The attacker's window: the name is taken away and replaced by a link.
	if err := os.Remove(suspect); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(precious, suspect); err != nil {
		t.Fatal(err)
	}

	err = removeOriginal(suspect, info, int64(len(data)))
	if !errors.Is(err, ErrPathChanged) {
		t.Fatalf("removeOriginal after a swap-to-symlink: err = %v, want ErrPathChanged", err)
	}
	// Nothing was unlinked: neither the link nor what it points at.
	for _, p := range []string{suspect, precious} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s is gone after the refusal: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(precious); string(b) != "service log nobody may delete\n" {
		t.Errorf("the link's target was damaged: %q", b)
	}
	if fi, _ := os.Lstat(suspect); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link itself was removed")
	}
}

// A rewrite in place keeps the inode and changes everything else. The vault
// holds the bytes that were read, so the file at the path now is not it.
func TestRemoveOriginalRefusesARewrittenFile(t *testing.T) {
	work := t.TempDir()
	p := writeSample(t, work, "changing.bin", []byte("first version"), 0o644)

	data, info, err := safefs.ReadFileNoFollow(p, maxEntrySize)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(p, []byte("a longer second version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOriginal(p, info, int64(len(data))); !errors.Is(err, ErrPathChanged) {
		t.Fatalf("removeOriginal after a rewrite: err = %v, want ErrPathChanged", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "a longer second version" {
		t.Errorf("the file was removed anyway: %q", b)
	}

	// A different file under the same name is refused for the same reason.
	other := writeSample(t, work, "other.bin", []byte("someone else's bytes"), 0o644)
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if err := removeOriginal(p, info, int64(len(data))); !errors.Is(err, ErrPathChanged) {
		t.Fatalf("removeOriginal after a replacement: err = %v, want ErrPathChanged", err)
	}
	if _, err := os.Lstat(p); err != nil {
		t.Errorf("the replacement was unlinked: %v", err)
	}
}

// The ordinary case still moves the file: identity holds and the name goes.
func TestRemoveOriginalUnlinksAnUnchangedFile(t *testing.T) {
	work := t.TempDir()
	p := writeSample(t, work, "quiet.bin", []byte("nothing changed"), 0o644)

	data, info, err := safefs.ReadFileNoFollow(p, maxEntrySize)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := removeOriginal(p, info, int64(len(data))); err != nil {
		t.Fatalf("removeOriginal: %v", err)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the original survived: %v", err)
	}
}

// The whole flow: a swap that lands between the read and the unlink must leave
// the target in place and say so, while the vault keeps the bytes it read.
func TestQuarantineReportsASwappedPathInsteadOfRemovingIt(t *testing.T) {
	work := t.TempDir()
	precious := writeSample(t, work, "audit.log", []byte("append-only audit data\n"), 0o644)
	suspect := writeSample(t, work, "dropper.bin", []byte("the flagged bytes"), 0o644)

	s, err := Open(filepath.Join(work, "vault"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	real := removeOriginal
	defer func() { removeOriginal = real }()
	removeOriginal = func(abs string, info os.FileInfo, size int64) error {
		// The attacker's window, reached from inside the call under test.
		if err := os.Remove(abs); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(precious, abs); err != nil {
			t.Fatal(err)
		}
		return real(abs, info, size)
	}

	e, err := s.Quarantine(suspect, "incident test: dropped by masquerade", false)
	if !errors.Is(err, ErrPathChanged) {
		t.Fatalf("quarantine after a swap: err = %v, want ErrPathChanged", err)
	}
	if !strings.Contains(err.Error(), "could not remove original") {
		t.Errorf("the report does not say what failed: %v", err)
	}
	// Nothing outside the vault was touched.
	for _, p := range []string{suspect, precious} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(precious); string(b) != "append-only audit data\n" {
		t.Errorf("the link's target was damaged: %q", b)
	}
	// The bytes that were read are still safely in the vault, with the entry
	// committed: refusing the unlink loses no evidence.
	if e.ID == "" {
		t.Fatal("no vault entry was recorded")
	}
	if err := s.Verify(e.ID); err != nil {
		t.Errorf("the stored entry does not verify: %v", err)
	}
	restored, err := s.Restore(e.ID, filepath.Join(work, "restored.bin"), false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if b, _ := os.ReadFile(restored); string(b) != "the flagged bytes" {
		t.Errorf("restored bytes = %q", b)
	}
}

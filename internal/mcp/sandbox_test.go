package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSandboxResolveWithinRoot(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "a.bin")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	real, size, err := sb.ResolveFile(f)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if size != 4 {
		t.Errorf("size = %d, want 4", size)
	}
	if real == "" {
		t.Error("empty real path")
	}
}

func TestSandboxRejectsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	outside := filepath.Join(other, "secret")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Resolve(outside); err == nil {
		t.Fatal("expected rejection of a path outside the root")
	}
}

func TestSandboxRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	root := t.TempDir()
	other := t.TempDir()
	target := filepath.Join(other, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	// The link lives inside the root, but resolves outside it: reject.
	if _, err := sb.Resolve(link); err == nil {
		t.Fatal("expected rejection of a symlink that escapes the root")
	}
}

func TestSandboxSizeCap(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "big")
	if err := os.WriteFile(f, make([]byte, 1024), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}, MaxBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sb.ResolveFile(f); err == nil {
		t.Fatal("expected size-cap rejection")
	}
}

func TestSandboxDirFileCap(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(root, string(rune('a'+i))), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: []string{root}, MaxDirFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sb.ResolveDir(root); err == nil {
		t.Fatal("expected dir-file-cap rejection")
	}
}

func TestSandboxNoRootsDisablesFileAccess(t *testing.T) {
	sb, _, err := NewSandbox(SandboxConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Resolve("/etc/passwd"); err == nil {
		t.Fatal("expected file access to be disabled with no roots")
	}
}

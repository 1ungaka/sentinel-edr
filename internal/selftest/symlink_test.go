package selftest

import (
	"os"
	"path/filepath"
	"testing"
)

// A symlinked rules directory used to digest as an empty tree, so the check
// passed whatever the rules became.
func TestDigestTreeFollowsASymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "a.yar"), []byte("rule a"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	viaLink, n, err := digestTree(link)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("digested %d file(s) through a symlinked root, want 1", n)
	}
	direct, _, err := digestTree(real)
	if err != nil {
		t.Fatal(err)
	}
	if viaLink != direct {
		t.Fatal("the same tree digests differently through a symlink")
	}
}

// The rule loader follows a link, so a link added to the tree has to move the
// digest, and so does repointing one.
func TestDigestTreeBindsSymlinks(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "a.yar"), []byte("rule a"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean, _, err := digestTree(tree)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tree, "evil.yar")
	if err := os.Symlink(filepath.Join(dir, "attacker-a"), link); err != nil {
		t.Skip(err)
	}
	withLink, _, err := digestTree(tree)
	if err != nil {
		t.Fatal(err)
	}
	if withLink == clean {
		t.Fatal("adding a symlink to the tree did not change the digest")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "attacker-b"), link); err != nil {
		t.Fatal(err)
	}
	repointed, _, err := digestTree(tree)
	if err != nil {
		t.Fatal(err)
	}
	if repointed == withLink {
		t.Fatal("repointing a symlink did not change the digest")
	}
}

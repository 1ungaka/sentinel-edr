package persist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The set-uid walk stops at a limit, and everything under it is then
// uninspected. A set-uid binary in that remainder would not be reported, so
// the tree has to be named as incomplete: a walk that stopped early and said
// nothing is a clean bill of health for a host nobody looked at.
func TestSUIDWalkLimitIsReportedAsIncomplete(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		name := filepath.Join(tmp, "f"+strings.Repeat("x", i)+".bin")
		if err := os.WriteFile(name, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a := &audit{root: root, maxWalk: 3, links: map[string]bool{}, unreadable: map[string]bool{}}
	a.checkSUID()
	if len(a.unreadable) == 0 {
		t.Fatal("the walk limit was not reported as incomplete coverage")
	}
	found := false
	for rel := range a.unreadable {
		if strings.Contains(rel, "tmp") {
			found = true
		}
	}
	if !found {
		t.Errorf("the incomplete path does not name the tree that was cut: %v", a.unreadable)
	}
}

// Below the limit the walk finishes and says nothing about coverage.
func TestSUIDWalkBelowTheLimitIsComplete(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "plain"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &audit{root: root, maxWalk: 100, links: map[string]bool{}, unreadable: map[string]bool{}}
	a.checkSUID()
	for rel := range a.unreadable {
		if strings.Contains(rel, "tmp") {
			t.Errorf("a walk that finished reported %q as incomplete", rel)
		}
	}
}

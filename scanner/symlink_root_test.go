package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// filepath.Walk lstats its root, so a root that is a symlink looks like a file
// and the walk ends without visiting anything. /bin, /sbin and /lib are symlinks
// on every merged-/usr host, so `cau scan /bin` scanned nothing and reported
// clean with exit 0.
func TestScanDirectoryFollowsASymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "payload"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}

	res, _ := (&Engine{}).ScanDirectory(link, nil)
	if len(res) != 1 {
		t.Fatalf("scanned %d file(s) through a symlinked root, want 1", len(res))
	}
}

// A link found during the walk stays unfollowed: only the root the caller named
// is resolved.
func TestScanDirectoryLeavesInnerSymlinksAlone(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	if res, _ := (&Engine{}).ScanDirectory(root, nil); len(res) != 0 {
		t.Fatalf("an inner symlink was followed: %+v", res)
	}
}

func TestCollectRuleFilesFollowsASymlinkedRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "a.yar"), []byte("rule a { condition: true }"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	files, err := collectRuleFiles(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("found %d rule file(s) through a symlinked rules dir, want 1", len(files))
	}
}

// A rule supplied as text comes from an MCP client, not from the operator's
// rules directory. include would read any file the server can, past the path
// sandbox every other file-touching tool goes through.
func TestInlineRuleTextCannotInclude(t *testing.T) {
	target := filepath.Join(t.TempDir(), "outside.yar")
	if err := os.WriteFile(target, []byte("rule from_outside { condition: true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	text := "include \"" + target + "\"\nrule inline { condition: true }\n"
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{Text: text, Name: "inline"}})
	if err == nil {
		defer ys.Close()
		if ys.RuleCount() != 0 {
			t.Fatalf("inline rule text pulled in a file through include: %d rule(s) compiled", ys.RuleCount())
		}
	}
}

// Includes on the operator's own rule files keep working.
func TestRuleFilesMayStillInclude(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "base.yara_inc"), []byte("rule base { condition: true }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.yar")
	if err := os.WriteFile(main, []byte("include \""+filepath.Join(dir, "base.yara_inc")+"\"\nrule top { condition: base }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{Path: main}})
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()
	if ys.RuleCount() != 2 {
		t.Fatalf("compiled %d rules from a rule file with an include, want 2", ys.RuleCount())
	}
}

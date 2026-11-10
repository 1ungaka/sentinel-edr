package behavior

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// behaviorTree builds a fake host: a process table, a systemd generator
// directory, a bpffs root and a package database that owns one of the
// libraries.
func behaviorTree(t *testing.T) (procRoot, root string) {
	t.Helper()
	root = t.TempDir()
	procRoot = filepath.Join(root, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	// A process whose environment loads an auditor library, and one whose
	// fanotify listener asks not to be told about some events.
	proc := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(filepath.Join(proc, "fd", "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proc, "fdinfo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "environ"),
		[]byte("PATH=/usr/bin\x00LD_PRELOAD=/tmp/rogue.so\x00HOME=/root\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "fdinfo", "7"),
		[]byte("pos:\t0\nflags:\t02000002\nmnt_id:\t29\nino:\t1234\nfanotify:\tgroup=1 mask=1f mark=1f ignored=8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "fd", "7", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// A package-owned process: its auditor library belongs to a package.
	owned := filepath.Join(procRoot, "4243")
	if err := os.MkdirAll(owned, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "environ"),
		[]byte("LD_AUDIT=/usr/lib/x86_64-linux-gnu/libaudit.so.1\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The generator directory and the bpffs root.
	gen := filepath.Join(root, "run", "systemd", "generator")
	if err := os.MkdirAll(gen, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gen, "late.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bpf := filepath.Join(root, "sys", "fs", "bpf")
	if err := os.MkdirAll(bpf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bpf, "cau_filter"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// The package database: one package owns the auditor library and one
	// owns a library the rogue process did not load.
	dpkg := filepath.Join(root, "var", "lib", "dpkg")
	if err := os.MkdirAll(filepath.Join(dpkg, "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Package: audit\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\nDescription: the audit library\n\n"
	if err := os.WriteFile(filepath.Join(dpkg, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(root, "usr", "lib", "x86_64-linux-gnu")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "libaudit.so.1"), []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dpkg, "info", "audit.list"),
		[]byte("/usr/lib/x86_64-linux-gnu/libaudit.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return procRoot, root
}

// The inventories are read and reported, and the package-owned library is
// not reported: the benign anchor is what makes the difference.
func TestTheInventoriesAreRead(t *testing.T) {
	procRoot, root := behaviorTree(t)
	res := Check(Options{ProcRoot: procRoot, Root: root})

	classes := map[string]int{}
	for _, f := range res.Findings {
		classes[f.Class]++
	}
	if classes[ClassAuditLibrary] != 1 {
		t.Errorf("audit-library findings = %d, want 1 (the package-owned one is the benign anchor): %+v", classes[ClassAuditLibrary], res.Findings)
	}
	if classes[ClassFanotify] != 1 {
		t.Errorf("fanotify findings = %d, want 1: %+v", classes[ClassFanotify], res.Findings)
	}
	if classes[ClassFanotifyMask] != 1 {
		t.Errorf("fanotify-mask findings = %d, want 1: %+v", classes[ClassFanotifyMask], res.Findings)
	}
	if classes[ClassGenerator] != 1 {
		t.Errorf("generator findings = %d, want 1: %+v", classes[ClassGenerator], res.Findings)
	}
	if classes[ClassBPFProgram] != 1 {
		t.Errorf("bpf findings = %d, want 1: %+v", classes[ClassBPFProgram], res.Findings)
	}
	if res.Provenance != "dpkg" {
		t.Errorf("the package manager = %q, want dpkg", res.Provenance)
	}
}

// A library a package owns is not reported: that is the benign anchor.
func TestAPackageOwnedLibraryIsNotReported(t *testing.T) {
	procRoot, root := behaviorTree(t)
	res := Check(Options{ProcRoot: procRoot, Root: root})
	for _, f := range res.Findings {
		if f.Class == ClassAuditLibrary && strings.Contains(f.Evidence, "4243") {
			t.Errorf("the package-owned auditor was reported: %+v", f)
		}
		if strings.Contains(f.Detail, "libaudit.so.1") {
			t.Errorf("the package-owned library was reported: %+v", f)
		}
	}
}

// Without a package database there is no benign anchor, and the result says so
// rather than presenting the inventories as clean.
func TestWithoutAPackageDatabaseTheAnchorIsNamed(t *testing.T) {
	procRoot, _ := behaviorTree(t)
	// A root with no package database under it.
	bare := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bare, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := Check(Options{ProcRoot: procRoot, Root: bare})
	if res.Provenance != "" {
		t.Errorf("the package manager = %q, want none", res.Provenance)
	}
	if len(res.Notes) == 0 {
		t.Error("the missing benign anchor was not noted")
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "benign anchor") {
		t.Errorf("the note does not say what is missing: %v", res.Notes)
	}
}

// The findings are sorted strongest first, so a report reads in order.
func TestTheFindingsAreSorted(t *testing.T) {
	procRoot, root := behaviorTree(t)
	res := Check(Options{ProcRoot: procRoot, Root: root})
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Score < res.Findings[i].Score {
			t.Fatalf("the findings are not sorted: %+v", res.Findings)
		}
	}
}

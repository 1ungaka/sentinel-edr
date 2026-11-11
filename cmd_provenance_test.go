package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// provenanceTestRoot builds a merged-/usr dpkg tree under a temp root with
// one intact binary, one modified ELF, one conffile and one unowned file,
// and returns the root and the files.
func provenanceTestRoot(t *testing.T) (root string, files []string) {
	t.Helper()
	root = t.TempDir()
	mk := func(rel string, data []byte) string {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sum := func(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	shippedLS := []byte("\x7fELF\x02\x01\x01\x00shipped")
	trojanLS := []byte("\x7fELF\x02\x01\x01\x00replaced by an attacker")
	conf := []byte("# shipped\n")
	mk("var/lib/dpkg/status", []byte("Package: coreutils\nStatus: install ok installed\nVersion: 9.4-3\n\nPackage: adduser\nStatus: install ok installed\nVersion: 3.1\nConffiles:\n /etc/adduser.conf "+sum(conf)+"\n\n"))
	mk("var/lib/dpkg/info/coreutils.list", []byte("/.\n/bin\n/bin/ls\n/bin/cat\n"))
	mk("var/lib/dpkg/info/coreutils.md5sums", []byte(sum(shippedLS)+"  usr/bin/ls\n"+sum(shippedLS)+"  usr/bin/cat\n"))
	mk("var/lib/dpkg/info/adduser.list", []byte("/.\n/etc\n/etc/adduser.conf\n"))
	files = append(files,
		mk("usr/bin/ls", shippedLS),
		mk("usr/bin/cat", trojanLS),
		mk("etc/adduser.conf", []byte("# edited\n")),
		mk("usr/local/bin/stray", []byte("nobody's")),
	)
	return root, files
}

func TestCLIScanProvenance(t *testing.T) {
	root, files := provenanceTestRoot(t)
	args := append([]string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--no-fuzzy", "--provenance", "--provenance-root", root, "--format", "json"}, files...)
	code, out, errOut := runCLI(t, args...)
	if code != report.ExitOK {
		t.Fatalf("exit %d, want 0 (provenance never moves the verdict)\nstderr:\n%s", code, errOut)
	}
	var doc struct {
		SchemaVersion string         `json:"schema_version"`
		Summary       map[string]any `json:"summary"`
		Files         []struct {
			Path       string `json:"path"`
			Verdict    string `json:"verdict"`
			Provenance *struct {
				Manager string `json:"manager"`
				Package string `json:"package"`
				Version string `json:"version"`
				State   string `json:"state"`
				Digest  string `json:"shipped_digest"`
				Algo    string `json:"digest_algo"`
				Finding *struct {
					Class     string `json:"class"`
					Technique string `json:"technique"`
					Kind      string `json:"kind"`
				} `json:"finding"`
			} `json:"provenance"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if doc.SchemaVersion != report.JSONSchemaVersion {
		t.Errorf("schema_version = %s", doc.SchemaVersion)
	}
	if doc.Summary["provenance_resolved"] != float64(4) || doc.Summary["provenance_modified_binaries"] != float64(1) {
		t.Errorf("summary: %v", doc.Summary)
	}
	want := map[string][3]string{ // base name -> manager, package, state
		"ls":           {"dpkg", "coreutils", "owned-intact"},
		"cat":          {"dpkg", "coreutils", "owned-modified"},
		"adduser.conf": {"dpkg", "adduser", "owned-conffile"},
		"stray":        {"dpkg", "", "unowned"},
	}
	seen := 0
	for _, f := range doc.Files {
		w, ok := want[filepath.Base(f.Path)]
		if !ok {
			continue
		}
		seen++
		if f.Provenance == nil {
			t.Errorf("%s: no provenance object", f.Path)
			continue
		}
		p := f.Provenance
		if p.Manager != w[0] || p.Package != w[1] || p.State != w[2] {
			t.Errorf("%s: provenance = %+v, want %v", f.Path, *p, w)
		}
		if f.Verdict != "clean" {
			t.Errorf("%s: verdict = %s, want clean", f.Path, f.Verdict)
		}
		switch filepath.Base(f.Path) {
		case "cat":
			if p.Finding == nil || p.Finding.Class != "provenance.modified-system-binary" || p.Finding.Technique != "T1554" || p.Finding.Kind != "elf" {
				t.Errorf("cat: finding = %+v", p.Finding)
			}
			if p.Algo != "md5" || p.Digest == "" {
				t.Errorf("cat: digest %s/%s", p.Algo, p.Digest)
			}
		case "ls":
			if p.Version != "9.4-3" || p.Algo != "md5" {
				t.Errorf("ls: %+v", *p)
			}
		}
	}
	if seen != 4 {
		t.Errorf("saw %d of 4 files", seen)
	}

	// Text output names the database and the observation.
	code, out, _ = runCLI(t, append([]string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--no-fuzzy", "--provenance", "--provenance-root", root}, files...)...)
	if code != report.ExitOK {
		t.Fatalf("text: exit %d", code)
	}
	for _, w := range []string{
		"provenance: dpkg coreutils 9.4-3 (intact, per the host's dpkg database)",
		"provenance: dpkg coreutils 9.4-3 (MODIFIED: shipped md5",
		"[OBS] provenance.modified-system-binary",
		"provenance: dpkg adduser 3.1 (conffile",
		"provenance: no package owns this path, per the host's dpkg database",
		"Provenance resolved   : 4 (modified package binaries: 1, observations only)",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("text report lacks %q:\n%s", w, out)
		}
	}

	// Without the flag nothing about provenance appears.
	_, out, _ = runCLI(t, append([]string{"scan", "--quiet", "--db", smokeDB, "--no-yara", "--no-fuzzy", "--format", "json"}, files...)...)
	if strings.Contains(out, "provenance") {
		t.Error("report mentions provenance without --provenance")
	}
}

// A root with no package database: every file is "unknown", the scan still
// succeeds, and the operator is told.
func TestCLIScanProvenanceNoDatabase(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "x.bin")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "scan", "--db", smokeDB, "--no-yara", "--no-fuzzy", "--provenance", "--provenance-root", root, "--format", "json", f)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if !strings.Contains(out, `"provenance":{"state":"unknown"}`) {
		t.Errorf("want state unknown:\n%s", out)
	}
	if !strings.Contains(errOut, "no package database found") {
		t.Errorf("stderr should say no database was found:\n%s", errOut)
	}
}

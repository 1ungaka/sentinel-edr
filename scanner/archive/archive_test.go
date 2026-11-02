package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

// ── builders ─────────────────────────────────────────────────────────────────

type zipEntry struct {
	name string
	data []byte
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("zip create %q: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("zip write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildTar(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipOf(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Name = name
	if _, err := gw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// setEncryptedBit flips the general-purpose "encrypted" flag (bit 0) in every
// central-directory header so zip.NewReader reports the entries as encrypted.
func setEncryptedBit(data []byte) {
	sig := []byte{'P', 'K', 0x01, 0x02}
	for i := 0; i+10 < len(data); i++ {
		if bytes.Equal(data[i:i+4], sig) {
			data[i+8] |= 0x01
		}
	}
}

func mz(n int) []byte {
	b := make([]byte, n)
	b[0], b[1] = 'M', 'Z'
	return b
}

func has(r *Result, class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

// ── helper-level tests ───────────────────────────────────────────────────────

func TestPathEscapes(t *testing.T) {
	bad := []string{"../x", "a/../../etc/passwd", "/etc/passwd", "C:\\windows\\x", "a\\..\\b"}
	for _, n := range bad {
		if !pathEscapes(n) {
			t.Errorf("%q should escape", n)
		}
	}
	for _, n := range []string{"a/b/c", "dir/file.txt", "./rel/ok"} {
		if pathEscapes(n) {
			t.Errorf("%q should not escape", n)
		}
	}
}

func TestDoubleExtensionLure(t *testing.T) {
	for _, n := range []string{"invoice.pdf.exe", "photo.jpg.scr", "report.docx.js", "a/b/statement.pdf.vbs"} {
		if !doubleExtensionLure(n) {
			t.Errorf("%q should be a lure", n)
		}
	}
	for _, n := range []string{"setup.exe", "archive.tar.gz", "notes.txt", "lib.so.6", "x.pdf"} {
		if doubleExtensionLure(n) {
			t.Errorf("%q should not be a lure", n)
		}
	}
}

func TestExtAndMagicKind(t *testing.T) {
	if extKind("a.exe") != kindExecutable || extKind("a.vbs") != kindScript || extKind("a.txt") != kindOther {
		t.Error("extKind wrong")
	}
	if magicKind([]byte("MZ...")) != kindExecutable {
		t.Error("MZ magic")
	}
	if magicKind([]byte{0x7f, 'E', 'L', 'F'}) != kindExecutable {
		t.Error("ELF magic")
	}
	if magicKind([]byte("#!/bin/sh")) != kindScript {
		t.Error("shebang")
	}
	if magicKind([]byte("plain text")) != kindOther {
		t.Error("text should be other")
	}
}

func TestBombLogicViaCollector(t *testing.T) {
	// Ratio path: 100x and over the absolute floor.
	c := &collector{format: "zip", members: 1, compressed: 1 << 20, uncompressed: 200 << 20}
	r := &Result{}
	c.result(r)
	if !has(r, "archive.bomb") {
		t.Errorf("expected bomb for 200x over floor: %+v", r.Findings)
	}
	// High ratio but tiny absolute size is NOT a bomb.
	c2 := &collector{format: "zip", members: 1, compressed: 100, uncompressed: 1 << 20}
	r2 := &Result{}
	c2.result(r2)
	if has(r2, "archive.bomb") {
		t.Errorf("small absolute size must not be a bomb: %+v", r2.Findings)
	}
}

// ── integration tests ────────────────────────────────────────────────────────

func TestBenignZipScoresZero(t *testing.T) {
	data := buildZip(t, []zipEntry{
		{"src/main.go", []byte("package main\nfunc main() {}\n")},
		{"README.md", []byte("# project\n")},
		{"data/values.csv", []byte("a,b,c\n1,2,3\n")},
	})
	r := Analyze(data, Options{})
	if r.Score != 0 {
		t.Errorf("benign zip scored %d: %+v", r.Score, r.Findings)
	}
	if r.Parsed == nil || r.Parsed.Members != 3 {
		t.Errorf("summary = %+v", r.Parsed)
	}
}

func TestSingleExecutableZip(t *testing.T) {
	data := buildZip(t, []zipEntry{{"payload.exe", mz(64)}})
	r := Analyze(data, Options{})
	if !has(r, "archive.single-executable") {
		t.Fatalf("expected single-executable: %+v", r.Findings)
	}
	if r.Score != scoreSingleExec {
		t.Errorf("score = %d, want %d", r.Score, scoreSingleExec)
	}
}

func TestDoubleExtensionLureZip(t *testing.T) {
	data := buildZip(t, []zipEntry{{"invoice.pdf.exe", mz(64)}})
	r := Analyze(data, Options{})
	if !has(r, "archive.lure-double-extension") {
		t.Fatalf("expected lure: %+v", r.Findings)
	}
	if !r.Detected() {
		t.Errorf("a .pdf.exe lure should cross the threshold; score %d", r.Score)
	}
}

func TestPathTraversalZip(t *testing.T) {
	data := buildZip(t, []zipEntry{
		{"ok.txt", []byte("x")},
		{"../../etc/cron.d/evil", []byte("* * * * * root sh\n")},
	})
	r := Analyze(data, Options{})
	if !has(r, "archive.path-traversal") {
		t.Fatalf("expected path-traversal: %+v", r.Findings)
	}
}

func TestExecutableAndNestedMembers(t *testing.T) {
	data := buildZip(t, []zipEntry{
		{"readme.txt", []byte("hi")},
		{"tool.exe", mz(32)},
		{"bundle.zip", []byte("PK\x03\x04nested")},
	})
	r := Analyze(data, Options{})
	if !has(r, "archive.executable-member") {
		t.Errorf("expected executable-member: %+v", r.Findings)
	}
	if !has(r, "archive.nested-archive") {
		t.Errorf("expected nested-archive: %+v", r.Findings)
	}
	if has(r, "archive.single-executable") {
		t.Error("multi-member archive must not be single-executable")
	}
}

func TestMagicDetectedExecutableNoExtension(t *testing.T) {
	// A member with a benign name but MZ content, alongside a data file.
	data := buildZip(t, []zipEntry{
		{"notes.txt", []byte("hello")},
		{"image.dat", mz(128)},
	})
	r := Analyze(data, Options{})
	if r.Parsed.Executables != 1 {
		t.Errorf("magic-based executable not counted: %+v", r.Parsed)
	}
}

func TestEncryptedZip(t *testing.T) {
	data := buildZip(t, []zipEntry{{"secret.exe", mz(64)}})
	setEncryptedBit(data)
	r := Analyze(data, Options{})
	if !has(r, "archive.encrypted-entry") {
		t.Fatalf("expected encrypted-entry: %+v", r.Findings)
	}
	// Encrypted single .exe (name still visible) is the malspam profile.
	if !has(r, "archive.single-executable") || !r.Detected() {
		t.Errorf("encrypted single exe should cross the threshold: %+v (score %d)", r.Findings, r.Score)
	}
}

func TestBenignTar(t *testing.T) {
	data := buildTar(t, []zipEntry{
		{"./project/main.c", []byte("int main(){}\n")},
		{"./project/Makefile", []byte("all:\n\tcc main.c\n")},
	})
	if !isTar(data) {
		t.Fatal("isTar false on a real tar")
	}
	r := Analyze(data, Options{})
	if r.Score != 0 {
		t.Errorf("benign tar scored %d: %+v", r.Score, r.Findings)
	}
}

func TestTarExecutableMember(t *testing.T) {
	data := buildTar(t, []zipEntry{
		{"doc.txt", []byte("readme")},
		{"run", mz(64)}, // no extension, MZ magic
	})
	r := Analyze(data, Options{})
	if r.Parsed.Executables != 1 {
		t.Errorf("tar executable not detected: %+v", r.Parsed)
	}
}

func TestTarGz(t *testing.T) {
	tarData := buildTar(t, []zipEntry{
		{"a.txt", []byte("one")},
		{"b.sh", []byte("#!/bin/sh\necho hi\n")},
	})
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write(tarData)
	gw.Close()
	r := Analyze(gz.Bytes(), Options{})
	if r.Parsed == nil || r.Parsed.Format != "tar.gz" {
		t.Fatalf("expected tar.gz enumeration: %+v", r.Parsed)
	}
	if r.Parsed.Members != 2 {
		t.Errorf("members = %d, want 2", r.Parsed.Members)
	}
}

func TestGzipSingleExecutable(t *testing.T) {
	data := gzipOf(t, "payload", mz(256))
	if !isGzip(data) {
		t.Fatal("isGzip false")
	}
	r := Analyze(data, Options{})
	if r.Parsed == nil || r.Parsed.Format != "gzip" {
		t.Fatalf("parsed = %+v", r.Parsed)
	}
	if r.Parsed.Executables != 1 {
		t.Errorf("gzip of an MZ should classify as executable: %+v", r.Parsed)
	}
}

func TestNonArchiveIsInert(t *testing.T) {
	r := Analyze([]byte("just some text, not an archive"), Options{})
	if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
		t.Errorf("non-archive produced output: %+v", r)
	}
	if IsArchive([]byte("hello")) {
		t.Error("IsArchive true on plain text")
	}
}

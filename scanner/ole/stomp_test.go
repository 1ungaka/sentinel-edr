package ole

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// ── synthetic dir stream / module stream builders ──────────────────────────────
//
// These build TEST DATA for a consistency check: a dir stream that declares
// modules, and module streams whose bytes before TextOffset are an opaque
// filler standing in for the PerformanceCache. The filler is not p-code and
// nothing here compiles, runs or could be opened as a working macro.

type dirMod struct {
	name     string
	stream   string // "" => same as name
	offset   uint32
	doc      bool // document module (0x0022) rather than procedural (0x0021)
	noOffset bool // omit the MODULEOFFSET record
	mbcsOnly bool // omit the unicode name records
}

func rec(id uint16, data []byte) []byte {
	out := make([]byte, 6, 6+len(data))
	binary.LittleEndian.PutUint16(out, id)
	binary.LittleEndian.PutUint32(out[2:], uint32(len(data)))
	return append(out, data...)
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func utf16le(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

// dirRecords returns a DECOMPRESSED dir stream declaring mods.
func dirRecords(mods ...dirMod) []byte {
	var b []byte
	b = append(b, rec(0x0001, u32(1))...)         // PROJECTSYSKIND
	b = append(b, rec(0x0002, u32(0x0409))...)    // PROJECTLCID
	b = append(b, rec(0x0014, u32(0x0409))...)    // PROJECTLCIDINVOKE
	b = append(b, rec(0x0003, u16(1252))...)      // PROJECTCODEPAGE
	b = append(b, rec(0x0004, []byte("Proj"))...) // PROJECTNAME
	// PROJECTVERSION: Size says 4, six bytes of data follow.
	b = append(b, u16(0x0009)...)
	b = append(b, u32(4)...)
	b = append(b, u32(0x5F3A1C2B)...)
	b = append(b, u16(7)...)
	b = append(b, rec(0x000F, u16(uint16(len(mods))))...) // PROJECTMODULES
	b = append(b, rec(0x0013, u16(0xFFFF))...)            // PROJECTCOOKIE
	for _, m := range mods {
		stream := m.stream
		if stream == "" {
			stream = m.name
		}
		b = append(b, rec(0x0019, []byte(m.name))...)
		if !m.mbcsOnly {
			b = append(b, rec(0x0047, utf16le(m.name))...)
		}
		b = append(b, rec(0x001A, []byte(stream))...)
		if !m.mbcsOnly {
			b = append(b, rec(0x0032, utf16le(stream))...)
		}
		if !m.noOffset {
			b = append(b, rec(0x0031, u32(m.offset))...)
		}
		b = append(b, rec(0x001E, u32(0))...)      // MODULEHELPCONTEXT
		b = append(b, rec(0x002C, u16(0xFFFF))...) // MODULECOOKIE
		if m.doc {
			b = append(b, rec(0x0022, nil)...)
		} else {
			b = append(b, rec(0x0021, nil)...)
		}
		b = append(b, rec(0x002B, nil)...) // module terminator
	}
	b = append(b, rec(0x0010, nil)...) // dir terminator
	return b
}

func dirStream(mods ...dirMod) []byte { return compressVBA(dirRecords(mods...)) }

// filler returns n opaque bytes: all in 0x80..0xF7, so no printable run, no
// 0x00 and no 0x01 container signature can arise from it by accident.
func filler(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0x80 | byte((i*37)%120)
	}
	return b
}

// pcodeRegion returns n filler bytes with the given byte strings laid over it
// at spaced offsets (each preceded and followed by filler).
func pcodeRegion(n int, runs ...[]byte) []byte {
	b := filler(n)
	at := 64
	for _, r := range runs {
		if at+len(r)+8 > n {
			panic("pcodeRegion: runs do not fit")
		}
		copy(b[at:], r)
		at += len(r) + 40
	}
	return b
}

const (
	attrOnly  = "Attribute VB_Name = \"ThisDocument\"\r\nAttribute VB_Base = \"1Normal.ThisDocument\"\r\nAttribute VB_GlobalNameSpace = False\r\n\r\n"
	benignSrc = "Attribute VB_Name = \"Module1\"\r\nSub Tidy()\r\n    Dim n As Long\r\n    n = n + 1\r\nEnd Sub\r\n"
	spawnSrc  = "Attribute VB_Name = \"Module1\"\r\nSub Run()\r\n    Set o = CreateObject(\"WScript.Shell\")\r\nEnd Sub\r\n"
)

// vbaProjectStream is a _VBA_PROJECT header followed by filler and the given
// names, standing in for the project-wide identifier table.
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

// vbaDoc assembles Macros/VBA/{dir,_VBA_PROJECT,<modules>}.
func vbaDoc(project []byte, mods []dirMod, streams map[string][]byte) []byte {
	entries := []oleEntry{
		{name: "Macros", storage: true},
		{name: "VBA", storage: true, in: "Macros"},
		{name: "dir", in: "VBA", content: dirStream(mods...)},
	}
	if project != nil {
		entries = append(entries, oleEntry{name: "_VBA_PROJECT", in: "VBA", content: project})
	}
	for _, m := range mods {
		name := m.stream
		if name == "" {
			name = m.name
		}
		if c, ok := streams[name]; ok {
			entries = append(entries, oleEntry{name: name, in: "VBA", content: c})
		}
	}
	return buildCFB(entries...)
}

// dirEntryBase returns the byte offset of directory entry index i in a file
// produced by buildCFB (whose directory is one contiguous region).
func dirEntryBase(file []byte, i int) int {
	dirStart := binary.LittleEndian.Uint32(file[48:])
	return (int(dirStart)+1)*512 + i*128
}

func stompClasses(r *Result) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		if f.Technique == techStomping {
			out[f.Class] = f
		}
	}
	return out
}

func onlyModule(t *testing.T, r *Result) ModuleInfo {
	t.Helper()
	if r.Parsed == nil || len(r.Parsed.VBAProjects) != 1 || len(r.Parsed.VBAProjects[0].Modules) != 1 {
		t.Fatalf("expected one project with one module, got %+v", r.Parsed)
	}
	return r.Parsed.VBAProjects[0].Modules[0]
}

// ── dir parser ─────────────────────────────────────────────────────────────────

func TestParseVBADir(t *testing.T) {
	d := parseVBADir(dirRecords(
		dirMod{name: "ThisDocument", offset: 813, doc: true},
		dirMod{name: "Module1", stream: "Module1Stream", offset: 4343},
	))
	if !d.terminated || d.truncated {
		t.Fatalf("well-formed dir: terminated=%v truncated=%v", d.terminated, d.truncated)
	}
	if d.declared != 2 || len(d.modules) != 2 {
		t.Fatalf("declared=%d parsed=%d, want 2/2", d.declared, len(d.modules))
	}
	if d.codePage != 1252 || !d.hasVersion || d.versionMajor != 0x5F3A1C2B || d.versionMinor != 7 {
		t.Fatalf("project info: %+v", d)
	}
	m0, m1 := d.modules[0], d.modules[1]
	if m0.name != "ThisDocument" || m0.streamName != "ThisDocument" || m0.textOffset != 813 || m0.moduleType != recModuleTypeDoc {
		t.Fatalf("module 0: %+v", m0)
	}
	if m1.name != "Module1" || m1.streamName != "Module1Stream" || m1.textOffset != 4343 || !m1.hasOffset || m1.moduleType != recModuleTypeProc {
		t.Fatalf("module 1: %+v", m1)
	}

	// MBCS-only names are kept, non-ASCII bytes rendered as '?'.
	d = parseVBADir(dirRecords(dirMod{name: "Mod\xE9", offset: 9, mbcsOnly: true}))
	if len(d.modules) != 1 || d.modules[0].name != "Mod?" || !d.modules[0].nameIsMBCS {
		t.Fatalf("MBCS-only module: %+v", d.modules)
	}

	// A module with no MODULEOFFSET record is kept, without an offset.
	d = parseVBADir(dirRecords(dirMod{name: "M", noOffset: true}))
	if len(d.modules) != 1 || d.modules[0].hasOffset {
		t.Fatalf("no-offset module: %+v", d.modules)
	}
}

func TestParseVBADirHostile(t *testing.T) {
	good := dirRecords(dirMod{name: "Module1", offset: 100})

	// Every truncation point parses without panicking, never yields more than
	// the one module, and is reported truncated unless it stops on a record
	// boundary.
	for n := 0; n < len(good); n++ {
		d := parseVBADir(good[:n])
		if len(d.modules) > 1 || d.terminated {
			t.Fatalf("truncated at %d: %+v", n, d)
		}
	}

	// A record claiming more bytes than remain ends the parse cleanly.
	over := append([]byte(nil), rec(recModuleName, []byte("A"))...)
	over = append(over, u16(recModuleOffset)...)
	over = append(over, u32(0xFFFFFFF0)...)
	over = append(over, 1, 2, 3, 4)
	d := parseVBADir(over)
	if !d.truncated || d.terminated {
		t.Fatalf("oversized record: truncated=%v terminated=%v", d.truncated, d.terminated)
	}
	if len(d.modules) != 1 || d.modules[0].hasOffset {
		t.Fatalf("oversized record must not yield an offset: %+v", d.modules)
	}

	// PROJECTVERSION cut short.
	short := append(u16(recProjectVersion), u32(4)...)
	short = append(short, 1, 2, 3)
	if d := parseVBADir(short); !d.truncated || d.hasVersion {
		t.Fatalf("short PROJECTVERSION: %+v", d)
	}

	// More module records than the cap: the cap holds and the parse says so.
	var many []byte
	for i := 0; i < maxDirModules+50; i++ {
		many = append(many, rec(recModuleName, []byte("M"))...)
		many = append(many, rec(recModuleTerminator, nil)...)
	}
	many = append(many, rec(recDirTerminator, nil)...)
	d = parseVBADir(many)
	if len(d.modules) != maxDirModules || !d.truncated {
		t.Fatalf("module cap: %d modules, truncated=%v", len(d.modules), d.truncated)
	}

	// More records than the record cap.
	var flood []byte
	for i := 0; i < maxDirRecords+10; i++ {
		flood = append(flood, rec(0x0099, nil)...)
	}
	d = parseVBADir(flood)
	if d.records != maxDirRecords || !d.truncated {
		t.Fatalf("record cap: %d records, truncated=%v", d.records, d.truncated)
	}

	// Over-long names are cut at the name cap.
	long := rec(recModuleName, bytes.Repeat([]byte("N"), 5000))
	long = append(long, rec(recModuleStreamNameU, utf16le(strings.Repeat("S", 5000)))...)
	long = append(long, rec(recDirTerminator, nil)...)
	d = parseVBADir(long)
	if len(d.modules) != 1 || len(d.modules[0].name) != maxVBANameBytes || len(d.modules[0].streamName) != maxVBANameBytes/2 {
		t.Fatalf("name cap: name %d bytes, stream %d bytes", len(d.modules[0].name), len(d.modules[0].streamName))
	}

	if d := parseVBADir(nil); len(d.modules) != 0 || d.truncated || d.declared != -1 {
		t.Fatalf("empty dir: %+v", d)
	}
}

func TestVBAProjectVersion(t *testing.T) {
	if v, ok := vbaProjectVersion(vbaProjectStream(0x00B2)); !ok || v != 0x00B2 {
		t.Fatalf("version = %#x, %v", v, ok)
	}
	if _, ok := vbaProjectVersion([]byte{0xCC, 0x61, 0x01}); ok {
		t.Fatal("short header accepted")
	}
	if _, ok := vbaProjectVersion([]byte{0x00, 0x00, 0xB2, 0x00, 0x00, 0xFF, 0xFF}); ok {
		t.Fatal("wrong Reserved1 accepted")
	}
}

// ── small pieces ───────────────────────────────────────────────────────────────

func TestSourceIsBlank(t *testing.T) {
	blank := []string{
		"",
		"\r\n\r\n",
		attrOnly,
		"  attribute vb_name = \"x\"\n\t\n",
		"Attribute VB_Name = \"x\"\rAttribute VB_Exposed = False",
	}
	for _, s := range blank {
		if !sourceIsBlank([]byte(s)) {
			t.Errorf("not blank: %q", s)
		}
	}
	code := []string{
		benignSrc,
		"Attribute VB_Name = \"x\"\r\n' a comment\r\n",
		"Attributes = 1\r\n",
		"x",
	}
	for _, s := range code {
		if sourceIsBlank([]byte(s)) {
			t.Errorf("blank: %q", s)
		}
	}
}

func TestPrintableRuns(t *testing.T) {
	b := pcodeRegion(600, []byte("WScript.Shell"), utf16le("AutoOpen"), []byte("abc"))
	orig := append([]byte(nil), b...)
	runs := printableRuns(b)
	if !bytes.Equal(b, orig) {
		t.Fatal("printableRuns wrote to its input")
	}
	lines := strings.Split(strings.TrimSpace(runs), "\n")
	want := map[string]bool{"wscript.shell": false, "autoopen": false}
	for _, l := range lines {
		if _, ok := want[l]; ok {
			want[l] = true
		}
		if l == "abc" {
			t.Fatalf("a run under %d characters was kept", minPCodeRun)
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("run %q not extracted; got %q", k, lines)
		}
	}
	if printableRuns(filler(4096)) != "" {
		t.Fatal("filler produced a printable run")
	}
}

// ── blue / red pairs ───────────────────────────────────────────────────────────

func TestStomping(t *testing.T) {
	// Each stream is the p-code stand-in followed by whatever sits at
	// TextOffset. buildCFB zero-pads short streams to 4096 bytes.
	mod := func(pcode []byte, tail []byte) []byte { return append(append([]byte(nil), pcode...), tail...) }
	one := func(offset uint32, stream []byte, project []byte) []byte {
		return vbaDoc(project, []dirMod{{name: "Module1", offset: offset}}, map[string][]byte{"Module1": stream})
	}

	cases := []struct {
		name         string
		data         []byte
		want         []string // stomping classes that must fire (and no others)
		wantState    string   // source state of the single module ("" = skip)
		wantDetected bool
		wantScore    int
	}{
		// ── blue: consistent modules ──
		{
			name:      "blue: source present, p-code strings accounted for",
			data:      one(3000, mod(pcodeRegion(3000, []byte("WScript.Shell"), []byte("CreateObject")), compressVBA([]byte(spawnSrc))), nil),
			wantState: srcPresent,
			// project 2 + ole.exec.shell 4 + late-binding 3, from the SOURCE rules.
			wantDetected: true, wantScore: 9,
		},
		{
			name:      "blue: empty module, Attribute-only source over a small p-code region",
			data:      one(917, mod(pcodeRegion(917), compressVBA([]byte(attrOnly))), nil),
			wantState: srcBlank, wantScore: 2,
		},
		{
			name: "blue: Attribute-only source of a module hosting controls",
			data: one(3000, mod(pcodeRegion(3000), compressVBA([]byte(
				attrOnly+"Attribute VB_Control = \"CommandButton1, 1, 0, MSForms, CommandButton\"\r\n"))), nil),
			wantState: srcBlank, wantScore: 2,
		},
		{
			name:      "blue: no source and no p-code either (stream of nothing)",
			data:      one(300, mod(pcodeRegion(300), nil), nil),
			wantState: srcMissing, wantScore: 2,
		},
		{
			name: "blue: leftover identifier in _VBA_PROJECT, every source present",
			data: one(3000, mod(pcodeRegion(3000), compressVBA([]byte(benignSrc))),
				vbaProjectStream(0x00B2, "Shell", "AutoOpen")),
			wantState: srcPresent, wantScore: 2,
		},

		// ── red: source missing ──
		{
			name:      "red: TextOffset beyond the end of the stream",
			data:      one(6000, pcodeRegion(5000), nil),
			want:      []string{"ole.vba.stomp.source-missing"},
			wantState: srcMissing, wantScore: 2 + weightStompMissing,
		},
		{
			name:      "red: TextOffset exactly at the end of the stream",
			data:      one(5000, pcodeRegion(5000), nil),
			want:      []string{"ole.vba.stomp.source-missing"},
			wantState: srcMissing, wantScore: 2 + weightStompMissing,
		},
		{
			name:      "red: no CompressedContainer at TextOffset (overwritten)",
			data:      one(3000, mod(pcodeRegion(3000), filler(400)), nil),
			want:      []string{"ole.vba.stomp.source-missing"},
			wantState: srcMissing, wantScore: 2 + weightStompMissing,
		},
		{
			name:      "red: no CompressedContainer at TextOffset (zeroed)",
			data:      one(3000, mod(pcodeRegion(3000), nil), nil),
			want:      []string{"ole.vba.stomp.source-missing"},
			wantState: srcMissing, wantScore: 2 + weightStompMissing,
		},
		{
			name: "red: no source, and the p-code strings name what ran",
			data: one(3000, mod(pcodeRegion(3000, []byte("WScript.Shell")), nil),
				vbaProjectStream(0x00B2, "AutoOpen", "CreateObject")),
			want:      []string{"ole.vba.stomp.source-missing", "ole.vba.stomp.mismatch"},
			wantState: srcMissing, wantDetected: true,
			wantScore: 2 + weightStompMissing + weightStompMismatch,
		},
		{
			name: "red: no source, identifiers only in the project-wide table",
			data: one(3000, mod(pcodeRegion(3000), nil),
				vbaProjectStream(0x00B2, "Document_Open", "Shell")),
			want:      []string{"ole.vba.stomp.source-missing", "ole.vba.stomp.mismatch"},
			wantState: srcMissing, wantDetected: true,
			wantScore: 2 + weightStompMissing + weightStompMismatch,
		},

		// ── red: source blank ──
		{
			name:      "red: Attribute-only source over a substantial p-code region",
			data:      one(3000, mod(pcodeRegion(3000), compressVBA([]byte(attrOnly))), nil),
			want:      []string{"ole.vba.stomp.source-blank"},
			wantState: srcBlank, wantScore: 2 + weightStompBlank,
		},
		{
			name: "red: Attribute-only source, p-code strings name what ran",
			data: one(3000, mod(pcodeRegion(3000, utf16le("powershell -nop")), compressVBA([]byte(attrOnly))),
				vbaProjectStream(0x00B2, "AutoOpen")),
			want:      []string{"ole.vba.stomp.source-blank", "ole.vba.stomp.mismatch"},
			wantState: srcBlank, wantDetected: true,
			wantScore: 2 + weightStompBlank + weightStompMismatch,
		},

		// ── red: mismatch (the weak one, alone) ──
		{
			name:      "red: harmless source, p-code string names a primitive it lacks",
			data:      one(3000, mod(pcodeRegion(3000, []byte("WScript.Shell")), compressVBA([]byte(benignSrc))), nil),
			want:      []string{"ole.vba.stomp.mismatch"},
			wantState: srcPresent, wantScore: 2 + weightStompMismatch,
		},
		{
			name:      "red: same, UTF-16 run",
			data:      one(3000, mod(pcodeRegion(3000, utf16le("URLDownloadToFileA")), compressVBA([]byte(benignSrc))), nil),
			want:      []string{"ole.vba.stomp.mismatch"},
			wantState: srcPresent, wantScore: 2 + weightStompMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := append([]byte(nil), tc.data...)
			r := Analyze(tc.data, Options{})
			if !bytes.Equal(orig, tc.data) {
				t.Fatal("Analyze wrote to its input")
			}
			got := stompClasses(r)
			if len(got) != len(tc.want) {
				t.Fatalf("stomping classes = %v, want %v (findings %+v)", got, tc.want, r.Findings)
			}
			for _, c := range tc.want {
				f, ok := got[c]
				if !ok {
					t.Fatalf("missing class %q; findings %+v", c, r.Findings)
				}
				if f.Technique != techStomping || f.Evidence == "" || f.Score <= 0 {
					t.Fatalf("class %q: %+v", c, f)
				}
			}
			if tc.wantState != "" {
				if m := onlyModule(t, r); m.SourceState != tc.wantState {
					t.Fatalf("source state = %q, want %q (%+v)", m.SourceState, tc.wantState, m)
				}
			}
			if r.Score != tc.wantScore {
				t.Fatalf("score = %d, want %d (findings %+v)", r.Score, tc.wantScore, r.Findings)
			}
			if r.Detected() != tc.wantDetected {
				t.Fatalf("Detected() = %v, want %v (score %d)", r.Detected(), tc.wantDetected, r.Score)
			}
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

// The weights must keep the three stated properties.
func TestStompWeights(t *testing.T) {
	if weightVBAProject+weightStompMismatch >= DefaultThreshold {
		t.Fatal("a lone string-run mismatch reaches the threshold")
	}
	if weightStompMismatch >= weightStompBlank || weightStompMismatch >= weightStompMissing {
		t.Fatal("mismatch must be the weakest stomping class")
	}
	if weightVBAProject+weightStompMissing+weightStompMismatch < DefaultThreshold {
		t.Fatal("no source + corroborating strings does not reach the threshold")
	}
	if weightVBAProject+weightStompBlank+weightStompMismatch < DefaultThreshold {
		t.Fatal("blank source + corroborating strings does not reach the threshold")
	}
}

func TestStompCatalog(t *testing.T) {
	want := map[string]int{
		"ole.vba.stomp.source-missing": weightStompMissing,
		"ole.vba.stomp.source-blank":   weightStompBlank,
		"ole.vba.stomp.mismatch":       weightStompMismatch,
	}
	for _, c := range Classes() {
		w, ok := want[c.Class]
		if !ok {
			continue
		}
		if c.Technique != "T1564.007" || c.Weight != w {
			t.Fatalf("catalog entry %+v", c)
		}
		if c.Class == "ole.vba.stomp.mismatch" && !strings.Contains(c.Description, "heuristic over string runs, not a p-code disassembly") {
			t.Fatalf("mismatch description must say what it is: %q", c.Description)
		}
		delete(want, c.Class)
	}
	if len(want) != 0 {
		t.Fatalf("classes not in the catalog: %v", want)
	}
}

// ── what the result surfaces ───────────────────────────────────────────────────

func TestStompParsedFields(t *testing.T) {
	data := vbaDoc(vbaProjectStream(0x00B2),
		[]dirMod{
			{name: "ThisDocument", offset: 800, doc: true},
			{name: "Module1", offset: 2500},
			{name: "Gone", offset: 10},
			{name: "NoOff", noOffset: true},
		},
		map[string][]byte{
			"ThisDocument": append(pcodeRegion(800), compressVBA([]byte(attrOnly))...),
			"Module1":      append(pcodeRegion(2500), compressVBA([]byte(benignSrc))...),
			"NoOff":        append(pcodeRegion(100), compressVBA([]byte(benignSrc))...),
		})
	r := Analyze(data, Options{})
	if len(stompClasses(r)) != 0 {
		t.Fatalf("consistent project raised %+v", r.Findings)
	}
	if r.Parsed == nil || len(r.Parsed.VBAProjects) != 1 {
		t.Fatalf("projects: %+v", r.Parsed)
	}
	p := r.Parsed.VBAProjects[0]
	if p.Storage != "VBA" || p.CodePage != 1252 || p.VersionMajor != 0x5F3A1C2B || p.VersionMinor != 7 ||
		p.PCodeVersion != 0x00B2 || p.DeclaredModules != 4 || p.ModuleCount != 4 || p.Warning != "" {
		t.Fatalf("project: %+v", p)
	}
	want := []ModuleInfo{
		{Name: "ThisDocument", Stream: "ThisDocument", Type: "document", TextOffset: 800, StreamBytes: 4096, PCodeBytes: 800, SourceBytes: len(attrOnly), SourceState: srcBlank},
		{Name: "Module1", Stream: "Module1", Type: "procedural", TextOffset: 2500, StreamBytes: 4096, PCodeBytes: 2500, SourceBytes: len(benignSrc), SourceState: srcPresent},
		{Name: "Gone", Stream: "Gone", Type: "procedural", TextOffset: 10, SourceState: srcNoStream},
		{Name: "NoOff", Stream: "NoOff", Type: "procedural", SourceState: srcNoOffset},
	}
	if len(p.Modules) != len(want) {
		t.Fatalf("modules: %+v", p.Modules)
	}
	for i := range want {
		if p.Modules[i] != want[i] {
			t.Fatalf("module %d = %+v, want %+v", i, p.Modules[i], want[i])
		}
	}
}

func TestStompModuleListBounded(t *testing.T) {
	var mods []dirMod
	streams := map[string][]byte{}
	for i := 0; i < maxModulesReported+6; i++ {
		name := "M" + itoa(i)
		mods = append(mods, dirMod{name: name, offset: 3000})
		streams[name] = pcodeRegion(3000) // no source at all, every one of them
	}
	r := Analyze(vbaDoc(nil, mods, streams), Options{})
	p := r.Parsed.VBAProjects[0]
	if len(p.Modules) != maxModulesReported || !p.ModulesTruncated || p.ModuleCount != len(mods) {
		t.Fatalf("listed %d modules, truncated=%v, count=%d", len(p.Modules), p.ModulesTruncated, p.ModuleCount)
	}
	// However many modules are affected, a class scores once.
	got := stompClasses(r)
	f, ok := got["ole.vba.stomp.source-missing"]
	if !ok || len(got) != 1 || f.Score != weightStompMissing {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if !strings.Contains(f.Detail, itoa(len(mods))+" occurrences") {
		t.Fatalf("detail does not carry the count: %q", f.Detail)
	}
	if r.Score != weightVBAProject+weightStompMissing {
		t.Fatalf("score %d", r.Score)
	}
}

// ── guards against reading damage as stomping ──────────────────────────────────

// A module stream that resolves to fewer bytes than its directory entry
// declares (a truncated file, a broken chain) is not judged.
func TestStompTruncatedStreamNotJudged(t *testing.T) {
	data := vbaDoc(nil, []dirMod{{name: "Module1", offset: 9000}},
		map[string][]byte{"Module1": pcodeRegion(8192)})
	// Sanity: as built, this is the "TextOffset beyond the end" shape.
	if _, ok := stompClasses(Analyze(data, Options{}))["ole.vba.stomp.source-missing"]; !ok {
		t.Fatal("fixture does not fire before the size is patched")
	}
	// Entries: 0 root, 1 Macros, 2 VBA, 3 dir, 4 Module1.
	base := dirEntryBase(data, 4)
	binary.LittleEndian.PutUint32(data[base+120:], 8192+4096) // declares more than the chain holds
	r := Analyze(data, Options{})
	if len(stompClasses(r)) != 0 {
		t.Fatalf("truncated stream raised %+v", r.Findings)
	}
	if m := onlyModule(t, r); m.SourceState != srcUnresolved {
		t.Fatalf("source state = %q, want %q", m.SourceState, srcUnresolved)
	}
}

// A same-named stream in another storage must not stand in for the module.
func TestStompStreamAttribution(t *testing.T) {
	build := func() []byte {
		return buildCFB(
			oleEntry{name: "Decoy", storage: true},
			// A healthy-looking stream of the same name, outside the project.
			oleEntry{name: "Module1", in: "Decoy", content: append(pcodeRegion(3000), compressVBA([]byte(benignSrc))...)},
			oleEntry{name: "VBA", storage: true},
			oleEntry{name: "dir", in: "VBA", content: dirStream(dirMod{name: "Module1", offset: 3000})},
			oleEntry{name: "Module1", in: "VBA", content: pcodeRegion(3000)}, // the project's own: no source
		)
	}

	// With the directory tree intact the project's own stream is the one read.
	r := Analyze(build(), Options{})
	if _, ok := stompClasses(r)["ole.vba.stomp.source-missing"]; !ok {
		t.Fatalf("project's own module not judged: %+v", r.Findings)
	}
	if got := r.Parsed.VBAProjects[0].Storage; got != "VBA" {
		t.Fatalf("storage = %q", got)
	}

	// With the tree cut (no storage reaches its streams) the name is ambiguous
	// and neither stream is attributed to the module.
	// Entries: 0 root, 1 Decoy, 2 Module1, 3 VBA, 4 dir, 5 Module1.
	cut := build()
	binary.LittleEndian.PutUint32(cut[dirEntryBase(cut, 1)+76:], noStream)
	binary.LittleEndian.PutUint32(cut[dirEntryBase(cut, 3)+76:], noStream)
	r = Analyze(cut, Options{})
	if len(stompClasses(r)) != 0 {
		t.Fatalf("ambiguous stream raised %+v", r.Findings)
	}
	if m := onlyModule(t, r); m.SourceState != srcAmbiguous {
		t.Fatalf("source state = %q, want %q", m.SourceState, srcAmbiguous)
	}
}

// With the tree cut and no name clash, the whole-file fallback still finds the
// module (this is also the shape of the package's older flat fixtures).
func TestStompFlatFallback(t *testing.T) {
	data := vbaDoc(nil, []dirMod{{name: "Module1", offset: 3000}},
		map[string][]byte{"Module1": pcodeRegion(3000)})
	// Entries: 0 root, 1 Macros, 2 VBA, 3 dir, 4 Module1.
	binary.LittleEndian.PutUint32(data[dirEntryBase(data, 2)+76:], noStream)
	r := Analyze(data, Options{})
	if _, ok := stompClasses(r)["ole.vba.stomp.source-missing"]; !ok {
		t.Fatalf("flat fallback did not judge the module: %+v", r.Findings)
	}
	if r.Parsed.VBAProjects[0].Storage != "" {
		t.Fatalf("storage reported for an unreachable dir stream: %q", r.Parsed.VBAProjects[0].Storage)
	}
}

func TestStompTwoProjects(t *testing.T) {
	data := buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: dirStream(dirMod{name: "Module1", offset: 3000})},
		oleEntry{name: "Module1", in: "VBA", content: append(pcodeRegion(3000), compressVBA([]byte(benignSrc))...)},
		oleEntry{name: "Embedded", storage: true},
		oleEntry{name: "dir", in: "Embedded", content: dirStream(dirMod{name: "Module1", offset: 3000})},
		oleEntry{name: "Module1", in: "Embedded", content: append(pcodeRegion(3000), compressVBA([]byte(attrOnly))...)},
	)
	r := Analyze(data, Options{})
	if len(r.Parsed.VBAProjects) != 2 {
		t.Fatalf("projects: %+v", r.Parsed.VBAProjects)
	}
	a, b := r.Parsed.VBAProjects[0], r.Parsed.VBAProjects[1]
	if a.Storage != "VBA" || a.Modules[0].SourceState != srcPresent ||
		b.Storage != "Embedded" || b.Modules[0].SourceState != srcBlank {
		t.Fatalf("projects: %+v / %+v", a, b)
	}
	got := stompClasses(r)
	if _, ok := got["ole.vba.stomp.source-blank"]; !ok || len(got) != 1 {
		t.Fatalf("findings: %+v", r.Findings)
	}
}

func TestStompProjectCap(t *testing.T) {
	var entries []oleEntry
	for i := 0; i < maxVBAProjects+3; i++ {
		st := "S" + itoa(i)
		entries = append(entries,
			oleEntry{name: st, storage: true},
			oleEntry{name: "dir", in: st, content: dirStream(dirMod{name: "Module1", offset: 3000})},
			oleEntry{name: "Module1", in: st, content: pcodeRegion(3000)},
		)
	}
	r := Analyze(buildCFB(entries...), Options{})
	if len(r.Parsed.VBAProjects) != maxVBAProjects {
		t.Fatalf("%d projects analysed, cap is %d", len(r.Parsed.VBAProjects), maxVBAProjects)
	}
}

// A dir stream that is not a compressed container yields a warning, no modules
// and no finding (the older fixtures in this package carry exactly that).
func TestStompUnreadableDir(t *testing.T) {
	r := Analyze(buildCFB(
		oleEntry{name: "VBA", storage: true},
		oleEntry{name: "dir", in: "VBA", content: []byte("not a container")},
		oleEntry{name: "Module1", in: "VBA", content: pcodeRegion(3000)},
	), Options{})
	if len(stompClasses(r)) != 0 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if len(r.Parsed.VBAProjects) != 1 || r.Parsed.VBAProjects[0].Warning == "" || len(r.Parsed.VBAProjects[0].Modules) != 0 {
		t.Fatalf("projects: %+v", r.Parsed.VBAProjects)
	}
}

func TestLinkTreeHostile(t *testing.T) {
	data := buildCFB(
		oleEntry{name: "A", storage: true},
		oleEntry{name: "s1", in: "A", content: []byte("x")},
		oleEntry{name: "s2", in: "A", content: []byte("y")},
	)
	// Entries: 0 root, 1 A, 2 s1, 3 s2. Make the sibling links a cycle and
	// point one at an id that does not exist.
	binary.LittleEndian.PutUint32(data[dirEntryBase(data, 3)+72:], 2)      // s2.right -> s1
	binary.LittleEndian.PutUint32(data[dirEntryBase(data, 3)+68:], 0xBEEF) // s2.left -> nowhere
	binary.LittleEndian.PutUint32(data[dirEntryBase(data, 2)+68:], 1)      // s1.left -> its own storage
	f := parseCFB(data)
	if len(f.entries) != 4 {
		t.Fatalf("entries: %d", len(f.entries))
	}
	if f.entries[2].parent != 1 || f.entries[3].parent != 1 {
		t.Fatalf("parents: s1=%d s2=%d, want 1/1", f.entries[2].parent, f.entries[3].parent)
	}
	if f.entries[0].parent != -1 {
		t.Fatalf("root has a parent: %d", f.entries[0].parent)
	}
}

// BenchmarkAnalyzeVBA puts a number on what the dir-record pass adds to a
// compound file that carries a VBA project: "signature-scan" is the detector as
// it was before the pass existed (parse + detect), "with-dir-pass" is Analyze.
// Files that are not compound files return before either.
func BenchmarkAnalyzeVBA(b *testing.B) {
	var mods []dirMod
	streams := map[string][]byte{}
	for i := 0; i < 12; i++ {
		name := "Module" + itoa(i)
		mods = append(mods, dirMod{name: name, offset: 6000})
		streams[name] = append(pcodeRegion(6000, []byte("WScript.Shell")), compressVBA([]byte(strings.Repeat(spawnSrc, 20)))...)
	}
	data := vbaDoc(vbaProjectStream(0x00B2, "Run", "CreateObject"), mods, streams)
	b.SetBytes(int64(len(data)))
	b.Run("signature-scan", func(b *testing.B) {
		for b.Loop() {
			detect(parseCFB(data))
		}
	})
	b.Run("with-dir-pass", func(b *testing.B) {
		for b.Loop() {
			Analyze(data, Options{})
		}
	})
}

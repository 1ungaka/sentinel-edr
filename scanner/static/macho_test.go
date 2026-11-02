package static

import (
	"encoding/binary"
	"testing"
)

// ── synthetic Mach-O builder (thin, 64-bit, little-endian) ───────────────────

type machoSegSpec struct {
	name     string
	initprot uint32
	maxprot  uint32
	data     []byte
	vmaddr   uint64
}

type machoSpec struct {
	cpu      uint32 // 0 => x86_64
	filetype uint32 // 0 => MH_EXECUTE
	flags    uint32
	segments []machoSegSpec
	dylibs   []string
	rpaths   []string
	// mainSeg >= 0 emits LC_MAIN with entryoff = that segment's fileoff;
	// badEntry emits LC_MAIN with an out-of-range entryoff.
	mainSeg  int
	badEntry bool
	sign     bool
	signSize uint32
	cryptid  uint32
	imports  []string
	overlay  []byte
}

func defaultMachoSpec() machoSpec {
	text := make([]byte, 2048)
	for i := range text {
		text[i] = byte(i % 7) // genuinely low-entropy filler (~2.8 bits/byte)
	}
	return machoSpec{
		segments: []machoSegSpec{
			{name: "__PAGEZERO", vmaddr: 0},
			{name: "__TEXT", initprot: vmProtRead | vmProtExec, maxprot: vmProtRead | vmProtExec, data: text, vmaddr: 0x100000000},
			{name: "__DATA", initprot: vmProtRead | vmProtWrite, maxprot: vmProtRead | vmProtWrite, data: make([]byte, 512), vmaddr: 0x100001000},
		},
		dylibs:  []string{"/usr/lib/libSystem.B.dylib"},
		mainSeg: 1,
	}
}

func buildMachO(t *testing.T, spec machoSpec) []byte {
	t.Helper()
	o := binary.LittleEndian
	cpu := spec.cpu
	if cpu == 0 {
		cpu = 7 | cpuArchABI64 // x86_64
	}
	ft := spec.filetype
	if ft == 0 {
		ft = mhExecute
	}

	// Build each load command's bytes (fileoffs patched in a second pass).
	type lc struct {
		bytes  []byte
		segIdx int // >=0: a segment command whose fileoff needs patching
	}
	var cmds []lc

	segFileData := make([][]byte, len(spec.segments))
	for i, s := range spec.segments {
		b := make([]byte, 72)
		o.PutUint32(b[0:], lcSegment64)
		o.PutUint32(b[4:], 72)
		copy(b[8:24], s.name)
		o.PutUint64(b[24:], s.vmaddr)
		o.PutUint64(b[32:], uint64(len(s.data)))
		// fileoff (b[40]) and filesize (b[48]) patched later
		o.PutUint64(b[48:], uint64(len(s.data)))
		o.PutUint32(b[56:], s.maxprot)
		o.PutUint32(b[60:], s.initprot)
		o.PutUint32(b[64:], 0) // nsects
		cmds = append(cmds, lc{bytes: b, segIdx: i})
		segFileData[i] = s.data
	}
	for _, d := range spec.dylibs {
		name := append([]byte(d), 0)
		sz := (24 + len(name) + 7) &^ 7
		b := make([]byte, sz)
		o.PutUint32(b[0:], lcLoadDylib)
		o.PutUint32(b[4:], uint32(sz))
		o.PutUint32(b[8:], 24) // name offset
		copy(b[24:], name)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}
	for _, rp := range spec.rpaths {
		name := append([]byte(rp), 0)
		sz := (12 + len(name) + 7) &^ 7
		b := make([]byte, sz)
		o.PutUint32(b[0:], lcRpath)
		o.PutUint32(b[4:], uint32(sz))
		o.PutUint32(b[8:], 12) // path offset
		copy(b[12:], name)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}
	if spec.cryptid != 0 {
		b := make([]byte, 24)
		o.PutUint32(b[0:], lcEncryptionInfo64)
		o.PutUint32(b[4:], 24)
		o.PutUint32(b[16:], spec.cryptid)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}
	// LC_SYMTAB (imports) and LC_CODE_SIGNATURE need file offsets to trailing
	// blobs; reserve their commands now and patch offsets after layout.
	symtabIdx, sigIdx := -1, -1
	var strtab []byte
	var nlist []byte
	if len(spec.imports) > 0 {
		strtab = append(strtab, 0)
		for _, n := range spec.imports {
			strx := len(strtab)
			strtab = append(strtab, []byte(n)...)
			strtab = append(strtab, 0)
			ent := make([]byte, 16)
			o.PutUint32(ent[0:], uint32(strx))
			ent[4] = nExt // undefined external
			nlist = append(nlist, ent...)
		}
		b := make([]byte, 24)
		o.PutUint32(b[0:], lcSymtab)
		o.PutUint32(b[4:], 24)
		symtabIdx = len(cmds)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}
	if spec.sign {
		b := make([]byte, 16)
		o.PutUint32(b[0:], lcCodeSignature)
		o.PutUint32(b[4:], 16)
		sigIdx = len(cmds)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}
	mainIdx := -1
	if spec.mainSeg >= 0 || spec.badEntry {
		b := make([]byte, 24)
		o.PutUint32(b[0:], lcMain)
		o.PutUint32(b[4:], 24)
		mainIdx = len(cmds)
		cmds = append(cmds, lc{bytes: b, segIdx: -1})
	}

	lcSize := 0
	for _, c := range cmds {
		lcSize += len(c.bytes)
	}
	cursor := 32 + lcSize
	// Align data start.
	for cursor%16 != 0 {
		cursor++
	}
	segFileOff := make([]int, len(spec.segments))
	for i, s := range spec.segments {
		if len(s.data) == 0 {
			continue
		}
		segFileOff[i] = cursor
		cursor += len(s.data)
	}
	symOff, strOff := 0, 0
	if symtabIdx >= 0 {
		symOff = cursor
		cursor += len(nlist)
		strOff = cursor
		cursor += len(strtab)
	}
	sigOff := 0
	if sigIdx >= 0 {
		sigOff = cursor
		cursor += int(spec.signSize)
	}

	// Patch segment fileoffs.
	for _, c := range cmds {
		if c.segIdx >= 0 {
			o.PutUint64(c.bytes[40:], uint64(segFileOff[c.segIdx]))
		}
	}
	if symtabIdx >= 0 {
		b := cmds[symtabIdx].bytes
		o.PutUint32(b[8:], uint32(symOff))
		o.PutUint32(b[12:], uint32(len(spec.imports)))
		o.PutUint32(b[16:], uint32(strOff))
		o.PutUint32(b[20:], uint32(len(strtab)))
	}
	if sigIdx >= 0 {
		b := cmds[sigIdx].bytes
		o.PutUint32(b[8:], uint32(sigOff))
		o.PutUint32(b[12:], spec.signSize)
	}
	if mainIdx >= 0 {
		b := cmds[mainIdx].bytes
		entry := uint64(0xdeadbeefdead)
		if !spec.badEntry && spec.mainSeg >= 0 {
			entry = uint64(segFileOff[spec.mainSeg])
		}
		o.PutUint64(b[8:], entry)
	}

	buf := make([]byte, cursor)
	// Header.
	o.PutUint32(buf[0:], mhMagic64)
	o.PutUint32(buf[4:], cpu)
	o.PutUint32(buf[8:], 0) // cpusubtype
	o.PutUint32(buf[12:], ft)
	o.PutUint32(buf[16:], uint32(len(cmds)))
	o.PutUint32(buf[20:], uint32(lcSize))
	o.PutUint32(buf[24:], spec.flags)
	// Load commands.
	p := 32
	for _, c := range cmds {
		copy(buf[p:], c.bytes)
		p += len(c.bytes)
	}
	// Segment data.
	for i, s := range spec.segments {
		if len(s.data) > 0 {
			copy(buf[segFileOff[i]:], s.data)
		}
	}
	if symtabIdx >= 0 {
		copy(buf[symOff:], nlist)
		copy(buf[strOff:], strtab)
	}
	if sigIdx >= 0 {
		for i := 0; i < int(spec.signSize); i++ {
			buf[sigOff+i] = 0x30
		}
	}
	buf = append(buf, spec.overlay...)
	return buf
}

func parseMacho(t *testing.T, spec machoSpec) *MachO {
	t.Helper()
	m, err := ParseMachO(buildMachO(t, spec))
	if err != nil {
		t.Fatalf("ParseMachO: %v", err)
	}
	return m
}

func machoHasClass(m *MachO, class string) bool {
	for _, a := range machoAnomalies(m) {
		if a.Class == class {
			return true
		}
	}
	return false
}

func TestMachOBenign(t *testing.T) {
	spec := defaultMachoSpec()
	spec.sign = true
	spec.signSize = 4096
	m := parseMacho(t, spec)
	if m.Fat || len(m.Arches) != 1 {
		t.Fatalf("expected one thin arch, got fat=%v arches=%d", m.Fat, len(m.Arches))
	}
	img := m.Arches[0]
	if img.CPUType != "x86_64" || img.FileType != "execute" {
		t.Errorf("cpu=%q filetype=%q", img.CPUType, img.FileType)
	}
	if !img.Signed || img.SignatureSize != 4096 {
		t.Errorf("signed=%v size=%d", img.Signed, img.SignatureSize)
	}
	if img.EntrySegment < 0 || !img.EntryExecutable {
		t.Errorf("entry segment=%d exec=%v", img.EntrySegment, img.EntryExecutable)
	}
	if img.ImportHash == "" {
		t.Error("expected a dylib import hash")
	}
	// A clean signed binary should carry no scored structural anomaly.
	res := Analyze(buildMachO(t, spec), Options{NoFuzzy: true})
	if res.Score != 0 {
		t.Errorf("benign Mach-O scored %d: %+v", res.Score, res.Anomalies)
	}
	if machoHasClass(m, "macho.overlay-present") || machoHasClass(m, "macho.overlay-high-entropy") {
		t.Error("code signature must not be reported as an overlay")
	}
}

func TestMachORWXSegment(t *testing.T) {
	spec := defaultMachoSpec()
	spec.segments[1].initprot = vmProtRead | vmProtWrite | vmProtExec
	spec.segments[1].maxprot = vmProtRead | vmProtWrite | vmProtExec
	m := parseMacho(t, spec)
	if !machoHasClass(m, "macho.segment-rwx") {
		t.Error("expected macho.segment-rwx")
	}
}

func TestMachOInsecurePaths(t *testing.T) {
	spec := defaultMachoSpec()
	spec.rpaths = []string{"/tmp/x", "@loader_path/../Frameworks"}
	spec.dylibs = []string{"/usr/lib/libSystem.B.dylib", "/tmp/evil.dylib", "@rpath/ok.dylib"}
	m := parseMacho(t, spec)
	if !machoHasClass(m, "macho.rpath-insecure") {
		t.Error("expected macho.rpath-insecure for /tmp/x")
	}
	if !machoHasClass(m, "macho.dylib-suspicious-path") {
		t.Error("expected macho.dylib-suspicious-path for /tmp/evil.dylib")
	}
}

func TestMachOEncrypted(t *testing.T) {
	spec := defaultMachoSpec()
	spec.cryptid = 1
	m := parseMacho(t, spec)
	if !m.Arches[0].Encrypted {
		t.Error("expected Encrypted")
	}
	if !machoHasClass(m, "macho.encrypted") {
		t.Error("expected macho.encrypted")
	}
}

func TestMachOEntryOutside(t *testing.T) {
	spec := defaultMachoSpec()
	spec.mainSeg = -1
	spec.badEntry = true
	m := parseMacho(t, spec)
	if m.Arches[0].EntrySegment >= 0 {
		t.Errorf("entry should resolve to no segment, got %d", m.Arches[0].EntrySegment)
	}
	if !machoHasClass(m, "macho.entry-outside-segments") {
		t.Error("expected macho.entry-outside-segments")
	}
}

func TestMachOImportsFromSymtab(t *testing.T) {
	spec := defaultMachoSpec()
	spec.imports = []string{"_malloc", "_dlopen", "_system"}
	m := parseMacho(t, spec)
	img := m.Arches[0]
	if img.ImportCount != 3 {
		t.Errorf("import count = %d, want 3", img.ImportCount)
	}
	found := false
	for _, n := range img.Imports {
		if n == "_dlopen" {
			found = true
		}
	}
	if !found {
		t.Errorf("imports = %v, want _dlopen", img.Imports)
	}
}

func TestMachOOverlay(t *testing.T) {
	spec := defaultMachoSpec()
	hi := make([]byte, 8192)
	for i := range hi {
		hi[i] = byte((i*2654435761 + 7) >> 3)
	}
	spec.overlay = hi
	m := parseMacho(t, spec)
	if m.Overlay.Size < 4096 {
		t.Fatalf("overlay size = %d", m.Overlay.Size)
	}
	if !machoHasClass(m, "macho.overlay-high-entropy") && !machoHasClass(m, "macho.overlay-present") {
		t.Error("expected an overlay anomaly")
	}
}

func TestMachOFatUniversal(t *testing.T) {
	a := buildMachO(t, defaultMachoSpec())
	arm := defaultMachoSpec()
	arm.cpu = 12 | cpuArchABI64 // arm64
	b := buildMachO(t, arm)

	// Assemble a big-endian fat header with two 4K-aligned slices.
	o := binary.BigEndian
	align := func(n int) int { return (n + 0x3fff) &^ 0x3fff }
	off1 := align(8 + 2*20)
	off2 := align(off1 + len(a))
	total := off2 + len(b)
	fat := make([]byte, total)
	o.PutUint32(fat[0:], fatMagic)
	o.PutUint32(fat[4:], 2)
	put := func(p int, cpu uint32, off, size int) {
		o.PutUint32(fat[p:], cpu)
		o.PutUint32(fat[p+4:], 0)
		o.PutUint32(fat[p+8:], uint32(off))
		o.PutUint32(fat[p+12:], uint32(size))
		o.PutUint32(fat[p+16:], 14) // 2^14 alignment
	}
	put(8, 7|cpuArchABI64, off1, len(a))
	put(28, 12|cpuArchABI64, off2, len(b))
	copy(fat[off1:], a)
	copy(fat[off2:], b)

	m, err := ParseMachO(fat)
	if err != nil {
		t.Fatalf("ParseMachO fat: %v", err)
	}
	if !m.Fat || len(m.Arches) != 2 {
		t.Fatalf("fat=%v arches=%d", m.Fat, len(m.Arches))
	}
	if m.Arches[0].CPUType != "x86_64" || m.Arches[1].CPUType != "arm64" {
		t.Errorf("arches = %q, %q", m.Arches[0].CPUType, m.Arches[1].CPUType)
	}
	if !machoHasClass(m, "macho.universal") {
		t.Error("expected macho.universal")
	}
}

func TestMachODetectedByAnalyze(t *testing.T) {
	// A packed-looking Mach-O: one high-entropy executable segment, no imports.
	spec := defaultMachoSpec()
	hi := make([]byte, 8192)
	for i := range hi {
		hi[i] = byte((i*2654435761 + 13) >> 1)
	}
	spec.segments[1].data = hi
	spec.dylibs = nil
	m := parseMacho(t, spec)
	if !machoHasClass(m, "macho.segment-high-entropy") {
		t.Errorf("expected macho.segment-high-entropy; anomalies=%+v", machoAnomalies(m))
	}
}

package static

import (
	"strings"
	"testing"
)

// execDataSpec is a dynamically linked image with a fixed-address executable
// section (.text at 0x500000) and a fixed-address writable data section
// (.data at 0x600000), so tests can point constructor pointers at a VA whose
// executability is known without first parsing the built file.
func execDataSpec(typ uint16) elfSpec {
	text := make([]byte, 256)
	for i := range text {
		text[i] = 0x90
	}
	data := make([]byte, 256)
	return elfSpec{
		typ:     typ,
		machine: 62,
		sections: []elfSecSpec{
			{name: ".text", shflags: shfAlloc | shfExecinstr, pflags: pfR | pfX, data: text, vaddr: 0x500000},
			{name: ".data", shflags: shfAlloc | shfWrite, pflags: pfR | pfW, data: data, vaddr: 0x600000},
		},
		interp:  "/lib64/ld-linux-x86-64.so.2",
		needed:  []string{"libc.so.6"},
		imports: []string{"__libc_start_main", "printf"},
	}
}

func parseSpec(t *testing.T, spec elfSpec) *ELF {
	t.Helper()
	e, err := ParseELF(buildELF(t, spec))
	if err != nil {
		t.Fatalf("ParseELF: %v", err)
	}
	return e
}

func elfHasClass(e *ELF, class string) bool {
	for _, a := range elfAnomalies(e) {
		if a.Class == class {
			return true
		}
	}
	return false
}

func TestELFInitArrayDirectResolution(t *testing.T) {
	// Non-PIE executable: slots hold the target VA directly. One points into
	// .text (executable), one into .data (not), one nowhere.
	spec := execDataSpec(etExec)
	spec.initArray = []uint64{0x500000, 0x600000, 0xdeadbeef}
	e := parseSpec(t, spec)
	if len(e.InitArrayTargets) != 3 {
		t.Fatalf("resolved %d init_array targets, want 3: %+v", len(e.InitArrayTargets), e.InitArrayTargets)
	}
	want := []struct {
		va   uint64
		exec bool
		src  string
	}{
		{0x500000, true, "file"},
		{0x600000, false, "file"},
		{0xdeadbeef, false, "file"},
	}
	for i, w := range want {
		got := e.InitArrayTargets[i]
		if got.VA != w.va || got.Executable != w.exec || got.Source != w.src {
			t.Errorf("target %d = %+v, want va=0x%x exec=%v src=%q", i, got, w.va, w.exec, w.src)
		}
	}
	if !elfHasClass(e, "dynamic.init-array-outside-code") {
		t.Error("expected dynamic.init-array-outside-code for the .data and unmapped targets")
	}
}

func TestELFInitArrayAllExecutableClean(t *testing.T) {
	spec := execDataSpec(etExec)
	spec.initArray = []uint64{0x500000, 0x500010}
	e := parseSpec(t, spec)
	for _, got := range e.InitArrayTargets {
		if !got.Executable {
			t.Errorf("target 0x%x should be executable", got.VA)
		}
	}
	if elfHasClass(e, "dynamic.init-array-outside-code") {
		t.Error("all-executable constructors must not raise dynamic.init-array-outside-code")
	}
}

func TestELFInitArrayRelativeResolution(t *testing.T) {
	// PIE: slots are zero and a R_X86_64_RELATIVE relocation carries the VA.
	spec := execDataSpec(etDyn)
	spec.pie = true
	spec.initArrayRelative = []uint64{0x500000, 0x600000}
	e := parseSpec(t, spec)
	if len(e.InitArrayTargets) != 2 {
		t.Fatalf("resolved %d targets, want 2: %+v", len(e.InitArrayTargets), e.InitArrayTargets)
	}
	for _, got := range e.InitArrayTargets {
		if got.Source != "relative-reloc" {
			t.Errorf("target 0x%x source = %q, want relative-reloc", got.VA, got.Source)
		}
	}
	if e.InitArrayTargets[0].VA != 0x500000 || !e.InitArrayTargets[0].Executable {
		t.Errorf("first target = %+v, want exec 0x500000", e.InitArrayTargets[0])
	}
	if e.InitArrayTargets[1].VA != 0x600000 || e.InitArrayTargets[1].Executable {
		t.Errorf("second target = %+v, want non-exec 0x600000", e.InitArrayTargets[1])
	}
	if !elfHasClass(e, "dynamic.init-array-outside-code") {
		t.Error("expected finding for the relocation-supplied .data constructor")
	}
}

func TestELFSymbolVersions(t *testing.T) {
	spec := execDataSpec(etDyn)
	spec.versionNeed = map[string][]string{"libc.so.6": {"GLIBC_2.2.5", "GLIBC_2.34"}}
	e := parseSpec(t, spec)
	if len(e.VersionsNeeded) != 1 {
		t.Fatalf("read %d version-need records, want 1: %+v", len(e.VersionsNeeded), e.VersionsNeeded)
	}
	vn := e.VersionsNeeded[0]
	if vn.File != "libc.so.6" {
		t.Errorf("file = %q, want libc.so.6", vn.File)
	}
	if strings.Join(vn.Versions, ",") != "GLIBC_2.2.5,GLIBC_2.34" {
		t.Errorf("versions = %v, want [GLIBC_2.2.5 GLIBC_2.34]", vn.Versions)
	}
	if !elfHasClass(e, "dynamic.symbol-versions") {
		t.Error("expected informational dynamic.symbol-versions anomaly")
	}
}

func TestELFSyscallInterposer(t *testing.T) {
	// A shared object redefining libc entry points that reaches the kernel
	// through raw syscalls (0f 05) and never imports dlsym.
	base := func() elfSpec {
		text := []byte{0x0f, 0x05, 0x90, 0x90, 0x0f, 0x05, 0xc3} // two syscalls
		s := elfSpec{
			typ:     etDyn,
			machine: 62,
			sections: []elfSecSpec{
				{name: ".text", shflags: shfAlloc | shfExecinstr, pflags: pfR | pfX, data: text, vaddr: 0x500000},
			},
			needed:  []string{"libc.so.6"},
			imports: []string{"write"},
			exports: []string{"readdir", "open"},
			soname:  "evil.so.1",
		}
		return s
	}

	e := parseSpec(t, base())
	if e.SyscallStubs < 2 {
		t.Errorf("SyscallStubs = %d, want >= 2", e.SyscallStubs)
	}
	if !elfHasClass(e, "dynamic.preload-interposer-syscall") {
		t.Fatal("expected dynamic.preload-interposer-syscall")
	}

	// With dlsym imported it is the classic dlsym variant, not the syscall one.
	withDlsym := base()
	withDlsym.imports = []string{"write", "dlsym"}
	e = parseSpec(t, withDlsym)
	if elfHasClass(e, "dynamic.preload-interposer-syscall") {
		t.Error("dlsym importer must not be flagged as the syscall variant")
	}
	if !elfHasClass(e, "dynamic.preload-interposer") {
		t.Error("dlsym importer should be the classic interposer")
	}

	// A named sanitizer/known interposer is reported, not scored.
	known := base()
	known.soname = "libasan.so.6"
	e = parseSpec(t, known)
	if elfHasClass(e, "dynamic.preload-interposer-syscall") {
		t.Error("known interposer must not be scored")
	}
	if !elfHasClass(e, "dynamic.preload-interposer-known") {
		t.Error("known interposer should be named")
	}

	// No syscalls and no dlsym: not an interposer at all.
	quiet := base()
	quiet.sections[0].data = []byte{0x90, 0x90, 0xc3}
	e = parseSpec(t, quiet)
	if e.SyscallStubs != 0 {
		t.Errorf("SyscallStubs = %d, want 0", e.SyscallStubs)
	}
	if elfHasClass(e, "dynamic.preload-interposer-syscall") || elfHasClass(e, "dynamic.preload-interposer") {
		t.Error("object with neither syscalls nor dlsym must not be an interposer")
	}
}

func TestELFTelfhash(t *testing.T) {
	// Enough distinct, non-excluded function names that the joined symbol
	// string clears TLSH's 50-byte floor.
	funcs := []string{
		"connect", "listen", "accept", "poll", "select", "fork", "execv",
		"waitpid", "dup", "pipe", "socket", "bind", "sendto", "recvfrom",
		"chmod", "chown", "kill", "alarm", "pause", "nanosleep",
	}
	spec := execDataSpec(etDyn)
	spec.exports = funcs
	e := parseSpec(t, spec)
	if e.TelfhashNote != "" {
		t.Fatalf("unexpected telfhash note: %q", e.TelfhashNote)
	}
	if len(e.Telfhash) != 70 {
		t.Fatalf("telfhash = %q (len %d), want 70 hex", e.Telfhash, len(e.Telfhash))
	}
	if e.Telfhash != strings.ToUpper(e.Telfhash) {
		t.Errorf("telfhash should be upper-cased: %q", e.Telfhash)
	}

	// Determinism.
	e2 := parseSpec(t, spec)
	if e.Telfhash != e2.Telfhash {
		t.Errorf("telfhash not deterministic: %q vs %q", e.Telfhash, e2.Telfhash)
	}

	// Excluded symbols must not change the digest: add names that telfhash
	// filters out (leading _, trailing 64, str*, mem*, and exact puts).
	withExcluded := execDataSpec(etDyn)
	withExcluded.exports = append(append([]string{}, funcs...),
		"_hidden", "readdir64", "strcpy_s", "memmove_impl", "puts")
	e3 := parseSpec(t, withExcluded)
	if e3.Telfhash != e.Telfhash {
		t.Errorf("excluded symbols changed telfhash: %q vs %q", e3.Telfhash, e.Telfhash)
	}
}

func TestTelfhashShortInput(t *testing.T) {
	// One short name after filtering: below TLSH's floor, so a note, not a hash.
	h, note := telfhash([]string{"connect"})
	if h != "" || note == "" {
		t.Errorf("short input: got (%q,%q), want empty hash with a note", h, note)
	}
	// No eligible names at all.
	h, note = telfhash(nil)
	if h != "" || !strings.Contains(note, "no global") {
		t.Errorf("empty input: got (%q,%q)", h, note)
	}
}

func TestTelfhashExcluded(t *testing.T) {
	excluded := []string{"_start", ".hidden", "readdir64", "strlen", "memcpy", "main", "abort", "puts"}
	for _, n := range excluded {
		if !telfhashExcluded(n) {
			t.Errorf("%q should be excluded", n)
		}
	}
	kept := []string{"connect", "fork", "listen", "chmod"}
	for _, n := range kept {
		if telfhashExcluded(n) {
			t.Errorf("%q should be kept", n)
		}
	}
}

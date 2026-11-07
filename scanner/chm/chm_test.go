package chm

import (
	"strings"
	"testing"
)

// ── synthetic CHM builder ────────────────────────────────────────────────────

// encEncint encodes a CHM variable-length integer (big-endian, high bit =
// continuation) — the inverse of the parser's encint.
func encEncint(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var le []byte
	for v > 0 {
		le = append(le, byte(v&0x7f))
		v >>= 7
	}
	out := make([]byte, len(le))
	for i := range le {
		out[i] = le[len(le)-1-i]
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func putLE32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func putLE64(b []byte, off int, v uint64) {
	putLE32(b, off, uint32(v))
	putLE32(b, off+4, uint32(v>>32))
}

const testChunkSize = 4096

// buildCHM assembles a minimal valid CHM whose directory lists the given
// member names in a single PMGL chunk. The LZX content section is omitted; the
// parser never reads it.
func buildCHM(t *testing.T, names []string) []byte {
	t.Helper()
	// Build the PMGL entries.
	entries := make([]byte, 0x14) // PMGL header
	copy(entries[0:4], "PMGL")
	putLE32(entries, 0x8, 0)
	putLE32(entries, 0xc, 0xffffffff)  // prev = -1
	putLE32(entries, 0x10, 0xffffffff) // next = -1
	for i, name := range names {
		entries = append(entries, encEncint(uint64(len(name)))...)
		entries = append(entries, []byte(name)...)
		entries = append(entries, encEncint(0)...)             // content section
		entries = append(entries, encEncint(uint64(i*100))...) // offset
		entries = append(entries, encEncint(64)...)            // length
	}
	used := len(entries)
	if used > testChunkSize {
		t.Fatalf("entries overflow chunk: %d", used)
	}
	chunk := make([]byte, testChunkSize)
	copy(chunk, entries)
	// free space is everything after the entries.
	putLE32(chunk, 0x4, uint32(testChunkSize-used))

	// ITSP header (0x54 bytes) + the one chunk.
	itsp := make([]byte, itspHeaderLen)
	copy(itsp[0:4], "ITSP")
	putLE32(itsp, 0x4, 1)              // version
	putLE32(itsp, 0x8, itspHeaderLen)  // header length
	putLE32(itsp, 0x10, testChunkSize) // chunk size
	putLE32(itsp, 0x18, 1)             // depth
	putLE32(itsp, 0x1c, 0xffffffff)    // root index chunk = none
	putLE32(itsp, 0x20, 0)             // first PMGL
	putLE32(itsp, 0x24, 0)             // last PMGL
	putLE32(itsp, 0x2c, 1)             // number of chunks
	dir := append(itsp, chunk...)

	// ITSF header (0x60 bytes) pointing section 1 at the directory.
	const itsfLen = 0x60
	buf := make([]byte, itsfLen)
	copy(buf[0:4], "ITSF")
	putLE32(buf, 0x4, 3)        // version
	putLE32(buf, 0x8, itsfLen)  // header length
	putLE64(buf, 0x38, itsfLen) // header section 0 offset
	putLE64(buf, 0x40, 0)       // header section 0 length
	putLE64(buf, 0x48, itsfLen) // header section 1 (directory) offset
	putLE64(buf, 0x50, uint64(len(dir)))
	buf = append(buf, dir...)
	return buf
}

func has(r *Result, class string) bool {
	for _, f := range r.Findings {
		if f.Class == class {
			return true
		}
	}
	return false
}

// buildCHMRaw assembles a CHM whose single PMGL chunk carries the given raw
// entries bytes (everything after the 0x14-byte PMGL header), so a test can
// craft malformed directory listings the name-list builder cannot express.
// Everything after the entries is free space, so end lands exactly at the last
// supplied byte.
func buildCHMRaw(t *testing.T, entries []byte) []byte {
	t.Helper()
	used := 0x14 + len(entries)
	if used > testChunkSize {
		t.Fatalf("entries overflow chunk: %d", used)
	}
	chunk := make([]byte, testChunkSize)
	copy(chunk[0:4], "PMGL")
	putLE32(chunk, 0x4, uint32(testChunkSize-used)) // free space after the entries
	putLE32(chunk, 0x8, 0)
	putLE32(chunk, 0xc, 0xffffffff)  // prev = -1
	putLE32(chunk, 0x10, 0xffffffff) // next = -1
	copy(chunk[0x14:], entries)

	itsp := make([]byte, itspHeaderLen)
	copy(itsp[0:4], "ITSP")
	putLE32(itsp, 0x4, 1)
	putLE32(itsp, 0x8, itspHeaderLen)
	putLE32(itsp, 0x10, testChunkSize)
	putLE32(itsp, 0x18, 1)
	putLE32(itsp, 0x1c, 0xffffffff)
	putLE32(itsp, 0x20, 0)
	putLE32(itsp, 0x24, 0)
	putLE32(itsp, 0x2c, 1)
	dir := append(itsp, chunk...)

	const itsfLen = 0x60
	buf := make([]byte, itsfLen)
	copy(buf[0:4], "ITSF")
	putLE32(buf, 0x4, 3)
	putLE32(buf, 0x8, itsfLen)
	putLE64(buf, 0x38, itsfLen)
	putLE64(buf, 0x40, 0)
	putLE64(buf, 0x48, itsfLen)
	putLE64(buf, 0x50, uint64(len(dir)))
	return append(buf, dir...)
}

// validEntry encodes one well-formed PMGL directory entry (name + the three
// trailing ENCINTs).
func validEntry(name string, idx int) []byte {
	var e []byte
	e = append(e, encEncint(uint64(len(name)))...)
	e = append(e, []byte(name)...)
	e = append(e, encEncint(0)...)               // content section
	e = append(e, encEncint(uint64(idx*100))...) // offset
	e = append(e, encEncint(64)...)              // length
	return e
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestCHMBenign(t *testing.T) {
	data := buildCHM(t, []string{
		"::DataSpace/NameList", "/#SYSTEM", "/#STRINGS",
		"/default.html", "/toc.hhc", "/index.hhk", "/images/logo.gif",
	})
	if !IsCHM(data) {
		t.Fatal("IsCHM false on a built CHM")
	}
	r := Analyze(data, Options{})
	if r.Score != 0 {
		t.Errorf("benign CHM scored %d: %+v", r.Score, r.Findings)
	}
	if r.Parsed == nil || r.Parsed.Entries != 7 {
		t.Fatalf("summary = %+v", r.Parsed)
	}
}

func TestCHMEmbeddedExecutable(t *testing.T) {
	data := buildCHM(t, []string{"/default.html", "/payload.exe"})
	r := Analyze(data, Options{})
	if !has(r, "chm.embedded-executable") {
		t.Fatalf("expected chm.embedded-executable: %+v", r.Findings)
	}
	if !r.Detected() {
		t.Errorf("a CHM carrying an .exe should cross the threshold; score %d", r.Score)
	}
}

func TestCHMMultipleExecutables(t *testing.T) {
	data := buildCHM(t, []string{"/a.exe", "/b.dll", "/c.html"})
	r := Analyze(data, Options{})
	if !has(r, "chm.embedded-executable") || !has(r, "chm.multiple-executables") {
		t.Errorf("expected both exec findings: %+v", r.Findings)
	}
}

func TestCHMEmbeddedScript(t *testing.T) {
	data := buildCHM(t, []string{"/help.html", "/run.hta"})
	r := Analyze(data, Options{})
	if !has(r, "chm.embedded-script") {
		t.Fatalf("expected chm.embedded-script: %+v", r.Findings)
	}
}

func TestCHMEmbeddedLNK(t *testing.T) {
	data := buildCHM(t, []string{"/readme.html", "/launch.lnk"})
	r := Analyze(data, Options{})
	if !has(r, "chm.embedded-lnk") {
		t.Fatalf("expected chm.embedded-lnk: %+v", r.Findings)
	}
}

func TestCHMPlainJSNotDangerous(t *testing.T) {
	// A .js file (common in help TOCs) is not in the dangerous-script set.
	data := buildCHM(t, []string{"/default.html", "/toc.js"})
	r := Analyze(data, Options{})
	if r.Score != 0 {
		t.Errorf(".js should not score on its own: %+v", r.Findings)
	}
}

func TestCHMNonCHMInert(t *testing.T) {
	r := Analyze([]byte("this is not a CHM file at all, just text"), Options{})
	if r.Score != 0 || len(r.Findings) != 0 || r.Parsed != nil {
		t.Errorf("non-CHM produced output: %+v", r)
	}
	if IsCHM([]byte("ITSFnope")) && len([]byte("ITSFnope")) < 0x60 {
		t.Error("IsCHM should require >= 0x60 bytes")
	}
}

func TestCHMEnumerateNames(t *testing.T) {
	names, truncated := enumerate(buildCHM(t, []string{"/one.html", "/two.exe", "::sys"}))
	if truncated {
		t.Error("clean CHM should not be truncated")
	}
	want := map[string]bool{"/one.html": false, "/two.exe": false, "::sys": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("name %q not enumerated (got %v)", n, names)
		}
	}
}

// ── malformed directory listings mark the walk partial ────────────────────────
//
// A crafted PMGL chunk must not be able to hide later member names while the
// result still claims a complete enumeration: every parse bound that stops the
// listing sets the truncation marker.

func TestCHMZeroNameLengthMarksTruncated(t *testing.T) {
	// A zero name length as the FIRST entry hides every later name, so the
	// walk is partial rather than complete.
	entries := append([]byte{0x00}, validEntry("/payload.exe", 0)...)
	data := buildCHMRaw(t, entries)
	names, truncated := enumerate(data)
	if !truncated {
		t.Errorf("zero name length must set truncated; names = %v", names)
	}
	if len(names) != 0 {
		t.Errorf("the hidden later entry must not be enumerated; names = %v", names)
	}
	// The summary must say so.
	r := Analyze(data, Options{})
	if r.Parsed == nil || !strings.Contains(r.Parsed.NotInspected, "directory walk hit a parse bound") {
		t.Errorf("summary must carry the parse-bound note: %+v", r.Parsed)
	}
}

func TestCHMNameOverrunMarksTruncated(t *testing.T) {
	// A declared name length that runs past the chunk stops the walk; a later
	// valid entry inside the same chunk is then not inspected.
	entries := append(validEntry("/payload.exe", 0), encEncint(64)...)
	entries = append(entries, []byte("short")...) // fewer bytes than declared
	entries = append(entries, validEntry("/later.exe", 1)...)
	names, truncated := enumerate(buildCHMRaw(t, entries))
	if !truncated {
		t.Errorf("name overrun must set truncated; names = %v", names)
	}
	if len(names) != 1 || names[0] != "/payload.exe" {
		t.Errorf("only the entry before the bound should be enumerated; got %v", names)
	}
}

func TestCHMExcessiveNameLengthMarksTruncated(t *testing.T) {
	// A name length beyond the parser's cap hides the rest of the chunk.
	entries := validEntry("/payload.exe", 0)
	entries = append(entries, encEncint(maxCHMNameLen+1)...)
	entries = append(entries, 'x')
	entries = append(entries, validEntry("/later.exe", 1)...)
	names, truncated := enumerate(buildCHMRaw(t, entries))
	if !truncated {
		t.Errorf("oversized name length must set truncated; names = %v", names)
	}
	if len(names) != 1 || names[0] != "/payload.exe" {
		t.Errorf("entry after the bound must not be enumerated; got %v", names)
	}
}

func TestCHMMalformedTrailingIntegersMarksTruncated(t *testing.T) {
	// The name is still recorded, but a length ENCINT that never terminates
	// ends the chunk walk and must be reported as partial.
	entries := validEntry("/payload.exe", 0)
	// Overwrite the third trailing integer (length) with an unterminated run.
	entries = entries[:len(entries)-1]
	entries = append(entries, 0xff, 0xff, 0xff, 0xff)
	entries = append(entries, validEntry("/later.exe", 1)...)
	names, truncated := enumerate(buildCHMRaw(t, entries))
	if !truncated {
		t.Errorf("unterminated trailing integer must set truncated; names = %v", names)
	}
	if len(names) != 1 || names[0] != "/payload.exe" {
		t.Errorf("the entry read before the bound should be kept; got %v", names)
	}
}

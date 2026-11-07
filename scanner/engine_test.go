package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineSinglePassMatchesSeparateDetectors(t *testing.T) {
	ys := loadRepoYara(t)
	path := writeTempFile(t, "wannacry.bin", []byte(wannacrySample))
	d, _ := hashFile(path)
	db := NewSignatureDB()
	_ = db.Add(Signature{HashType: "SHA1", Hash: d.sha1, ThreatName: "Synthetic WannaCry"})

	e := &Engine{DB: db, Yara: ys, Heuristics: true}
	res, h := e.ScanFile(path)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if !res.Detected || res.MatchType != "SHA1" || res.ThreatName != "Synthetic WannaCry" {
		t.Errorf("hash: %+v", res)
	}
	findMatch(t, res.YaraMatches, "wannacry_ransomware")
	if h == nil {
		t.Fatal("heuristics enabled but no result")
	}
	if h.FilePath != path || h.Error != nil || h.Skipped != "" {
		t.Errorf("heuristic result: %+v", h)
	}

	// Same answers as the independent entry points.
	sep := ScanFile(path, db, ys)
	if sep.SHA256 != res.SHA256 || len(sep.YaraMatches) != len(res.YaraMatches) || sep.Detected != res.Detected {
		t.Errorf("Engine and ScanFile disagree: %+v vs %+v", sep, res)
	}
	hs := ScanHeuristics(path)
	if hs.Score != h.Score || len(hs.Matches) != len(h.Matches) {
		t.Errorf("Engine and ScanHeuristics disagree: %d/%d vs %d/%d", hs.Score, len(hs.Matches), h.Score, len(h.Matches))
	}
}

func TestEngineLargeFileIsStreamed(t *testing.T) {
	const needle = "CAU_ENGINE_STREAM_PROBE"
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{
		Text: "rule stream_probe { strings: $n = \"" + needle + "\" condition: $n }",
	}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	buf := bytes.Repeat([]byte{0x20}, 256*1024)
	copy(buf[100000:], needle)
	path := writeTempFile(t, "big.bin", buf)
	want := hashBytes(buf)

	e := &Engine{DB: NewSignatureDB(), Yara: ys, Heuristics: true, MaxInMemory: 4096}
	res, h := e.ScanFile(path)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if res.SHA256 != want.sha256 || res.MD5 != want.md5 {
		t.Errorf("streamed hashes differ from in-memory hashes")
	}
	m := findMatch(t, res.YaraMatches, "stream_probe")
	if s := findString(t, m, "$n"); s.Offset != 100000 {
		t.Errorf("mmap offset = %d, want 100000", s.Offset)
	}
	if h == nil || h.Skipped == "" || h.Detected() || h.Error != nil {
		t.Errorf("heuristics on an oversized file must be skipped with a reason, got %+v", h)
	}
	if !strings.Contains(h.Skipped, "in-memory limit") {
		t.Errorf("skip reason = %q", h.Skipped)
	}
}

func TestEngineScanDirectoryIsDeterministicAndConcurrent(t *testing.T) {
	root := t.TempDir()
	var want []string
	for _, rel := range []string{"a/1.bin", "a/2.bin", "b/x.bin", "c/d/e.bin", "z.bin"} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content "+rel), 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, p)
	}
	// Things that must be skipped, not errored: a symlink to a directory
	// (loop risk) and a dangling symlink.
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link_to_dir")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "nope"), filepath.Join(root, "dangling")); err != nil {
			t.Fatal(err)
		}
	}

	e := &Engine{DB: NewSignatureDB(), Heuristics: true, Jobs: 8}
	var progressCalls int
	results, hs := e.ScanDirectory(root, func(done, total int, path string) { progressCalls++ })

	got := make([]string, 0, len(results))
	for _, r := range results {
		if r.Error != nil {
			t.Errorf("%s: %v", r.FilePath, r.Error)
		}
		got = append(got, r.FilePath)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order/content mismatch:\n got %v\nwant %v", got, want)
	}
	if len(hs) != len(want) {
		t.Errorf("%d heuristic results, want %d", len(hs), len(want))
	}
	for i := range hs {
		if hs[i].FilePath != want[i] {
			t.Errorf("heuristic[%d] = %s, want %s (alignment broken)", i, hs[i].FilePath, want[i])
		}
	}
	if progressCalls != len(want) {
		t.Errorf("progress called %d times, want %d", progressCalls, len(want))
	}

	// Repeat with Jobs=1 and compare: concurrency must not change output.
	single, _ := (&Engine{DB: NewSignatureDB(), Heuristics: true, Jobs: 1}).ScanDirectory(root, nil)
	for i := range single {
		if single[i].FilePath != results[i].FilePath || single[i].SHA256 != results[i].SHA256 {
			t.Errorf("Jobs=1 and Jobs=8 disagree at %d", i)
		}
	}
}

func TestEngineScanDirectoryFollowsFileSymlinksOnlyWhenAsked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	root := t.TempDir()
	target := writeTempFile(t, "target.bin", []byte("linked"))
	if err := os.Symlink(target, filepath.Join(root, "link.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plain.bin"), []byte("plain"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _ := (&Engine{}).ScanDirectory(root, nil)
	if len(res) != 1 || filepath.Base(res[0].FilePath) != "plain.bin" {
		t.Errorf("symlink followed by default: %v", paths(res))
	}
	res, _ = (&Engine{FollowSymlinks: true}).ScanDirectory(root, nil)
	if len(res) != 2 {
		t.Errorf("FollowSymlinks: got %v", paths(res))
	}
	for _, r := range res {
		if r.Error != nil {
			t.Errorf("%s: %v", r.FilePath, r.Error)
		}
	}
}

func TestEngineScanDirectoryReportsUnreadableEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "secret.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if err := os.WriteFile(filepath.Join(root, "ok.bin"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _ := (&Engine{}).ScanDirectory(root, nil)
	var errs, oks int
	for _, r := range res {
		if r.Error != nil {
			errs++
		} else {
			oks++
		}
	}
	if errs != 1 || oks != 1 {
		t.Errorf("want 1 error + 1 ok, got %d errors, %d ok: %v", errs, oks, paths(res))
	}
}

func paths(rs []ScanResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.FilePath
	}
	return out
}

// hostileELF is a relocatable object whose .symtab declares a 1-byte entsize
// with the table at end-of-file: the input that used to panic the ELF parser.
// It is built here so the engine test does not depend on the static package's
// test helpers.
func hostileELF() []byte {
	const shentsize, shnum = 64, 4
	le := func(b []byte, v uint64, n int) {
		for i := 0; i < n; i++ {
			b[i] = byte(v >> (8 * i))
		}
	}
	header := make([]byte, 64)
	shtab := make([]byte, shnum*shentsize)
	shstr := append([]byte{0}, []byte(".symtab\x00.strtab\x00.shstrtab\x00")...)
	strtab := append([]byte{0}, []byte("evil\x00")...)
	shoff := uint64(len(header))
	shstrOff := shoff + uint64(len(shtab))
	strOff := shstrOff + uint64(len(shstr))
	symOff := strOff + uint64(len(strtab))
	symSize := uint64(40)

	putSec := func(idx int, nameOff, typ uint32, off, size, link, entsize uint64) {
		b := shtab[idx*shentsize:]
		le(b[0:], uint64(nameOff), 4)
		le(b[4:], uint64(typ), 4)
		le(b[24:], off, 8)
		le(b[32:], size, 8)
		le(b[40:], link, 4)
		le(b[56:], entsize, 8)
	}
	putSec(1, 1, 2 /*SHT_SYMTAB*/, symOff, symSize, 2, 1 /*tiny*/)
	putSec(2, 9, 3 /*SHT_STRTAB*/, strOff, uint64(len(strtab)), 0, 0)
	putSec(3, 17, 3, shstrOff, uint64(len(shstr)), 0, 0)

	copy(header[0:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le(header[16:], 1, 2)  // ET_REL
	le(header[18:], 62, 2) // x86-64
	le(header[20:], 1, 4)
	le(header[40:], shoff, 8)
	le(header[52:], 64, 2)
	le(header[58:], shentsize, 2)
	le(header[60:], shnum, 2)
	le(header[62:], 3, 2)

	buf := append([]byte{}, header...)
	buf = append(buf, shtab...)
	buf = append(buf, shstr...)
	buf = append(buf, strtab...)
	buf = append(buf, make([]byte, symSize)...)
	return buf
}

// TestEngineHostileFileDoesNotBreakBatch is the stability contract: a file
// that stresses a parser must degrade to a per-file result and never take
// down the rest of a directory scan.
func TestEngineHostileFileDoesNotBreakBatch(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a_clean.txt"), []byte("hello, world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b_hostile.o"), hostileELF(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "c_clean.txt"), []byte("goodbye, world"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := &Engine{DB: NewSignatureDB(), Heuristics: true, Static: true, Stego: true, Jobs: 4}
	results, _ := e.ScanDirectory(root, nil)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (a hostile file must not drop the others)", len(results))
	}
	byName := map[string]ScanResult{}
	for _, r := range results {
		byName[filepath.Base(r.FilePath)] = r
	}
	// The two clean files scan normally.
	for _, n := range []string{"a_clean.txt", "c_clean.txt"} {
		if r, ok := byName[n]; !ok || r.Error != nil {
			t.Errorf("%s should scan cleanly: %+v", n, r)
		}
	}
	// The hostile file produced a result (no crash); the parser fix means it
	// is not even an error, but either way the batch survived.
	if _, ok := byName["b_hostile.o"]; !ok {
		t.Error("hostile file missing from results")
	}

	// Scanning the hostile file on its own also returns rather than panics.
	single := writeTempFile(t, "hostile.o", hostileELF())
	res, _ := e.ScanFile(single)
	if res.FilePath == "" {
		t.Error("ScanFile returned an empty result on hostile input")
	}
}

// A YARA pass that errored or timed out judged only part of the file, so the
// result must not be readable as a full scan of a clean file. A closed scanner
// fails every scan: the error path and the timeout path meet there.
func TestIncompleteYaraPassIsNotACleanVerdict(t *testing.T) {
	const rule = "rule no_needle { strings: $n = \"CAU_NO_SUCH_BYTES_ANYWHERE\" condition: $n }"
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{Text: rule}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ys.Close(); err != nil {
		t.Fatal(err)
	}

	path := writeTempFile(t, "partial.bin", []byte("plain bytes, nothing wrong with them"))
	res, _ := (&Engine{Yara: ys}).ScanFile(path)
	if res.Verdict != VerdictError || res.Error == nil {
		t.Fatalf("verdict %v, err %v: a YARA pass that did not finish must not read as clean", res.Verdict, res.Error)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "YARA:") {
		t.Fatalf("the warning is the trace of what happened: %v", res.Warnings)
	}
	if res.Detected || len(res.YaraMatches) != 0 {
		t.Fatalf("nothing matched, so no detection may be invented: %+v", res)
	}

	// The other side of the same rule: a pass that ran keeps its clean verdict.
	ok, _, err := LoadYaraRuleFiles([]RuleSource{{Text: rule}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()
	res2, _ := (&Engine{Yara: ok}).ScanFile(path)
	if res2.Verdict != VerdictClean || res2.Error != nil {
		t.Fatalf("a YARA pass that ran on a clean file: verdict %v, err %v", res2.Verdict, res2.Error)
	}
}

// Above the in-memory limit the digests come from one open of the path and
// YARA's matches from a later one. A file replaced in between must be reported
// as an incomplete scan, never as coherent evidence about one version.
func TestFileReplacedBetweenHashAndYaraIsFlagged(t *testing.T) {
	const needle = "CAU_SWAP_NEEDLE"
	ys, _, err := LoadYaraRuleFiles([]RuleSource{{
		Text: "rule swap_probe { strings: $n = \"" + needle + "\" condition: $n }",
	}}, WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	original := bytes.Repeat([]byte{0x20}, 8192)
	want := hashBytes(original)
	path := writeTempFile(t, "streamed.bin", original)

	e := &Engine{Yara: ys, MaxInMemory: 4096}
	swapped := false
	e.beforeDetector = func(name string) {
		if name != "yara" || swapped {
			return
		}
		// The write happens on the detector goroutine, so the error is only
		// visible here; a temp-directory write is not the thing under test.
		swapped = true
		_ = os.WriteFile(path, append(bytes.Repeat([]byte{0x20}, 4096), needle...), 0o644)
	}
	res, _ := e.ScanFile(path)
	if !swapped {
		t.Fatal("the swap never happened, so this proves nothing")
	}

	// The digests kept their version, which is exactly the mixing to prevent.
	if res.SHA256 != want.sha256 || res.MD5 != want.md5 {
		t.Errorf("hashes drifted from the version that was read first")
	}
	if res.Verdict != VerdictError || res.Error == nil {
		t.Fatalf("verdict %v, err %v: hashes and matches may describe different versions", res.Verdict, res.Error)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "changed while it was scanned") {
		t.Fatalf("the report has to say what happened: %v", res.Warnings)
	}
	// YARA read the second version, so its matches are kept rather than dropped.
	if got := ruleNames(res.YaraMatches); len(got) != 1 || got[0] != "swap_probe" {
		t.Fatalf("YARA matches = %v, want swap_probe (the match must not be dropped)", got)
	}
}

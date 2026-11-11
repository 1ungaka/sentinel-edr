package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/scanner/static"
)

func TestEngineStaticPass(t *testing.T) {
	path := writeTempFile(t, "text.bin", []byte(strings.Repeat("ordinary text content\n", 400)))
	db := NewSignatureDB()

	// Off by default: no result.
	res, _ := (&Engine{DB: db}).ScanFile(path)
	if res.Static != nil {
		t.Error("static result present with Static=false")
	}

	// On: entropy + digests for any file type, no anomalies for text.
	res, _ = (&Engine{DB: db, Static: true}).ScanFile(path)
	if res.Static == nil {
		t.Fatal("static result missing")
	}
	s := res.Static
	if s.FilePath != path || s.IsPE || s.Score != 0 || s.Detected() || s.Fuzzy.TLSH == "" || s.Fuzzy.SSDeep == "" {
		t.Errorf("static = %+v", s)
	}
	if res.Verdict != VerdictClean {
		t.Errorf("verdict = %s", res.Verdict)
	}

	// NoFuzzy skips the digests but keeps the analysis.
	res, _ = (&Engine{DB: db, Static: true, StaticNoFuzzy: true}).ScanFile(path)
	if res.Static.Fuzzy.TLSH != "" || res.Static.Fuzzy.SSDeep != "" {
		t.Errorf("digests computed with StaticNoFuzzy: %+v", res.Static.Fuzzy)
	}

	// Threshold plumbing.
	res, _ = (&Engine{DB: db, Static: true, StaticThreshold: 42}).ScanFile(path)
	if res.Static.Threshold != 42 || res.Static.EffectiveThreshold() != 42 {
		t.Errorf("threshold = %d", res.Static.Threshold)
	}
}

func TestEngineStaticSkippedOverInMemoryLimit(t *testing.T) {
	big := bytes.Repeat([]byte{0x41}, 64*1024)
	path := writeTempFile(t, "big.bin", big)
	res, h := (&Engine{DB: NewSignatureDB(), Heuristics: true, Static: true, MaxInMemory: 1024}).ScanFile(path)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if h == nil || h.Skipped == "" {
		t.Error("heuristics should be skipped over the limit")
	}
	if res.Static == nil || res.Static.Skipped == "" || res.Static.Detected() || res.Static.FilePath != path {
		t.Errorf("static over the limit: %+v", res.Static)
	}
	// Hashing still happened on the streamed path.
	if res.SHA256 == "" {
		t.Error("no SHA256 for streamed file")
	}
}

func TestEngineStaticFuzzyDB(t *testing.T) {
	data := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog 0123456789 "), 300)
	for i := range data {
		data[i] ^= byte(i * 7) // give TLSH something with byte variety
	}
	path := writeTempFile(t, "sample.bin", data)
	h := static.ComputeFuzzy(data)
	if h.TLSH == "" {
		t.Fatalf("no TLSH: %s", h.TLSHNote)
	}
	fdb, err := static.ParseFuzzyDB(strings.NewReader("TLSH|"+h.TLSH+"|Synthetic Family\n"), "mem")
	if err != nil {
		t.Fatal(err)
	}
	res, _ := (&Engine{DB: NewSignatureDB(), Static: true, FuzzyDB: fdb}).ScanFile(path)
	s := res.Static
	if len(s.FuzzyMatches) != 1 || s.FuzzyMatches[0].ThreatName != "Synthetic Family" || !s.Detected() {
		t.Errorf("fuzzy: matches %+v score %d", s.FuzzyMatches, s.Score)
	}
	// Similarity is the SUSPICIOUS tier: the scan verdict stays CLEAN; the
	// report layer promotes it, exactly like a heuristic breach.
	if res.Verdict != VerdictClean || res.Detected {
		t.Errorf("fuzzy match must not produce a MALICIOUS verdict: %s", res.Verdict)
	}
}

func TestEngineDirectoryCarriesStatic(t *testing.T) {
	dir := t.TempDir()
	writeFileIn(t, dir, "a.txt", []byte(strings.Repeat("a plain file\n", 200)))
	writeFileIn(t, dir, "b.txt", []byte(strings.Repeat("another one\n", 200)))
	results, _ := (&Engine{DB: NewSignatureDB(), Static: true, Jobs: 2}).ScanDirectory(dir, nil)
	if len(results) != 2 {
		t.Fatalf("results = %d", len(results))
	}
	for _, r := range results {
		if r.Static == nil || r.Static.FilePath != r.FilePath {
			t.Errorf("%s: static %+v", r.FilePath, r.Static)
		}
	}
}

func writeFileIn(t testing.TB, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

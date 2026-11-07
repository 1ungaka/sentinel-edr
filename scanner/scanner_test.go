package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

const repoSignatures = "../signatures/hashes.txt"

func TestValidateHash(t *testing.T) {
	tests := []struct {
		typ, hash string
		wantType  string
		wantErr   string
	}{
		{"SHA256", strings.Repeat("ab", 32), "SHA256", ""},
		{"sha-256", strings.ToUpper(strings.Repeat("ab", 32)), "SHA256", ""},
		{"md5", strings.Repeat("0f", 16), "MD5", ""},
		{"Sha1", strings.Repeat("9c", 20), "SHA1", ""},
		{"SHA256", strings.Repeat("ab", 31) + "a", "", "has 63 hex characters, want 64"},
		{"SHA256", strings.Repeat("ab", 16), "", "the length matches MD5"},
		{"MD5", strings.Repeat("ab", 32), "", "the length matches SHA256"},
		{"SHA256", strings.Repeat("zz", 32), "", "not hexadecimal"},
		{"SHA256", "", "", "empty"},
		{"CRC32", "deadbeef", "", "unsupported hash type"},
	}
	for _, tc := range tests {
		gotType, gotHash, err := ValidateHash(tc.typ, tc.hash)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ValidateHash(%q, %q) error = %v, want substring %q", tc.typ, tc.hash, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateHash(%q, %q): %v", tc.typ, tc.hash, err)
			continue
		}
		if gotType != tc.wantType || gotHash != strings.ToLower(tc.hash) {
			t.Errorf("ValidateHash(%q, %q) = %q,%q", tc.typ, tc.hash, gotType, gotHash)
		}
	}
}

func TestParseSignaturesRejectsBadLines(t *testing.T) {
	src := strings.Join([]string{
		"# comment",
		"",
		"SHA256|" + strings.Repeat("aa", 32) + "|Alpha",
		"MD5|" + strings.Repeat("bb", 16) + "|Beta",
		"SHA256|" + strings.Repeat("aa", 32) + "|Alpha",     // exact duplicate
		"SHA256|" + strings.Repeat("aa", 32) + "|Different", // conflict
		"SHA256|" + strings.Repeat("cc", 31) + "c|Short",    // 63 chars
		"SHA256|" + strings.Repeat("bb", 16) + "|WrongType", // md5-length under SHA256
		"SHA1|" + strings.Repeat("zz", 20) + "|NotHex",
		"garbage line",
		"SHA256|" + strings.Repeat("dd", 32) + "|",       // empty name
		"sha1|" + strings.Repeat("EE", 20) + "|  Gamma ", // normalised
	}, "\n")

	db, err := ParseSignatures(strings.NewReader(src), "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3 (%v)", got, db.Warnings())
	}
	if got := db.Skipped(); got != 7 {
		t.Errorf("Skipped() = %d, want 7:\n%s", got, strings.Join(db.Warnings(), "\n"))
	}
	byType := db.CountByType()
	if byType["SHA256"] != 1 || byType["MD5"] != 1 || byType["SHA1"] != 1 {
		t.Errorf("CountByType() = %v", byType)
	}

	// The first entry wins on conflict.
	sig, ok := db.Lookup(strings.ToUpper(strings.Repeat("aa", 32)))
	if !ok || sig.ThreatName != "Alpha" {
		t.Errorf("Lookup = %+v, %v; want Alpha", sig, ok)
	}
	if sig, ok := db.Lookup(strings.Repeat("ee", 20)); !ok || sig.ThreatName != "Gamma" || sig.HashType != "SHA1" {
		t.Errorf("normalised entry = %+v, %v", sig, ok)
	}

	joined := strings.Join(db.Warnings(), "\n")
	for _, want := range []string{
		"test.txt:5: skipped: duplicate SHA256",
		"test.txt:6: skipped: conflicting SHA256",
		`already listed as "Alpha" at line 3`,
		"test.txt:7: skipped: SHA256 hash",
		"has 63 hex characters",
		"test.txt:8:",
		"the length matches MD5",
		"test.txt:9:",
		"not hexadecimal",
		"test.txt:10: skipped: malformed line",
		"test.txt:11: skipped: empty threat name",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings lack %q:\n%s", want, joined)
		}
	}
	if sigs := db.Signatures(); len(sigs) != 3 || sigs[0].HashType != "MD5" || sigs[1].HashType != "SHA1" {
		t.Errorf("Signatures() order = %+v", sigs)
	}
}

// TestShippedSignatureDatabaseIsClean fails the build if signatures/hashes.txt
// regresses to carrying invalid, duplicate or synthetic entries.
func TestShippedSignatureDatabaseIsClean(t *testing.T) {
	db, err := LoadSignatures(repoSignatures)
	if err != nil {
		t.Fatal(err)
	}
	if w := db.Warnings(); len(w) != 0 {
		t.Errorf("shipped database has %d rejected lines:\n%s", len(w), strings.Join(w, "\n"))
	}
	if db.Count() < 10 {
		t.Errorf("shipped database has only %d entries", db.Count())
	}
	for _, s := range db.Signatures() {
		if looksSynthetic(s.Hash) {
			t.Errorf("entry %s %s (%s) looks like synthetic filler", s.HashType, s.Hash, s.ThreatName)
		}
	}
}

// looksSynthetic flags digests built from a repeating "a1b2c3d4..." style
// sequence: the hex digits cycle through the alphabet in order.
func looksSynthetic(h string) bool {
	ascending := 0
	for i := 1; i < len(h); i += 2 {
		if i+2 < len(h) && h[i+2] == h[i]+1 && (h[i-1] == h[i+1]-1 || h[i-1] == h[i+1]+1) {
			ascending++
		}
	}
	return ascending > len(h)/4
}

func TestAddSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hashes.txt")
	h1 := strings.Repeat("01", 32)
	h2 := strings.Repeat("02", 16)

	if err := AddSignature(path, "sha256", strings.ToUpper(h1), "First"); err != nil {
		t.Fatalf("AddSignature to a new file: %v", err)
	}
	// No trailing newline on the existing file must not glue entries together.
	if err := os.WriteFile(path, []byte("SHA256|"+h1+"|First"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddSignature(path, "MD5", h2, "Second"); err != nil {
		t.Fatalf("AddSignature append: %v", err)
	}

	db, err := LoadSignatures(path)
	if err != nil {
		t.Fatal(err)
	}
	if db.Count() != 2 || len(db.Warnings()) != 0 {
		data, _ := os.ReadFile(path)
		t.Fatalf("after two adds: count=%d warnings=%v file=%q", db.Count(), db.Warnings(), data)
	}

	cases := []struct {
		typ, hash, name, wantErr string
	}{
		{"SHA256", h1, "First", "already in"},
		{"SHA256", h1, "Renamed", "remove that line first"},
		{"SHA256", h2, "WrongType", "the length matches MD5"},
		{"SHA256", strings.Repeat("0g", 32), "NotHex", "not hexadecimal"},
		{"SHA256", strings.Repeat("03", 32), "", "must not be empty"},
		{"SHA256", strings.Repeat("03", 32), "a|b", "must not contain"},
		{"SHA512", strings.Repeat("03", 32), "x", "unsupported hash type"},
	}
	for _, tc := range cases {
		err := AddSignature(path, tc.typ, tc.hash, tc.name)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("AddSignature(%s,%s,%q) error = %v, want %q", tc.typ, tc.hash, tc.name, err, tc.wantErr)
		}
	}

	db, _ = LoadSignatures(path)
	if db.Count() != 2 {
		t.Errorf("rejected adds changed the database: count=%d", db.Count())
	}
}

func TestScanFileHashDetection(t *testing.T) {
	path := writeTempFile(t, "sample.bin", []byte("CAU hash detection sample"))
	// SHA256 of the content above, computed by the scanner itself.
	d, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}

	db := NewSignatureDB()
	if err := db.Add(Signature{HashType: "md5", Hash: d.md5, ThreatName: "Via MD5"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Add(Signature{HashType: "SHA256", Hash: d.sha256, ThreatName: "Via SHA256"}); err != nil {
		t.Fatal(err)
	}

	res := ScanFile(path, db, nil)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if !res.Detected || res.Verdict != VerdictMalicious {
		t.Fatalf("not detected: %+v", res)
	}
	// SHA256 is consulted first.
	if res.MatchType != "SHA256" || res.ThreatName != "Via SHA256" || res.MatchHash != d.sha256 {
		t.Errorf("match = %s %s %q", res.MatchType, res.MatchHash, res.ThreatName)
	}
	if res.MD5 != d.md5 || res.SHA1 != d.sha1 || res.SHA256 != d.sha256 {
		t.Errorf("hashes differ between streaming and in-memory paths")
	}
	if res.Size != int64(len("CAU hash detection sample")) {
		t.Errorf("Size = %d", res.Size)
	}

	clean := ScanFile(writeTempFile(t, "clean.bin", []byte("nothing")), db, nil)
	if clean.Detected || clean.Verdict != VerdictClean || clean.Error != nil {
		t.Errorf("clean file: %+v", clean)
	}

	missing := ScanFile(filepath.Join(t.TempDir(), "missing"), db, nil)
	if missing.Error == nil || missing.Verdict != VerdictError {
		t.Errorf("missing file: %+v", missing)
	}
	dirRes := ScanFile(t.TempDir(), db, nil)
	if dirRes.Error == nil || !strings.Contains(dirRes.Error.Error(), "is a directory") {
		t.Errorf("directory: %+v", dirRes)
	}
}

func TestHashBytesMatchesHashReader(t *testing.T) {
	data := []byte(strings.Repeat("abc123", 10000))
	a := hashBytes(data)
	b, err := hashReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("hashBytes %+v != hashReader %+v", a, b)
	}
}

// The streaming path hands SHA-1 and SHA-256 to a helper for the whole pass,
// so many chunks must give the same digests as one. A reader that returns one
// byte at a time goes through the chunk machinery with an empty tail.
func TestHashReaderManyChunksMatchInMemory(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 40000) // ~640 KiB, over one chunk
	whole := hashBytes(data)
	streamed, err := hashReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if whole != streamed {
		t.Fatalf("one pass %+v != streamed %+v", whole, streamed)
	}
	drip, err := hashReader(iotest.OneByteReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	if whole != drip {
		t.Fatalf("one pass %+v != one-byte reads %+v", whole, drip)
	}
}

func BenchmarkHashReader(b *testing.B) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<19) // 8 MiB, several chunks
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := hashReader(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

package heldout

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a MalwareBazaar-shaped CSV: a '#' comment block, then 14-column quoted rows.
func mbCSV(rows ...string) string {
	head := "# MalwareBazaar export\n# first_seen_utc,sha256_hash,...\n"
	return head + strings.Join(rows, "\n") + "\n"
}

func mbRow(first, sha, reporter, ftype, sig, imphash, tags string) string {
	cols := []string{first, sha, "md5", "sha1", reporter, "file", ftype, "mime", sig, "clamav", "50", imphash, "ssdeep", tags}
	for i, c := range cols {
		cols[i] = `"` + c + `"`
	}
	return strings.Join(cols, ",")
}

func testOpts(o PullOptions) *PullOptions { o.defaults(); return &o }

func TestIngestCSV(t *testing.T) {
	csv := mbCSV(
		mbRow("2024-01-01", sha1, "rep1", "exe", "LokiBot", "imphashAAA", "exe,lokibot"),
		mbRow("2024-01-02", sha2, "rep2", "elf", "Mimikatz", "", "mimikatz"),
	)
	db := &DB{}
	saves := 0
	save := func(*DB) error { saves++; return nil }
	stats, err := ingestCSV(context.Background(), strings.NewReader(csv), db, save, testOpts(PullOptions{Batch: 100}), PullStats{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Added != 2 || stats.Seen != 2 {
		t.Fatalf("stats = %+v, want 2 added / 2 seen", stats)
	}
	if db.Len() != 2 {
		t.Fatalf("db has %d, want 2", db.Len())
	}
	var loki *Record
	for i := range db.Records {
		if db.Records[i].SHA256 == sha1 {
			loki = &db.Records[i]
		}
	}
	if loki == nil {
		t.Fatal("lokibot row not ingested")
	}
	if loki.Family != "lokibot" || loki.Signature != "lokibot" {
		t.Errorf("family/signature = %q/%q", loki.Family, loki.Signature)
	}
	if loki.FileType != "exe" || loki.Imphash != "imphashAAA" || loki.FirstSeen != "2024-01-01" {
		t.Errorf("intel not captured: %+v", loki)
	}
	if len(loki.Tags) != 2 || loki.Tags[0] != "exe" {
		t.Errorf("tags = %v", loki.Tags)
	}
	if !strings.HasSuffix(loki.URL, sha1+"/") {
		t.Errorf("provenance url = %q", loki.URL)
	}
	if saves == 0 {
		t.Error("final checkpoint not saved")
	}
}

func TestIngestDedupAndUpdate(t *testing.T) {
	csv := mbCSV(
		mbRow("2024-01-01", sha1, "rep1", "exe", "LokiBot", "", "a"),
		mbRow("2024-02-02", sha1, "rep1", "exe", "LokiBot", "", "a,newtag"), // same hash, richer intel
	)
	db := &DB{}
	stats, err := ingestCSV(context.Background(), strings.NewReader(csv), db, func(*DB) error { return nil }, testOpts(PullOptions{Batch: 100}), PullStats{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Added != 1 || stats.Updated != 1 {
		t.Fatalf("stats = %+v, want 1 added / 1 updated", stats)
	}
	if db.Len() != 1 {
		t.Fatalf("db has %d, want 1 (deduped)", db.Len())
	}
	if len(db.Records[0].Tags) != 2 {
		t.Errorf("intel not refreshed on update: %v", db.Records[0].Tags)
	}
}

func TestIngestFamilyFilterAndLimit(t *testing.T) {
	csv := mbCSV(
		mbRow("d", sha1, "r", "exe", "LokiBot", "", ""),
		mbRow("d", sha2, "r", "elf", "Mimikatz", "", ""),
	)
	db := &DB{}
	stats, _ := ingestCSV(context.Background(), strings.NewReader(csv), db, func(*DB) error { return nil }, testOpts(PullOptions{Batch: 100, Family: "mimikatz"}), PullStats{})
	if stats.Added != 1 || db.Records[0].Family != "mimikatz" {
		t.Errorf("family filter: added %d, %+v", stats.Added, db.Records)
	}

	db2 := &DB{}
	stats2, _ := ingestCSV(context.Background(), strings.NewReader(csv), db2, func(*DB) error { return nil }, testOpts(PullOptions{Batch: 100, Limit: 1}), PullStats{})
	if stats2.Added != 1 {
		t.Errorf("limit: added %d, want 1", stats2.Added)
	}
}

func TestIngestCheckpointEveryBatch(t *testing.T) {
	csv := mbCSV(
		mbRow("d", sha1, "r", "exe", "a", "", ""),
		mbRow("d", sha2, "r", "exe", "b", "", ""),
	)
	db := &DB{}
	saves := 0
	_, err := ingestCSV(context.Background(), strings.NewReader(csv), db, func(*DB) error { saves++; return nil }, testOpts(PullOptions{Batch: 1}), PullStats{})
	if err != nil {
		t.Fatal(err)
	}
	if saves != 2 {
		t.Errorf("checkpoints = %d, want 2 (one per new record at batch=1)", saves)
	}
}

// A crash between checkpoints must not lose or double-count: re-running over
// the same feed with the already-saved records present skips them.
func TestIngestResumeSkipsPresent(t *testing.T) {
	csv := mbCSV(
		mbRow("d", sha1, "r", "exe", "a", "", ""),
		mbRow("d", sha2, "r", "exe", "b", "", ""),
	)
	db := &DB{}
	// First pass: pretend the process died after the first checkpoint by
	// keeping only what was saved — simulate by ingesting with Limit 1.
	_, _ = ingestCSV(context.Background(), strings.NewReader(csv), db, func(*DB) error { return nil }, testOpts(PullOptions{Batch: 1, Limit: 1}), PullStats{})
	if db.Len() != 1 {
		t.Fatalf("first pass added %d, want 1", db.Len())
	}
	// Second pass over the whole feed: the present hash is skipped.
	stats, _ := ingestCSV(context.Background(), strings.NewReader(csv), db, func(*DB) error { return nil }, testOpts(PullOptions{Batch: 100}), PullStats{})
	if stats.Added != 1 {
		t.Errorf("resume added %d new, want 1 (the remaining row)", stats.Added)
	}
	if db.Len() != 2 {
		t.Errorf("db has %d, want 2 total", db.Len())
	}
}

func TestDownloadResumable(t *testing.T) {
	payload := bytes.Repeat([]byte("MALWAREBAZAAR-EXPORT-ZIP-BYTES!!"), 4096) // 128 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "full.zip", time.Unix(0, 0), bytes.NewReader(payload))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "full.zip")

	// Fresh download: full body, 200.
	n, resumed, err := downloadResumable(context.Background(), srv.URL, dest, srv.Client(), 3, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if resumed || n != int64(len(payload)) {
		t.Fatalf("fresh: n=%d resumed=%v, want %d/false", n, resumed, len(payload))
	}

	// Truncate to simulate a partial download, then resume: Range -> 206.
	half := len(payload) / 2
	if err := os.WriteFile(dest, payload[:half], 0o600); err != nil {
		t.Fatal(err)
	}
	n, resumed, err = downloadResumable(context.Background(), srv.URL, dest, srv.Client(), 3, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed || n != int64(len(payload)) {
		t.Fatalf("resume: n=%d resumed=%v, want %d/true", n, resumed, len(payload))
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed file does not match the full payload")
	}

	// Already complete: Range beyond EOF -> 416 -> treated as done.
	n, _, err = downloadResumable(context.Background(), srv.URL, dest, srv.Client(), 3, time.Now)
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("complete: n=%d err=%v", n, err)
	}
}

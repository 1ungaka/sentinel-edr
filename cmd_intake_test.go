package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

const (
	testSHA256 = "1111111111111111111111111111111111111111111111111111111111111111"
	testSHA1   = "2222222222222222222222222222222222222222"
)

func TestCLIIntakeDryRun(t *testing.T) {
	work := t.TempDir()
	feed := filepath.Join(work, "drivers.json")
	os.WriteFile(feed, []byte(`[{"Id":"x","KnownVulnerableSamples":[{"SHA256":"`+testSHA256+`","Filename":"evil.sys"}]}]`), 0o644)

	code, out, errOut := runCLI(t, "intake", "--format", "loldrivers", "--input", feed, "--dry-run")
	if code != report.ExitOK {
		t.Fatalf("intake dry-run: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "SHA256|"+testSHA256+"|") {
		t.Errorf("dry-run output missing signature line:\n%s", out)
	}
	if !strings.Contains(out, "evil.sys") {
		t.Errorf("dry-run output missing driver label:\n%s", out)
	}
}

func TestCLIIntakeAppendsToDB(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("9", 64)+"|Seed\n"), 0o644)
	feed := filepath.Join(work, "mb.json")
	os.WriteFile(feed, []byte(`{"query_status":"ok","data":[{"sha256_hash":"`+testSHA256+`","signature":"AgentTesla"}]}`), 0o644)

	code, out, errOut := runCLI(t, "intake", "--format", "malwarebazaar", "--input", feed, "--db", db)
	if code != report.ExitOK {
		t.Fatalf("intake append: code=%d err=%s", code, errOut)
	}
	if !strings.Contains(out, "appended 1") {
		t.Errorf("unexpected output: %q", out)
	}
	content, _ := os.ReadFile(db)
	if !strings.Contains(string(content), "SHA256|"+testSHA256+"|AgentTesla") {
		t.Errorf("db not appended:\n%s", content)
	}
	// Second run is a no-op (already present).
	code, out, _ = runCLI(t, "intake", "--format", "malwarebazaar", "--input", feed, "--db", db)
	if code != report.ExitOK || !strings.Contains(out, "nothing new") {
		t.Errorf("second run should be a no-op: code=%d out=%q", code, out)
	}
}

func TestCLIIntakeOutputFile(t *testing.T) {
	work := t.TempDir()
	feed := filepath.Join(work, "stix.json")
	os.WriteFile(feed, []byte(`{"type":"bundle","objects":[{"type":"indicator","name":"X","pattern":"[file:hashes.'SHA-1'='`+testSHA1+`']"}]}`), 0o644)
	out := filepath.Join(work, "new.txt")

	code, _, errOut := runCLI(t, "intake", "--format", "stix", "--input", feed, "--output", out)
	if code != report.ExitOK {
		t.Fatalf("intake --output: code=%d err=%s", code, errOut)
	}
	content, _ := os.ReadFile(out)
	if !strings.Contains(string(content), "SHA1|"+testSHA1+"|X") {
		t.Errorf("output file wrong:\n%s", content)
	}
}

func TestCLIIntakeUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "intake"); code != report.ExitUsage {
		t.Errorf("no format: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "stix"); code != report.ExitUsage {
		t.Errorf("no input/url: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "stix", "--input", "a", "--url", "http://x"); code != report.ExitUsage {
		t.Errorf("both input and url: code=%d", code)
	}
	if code, _, _ := runCLI(t, "intake", "--format", "bogus", "--input", "/dev/null"); code != report.ExitRunFailed && code != report.ExitUsage {
		t.Errorf("bad format: code=%d", code)
	}
}

// A TAXII poll writes new signatures, a provenance record per signature, and a
// cursor; the next run sends that cursor back and a dry run changes nothing.
func TestCLIIntakeTAXII(t *testing.T) {
	var afters []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		afters = append(afters, r.URL.Query().Get("added_after"))
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.HasSuffix(r.URL.Path, "/collections/c1/objects/") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		w.Header().Set("X-TAXII-Date-Added-Last", "2026-11-05T10:00:00.000Z")
		io.WriteString(w, `{"objects":[{"type":"indicator","name":"Feed.Sample","confidence":80,"pattern":"[file:hashes.'SHA-256' = '`+testSHA256+`']"}]}`)
	}))
	defer srv.Close()
	t.Setenv("CAU_TEST_TAXII_AUTH", "Bearer tok")

	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	os.WriteFile(db, []byte("SHA256|"+strings.Repeat("9", 64)+"|Seed\n"), 0o644)
	state := filepath.Join(work, "taxii.state")
	prov := filepath.Join(work, "intake.jsonl")
	col := srv.URL + "/api/collections/c1/"
	args := []string{"intake", "--taxii", col, "--allow-http", "--auth-env", "CAU_TEST_TAXII_AUTH",
		"--taxii-state", state, "--provenance", prov, "--db", db}

	// Cleartext is refused without the opt-in, before any request.
	if code, _, errOut := runCLI(t, "intake", "--taxii", col, "--db", db); code != report.ExitRunFailed || !strings.Contains(errOut, "cleartext") || len(afters) != 0 {
		t.Fatalf("http without --allow-http: code=%d requests=%d err=%s", code, len(afters), errOut)
	}

	// A dry run prints the signature and persists nothing.
	code, out, errOut := runCLI(t, append(append([]string(nil), args...), "--dry-run")...)
	if code != report.ExitOK || !strings.Contains(out, "SHA256|"+testSHA256+"|Feed.Sample") {
		t.Fatalf("dry run: code=%d out=%q err=%s", code, out, errOut)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("a dry run must not advance the cursor")
	}
	if _, err := os.Stat(prov); err == nil {
		t.Error("a dry run must not write provenance")
	}

	code, out, errOut = runCLI(t, args...)
	if code != report.ExitOK || !strings.Contains(out, "appended 1") {
		t.Fatalf("first poll: code=%d out=%q err=%s", code, out, errOut)
	}
	if content, _ := os.ReadFile(db); !strings.Contains(string(content), "SHA256|"+testSHA256+"|Feed.Sample") {
		t.Errorf("db not appended:\n%s", content)
	}
	rec, _ := os.ReadFile(prov)
	for _, want := range []string{`"source":"stix"`, `"origin":"` + col + `"`, `"confidence":"high"`, `"retrieved_at":"20`, testSHA256} {
		if !strings.Contains(string(rec), want) {
			t.Errorf("provenance lacks %s:\n%s", want, rec)
		}
	}
	if fi, err := os.Stat(prov); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("provenance log should be owner-only: %v %v", fi, err)
	}
	if st, _ := os.ReadFile(state); !strings.Contains(string(st), "2026-11-05T10:00:00.000Z") {
		t.Errorf("cursor not saved:\n%s", st)
	}

	// The second poll sends the saved cursor and finds nothing new.
	code, out, _ = runCLI(t, args...)
	if code != report.ExitOK || !strings.Contains(out, "nothing new") {
		t.Errorf("second poll: code=%d out=%q", code, out)
	}
	if got := afters[len(afters)-1]; got != "2026-11-05T10:00:00.000Z" {
		t.Errorf("second poll sent added_after=%q; all: %q", got, afters)
	}
	if n := strings.Count(string(mustRead(t, prov)), "\n"); n != 1 {
		t.Errorf("provenance has %d records, want 1 (nothing new was added)", n)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCLIIntakeTAXIIUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"non-stix format":  {"intake", "--taxii", "https://h/collections/c/", "--format", "misp"},
		"cursor twice":     {"intake", "--taxii", "https://h/collections/c/", "--added-after", "2026-01-01T00:00:00Z", "--taxii-state", "s"},
		"state sans taxii": {"intake", "--format", "stix", "--input", "x", "--taxii-state", "s"},
		"two sources":      {"intake", "--taxii", "https://h/collections/c/", "--input", "x"},
	} {
		if code, _, errOut := runCLI(t, args...); code != report.ExitUsage {
			t.Errorf("%s: code=%d err=%s", name, code, errOut)
		}
	}
}

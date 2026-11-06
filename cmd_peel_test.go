package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/report"
)

// buildChain base64(gzip(base64(payload))) — a depth-3 chain the peeler flags.
func buildChain(payload []byte) []byte {
	inner := []byte(base64.StdEncoding.EncodeToString(payload))
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(inner)
	w.Close()
	return []byte(base64.StdEncoding.EncodeToString(gz.Bytes()))
}

func TestCLIPeelRevealsChain(t *testing.T) {
	work := t.TempDir()
	payload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("inert-body."), 8)...)
	f := filepath.Join(work, "chain.txt")
	if err := os.WriteFile(f, buildChain(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := runCLI(t, "peel", "--format", "json", f)
	if code != report.ExitThreat {
		t.Fatalf("peel chain: code=%d (want %d) err=%s", code, report.ExitThreat, errOut)
	}
	var r struct {
		Outcome          string `json:"outcome"`
		MaxDepth         int    `json:"max_depth"`
		PrimarySignature string `json:"primary_signature"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v (%s)", err, out)
	}
	if r.Outcome != "revealed-executable" {
		t.Errorf("outcome = %s, want revealed-executable", r.Outcome)
	}
	if r.MaxDepth != 3 {
		t.Errorf("max depth = %d, want 3", r.MaxDepth)
	}
	if !strings.Contains(r.PrimarySignature, "gzip") {
		t.Errorf("signature = %q, want a gzip layer", r.PrimarySignature)
	}
}

func TestCLIPeelCleanFile(t *testing.T) {
	work := t.TempDir()
	f := filepath.Join(work, "plain.txt")
	os.WriteFile(f, []byte("just an ordinary config file\nkey=value\n"), 0o644)
	if code, _, _ := runCLI(t, "peel", f); code != report.ExitOK {
		t.Errorf("clean file: code=%d, want %d", code, report.ExitOK)
	}
}

func TestReadFileCappedRefusesOversize(t *testing.T) {
	work := t.TempDir()
	// A file one byte over a tiny cap must be refused, not read.
	p := filepath.Join(work, "big.bin")
	if err := os.WriteFile(p, make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileCapped(p, 50); err == nil {
		t.Error("readFileCapped accepted a file over the cap")
	}
	// At/under the cap is fine.
	if data, err := readFileCapped(p, 100); err != nil || len(data) != 100 {
		t.Errorf("readFileCapped rejected an in-cap file: %v len=%d", err, len(data))
	}
}

func TestCLIPeelUsage(t *testing.T) {
	if code, _, _ := runCLI(t, "peel"); code != report.ExitUsage {
		t.Errorf("no file: code=%d", code)
	}
	if code, _, _ := runCLI(t, "peel", "--format", "yaml", "x"); code != report.ExitUsage {
		t.Errorf("bad format: code=%d", code)
	}
	if code, _, _ := runCLI(t, "peel", "/definitely/not/here"); code != report.ExitRunFailed {
		t.Errorf("missing file: code=%d", code)
	}
}

func writePeelFiles(t *testing.T) (dir string, chain, clean string) {
	t.Helper()
	dir = t.TempDir()
	chain = filepath.Join(dir, "chain.txt")
	clean = filepath.Join(dir, "clean.txt")
	payload := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("inert-body."), 8)...)
	if err := os.WriteFile(chain, buildChain(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, []byte("nothing hidden here at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, chain, clean
}

func TestCLIPeelManyFiles(t *testing.T) {
	_, chain, clean := writePeelFiles(t)
	code, out, errOut := runCLI(t, "peel", "--jobs", "4", clean, chain)
	if code != report.ExitThreat {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	// Command-line order, however the files finished.
	if a, b := strings.Index(out, clean), strings.Index(out, chain); a < 0 || b < a {
		t.Fatalf("files out of order:\n%s", out)
	}
	if !strings.Contains(out, "base64>gzip>base64") {
		t.Fatalf("chain missing:\n%s", out)
	}
}

func TestCLIPeelManyFilesAsJSON(t *testing.T) {
	_, chain, clean := writePeelFiles(t)
	_, out, _ := runCLI(t, "peel", "--format", "json", clean, chain)
	var doc []struct {
		FilePath string `json:"file_path"`
		Outcome  string `json:"outcome"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(doc) != 2 || doc[0].FilePath != clean || doc[1].Outcome != "revealed-executable" {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestCLIPeelStreamsEachLayer(t *testing.T) {
	_, chain, _ := writePeelFiles(t)
	code, out, _ := runCLI(t, "peel", "--stream", chain)
	if code != report.ExitThreat {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{"[layer]", "[chain]", "base64>gzip>base64 -> revealed-executable", "Outcome     : revealed-executable"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

func TestCLIPeelStreamsJSONLines(t *testing.T) {
	_, chain, clean := writePeelFiles(t)
	_, out, _ := runCLI(t, "peel", "--stream", "--format", "json", chain, clean)
	kinds := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var e struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		kinds[e.Kind]++
	}
	if kinds["layer"] == 0 || kinds["chain"] != 1 || kinds["result"] != 2 {
		t.Fatalf("kinds = %v\n%s", kinds, out)
	}
}

// An unreadable file must not hide a finding in the next one.
func TestCLIPeelKeepsGoingPastABadFile(t *testing.T) {
	_, chain, _ := writePeelFiles(t)
	code, out, errOut := runCLI(t, "peel", "/definitely/not/here", chain)
	if code != report.ExitThreat {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "revealed-executable") || !strings.Contains(errOut, "not/here") {
		t.Fatalf("out=%s err=%s", out, errOut)
	}
}

func TestCLIPeelRejectsNegativeJobs(t *testing.T) {
	if code, _, _ := runCLI(t, "peel", "--jobs", "-1", "x"); code != report.ExitUsage {
		t.Fatalf("code = %d", code)
	}
}

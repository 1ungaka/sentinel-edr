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

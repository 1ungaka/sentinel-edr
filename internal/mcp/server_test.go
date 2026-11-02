package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cau-edr/cau/scanner"
)

// drive feeds newline-delimited requests through Serve and returns the decoded
// responses, keyed by id (notifications and id-less responses are dropped).
func drive(t *testing.T, srv *Server, requests ...string) map[float64]rpcResponse {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	responses := map[float64]rpcResponse{}
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var resp rpcResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("decode response %q: %v", line, err)
		}
		var id float64
		if len(resp.ID) > 0 {
			_ = json.Unmarshal(resp.ID, &id)
			responses[id] = resp
		}
	}
	return responses
}

// toolPayload unmarshals a tool result's text content into dst.
func toolPayload(t *testing.T, resp rpcResponse, dst interface{}) {
	t.Helper()
	b, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	var tr toolResult
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	if len(tr.Content) == 0 {
		t.Fatal("empty tool content")
	}
	if dst != nil {
		if err := json.Unmarshal([]byte(tr.Content[0].Text), dst); err != nil {
			t.Fatalf("unmarshal tool payload %q: %v", tr.Content[0].Text, err)
		}
	}
}

func testServer(t *testing.T, roots ...string) *Server {
	t.Helper()
	db := scanner.NewSignatureDB()
	if err := db.Add(scanner.Signature{HashType: "SHA256", Hash: strings.Repeat("a", 64), ThreatName: "Test.Marker"}); err != nil {
		t.Fatal(err)
	}
	sb, _, err := NewSandbox(SandboxConfig{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	engine := &scanner.Engine{DB: db, Heuristics: true, Static: true, Stego: true, EncChain: true}
	return NewServer(Deps{
		Engine:  engine,
		SigDB:   db,
		Sandbox: sb,
		Info:    ServerInfo{Name: "cau-mcp-test", Version: "test"},
	})
}

func TestInitializeAndToolsList(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	var init initializeResult
	b, _ := json.Marshal(resp[1].Result)
	if err := json.Unmarshal(b, &init); err != nil {
		t.Fatal(err)
	}
	if init.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol = %q, want %q", init.ProtocolVersion, ProtocolVersion)
	}
	var list struct {
		Tools []toolDesc `json:"tools"`
	}
	b, _ = json.Marshal(resp[2].Result)
	json.Unmarshal(b, &list)
	if len(list.Tools) != 9 {
		t.Errorf("tools = %d, want 9", len(list.Tools))
	}
	// evasion_report must not be exposed (scope note).
	for _, tl := range list.Tools {
		if strings.Contains(tl.Name, "evasion") {
			t.Errorf("evasion tool %q must not be exposed", tl.Name)
		}
	}
}

func TestScanHashMatch(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_hash","arguments":{"hash":"`+strings.Repeat("a", 64)+`"}}}`,
	)
	var out struct {
		Matched    bool   `json:"matched"`
		ThreatName string `json:"threat_name"`
		Type       string `json:"type"`
	}
	toolPayload(t, resp[1], &out)
	if !out.Matched || out.ThreatName != "Test.Marker" || out.Type != "SHA256" {
		t.Errorf("scan_hash = %+v", out)
	}
}

func TestScanFileSandbox(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "sample.txt")
	if err := os.WriteFile(f, []byte("just some text"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := testServer(t, root)

	// inside the root: scans and returns a verdict
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_file","arguments":{"path":"`+f+`"}}}`,
	)
	var out fileSummary
	toolPayload(t, resp[1], &out)
	if out.Verdict == "" {
		t.Error("empty verdict")
	}

	// outside the root: tool error
	resp = drive(t, srv,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_file","arguments":{"path":"/etc/hostname"}}}`,
	)
	b, _ := json.Marshal(resp[2].Result)
	var tr toolResult
	json.Unmarshal(b, &tr)
	if !tr.IsError {
		t.Error("expected isError for a path outside the sandbox")
	}
}

func TestGenerateYaraRuleCompiles(t *testing.T) {
	srv := testServer(t)
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"generate_yara_rule","arguments":{"name":"gen_test","strings":["a_distinctive_marker_string"],"technique":"T1059.001","threat_name":"Gen.Test","description":"generated in a test"}}}`
	resp := drive(t, srv, req)
	var out struct {
		Rule     string `json:"rule"`
		Compiled bool   `json:"compiled"`
	}
	toolPayload(t, resp[1], &out)
	if !out.Compiled {
		t.Errorf("generated rule did not compile:\n%s", out.Rule)
	}
	if !strings.Contains(out.Rule, "mitre_attack = \"T1059.001\"") {
		t.Errorf("rule missing technique meta:\n%s", out.Rule)
	}
}

func TestYaraTestRuleMatches(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "s.txt")
	if err := os.WriteFile(f, []byte("the quick brown fox marker_xyz jumps"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := testServer(t, root)
	rule := `rule t { strings: $a = \"marker_xyz\" condition: $a }`
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"yara_test_rule","arguments":{"rule":"` + rule + `","paths":["` + f + `"]}}}`
	resp := drive(t, srv, req)
	var out struct {
		Compiled bool `json:"compiled"`
		Tested   []struct {
			Matched bool `json:"matched"`
		} `json:"tested"`
	}
	toolPayload(t, resp[1], &out)
	if !out.Compiled {
		t.Fatal("rule did not compile")
	}
	if len(out.Tested) != 1 || !out.Tested[0].Matched {
		t.Errorf("expected a match, got %+v", out.Tested)
	}
}

func TestMitreCoverage(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mitre_coverage","arguments":{}}}`,
	)
	var out struct {
		CoveredCount int      `json:"covered_count"`
		Covered      []string `json:"covered"`
	}
	toolPayload(t, resp[1], &out)
	// The heuristic/static/stego/encchain catalogs always map some techniques,
	// even with no YARA rules loaded.
	if out.CoveredCount == 0 {
		t.Error("expected non-empty coverage from the built-in catalogs")
	}
}

func TestUnknownMethod(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"does/not/exist"}`,
	)
	if resp[1].Error == nil || resp[1].Error.Code != codeMethodNotFound {
		t.Errorf("expected method-not-found, got %+v", resp[1].Error)
	}
}

func TestResourcesReadSignatures(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"cau://signatures"}}`,
	)
	b, _ := json.Marshal(resp[1].Result)
	var out struct {
		Contents []resourceContent `json:"contents"`
	}
	json.Unmarshal(b, &out)
	if len(out.Contents) == 0 || !strings.Contains(out.Contents[0].Text, "Test.Marker") {
		t.Errorf("signatures resource missing the seeded signature: %+v", out.Contents)
	}
}

func TestPromptsHaveNoEvasion(t *testing.T) {
	srv := testServer(t)
	resp := drive(t, srv, `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	b, _ := json.Marshal(resp[1].Result)
	var out struct {
		Prompts []promptDesc `json:"prompts"`
	}
	json.Unmarshal(b, &out)
	if len(out.Prompts) != 2 {
		t.Errorf("prompts = %d, want 2", len(out.Prompts))
	}
	for _, p := range out.Prompts {
		if strings.Contains(p.Name, "evasion") {
			t.Errorf("evasion prompt %q must not be exposed", p.Name)
		}
	}
}

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postRPC(t *testing.T, h http.Handler, body string) (*http.Response, rpcResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	var resp rpcResponse
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return res, resp
}

func TestHTTPInitializeAndCall(t *testing.T) {
	srv := testServer(t)
	h := srv.HTTPHandler()

	res, resp := postRPC(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	var init initializeResult
	b, _ := json.Marshal(resp.Result)
	json.Unmarshal(b, &init)
	if init.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol = %q", init.ProtocolVersion)
	}

	// A tool call over HTTP returns the same payload shape as stdio.
	_, resp = postRPC(t, h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_hash","arguments":{"hash":"`+strings.Repeat("a", 64)+`"}}}`)
	var tr toolResult
	b, _ = json.Marshal(resp.Result)
	json.Unmarshal(b, &tr)
	if len(tr.Content) == 0 || !strings.Contains(tr.Content[0].Text, "Test.Marker") {
		t.Errorf("scan_hash over HTTP = %+v", tr)
	}
}

func TestHTTPNotificationNoBody(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	rec := httptest.NewRecorder()
	srv.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("notification returned a body: %q", rec.Body.String())
	}
}

func TestHTTPParseError(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{not json`)))
	rec := httptest.NewRecorder()
	srv.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var resp rpcResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != codeParseError {
		t.Errorf("expected parse error, got %+v", resp.Error)
	}
}

func TestHTTPGetNotAllowed(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	srv.HTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}
}

package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postWithOrigin(srv *Server, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	srv.HTTPHandler().ServeHTTP(rec, req)
	return rec
}

// A browser sends Origin on every cross-site POST, including one that DNS
// rebinding has aimed at 127.0.0.1. Without this check any page the analyst
// opens can drive the server, add_signature included.
func TestHTTPRejectsBrowserOrigins(t *testing.T) {
	srv := testServer(t)
	for _, origin := range []string{
		"https://evil.example",
		"http://evil.example:8923",
		"http://127.0.0.1.evil.example",
		"http://localhost.evil.example",
		"null",
		"file://",
		"not a url",
	} {
		if rec := postWithOrigin(srv, origin); rec.Code != http.StatusForbidden {
			t.Errorf("Origin %q: status %d, want 403", origin, rec.Code)
		}
	}
}

func TestHTTPAcceptsLocalAndNonBrowserClients(t *testing.T) {
	srv := testServer(t)
	for _, origin := range []string{
		"", // curl, SDKs and agents send no Origin at all
		"http://localhost:8923",
		"http://127.0.0.1:8923",
		"http://[::1]:8923",
		"https://localhost",
	} {
		if rec := postWithOrigin(srv, origin); rec.Code != http.StatusOK {
			t.Errorf("Origin %q: status %d, want 200", origin, rec.Code)
		}
	}
}

func TestSandboxRootOfSlashContainsEverything(t *testing.T) {
	s, _, err := NewSandbox(SandboxConfig{Roots: []string{"/"}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.contains("/etc/hostname") {
		t.Fatal(`a root of "/" contains nothing`)
	}
}

func TestSandboxRootBoundaryStillHolds(t *testing.T) {
	s := &Sandbox{roots: []string{"/a/b"}}
	if s.contains("/a/bc") {
		t.Fatal(`"/a/bc" treated as inside root "/a/b"`)
	}
	if !s.contains("/a/b/c") || !s.contains("/a/b") {
		t.Fatal("paths inside the root rejected")
	}
}

package wazuh

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newWazuhStub(t *testing.T, token string, authFail, sendFail bool) *httptest.Server {
	t.Helper()
	var auths, sends atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		auths.Add(1)
		got := r.Header.Get("Authorization")
		if !strings.HasPrefix(got, "Basic ") {
			t.Errorf("authenticate: want Basic, got %q", got)
		}
		if authFail {
			http.Error(w, `{"error":1,"detail":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": token}})
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "bad bearer", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("events: want Content-Type application/json, got %q", r.Header.Get("Content-Type"))
		}
		if sendFail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var env struct {
			Events []string `json:"events"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("events: decode: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if len(env.Events) == 0 {
			t.Error("events: empty batch")
		}
		// Each event must itself be valid JSON (we send the OCSF finding as a string).
		for i, e := range env.Events {
			var tmp any
			if err := json.Unmarshal([]byte(e), &tmp); err != nil {
				t.Errorf("events[%d]: inner JSON invalid: %v", i, err)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"error":0}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSendAuthenticatesThenPostsEachBatch(t *testing.T) {
	srv := newWazuhStub(t, "tok-1234", false, false)
	c, err := New(Options{URL: srv.URL, User: "admin", Password: "s3cret", Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	findings := make([]map[string]any, MaxEventsPerRequest+5)
	for i := range findings {
		findings[i] = map[string]any{"class_uid": 2004, "severity_id": 3, "seq": i}
	}
	res := c.Send(context.Background(), findings)
	if res.Err != nil {
		t.Fatalf("Send: %v", res.Err)
	}
	if res.Delivered != len(findings) {
		t.Errorf("Delivered = %d, want %d", res.Delivered, len(findings))
	}
}

func TestSendAuthFailurePropagatesWithoutDelivering(t *testing.T) {
	srv := newWazuhStub(t, "", true, false)
	c, err := New(Options{URL: srv.URL, User: "admin", Password: "wrong", Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res := c.Send(context.Background(), []map[string]any{{"x": 1}})
	if res.Err == nil {
		t.Fatal("want auth error")
	}
	if res.Delivered != 0 {
		t.Errorf("Delivered = %d, want 0", res.Delivered)
	}
}

func TestSendStopsOnFirstBatchError(t *testing.T) {
	srv := newWazuhStub(t, "tok", false, true)
	c, err := New(Options{URL: srv.URL, User: "admin", Password: "pw", Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	findings := make([]map[string]any, MaxEventsPerRequest+5)
	for i := range findings {
		findings[i] = map[string]any{"i": i}
	}
	res := c.Send(context.Background(), findings)
	if res.Err == nil {
		t.Fatal("want send error")
	}
	if res.Delivered != 0 {
		t.Errorf("Delivered = %d, want 0", res.Delivered)
	}
}

func TestSendEmptyIsNoOp(t *testing.T) {
	// No server needed: Send on nothing must not even authenticate.
	c, err := New(Options{URL: "https://127.0.0.1:1", User: "u", Password: "p", Insecure: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if res := c.Send(context.Background(), nil); res.Err != nil || res.Delivered != 0 || res.Attempted != 0 {
		t.Fatalf("empty: %+v", res)
	}
}

func TestNewValidation(t *testing.T) {
	for name, o := range map[string]Options{
		"no url":             {User: "u", Password: "p"},
		"bad url":            {URL: "::/not-a-url", User: "u", Password: "p"},
		"no user":            {URL: "https://h:55000", Password: "p"},
		"no password":        {URL: "https://h:55000", User: "u"},
		"http no --insecure": {URL: "http://h:55000", User: "u", Password: "p"},
		"bad scheme":         {URL: "ftp://h:55000", User: "u", Password: "p"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(o); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestSendContextCancelled(t *testing.T) {
	srv := newWazuhStub(t, "tok", false, false)
	c, err := New(Options{URL: srv.URL, User: "admin", Password: "pw", Insecure: true, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.Send(ctx, []map[string]any{{"x": 1}})
	if res.Err == nil {
		t.Fatal("want context error")
	}
}

func TestTrimSnippetKeepsItShort(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := trimSnippet([]byte(long + "\x1b[2K\n"))
	// 200 ASCII bytes + the 3-byte UTF-8 ellipsis.
	if len(got) > 203 {
		t.Errorf("snippet too long: %d (%q)", len(got), got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("snippet lost its truncation marker: %q", got)
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\n") {
		t.Errorf("snippet carries control chars: %q", got)
	}
}

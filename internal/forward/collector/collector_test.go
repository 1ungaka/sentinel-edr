package collector

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	frameA = `<83>1 2026-10-24T12:00:00.000Z host cau - finding [cau@32473 uid="a"] first`
	frameB = `<84>1 2026-10-24T12:00:00.000Z host cau - finding [cau@32473 uid="b"] second line`
)

func twoFrames() []byte { return []byte(frameA + "\n" + frameB + "\n") }

func TestNewValidates(t *testing.T) {
	bad := []struct {
		name string
		opts Options
		want string
	}{
		{"empty", Options{Format: "syslog"}, "required"},
		{"scheme", Options{URL: "ftp://h:21", Format: "syslog"}, "scheme"},
		{"no port", Options{URL: "tcp://host", Format: "syslog"}, "host:port"},
		{"otlp over tcp", Options{URL: "tcp://h:1", Format: "otlp"}, "HTTP-only"},
		{"report format", Options{URL: "udp://h:1", Format: "sarif"}, "cannot be sent"},
		{"plain http", Options{URL: "http://h/x", Format: "otlp"}, "insecure"},
		{"bulk on tcp", Options{URL: "tcp://h:1", Format: "ecs", BulkIndex: "i"}, "http(s)"},
		{"bulk needs ecs", Options{URL: "https://h/_bulk", Format: "cef", BulkIndex: "i"}, "ecs"},
		{"bulk index chars", Options{URL: "https://h/_bulk", Format: "ecs", BulkIndex: "a\nb"}, "index name"},
		{"auth on udp", Options{URL: "udp://h:1", Format: "cef", Authorization: "Bearer x"}, "http(s)"},
		{"missing ca", Options{URL: "tls://h:1", Format: "syslog", CAFile: "/nonexistent/ca.pem"}, "CA bundle"},
		{"not a sink format over http", Options{URL: "https://h/x", Format: "json"}, "not a sink format"},
	}
	for _, tc := range bad {
		if _, err := New(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	c, err := New(Options{URL: "tls://collector.example:6514", Format: "SYSLOG"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Cleartext() || c.tlsCfg.InsecureSkipVerify || c.tlsCfg.ServerName != "collector.example" {
		t.Errorf("tls client should verify the named host: %+v", c.tlsCfg)
	}
	if c, _ := New(Options{URL: "udp://127.0.0.1:514", Format: "cef"}); c == nil || !c.Cleartext() {
		t.Error("udp must report cleartext")
	}
}

func TestEventsCounts(t *testing.T) {
	if ev, n := Events("syslog", twoFrames()); n != 2 || string(ev[1]) != frameB {
		t.Errorf("lines: %d %q", n, ev)
	}
	if _, n := Events("cef", nil); n != 0 {
		t.Errorf("empty payload counted %d", n)
	}
	otlp := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{},{},{}]}]}]}` + "\n"
	if ev, n := Events("otlp", []byte(otlp)); n != 3 || len(ev) != 1 {
		t.Errorf("otlp: %d records in %d documents", n, len(ev))
	}
	if _, n := Events("otlp", []byte(`{"resourceLogs":[]}`)); n != 0 {
		t.Errorf("empty otlp counted %d", n)
	}
}

func TestUDPDatagramPerEvent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp loopback: %v", err)
	}
	defer pc.Close()
	c, err := New(Options{URL: "udp://" + pc.LocalAddr().String(), Format: "syslog", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Send(context.Background(), twoFrames())
	if res.Err != nil || res.Attempted != 2 || res.Delivered != 2 {
		t.Fatalf("result: %+v", res)
	}
	buf := make([]byte, 65536)
	for _, want := range []string{frameA, frameB} {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != want {
			t.Errorf("datagram %q, want %q", buf[:n], want)
		}
	}
}

func TestUDPOversizeIsReportedNotTruncated(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp loopback: %v", err)
	}
	defer pc.Close()
	c, _ := New(Options{URL: "udp://" + pc.LocalAddr().String(), Format: "cef", Timeout: 2 * time.Second})
	big := strings.Repeat("x", MaxDatagram+1)
	res := c.Send(context.Background(), []byte(big+"\nsmall\n"))
	if res.Err == nil || res.Attempted != 2 || res.Delivered != 1 {
		t.Fatalf("oversize must be an error with the small event still sent: %+v", res)
	}
}

// readOctetCounted reads RFC 6587 octet-counted frames until EOF.
func readOctetCounted(t *testing.T, r io.Reader) []string {
	t.Helper()
	br := bufio.NewReader(r)
	var out []string
	for {
		lenStr, err := br.ReadString(' ')
		if err == io.EOF && lenStr == "" {
			return out
		}
		if err != nil {
			t.Fatalf("read MSG-LEN: %v (%q)", err, lenStr)
		}
		n, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
		if err != nil || n <= 0 {
			t.Fatalf("bad MSG-LEN %q", lenStr)
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(br, msg); err != nil {
			t.Fatalf("short frame: %v", err)
		}
		out = append(out, string(msg))
	}
}

func serveOnce(t *testing.T, ln net.Listener, read func(net.Conn)) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		read(conn)
	}()
	return done
}

func TestTCPSyslogOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	var got []string
	done := serveOnce(t, ln, func(c net.Conn) { got = readOctetCounted(t, c) })
	c, err := New(Options{URL: "tcp://" + ln.Addr().String(), Format: "syslog-cef", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Send(context.Background(), twoFrames())
	<-done
	if res.Err != nil || res.Delivered != 2 {
		t.Fatalf("result: %+v", res)
	}
	if len(got) != 2 || got[0] != frameA || got[1] != frameB {
		t.Errorf("frames: %q", got)
	}
}

func TestTCPFramingPerFormat(t *testing.T) {
	for format, delim := range map[string]byte{"gelf": 0, "cef": '\n', "ecs": '\n', "leef": '\n'} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no tcp loopback: %v", err)
		}
		var raw []byte
		done := serveOnce(t, ln, func(c net.Conn) { raw, _ = io.ReadAll(c) })
		c, _ := New(Options{URL: "tcp://" + ln.Addr().String(), Format: format, Timeout: 2 * time.Second})
		res := c.Send(context.Background(), []byte("one\ntwo\n"))
		<-done
		ln.Close()
		want := "one" + string(delim) + "two" + string(delim)
		if res.Err != nil || string(raw) != want {
			t.Errorf("%s: err %v, stream %q, want %q", format, res.Err, raw, want)
		}
	}
}

func TestTLSVerifiesByDefault(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS() // a self-signed certificate the client has no reason to trust
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	c, _ := New(Options{URL: "tls://" + addr, Format: "syslog", Timeout: 2 * time.Second})
	if res := c.Send(context.Background(), twoFrames()); res.Err == nil || res.Delivered != 0 {
		t.Fatalf("an untrusted certificate must fail the send: %+v", res)
	}
}

func TestTLSStreamWithOptIn(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	tlsCfg := &tls.Config{Certificates: cert.TLS.Certificates}
	cert.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Skipf("no tls loopback: %v", err)
	}
	defer ln.Close()
	var got []string
	done := serveOnce(t, ln, func(c net.Conn) { got = readOctetCounted(t, c) })
	c, _ := New(Options{URL: "tls://" + ln.Addr().String(), Format: "syslog", Insecure: true, Timeout: 2 * time.Second})
	res := c.Send(context.Background(), twoFrames())
	<-done
	if res.Err != nil || len(got) != 2 || got[1] != frameB {
		t.Fatalf("result %+v frames %q", res, got)
	}
}

func TestHTTPOTLP(t *testing.T) {
	doc := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"x"}},{"body":{"stringValue":"y"}}]}]}]}`
	var gotBody, gotCT, gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotCT, gotAuth = string(b), r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := New(Options{URL: srv.URL + "/v1/logs", Format: "otlp", Insecure: true, Authorization: "Bearer s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Send(context.Background(), []byte(doc+"\n"))
	if res.Err != nil || res.Attempted != 2 || res.Delivered != 2 {
		t.Fatalf("result: %+v", res)
	}
	if gotBody != doc || gotCT != "application/json" || gotAuth != "Bearer s3cret" {
		t.Errorf("request: ct %q auth %q body %q", gotCT, gotAuth, gotBody)
	}
}

func TestHTTPBulk(t *testing.T) {
	var lines []string
	reply := `{"errors":false,"items":[]}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/x-ndjson" || !strings.HasSuffix(string(b), "\n") {
			t.Errorf("bulk body must be NDJSON ending in a newline: %q", b)
		}
		lines = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		io.WriteString(w, reply)
	}))
	defer srv.Close()
	c, _ := New(Options{URL: srv.URL + "/_bulk", Format: "ecs", BulkIndex: "logs-cau.finding-default", Insecure: true})
	payload := []byte(`{"message":"a"}` + "\n" + `{"message":"b"}` + "\n")
	res := c.Send(context.Background(), payload)
	if res.Err != nil || res.Delivered != 2 {
		t.Fatalf("result: %+v", res)
	}
	if len(lines) != 4 {
		t.Fatalf("want action+doc pairs, got %q", lines)
	}
	for i := 0; i < len(lines); i += 2 {
		var action map[string]map[string]string
		if err := json.Unmarshal([]byte(lines[i]), &action); err != nil || action["create"]["_index"] != "logs-cau.finding-default" {
			t.Errorf("action line %q", lines[i])
		}
	}
	if lines[1] != `{"message":"a"}` || lines[3] != `{"message":"b"}` {
		t.Errorf("documents: %q", lines)
	}

	// A 200 that rejected documents is a failure, not a delivery.
	reply = `{"errors":true,"items":[{"create":{"status":400}}]}`
	if res := c.Send(context.Background(), payload); res.Err == nil || res.Delivered != 0 {
		t.Errorf("bulk errors:true must surface: %+v", res)
	}
}

func TestHTTPGELFOnePerRequest(t *testing.T) {
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c, _ := New(Options{URL: srv.URL + "/gelf", Format: "gelf", Insecure: true})
	res := c.Send(context.Background(), []byte(`{"version":"1.1","a":1}`+"\n"+`{"version":"1.1","a":2}`+"\n"))
	if res.Err != nil || res.Delivered != 2 || len(bodies) != 2 || bodies[1] != `{"version":"1.1","a":2}` {
		t.Fatalf("result %+v bodies %q", res, bodies)
	}
}

func TestHTTPErrorIsBoundedAndNotFollowed(t *testing.T) {
	hits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "denied\r\n\x1b[2Jforged "+strings.Repeat("z", 500))
	}))
	defer srv.Close()

	c, _ := New(Options{URL: srv.URL + "/x", Format: "cef", Insecure: true})
	res := c.Send(context.Background(), []byte("CEF:0|a\n"))
	if res.Err == nil || res.Delivered != 0 {
		t.Fatalf("a 403 must fail: %+v", res)
	}
	if msg := res.Err.Error(); strings.ContainsAny(msg, "\r\n\x1b") || len(msg) > 320 {
		t.Errorf("error is not terminal-safe or not bounded: %q", msg)
	}

	c, _ = New(Options{URL: srv.URL + "/redirect", Format: "cef", Insecure: true})
	if res := c.Send(context.Background(), []byte("CEF:0|a\n")); res.Err == nil || hits != 0 {
		t.Errorf("a redirect must not be followed (hits %d, result %+v)", hits, res)
	}
}

func TestEmptyPayloadOpensNoConnection(t *testing.T) {
	// Port 1 on loopback refuses connections; an empty payload must not try.
	c, _ := New(Options{URL: "tcp://127.0.0.1:1", Format: "syslog", Timeout: time.Second})
	if res := c.Send(context.Background(), nil); res.Err != nil || res.Attempted != 0 {
		t.Errorf("empty payload: %+v", res)
	}
}

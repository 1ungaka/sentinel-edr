package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// The --sink-* flags are validated before the scan starts: a mistyped
// collector is a usage error, not a warning after the work is done.
func TestCLISinkFlagValidation(t *testing.T) {
	base := []string{"scan", "--quiet", "--db", smokeDB, "--no-yara"}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"format without url", []string{"--sink-format", "cef", "LICENSE"}, "need --sink-url"},
		{"url without sink format", []string{"--sink-url", "udp://127.0.0.1:9", "LICENSE"}, "--sink-format"},
		{"report format as sink", []string{"--sink-url", "udp://127.0.0.1:9", "--sink-format", "sarif", "LICENSE"}, "--sink-format"},
		{"plain http", []string{"--sink-url", "http://127.0.0.1:9/v1/logs", "--sink-format", "otlp", "LICENSE"}, "insecure"},
		{"otlp over tcp", []string{"--sink-url", "tcp://127.0.0.1:9", "--sink-format", "otlp", "LICENSE"}, "HTTP-only"},
		{"index without ecs", []string{"--sink-url", "https://127.0.0.1:9/_bulk", "--sink-format", "cef", "--sink-index", "x", "LICENSE"}, "ecs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, append(append([]string(nil), base...), tc.args...)...)
			if code != report.ExitUsage || !strings.Contains(errOut, tc.want) {
				t.Errorf("exit %d, want usage error mentioning %q\nstderr:\n%s", code, tc.want, errOut)
			}
		})
	}
}

// A finding is forwarded as an octet-counted RFC 5424 frame, and the exit code
// is the scan's own.
func TestCLISinkForwardsSyslogOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	frames := make(chan string, 4)
	go func() {
		defer close(frames)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)
		for {
			lenStr, err := br.ReadString(' ')
			if err != nil {
				return
			}
			n, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil {
				return
			}
			msg := make([]byte, n)
			if _, err := io.ReadFull(br, msg); err != nil {
				return
			}
			frames <- string(msg)
		}
	}()

	code, _, errOut := runCLI(t, "scan", "--db", smokeDB, "--no-yara",
		"--sink-url", "tcp://"+ln.Addr().String(), "--sink-format", "syslog", smokeHashHit)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want the scan's own threat code\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "sink forward (syslog): 1/1 findings delivered") || !strings.Contains(errOut, "cleartext transport") {
		t.Errorf("status line missing:\n%s", errOut)
	}
	var got []string
	for f := range frames {
		got = append(got, f)
	}
	if len(got) != 1 {
		t.Fatalf("collector received %d frames, want 1: %q", len(got), got)
	}
	if !strings.HasPrefix(got[0], "<83>1 ") || !strings.Contains(got[0], `verdict="malicious"`) || !strings.Contains(got[0], "hash_only.bin") {
		t.Errorf("frame: %q", got[0])
	}
}

// A clean scan opens no connection, and a dead collector never changes the
// exit code.
func TestCLISinkIsBestEffort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close() // nothing listens here any more

	code, _, errOut := runCLI(t, "scan", "--db", smokeDB, "--no-yara",
		"--sink-url", "tcp://"+dead, "--sink-format", "cef", "--sink-timeout", "2s", "LICENSE")
	if code != report.ExitOK || strings.Contains(errOut, "sink forward") {
		t.Errorf("clean scan: exit %d, stderr:\n%s", code, errOut)
	}
	code, _, errOut = runCLI(t, "scan", "--db", smokeDB, "--no-yara",
		"--sink-url", "tcp://"+dead, "--sink-format", "cef", "--sink-timeout", "2s", smokeHashHit)
	if code != report.ExitThreat || !strings.Contains(errOut, "[WARN] sink forward (cef): 0/1 delivered") {
		t.Errorf("dead collector: exit %d, stderr:\n%s", code, errOut)
	}
}

// --format picks the local report and the sink format independently, the
// Authorization value comes from the environment, and it never reaches stderr.
func TestCLISinkOTLPOverHTTPS(t *testing.T) {
	var body, auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, auth = string(b), r.Header.Get("Authorization")
	}))
	defer srv.Close()
	t.Setenv("CAU_TEST_SINK_AUTH", "Bearer t0ps3cret")

	code, out, errOut := runCLI(t, "scan", "--db", smokeDB, "--no-yara", "--format", "json",
		"--sink-url", srv.URL+"/v1/logs", "--sink-format", "otlp", "--sink-insecure",
		"--sink-auth-env", "CAU_TEST_SINK_AUTH", smokeHashHit)
	if code != report.ExitThreat {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") || !strings.Contains(out, `"schema_version"`) {
		t.Errorf("stdout should still be the JSON report: %.120s", out)
	}
	if auth != "Bearer t0ps3cret" || !strings.Contains(body, `"resourceLogs"`) || !strings.Contains(body, "hash_only.bin") {
		t.Errorf("collector got auth %q body %.200s", auth, body)
	}
	if strings.Contains(errOut, "t0ps3cret") {
		t.Errorf("the credential leaked to stderr:\n%s", errOut)
	}
}

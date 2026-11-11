package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/forward"
)

// recordSender stands in for a Wazuh manager. hang makes it unreachable in the
// worst way for a daemon: answering neither yes nor no.
type recordSender struct {
	mu   sync.Mutex
	got  []map[string]any
	hang chan struct{}
	fail bool
}

func (r *recordSender) Send(ctx context.Context, events []map[string]any) (int, error) {
	if r.hang != nil {
		select {
		case <-r.hang:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if r.fail {
		return 0, errors.New("manager unreachable")
	}
	r.mu.Lock()
	r.got = append(r.got, events...)
	r.mu.Unlock()
	return len(events), nil
}

func (r *recordSender) events() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any(nil), r.got...)
}

// attachSink puts a sink over s onto the fixture's defender, as startForward
// would, and flushes it at the end of the test.
func attachSink(t *testing.T, f *fixture, s forward.Sender) {
	t.Helper()
	f.d.product = forward.DefaultProduct("test-host")
	f.d.sink = forward.NewSink(s, forward.SinkOptions{
		Queue: 256, Batch: 16, Flush: 5 * time.Millisecond,
		Retries: 2, Backoff: time.Millisecond, Timeout: time.Second,
	})
	f.d.sink.Start()
	t.Cleanup(func() { f.d.sink.Close(2 * time.Second) })
}

// What the daemon writes locally and what it forwards must be the same set of
// incidents: a SIEM that sees fewer is a SIEM nobody can trust to be watching.
func TestDefendForwardsEveryRaisedIncident(t *testing.T) {
	f := newFixture(t)
	rec := &recordSender{}
	attachSink(t, f, rec)

	f.d.enqueue(f.implant(t))
	f.d.cycle()
	f.d.sink.Close(2 * time.Second)

	local := 0
	for _, line := range splitLines(f.out.String()) {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) == nil && v["incident"] != nil {
			local++
		}
	}
	if local == 0 {
		t.Fatal("the fixture raised no incident locally, nothing to forward")
	}
	fwd := rec.events()
	if len(fwd) != local {
		t.Errorf("forwarded %d incidents, wrote %d locally; they must match", len(fwd), local)
	}
	for _, ev := range fwd {
		if ev["class_uid"] != 2004 {
			t.Errorf("forwarded event is not a Detection Finding: %v", ev["class_uid"])
		}
		if ev["message"] == "" || ev["message"] == nil {
			t.Error("forwarded event has no message for an analyst to read")
		}
		un, ok := ev["unmapped"].(map[string]any)
		if !ok || un["agent_host"] != "test-host" {
			t.Errorf("forwarded event does not name the agent host: %v", ev["unmapped"])
		}
	}
}

// The property that makes forwarding safe to leave on: an unreachable SIEM must
// not slow detection by even one incident.
func TestDefendForwardDoesNotBlockDetection(t *testing.T) {
	f := newFixture(t)
	rec := &recordSender{hang: make(chan struct{})}
	attachSink(t, f, rec)
	defer close(rec.hang)

	f.d.enqueue(f.implant(t))
	done := make(chan struct{})
	go func() { f.d.cycle(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a detection cycle blocked on an unreachable SIEM")
	}
	if f.out.Len() == 0 {
		t.Error("the local report must be written even when the SIEM is unreachable")
	}
}

// A failing manager must not cost the local record either.
func TestDefendForwardFailureKeepsLocalReport(t *testing.T) {
	f := newFixture(t)
	attachSink(t, f, &recordSender{fail: true})

	f.d.enqueue(f.implant(t))
	f.d.cycle()
	if f.out.Len() == 0 {
		t.Error("the local report must be complete regardless of delivery")
	}
}

// No forwarder configured is the default and must stay free of any sink.
func TestDefendForwardOffByDefault(t *testing.T) {
	f := newFixture(t)
	closeSink, err := f.d.startForward(defendForward{}, func(string, ...interface{}) {})
	if err != nil {
		t.Fatalf("no forwarder configured should not be an error: %v", err)
	}
	if f.d.sink != nil {
		t.Error("no sink should be built when --wazuh-url is unset")
	}
	f.d.enqueue(f.implant(t))
	f.d.cycle() // emit must tolerate a nil sink
	closeSink()
}

// A forwarder the operator asked for that cannot work is a startup error, not a
// daemon that looks healthy and delivers nothing.
func TestDefendForwardMissingPasswordFailsStartup(t *testing.T) {
	f := newFixture(t)
	const envVar = "CAU_TEST_WAZUH_PASSWORD_UNSET"
	os.Unsetenv(envVar)
	_, err := f.d.startForward(defendForward{
		url: "https://wazuh.example:55000", user: "cau", passwordEnv: envVar,
	}, func(string, ...interface{}) {})
	if err == nil {
		t.Fatal("a configured forwarder with no password must fail to start")
	}
	if f.d.sink != nil {
		t.Error("no sink should be left behind on a failed start")
	}
}

func TestDefendForwardRejectsBadURL(t *testing.T) {
	f := newFixture(t)
	const envVar = "CAU_TEST_WAZUH_PASSWORD_SET"
	t.Setenv(envVar, "secret")
	if _, err := f.d.startForward(defendForward{
		url: "not-a-url", user: "cau", passwordEnv: envVar,
	}, func(string, ...interface{}) {}); err == nil {
		t.Fatal("a malformed --wazuh-url must fail at startup, not at the first incident")
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

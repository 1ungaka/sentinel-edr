package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/forward"
)

func parse(t *testing.T, line string, opts Options) []correlate.Signal {
	t.Helper()
	got, err := ParseLine([]byte(line), opts)
	if err != nil {
		t.Fatalf("ParseLine(%q): %v", line, err)
	}
	return got
}

// TestNothingFromOutsideIsEverLocal is the safety property of this package. A
// signal with an empty Host means "this machine" to the correlator, which
// licenses stopping a process and quarantining a file. Nothing read here may
// ever produce one.
func TestNothingFromOutsideIsEverLocal(t *testing.T) {
	lines := []string{
		`{"class":"ids.alert","detail":"something"}`,
		`{"class_uid":2004,"message":"firewall drop","severity":"High"}`,
		`{"time":"2026-01-01T00:00:00Z","incident":{"id":"abc","signals":[{"layer":"process","class":"procscan.netshell.socket-stdio","score":9,"live":true,"pid":42,"files":["/tmp/x"]}]}}`,
	}
	for _, l := range lines {
		for _, host := range []string{"", "sensor-7"} {
			for _, s := range parse(t, l, Options{Host: host}) {
				if s.Host == "" {
					t.Fatalf("line %q produced a signal with no host, which reads as local state: %+v", l, s)
				}
				if s.Layer != correlate.LayerExternal {
					t.Errorf("line %q produced layer %q, want external", l, s.Layer)
				}
			}
		}
	}
}

func TestPlainEvent(t *testing.T) {
	line := `{"host":"fw-1","class":"firewall.deny","score":6,"technique":"T1071",
	          "detail":"outbound deny","peers":["203.0.113.9","127.0.0.1"],"pid":99,"file":"/tmp/x"}`
	got := parse(t, line, Options{Host: "fallback"})
	if len(got) != 1 {
		t.Fatalf("want one signal, got %d", len(got))
	}
	s := got[0]
	if s.Host != "fw-1" {
		t.Errorf("host %q, want the one in the event", s.Host)
	}
	if s.Class != "external.firewall.deny" {
		t.Errorf("class %q, want it marked external", s.Class)
	}
	if s.Score != 6 || s.Technique != "T1071" || s.Detail != "outbound deny" {
		t.Errorf("signal = %+v", s)
	}
	if len(s.Peers) != 1 || s.Peers[0] != "203.0.113.9" {
		t.Errorf("peers = %v; loopback identifies nothing and must be dropped", s.Peers)
	}
	if len(s.Files) != 1 || s.Files[0] != "/tmp/x" {
		t.Errorf("files = %v", s.Files)
	}
}

func TestPlainEventWithoutScore(t *testing.T) {
	got := parse(t, `{"class":"ids.alert","detail":"saw something"}`, Options{Host: "ids-1"})
	if len(got) != 1 || got[0].Score != 4 {
		t.Fatalf("an event with no number must corroborate but never stand alone: %+v", got)
	}
}

func TestLinesThatCarryNothing(t *testing.T) {
	for _, l := range []string{"", "   ", "# a header", "[1,2,3]", `{"unrelated":true}`, `{"class":""}`} {
		got, err := ParseLine([]byte(l), Options{Host: "x"})
		if err != nil {
			t.Errorf("ParseLine(%q) failed instead of skipping: %v", l, err)
		}
		if len(got) != 0 {
			t.Errorf("ParseLine(%q) invented %d signals", l, len(got))
		}
	}
	if _, err := ParseLine([]byte(`{"class":`), Options{}); err == nil {
		t.Error("a broken JSON object should be reported, so the operator knows a sensor is writing rubbish")
	}
}

func TestOCSFFromAnotherProduct(t *testing.T) {
	line := `{"class_uid":2004,"class_name":"Detection Finding","severity":"High","severity_id":4,
	  "message":"C2 beacon to 203.0.113.9","time":1767225600000,
	  "metadata":{"product":{"name":"Suricata IDS"}},
	  "device":{"hostname":"sensor-3"},
	  "src_endpoint":{"ip":"192.168.1.20"},"dst_endpoint":{"ip":"203.0.113.9"},
	  "process":{"pid":4242,"file":{"path":"/opt/app/agent"}},
	  "finding_info":{"title":"beacon","attacks":[{"technique":{"uid":"T1071.001"}}]}}`
	got := parse(t, line, Options{Host: "fallback"})
	if len(got) != 1 {
		t.Fatalf("want one signal, got %d", len(got))
	}
	s := got[0]
	if s.Host != "sensor-3" {
		t.Errorf("host %q, want the reporting device", s.Host)
	}
	if s.Score != 7 {
		t.Errorf("score %d, want High mapped to 7", s.Score)
	}
	if s.Class != "external.suricata-ids.detection-finding" {
		t.Errorf("class %q", s.Class)
	}
	if s.Technique != "T1071.001" {
		t.Errorf("technique %q", s.Technique)
	}
	if len(s.Peers) != 2 {
		t.Errorf("both endpoints are peers to join on: %v", s.Peers)
	}
	if s.PID != 4242 {
		t.Errorf("pid %d", s.PID)
	}
}

func TestOCSFSeverityMapping(t *testing.T) {
	cases := []struct {
		id    int
		name  string
		score int
	}{
		{6, "Fatal", 9}, {5, "Critical", 9}, {4, "High", 7}, {3, "Medium", 4},
		{2, "Low", 2}, {1, "Informational", 1}, {0, "", 1}, {4, "", 7},
	}
	for _, c := range cases {
		if got := ocsfSeverity(c.id, c.name); got != c.score {
			t.Errorf("ocsfSeverity(%d, %q) = %d, want %d", c.id, c.name, got, c.score)
		}
	}
}

// TestCAUIncidentRoundTrip is the fleet path: what one host forwards is exactly
// what another host can read back, with no lossy mapping in between.
func TestCAUIncidentRoundTrip(t *testing.T) {
	inc := correlate.Build([]correlate.Signal{
		{Layer: correlate.LayerNetwork, Class: "netscan.egress.fileless", Score: 9, Technique: "T1620,T1071",
			Detail: "bash pid 900 (memfd executable) is connected to 203.0.113.9:443",
			Peers:  []string{"203.0.113.9"}, PID: 900, Live: true},
		{Layer: correlate.LayerFile, Class: "yara", Score: 10, Definitive: true, Files: []string{"/tmp/payload"}, PID: 900},
	})[0]
	if !inc.Confirmed {
		t.Fatal("the fixture should be a confirmed incident")
	}
	event := forward.OCSFIncident(inc, forward.DefaultProduct("host-a"), time.Now())
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	got := parse(t, string(data), Options{Host: "ignored-because-the-event-names-its-host"})
	if len(got) != 2 {
		t.Fatalf("want both signals back, got %d", len(got))
	}
	for _, s := range got {
		if s.Host != "host-a" {
			t.Errorf("host %q, want the forwarding agent's", s.Host)
		}
		if s.Layer != correlate.LayerExternal {
			t.Errorf("layer %q, want external", s.Layer)
		}
	}
	var net correlate.Signal
	for _, s := range got {
		if strings.Contains(s.Class, "netscan.egress.fileless") {
			net = s
		}
	}
	if net.Class != "network/netscan.egress.fileless" {
		t.Errorf("class %q: the original layer belongs in the class so an analyst still sees it", net.Class)
	}
	if net.Score != 9 || !net.Live {
		t.Errorf("the peer host's own scoring must come through unchanged: %+v", net)
	}
	if len(net.Peers) != 1 || net.Peers[0] != "203.0.113.9" {
		t.Errorf("peers = %v", net.Peers)
	}
}

func TestBareIncidentEnvelope(t *testing.T) {
	line := `{"time":"2026-01-01T00:00:00Z","incident":{"id":"abc","why":"live attack state",
	  "peers":["203.0.113.9"],"signals":[{"layer":"kernel","class":"kernel.refused.memfd","score":9,"live":true,"pid":7}]}}`
	got := parse(t, line, Options{Host: "host-b"})
	if len(got) != 1 {
		t.Fatalf("want one signal, got %d", len(got))
	}
	if got[0].Class != "kernel/kernel.refused.memfd" || got[0].Host != "host-b" {
		t.Errorf("signal = %+v", got[0])
	}
	if len(got[0].Peers) != 1 {
		t.Errorf("a signal with no peers of its own inherits the incident's: %v", got[0].Peers)
	}
}

func TestMaxAgeDropsStaleTelemetry(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	old := `{"time":"2026-02-01T00:00:00Z","class":"ids.alert","detail":"a month ago"}`
	fresh := `{"time":"2026-03-01T11:59:00Z","class":"ids.alert","detail":"a minute ago"}`
	opts := Options{Host: "ids", MaxAge: time.Hour, Now: now}
	if got := parse(t, old, opts); len(got) != 0 {
		t.Errorf("a month-old event must be dropped: %+v", got)
	}
	if got := parse(t, fresh, opts); len(got) != 1 {
		t.Errorf("a fresh event must be kept: %+v", got)
	}
	// With no window, age does not matter.
	if got := parse(t, old, Options{Host: "ids", Now: now}); len(got) != 1 {
		t.Errorf("without MaxAge nothing is dropped: %+v", got)
	}
}

func TestEventTime(t *testing.T) {
	cases := map[string]bool{
		`"2026-01-01T00:00:00Z"`:     true,
		`"2026-01-01T00:00:00.500Z"`: true,
		`1767225600000`:              true,
		`1767225600`:                 true,
		`"not a time"`:               false,
		`0`:                          false,
		`null`:                       false,
	}
	for in, want := range cases {
		_, ok := eventTime([]byte(in))
		if ok != want {
			t.Errorf("eventTime(%s) ok = %v, want %v", in, ok, want)
		}
	}
	ms, _ := eventTime([]byte(`1767225600000`))
	sec, _ := eventTime([]byte(`1767225600`))
	if !ms.Equal(sec) {
		t.Errorf("seconds and milliseconds should read as the same instant: %v vs %v", sec, ms)
	}
}

func TestReaderReadsOnlyWhatIsNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor.jsonl")
	appendLine := func(s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fmt.Fprintln(f, s)
	}
	appendLine(`{"class":"a","detail":"one","peer":"203.0.113.1"}`)
	appendLine(`{"class":"b","detail":"two","peer":"203.0.113.2"}`)

	r := NewReader(Options{})
	got, warns := r.Collect([]string{path})
	if len(warns) != 0 {
		t.Fatalf("warnings on a clean read: %v", warns)
	}
	if len(got) != 2 {
		t.Fatalf("first pass read %d signals, want 2", len(got))
	}
	// The host falls back to the file's name, so a fleet dropping one file per
	// host needs no configuration.
	if got[0].Host != "sensor" {
		t.Errorf("host %q, want the file's name", got[0].Host)
	}
	if again, _ := r.Collect([]string{path}); len(again) != 0 {
		t.Fatalf("second pass re-read %d signals; nothing was appended", len(again))
	}
	appendLine(`{"class":"c","detail":"three"}`)
	third, _ := r.Collect([]string{path})
	if len(third) != 1 || third[0].Class != "external.c" {
		t.Fatalf("third pass = %+v, want only the appended line", third)
	}
	r.Rewind()
	if all, _ := r.Collect([]string{path}); len(all) != 3 {
		t.Fatalf("after Rewind a pass should read everything, got %d", len(all))
	}
}

func TestReaderHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor.jsonl")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"class":"a","detail":"one"}` + "\n" + `{"class":"b","detail":"two"}` + "\n")
	r := NewReader(Options{})
	if got, _ := r.Collect([]string{path}); len(got) != 2 {
		t.Fatalf("first pass = %d signals", len(got))
	}
	// Rotated: the file is shorter than where reading got to, so what is there
	// now is new.
	write(`{"class":"c","detail":"three"}` + "\n")
	got, _ := r.Collect([]string{path})
	if len(got) != 1 || got[0].Class != "external.c" {
		t.Fatalf("after rotation = %+v", got)
	}
}

func TestReaderDoesNotConsumeAHalfWrittenLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sensor.jsonl")
	// A sensor caught mid-write: the last line has no newline yet.
	if err := os.WriteFile(path, []byte(`{"class":"a","detail":"one"}`+"\n"+`{"class":"b","det`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewReader(Options{})
	got, _ := r.Collect([]string{path})
	if len(got) != 1 {
		t.Fatalf("first pass = %+v, want only the complete line", got)
	}
	// The rest of the line arrives.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(f, `ail":"two"}`)
	f.Close()
	got, _ = r.Collect([]string{path})
	if len(got) != 1 || got[0].Detail != "two" {
		t.Fatalf("second pass = %+v, want the line that is now complete", got)
	}
}

func TestReaderOverADirectory(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"host-a.jsonl": `{"class":"a","detail":"from a","peer":"203.0.113.1"}` + "\n",
		"host-b.json":  `{"class":"b","detail":"from b","peer":"203.0.113.2"}` + "\n",
		"notes.txt":    "this is not telemetry\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := NewReader(Options{})
	got, warns := r.Collect([]string{dir})
	if len(warns) != 0 {
		t.Fatalf("warnings: %v", warns)
	}
	if len(got) != 2 {
		t.Fatalf("read %d signals from the directory, want 2: %+v", len(got), got)
	}
	hosts := map[string]bool{got[0].Host: true, got[1].Host: true}
	if !hosts["host-a"] || !hosts["host-b"] {
		t.Errorf("hosts = %v, want one per file", hosts)
	}
}

func TestReaderWarnsAboutWhatItCannotRead(t *testing.T) {
	r := NewReader(Options{})
	got, warns := r.Collect([]string{filepath.Join(t.TempDir(), "missing.jsonl")})
	if len(got) != 0 {
		t.Errorf("signals from a missing file: %+v", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "missing.jsonl") {
		t.Errorf("warnings = %v, want one naming the file", warns)
	}
}

func TestReaderBoundsOnePass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flood.jsonl")
	var b strings.Builder
	for i := range 50 {
		fmt.Fprintf(&b, `{"class":"c%d","detail":"x"}`+"\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewReader(Options{MaxEvents: 10})
	got, warns := r.Collect([]string{path})
	if len(got) != 10 {
		t.Fatalf("one pass produced %d signals, want the cap of 10", len(got))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "next one") {
		t.Errorf("the cap must be said out loud: %v", warns)
	}
}

// TestCrossHostIncident is the whole point of this package: another host's
// report of a peer joins this host's own connection to it, and the pair is
// confirmed by two independent layers — while the response plan still refuses
// to act on the remote host's PID or path.
func TestCrossHostIncident(t *testing.T) {
	remote := parse(t, `{"host":"host-b","class":"network/netscan.egress.intel","score":9,"definitive":true,
	  "detail":"host-b saw a connection to a known-bad peer","peers":["203.0.113.9"],"pid":31337,"file":"/tmp/implant"}`,
		Options{})
	local := correlate.Signal{
		Layer: correlate.LayerNetwork, Class: "netscan.egress.handler-port", Score: 3,
		Detail: "app pid 500 is connected to 203.0.113.9:4444", Peers: []string{"203.0.113.9"}, PID: 500,
	}
	incidents := correlate.Build(append(remote, local))
	if len(incidents) != 1 {
		t.Fatalf("the shared peer should join them into one incident, got %d", len(incidents))
	}
	inc := incidents[0]
	if !inc.Confirmed {
		t.Fatalf("two layers about one peer is a confirmed incident: %s", inc.Why)
	}
	if len(inc.Hosts) != 1 || inc.Hosts[0] != "host-b" {
		t.Errorf("hosts = %v, want the remote one named", inc.Hosts)
	}
	plan := correlate.PlanFor(inc)
	if len(plan.Block) != 1 || plan.Block[0] != "203.0.113.9" {
		t.Errorf("plan.Block = %v, want the peer", plan.Block)
	}
	if len(plan.Stop) != 1 || plan.Stop[0] != 500 {
		t.Errorf("plan.Stop = %v: only this host's process may be stopped", plan.Stop)
	}
	if len(plan.Quarantine) != 0 {
		t.Errorf("plan.Quarantine = %v: /tmp/implant is on the other host", plan.Quarantine)
	}
}

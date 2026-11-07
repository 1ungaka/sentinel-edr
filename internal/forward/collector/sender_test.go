package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/forward"
	"github.com/s-b-repo/cau/internal/report"
)

// The Sender is what forward.NewSink takes. sender.go does not import the
// forward package, so the method set is asserted here.
var _ forward.Sender = (*Sender)(nil)

var incidentTime = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// incident builds the n-th test incident through the daemon's own renderer,
// so these tests exercise the map shape that is really queued.
func incident(n int, confirmed bool) map[string]any {
	inc := correlate.Incident{
		ID:         fmt.Sprintf("inc-%04d", n),
		Files:      []string{fmt.Sprintf("/tmp/stage-%d.sh", n)},
		PIDs:       []int{4000 + n},
		Peers:      []string{fmt.Sprintf("203.0.113.%d", n)},
		Layers:     []correlate.Layer{correlate.LayerFile, correlate.LayerNetwork},
		Techniques: []string{"T1059.004", "T1071.001"},
		Score:      9,
		Confirmed:  confirmed,
		Why:        "a shell with a socket for stdio, started from a file that matched a rule",
		Signals: []correlate.Signal{
			{Layer: correlate.LayerFile, Class: "yara", Score: 5, Detail: "reverse_shell_generic", Definitive: true},
			{Layer: correlate.LayerNetwork, Class: "socket-stdio", Score: 4, Live: true},
		},
	}
	return forward.OCSFIncident(inc, forward.Product{Name: "CAU EDR", Version: "9.9.9-test", Host: "edr-agent-7"}, incidentTime)
}

func incidents(n int) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = incident(i+1, i%2 == 0)
	}
	return out
}

func uidOf(t *testing.T, m map[string]any) string {
	t.Helper()
	uid, ok := m["finding_info"].(map[string]any)["uid"].(string)
	if !ok || uid == "" {
		t.Fatalf("incident has no uid: %v", m)
	}
	return uid
}

func mustSender(t *testing.T, opts Options) *Sender {
	t.Helper()
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	s, err := NewSender(opts, report.WithHostname("fallback-host"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func field(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var cur any = doc
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q is not an object in %v", path, p, doc)
		}
		cur = obj[p]
	}
	return cur
}

func TestNewSenderValidates(t *testing.T) {
	for name, tc := range map[string]struct {
		opts Options
		want string
	}{
		"stix over https":   {Options{URL: "https://taxii.example/api/", Format: "stix"}, "TAXII"},
		"stix over tcp":     {Options{URL: "tcp://h:1", Format: "stix"}, "TAXII"},
		"report format":     {Options{URL: "tcp://h:1", Format: "ocsf"}, "cannot be sent"},
		"otlp over tcp":     {Options{URL: "tcp://h:1", Format: "otlp"}, "HTTP-only"},
		"no url":            {Options{Format: "ecs"}, "required"},
		"plain http":        {Options{URL: "http://h/x", Format: "ecs"}, "insecure"},
		"unknown over http": {Options{URL: "https://h/x", Format: "splunk"}, "not a sink format"},
	} {
		if _, err := NewSender(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	// The one-shot client rejects stix with the same message.
	if _, err := New(Options{URL: "udp://h:1", Format: "STIX"}); err == nil || !strings.Contains(err.Error(), "TAXII") {
		t.Errorf("collector.New accepted stix: %v", err)
	}
	// Every sink format has a transport.
	for _, f := range report.SinkFormats() {
		url := "tls://collector.example:6514"
		if f == "otlp" {
			url = "https://collector.example/v1/logs"
		}
		s, err := NewSender(Options{URL: url, Format: f})
		if err != nil || s.Client() == nil || s.Client().Cleartext() {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// A batch of incidents over TCP as syslog-ecs: one octet-counted RFC 5424
// frame per incident, whose MSG is the ECS document with the peer and the
// process an incident has and a file finding does not.
func TestSenderTCPSyslogECS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	var frames []string
	done := serveOnce(t, ln, func(c net.Conn) { frames = readOctetCounted(t, c) })
	s := mustSender(t, Options{URL: "tcp://" + ln.Addr().String(), Format: "syslog-ecs"})

	batch := incidents(4)
	n, err := s.Send(context.Background(), batch)
	<-done
	if err != nil || n != 4 {
		t.Fatalf("Send = %d, %v", n, err)
	}
	if len(frames) != 4 {
		t.Fatalf("collector read %d frames, want 4: %q", len(frames), frames)
	}
	for i, frame := range frames {
		// <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG
		parts := strings.SplitN(frame, " ", 8)
		if len(parts) != 8 {
			t.Fatalf("frame %d is not RFC 5424: %q", i, frame)
		}
		wantPRI := "<83>1" // authpriv.err: confirmed
		if i%2 == 1 {
			wantPRI = "<84>1" // authpriv.warning: unconfirmed
		}
		if parts[0] != wantPRI || parts[2] != "edr-agent-7" || parts[3] != "cau" || parts[5] != "finding" || parts[6] != "-" {
			t.Errorf("frame %d header: %q", i, parts[:7])
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(parts[7]), &doc); err != nil {
			t.Fatalf("frame %d MSG is not the ECS document: %v\n%s", i, err, parts[7])
		}
		peer := fmt.Sprintf("203.0.113.%d", i+1)
		if field(t, doc, "event", "id") != uidOf(t, batch[i]) {
			t.Errorf("frame %d is not incident %d: %v", i, i, field(t, doc, "event", "id"))
		}
		if field(t, doc, "destination", "ip") != peer || field(t, doc, "related", "ip").([]any)[0] != peer {
			t.Errorf("frame %d peer: %v / %v", i, doc["destination"], doc["related"])
		}
		if field(t, doc, "process", "pid") != float64(4001+i) {
			t.Errorf("frame %d process: %v", i, doc["process"])
		}
		if field(t, doc, "file", "path") != fmt.Sprintf("/tmp/stage-%d.sh", i+1) || field(t, doc, "host", "name") != "edr-agent-7" {
			t.Errorf("frame %d file/host: %v %v", i, doc["file"], doc["host"])
		}
		if ids := field(t, doc, "threat", "technique", "id").([]any); len(ids) != 2 || ids[0] != "T1059.004" {
			t.Errorf("frame %d techniques: %v", i, ids)
		}
		if mw := field(t, doc, "cau", "malware").([]any); len(mw) != 1 || mw[0] != "reverse_shell_generic" {
			t.Errorf("frame %d malware: %v", i, mw)
		}
		if ts, err := time.Parse(time.RFC3339Nano, doc["@timestamp"].(string)); err != nil || !ts.Equal(incidentTime) {
			t.Errorf("frame %d @timestamp: %v", i, doc["@timestamp"])
		}
	}
	if st := s.Stats(); st != (SenderStats{Sent: 4}) {
		t.Errorf("stats: %+v", st)
	}

	// What went over the wire is what the report package renders for the
	// same maps: the Sender adds framing and nothing else.
	want, _, err := report.RenderSinkEvents("syslog-ecs", batch, report.WithHostname("fallback-host"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(frames, "\n") + "\n"; got != string(want) {
		t.Errorf("wire bytes differ from report.RenderSinkEvents\n got: %s\nwant: %s", got, want)
	}
}

type otlpRecord struct {
	SeverityNumber int `json:"severityNumber"`
	Attributes     []struct {
		Key   string `json:"key"`
		Value struct {
			StringValue string `json:"stringValue"`
			IntValue    string `json:"intValue"`
			ArrayValue  struct {
				Values []struct {
					StringValue string `json:"stringValue"`
				} `json:"values"`
			} `json:"arrayValue"`
		} `json:"value"`
	} `json:"attributes"`
}

func (r otlpRecord) attr(key string) string {
	for _, a := range r.Attributes {
		if a.Key != key {
			continue
		}
		if a.Value.IntValue != "" {
			return a.Value.IntValue
		}
		if len(a.Value.ArrayValue.Values) > 0 {
			var items []string
			for _, v := range a.Value.ArrayValue.Values {
				items = append(items, v.StringValue)
			}
			return strings.Join(items, ",")
		}
		return a.Value.StringValue
	}
	return ""
}

// The same incidents as one OTLP/JSON request over HTTPS.
func TestSenderHTTPSOTLP(t *testing.T) {
	var body []byte
	var ctype, auth, path string
	posts := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		body, _ = io.ReadAll(r.Body)
		ctype, auth, path = r.Header.Get("Content-Type"), r.Header.Get("Authorization"), r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	s := mustSender(t, Options{URL: srv.URL + "/v1/logs", Format: "otlp", Insecure: true, Authorization: "Bearer s3cret"})

	batch := incidents(3)
	n, err := s.Send(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("Send = %d, %v", n, err)
	}
	if posts != 1 || ctype != "application/json" || auth != "Bearer s3cret" || path != "/v1/logs" {
		t.Errorf("request: %d posts, ct %q, auth %q, path %q", posts, ctype, auth, path)
	}
	var doc struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []otlpRecord `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.ResourceLogs) != 1 {
		t.Fatalf("body is not one ExportLogsServiceRequest: %v\n%s", err, body)
	}
	recs := doc.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 3 {
		t.Fatalf("%d log records, want 3", len(recs))
	}
	for i, rec := range recs {
		peer := fmt.Sprintf("203.0.113.%d", i+1)
		wantSev := 17
		if i%2 == 1 {
			wantSev = 13
		}
		if rec.SeverityNumber != wantSev || rec.attr("event.id") != uidOf(t, batch[i]) {
			t.Errorf("record %d: severity %d, id %q", i, rec.SeverityNumber, rec.attr("event.id"))
		}
		if rec.attr("destination.ip") != peer || rec.attr("related.ip") != peer || rec.attr("process.pid") != fmt.Sprint(4001+i) {
			t.Errorf("record %d: peer %q / %q, pid %q", i, rec.attr("destination.ip"), rec.attr("related.ip"), rec.attr("process.pid"))
		}
		if rec.attr("file.path") != fmt.Sprintf("/tmp/stage-%d.sh", i+1) || rec.attr("threat.technique.id") != "T1059.004,T1071.001" {
			t.Errorf("record %d: file %q, techniques %q", i, rec.attr("file.path"), rec.attr("threat.technique.id"))
		}
	}

	// A collector that refuses the request delivered nothing.
	down := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer down.Close()
	s2 := mustSender(t, Options{URL: down.URL + "/v1/logs", Format: "otlp", Insecure: true})
	if n, err := s2.Send(context.Background(), batch); err == nil || n != 0 {
		t.Errorf("a 503 must deliver nothing: %d, %v", n, err)
	}
	if st := s2.Stats(); st.Sent != 0 {
		t.Errorf("stats after a 503: %+v", st)
	}
}

// gelfCollector accepts messages over HTTPS until it "dies": from then on it
// drops every connection without an answer.
type gelfCollector struct {
	mu      sync.Mutex
	uids    []string
	dieAt   int // die when this many messages have been accepted; 0 = never
	srv     *httptest.Server
	dropped int
}

func newGELFCollector(dieAt int) *gelfCollector {
	g := &gelfCollector{dieAt: dieAt}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.dieAt > 0 && len(g.uids) >= g.dieAt {
			g.dropped++
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
				}
			}
			return
		}
		var msg map[string]any
		b, _ := io.ReadAll(r.Body)
		if json.Unmarshal(b, &msg) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		uid, _ := msg["_event_uid"].(string)
		g.uids = append(g.uids, uid)
		w.WriteHeader(http.StatusAccepted)
	}))
	return g
}

// A collector that dies in the middle of a batch: Send returns the count that
// landed together with the error, a malformed map in the batch is passed over
// rather than resent, and resending the tail delivers every incident exactly
// once.
func TestSenderPartialDeliveryAndMalformedMap(t *testing.T) {
	good := incidents(5)
	notAFinding := map[string]any{"class_uid": 4001, "message": "a network activity event, not a finding"}
	batch := []map[string]any{good[0], notAFinding, good[1], good[2], good[3], good[4]}

	dying := newGELFCollector(2)
	defer dying.srv.Close()
	s := mustSender(t, Options{URL: dying.srv.URL + "/gelf", Format: "gelf", Insecure: true})
	var warnings []string
	s.Warn = func(format string, args ...interface{}) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	n, err := s.Send(context.Background(), batch)
	if err == nil {
		t.Fatal("the collector died mid-batch and Send reported no error")
	}
	// Two incidents landed; the malformed map between them is done with too.
	if n != 3 {
		t.Fatalf("Send = %d (%v), want 3: two delivered and the malformed map passed over", n, err)
	}
	if len(dying.uids) != 2 || dying.uids[0] != uidOf(t, good[0]) || dying.uids[1] != uidOf(t, good[1]) {
		t.Fatalf("the collector accepted %q", dying.uids)
	}
	if st := s.Stats(); st != (SenderStats{Sent: 2, Malformed: 1}) {
		t.Errorf("stats after the partial delivery: %+v", st)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not OCSF Detection Findings") {
		t.Errorf("warnings: %q", warnings)
	}

	// What forward.Sink does next: resend batch[n:], to a collector that is
	// back up.
	healthy := newGELFCollector(0)
	defer healthy.srv.Close()
	s2 := mustSender(t, Options{URL: healthy.srv.URL + "/gelf", Format: "gelf", Insecure: true})
	rest := batch[n:]
	if n2, err := s2.Send(context.Background(), rest); err != nil || n2 != len(rest) {
		t.Fatalf("resend = %d, %v", n2, err)
	}
	var all []string
	all = append(append(all, dying.uids...), healthy.uids...)
	if len(all) != 5 {
		t.Fatalf("%d messages delivered in total, want each of the 5 incidents once: %q", len(all), all)
	}
	for i, m := range good {
		if all[i] != uidOf(t, m) {
			t.Errorf("message %d is %q, want incident %d", i, all[i], i)
		}
	}

	// A malformed map at the head is consumed even when nothing after it
	// lands, so it cannot pin the queue.
	dead := newGELFCollector(0)
	dead.srv.Close()
	s3 := mustSender(t, Options{URL: dead.srv.URL + "/gelf", Format: "gelf", Insecure: true, Timeout: time.Second})
	if n, err := s3.Send(context.Background(), []map[string]any{nil, notAFinding, good[0]}); err == nil || n != 2 {
		t.Errorf("head of malformed maps against a dead collector: %d, %v; want 2 and an error", n, err)
	}
	// And a batch of nothing but malformed maps is done without a connection.
	if n, err := s3.Send(context.Background(), []map[string]any{nil, notAFinding, {}}); err != nil || n != 3 {
		t.Errorf("all-malformed batch against a dead collector: %d, %v; want 3 and no error", n, err)
	}
	if st := s3.Stats(); st != (SenderStats{Malformed: 5}) {
		t.Errorf("stats: %+v", st)
	}
	if n, err := s3.Send(context.Background(), nil); err != nil || n != 0 {
		t.Errorf("empty batch: %d, %v", n, err)
	}
}

// The same over a TCP stream: the collector resets the connection after two
// frames. The seam holds the client until the reset has been sent, so the
// write that follows is the one that fails.
func TestSenderTCPCollectorDiesMidBatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	var first []string
	reset := make(chan struct{})
	go func() {
		defer close(reset)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		for len(first) < 2 {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			first = append(first, strings.TrimSuffix(line, "\n"))
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // close with a reset: the collector is gone
		}
		conn.Close()
	}()

	s := mustSender(t, Options{URL: "tcp://" + ln.Addr().String(), Format: "ecs"})
	s.client.afterEvent = func(sent int) {
		if sent == 2 {
			<-reset
			time.Sleep(50 * time.Millisecond)
		}
	}
	batch := incidents(8)
	n, err := s.Send(context.Background(), batch)
	if err == nil {
		t.Fatalf("the collector reset the connection after 2 of 8 events and Send reported no error (n = %d)", n)
	}
	// TCP acknowledges nothing to the application: the count is what was
	// written before a write failed, which is the two the collector read and
	// at most the one write that raced the reset.
	if n < 2 || n > 3 {
		t.Fatalf("Send = %d (%v), want 2 (or 3 if one write raced the reset)", n, err)
	}
	if len(first) != 2 {
		t.Fatalf("the collector read %d events before it died", len(first))
	}
	for i, line := range first {
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil || field(t, doc, "event", "id") != uidOf(t, batch[i]) {
			t.Errorf("event %d: %v %s", i, err, line)
		}
	}
	if st := s.Stats(); st.Sent != int64(n) {
		t.Errorf("stats: %+v, want Sent %d", st, n)
	}
}

// One event too large for a datagram is passed over and counted; its
// neighbours are sent. Resending it could never succeed.
func TestSenderUDPOversizeIsNotRetried(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp loopback: %v", err)
	}
	defer pc.Close()
	s := mustSender(t, Options{URL: "udp://" + pc.LocalAddr().String(), Format: "cef"})
	var warnings []string
	s.Warn = func(format string, args ...interface{}) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	batch := incidents(3)
	batch[1]["finding_info"].(map[string]any)["desc"] = strings.Repeat("x", MaxDatagram)
	n, err := s.Send(context.Background(), batch)
	if err != nil || n != 3 {
		t.Fatalf("Send = %d, %v; want the whole batch done without an error", n, err)
	}
	buf := make([]byte, 65536)
	for _, want := range []int{0, 2} {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(buf[:got]), "CEF:0|CAU|cau|") || !strings.Contains(string(buf[:got]), "externalId="+strings.ReplaceAll(uidOf(t, batch[want]), "=", `\=`)) {
			t.Errorf("datagram is not incident %d: %s", want, buf[:got])
		}
		if !strings.Contains(string(buf[:got]), fmt.Sprintf(" dst=203.0.113.%d ", want+1)) || !strings.Contains(string(buf[:got]), fmt.Sprintf(" spid=%d", 4001+want)) {
			t.Errorf("datagram %d lacks the peer or the process: %s", want, buf[:got])
		}
	}
	if st := s.Stats(); st != (SenderStats{Sent: 2, Oversize: 1}) {
		t.Errorf("stats: %+v", st)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "datagram limit") {
		t.Errorf("warnings: %q", warnings)
	}
	// Warned once, however often it happens.
	if _, err := s.Send(context.Background(), batch[1:2]); err != nil || len(warnings) != 1 || s.Stats().Oversize != 2 {
		t.Errorf("second oversize: err %v, warnings %d, stats %+v", err, len(warnings), s.Stats())
	}
}

// The _bulk API answers 200 and reports per document. A document the index
// refuses for good is counted and not resent (resending would index its
// accepted neighbours again on every retry); a 429 item stops the batch there.
func TestSenderBulkPerDocumentOutcome(t *testing.T) {
	reply := ""
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		io.WriteString(w, reply)
	}))
	defer srv.Close()
	opts := Options{URL: srv.URL + "/_bulk", Format: "ecs", BulkIndex: "logs-cau.finding-default", Insecure: true}
	batch := incidents(3)

	s := mustSender(t, opts)
	var warnings []string
	s.Warn = func(format string, args ...interface{}) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	reply = `{"errors":false,"items":[{"create":{"status":201}},{"create":{"status":201}},{"create":{"status":201}}]}`
	if n, err := s.Send(context.Background(), batch); err != nil || n != 3 {
		t.Fatalf("all accepted: %d, %v", n, err)
	}
	if lines := strings.Split(strings.TrimSuffix(bodies[0], "\n"), "\n"); len(lines) != 6 || !strings.Contains(lines[0], `"_index":"logs-cau.finding-default"`) {
		t.Fatalf("bulk body: %q", bodies[0])
	}

	reply = `{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [destination.ip]"}}},{"create":{"status":201}}]}`
	if n, err := s.Send(context.Background(), batch); err != nil || n != 3 {
		t.Fatalf("one document refused for good: %d, %v; want the batch done without an error", n, err)
	}
	if st := s.Stats(); st != (SenderStats{Sent: 5, Rejected: 1}) {
		t.Errorf("stats: %+v", st)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "mapper_parsing_exception") || !strings.Contains(warnings[0], "status 400") {
		t.Errorf("warnings: %q", warnings)
	}

	reply = `{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":429,"error":{"type":"es_rejected_execution_exception"}}},{"create":{"status":201}}]}`
	n, err := s.Send(context.Background(), batch)
	if err == nil || n != 1 || !strings.Contains(err.Error(), "429") {
		t.Fatalf("a 429 item: %d, %v; want 1 and an error naming the status", n, err)
	}

	// errors:true with no usable per-item report: nothing is claimed.
	reply = `{"errors":true,"items":[{"create":{"status":400}}]}`
	if n, err := s.Send(context.Background(), batch); err == nil || n != 0 {
		t.Errorf("an unreadable item list: %d, %v", n, err)
	}

	// The one-shot client reports the same response as an error, and counts
	// what was indexed.
	c, _ := New(opts)
	reply = `{"errors":true,"items":[{"create":{"status":201}},{"create":{"status":400,"error":{"reason":"bad"}}},{"create":{"status":201}}]}`
	payload, _, _ := report.RenderSinkEvents("ecs", batch)
	if res := c.Send(context.Background(), payload); res.Err == nil || res.Attempted != 3 || res.Delivered != 2 || !strings.Contains(res.Err.Error(), "1 of 3 documents were rejected") {
		t.Errorf("one-shot bulk with a refused document: %+v", res)
	}
}

// Send must not outlive its context: a daemon shutting down cancels, and a
// collector that has stopped reading must not hold it.
func TestSendStopsWhenTheContextIsCancelled(t *testing.T) {
	// Already cancelled: nothing is rendered or dialled.
	s := mustSender(t, Options{URL: "tcp://127.0.0.1:1", Format: "ecs"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := s.Send(ctx, incidents(2)); n != 0 || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled before Send: %d, %v", n, err)
	}

	// Cancelled while a write is blocked on a collector that accepts and
	// never reads. The client's own timeout is far longer than the test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	hold := make(chan struct{})
	defer close(hold)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-hold
	}()
	c, err := New(Options{URL: "tcp://" + ln.Addr().String(), Format: "cef", Timeout: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	// More than the socket buffers of a loopback connection can absorb.
	line := strings.Repeat("x", 1<<20)
	payload := []byte(strings.Repeat(line+"\n", 24))
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	res := c.Send(ctx, payload)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Send returned %v after the context was cancelled", elapsed)
	}
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) || res.Delivered >= res.Attempted {
		t.Errorf("result: delivered %d of %d, err %v", res.Delivered, res.Attempted, res.Err)
	}

	// The same for a request in flight.
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release) // runs first: lets the handler return so Close can
	hs := mustSender(t, Options{URL: srv.URL + "/v1/logs", Format: "otlp", Insecure: true, Timeout: 5 * time.Minute})
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start = time.Now()
	n, err := hs.Send(ctx, incidents(2))
	if elapsed := time.Since(start); elapsed > 10*time.Second || n != 0 || err == nil {
		t.Errorf("https: %d, %v after %v", n, err, elapsed)
	}
}

// End to end through the daemon's queue: incidents offered to a forward.Sink
// arrive at the collector, and the sink's own accounting agrees.
func TestSenderBehindForwardSink(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no tcp loopback: %v", err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var frames []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				got := readOctetCounted(t, conn)
				mu.Lock()
				frames = append(frames, got...)
				mu.Unlock()
			}()
		}
	}()

	s := mustSender(t, Options{URL: "tcp://" + ln.Addr().String(), Format: "syslog-cef"})
	sink := forward.NewSink(s, forward.SinkOptions{Batch: 4, Flush: 20 * time.Millisecond, Backoff: 20 * time.Millisecond, Timeout: 5 * time.Second})
	sink.Start()
	batch := incidents(10)
	for i, m := range batch {
		sink.Offer(m)
		if i == 4 {
			sink.Offer(map[string]any{"not": "a finding"})
		}
	}
	stats := sink.Close(5 * time.Second)
	// The queue counts what the Sender consumed; the Sender says how many of
	// those were events on the wire.
	if stats.Offered != 11 || stats.Delivered != 11 || stats.Dropped != 0 || stats.Failed != 0 || stats.Pending != 0 {
		t.Errorf("sink stats: %+v", stats)
	}
	if st := s.Stats(); st != (SenderStats{Sent: 10, Malformed: 1}) {
		t.Errorf("sender stats: %+v", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(frames)
		mu.Unlock()
		if got >= 10 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(frames) != 10 {
		t.Fatalf("the collector received %d frames, want 10", len(frames))
	}
	// Each batch travels on its own connection, so only the set is asserted:
	// every incident exactly once.
	all := strings.Join(frames, "\n")
	for i, m := range batch {
		if n := strings.Count(all, "externalId="+strings.ReplaceAll(uidOf(t, m), "=", `\=`)+" "); n != 1 {
			t.Errorf("incident %d arrived %d times", i, n)
		}
	}
	for i, f := range frames {
		if !strings.Contains(f, " CEF:0|CAU|cau|") {
			t.Errorf("frame %d is not a CEF event in a syslog frame: %s", i, f)
		}
	}
}

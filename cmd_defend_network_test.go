package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/correlate"
	"github.com/1ungaka/sentinel-edr/internal/ingest"
	"github.com/1ungaka/sentinel-edr/internal/netblock"
	"github.com/1ungaka/sentinel-edr/internal/netscan"
	"github.com/1ungaka/sentinel-edr/scanner"
)

// netFixture is a defender whose only layers are the network one and whatever
// the test adds, reading a /proc and an /etc the test wrote.
type netFixture struct {
	dir, proc, etc string
	out            bytes.Buffer
	fw             *recorder
	d              *defender
}

// recorder stands in for the firewall.
type recorder struct {
	calls []string
	tools map[string]bool
}

func (r *recorder) run(name string, args []string, stdin string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func (r *recorder) look(name string) (string, error) {
	if r.tools[name] {
		return "/usr/sbin/" + name, nil
	}
	return "", errors.New("not found")
}

func (r *recorder) called(substr string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func newNetFixture(t *testing.T) *netFixture {
	t.Helper()
	f := &netFixture{dir: t.TempDir()}
	f.proc, f.etc = filepath.Join(f.dir, "proc"), filepath.Join(f.dir, "etc")
	for _, d := range []string{f.proc, f.etc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.etc, "resolv.conf"), []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.fw = &recorder{tools: map[string]bool{"nft": true}}
	f.d = &defender{
		engine:   &scanner.Engine{Tradecraft: true, Heuristics: true},
		procRoot: f.proc, persistRoot: f.dir, hostRoot: f.dir, etcRoot: f.etc, network: true,
		store: filepath.Join(f.dir, "vault"), json: true, out: &f.out,
		warn: func(string, ...interface{}) {},
	}
	f.d.ready()
	return f
}

// arm gives the fixture a firewall whose commands are recorded, not run.
func (f *netFixture) arm(t *testing.T, protect ...string) {
	t.Helper()
	b, err := netblock.Open(netblock.Options{
		Run: f.fw.run, Look: f.fw.look, Protect: protect, TTL: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.d.blocker = b
}

// socket declares a process holding one established connection.
func (f *netFixture) socket(t *testing.T, pid int, comm, exe, remote string, port int) {
	t.Helper()
	base := filepath.Join(f.proc, strconv.Itoa(pid))
	for _, d := range []string{"fd", "net", "ns"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[4026531840]", filepath.Join(base, "ns", "net")); err != nil {
		t.Fatal(err)
	}
	inode := strconv.Itoa(5000 + pid)
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(base, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	row := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 1000 0 %s 1 0000 20 4",
		kernelHex(t, "10.0.0.2", 44000+pid), kernelHex(t, remote, port), inode)
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" + row + "\n"
	if err := os.WriteFile(filepath.Join(base, "net", "tcp"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
}

// kernelHex renders an address the way /proc/net/tcp holds it.
func kernelHex(t *testing.T, addr string, port int) string {
	t.Helper()
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		t.Fatalf("kernelHex wants an IPv4 address, got %q", addr)
	}
	var b [4]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatal(err)
		}
		b[i] = n
	}
	return fmt.Sprintf("%02X%02X%02X%02X:%04X", b[3], b[2], b[1], b[0], port)
}

// incidents reads the JSON lines the fixture wrote.
func (f *netFixture) incidents(t *testing.T) []incidentLine {
	t.Helper()
	var out []incidentLine
	for _, line := range strings.Split(strings.TrimSpace(f.out.String()), "\n") {
		if line == "" {
			continue
		}
		var rec incidentLine
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("output is not one JSON object per line: %v\n%s", err, line)
		}
		out = append(out, rec)
	}
	return out
}

type incidentLine struct {
	Incident correlate.Incident `json:"incident"`
	Actions  []string           `json:"actions"`
}

// TestDefendNetworkLayerConfirmsFilelessEgress: a process with no file on disk
// holding a socket is live state, so the daemon may act on it without waiting
// for a second layer — and what it does is block the peer and stop the holder.
func TestDefendNetworkLayerConfirmsFilelessEgress(t *testing.T) {
	f := newNetFixture(t)
	f.arm(t, "192.168.1.1")
	f.socket(t, 900, "bash", "/memfd:payload (deleted)", "203.0.113.9", 443)

	f.d.cycle()
	lines := f.incidents(t)
	if len(lines) != 1 {
		t.Fatalf("want one incident, got %d:\n%s", len(lines), f.out.String())
	}
	inc := lines[0].Incident
	if !hasLayer(inc, correlate.LayerNetwork) {
		t.Fatalf("the network layer is missing: %v", inc.Layers)
	}
	if !inc.Confirmed {
		t.Fatalf("a fileless process holding a socket is live state: %s", inc.Why)
	}
	if len(inc.Peers) != 1 || inc.Peers[0] != "203.0.113.9" {
		t.Errorf("peers = %v", inc.Peers)
	}
	if !f.fw.called("nft add element inet cau blocked4 { 203.0.113.9 }") {
		t.Errorf("the peer was not blocked: %v", f.fw.calls)
	}
	if !strings.Contains(strings.Join(lines[0].Actions, " "), "203.0.113.9") {
		t.Errorf("the response is not in the report: %v", lines[0].Actions)
	}
}

// TestDefendNeverBlocksWhatTheHostNeeds: the policy holds even when the
// incident is confirmed, and the refusal is reported rather than swallowed.
func TestDefendNeverBlocksWhatTheHostNeeds(t *testing.T) {
	f := newNetFixture(t)
	f.arm(t, "192.168.1.1")
	// The implant is talking to the host's own gateway, which is also its
	// resolver. Blocking that would take the host off the network.
	f.socket(t, 901, "bash", "/memfd:payload (deleted)", "192.168.1.1", 443)

	f.d.cycle()
	lines := f.incidents(t)
	if len(lines) != 1 {
		t.Fatalf("want one incident, got %d", len(lines))
	}
	if f.fw.called("add element") {
		t.Fatalf("the gateway was blocked: %v", f.fw.calls)
	}
	joined := strings.Join(lines[0].Actions, " ")
	if !strings.Contains(joined, "not blocked") {
		t.Errorf("the refusal must be reported: %v", lines[0].Actions)
	}
}

// TestDefendNetworkLayerAloneIsAnAlert: a listener from a relay tool is a
// strong alert, and still only one layer's opinion, so nothing is blocked.
func TestDefendNetworkLayerAloneIsAnAlert(t *testing.T) {
	f := newNetFixture(t)
	f.arm(t)
	f.socket(t, 902, "nc", "/usr/bin/nc", "203.0.113.50", 9999)

	f.d.cycle()
	lines := f.incidents(t)
	if len(lines) != 1 {
		t.Fatalf("want one incident, got %d:\n%s", len(lines), f.out.String())
	}
	if lines[0].Incident.Confirmed {
		t.Errorf("one layer with no live state must stay an alert: %s", lines[0].Incident.Why)
	}
	if f.fw.called("add element") {
		t.Fatalf("an unconfirmed incident must not block: %v", f.fw.calls)
	}
}

// TestDefendIngestConfirmsOnAPeer is the cross-domain path: this host's own
// view of a peer is weak, another sensor's is definitive, and the peer address
// is what lets them meet.
func TestDefendIngestConfirmsOnAPeer(t *testing.T) {
	f := newNetFixture(t)
	f.arm(t)
	// Weak on its own: a connection to a handler port scores 3 and is not even
	// reported by the sensor alone.
	f.socket(t, 903, "agent", "/opt/vendor/agent", "203.0.113.9", 4444)

	telemetry := filepath.Join(f.dir, "sensors")
	if err := os.MkdirAll(telemetry, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"host":"fw-1","class":"firewall.c2","score":9,"definitive":true,` +
		`"detail":"the perimeter firewall identified 203.0.113.9 as a Cobalt Strike team server",` +
		`"peers":["203.0.113.9"]}` + "\n"
	if err := os.WriteFile(filepath.Join(telemetry, "fw-1.jsonl"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.ingestPaths = []string{telemetry}
	f.d.feeder = newIngestReaderForTest()

	f.d.cycle()
	lines := f.incidents(t)
	if len(lines) != 1 {
		t.Fatalf("want one joined incident, got %d:\n%s", len(lines), f.out.String())
	}
	inc := lines[0].Incident
	if !hasLayer(inc, correlate.LayerExternal) || !hasLayer(inc, correlate.LayerNetwork) {
		t.Fatalf("both sides should be in the incident: %v", inc.Layers)
	}
	if !inc.Confirmed {
		t.Fatalf("two layers about one peer is confirmed: %s", inc.Why)
	}
	if len(inc.Hosts) != 1 || inc.Hosts[0] != "fw-1" {
		t.Errorf("hosts = %v, want the sensor named", inc.Hosts)
	}
	if !f.fw.called("nft add element inet cau blocked4 { 203.0.113.9 }") {
		t.Errorf("the corroborated peer was not blocked: %v", f.fw.calls)
	}
	// The response is planned for this host only: the sensor named no process
	// and no file here, so nothing else happened.
	if len(correlate.PlanFor(inc).Quarantine) != 0 {
		t.Errorf("nothing should be quarantined: %v", correlate.PlanFor(inc).Quarantine)
	}
}

// TestDefendIngestIsBounded: a sensor writing endlessly costs bounded memory.
func TestDefendIngestIsBounded(t *testing.T) {
	f := newNetFixture(t)
	f.d.network = false
	dir := filepath.Join(f.dir, "flood")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := range defendMaxExternal + 50 {
		fmt.Fprintf(&b, `{"host":"s","class":"c%d","score":1,"detail":"x"}`+"\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.ingestPaths = []string{dir}
	f.d.feeder = newIngestReaderForTest()
	for range 3 {
		f.d.ingestLayer()
	}
	f.d.mu.Lock()
	held := len(f.d.external)
	f.d.mu.Unlock()
	if held > defendMaxExternal {
		t.Fatalf("held %d external signals, cap is %d", held, defendMaxExternal)
	}
}

// TestDefendNetworkHistoryPersistsAcrossCycles: the analytics that need more
// than one sample are the daemon's reason to exist, so the record must survive
// a cycle.
func TestDefendNetworkHistoryPersistsAcrossCycles(t *testing.T) {
	f := newNetFixture(t)
	f.socket(t, 904, "agent", "/usr/bin/agent", "203.0.113.9", 443)
	f.d.cycle()
	first := f.d.netHistory.Samples()
	f.d.networkLayer()
	if f.d.netHistory.Samples() <= first {
		t.Fatalf("the network history did not grow: %d then %d", first, f.d.netHistory.Samples())
	}
}

// TestDefendBlockTTLFlagMeaning: 0 on the command line means "until removed",
// which the package spells as a negative, and anything else is itself.
func TestBlockTTLFlagMeaning(t *testing.T) {
	if got := blockTTLValue(0); got >= 0 {
		t.Errorf("blockTTLValue(0) = %v, want a negative (no expiry)", got)
	}
	if got := blockTTLValue(netblock.DefaultTTL); got != netblock.DefaultTTL {
		t.Errorf("blockTTLValue(1h) = %v", got)
	}
}

func TestNetscanAndDefendAgreeOnDeletedPaths(t *testing.T) {
	// Both halves strip the kernel's suffix the same way, or a file verdict and
	// a socket would never meet.
	if netscan.TrimDeleted("/tmp/x (deleted)") != trimDeleted("/tmp/x (deleted)") {
		t.Error("netscan.TrimDeleted and the daemon's trimDeleted disagree")
	}
}

// newIngestReaderForTest keeps the test's intent readable: the reader has no
// age limit, so a fixture's fresh file is never skipped for want of a clock.
func newIngestReaderForTest() *ingest.Reader { return ingest.NewReader(ingest.Options{}) }

// TestRunningVerdictsSurviveAnotherLayersPass: two layers read processes
// through /proc now, and each sees its own set. A layer's pass must forget only
// its own names, or whichever ran last would erase the other's evidence — the
// process layer's masquerade finding and the network layer's memfd-with-a-socket
// finding are rarely about the same process.
func TestRunningVerdictsSurviveAnotherLayersPass(t *testing.T) {
	f := newNetFixture(t)
	key := runningPrefix + "/tmp/implant"
	f.d.record(key, fileEntry{hit: true, signal: correlate.Signal{
		Layer: correlate.LayerFile, Class: "yara", Score: 10, Definitive: true, Files: []string{"/tmp/implant"},
	}})

	// The network layer is reading it; the process table never flagged it.
	f.d.keepRunning(viewNetwork, []string{"/tmp/implant"})
	f.d.keepRunning(viewProcess, nil)

	f.d.mu.Lock()
	_, held := f.d.hits[key]
	f.d.mu.Unlock()
	if !held {
		t.Fatal("the process layer's pass erased the network layer's running verdict")
	}

	// Once no layer names it, the bytes are gone and so is the verdict.
	f.d.keepRunning(viewNetwork, nil)
	f.d.mu.Lock()
	_, stillHeld := f.d.hits[key]
	f.d.mu.Unlock()
	if stillHeld {
		t.Fatal("a running verdict no layer names any more must be dropped")
	}
}

// TestNetworkLayerScansADeletedBinarysBytes: the strongest thing this layer
// finds is a process with no file on disk holding a socket, and a path that has
// been unlinked cannot be opened. Reading through /proc/<pid>/exe is the only
// chance to see those bytes, so the file scanner's verdict on them has to join
// the network layer's finding rather than being lost.
func TestNetworkLayerScansADeletedBinarysBytes(t *testing.T) {
	f := newNetFixture(t)
	// A real file whose name carries the kernel's " (deleted)" suffix: reading
	// /proc/<pid>/exe reaches the bytes, while the name it reports is a path
	// that is not on disk.
	bytesDir := t.TempDir()
	onDisk := filepath.Join(bytesDir, "implant (deleted)")
	if err := os.WriteFile(onDisk, []byte(fixtureShell), 0o755); err != nil {
		t.Fatal(err)
	}
	f.socket(t, 900, "bash", onDisk, "203.0.113.9", 443)

	name := filepath.Join(bytesDir, "implant")
	if _, err := os.Stat(name); err == nil {
		t.Fatal("the fixture is wrong: the reported path must not exist on disk")
	}

	f.d.cycle()

	f.d.mu.Lock()
	_, viaPath := f.d.hits[name]
	running, viaProc := f.d.hits[runningPrefix+name]
	f.d.mu.Unlock()
	if viaPath {
		t.Error("there is no file at that path, so there should be no path-keyed verdict")
	}
	if !viaProc {
		t.Fatal("the bytes behind the process were never scanned: a deleted binary flagged only by the network layer goes unread")
	}
	if !slices.Contains(running.Files, name) {
		t.Errorf("the file signal names %v, which cannot link to the network signal's %q", running.Files, name)
	}

	lines := f.incidents(t)
	if len(lines) != 1 {
		t.Fatalf("want one incident, got %d:\n%s", len(lines), f.out.String())
	}
	inc := lines[0].Incident
	if !hasLayer(inc, correlate.LayerFile) || !hasLayer(inc, correlate.LayerNetwork) {
		t.Fatalf("the file verdict and the socket must meet in one incident: %v", inc.Layers)
	}
	if !inc.Confirmed {
		t.Errorf("a scanned payload holding a socket is confirmed: %s", inc.Why)
	}
}

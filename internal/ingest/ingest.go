// Package ingest reads telemetry from somewhere other than this host and turns
// it into signals the correlator can join.
//
// This is what makes the engine cross-domain rather than host-only: a firewall
// that saw a peer, an IDS that saw a session, or another cau host that saw the
// same command-and-control address becomes one more source of evidence about an
// artefact this host also knows. The join happens on the peer address, which is
// the one identifier two machines can agree on — a PID and a path mean nothing
// off the host that produced them.
//
// Three shapes are read, all as JSON lines:
//
//   - A cau incident, either bare (`cau defend --format json`) or inside the
//     OCSF Detection Finding envelope the forwarder emits. Both carry the
//     incident verbatim, so another cau host's evidence arrives without being
//     flattened into a message string.
//   - An OCSF event from anything else. Severity becomes a score, the ATT&CK
//     objects become techniques, and the endpoint addresses become peers.
//   - A plain event: {"host","class","score","technique","detail","files",
//     "pid","peers"}, for a sensor or script with no format of its own.
//
// Two rules keep ingested evidence honest, and they are enforced here rather
// than left to the caller:
//
//   - Every signal is marked with the host it came from, never with this one.
//     An event whose source cannot be determined is attributed to the file it
//     was read from, so nothing from outside is ever mistaken for local state.
//     correlate.PlanFor then refuses to stop a process or quarantine a file on
//     a remote signal's word: it corroborates, it does not direct.
//   - Reading is append-only and bounded. A Reader remembers how far it got in
//     each file, re-reads nothing, and takes at most MaxBytes per pass, so a
//     sensor writing a gigabyte of events cannot stall the defence.
package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/safefs"
)

// Defaults.
const (
	// DefaultMaxBytes is how much new telemetry one pass reads from one file.
	DefaultMaxBytes = 8 << 20
	// DefaultMaxEvents is how many signals one pass produces.
	DefaultMaxEvents = 4096
	// maxLineBytes bounds one line, so a file with no newlines cannot be read
	// into memory whole.
	maxLineBytes = 1 << 20
)

// UnknownHost is the source attributed to an event that names no host and came
// from no file. It is never empty, because an empty host means "this machine" to
// the correlator and would license a local response.
const UnknownHost = "unknown-sensor"

// Options configure parsing.
type Options struct {
	// Host is the source attributed to events that name none. Empty falls back
	// to the file's name, then to UnknownHost.
	Host string
	// MaxBytes is how much new data one pass reads from one file.
	MaxBytes int64
	// MaxEvents is how many signals one pass produces.
	MaxEvents int
	// MaxAge drops events older than this, so a file left behind by an old
	// sensor does not keep raising the same incident. 0 keeps everything.
	MaxAge time.Duration
	// Now overrides the clock (for tests).
	Now time.Time
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o Options) maxBytes() int64 {
	if o.MaxBytes <= 0 {
		return DefaultMaxBytes
	}
	return o.MaxBytes
}

func (o Options) maxEvents() int {
	if o.MaxEvents <= 0 {
		return DefaultMaxEvents
	}
	return o.MaxEvents
}

// ParseLine reads one JSON line. It returns every signal the line carries: an
// incident envelope holds several, a plain event holds one. A line that is not
// JSON, or carries nothing recognisable, returns no signals and no error — a
// telemetry file with a header or a blank line is normal, and refusing the whole
// file over one line would lose the rest.
func ParseLine(data []byte, opts Options) ([]correlate.Signal, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	host := opts.Host
	if host == "" {
		host = UnknownHost
	}
	// An event older than the window is dropped here rather than in the caller:
	// a telemetry file left behind by a sensor that stopped weeks ago would
	// otherwise raise its last incident again every time a daemon restarts.
	if opts.MaxAge > 0 {
		if ts, ok := eventTime(doc["time"]); ok && opts.now().Sub(ts) > opts.MaxAge {
			return nil, nil
		}
	}

	// A cau incident, bare or inside the OCSF envelope the forwarder emits.
	if raw, ok := doc["incident"]; ok {
		return fromIncident(raw, host, "")
	}
	if raw, ok := doc["unmapped"]; ok {
		var un struct {
			Incident  json.RawMessage `json:"incident"`
			AgentHost string          `json:"agent_host"`
		}
		if err := json.Unmarshal(raw, &un); err == nil && len(un.Incident) > 0 {
			if un.AgentHost != "" {
				host = un.AgentHost
			}
			return fromIncident(un.Incident, host, "")
		}
	}
	if _, ok := doc["class_uid"]; ok {
		return fromOCSF(data, host)
	}
	return fromPlain(data, host)
}

// fromIncident reads another host's correlated incident. Its signals are taken
// as they are — class, score, technique, detail, peers — and re-marked as
// evidence from elsewhere. Nothing is re-scored: a peer host's engine is this
// engine, and silently halving its numbers would make a fleet disagree with
// itself.
func fromIncident(raw json.RawMessage, host, _ string) ([]correlate.Signal, error) {
	var inc correlate.Incident
	if err := json.Unmarshal(raw, &inc); err != nil {
		return nil, fmt.Errorf("reading an incident: %w", err)
	}
	out := make([]correlate.Signal, 0, len(inc.Signals))
	for _, s := range inc.Signals {
		s.Host = firstNonEmpty(s.Host, host)
		// The original layer is kept in the class, so an analyst can still see
		// that it was a process signal, while the layer itself says plainly that
		// the evidence is not from here.
		if s.Layer != "" && s.Layer != correlate.LayerExternal {
			s.Class = string(s.Layer) + "/" + s.Class
		}
		s.Layer = correlate.LayerExternal
		if len(s.Peers) == 0 {
			s.Peers = inc.Peers
		}
		out = append(out, s)
	}
	if len(out) == 0 && inc.ID != "" {
		out = append(out, correlate.Signal{
			Layer: correlate.LayerExternal, Class: "external.incident", Score: inc.Score,
			Technique: strings.Join(inc.Techniques, ","), Detail: inc.Why,
			Files: inc.Files, Peers: inc.Peers, Host: host,
		})
	}
	return out, nil
}

// ocsfSeverity maps OCSF's severity to this engine's scale. The two meet at the
// point both call "act on this": a High OCSF finding scores what a corroborated
// local signal scores, and a Critical one scores what definitive evidence does.
func ocsfSeverity(id int, name string) int {
	switch strings.ToLower(name) {
	case "critical", "fatal":
		return 9
	case "high":
		return 7
	case "medium":
		return 4
	case "low":
		return 2
	case "informational", "info":
		return 1
	}
	switch id {
	case 6, 5:
		return 9
	case 4:
		return 7
	case 3:
		return 4
	case 2:
		return 2
	}
	return 1
}

// fromOCSF reads an OCSF event from another product.
func fromOCSF(data []byte, host string) ([]correlate.Signal, error) {
	var ev struct {
		ClassName   string `json:"class_name"`
		Message     string `json:"message"`
		Severity    string `json:"severity"`
		SeverityID  int    `json:"severity_id"`
		IsAlert     bool   `json:"is_alert"`
		Time        int64  `json:"time"`
		FindingInfo struct {
			Title   string `json:"title"`
			Desc    string `json:"desc"`
			Attacks []struct {
				Technique struct {
					UID string `json:"uid"`
				} `json:"technique"`
			} `json:"attacks"`
		} `json:"finding_info"`
		Device struct {
			Hostname string `json:"hostname"`
			Name     string `json:"name"`
		} `json:"device"`
		Metadata struct {
			Product struct {
				Name string `json:"name"`
			} `json:"product"`
		} `json:"metadata"`
		SrcEndpoint struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		} `json:"src_endpoint"`
		DstEndpoint struct {
			IP string `json:"ip"`
		} `json:"dst_endpoint"`
		Process struct {
			PID  int `json:"pid"`
			File struct {
				Path string `json:"path"`
			} `json:"file"`
		} `json:"process"`
		File struct {
			Path string `json:"path"`
		} `json:"file"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("reading an OCSF event: %w", err)
	}
	detail := firstNonEmpty(ev.Message, ev.FindingInfo.Title, ev.FindingInfo.Desc)
	if detail == "" {
		return nil, nil
	}
	var techs []string
	for _, a := range ev.FindingInfo.Attacks {
		if a.Technique.UID != "" {
			techs = append(techs, a.Technique.UID)
		}
	}
	var peers []string
	for _, p := range []string{ev.SrcEndpoint.IP, ev.DstEndpoint.IP} {
		if correlate.LinkablePeer(p) {
			peers = append(peers, p)
		}
	}
	var files []string
	for _, f := range []string{ev.File.Path, ev.Process.File.Path} {
		if f != "" && correlate.Linkable(f) {
			files = append(files, f)
		}
	}
	product := ev.Metadata.Product.Name
	if product == "" {
		product = "ocsf"
	}
	class := "external." + slug(product)
	if ev.ClassName != "" {
		class += "." + slug(ev.ClassName)
	}
	return []correlate.Signal{{
		Layer: correlate.LayerExternal, Class: class,
		Score:     ocsfSeverity(ev.SeverityID, ev.Severity),
		Technique: strings.Join(techs, ","),
		Detail:    detail,
		Files:     files, Peers: peers,
		// The PID belongs to the reporting host, and PlanFor refuses to act on a
		// remote signal, so carrying it is a help to an analyst and a risk to
		// nobody.
		PID:  ev.Process.PID,
		Host: firstNonEmpty(ev.Device.Hostname, ev.Device.Name, ev.SrcEndpoint.Hostname, host),
	}}, nil
}

// plainEvent is the format for a sensor with no format of its own.
type plainEvent struct {
	Host       string   `json:"host"`
	Source     string   `json:"source"`
	Class      string   `json:"class"`
	Score      int      `json:"score"`
	Technique  string   `json:"technique"`
	Detail     string   `json:"detail"`
	Message    string   `json:"message"`
	File       string   `json:"file"`
	Files      []string `json:"files"`
	PID        int      `json:"pid"`
	Peer       string   `json:"peer"`
	Peers      []string `json:"peers"`
	Live       bool     `json:"live"`
	Definitive bool     `json:"definitive"`
}

func fromPlain(data []byte, host string) ([]correlate.Signal, error) {
	var ev plainEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("reading an event: %w", err)
	}
	if ev.Class == "" {
		return nil, nil
	}
	files := ev.Files
	if ev.File != "" {
		files = append(files, ev.File)
	}
	peers := ev.Peers
	if ev.Peer != "" {
		peers = append(peers, ev.Peer)
	}
	keep := peers[:0]
	for _, p := range peers {
		if correlate.LinkablePeer(p) {
			keep = append(keep, p)
		}
	}
	score := ev.Score
	if score <= 0 {
		score = 4 // said without a number: enough to corroborate, never alone
	}
	class := ev.Class
	if !strings.HasPrefix(class, "external.") {
		class = "external." + class
	}
	return []correlate.Signal{{
		Layer: correlate.LayerExternal, Class: class, Score: score,
		Technique: ev.Technique, Detail: firstNonEmpty(ev.Detail, ev.Message),
		Files: files, Peers: keep, PID: ev.PID,
		Live: ev.Live, Definitive: ev.Definitive,
		Host: firstNonEmpty(ev.Host, ev.Source, host),
	}}, nil
}

// Reader reads new telemetry from a set of files or directories, remembering
// where it got to in each. It is safe for concurrent use.
type Reader struct {
	opts    Options
	mu      sync.Mutex
	offsets map[string]int64
}

// NewReader returns a Reader that has seen nothing yet. Its first pass reads
// each file from the beginning; every later pass reads only what was appended.
func NewReader(opts Options) *Reader {
	return &Reader{opts: opts, offsets: map[string]int64{}}
}

// Collect reads what is new in each path and returns the signals found, with a
// warning for every path that could not be read. Paths may be files or
// directories; a directory contributes its .json, .jsonl and .log files, one
// level deep.
func (r *Reader) Collect(paths []string) ([]correlate.Signal, []string) {
	var out []correlate.Signal
	var warnings []string
	for _, p := range expand(paths, &warnings) {
		signals, warn := r.readFile(p)
		out = append(out, signals...)
		warnings = append(warnings, warn...)
		if len(out) >= r.opts.maxEvents() {
			warnings = append(warnings, fmt.Sprintf("ingest stopped at %d events this pass; the rest is read on the next one", r.opts.maxEvents()))
			return out[:r.opts.maxEvents()], warnings
		}
	}
	return out, warnings
}

func expand(paths []string, warnings *[]string) []string {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("ingest %s: %v", p, err))
			continue
		}
		if !st.IsDir() {
			// A path named outright is read whatever it is: safefs refuses a
			// FIFO or a device at open and the warning names it, which is more
			// useful than silently ignoring what the operator asked for.
			out = append(out, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("ingest %s: %v", p, err))
			continue
		}
		var files []string
		for _, e := range entries {
			switch strings.ToLower(filepath.Ext(e.Name())) {
			case ".json", ".jsonl", ".log", ".ndjson":
			default:
				continue
			}
			// Only regular files are queued. A directory, a FIFO, a device or a
			// socket with a telemetry name is reported once and skipped: this is
			// the message, while safefs at open is the guarantee, because a stat
			// here and an open later are two different files on a directory
			// somebody else can write to.
			if !e.Type().IsRegular() {
				if fi, err := os.Stat(filepath.Join(p, e.Name())); err != nil || !fi.Mode().IsRegular() {
					*warnings = append(*warnings, fmt.Sprintf("ingest %s: skipped, not a regular file (%s)",
						filepath.Join(p, e.Name()), e.Type().String()))
					continue
				}
			}
			files = append(files, filepath.Join(p, e.Name()))
		}
		sort.Strings(files)
		out = append(out, files...)
	}
	return out
}

// readFile reads the part of one file that is new.
func (r *Reader) readFile(path string) ([]correlate.Signal, []string) {
	// safefs opens with O_NONBLOCK and asks the open descriptor what it got, so
	// a FIFO cannot hold this layer open for ever. That matters more here than
	// anywhere else in the agent: an ingest directory is somewhere an operator
	// points at another program's output, a named pipe is a plausible thing to
	// find there, and a blocking open would hang the ingest layer, then
	// shutdown, and then --once outright, because this layer runs first.
	f, st, err := safefs.Open(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("ingest %s: %v", path, err)}
	}
	defer f.Close()

	r.mu.Lock()
	offset := r.offsets[path]
	r.mu.Unlock()
	// A file that shrank was rotated or replaced, so what is there now is new.
	if st.Size() < offset {
		offset = 0
	}
	if st.Size() == offset {
		return nil, nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, []string{fmt.Sprintf("ingest %s: %v", path, err)}
	}

	limit := r.opts.maxBytes()
	sc := bufio.NewScanner(io.LimitReader(f, limit))
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)

	opts := r.opts
	if opts.Host == "" {
		opts.Host = hostFromPath(path)
	}
	var out []correlate.Signal
	var warnings []string
	read := int64(0)
	complete := int64(0)
	for sc.Scan() {
		line := sc.Bytes()
		read += int64(len(line)) + 1
		// Only advance past a line that ended with a newline. A sensor that is
		// mid-write would otherwise have its half-line consumed and lost.
		if read <= limit && offset+read <= st.Size() {
			complete = read
		}
		signals, err := ParseLine(line, opts)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ingest %s: %v", path, err))
			continue
		}
		out = append(out, signals...)
	}
	if err := sc.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("ingest %s: %v", path, err))
	}
	r.mu.Lock()
	r.offsets[path] = offset + complete
	r.mu.Unlock()
	return out, warnings
}

// Rewind forgets how far reading got, so the next pass re-reads everything.
func (r *Reader) Rewind() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.offsets = map[string]int64{}
}

// hostFromPath attributes an event to the file it came from, so a fleet that
// drops one file per host per directory needs no configuration at all.
func hostFromPath(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if name == "" {
		return UnknownHost
	}
	return name
}

// eventTime reads the timestamp an event carries: RFC 3339 as cau's own JSON
// lines write it, or milliseconds since the epoch as OCSF does.
func eventTime(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 {
		return time.Time{}, false
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", time.RFC1123Z} {
			if t, err := time.Parse(layout, str); err == nil {
				return t, true
			}
		}
		return time.Time{}, false
	}
	var ms int64
	if err := json.Unmarshal(raw, &ms); err != nil || ms <= 0 {
		return time.Time{}, false
	}
	// Seconds and milliseconds are both seen in the wild; anything below this
	// bound cannot be a millisecond timestamp of a date that has happened.
	if ms < 1e11 {
		return time.Unix(ms, 0).UTC(), true
	}
	return time.UnixMilli(ms).UTC(), true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// slug makes a class component out of a product or class name.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ', r == '_', r == '-', r == '.', r == '/':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

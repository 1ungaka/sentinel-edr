package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// SIEM sink profiles: one event model in, N wire formats out.
//
// Every profile here serializes the same internal object, sinkEvent, which is
// derived from the OCSF Detection Finding the `ocsf` format writes. There is
// no second mapping of engine results to findings: a file that is a finding
// in OCSF is exactly one event in every profile below, with the same uid,
// severity, techniques and digests. The per-SIEM differences are spelling
// (field names, escaping, framing), never content, and a conformance test
// round-trips one fixture per standard so a profile change cannot silently
// break ingestion.
//
//	ecs          Elastic Common Schema documents, NDJSON (OpenSearch Security
//	             Analytics, Security Onion, anything ECS-shaped)
//	cef          ArcSight Common Event Format, one event per line (OSSIM)
//	leef         IBM LEEF 2.0, one event per line (OSSIM, QRadar)
//	gelf         Graylog Extended Log Format 1.1, NDJSON
//	syslog       RFC 5424 frames with the finding as structured data
//	syslog-ecs   RFC 5424 frames whose MSG is the ECS document
//	syslog-cef   RFC 5424 frames whose MSG is the CEF event
//	syslog-leef  RFC 5424 frames whose MSG is the LEEF event
//	otlp         one OTLP/JSON ExportLogsServiceRequest (OpenTelemetry logs)
//
// Fidelity, stated per format: ECS, GELF and OTLP are JSON and carry file
// paths byte-exact. CEF, LEEF and RFC 5424 are line formats; a control
// character in an attacker-chosen path would forge a second event, so those
// profiles render control and bidi characters as visible escapes (the same
// rule the text reporter follows) after applying each format's own escaping.
// A consumer that needs the exact bytes reads a JSON profile.
const (
	// ECSVersion is the Elastic Common Schema version the ecs profile targets.
	ECSVersion = "8.11.0"
	// GELFVersion is the GELF payload specification version.
	GELFVersion = "1.1"
	// CEFVersion is the CEF header version.
	CEFVersion = "0"
	// LEEFVersion is the LEEF header version.
	LEEFVersion = "2.0"

	sinkVendor = "CAU"
	// sinkSlug is the machine name every profile uses where a standard wants
	// an identifier rather than a display name: the ECS module, dataset and
	// custom namespace, the OTLP service.name and attribute prefix, the CEF
	// and LEEF device product, the RFC 5424 APP-NAME. It is a constant, not
	// the configured tool name, so a rebranded display name can never rename
	// the fields a SIEM pipeline has already keyed on.
	sinkSlug = "cau"

	// syslogFacility is "security/authorization messages" (authpriv, 10): the
	// findings are security events and that is the facility a receiver's
	// default security pipeline keys on.
	syslogFacility = 10
	// syslogSDID is the structured-data identifier. RFC 5424 requires a
	// private enterprise number after the "@" for a non-IANA SD-ID; 32473 is
	// the number RFC 5612 reserves for documentation and examples, used here
	// because the project holds no registered PEN. It is a constant so that a
	// registration is a one-line change the conformance fixture then records.
	syslogSDID  = "cau@32473"
	syslogMsgID = "finding"
)

// sinkProfile names one wire format.
type sinkProfile int

const (
	profileECS sinkProfile = iota
	profileCEF
	profileLEEF
	profileGELF
	profileSyslog
	profileSyslogECS
	profileSyslogCEF
	profileSyslogLEEF
	profileOTLP
)

// sinkFormats maps the --format names to profiles, in documentation order.
var sinkFormats = []struct {
	name    string
	profile sinkProfile
}{
	{"ecs", profileECS},
	{"cef", profileCEF},
	{"leef", profileLEEF},
	{"gelf", profileGELF},
	{"syslog", profileSyslog},
	{"syslog-ecs", profileSyslogECS},
	{"syslog-cef", profileSyslogCEF},
	{"syslog-leef", profileSyslogLEEF},
	{"otlp", profileOTLP},
}

// SinkFormats lists the SIEM sink format names NewReporter accepts.
func SinkFormats() []string {
	out := make([]string, 0, len(sinkFormats))
	for _, f := range sinkFormats {
		out = append(out, f.name)
	}
	return out
}

func sinkProfileFor(format string) (sinkProfile, bool) {
	for _, f := range sinkFormats {
		if f.name == format {
			return f.profile, true
		}
	}
	return 0, false
}

// SinkReporter renders findings in one SIEM sink profile.
type SinkReporter struct {
	cfg     config
	profile sinkProfile
}

// NewSinkReporter builds a reporter for a sink format name from SinkFormats.
func NewSinkReporter(format string, opts ...Option) (*SinkReporter, error) {
	p, ok := sinkProfileFor(strings.ToLower(strings.TrimSpace(format)))
	if !ok {
		return nil, fmt.Errorf("unknown sink format %q (want one of %s)", format, strings.Join(SinkFormats(), ", "))
	}
	return &SinkReporter{cfg: buildConfig(opts), profile: p}, nil
}

// sinkEvent is the one internal event every sink profile serializes. It holds
// nothing the OCSF finding does not: it is that finding, flattened.
type sinkEvent struct {
	Time       time.Time
	UID        string
	Title      string
	Desc       string
	Verdict    string
	SeverityID int // OCSF severity_id: 3 Medium (suspicious), 4 High (malicious)
	Severity   string
	Confidence string

	Path   string
	Name   string
	Size   *int64
	MD5    string
	SHA1   string
	SHA256 string

	RuleName string
	RuleUID  string
	RuleDesc string

	TechniqueIDs   []string
	TechniqueNames []string
	Tactics        []string
	Malware        []string
	Detectors      []string

	Product string
	Version string
	Host    string

	// What a correlated incident names and a file finding never does (see
	// sinkEventFromMap). All three are empty for a file scan, so every
	// renderer below writes them only when present and a file finding's bytes
	// are unchanged by their existence.
	Peers     []string // dst_endpoint addresses, in first-seen order
	PIDs      []int64  // evidences[].process.pid, in first-seen order
	MoreFiles []string // paths of the file evidences after the first

	// Provenance is the file's package-manager provenance (unmapped.provenance
	// of the OCSF finding), nil for a run without --provenance. Every renderer
	// writes it only when present, so a finding without it is byte-identical
	// to one from before the field existed.
	Provenance *sinkProvenance
}

// sinkProvenance is the part of a provenance object the sink formats carry.
type sinkProvenance struct {
	Manager, Package, Version, State string
}

// String is the flat form for the line formats: "dpkg coreutils 9.4-3
// owned-intact", "dpkg unowned", "unknown".
func (p *sinkProvenance) String() string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	for _, s := range []string{p.Manager, p.Package, p.Version, p.State} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// object is the structured form for ECS.
func (p *sinkProvenance) object() map[string]any {
	m := map[string]any{"state": p.State}
	if p.Manager != "" {
		m["manager"] = p.Manager
	}
	if p.Package != "" {
		m["package"] = p.Package
	}
	if p.Version != "" {
		m["version"] = p.Version
	}
	return m
}

// host is the reporting host every event of a run carries: the configured
// name, else the machine's own.
func (r *SinkReporter) host() string {
	if r.cfg.hostname != "" {
		return r.cfg.hostname
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// events derives the sink events from the OCSF findings of the run.
func (r *SinkReporter) events(in Input) []sinkEvent {
	findings := (&OCSFReporter{cfg: r.cfg}).Build(in)
	host := r.host()
	out := make([]sinkEvent, 0, len(findings))
	for _, fi := range findings {
		out = append(out, sinkEventFrom(fi, host))
	}
	return out
}

func sinkEventFrom(fi ocsfFinding, host string) sinkEvent {
	e := sinkEvent{
		Time:       time.UnixMilli(fi.Time).UTC(),
		UID:        fi.FindingInfo.UID,
		Title:      fi.FindingInfo.Title,
		Desc:       fi.FindingInfo.Desc,
		SeverityID: fi.SeverityID,
		Severity:   fi.Severity,
		Confidence: fi.Confidence,
		RuleName:   fi.FindingInfo.Analytic.Name,
		RuleUID:    fi.FindingInfo.Analytic.UID,
		RuleDesc:   fi.FindingInfo.Analytic.Desc,
		Detectors:  append([]string(nil), fi.FindingInfo.Types...),
		Product:    fi.Metadata.Product.Name,
		Version:    fi.Metadata.Product.Version,
		Host:       host,
	}
	if v, ok := fi.Unmapped["verdict"].(string); ok {
		e.Verdict = v
	}
	if p, ok := fi.Unmapped["provenance"].(*Provenance); ok && p != nil {
		e.Provenance = &sinkProvenance{Manager: p.Manager, Package: p.Package, Version: p.Version, State: p.State}
	}
	if len(fi.Evidences) > 0 {
		f := fi.Evidences[0].File
		e.Path, e.Name, e.Size = f.Path, f.Name, f.Size
		for _, h := range f.Hashes {
			switch h.AlgorithmID {
			case 1:
				e.MD5 = h.Value
			case 2:
				e.SHA1 = h.Value
			case 3:
				e.SHA256 = h.Value
			}
		}
	}
	seenTactic := map[string]bool{}
	for _, a := range fi.FindingInfo.Attacks {
		e.TechniqueIDs = append(e.TechniqueIDs, a.Technique.UID)
		// Names stay index-aligned with ids, so an unnamed technique keeps an
		// empty slot rather than shifting its neighbours.
		e.TechniqueNames = append(e.TechniqueNames, a.Technique.Name)
		for _, t := range a.Tactics {
			if !seenTactic[t.Name] {
				seenTactic[t.Name] = true
				e.Tactics = append(e.Tactics, t.Name)
			}
		}
	}
	seenMalware := map[string]bool{}
	for _, m := range fi.Malware {
		if m.Name != "" && !seenMalware[m.Name] {
			seenMalware[m.Name] = true
			e.Malware = append(e.Malware, m.Name)
		}
	}
	return e
}

// ── OCSF maps in ─────────────────────────────────────────────────────────────
//
// The defend daemon's forward queue carries findings as OCSF Detection
// Finding maps (forward.OCSFIncident), not as a scan Input. RenderSinkBatch
// renders such maps in a sink format through the same sinkEvent and the same
// encoder a scan uses; the only code particular to it is the extraction below,
// and a test holds it byte-identical to SinkReporter for a scan's findings.

// maxSinkListItems bounds every list read out of one finding map (attacks,
// evidences, malware, detector types). A real finding holds a handful; the
// cap keeps one oversized map from producing an unbounded event.
const maxSinkListItems = 1024

// SinkBatch is the rendering of a batch of OCSF finding maps.
type SinkBatch struct {
	// Payload is the wire bytes: one line per rendered event, or the single
	// ExportLogsServiceRequest for otlp. It is what SinkReporter.Write emits
	// for the same events.
	Payload []byte
	// Rendered counts the events in Payload.
	Rendered int
	// Skipped holds the indexes (into the findings argument, ascending) of the
	// maps that are not a Detection Finding with a uid and so produced no
	// event. The n-th event of Payload is the n-th finding not listed here.
	Skipped []int
}

// RenderSinkBatch renders OCSF Detection Finding maps (as OCSFReporter and
// forward.OCSFIncident produce them, either as built or after a JSON
// round-trip) in a sink format from SinkFormats.
//
// A map that is not a Detection Finding (class_uid 2004) or has no
// finding_info.uid is skipped and listed in SinkBatch.Skipped: without a uid
// a SIEM cannot deduplicate the event, and neither producer emits one. Every
// other field is optional; a field of the wrong type is read as absent. The
// reporting host of an event is its own unmapped.agent_host when it states
// one, else WithHostname, else the machine's name. An event with no readable
// time is stamped with the reporter's clock.
func RenderSinkBatch(format string, findings []map[string]any, opts ...Option) (SinkBatch, error) {
	r, err := NewSinkReporter(format, opts...)
	if err != nil {
		return SinkBatch{}, err
	}
	host, now := r.host(), r.cfg.now().UTC()
	var b SinkBatch
	evs := make([]sinkEvent, 0, len(findings))
	for i, m := range findings {
		e, ok := sinkEventFromMap(m, host, now)
		if !ok {
			b.Skipped = append(b.Skipped, i)
			continue
		}
		evs = append(evs, e)
	}
	var buf bytes.Buffer
	if err := r.writeEvents(&buf, evs); err != nil {
		return SinkBatch{}, err
	}
	b.Payload, b.Rendered = buf.Bytes(), len(evs)
	return b, nil
}

// RenderSinkEvents is RenderSinkBatch for a caller that needs only the bytes
// and the number of events in them.
func RenderSinkEvents(format string, findings []map[string]any, opts ...Option) ([]byte, int, error) {
	b, err := RenderSinkBatch(format, findings, opts...)
	return b.Payload, b.Rendered, err
}

// The readers below take whatever a map holds. A finding built in process has
// Go-typed values (int, []string, []map[string]any); one that crossed JSON has
// float64 and []any. Both are accepted, and anything else reads as absent.

func mapObject(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m // nil when v is not an object; indexing a nil map is safe
}

func mapString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// mapInt reads an integer of any Go or JSON spelling. A float must be finite
// and whole; nothing is rounded into a value the producer did not write.
func mapInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float32:
		return floatInt(float64(n))
	case float64:
		return floatInt(n)
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func floatInt(f float64) (int64, bool) {
	// 2^63 is exactly representable; everything below it converts safely.
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || f < -(1<<63) || f >= 1<<63 {
		return 0, false
	}
	return int64(f), true
}

// mapList reads a list of any of the element types a finding uses, bounded to
// maxSinkListItems.
func mapList(v any) []any {
	var out []any
	switch l := v.(type) {
	case []any:
		out = l
	case []map[string]any:
		out = make([]any, 0, min(len(l), maxSinkListItems))
		for i := 0; i < len(l) && i < maxSinkListItems; i++ {
			out = append(out, l[i])
		}
	case []string:
		out = make([]any, 0, min(len(l), maxSinkListItems))
		for i := 0; i < len(l) && i < maxSinkListItems; i++ {
			out = append(out, l[i])
		}
	}
	if len(out) > maxSinkListItems {
		out = out[:maxSinkListItems]
	}
	return out
}

// sinkEventFromMap is sinkEventFrom for a finding held as a map. It reports
// false for a map that is not a Detection Finding with a uid.
func sinkEventFromMap(m map[string]any, host string, now time.Time) (sinkEvent, bool) {
	info := mapObject(m["finding_info"])
	uid := mapString(info, "uid")
	if class, ok := mapInt(m["class_uid"]); !ok || class != ocsfClassUID || uid == "" {
		return sinkEvent{}, false
	}
	analytic := mapObject(info["analytic"])
	product := mapObject(mapObject(m["metadata"])["product"])
	unmapped := mapObject(m["unmapped"])
	e := sinkEvent{
		Time:       now,
		UID:        uid,
		Title:      mapString(info, "title"),
		Desc:       mapString(info, "desc"),
		Verdict:    mapString(unmapped, "verdict"),
		Severity:   mapString(m, "severity"),
		Confidence: mapString(m, "confidence"),
		RuleName:   mapString(analytic, "name"),
		RuleUID:    mapString(analytic, "uid"),
		RuleDesc:   mapString(analytic, "desc"),
		Product:    mapString(product, "name"),
		Version:    mapString(product, "version"),
		Host:       host,
	}
	if ms, ok := mapInt(m["time"]); ok {
		e.Time = time.UnixMilli(ms).UTC()
	}
	// OCSF severity_id runs 0 (Unknown) to 6 (Fatal). 99 is "Other", which
	// names no tier, so it is left unset like any value outside the scale.
	if id, ok := mapInt(m["severity_id"]); ok && id >= 0 && id <= 6 {
		e.SeverityID = int(id)
	}
	if h := mapString(unmapped, "agent_host"); h != "" {
		e.Host = h
	}
	if p := mapObject(unmapped["provenance"]); p != nil {
		e.Provenance = &sinkProvenance{
			Manager: mapString(p, "manager"), Package: mapString(p, "package"),
			Version: mapString(p, "version"), State: mapString(p, "state"),
		}
	}
	for _, t := range mapList(info["types"]) {
		if s, ok := t.(string); ok {
			e.Detectors = append(e.Detectors, s)
		}
	}

	seenPeer := map[string]bool{}
	peer := func(v any) {
		ep := mapObject(v)
		addr := mapString(ep, "ip")
		if addr == "" {
			addr = mapString(ep, "hostname")
		}
		if addr != "" && !seenPeer[addr] {
			seenPeer[addr] = true
			e.Peers = append(e.Peers, addr)
		}
	}
	peer(m["dst_endpoint"])
	seenPID := map[int64]bool{}
	haveFile := false
	for _, ev := range mapList(m["evidences"]) {
		evidence := mapObject(ev)
		if f := mapObject(evidence["file"]); f != nil {
			if !haveFile {
				haveFile = true
				e.Path, e.Name = mapString(f, "path"), mapString(f, "name")
				if n, ok := mapInt(f["size"]); ok {
					e.Size = &n
				}
				for _, h := range mapList(f["hashes"]) {
					hash := mapObject(h)
					alg, _ := mapInt(hash["algorithm_id"])
					switch alg {
					case 1:
						e.MD5 = mapString(hash, "value")
					case 2:
						e.SHA1 = mapString(hash, "value")
					case 3:
						e.SHA256 = mapString(hash, "value")
					}
				}
			} else if p := mapString(f, "path"); p != "" {
				e.MoreFiles = append(e.MoreFiles, p)
			}
		}
		if pid, ok := mapInt(mapObject(evidence["process"])["pid"]); ok && !seenPID[pid] {
			seenPID[pid] = true
			e.PIDs = append(e.PIDs, pid)
		}
		peer(evidence["dst_endpoint"])
	}

	seenTactic := map[string]bool{}
	for _, a := range mapList(info["attacks"]) {
		atk := mapObject(a)
		tech := mapObject(atk["technique"])
		id := mapString(tech, "uid")
		if id == "" {
			continue
		}
		e.TechniqueIDs = append(e.TechniqueIDs, id)
		e.TechniqueNames = append(e.TechniqueNames, mapString(tech, "name"))
		for _, t := range mapList(atk["tactics"]) {
			if name := mapString(mapObject(t), "name"); name != "" && !seenTactic[name] {
				seenTactic[name] = true
				e.Tactics = append(e.Tactics, name)
			}
		}
	}
	seenMalware := map[string]bool{}
	for _, mw := range mapList(m["malware"]) {
		if name := mapString(mapObject(mw), "name"); name != "" && !seenMalware[name] {
			seenMalware[name] = true
			e.Malware = append(e.Malware, name)
		}
	}
	return e, true
}

// hasFile reports whether the event names a file. A scan's finding always
// does; a correlated incident may be about a process or a peer only.
func (e sinkEvent) hasFile() bool {
	return e.Path != "" || e.Name != "" || e.MD5 != "" || e.SHA1 != "" || e.SHA256 != ""
}

// peerIP reports whether a peer address is a plain IP, and whether it is
// IPv4. Standards type their address fields (ECS destination.ip, CEF dst), so
// a peer that is a host name or carries a zone goes to a name field instead.
func peerIP(addr string) (isIP, isV4 bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return false, false
	}
	return true, a.Unmap().Is4()
}

// onePeer is the peer of an event about exactly one conversation. With
// several peers no standard "destination" field is filled: naming one of them
// would make a SIEM rule act on an arbitrary choice.
func (e sinkEvent) onePeer() string {
	if len(e.Peers) == 1 {
		return e.Peers[0]
	}
	return ""
}

// splitPeers separates the peers into IP addresses and other names.
func (e sinkEvent) splitPeers() (ips, names []string) {
	for _, p := range e.Peers {
		if ok, _ := peerIP(p); ok {
			ips = append(ips, p)
		} else {
			names = append(names, p)
		}
	}
	return ips, names
}

// pidList is the process ids comma-joined, "" when there are none.
func (e sinkEvent) pidList() string {
	parts := make([]string, 0, len(e.PIDs))
	for _, p := range e.PIDs {
		parts = append(parts, strconv.FormatInt(p, 10))
	}
	return strings.Join(parts, ",")
}

// allFiles is every file path of an event that names more than one, nil
// otherwise (the one path already has its own field).
func (e sinkEvent) allFiles() []string {
	if len(e.MoreFiles) == 0 {
		return nil
	}
	return append([]string{e.Path}, e.MoreFiles...)
}

// Severity scales. The engine has two finding tiers; each standard gets the
// pair of values that means "high" and "medium" on its own scale. Critical is
// never claimed by a file scanner, in any format.
func (e sinkEvent) malicious() bool { return e.SeverityID >= 4 }

// cefSeverity is the 0-10 scale CEF and LEEF share (7-8 high, 4-6 medium).
func (e sinkEvent) cefSeverity() int {
	if e.malicious() {
		return 8
	}
	return 5
}

// syslogSeverity is the RFC 5424 / GELF level: 3 error, 4 warning.
func (e sinkEvent) syslogSeverity() int {
	if e.malicious() {
		return 3
	}
	return 4
}

// otlpSeverity is the OpenTelemetry SeverityNumber: 17 ERROR, 13 WARN.
func (e sinkEvent) otlpSeverity() (int, string) {
	if e.malicious() {
		return 17, "ERROR"
	}
	return 13, "WARN"
}

// Write renders the run's findings to w in the reporter's profile.
func (r *SinkReporter) Write(w io.Writer, in Input) error {
	return r.writeEvents(w, r.events(in))
}

// writeEvents is the one encoder of the package's sink formats. A scan's
// findings (Write) and findings that arrive as OCSF maps (RenderSinkBatch)
// both end here, so the two cannot spell an event differently.
func (r *SinkReporter) writeEvents(w io.Writer, evs []sinkEvent) error {
	bw := bufio.NewWriter(w)
	var err error
	switch r.profile {
	case profileOTLP:
		err = writeJSONLine(bw, otlpRequest(evs), r.cfg.indent)
	default:
		for _, e := range evs {
			var line string
			line, err = r.renderLine(e)
			if err != nil {
				break
			}
			bw.WriteString(line)
			bw.WriteByte('\n')
		}
	}
	if err != nil {
		return fmt.Errorf("report: encode sink: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("report: write sink: %w", err)
	}
	return nil
}

// renderLine renders one event as one line (no trailing newline) for every
// line-framed profile.
func (r *SinkReporter) renderLine(e sinkEvent) (string, error) {
	switch r.profile {
	case profileECS:
		return jsonLine(ecsDocument(e))
	case profileGELF:
		return jsonLine(gelfMessage(e))
	case profileCEF:
		return cefEvent(e), nil
	case profileLEEF:
		return leefEvent(e), nil
	case profileSyslog:
		return syslogFrame(e, syslogStructuredData(e), syslogText(e.Title)), nil
	case profileSyslogECS:
		msg, err := jsonLine(ecsDocument(e))
		if err != nil {
			return "", err
		}
		return syslogFrame(e, "-", msg), nil
	case profileSyslogCEF:
		return syslogFrame(e, "-", cefEvent(e)), nil
	case profileSyslogLEEF:
		// LEEF separates attributes with a tab, which a syslog relay may
		// rewrite; the frame keeps it because the LEEF header declares it.
		return syslogFrame(e, "-", leefEvent(e)), nil
	}
	return "", fmt.Errorf("unhandled sink profile %d", r.profile)
}

func jsonLine(v any) (string, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return displaySafeJSON(strings.TrimRight(sb.String(), "\n")), nil
}

func writeJSONLine(w io.Writer, v any, indent bool) error {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(true)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := io.WriteString(w, displaySafeJSON(sb.String()))
	return err
}

// displaySafeJSON rewrites the display-altering characters encoding/json
// leaves raw (bidi controls and the other non-ASCII format characters) as
// \uXXXX escapes. The decoded value is unchanged, byte for byte; what changes
// is that a sink stream shown in a terminal or a log viewer cannot be
// reordered by a file name. Such characters only occur inside JSON strings,
// and all of them are in the Basic Multilingual Plane, so a plain four-digit
// escape is always correct.
func displaySafeJSON(s string) string {
	if strings.IndexFunc(s, displayUnsafe) < 0 {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s) + 16)
	for _, r := range s {
		if displayUnsafe(r) {
			fmt.Fprintf(&sb, `\u%04x`, r)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// displayUnsafe is unsafeRune restricted to what encoding/json leaves raw:
// the JSON whitespace between tokens of an indented document must stay.
func displayUnsafe(r rune) bool { return r >= 0x7f && r <= 0xffff && unsafeRune(r) }

// ── ECS ──────────────────────────────────────────────────────────────────────

// ecsDocument maps a finding onto Elastic Common Schema fields. Engine-native
// detail with no ECS home lives under the "cau" object, which is the custom
// top-level namespace ECS reserves for a product.
//
// An incident's extras: one peer is destination.address (and destination.ip
// when it is an IP, the only thing that field's type accepts); every peer is
// in related.ip or related.hosts; one process is process.pid and several are
// cau.pids; several files are cau.files. An event that names no file is
// categorised intrusion_detection rather than malware and has no file object.
func ecsDocument(e sinkEvent) map[string]any {
	ts := e.Time.Format("2006-01-02T15:04:05.000Z07:00")
	file := map[string]any{"path": e.Path, "name": e.Name}
	if e.Size != nil {
		file["size"] = *e.Size
	}
	hash := map[string]any{}
	if e.MD5 != "" {
		hash["md5"] = e.MD5
	}
	if e.SHA1 != "" {
		hash["sha1"] = e.SHA1
	}
	if e.SHA256 != "" {
		hash["sha256"] = e.SHA256
	}
	if len(hash) > 0 {
		file["hash"] = hash
	}
	rule := map[string]any{"name": e.RuleName, "ruleset": sinkSlug}
	if e.RuleUID != "" {
		rule["id"] = e.RuleUID
	}
	if e.RuleDesc != "" {
		rule["description"] = e.RuleDesc
	}
	native := map[string]any{"verdict": e.Verdict, "detectors": nonNil(e.Detectors)}
	if e.Confidence != "" {
		native["confidence"] = strings.ToLower(e.Confidence)
	}
	if len(e.Malware) > 0 {
		native["malware"] = e.Malware
	}
	if files := e.allFiles(); files != nil {
		native["files"] = files
	}
	if len(e.PIDs) > 1 {
		native["pids"] = e.PIDs
	}
	if e.Provenance != nil {
		native["provenance"] = e.Provenance.object()
	}
	category := "malware"
	if !e.hasFile() {
		category = "intrusion_detection"
	}
	doc := map[string]any{
		"@timestamp": ts,
		"ecs":        map[string]any{"version": ECSVersion},
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{category},
			"type":     []string{"info"},
			"module":   sinkSlug,
			"dataset":  sinkSlug + ".finding",
			"provider": sinkSlug,
			"id":       e.UID,
			"severity": e.cefSeverity(),
			"reason":   e.Desc,
			"created":  ts,
		},
		"message":  e.Title,
		"rule":     rule,
		"observer": map[string]any{"vendor": sinkVendor, "product": e.Product, "version": e.Version, "type": "edr"},
		sinkSlug:   native,
	}
	if e.hasFile() {
		doc["file"] = file
	}
	if e.Host != "" {
		doc["host"] = map[string]any{"name": e.Host}
	}
	if p := e.onePeer(); p != "" {
		dst := map[string]any{"address": p}
		if isIP, _ := peerIP(p); isIP {
			dst["ip"] = p
		}
		doc["destination"] = dst
	}
	if ips, names := e.splitPeers(); len(ips)+len(names) > 0 {
		related := map[string]any{}
		if len(ips) > 0 {
			related["ip"] = ips
		}
		if len(names) > 0 {
			related["hosts"] = names
		}
		doc["related"] = related
	}
	if len(e.PIDs) == 1 {
		doc["process"] = map[string]any{"pid": e.PIDs[0]}
	}
	if len(e.TechniqueIDs) > 0 {
		threat := map[string]any{
			"framework": "MITRE ATT&CK",
			"technique": map[string]any{"id": e.TechniqueIDs, "name": e.TechniqueNames},
		}
		if len(e.Tactics) > 0 {
			threat["tactic"] = map[string]any{"name": e.Tactics}
		}
		doc["threat"] = threat
	}
	return doc
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ── GELF ─────────────────────────────────────────────────────────────────────

// gelfMessage builds a GELF 1.1 payload. Additional fields carry the leading
// underscore the specification requires and are strings or numbers only;
// lists are comma-joined. "_id" is reserved by the specification and unused.
//
// An incident's extras: _destination_ip for one IP peer, _peers otherwise;
// _pids (always a string, so the field keeps one type however many there
// are); _files when the event names more than one.
func gelfMessage(e sinkEvent) map[string]any {
	host := e.Host
	if host == "" {
		host = "unknown" // GELF requires a non-empty host
	}
	m := map[string]any{
		"version":          GELFVersion,
		"host":             host,
		"short_message":    e.Title,
		"timestamp":        float64(e.Time.UnixMilli()) / 1000,
		"level":            e.syslogSeverity(),
		"_event_uid":       e.UID,
		"_verdict":         e.Verdict,
		"_severity":        e.Severity,
		"_rule_name":       e.RuleName,
		"_detectors":       strings.Join(e.Detectors, ","),
		"_product":         e.Product,
		"_product_version": e.Version,
	}
	if e.Desc != "" {
		m["full_message"] = e.Desc
	}
	if e.Size != nil {
		m["_file_size"] = *e.Size
	}
	setIf := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	if e.hasFile() {
		m["_file_path"], m["_file_name"] = e.Path, e.Name
	}
	setIf("_file_md5", e.MD5)
	setIf("_file_sha1", e.SHA1)
	setIf("_file_sha256", e.SHA256)
	setIf("_rule_id", e.RuleUID)
	setIf("_confidence", strings.ToLower(e.Confidence))
	setIf("_attack_techniques", strings.Join(e.TechniqueIDs, ","))
	setIf("_attack_tactics", strings.Join(e.Tactics, ","))
	setIf("_malware", strings.Join(e.Malware, ","))
	if isIP, _ := peerIP(e.onePeer()); isIP {
		m["_destination_ip"] = e.onePeer()
	} else {
		setIf("_peers", strings.Join(e.Peers, ","))
	}
	setIf("_pids", e.pidList())
	setIf("_files", strings.Join(e.allFiles(), ","))
	setIf("_provenance", e.Provenance.String())
	return m
}

// ── CEF ──────────────────────────────────────────────────────────────────────

// cefEvent renders one CEF:0 event:
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// Extension keys are from the CEF dictionary; the six custom-string slots
// carry what the dictionary has no key for, each with its label.
//
// An incident's extras use dictionary keys too: one peer is dst (IPv4), the
// IPv6 custom address c6a3 or dhost (a name); several peers are flexString1.
// The process the incident was seen in is the source of the activity, so one
// pid is spid and several are flexString2. The dictionary has no slot left
// for a second file path: CEF carries only the first.
func cefEvent(e sinkEvent) string {
	sig := e.RuleUID
	if sig == "" {
		sig = e.RuleName
	}
	var sb strings.Builder
	sb.WriteString("CEF:" + CEFVersion)
	for _, h := range []string{sinkVendor, sinkSlug, e.Version, sig, e.Title, strconv.Itoa(e.cefSeverity())} {
		sb.WriteByte('|')
		sb.WriteString(cefHeader(h))
	}
	sb.WriteByte('|')
	first := true
	ext := func(k, v string) {
		if v == "" {
			return
		}
		if !first {
			sb.WriteByte(' ')
		}
		first = false
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(cefValue(v))
	}
	ext("rt", strconv.FormatInt(e.Time.UnixMilli(), 10))
	ext("dvchost", e.Host)
	ext("cat", e.Verdict)
	ext("externalId", e.UID)
	ext("filePath", e.Path)
	ext("fname", e.Name)
	if e.Size != nil {
		ext("fsize", strconv.FormatInt(*e.Size, 10))
	}
	ext("fileHash", e.SHA256)
	ext("msg", e.Desc)
	custom := func(n int, label, v string) {
		if v == "" {
			return
		}
		ext(fmt.Sprintf("cs%d", n), v)
		ext(fmt.Sprintf("cs%dLabel", n), label)
	}
	custom(1, "attackTechniques", strings.Join(e.TechniqueIDs, ","))
	custom(2, "detectors", strings.Join(e.Detectors, ","))
	custom(3, "malware", strings.Join(e.Malware, ","))
	custom(4, "confidence", strings.ToLower(e.Confidence))
	custom(5, "fileHashSha1", e.SHA1)
	custom(6, "fileHashMd5", e.MD5)
	if p := e.onePeer(); p != "" {
		switch isIP, isV4 := peerIP(p); {
		case isV4:
			ext("dst", p)
		case isIP:
			ext("c6a3", p)
			ext("c6a3Label", "Destination IPv6 Address")
		default:
			ext("dhost", p)
		}
	} else if len(e.Peers) > 1 {
		ext("flexString1", strings.Join(e.Peers, ","))
		ext("flexString1Label", "destinationAddresses")
	}
	if len(e.PIDs) == 1 {
		ext("spid", e.pidList())
	} else if len(e.PIDs) > 1 {
		ext("flexString2", e.pidList())
		ext("flexString2Label", "processIds")
	}
	// The six custom strings are taken; provenance (a file finding's field,
	// which never has several peers) rides in flexString1 when that is free.
	if e.Provenance != nil && len(e.Peers) <= 1 {
		ext("flexString1", e.Provenance.String())
		ext("flexString1Label", "provenance")
	}
	return sb.String()
}

// cefHeader escapes a header field: backslash and pipe are escaped, and
// anything that would break the line is shown as a visible escape.
func cefHeader(s string) string {
	return escapeLine(s, func(r rune) (string, bool) {
		switch r {
		case '\\':
			return `\\`, true
		case '|':
			return `\|`, true
		}
		return "", false
	})
}

// cefValue escapes an extension value: backslash and equals are escaped and a
// newline is written as the two characters the specification defines.
func cefValue(s string) string {
	return escapeLine(s, func(r rune) (string, bool) {
		switch r {
		case '\\':
			return `\\`, true
		case '=':
			return `\=`, true
		case '\n':
			return `\n`, true
		case '\r':
			return `\r`, true
		}
		return "", false
	})
}

// escapeLine applies a format's own escapes (special) and renders every other
// control, bidi or invalid-UTF-8 character as a visible escape. The visible
// escape's backslash is itself passed through special, so a consumer that
// unescapes the field reads the same visible text TermSafe would print.
func escapeLine(s string, special func(rune) (string, bool)) string {
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	emit := func(visible string) {
		for _, r := range visible {
			if rep, ok := special(r); ok {
				sb.WriteString(rep)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			emit(fmt.Sprintf(`\x%02x`, s[i]))
			i += n
			continue
		}
		if rep, ok := special(r); ok {
			sb.WriteString(rep)
		} else if unsafeRune(r) {
			emit(TermSafe(string(r)))
		} else {
			sb.WriteRune(r)
		}
		i += n
	}
	return sb.String()
}

// ── LEEF ─────────────────────────────────────────────────────────────────────

// leefEvent renders one LEEF 2.0 event:
//
//	LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|key=value<TAB>key=value
//
// LEEF defines no escape for its header separator or its attribute delimiter,
// so a pipe in a header field becomes "/" and a tab inside a value is shown
// as the visible escape `\t`: lossy by the format's own limits, and stated.
func leefEvent(e sinkEvent) string {
	id := e.RuleUID
	if id == "" {
		id = e.RuleName
	}
	var sb strings.Builder
	sb.WriteString("LEEF:" + LEEFVersion)
	for _, h := range []string{sinkVendor, sinkSlug, e.Version, id} {
		sb.WriteByte('|')
		sb.WriteString(leefHeader(h))
	}
	sb.WriteString("|0x09|")
	first := true
	attr := func(k, v string) {
		if v == "" {
			return
		}
		if !first {
			sb.WriteByte('\t')
		}
		first = false
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(TermSafe(v))
	}
	attr("devTime", strconv.FormatInt(e.Time.UnixMilli(), 10))
	attr("sev", strconv.Itoa(e.cefSeverity()))
	attr("cat", e.Verdict)
	attr("resource", e.Host)
	attr("externalId", e.UID)
	attr("filePath", e.Path)
	attr("fileName", e.Name)
	if e.Size != nil {
		attr("fileSize", strconv.FormatInt(*e.Size, 10))
	}
	attr("fileHash", e.SHA256)
	attr("fileHashSha1", e.SHA1)
	attr("fileHashMd5", e.MD5)
	attr("ruleName", e.RuleName)
	attr("msg", e.Title)
	attr("reason", e.Desc)
	attr("attackTechniques", strings.Join(e.TechniqueIDs, ","))
	attr("detectors", strings.Join(e.Detectors, ","))
	attr("malware", strings.Join(e.Malware, ","))
	attr("confidence", strings.ToLower(e.Confidence))
	// An incident's extras: dst is LEEF's own key and takes one IP; the rest
	// are custom attributes, which LEEF allows freely.
	if isIP, _ := peerIP(e.onePeer()); isIP {
		attr("dst", e.onePeer())
	} else {
		attr("peers", strings.Join(e.Peers, ","))
	}
	attr("pids", e.pidList())
	attr("files", strings.Join(e.allFiles(), ","))
	attr("provenance", e.Provenance.String())
	return sb.String()
}

func leefHeader(s string) string {
	return strings.ReplaceAll(TermSafe(s), "|", "/")
}

// ── RFC 5424 syslog ──────────────────────────────────────────────────────────

// syslogFrame renders one RFC 5424 message:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
//
// No transport framing is added: one frame per line suits a file, a pipe and
// a UDP datagram, and RFC 6587 octet counting is the forwarder's job.
func syslogFrame(e sinkEvent, sd, msg string) string {
	pri := syslogFacility*8 + e.syslogSeverity()
	ts := e.Time.Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		pri, ts, syslogHeaderField(e.Host, 255), sinkSlug, syslogMsgID, sd, msg)
}

// syslogHeaderField constrains a header field to PRINTUSASCII without spaces,
// bounded to the field's maximum length; an empty field is the NILVALUE.
func syslogHeaderField(s string, max int) string {
	var sb strings.Builder
	for i := 0; i < len(s) && sb.Len() < max; i++ {
		if c := s[i]; c > 32 && c < 127 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	if sb.Len() == 0 {
		return "-"
	}
	return sb.String()
}

// syslogStructuredData renders the finding as one SD-ELEMENT.
func syslogStructuredData(e sinkEvent) string {
	var sb strings.Builder
	sb.WriteString("[" + syslogSDID)
	param := func(k, v string) {
		if v == "" {
			return
		}
		sb.WriteByte(' ')
		sb.WriteString(k)
		sb.WriteString(`="`)
		sb.WriteString(syslogParamValue(v))
		sb.WriteByte('"')
	}
	param("uid", e.UID)
	param("verdict", e.Verdict)
	param("severity", e.Severity)
	param("confidence", strings.ToLower(e.Confidence))
	param("filePath", e.Path)
	param("fileName", e.Name)
	if e.Size != nil {
		param("fileSize", strconv.FormatInt(*e.Size, 10))
	}
	param("sha256", e.SHA256)
	param("sha1", e.SHA1)
	param("md5", e.MD5)
	param("ruleName", e.RuleName)
	param("ruleId", e.RuleUID)
	param("attackTechniques", strings.Join(e.TechniqueIDs, ","))
	param("attackTactics", strings.Join(e.Tactics, ","))
	param("detectors", strings.Join(e.Detectors, ","))
	param("malware", strings.Join(e.Malware, ","))
	param("product", e.Product)
	param("productVersion", e.Version)
	// An incident's extras, under the same names the LEEF profile uses.
	if isIP, _ := peerIP(e.onePeer()); isIP {
		param("dst", e.onePeer())
	} else {
		param("peers", strings.Join(e.Peers, ","))
	}
	param("pids", e.pidList())
	param("files", strings.Join(e.allFiles(), ","))
	param("provenance", e.Provenance.String())
	sb.WriteByte(']')
	return sb.String()
}

// syslogParamValue escapes a PARAM-VALUE: the three characters RFC 5424
// names (quote, backslash, closing bracket), with line-breaking characters
// shown as visible escapes first.
func syslogParamValue(s string) string {
	return escapeLine(s, func(r rune) (string, bool) {
		switch r {
		case '"':
			return `\"`, true
		case '\\':
			return `\\`, true
		case ']':
			return `\]`, true
		}
		return "", false
	})
}

// syslogText renders free text for the MSG part of a native frame.
func syslogText(s string) string { return TermSafe(s) }

// ── OTLP ─────────────────────────────────────────────────────────────────────

// otlpRequest builds an OTLP/JSON ExportLogsServiceRequest holding one
// LogRecord per finding. Per the OTLP JSON mapping, 64-bit integers are
// strings and enum values are numbers. Attribute names follow the ECS-aligned
// dotted names the ecs profile uses, so one query vocabulary serves both.
func otlpRequest(evs []sinkEvent) map[string]any {
	if len(evs) == 0 {
		return map[string]any{"resourceLogs": []any{}}
	}
	first := evs[0]
	records := make([]any, 0, len(evs))
	for _, e := range evs {
		num, text := e.otlpSeverity()
		ns := strconv.FormatInt(e.Time.UnixNano(), 10)
		attrs := []any{
			otlpString("event.name", sinkSlug+".finding"),
			otlpString("event.id", e.UID),
		}
		if e.hasFile() {
			attrs = append(attrs, otlpString("file.path", e.Path), otlpString("file.name", e.Name))
		}
		attrs = append(attrs,
			otlpString("rule.name", e.RuleName),
			otlpString(sinkSlug+".verdict", e.Verdict),
			otlpStrings(sinkSlug+".detectors", e.Detectors),
		)
		add := func(k, v string) {
			if v != "" {
				attrs = append(attrs, otlpString(k, v))
			}
		}
		if e.Size != nil {
			attrs = append(attrs, otlpInt("file.size", *e.Size))
		}
		add("file.hash.md5", e.MD5)
		add("file.hash.sha1", e.SHA1)
		add("file.hash.sha256", e.SHA256)
		add("rule.id", e.RuleUID)
		add("event.reason", e.Desc)
		add(sinkSlug+".confidence", strings.ToLower(e.Confidence))
		if len(e.TechniqueIDs) > 0 {
			attrs = append(attrs, otlpStrings("threat.technique.id", e.TechniqueIDs))
		}
		if len(e.Tactics) > 0 {
			attrs = append(attrs, otlpStrings("threat.tactic.name", e.Tactics))
		}
		if len(e.Malware) > 0 {
			attrs = append(attrs, otlpStrings(sinkSlug+".malware", e.Malware))
		}
		// An incident's extras, under the names the ecs profile gives them.
		if p := e.onePeer(); p != "" {
			add("destination.address", p)
			if isIP, _ := peerIP(p); isIP {
				add("destination.ip", p)
			}
		}
		if ips, names := e.splitPeers(); len(ips)+len(names) > 0 {
			if len(ips) > 0 {
				attrs = append(attrs, otlpStrings("related.ip", ips))
			}
			if len(names) > 0 {
				attrs = append(attrs, otlpStrings("related.hosts", names))
			}
		}
		if len(e.PIDs) == 1 {
			attrs = append(attrs, otlpInt("process.pid", e.PIDs[0]))
		} else if len(e.PIDs) > 1 {
			values := make([]any, 0, len(e.PIDs))
			for _, p := range e.PIDs {
				values = append(values, map[string]any{"intValue": strconv.FormatInt(p, 10)})
			}
			attrs = append(attrs, map[string]any{"key": sinkSlug + ".pids", "value": map[string]any{"arrayValue": map[string]any{"values": values}}})
		}
		if files := e.allFiles(); files != nil {
			attrs = append(attrs, otlpStrings(sinkSlug+".files", files))
		}
		add(sinkSlug+".provenance", e.Provenance.String())
		records = append(records, map[string]any{
			"timeUnixNano":         ns,
			"observedTimeUnixNano": ns,
			"severityNumber":       num,
			"severityText":         text,
			"body":                 map[string]any{"stringValue": e.Title},
			"attributes":           attrs,
		})
	}
	resource := []any{
		otlpString("service.name", sinkSlug),
		otlpString("service.version", first.Version),
	}
	if first.Host != "" {
		resource = append(resource, otlpString("host.name", first.Host))
	}
	return map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": resource},
			"scopeLogs": []any{map[string]any{
				"scope":      map[string]any{"name": sinkSlug, "version": first.Version},
				"logRecords": records,
			}},
		}},
	}
}

func otlpString(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

// otlpInt is an intValue attribute; OTLP/JSON spells a 64-bit integer as a
// decimal string.
func otlpInt(k string, v int64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"intValue": strconv.FormatInt(v, 10)}}
}

func otlpStrings(k string, vs []string) map[string]any {
	values := make([]any, 0, len(vs))
	for _, v := range vs {
		values = append(values, map[string]any{"stringValue": v})
	}
	return map[string]any{"key": k, "value": map[string]any{"arrayValue": map[string]any{"values": values}}}
}

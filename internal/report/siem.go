package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
}

// events derives the sink events from the OCSF findings of the run.
func (r *SinkReporter) events(in Input) []sinkEvent {
	findings := (&OCSFReporter{cfg: r.cfg}).Build(in)
	host := r.cfg.hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		}
	}
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
	evs := r.events(in)
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
	doc := map[string]any{
		"@timestamp": ts,
		"ecs":        map[string]any{"version": ECSVersion},
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"malware"},
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
		"file":     file,
		"rule":     rule,
		"observer": map[string]any{"vendor": sinkVendor, "product": e.Product, "version": e.Version, "type": "edr"},
		sinkSlug:   native,
	}
	if e.Host != "" {
		doc["host"] = map[string]any{"name": e.Host}
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
		"_file_path":       e.Path,
		"_file_name":       e.Name,
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
	setIf("_file_md5", e.MD5)
	setIf("_file_sha1", e.SHA1)
	setIf("_file_sha256", e.SHA256)
	setIf("_rule_id", e.RuleUID)
	setIf("_confidence", strings.ToLower(e.Confidence))
	setIf("_attack_techniques", strings.Join(e.TechniqueIDs, ","))
	setIf("_attack_tactics", strings.Join(e.Tactics, ","))
	setIf("_malware", strings.Join(e.Malware, ","))
	return m
}

// ── CEF ──────────────────────────────────────────────────────────────────────

// cefEvent renders one CEF:0 event:
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// Extension keys are from the CEF dictionary; the six custom-string slots
// carry what the dictionary has no key for, each with its label.
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
			otlpString("file.path", e.Path),
			otlpString("file.name", e.Name),
			otlpString("rule.name", e.RuleName),
			otlpString(sinkSlug+".verdict", e.Verdict),
			otlpStrings(sinkSlug+".detectors", e.Detectors),
		}
		add := func(k, v string) {
			if v != "" {
				attrs = append(attrs, otlpString(k, v))
			}
		}
		if e.Size != nil {
			attrs = append(attrs, map[string]any{"key": "file.size", "value": map[string]any{"intValue": strconv.FormatInt(*e.Size, 10)}})
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

func otlpStrings(k string, vs []string) map[string]any {
	values := make([]any, 0, len(vs))
	for _, v := range vs {
		values = append(values, map[string]any{"stringValue": v})
	}
	return map[string]any{"key": k, "value": map[string]any{"arrayValue": map[string]any{"values": values}}}
}

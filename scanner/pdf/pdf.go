// Package pdf detects malicious-document tradecraft in PDF files from the public
// PDF structure alone — a weaponised PDF is a common initial-access and user-
// execution vector (phishing lures whose document auto-runs JavaScript, launches
// an external program, or carries an embedded payload).
//
// It is DETECTION ONLY. Nothing here creates, weaponises or executes a PDF; the
// signal is derived entirely from the public file structure and from published
// abuse tradecraft, read out of the bytes a scanner already has.
//
// A PDF is a sequence of indirect objects with a cross-reference table, but a
// full parse is unnecessary (and, on adversarial files, dangerous). This detector
// is a bounded, robust lexical + shallow-structural scan — the tool most PDF
// malware detectors actually use. It never recurses, caps the amount of data it
// reads, caps the number of name tokens it processes, and returns a partial
// result with a warning rather than panicking or hanging on truncated or
// adversarial input. Findings carry small additive weights, chosen so that a
// single benign signal (a lone /URI link) cannot cross the default threshold
// while a clear malicious combination (auto-run plus embedded JavaScript) does.
package pdf

import (
	"bytes"
	"os"
)

// ── ATT&CK technique ids ───────────────────────────────────────────────────────

const (
	techUserExec    = "T1204.002" // User Execution: Malicious File (OpenAction/AA, EmbeddedFile)
	techMalLink     = "T1204.001" // User Execution: Malicious Link (URI)
	techInterp      = "T1059"     // Command and Scripting Interpreter (Launch an external program)
	techJS          = "T1059.007" // ... JavaScript (embedded JavaScript)
	techIngress     = "T1105"     // Ingress Tool Transfer (remote fetch: GoToR / SubmitForm)
	techObfuscation = "T1027"     // Obfuscated Files or Information (name #xx escapes, JS exploit primitives, encryption evasion)
)

// ── finding weights ────────────────────────────────────────────────────────────
//
// The scale mirrors the sibling lnk/ole detectors (DefaultThreshold 8). Weights
// are deliberately small and additive so that no single rule crosses the
// threshold on its own — the document must combine signals the way real malicious
// PDFs do. Worked examples (all reach or pass 8):
//
//	/OpenAction + /JavaScript              = 4 + 4 = 8   (canonical auto-run-JS dropper)
//	/OpenAction + /Launch                  = 4 + 4 = 8   (auto-launch external program)
//	/J#61vaScript (hex-obfuscated) + JS    = 4 + 4 = 8   (name obfuscation + embedded JS)
//	/OpenAction + JS + exploit primitives  = 4 + 4 + 2 = 10
//
// while a lone benign tell stays well below:
//
//	a PDF that merely carries a /URI link  = 1
//	a PDF that merely embeds a file        = 3
//	a plain one-page PDF                    = 0
const (
	weightAutoAction  = 4 // /OpenAction or /AA — code that runs on open
	weightJavaScript  = 4 // /JavaScript or /JS — embedded JavaScript
	weightLaunch      = 4 // /Launch — launch an external program
	weightEmbedded    = 3 // /EmbeddedFile (or /EF) — embedded-payload carrier
	weightRemote      = 2 // /SubmitForm or /GoToR — remote fetch
	weightURI         = 1 // /URI — network callout / link (low: common in benign PDFs)
	weightNameObf     = 4 // a sensitive /Name spelled with #xx hex escapes (strong intent)
	weightJSHeuristic = 2 // exploitation / obfuscation primitives inside embedded JS
	weightEncEvasion  = 1 // encrypted + auto-run-JS (known evasion; tiny amplifier only)
)

// DefaultThreshold is the shipped score at which a document is reported
// suspicious. A clear auto-run-plus-execution combination crosses it; a single
// benign structural tell does not.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can be
// retuned without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory. Ordinary PDFs
// are well under this; anything far larger is handled by the size cap rather than
// loaded whole.
const DefaultMaxSize int64 = 16 << 20

// Detector work caps. These bound the scan regardless of how adversarial the
// bytes are, so a pathological file cannot make the work quadratic or unbounded.
const (
	headerWindow        = 1024     // bytes searched for the %PDF- header
	maxScanBytes        = 64 << 20 // most bytes any one Analyze will lex
	maxNameLen          = 256      // longest /Name token decoded
	maxNames            = 4096     // distinct generic names remembered
	maxNameTokens       = 200000   // /Name tokens processed before giving up
	maxJSHeuristicBytes = 16 << 20 // region scanned for JS exploit primitives
	heapSprayCount      = 8        // "%u" occurrences treated as a heap-spray tell
	longHexRun          = 16       // "\x" escape occurrences treated as embedded shellcode
)

// Options configure a scan. The zero value uses the package defaults.
type Options struct {
	Threshold int
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one detection signal raised against a document.
type Finding struct {
	// Class is a stable identifier ("pdf.action.openaction").
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	// Evidence is a short excerpt of the triggering token; it never carries a
	// large blob.
	Evidence string `json:"evidence,omitempty"`
}

// Parsed is a compact summary of the document's structure, useful to a caller
// without exposing a full parse tree.
type Parsed struct {
	Version       string `json:"version,omitempty"`
	Objects       int    `json:"objects"`
	Streams       int    `json:"streams"`
	HasOpenAction bool   `json:"has_open_action"`
	HasJavaScript bool   `json:"has_javascript"`
	Encrypted     bool   `json:"encrypted"`
	Warning       string `json:"warning,omitempty"`
}

// Result is the outcome for one file.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	Parsed    *Parsed   `json:"parsed,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
}

// EffectiveThreshold returns the threshold applied to this result.
func (r *Result) EffectiveThreshold() int {
	if r == nil {
		return Threshold
	}
	if r.Threshold > 0 {
		return r.Threshold
	}
	return Threshold
}

// Detected reports whether the score reached the threshold.
func (r *Result) Detected() bool {
	return r != nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// IsPDF reports whether the %PDF- signature appears within the first 1024 bytes.
// The spec allows arbitrary leading bytes before the header, so the signature is
// searched for rather than required at offset 0.
func IsPDF(data []byte) bool {
	window := data
	if len(window) > headerWindow {
		window = window[:headerWindow]
	}
	return bytes.Contains(window, []byte("%PDF-"))
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a PDF
// gets an immediate zero-score result; otherwise the file is lexed defensively
// (bounded) and the detection rules are summed into Result.Score.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsPDF(data) {
		return r
	}
	scan := data
	warning := ""
	if len(scan) > maxScanBytes {
		scan = scan[:maxScanBytes]
		warning = "scan truncated at " + itoa(maxScanBytes>>20) + " MiB cap"
	}
	d := parse(scan, warning)
	r.Findings = d.detect()
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	r.Parsed = d.summary()
	return r
}

// ScanFile reads a file (subject to the size cap) and analyses it. A file over
// the cap, or one that cannot be read, is reported Skipped, never an error.
func ScanFile(path string, opts Options) *Result {
	fi, err := os.Stat(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "stat: " + err.Error()}
	}
	if fi.Size() > DefaultMaxSize {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "file over the in-memory size limit"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── lexical scan ─────────────────────────────────────────────────────────────

// doc holds what the detector reasons about. Unexported; callers see the Parsed
// summary instead.
type doc struct {
	data      []byte          // the capped scan slice
	version   string          // from the %PDF- header
	objects   int             // count of "N G obj" definitions
	streams   int             // count of stream ... endstream bodies
	names     map[string]bool // de-obfuscated /Name tokens present
	hexObf    map[string]bool // sensitive names that used #xx hex escapes
	encrypted bool            // /Encrypt present
	warning   string
}

func (d *doc) warn(msg string) {
	if d.warning == "" {
		d.warning = msg
	}
}

// parse runs the bounded lexical scan over data (already capped by Analyze).
func parse(scan []byte, warning string) *doc {
	d := &doc{
		data:    scan,
		names:   make(map[string]bool),
		hexObf:  make(map[string]bool),
		warning: warning,
	}
	d.version = parseVersion(scan)
	d.scanNames()
	d.objects = countObjects(scan)
	d.streams = countStreams(scan)
	d.encrypted = d.names["Encrypt"]
	return d
}

// parseVersion extracts the version string that follows the %PDF- header.
func parseVersion(data []byte) string {
	window := data
	if len(window) > headerWindow {
		window = window[:headerWindow]
	}
	idx := bytes.Index(window, []byte("%PDF-"))
	if idx < 0 {
		return ""
	}
	i := idx + 5
	var b []byte
	for i < len(data) && len(b) < 8 {
		c := data[i]
		if isDigit(c) || c == '.' {
			b = append(b, c)
			i++
			continue
		}
		break
	}
	return string(b)
}

// scanNames walks the buffer once, decoding every /Name token (resolving #xx hex
// escapes to their canonical form) and recording which names are present and
// which sensitive names used hex obfuscation. The work is bounded by the token
// cap so a buffer dense in '/' cannot amplify into unbounded work.
func (d *doc) scanNames() {
	data := d.data
	tokens := 0
	for i := 0; i < len(data); {
		if data[i] != '/' {
			i++
			continue
		}
		name, usedHex, next := decodeName(data, i)
		i = next
		if name == "" {
			continue
		}
		tokens++
		if tokens > maxNameTokens {
			d.warn("name-scan work cap reached")
			break
		}
		// Always remember signal names; cap only the generic ones so a flood of
		// unique junk names cannot grow the map without bound.
		if signalNames[name] || len(d.names) < maxNames {
			d.names[name] = true
		}
		if usedHex && sensitiveObfNames[name] {
			d.hexObf[name] = true
		}
	}
}

// decodeName reads one /Name token starting at data[start] == '/'. It resolves
// #xx hex escapes (e.g. "J#61vaScript" -> "JavaScript") and reports whether any
// escape was used. The name ends at the first PDF delimiter or whitespace, and
// its length is capped. Returns the decoded name, the hex-escape flag, and the
// index just past the consumed bytes (always > start, so the caller progresses).
func decodeName(data []byte, start int) (string, bool, int) {
	i := start + 1 // skip '/'
	var b []byte
	usedHex := false
	for i < len(data) && len(b) < maxNameLen {
		c := data[i]
		if isWhitespace(c) || isDelim(c) {
			break
		}
		if c == '#' && i+2 < len(data) && isHex(data[i+1]) && isHex(data[i+2]) {
			b = append(b, hexVal(data[i+1])<<4|hexVal(data[i+2]))
			usedHex = true
			i += 3
			continue
		}
		b = append(b, c)
		i++
	}
	return string(b), usedHex, i
}

// countObjects counts "N G obj" indirect-object definitions. An "obj" keyword is
// counted only when it is token-bounded and preceded by the "<num> <gen> "
// shape, which excludes "endobj" and words such as "object".
func countObjects(data []byte) int {
	n := 0
	for i := 0; i+3 <= len(data); {
		j := bytes.Index(data[i:], []byte("obj"))
		if j < 0 {
			break
		}
		pos := i + j
		after := pos + 3
		boundedAfter := after >= len(data) || isWhitespace(data[after]) || isDelim(data[after])
		if pos > 0 && isWhitespace(data[pos-1]) && boundedAfter && hasObjPrefix(data, pos) {
			n++
		}
		i = pos + 3
	}
	return n
}

// hasObjPrefix reports whether the bytes before pos (an "obj" keyword) match the
// "<digits> <ws> <digits> <ws>" object-header shape.
func hasObjPrefix(data []byte, pos int) bool {
	k := pos - 1
	ws := 0
	for k >= 0 && isWhitespace(data[k]) {
		k--
		ws++
	}
	if ws == 0 {
		return false
	}
	gen := 0
	for k >= 0 && isDigit(data[k]) {
		k--
		gen++
	}
	if gen == 0 {
		return false
	}
	ws = 0
	for k >= 0 && isWhitespace(data[k]) {
		k--
		ws++
	}
	if ws == 0 {
		return false
	}
	num := 0
	for k >= 0 && isDigit(data[k]) {
		k--
		num++
	}
	return num > 0
}

// countStreams counts stream bodies. "endstream" contains "stream", so the count
// of "stream" minus the count of "endstream" is the number of stream starts.
func countStreams(data []byte) int {
	s := bytes.Count(data, []byte("stream")) - bytes.Count(data, []byte("endstream"))
	if s < 0 {
		s = 0
	}
	return s
}

// ── detection ──────────────────────────────────────────────────────────────────

// detect runs every rule and returns the findings in a stable order.
func (d *doc) detect() []Finding {
	var out []Finding

	hasAuto := d.names["OpenAction"] || d.names["AA"]
	hasJS := d.names["JavaScript"] || d.names["JS"]
	hasLaunch := d.names["Launch"]
	hasEmbedded := d.names["EmbeddedFile"] || d.names["EF"]
	hasRemote := d.names["SubmitForm"] || d.names["GoToR"]
	hasURI := d.names["URI"]

	// Rule 1 — an automatic action that runs when the file is opened (T1204.002).
	if hasAuto {
		ev := "/OpenAction"
		if !d.names["OpenAction"] {
			ev = "/AA"
		}
		out = append(out, Finding{
			Class: "pdf.action.openaction", Score: weightAutoAction, Technique: techUserExec,
			Detail:   "document defines an automatic action that runs when the file is opened",
			Evidence: ev,
		})
	}

	// Rule 2 — embedded JavaScript (T1059.007).
	if hasJS {
		ev := "/JavaScript"
		if !d.names["JavaScript"] {
			ev = "/JS"
		}
		out = append(out, Finding{
			Class: "pdf.javascript", Score: weightJavaScript, Technique: techJS,
			Detail:   "document embeds JavaScript",
			Evidence: ev,
		})
	}

	// Rule 3 — a Launch action that runs an external program (T1059).
	if hasLaunch {
		out = append(out, Finding{
			Class: "pdf.action.launch", Score: weightLaunch, Technique: techInterp,
			Detail:   "document uses a Launch action to run an external program",
			Evidence: "/Launch",
		})
	}

	// Rule 4 — an embedded file, a payload carrier (T1204.002).
	if hasEmbedded {
		ev := "/EmbeddedFile"
		if !d.names["EmbeddedFile"] {
			ev = "/EF"
		}
		out = append(out, Finding{
			Class: "pdf.embeddedfile", Score: weightEmbedded, Technique: techUserExec,
			Detail:   "document carries an embedded file (payload carrier)",
			Evidence: ev,
		})
	}

	// Rule 5 — a remote-fetch action (T1105).
	if hasRemote {
		ev := "/SubmitForm"
		if !d.names["SubmitForm"] {
			ev = "/GoToR"
		}
		out = append(out, Finding{
			Class: "pdf.action.remote", Score: weightRemote, Technique: techIngress,
			Detail:   "document uses a remote-fetch action (SubmitForm / remote GoTo)",
			Evidence: ev,
		})
	}

	// Rule 6 — a URI action: a network callout / link (T1204.001). Low weight;
	// benign PDFs frequently carry link annotations.
	if hasURI {
		out = append(out, Finding{
			Class: "pdf.uri", Score: weightURI, Technique: techMalLink,
			Detail:   "document contains a URI action (network callout / link)",
			Evidence: "/URI",
		})
	}

	// Rule 7 — name obfuscation: a sensitive name spelled with #xx hex escapes
	// (T1027). Benign PDFs almost never hex-escape these, so it is a strong
	// intent signal in its own right.
	if name, ok := firstKey(d.hexObf, obfOrder); ok {
		out = append(out, Finding{
			Class: "pdf.obfuscation.name", Score: weightNameObf, Technique: techObfuscation,
			Detail:   "a sensitive name was written with #xx hex escapes to evade string matching",
			Evidence: "decoded /" + name,
		})
	}

	// Rule 8 — exploitation / obfuscation primitives inside embedded JavaScript
	// (T1027). Conservative: only considered when JavaScript is actually present.
	if hasJS {
		if ev, ok := d.jsHeuristics(); ok {
			out = append(out, Finding{
				Class: "pdf.javascript.heuristic", Score: weightJSHeuristic, Technique: techObfuscation,
				Detail:   "embedded JavaScript uses exploitation / obfuscation primitives",
				Evidence: ev,
			})
		}
	}

	// Rule 9 — encryption is a neutral fact on its own (many benign PDFs are
	// encrypted) and is never scored alone. But an encrypted document that ALSO
	// auto-runs embedded JavaScript is a known evasion, so it adds a tiny
	// amplifier here (T1027).
	if d.encrypted && hasJS && hasAuto {
		out = append(out, Finding{
			Class: "pdf.evasion.encrypted-autojs", Score: weightEncEvasion, Technique: techObfuscation,
			Detail:   "encrypted document that also auto-runs embedded JavaScript (evasion)",
			Evidence: "/Encrypt + auto-run JavaScript",
		})
	}

	return out
}

// jsHeuristics scans a bounded region for JavaScript exploitation / obfuscation
// primitives. It returns the first tell found. Matching is case-insensitive over
// a one-time lowercased copy of the bounded region.
func (d *doc) jsHeuristics() (string, bool) {
	region := d.data
	if len(region) > maxJSHeuristicBytes {
		region = region[:maxJSHeuristicBytes]
	}
	lower := bytes.ToLower(region)
	for _, n := range jsHeuristicNeedles {
		if bytes.Contains(lower, []byte(n)) {
			return n, true
		}
	}
	if bytes.Count(lower, []byte("%u")) >= heapSprayCount {
		return "%u heap-spray pattern", true
	}
	if bytes.Count(lower, []byte("\\x")) >= longHexRun {
		return "long \\xNN escape run", true
	}
	return "", false
}

// summary builds the compact Parsed view returned to callers.
func (d *doc) summary() *Parsed {
	return &Parsed{
		Version:       d.version,
		Objects:       d.objects,
		Streams:       d.streams,
		HasOpenAction: d.names["OpenAction"] || d.names["AA"],
		HasJavaScript: d.names["JavaScript"] || d.names["JS"],
		Encrypted:     d.encrypted,
		Warning:       d.warning,
	}
}

// ── rule tables ────────────────────────────────────────────────────────────────

// signalNames are the names the detector reasons about; they are remembered even
// once the generic-name cap is hit so a junk-name flood cannot hide them.
var signalNames = map[string]bool{
	"OpenAction": true, "AA": true, "JavaScript": true, "JS": true,
	"Launch": true, "EmbeddedFile": true, "EF": true, "Filespec": true,
	"URI": true, "SubmitForm": true, "GoToR": true, "Encrypt": true,
}

// sensitiveObfNames are the names whose hex-escaped spelling is a strong intent
// signal (benign PDFs do not hex-escape these).
var sensitiveObfNames = map[string]bool{
	"JavaScript": true, "JS": true, "OpenAction": true, "AA": true, "Launch": true,
}

// obfOrder fixes a deterministic reporting order for the name-obfuscation rule.
var obfOrder = []string{"JavaScript", "JS", "OpenAction", "AA", "Launch"}

// jsHeuristicNeedles are lowercase exploitation / obfuscation primitives commonly
// seen in malicious PDF JavaScript. app.alert alone is intentionally absent (it
// is benign and common); the primitives here are the ones that signal intent.
var jsHeuristicNeedles = []string{
	"unescape(",
	"eval(",
	"fromcharcode",
	"util.printf",
	"getannots(",
	"collab.collectemailinfo",
	"media.newplayer",
	"spell.customdictionaryopen",
	"this.exportdataobject",
	"newfunction",
}

// ── small helpers ──────────────────────────────────────────────────────────────

func isWhitespace(c byte) bool {
	switch c {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func firstKey(set map[string]bool, order []string) (string, bool) {
	for _, k := range order {
		if set[k] {
			return k, true
		}
	}
	return "", false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

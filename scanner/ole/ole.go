package ole

import (
	"os"
	"strings"
)

// ── ATT&CK technique ids ───────────────────────────────────────────────────────

const (
	techVBScript      = "T1059.005" // Command and Scripting Interpreter: Visual Basic
	techOfficeStartup = "T1137"     // Office Application Startup
	techUserExec      = "T1204.002" // User Execution: Malicious File
	techPowerShell    = "T1059.001" // ... PowerShell
	techCmd           = "T1059.003" // ... Windows Command Shell
	techIngress       = "T1105"     // Ingress Tool Transfer
	techObfuscation   = "T1027"     // Obfuscated Files or Information
	techExploit       = "T1203"     // Exploitation for Client Execution
)

// ── finding weights ────────────────────────────────────────────────────────────
//
// The scale mirrors the sibling lnk detector (DefaultThreshold 8). Weights are
// small and additive so no single benign structural tell crosses the threshold:
// a plain macro-bearing document (legit macros are common) stays BELOW, while a
// clear malicious combination the way droppers actually build them crosses it.
// Worked examples:
//
//	AutoOpen + Shell("powershell …")  = project 2 + autoexec 4 + shell 4 + ps 4 = 14  (detected)
//	Document_Open + URLDownloadToFile = project 2 + autoexec 4 + download 4       = 10  (detected)
//	a module that merely CreateObjects = project 2 + late-binding 3               = 5   (below)
//
// while a lone tell stays below:
//
//	a document that merely carries a VBA project = 2
//	an Equation Native / Ole10Native carrier     = 3
const (
	weightVBAProject = 2 // a VBA project is present (legit docs have macros)
	weightAutoExec   = 4 // an auto-execution entry point in the source
	weightShell      = 4 // a process-spawn / download primitive in the source
	weightLateBind   = 3 // late-binding object creation (CreateObject/GetObject)
	weightObfusc     = 3 // base64 / string-reversal / Chr()-heavy obfuscation
	weightEmbedded   = 3 // an Equation Editor / embedded-object lure stream
)

// DefaultThreshold is the shipped score at which a document is reported
// suspicious. A macro that auto-executes AND reaches for a shell / download
// crosses it; a document that merely carries macros does not.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can be
// retuned without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory. Legacy Office
// documents are well under this; anything far larger is handled by the size cap
// rather than loaded whole.
const DefaultMaxSize int64 = 16 << 20

// Detector work caps.
const (
	maxNamesReported  = 64 // stream/storage names surfaced in Parsed
	maxModulesScanned = 256
	maxScanAttempts   = 64       // CompressedContainer offsets tried per stream
	decompressBudget  = 32 << 20 // total decompressed bytes produced per file
	minVBASourceBytes = 4        // shortest decompressed blob treated as a module
	chrObfuscCount    = 12       // Chr( occurrences treated as obfuscation
	vbaTextRatio      = 0.80     // printable-byte fraction required of a module source
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
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Parsed is a compact summary of the compound file's structure.
type Parsed struct {
	HasVBA      bool     `json:"has_vba"`
	Modules     int      `json:"modules,omitempty"`
	StreamNames []string `json:"stream_names,omitempty"`
	Warning     string   `json:"warning,omitempty"`
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

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// compound file gets an immediate zero-score result; otherwise the file is
// parsed defensively and the detection rules are summed into Result.Score.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsOLE(data) {
		return r
	}
	f := parseCFB(data)

	findings, hasVBA, modules := detect(f)
	r.Findings = findings
	for _, fd := range findings {
		r.Score += fd.Score
	}
	r.Parsed = &Parsed{
		HasVBA:      hasVBA,
		Modules:     modules,
		StreamNames: streamNames(f),
		Warning:     f.warning,
	}
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

// ── detection ──────────────────────────────────────────────────────────────────

// detect runs every rule over a parsed compound file and returns the findings
// plus the HasVBA / module-count summary.
func detect(f *cfbFile) (findings []Finding, hasVBA bool, modules int) {
	// Rule 1 — a VBA project is present (low weight; legit docs carry macros).
	if marker, ok := vbaProjectMarker(f); ok {
		hasVBA = true
		findings = append(findings, Finding{
			Class: "ole.vba.project", Score: weightVBAProject, Technique: techVBScript,
			Detail: "document carries a VBA macro project", Evidence: marker,
		})
	}

	// Rule 2 — embedded-object / exploit lure streams.
	for _, e := range f.entries {
		if e.objType != objStream {
			continue
		}
		switch strings.ToLower(trimCtrl(e.name)) {
		case "equation native":
			findings = append(findings, Finding{
				Class: "ole.lure.equation", Score: weightEmbedded, Technique: techExploit,
				Detail: "Equation Editor native stream (classic exploit carrier)", Evidence: e.name,
			})
		case "ole10native":
			findings = append(findings, Finding{
				Class: "ole.lure.ole10native", Score: weightEmbedded, Technique: techUserExec,
				Detail: "Ole10Native embedded-object stream (embedded-payload carrier)", Evidence: e.name,
			})
		}
	}

	// Rule 3+ — decompress the VBA module sources and read tradecraft out of them.
	sources := extractModuleSources(f)
	modules = len(sources)
	if modules == 0 {
		return findings, hasVBA, modules
	}
	src := strings.ToLower(strings.Join(sources, "\n"))

	// Auto-execution entry points (weighty).
	if hit, ok := matchAny(src, autoExecNeedles); ok {
		findings = append(findings, Finding{
			Class: "ole.vba.autoexec", Score: weightAutoExec, Technique: techOfficeStartup,
			Detail: "VBA auto-execution entry point", Evidence: hit,
		})
	}

	// Suspicious calls, grouped by technique; each group fires at most once.
	for _, g := range suspiciousGroups {
		if hit, ok := matchAny(src, g.needles); ok {
			findings = append(findings, Finding{
				Class: g.class, Score: g.weight, Technique: g.tech,
				Detail: g.detail, Evidence: hit,
			})
		}
	}

	// Heavy Chr()-based string building — a common inline-obfuscation tell.
	if n := countOccurrences(src, "chr("); n >= chrObfuscCount {
		findings = append(findings, Finding{
			Class: "ole.vba.obfuscation", Score: weightObfusc, Technique: techObfuscation,
			Detail: "heavy Chr()-based string obfuscation", Evidence: "chr( x" + itoa(n),
		})
	}

	return findings, hasVBA, modules
}

// extractModuleSources resolves candidate module streams and decompresses the
// CompressedSourceCode out of each. See the module-location note below.
func extractModuleSources(f *cfbFile) []string {
	var out []string
	budget := decompressBudget
	for _, e := range f.entries {
		if e.objType != objStream || isMetadataStream(e.name) {
			continue
		}
		if budget <= 0 {
			break
		}
		raw := f.readEntry(e)
		if len(raw) == 0 {
			continue
		}
		if src, ok := scanForVBASource(raw, &budget); ok {
			out = append(out, src)
			if len(out) >= maxModulesScanned {
				break
			}
		}
	}
	return out
}

// Module-location approach — SIGNATURE SCAN (documented choice).
//
// A proper [MS-OVBA] offset parse reads MODULEOFFSET records out of the (itself
// compressed) "dir" stream to find each module's CompressedSourceCode. That is
// correct but sizeable. Per the brief, this v1 uses the blessed bounded fallback
// instead: for each candidate module stream it scans for the 0x01
// CompressedContainer signature followed by a valid chunk header (signature bits
// == 0b011), attempts decompression, and accepts the result only if it reads as
// VBA source text. The decompressor stops at the first invalid chunk signature,
// so trailing bytes past a container (including PerformanceCache padding) are
// ignored. The offsets tried per stream (maxScanAttempts) and the total bytes
// decompressed per file (*budget) are both bounded, so a stream crafted to be
// dense in 0x01 chunk headers cannot amplify into unbounded work.
func scanForVBASource(raw []byte, budget *int) (string, bool) {
	attempts := 0
	for off := 0; off+3 <= len(raw); off++ {
		if *budget <= 0 {
			break
		}
		if raw[off] != 0x01 {
			continue
		}
		header := uint16(raw[off+1]) | uint16(raw[off+2])<<8
		if (header>>12)&0x07 != 0b011 {
			continue // not a plausible CompressedChunkHeader
		}
		attempts++
		if attempts > maxScanAttempts {
			break
		}
		if decompressed, ok := decompressContainer(raw[off:], *budget); ok {
			*budget -= len(decompressed)
			if len(decompressed) >= minVBASourceBytes && looksLikeVBASource(decompressed) {
				return string(decompressed), true
			}
		}
	}
	return "", false
}

// looksLikeVBASource accepts a blob whose bytes are overwhelmingly printable
// text, which separates decompressed VBA source from the binary records of the
// "dir" stream or compiled p-code.
func looksLikeVBASource(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c <= 0x7E) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= vbaTextRatio
}

// streamNames returns a capped list of the stream/storage names for Parsed.
func streamNames(f *cfbFile) []string {
	var names []string
	for _, e := range f.entries {
		if e.objType == objStream || e.objType == objStorage {
			names = append(names, e.name)
			if len(names) >= maxNamesReported {
				break
			}
		}
	}
	return names
}

// ── markers & rule tables ───────────────────────────────────────────────────────

// vbaProjectMarker reports a VBA project when a known storage or stream is
// present, returning the marker that matched.
func vbaProjectMarker(f *cfbFile) (string, bool) {
	for _, e := range f.entries {
		n := strings.ToLower(trimCtrl(e.name))
		switch {
		case e.objType == objStorage && (n == "vba" || n == "macros" || n == "_vba_project_cur"):
			return e.name, true
		case e.objType == objStream && (n == "_vba_project" || n == "dir" || n == "project" || n == "projectwm"):
			return e.name, true
		}
	}
	return "", false
}

// metadataStreams are the well-known non-module streams inside a VBA project or
// a compound file; everything else is a candidate module stream for the scan.
var metadataStreams = map[string]bool{
	"dir": true, "project": true, "projectwm": true, "projectlk": true,
	"projectcompat": true, "_vba_project": true, "compobj": true, "ole": true,
	"summaryinformation": true, "documentsummaryinformation": true,
}

func isMetadataStream(name string) bool {
	n := strings.ToLower(trimCtrl(name))
	if metadataStreams[n] {
		return true
	}
	return strings.HasPrefix(n, "__srp_") || strings.HasPrefix(n, "_srp")
}

// autoExecNeedles are VBA auto-execution entry points (matched lowercased).
var autoExecNeedles = []string{
	"autoopen", "autoclose", "autoexec", "auto_open", "auto_close",
	"document_open", "document_close", "documentopen",
	"workbook_open", "workbook_activate",
}

type suspiciousGroup struct {
	class   string
	tech    string
	weight  int
	detail  string
	needles []string
}

// suspiciousGroups map VBA tradecraft primitives to a finding class, the most
// specific ATT&CK technique, and a weight. Needles are matched lowercased.
var suspiciousGroups = []suspiciousGroup{
	{"ole.exec.powershell", techPowerShell, weightShell,
		"VBA spawns PowerShell", []string{"powershell", "pwsh"}},
	{"ole.exec.cmd", techCmd, weightShell,
		"VBA spawns the Windows command shell", []string{"cmd.exe", "cmd /c", "%comspec%", "comspec"}},
	{"ole.exec.shell", techVBScript, weightShell,
		"VBA shell / Windows Script Host execution",
		[]string{"shell(", "vba.shell", "wscript.shell", "wshshell", "shellexecute"}},
	{"ole.download", techIngress, weightShell,
		"VBA network-download primitive",
		[]string{"urldownloadtofile", "xmlhttp", "winhttp", "serverxmlhttp", "downloadfile", "downloadstring", "adodb.stream", "msxml2"}},
	{"ole.exec.late-binding", techVBScript, weightLateBind,
		"VBA late-binding object creation",
		[]string{"createobject", "getobject", "callbyname"}},
	{"ole.obfuscation.encoded", techObfuscation, weightObfusc,
		"VBA base64 / string-reversal obfuscation",
		[]string{"frombase64string", "strreverse", "fromcharcode", "xor "}},
}

// ── small helpers ──────────────────────────────────────────────────────────────

// trimCtrl drops leading control bytes (e.g. the 0x01 / 0x05 prefixes compound
// files put on special stream names) so names compare cleanly.
func trimCtrl(s string) string {
	i := 0
	for i < len(s) && s[i] < 0x20 {
		i++
	}
	return s[i:]
}

func matchAny(hay string, needles []string) (string, bool) {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return n, true
		}
	}
	return "", false
}

func countOccurrences(hay, needle string) int {
	if needle == "" {
		return 0
	}
	return strings.Count(hay, needle)
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

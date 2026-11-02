// Package report renders CAU EDR scan results into machine-readable formats.
//
// The package exists because stdout prose and a hard-coded `os.Exit(0)` are
// useless in CI: a pipeline needs a document it can diff, store and query, and
// an exit code it can branch on.
//
// Three concerns live here, deliberately separated:
//
//   - json.go  — a versioned, self-describing JSON document (the native schema).
//   - sarif.go — SARIF 2.1.0, so findings land in GitHub code scanning,
//     Azure DevOps, GitLab, DefectDojo, etc.
//   - exit.go  — an explicit, pure exit-code policy.
//
// # Design rules
//
//   - Standard library only. Reports are the most load-bearing part of a
//     security tool: no supply-chain risk, no version skew, trivially auditable.
//   - Never trust the input. Every string that came from a scanned file or from
//     a signature database is length-bounded before it reaches the output
//     (see util.go), and JSON HTML escaping is left ON so that a malicious file
//     name cannot inject markup into a web UI that renders the report.
//   - Reporters never fail on suspicious content. They fail only if the output
//     cannot be encoded or written. A detection is data, not an exception.
//
// # Schema stability
//
// JSONSchemaVersion is a public contract:
//
//   - patch (1.0.1) — no consumer-visible change; bug fix in this package.
//   - minor (1.1)   — new OPTIONAL field, or a new value in an existing enum.
//     Existing consumers keep working; this is what additive changes must use.
//   - major (2.0)   — a required field is removed/renamed/retyped, or an enum
//     value disappears. Consumers must opt in explicitly.
//
// Consumers should treat unknown fields as forward-compatible and ignore them,
// which is what lets the minor bump be non-breaking.
package report

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/fusion"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// Branding defaults. main.go owns the canonical version string; these are the
// fallbacks used when the caller does not pass WithToolVersion.
const (
	DefaultToolName       = "CAU EDR"
	DefaultToolTagline    = "Certs Are Useless"
	DefaultToolVersion    = "unknown"
	DefaultInformationURI = "https://github.com/cau-edr/cau"
)

// Truncation defaults. These are deliberately small: a report is uploaded to
// bug trackers and pasted into issues, so a single multi-megabyte match must
// not be able to blow up the document.
const (
	// DefaultMaxMatchStringBytes caps the raw matched-string blob (before hex
	// encoding) that survives into a report.
	DefaultMaxMatchStringBytes = 256
	// DefaultMaxHashChars caps hash-shaped strings (SHA256 is 64 chars, so
	// this only ever bites on malformed or hostile signature-database input).
	DefaultMaxHashChars = 128
	// DefaultMaxMessageRunes caps free-text fields (threat names, SARIF
	// messages).
	DefaultMaxMessageRunes = 1024
	// DefaultMaxPreviewBytes caps the printable rendering of a matched blob.
	DefaultMaxPreviewBytes = 80
	// DefaultHeuristicThreshold mirrors the scanner's own default. Callers
	// should pass WithHeuristicThreshold(scanner.HeuristicThreshold) so the
	// report and the engine cannot drift apart — this package deliberately
	// does not import that identifier, because it is being promoted from const
	// to var and may be retuned at runtime.
	DefaultHeuristicThreshold = 3
	// DefaultStaticThreshold mirrors static.DefaultThreshold. Callers pass
	// WithStaticThreshold(static.Threshold) for the same reason as above.
	DefaultStaticThreshold = static.DefaultThreshold
	// DefaultStegoThreshold mirrors stego.DefaultThreshold.
	DefaultStegoThreshold = stego.DefaultThreshold
	// DefaultEncChainThreshold mirrors encchain.DefaultThreshold.
	DefaultEncChainThreshold = encchain.DefaultThreshold
	// DefaultLNKThreshold mirrors lnk.DefaultThreshold.
	DefaultLNKThreshold = lnk.DefaultThreshold
	// DefaultOLEThreshold mirrors ole.DefaultThreshold.
	DefaultOLEThreshold = ole.DefaultThreshold
	// DefaultPDFThreshold mirrors pdf.DefaultThreshold.
	DefaultPDFThreshold = pdf.DefaultThreshold
	// DefaultISOThreshold mirrors iso.DefaultThreshold.
	DefaultISOThreshold = iso.DefaultThreshold
)

// TruncationMarker is appended to any string that was cut short. Blob-shaped
// fields (hex dumps) additionally carry an explicit `truncated` boolean and the
// original length, because appending text to a hex dump would make it
// un-parseable for exactly the tools that need it.
const TruncationMarker = "…[truncated]"

// Input is everything a reporter (or the exit policy) needs to describe one
// scan run. It is a plain value: pure functions, no hidden state, no clock, no
// filesystem. Anything environment-dependent is injected via Option.
type Input struct {
	// Results is the per-file output of the hash + YARA scanners, in scan order.
	Results []scanner.ScanResult
	// Heuristics is the per-file output of the heuristic scanner. These are a
	// parallel stream, not a field of ScanResult, so they are correlated by
	// FilePath (see HeuristicsByPath).
	Heuristics []scanner.HeuristicResult
	// Elapsed is the wall-clock time the run took.
	Elapsed time.Duration
	// RunError is set when the scan could not run at all — signature database
	// unreadable, YARA rules that would not compile, bad flags. This is the
	// "internal error" case for the exit policy and is surfaced verbatim in
	// both output formats; a per-file error does not belong here.
	RunError error
}

// Empty reports whether the run scanned nothing. A run that produced no
// results and no heuristics did not find anything — it looked at nothing.
func (in Input) Empty() bool {
	return len(in.Results) == 0 && len(in.Heuristics) == 0
}

// HeuristicsByPath indexes heuristic results by file path.
//
// Malformed input is tolerated on purpose: if the caller supplies two heuristic
// results for one path (a file rescanned, or two roots that overlap), the last
// one wins rather than being dropped, because silently discarding a detection
// would be the dangerous direction to fail in.
func (in Input) HeuristicsByPath() map[string]scanner.HeuristicResult {
	out := make(map[string]scanner.HeuristicResult, len(in.Heuristics))
	for _, h := range in.Heuristics {
		out[h.FilePath] = h
	}
	return out
}

// AllPaths returns every path that deserves an entry in the report: the scanned
// files in scan order, followed by any heuristic-only path the scanner reported
// on but that has no ScanResult. The tail is sorted so the report is stable
// regardless of how the caller accumulated the heuristic results.
func (in Input) AllPaths() []string {
	seen := make(map[string]bool, len(in.Results)+len(in.Heuristics))
	paths := make([]string, 0, len(in.Results)+len(in.Heuristics))

	for _, r := range in.Results {
		if seen[r.FilePath] {
			continue
		}
		seen[r.FilePath] = true
		paths = append(paths, r.FilePath)
	}

	var extra []string
	for _, h := range in.Heuristics {
		if seen[h.FilePath] {
			continue
		}
		seen[h.FilePath] = true
		extra = append(extra, h.FilePath)
	}
	sortStrings(extra)
	return append(paths, extra...)
}

// ErrorCount counts every failure observed during the run: run-level plus
// per-file (scan and heuristic). Heuristic errors are counted separately from
// scan errors because only the former can occur on a file whose scan succeeded.
func (in Input) ErrorCount() int {
	n := 0
	if in.RunError != nil {
		n++
	}
	for _, r := range in.Results {
		if r.Error != nil {
			n++
		}
	}
	for _, h := range in.Heuristics {
		if h.Error != nil {
			n++
		}
	}
	for _, r := range in.Results {
		if r.Error == nil && r.Static != nil && r.Static.Error != nil {
			n++
		}
		if r.Error == nil && r.Stego != nil && r.Stego.Error != nil {
			n++
		}
	}
	return n
}

// FileErrorCount is ErrorCount without the run-level error — i.e. the number of
// individual files the engine could not judge.
func (in Input) FileErrorCount() int {
	n := 0
	for _, r := range in.Results {
		if r.Error != nil {
			n++
		}
	}
	for _, h := range in.Heuristics {
		if h.Error != nil {
			n++
		}
	}
	for _, r := range in.Results {
		if r.Error == nil && r.Static != nil && r.Static.Error != nil {
			n++
		}
		if r.Error == nil && r.Stego != nil && r.Stego.Error != nil {
			n++
		}
	}
	return n
}

// Malicious returns the scan results that constitute a confirmed detection:
// a hash-signature hit or at least one YARA rule match. The Verdict is trusted
// when set, but a result carrying detections is treated as malicious even if
// the verdict is missing, because dropping a detection would be the unsafe
// direction to fail in.
func (in Input) Malicious() []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if isMalicious(r) {
			out = append(out, r)
		}
	}
	return out
}

func isMalicious(r scanner.ScanResult) bool {
	return r.Verdict == scanner.VerdictMalicious || r.Detected || len(r.YaraMatches) > 0
}

// HashDetectionCount is the number of files with a hash-signature hit.
func (in Input) HashDetectionCount() int {
	n := 0
	for _, r := range in.Results {
		if r.Detected {
			n++
		}
	}
	return n
}

// YaraDetectionCount is the number of files with at least one YARA match.
func (in Input) YaraDetectionCount() int {
	n := 0
	for _, r := range in.Results {
		if len(r.YaraMatches) > 0 {
			n++
		}
	}
	return n
}

// MaxHeuristicScore is the highest heuristic score observed. Zero when
// heuristics did not run.
func (in Input) MaxHeuristicScore() int {
	max := 0
	for _, h := range in.Heuristics {
		if h.Score > max {
			max = h.Score
		}
	}
	return max
}

// HeuristicBreach returns the heuristic results whose score reached or passed
// the threshold, i.e. the results the engine itself calls detected.
//
// A result that recorded the threshold it was scored against (Threshold > 0)
// is judged against that; the parameter is the fallback for results that did
// not. It is a parameter rather than scanner.HeuristicThreshold because that
// identifier is a tunable: reporting "3/3" when the engine ran with 5/5 would
// be a lie. Errored and skipped results never breach.
func (in Input) HeuristicBreach(threshold int) []scanner.HeuristicResult {
	var out []scanner.HeuristicResult
	for _, h := range in.Heuristics {
		if heuristicBreached(h, threshold) {
			out = append(out, h)
		}
	}
	return out
}

// thresholdFor returns the threshold that applies to one result.
func thresholdFor(h scanner.HeuristicResult, fallback int) int {
	if h.Threshold > 0 {
		return h.Threshold
	}
	return fallback
}

// heuristicBreached is the single definition of "the heuristics fired" used by
// every reporter and the exit policy.
func heuristicBreached(h scanner.HeuristicResult, fallback int) bool {
	return h.Error == nil && h.Skipped == "" && h.Score >= thresholdFor(h, fallback)
}

// HasHeuristicObservation reports whether any file produced *any* heuristic
// evidence at all (a non-zero score, or matches, or a failed heuristic read).
// This is the "not clean, but below the alert threshold" tier that the strict
// FailOnClean policy targets.
func (in Input) HasHeuristicObservation() bool {
	for _, h := range in.Heuristics {
		if h.Error != nil || h.Score > 0 || len(h.Matches) > 0 {
			return true
		}
	}
	return false
}

// StaticBreach returns the scan results whose structural (static) score
// reached its threshold. Same contract as HeuristicBreach: a result that
// recorded its own threshold is judged against that, the parameter is the
// fallback. Skipped and errored static results never breach.
func (in Input) StaticBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if staticBreached(r.Static, threshold) {
			out = append(out, r)
		}
	}
	return out
}

// staticThresholdFor returns the threshold that applies to one static result.
func staticThresholdFor(s *static.Result, fallback int) int {
	if s != nil && s.Threshold > 0 {
		return s.Threshold
	}
	return fallback
}

// staticBreached is the single definition of "the static analysis fired"
// used by every reporter and the exit policy.
func staticBreached(s *static.Result, fallback int) bool {
	return s != nil && s.Error == nil && s.Skipped == "" && s.Score >= staticThresholdFor(s, fallback)
}

// HasStaticObservation reports whether any file produced scored structural
// evidence below the threshold, or a failed static pass — the static side of
// the "not spotless" tier.
func (in Input) HasStaticObservation() bool {
	for _, r := range in.Results {
		if r.Static != nil && (r.Static.Error != nil || r.Static.HasObservation()) {
			return true
		}
	}
	return false
}

// StegoBreach returns the scan results whose invisible-codepoint score
// reached its threshold. Same contract as StaticBreach.
func (in Input) StegoBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if stegoBreached(r.Stego, threshold) {
			out = append(out, r)
		}
	}
	return out
}

// EncChainBreach returns the scan results whose encoded-executable score
// reached the threshold.
func (in Input) EncChainBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if encChainBreached(r.EncChain, threshold) {
			out = append(out, r)
		}
	}
	return out
}

func encChainThresholdFor(e *encchain.Result, fallback int) int {
	if e != nil && e.Threshold > 0 {
		return e.Threshold
	}
	return fallback
}

// encChainBreached is the single definition of "the encoded-executable
// detector fired".
func encChainBreached(e *encchain.Result, fallback int) bool {
	return e != nil && e.Skipped == "" && e.Score >= encChainThresholdFor(e, fallback)
}

// LNKBreach returns the scan results whose Shell Link score reached the
// threshold.
func (in Input) LNKBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if lnkBreached(r.LNK, threshold) {
			out = append(out, r)
		}
	}
	return out
}

func lnkThresholdFor(l *lnk.Result, fallback int) int {
	if l != nil && l.Threshold > 0 {
		return l.Threshold
	}
	return fallback
}

// lnkBreached is the single definition of "the Shell Link detector fired".
func lnkBreached(l *lnk.Result, fallback int) bool {
	return l != nil && l.Skipped == "" && l.Score >= lnkThresholdFor(l, fallback)
}

// OLEBreach returns the scan results whose OLE (VBA macro) score reached the
// threshold.
func (in Input) OLEBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if oleBreached(r.OLE, threshold) {
			out = append(out, r)
		}
	}
	return out
}

func oleThresholdFor(o *ole.Result, fallback int) int {
	if o != nil && o.Threshold > 0 {
		return o.Threshold
	}
	return fallback
}

// oleBreached is the single definition of "the OLE macro detector fired".
func oleBreached(o *ole.Result, fallback int) bool {
	return o != nil && o.Skipped == "" && o.Score >= oleThresholdFor(o, fallback)
}

// PDFBreach returns the scan results whose PDF score reached the threshold.
func (in Input) PDFBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if pdfBreached(r.PDF, threshold) {
			out = append(out, r)
		}
	}
	return out
}

func pdfThresholdFor(p *pdf.Result, fallback int) int {
	if p != nil && p.Threshold > 0 {
		return p.Threshold
	}
	return fallback
}

// pdfBreached is the single definition of "the PDF detector fired".
func pdfBreached(p *pdf.Result, fallback int) bool {
	return p != nil && p.Skipped == "" && p.Score >= pdfThresholdFor(p, fallback)
}

// ISOBreach returns the scan results whose ISO score reached the threshold.
func (in Input) ISOBreach(threshold int) []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if isoBreached(r.ISO, threshold) {
			out = append(out, r)
		}
	}
	return out
}

func isoThresholdFor(i *iso.Result, fallback int) int {
	if i != nil && i.Threshold > 0 {
		return i.Threshold
	}
	return fallback
}

// isoBreached is the single definition of "the ISO detector fired".
func isoBreached(i *iso.Result, fallback int) bool {
	return i != nil && i.Skipped == "" && i.Score >= isoThresholdFor(i, fallback)
}

func stegoThresholdFor(s *stego.Result, fallback int) int {
	if s != nil && s.Threshold > 0 {
		return s.Threshold
	}
	return fallback
}

// stegoBreached is the single definition of "the stego detector fired".
func stegoBreached(s *stego.Result, fallback int) bool {
	return s != nil && s.Error == nil && s.Skipped == "" && s.Score >= stegoThresholdFor(s, fallback)
}

// FusionCorroborated returns the scan results the fusion lattice reports as
// suspicious although no single detector crossed its own threshold: the
// detections fusion adds. A fused verdict that merely restates a detector's
// own breach is not counted here, so the number is the lattice's own
// contribution and nothing else.
func (in Input) FusionCorroborated() []scanner.ScanResult {
	var out []scanner.ScanResult
	for _, r := range in.Results {
		if fusionCorroborated(r.Fusion) {
			out = append(out, r)
		}
	}
	return out
}

func fusionCorroborated(v *fusion.Verdict) bool {
	return v != nil && v.Tier == fusion.TierSuspicious && v.Corroborated
}

// StatFunc reports a file's size in bytes. Injecting it keeps the reporters
// pure and the tests hermetic — no reporter test touches a real filesystem.
type StatFunc func(path string) (int64, error)

// config is the shared, fully-defaulted configuration behind every constructor
// in this package. One config type for three reporters (plus the exit policy)
// means a caller can build one option slice and hand it to whichever consumer
// cares.
type config struct {
	toolName       string
	toolVersion    string
	toolTagline    string
	informationURI string

	indent bool
	root   string

	maxMatchStringBytes int
	maxHashChars        int
	maxMessageRunes     int
	maxPreviewBytes     int

	heuristicThreshold int
	staticThreshold    int
	stegoThreshold     int
	encChainThreshold  int
	lnkThreshold       int
	oleThreshold       int
	pdfThreshold       int
	isoThreshold       int
	stat               StatFunc
	now                func() time.Time

	// SARIF knobs.
	sarifIncludeHeuristics bool
	sarifIncludeScanErrors bool
	levelHash              string
	levelYara              string
	levelHeuristic         string
	levelScanError         string

	// Exit-policy knobs.
	failOn          FailOn
	failOnScanError bool
}

// Option configures a reporter or the exit policy. Options are shared on
// purpose: `opts := []report.Option{report.WithToolVersion(v)}` can be passed
// to NewJSONReporter, NewSARIFReporter and NewExitPolicy alike.
type Option func(*config)

// WithToolName sets the tool name recorded in the JSON document and used as the
// SARIF driver name.
func WithToolName(name string) Option { return func(c *config) { c.toolName = name } }

// WithToolVersion sets the tool version. main.go should pass its own `version`
// const so the report matches the binary that produced it.
func WithToolVersion(v string) Option { return func(c *config) { c.toolVersion = v } }

// WithToolTagline sets the "Certs Are Useless" tagline carried in the JSON
// document only; SARIF has no field for it.
func WithToolTagline(s string) Option { return func(c *config) { c.toolTagline = s } }

// WithInformationURI sets the SARIF driver informationUri. This is what
// code-scanning UIs link to from the tool name, so it must be a stable public
// URL.
func WithInformationURI(u string) Option { return func(c *config) { c.informationURI = u } }

// WithIndent selects pretty-printed JSON. Compact is the default because the
// machine consumer is the primary audience; humans can pipe compact JSON
// through any formatter.
func WithIndent(indent bool) Option { return func(c *config) { c.indent = indent } }

// WithRoot records the directory the scan was rooted at and, for SARIF, makes
// artifact URIs relative to it. Code-scanning UIs need repo-relative URIs to
// attach findings to files in the repository.
func WithRoot(dir string) Option { return func(c *config) { c.root = dir } }

// WithMaxMatchStringBytes caps how many raw bytes of a matched blob are kept.
// Hex encoding doubles the size in the output, so the effective cap in the
// document is 2× this value.
func WithMaxMatchStringBytes(n int) Option {
	return func(c *config) { c.maxMatchStringBytes = n }
}

// WithMaxHashChars caps hash-shaped strings in the document.
func WithMaxHashChars(n int) Option { return func(c *config) { c.maxHashChars = n } }

// WithMaxMessageRunes caps free-text fields such as threat names and SARIF
// message bodies.
func WithMaxMessageRunes(n int) Option { return func(c *config) { c.maxMessageRunes = n } }

// WithMaxPreviewBytes caps the printable rendering of a matched blob.
func WithMaxPreviewBytes(n int) Option { return func(c *config) { c.maxPreviewBytes = n } }

// WithHeuristicThreshold records which threshold the heuristic engine actually
// used. It does not change any verdict — the engine already decided those — it
// only makes the report self-consistent ("score 7 / threshold 5").
func WithHeuristicThreshold(n int) Option { return func(c *config) { c.heuristicThreshold = n } }

// WithStaticThreshold records which threshold the static (structural) analysis
// actually used, so the report can say "score 9 / threshold 8" truthfully.
func WithStaticThreshold(n int) Option { return func(c *config) { c.staticThreshold = n } }

// WithStegoThreshold records which threshold the invisible-codepoint detector
// actually used.
func WithStegoThreshold(n int) Option { return func(c *config) { c.stegoThreshold = n } }

// WithEncChainThreshold records which threshold the encoded-executable
// detector ran at.
func WithEncChainThreshold(n int) Option { return func(c *config) { c.encChainThreshold = n } }

// WithLNKThreshold records which threshold the Shell Link detector ran at.
func WithLNKThreshold(n int) Option { return func(c *config) { c.lnkThreshold = n } }

// WithOLEThreshold records which threshold the OLE macro detector ran at.
func WithOLEThreshold(n int) Option { return func(c *config) { c.oleThreshold = n } }

// WithPDFThreshold records which threshold the PDF detector ran at.
func WithPDFThreshold(n int) Option { return func(c *config) { c.pdfThreshold = n } }

// WithISOThreshold records which threshold the ISO detector ran at.
func WithISOThreshold(n int) Option { return func(c *config) { c.isoThreshold = n } }

// WithStatFunc overrides how file sizes are resolved (os.Stat by default).
func WithStatFunc(f StatFunc) Option { return func(c *config) { c.stat = f } }

// WithClock overrides the timestamp source, for deterministic tests and for
// embedding a run id that predates the scan.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// WithSARIFHeuristics controls whether heuristic breaches become SARIF results.
// On by default, at "note" level: hiding evidence by default is worse than
// showing it quietly, but the level keeps it out of the way of real findings.
func WithSARIFHeuristics(include bool) Option {
	return func(c *config) { c.sarifIncludeHeuristics = include }
}

// WithSARIFScanErrors controls whether per-file scan failures become SARIF
// results. On by default at "warning": a file the engine could not read is a
// coverage gap, and a gap that is not reported reads as a clean bill of health.
func WithSARIFScanErrors(include bool) Option {
	return func(c *config) { c.sarifIncludeScanErrors = include }
}

// WithSARIFLevels overrides the SARIF level for each detection channel. Valid
// values are "error", "warning", "note" and "none"; anything else falls back to
// the default for that channel. "none" keeps the result but suppresses it in
// most UIs.
func WithSARIFLevels(hash, yara, heuristic, scanError string) Option {
	return func(c *config) {
		c.levelHash = hash
		c.levelYara = yara
		c.levelHeuristic = heuristic
		c.levelScanError = scanError
	}
}

// WithFailOn selects how strict the exit-code policy is (see FailOn).
func WithFailOn(l FailOn) Option { return func(c *config) { c.failOn = l } }

// WithFailOnScanError decides whether a file the engine could not scan fails
// the run with ExitScanFailed. On by default: an unscanned artifact and a clean
// artifact must never look the same to a pipeline. The run-level Input.RunError
// fails regardless of this setting.
func WithFailOnScanError(v bool) Option { return func(c *config) { c.failOnScanError = v } }

// defaultConfig returns the shipped defaults. A new option added here must also
// be documented in the package doc, because these are public defaults.
func defaultConfig() config {
	return config{
		toolName:            DefaultToolName,
		toolVersion:         DefaultToolVersion,
		toolTagline:         DefaultToolTagline,
		informationURI:      DefaultInformationURI,
		indent:              false,
		maxMatchStringBytes: DefaultMaxMatchStringBytes,
		maxHashChars:        DefaultMaxHashChars,
		maxMessageRunes:     DefaultMaxMessageRunes,
		maxPreviewBytes:     DefaultMaxPreviewBytes,
		heuristicThreshold:  DefaultHeuristicThreshold,
		staticThreshold:     DefaultStaticThreshold,
		stegoThreshold:      DefaultStegoThreshold,
		encChainThreshold:   DefaultEncChainThreshold,
		lnkThreshold:        DefaultLNKThreshold,
		oleThreshold:        DefaultOLEThreshold,
		pdfThreshold:        DefaultPDFThreshold,
		isoThreshold:        DefaultISOThreshold,
		stat:                osFileSize,
		now:                 time.Now,

		sarifIncludeHeuristics: true,
		sarifIncludeScanErrors: true,
		levelHash:              LevelError,
		levelYara:              LevelError,
		levelHeuristic:         LevelNote,
		levelScanError:         LevelWarning,

		failOn:          FailOnMalicious,
		failOnScanError: true,
	}
}

// normalize clamps nonsense values instead of rejecting them. A report is not
// the place to fail a build over a bad flag: negative limits fall back to the
// defaults, invalid levels fall back to the default level for that channel, and
// an unknown fail-on level falls back to FailOnMalicious (the safest choice —
// a typo must not silently disable failure).
func (c *config) normalize() {
	if c.toolName == "" {
		c.toolName = DefaultToolName
	}
	if c.toolVersion == "" {
		c.toolVersion = DefaultToolVersion
	}
	if c.informationURI == "" {
		c.informationURI = DefaultInformationURI
	}
	if c.maxMatchStringBytes < 0 {
		c.maxMatchStringBytes = DefaultMaxMatchStringBytes
	}
	if c.maxHashChars < 0 {
		c.maxHashChars = DefaultMaxHashChars
	}
	if c.maxMessageRunes < 0 {
		c.maxMessageRunes = DefaultMaxMessageRunes
	}
	if c.maxPreviewBytes < 0 {
		c.maxPreviewBytes = DefaultMaxPreviewBytes
	}
	if c.staticThreshold <= 0 {
		c.staticThreshold = DefaultStaticThreshold
	}
	if c.stegoThreshold <= 0 {
		c.stegoThreshold = DefaultStegoThreshold
	}
	if c.encChainThreshold <= 0 {
		c.encChainThreshold = DefaultEncChainThreshold
	}
	if c.lnkThreshold <= 0 {
		c.lnkThreshold = DefaultLNKThreshold
	}
	if c.oleThreshold <= 0 {
		c.oleThreshold = DefaultOLEThreshold
	}
	if c.pdfThreshold <= 0 {
		c.pdfThreshold = DefaultPDFThreshold
	}
	if c.isoThreshold <= 0 {
		c.isoThreshold = DefaultISOThreshold
	}
	if c.stat == nil {
		c.stat = osFileSize
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.levelHash = normalizeLevel(c.levelHash, LevelError)
	c.levelYara = normalizeLevel(c.levelYara, LevelError)
	c.levelHeuristic = normalizeLevel(c.levelHeuristic, LevelNote)
	c.levelScanError = normalizeLevel(c.levelScanError, LevelWarning)

	switch c.failOn {
	case FailOnNone, FailOnClean, FailOnHeuristic, FailOnMalicious:
	default:
		c.failOn = FailOnMalicious
	}
}

// normalizeLevel validates a SARIF level against the values the specification
// allows, falling back to def for anything else.
func normalizeLevel(level, def string) string {
	switch level {
	case LevelError, LevelWarning, LevelNote, LevelNone:
		return level
	default:
		return def
	}
}

// timestamp renders an instant in the format the document uses: RFC 3339, UTC,
// second precision. Second precision is deliberate — a run id is an identity,
// not a measurement, and sub-second precision would make otherwise identical
// runs look different for no benefit.
func (c config) timestamp() string {
	return c.now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

// sortStrings is a tiny insertion-free helper kept local so the package does not
// need sort for the one place that wants deterministic ordering. sortStrings
// uses sort.Strings under the hood; it exists purely so call sites read well.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// errorString renders an error for a JSON field.
//
// This is the whole reason the reporters build their own structs instead of
// marshalling scanner.ScanResult directly: `error` is an interface, and
// encoding/json can only encode its dynamic type's exported fields. A
// fmt.Errorf("%w") value marshals to `{}`, which is worse than useless — it
// looks like "there was an error, details unknown" and hides the failure in
// CI. Rendering the message here keeps the field a readable string and keeps
// the scanner's error type out of the public schema.
func (c config) errorString(err error) string {
	if err == nil {
		return ""
	}
	s, _ := truncateString(err.Error(), c.maxMessageRunes)
	return s
}

// validUTF8 makes a string safe to embed in a JSON document.
//
// Scanner output is not guaranteed to be UTF-8: a YARA rule can match arbitrary
// bytes, a filename on Linux can hold invalid sequences, and the signature
// database is a plain text file anyone can edit. encoding/json silently
// replaces invalid UTF-8 with U+FFFD, which is safe but lossy; doing it
// explicitly means the truncation marker and the length are computed on the
// same string the reader will see.
func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

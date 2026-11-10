package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaVersion is the corpus-manifest format version this package reads and
// writes. Manifests declaring anything else are rejected rather than
// best-effort parsed: a mis-parsed label silently turns a malware sample into a
// false negative.
const SchemaVersion = "1"

// LabelClean is the canonical benign label. Every other label names a malware
// family (or a cluster, or "unknown") and therefore counts as a positive.
const LabelClean = "clean"

// benignAliases maps the spellings a human is likely to write onto LabelClean.
var benignAliases = map[string]string{
	"clean":    LabelClean,
	"benign":   LabelClean,
	"good":     LabelClean,
	"negative": LabelClean,
	"false":    LabelClean,
	"safe":     LabelClean,
}

// NormalizeLabel lowercases and trims a label and folds benign synonyms onto
// LabelClean. It returns "" for an empty label so callers can tell "unset"
// apart from "a family literally named clean".
func NormalizeLabel(label string) string {
	l := strings.ToLower(strings.TrimSpace(label))
	if alias, ok := benignAliases[l]; ok {
		return alias
	}
	return l
}

// IsBenign reports whether a label denotes a known-good sample.
func IsBenign(label string) bool { return NormalizeLabel(label) == LabelClean }

// FileSystem is the sliver of *os.File the validator needs. Injecting it keeps
// validation testable without touching a real filesystem, and documents
// exactly how much of the OS this package depends on.
type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// OSFS is the default FileSystem: the real operating system.
type OSFS struct{}

func (OSFS) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }
func (OSFS) ReadFile(name string) ([]byte, error)  { return os.ReadFile(name) }

// Defaults supplies manifest-wide fallbacks for samples that omit a field.
type Defaults struct {
	Label   string `json:"label,omitempty"`
	Family  string `json:"family,omitempty"`
	Source  string `json:"source,omitempty"`
	License string `json:"license,omitempty"`
	// Period is the default time period for samples that declare none. The
	// temporal gate splits the corpus on it.
	Period string `json:"period,omitempty"`
}

// Provenance records where a sample came from. It is mandatory (as a warning at
// minimum) for malware samples: an unreproducible corpus cannot be audited and
// its licence status is unknown.
type Provenance struct {
	Source    string `json:"source,omitempty"`    // e.g. "malwarebazaar", "self-built", "vendor-drop"
	URL       string `json:"url,omitempty"`       // canonical retrieval location
	License   string `json:"license,omitempty"`   // e.g. "CC-BY-SA-4.0", "internal"
	Retrieved string `json:"retrieved,omitempty"` // RFC 3339 timestamp
}

// Sample is one labelled file in the corpus.
type Sample struct {
	ID         string     `json:"id,omitempty"`
	Path       string     `json:"path"`
	Label      string     `json:"label,omitempty"`
	Family     string     `json:"family,omitempty"`
	SHA256     string     `json:"sha256,omitempty"`
	Source     string     `json:"source,omitempty"` // shorthand for Provenance.Source
	Notes      string     `json:"notes,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
	Provenance Provenance `json:"provenance,omitempty"`
	// Period is the time period the sample belongs to ("2026-10"). The
	// temporal gate splits the corpus on it, so a corpus that grew over time
	// can say whether the content still catches what it caught earlier. It is
	// a string that sorts chronologically.
	Period string `json:"period,omitempty"`

	// resolved is the absolute (or manifest-relative) filesystem path derived
	// from Path and the manifest directory. Computed by Resolve, never
	// serialised, and readable from outside the package via FullPath.
	resolved string
}

// FullPath returns the resolved filesystem path of the sample.
func (s Sample) FullPath() string { return s.resolved }

// Expected returns the normalized label, i.e. what a perfect detector must do
// with this sample.
func (s Sample) Expected() string {
	if l := NormalizeLabel(s.Label); l != "" {
		return l
	}
	return NormalizeLabel(Defaults{}.Label)
}

// Benign reports whether the sample is labelled clean.
func (s Sample) Benign() bool { return IsBenign(s.Label) }

// Key is the sample's stable identity for baseline comparison. An explicit ID
// wins so that corpora can be moved or re-pathed without invalidating a
// baseline; otherwise the declared (relative) path is the identity.
func (s Sample) Key() string {
	if s.ID != "" {
		return s.ID
	}
	return s.Path
}

// ExpectedFamily returns the family a sample belongs to. Malicious samples
// default to their own label so per-family breakdowns are never empty.
func (s Sample) ExpectedFamily() string {
	if f := strings.TrimSpace(s.Family); f != "" {
		return f
	}
	if l := NormalizeLabel(s.Label); l != "" && l != LabelClean {
		return l
	}
	return LabelClean
}

// Manifest is the declarative description of a corpus.
type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name,omitempty"`
	Description   string `json:"description,omitempty"`
	// Root, when set, is the base directory sample paths resolve against.
	// Defaults to the directory containing the manifest.
	Root     string   `json:"root,omitempty"`
	Defaults Defaults `json:"defaults,omitempty"`
	Samples  []Sample `json:"samples"`

	// SourcePath and Dir are filled by LoadManifest/Resolve and are never
	// serialised.
	SourcePath string `json:"-"`
	Dir        string `json:"-"`
}

// LoadManifest reads and resolves a manifest from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("eval: read manifest: %w", err)
	}
	m, err := ParseManifest(data, path)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ParseManifest decodes a manifest from memory. sourcePath is used both to
// resolve relative sample paths and for error reporting; it may be empty, in
// which case resolution falls back to root (or "." when root is also empty).
//
// Unknown JSON fields are a hard error. A typo like "lable" would otherwise be
// ignored and the sample would silently be treated as unlabelled.
func ParseManifest(data []byte, sourcePath string) (*Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("eval: parse manifest %s: %w", displayPath(sourcePath), err)
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return nil, fmt.Errorf("eval: parse manifest %s: %w", displayPath(sourcePath), err)
	}

	m.SourcePath = sourcePath
	if err := m.Resolve(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ensureNoTrailingJSON rejects a second JSON document glued onto the first,
// which is how a truncated-then-appended manifest silently loses samples.
func ensureNoTrailingJSON(dec *json.Decoder) error {
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected trailing data after the manifest object")
	}
	return nil
}

// Resolve computes every sample's filesystem path. It is idempotent and must
// be called (directly or via LoadManifest) before FullPath is meaningful.
func (m *Manifest) Resolve() error {
	base := m.Root
	if base == "" {
		base = filepath.Dir(m.SourcePath)
	}
	if base == "" {
		base = "."
	}
	base = filepath.Clean(base)
	if !filepath.IsAbs(base) {
		abs, err := filepath.Abs(base)
		if err == nil {
			base = abs
		}
	}
	m.Dir = base

	for i := range m.Samples {
		s := &m.Samples[i]
		s.Label = NormalizeLabel(firstNonEmpty(s.Label, m.Defaults.Label))
		if s.Period == "" {
			s.Period = strings.TrimSpace(m.Defaults.Period)
		}
		if s.Provenance.Source == "" {
			s.Provenance.Source = firstNonEmpty(s.Source, m.Defaults.Source)
		}
		if s.Provenance.License == "" {
			s.Provenance.License = m.Defaults.License
		}
		if s.Family == "" {
			s.Family = s.ExpectedFamily()
		}
		s.resolved = resolveSamplePath(base, s.Path)
	}
	return nil
}

// resolveSamplePath resolves a declared path against the manifest base
// directory. Absolute paths are used verbatim.
func resolveSamplePath(base, path string) string {
	p := filepath.FromSlash(strings.TrimSpace(path))
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) || isForeignAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(base, p))
}

// isForeignAbs recognises a Windows-style absolute path ("C:\x", "\\server\x")
// so a Windows-authored manifest is at least flagged rather than joined onto a
// POSIX base into something that looks relative but is nonsense.
func isForeignAbs(p string) bool {
	if strings.HasPrefix(p, `\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return false
}

// ── Validation ─────────────────────────────────────────────────────────────

// Severity classifies a validation issue.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Issue is one validation finding about one sample (or the manifest itself).
type Issue struct {
	Severity Severity `json:"severity"`
	SampleID string   `json:"sample_id,omitempty"`
	Path     string   `json:"path,omitempty"`
	Field    string   `json:"field,omitempty"`
	Message  string   `json:"message"`
}

func (i Issue) String() string {
	loc := i.SampleID
	if loc == "" {
		loc = i.Path
	}
	if loc == "" {
		loc = "<manifest>"
	}
	return fmt.Sprintf("[%s] %s: %s", i.Severity, loc, i.Message)
}

// ValidateOptions tunes Manifest.Validate. The zero value is the recommended
// configuration.
type ValidateOptions struct {
	// FS defaults to OSFS.
	FS FileSystem
	// VerifyHashes recomputes SHA-256 for samples that declare one and fails
	// on mismatch. A corpus whose contents drifted from its manifest is worse
	// than no corpus.
	VerifyHashes bool
	// RequireProvenance upgrades "malware sample with no provenance" from a
	// warning to an error.
	RequireProvenance bool
	// MaxFileSize, when > 0, warns about samples larger than this many bytes.
	MaxFileSize int64
}

func (o ValidateOptions) normalized() ValidateOptions {
	if o.FS == nil {
		o.FS = OSFS{}
	}
	return o
}

// Validation is the result of Manifest.Validate.
type Validation struct {
	Manifest string  `json:"manifest"`
	Root     string  `json:"root"`
	Samples  int     `json:"samples"`
	Checked  int     `json:"checked"`
	Benign   int     `json:"benign"`
	Malware  int     `json:"malware"`
	Issues   []Issue `json:"issues"`
}

// OK reports whether validation found no errors. Warnings do not clear it.
func (v *Validation) OK() bool { return v.errorCount() == 0 }

// ErrorCount returns the number of error-severity issues.
func (v *Validation) ErrorCount() int { return v.errorCount() }

// WarningCount returns the number of warning-severity issues.
func (v *Validation) WarningCount() int { return v.warningCount() }

func (v *Validation) errorCount() int {
	n := 0
	for _, i := range v.Issues {
		if i.Severity == SeverityError {
			n++
		}
	}
	return n
}

func (v *Validation) warningCount() int {
	n := 0
	for _, i := range v.Issues {
		if i.Severity == SeverityWarning {
			n++
		}
	}
	return n
}

// Errors returns only the error-severity issues.
func (v *Validation) Errors() []Issue { return v.filter(SeverityError) }

// Warnings returns only the warning-severity issues.
func (v *Validation) Warnings() []Issue { return v.filter(SeverityWarning) }

func (v *Validation) filter(s Severity) []Issue {
	var out []Issue
	for _, i := range v.Issues {
		if i.Severity == s {
			out = append(out, i)
		}
	}
	return out
}

// Err returns nil when OK, otherwise a single error summarising every issue.
func (v *Validation) Err() error {
	if v.OK() {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "eval: corpus manifest %s has %d error(s)", displayPath(v.Manifest), v.errorCount())
	for _, i := range v.Errors() {
		fmt.Fprintf(&b, "\n  %s", i.String())
	}
	return fmt.Errorf("%s", b.String())
}

// WriteText renders the validation as a readable report.
func (v *Validation) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "corpus %s\n  root    : %s\n  samples : %d (%d benign, %d malware, %d checked)\n",
		displayPath(v.Manifest), v.Root, v.Samples, v.Benign, v.Malware, v.Checked)
	for _, i := range v.Issues {
		fmt.Fprintf(w, "  %s\n", i.String())
	}
	if len(v.Issues) == 0 {
		fmt.Fprintln(w, "  no issues")
	}
	return nil
}

func (v *Validation) String() string {
	var b strings.Builder
	_ = v.WriteText(&b)
	return b.String()
}

// Validate checks the manifest without running a single detector. It reports
// missing files, path escapes, label problems, hash drift and provenance gaps.
//
// Any error-severity issue makes the corpus unusable for measurement: run
// [Runner.Run] only after checking [Validation.OK].
func (m *Manifest) Validate(opts ValidateOptions) *Validation {
	opts = opts.normalized()

	v := &Validation{
		Manifest: m.SourcePath,
		Root:     m.Dir,
		Samples:  len(m.Samples),
	}

	add := func(sev Severity, s *Sample, field, format string, args ...any) {
		issue := Issue{Severity: sev, Field: field, Message: fmt.Sprintf(format, args...)}
		if s != nil {
			issue.SampleID = s.Key()
			issue.Path = s.Path
		}
		v.Issues = append(v.Issues, issue)
	}

	if m.SchemaVersion != "" && m.SchemaVersion != SchemaVersion {
		add(SeverityError, nil, "schema_version",
			"unsupported schema_version %q (this build understands %q)", m.SchemaVersion, SchemaVersion)
	}
	if len(m.Samples) == 0 {
		add(SeverityError, nil, "samples", "corpus contains no samples")
	}
	if isForeignAbs(m.Dir) {
		add(SeverityWarning, nil, "root", "root %q looks like a Windows path; manifests are resolved on the host running the harness", m.Dir)
	}

	seenID := make(map[string]int)
	seenPath := make(map[string]int)

	for i := range m.Samples {
		s := &m.Samples[i]

		if s.ID == "" {
			add(SeverityWarning, s, "id",
				"no id; baseline diffing will fall back to the declared path, which breaks if the corpus moves")
		} else if prev, dup := seenID[s.ID]; dup {
			add(SeverityError, s, "id", "duplicate id (already used by sample #%d)", prev)
		} else {
			seenID[s.ID] = i
		}

		if s.Path == "" {
			add(SeverityError, s, "path", "empty path")
			continue
		}
		if prev, dup := seenPath[s.resolved]; dup {
			add(SeverityWarning, s, "path", "same file as sample #%d (%s)", prev, s.resolved)
		} else {
			seenPath[s.resolved] = i
		}

		if s.Label == "" {
			add(SeverityError, s, "label", "no label and no manifest default; every sample must declare clean or a family name")
		}

		if isForeignAbs(s.Path) || filepath.IsAbs(s.Path) {
			add(SeverityWarning, s, "path", "absolute path %q; manifests should use paths relative to the corpus root", s.Path)
		} else if !withinRoot(m.Dir, s.resolved) {
			add(SeverityError, s, "path", "path escapes the corpus root (%s)", m.Dir)
		}

		// ── filesystem ──
		full := s.resolved
		if full == "" {
			continue
		}
		info, err := opts.FS.Stat(full)
		switch {
		case os.IsNotExist(err):
			add(SeverityError, s, "path", "sample not found: %s", full)
			continue
		case err != nil:
			add(SeverityError, s, "path", "cannot stat sample %s: %v", full, err)
			continue
		case info.IsDir():
			add(SeverityError, s, "path", "sample is a directory: %s", full)
			continue
		case info.Size() == 0:
			add(SeverityWarning, s, "path", "sample is empty: %s", full)
		}

		v.Checked++

		// ── label bookkeeping ──
		if s.Benign() {
			v.Benign++
		} else {
			v.Malware++
		}

		// ── content hash ──
		if s.SHA256 != "" {
			want := strings.ToLower(strings.TrimSpace(s.SHA256))
			switch {
			case !isSHA256(want):
				add(SeverityError, s, "sha256", "malformed sha256 %q (want 64 hex characters)", s.SHA256)
			case opts.VerifyHashes:
				data, rerr := opts.FS.ReadFile(full)
				if rerr != nil {
					add(SeverityError, s, "sha256", "cannot read sample to verify hash: %v", rerr)
				} else {
					sum := sha256.Sum256(data)
					if got := hex.EncodeToString(sum[:]); got != want {
						add(SeverityError, s, "sha256",
							"content drift: manifest says %s, file hashes to %s", want, got)
					}
				}
			}
		}

		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			add(SeverityWarning, s, "path", "sample is %d bytes, over the %d byte budget", info.Size(), opts.MaxFileSize)
		}

		// ── provenance ──
		sev := SeverityWarning
		if opts.RequireProvenance && !s.Benign() {
			sev = SeverityError
		}
		if !s.Benign() && s.Provenance.Source == "" {
			add(sev, s, "provenance.source", "malware sample has no provenance source recorded")
		} else if s.Provenance.Source != "" && s.Provenance.License == "" {
			add(SeverityWarning, s, "provenance.license", "provenance records a source but no licence")
		}
	}

	sortIssues(v.Issues)
	return v
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Severity != b.Severity {
			// errors first: a manifest with errors is unusable regardless of
			// how many warnings it also has.
			return a.Severity == SeverityError
		}
		if a.SampleID != b.SampleID {
			return a.SampleID < b.SampleID
		}
		return a.Message < b.Message
	})
}

// ── helpers ────────────────────────────────────────────────────────────────

// withinRoot reports whether p is base itself or lives underneath it.
func withinRoot(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func displayPath(p string) string {
	if p == "" {
		return "<memory>"
	}
	return p
}

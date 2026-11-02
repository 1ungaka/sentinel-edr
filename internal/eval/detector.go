package eval

import (
	"errors"
	"sort"
	"strings"
	"time"
)

// Verdict is the outcome of scanning one sample.
type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictMalicious  Verdict = "MALICIOUS"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictUnknown    Verdict = "UNKNOWN"
	VerdictError      Verdict = "ERROR"
)

// Canonical detector identifiers. Per-detector metrics are keyed by the
// Detector.Name of the detector, so these are conventions rather than a closed
// set; a new detector may use any stable name.
const (
	DetectorHash      = "hash"
	DetectorYara      = "yara"
	DetectorHeuristic = "heuristic"
	DetectorStatic    = "static"
	DetectorStego     = "stego"
	DetectorEncChain  = "encchain"
	DetectorFusion    = "fusion"
)

// Signal is one reason a detector believes a sample is malicious. Signals are
// the unit of attribution: per-rule and per-family breakdowns are built from
// them, so a detector that cannot name *why* it fired contributes to the
// confusion matrix but nothing to the triage list.
type Signal struct {
	// Detector is the logical detector that produced the signal. It defaults
	// to the scanning Detector's Name when empty.
	Detector string `json:"detector,omitempty"`
	// Rule is the matching rule or signature name ("wannacry_ransomware",
	// "WannaCry Ransomware"). This is the key used for per-rule metrics.
	Rule string `json:"rule,omitempty"`
	// Family is the family the rule claims to detect, when it declares one.
	Family string `json:"family,omitempty"`
	// Detail is free-form context (hash type, score vs threshold, offsets).
	Detail string `json:"detail,omitempty"`
}

// DetectorScore is the numeric score a scored detector assigned a sample,
// recorded even when the score stayed below the detector's firing threshold.
// It is the raw material for the near-miss metric: a benign file that scored
// just under the line is the one a threshold nudge would turn into a false
// positive, and a clean corpus that never records sub-threshold scores can
// only measure the false positives it already has, never how close it came.
//
// Binary detectors (hash, yara, fusion) have no margin — a byte pattern
// either matches or it does not — so they do not emit a DetectorScore.
type DetectorScore struct {
	Detector  string `json:"detector"`
	Score     int    `json:"score"`
	Threshold int    `json:"threshold"`
}

// Margin is how far the score sat below the firing threshold. A margin of 0
// or less means the detector fired (or was exactly at the line); a small
// positive margin is a near miss.
func (d DetectorScore) Margin() int { return d.Threshold - d.Score }

// Finding is the result of scanning one sample with one detector.
type Finding struct {
	Path    string   `json:"path"`
	Verdict Verdict  `json:"verdict"`
	Signals []Signal `json:"signals,omitempty"`
	// Scores carries the numeric score of every scored detector that looked
	// at the sample, including those that did not fire. Unset for detectors
	// that have no notion of a score.
	Scores   []DetectorScore `json:"scores,omitempty"`
	Duration time.Duration   `json:"-"`
	Err      error           `json:"-"`
}

// Detected reports whether any signal fired. This, not the verdict string, is
// what the confusion matrix is built from: a detector that returns SUSPICIOUS
// with no signal, or MALICIOUS with a signal it forgot to record, would
// otherwise be silently mis-measured.
func (f Finding) Detected() bool { return len(f.Signals) > 0 }

// Error returns the scan error, if any.
func (f Finding) Error() error { return f.Err }

// SignalsFor returns the signals attributed to one detector, falling back to
// the supplied default when a signal left the field blank.
func (f Finding) SignalsFor(detector string) []Signal {
	var out []Signal
	for _, s := range f.Signals {
		name := s.Detector
		if name == "" {
			name = detector
		}
		if strings.EqualFold(name, detector) {
			out = append(out, s)
		}
	}
	return out
}

// DetectorNames returns the sorted, de-duplicated detectors that fired.
func (f Finding) DetectorNames() []string {
	seen := make(map[string]struct{}, len(f.Signals))
	for _, s := range f.Signals {
		if s.Detector != "" {
			seen[s.Detector] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Normalize stamps missing detector names onto the signals and returns the
// finding. Empty verdicts are filled in from the signals.
func (f Finding) Normalize(detector string) Finding {
	for i := range f.Signals {
		if f.Signals[i].Detector == "" {
			f.Signals[i].Detector = detector
		}
	}
	switch {
	case f.Err != nil:
		f.Verdict = VerdictError
	case f.Verdict == "" || f.Verdict == VerdictUnknown:
		if f.Detected() {
			f.Verdict = VerdictMalicious
		} else {
			f.Verdict = VerdictClean
		}
	}
	return f
}

// Detector is the seam between the evaluation harness and whatever actually
// inspects bytes. The harness never imports the scanner; a caller wires the
// two together (see internal/eval/scannerbridge).
//
// Implementations must be safe for concurrent use: the runner may call
// ScanFile from several goroutines at once.
type Detector interface {
	// Name is a stable identifier used for per-detector attribution in
	// reports and baselines. Changing it breaks baseline continuity.
	Name() string
	// ScanFile inspects one file. Returning a Finding with signals is how a
	// detector reports a detection; returning an error means "could not
	// scan", which the runner records separately from "scanned and found
	// nothing".
	ScanFile(path string) (Finding, error)
}

// DetectorFunc adapts a function to the Detector interface.
type DetectorFunc struct {
	DetectorName string
	Fn           func(path string) (Finding, error)
}

func (d DetectorFunc) Name() string { return d.DetectorName }

func (d DetectorFunc) ScanFile(path string) (Finding, error) {
	if d.Fn == nil {
		return Finding{Path: path}, nil
	}
	return d.Fn(path)
}

// Ensure the adapters satisfy the interface at compile time.
var (
	_ Detector = DetectorFunc{}
	_ Detector = (*CompositeDetector)(nil)
)

// ErrNotConfigured is returned by detectors that were constructed without the
// content they need (an empty signature database, no rules path, ...). The
// runner treats it as a hard configuration error rather than a sample failure,
// because "silently detects nothing" is the worst possible outcome for an
// evaluation harness.
var ErrNotConfigured = errors.New("eval: detector not configured")

// CompositeDetector runs several detectors over the same file and merges their
// signals into a single finding. It exists so a caller can treat "the engine"
// as one detector while still reporting per-detector attribution.
type CompositeDetector struct {
	CompositeName string
	Detectors     []Detector
}

func (c *CompositeDetector) Name() string {
	if c.CompositeName != "" {
		return c.CompositeName
	}
	return "composite"
}

func (c *CompositeDetector) ScanFile(path string) (Finding, error) {
	out := Finding{Path: path, Verdict: VerdictClean}
	var errs []error

	for _, d := range c.Detectors {
		if d == nil {
			continue
		}
		f, err := d.ScanFile(path)
		if err != nil {
			if errors.Is(err, ErrNotConfigured) {
				return Finding{Path: path, Verdict: VerdictError, Err: err}, err
			}
			errs = append(errs, err)
			f = f.Normalize(d.Name())
			f.Err = err
			out.Verdict = VerdictError
			continue
		}
		f = f.Normalize(d.Name())
		out.Signals = append(out.Signals, f.Signals...)
		out.Scores = append(out.Scores, f.Scores...)
		if len(f.Signals) > 0 {
			out.Verdict = VerdictMalicious
		}
		out.Duration += f.Duration
	}

	if len(out.Signals) == 0 && out.Verdict == VerdictClean && len(errs) > 0 {
		return Finding{Path: path, Verdict: VerdictError, Err: errors.Join(errs...)}, errors.Join(errs...)
	}
	if len(errs) > 0 {
		out.Err = errors.Join(errs...)
	}
	return out, nil
}

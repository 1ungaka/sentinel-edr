package eval

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// The temporal gate asks one question about the shipped content: does it
// still catch what it caught, when the samples come from a later period?
//
// Temporal snooping is the field's most widespread evaluation flaw — a
// detector (or a model) tuned on everything at once looks best in
// distribution and is often the worst across a time boundary. A corpus that
// carries the period each sample belongs to makes the boundary explicit: the
// content is scored on the earlier periods and on the later ones, and a drop
// across the boundary is a finding rather than a footnote.
//
// This is the engine-side form of the rule. There is no model here: the thing
// that has to generalise is the shipped detection content, and the gate says
// how much of it did not.

// Period is a sample's time period. It is a string that sorts
// chronologically: "2026", "2026-10", "2026-Q3", "2026-10-24".
type Period = string

// TemporalSplit is a corpus cut into an earlier and a later half.
type TemporalSplit struct {
	// Early holds the samples from the periods before the split.
	Early *Manifest
	// Late holds the samples from the split period on.
	Late *Manifest
	// Split is the period that opens the later half.
	Split string
	// Periods are every period in the corpus, in order.
	Periods []string
	// Undated counts the samples that declare no period. They are left out of
	// both halves: a sample with no period has no place on the timeline.
	Undated int
}

// SamplePeriod is the period a sample belongs to, or "" when it declares none.
func SamplePeriod(s Sample) string {
	return strings.TrimSpace(s.Period)
}

// SplitByPeriod cuts a manifest on the samples' declared periods.
//
// The split point is the median period, so both halves hold samples: a corpus
// with three periods is cut after the first. An explicit split names the
// period that opens the later half.
func SplitByPeriod(m *Manifest, split string) (*TemporalSplit, error) {
	if m == nil {
		return nil, fmt.Errorf("eval: nil manifest")
	}
	periods := map[string]bool{}
	undated := 0
	for _, s := range m.Samples {
		p := SamplePeriod(s)
		if p == "" {
			undated++
			continue
		}
		periods[p] = true
	}
	if len(periods) < 2 {
		return nil, fmt.Errorf("eval: the corpus declares %d period(s); the temporal gate needs at least two", len(periods))
	}
	list := make([]string, 0, len(periods))
	for p := range periods {
		list = append(list, p)
	}
	sort.Strings(list)

	cut := list[len(list)/2]
	if split != "" {
		if !periods[split] {
			return nil, fmt.Errorf("eval: no sample declares the period %q", split)
		}
		cut = split
	}

	out := &TemporalSplit{Split: cut, Periods: list, Undated: undated}
	out.Early = subsetManifest(m, func(p Period) bool { return p != "" && p < cut })
	out.Late = subsetManifest(m, func(p Period) bool { return p != "" && p >= cut })
	if len(out.Early.Samples) == 0 || len(out.Late.Samples) == 0 {
		return nil, fmt.Errorf("eval: the split at %q leaves one side empty", cut)
	}
	return out, nil
}

// subsetManifest copies the manifest with the samples the predicate keeps.
func subsetManifest(m *Manifest, keep func(Period) bool) *Manifest {
	out := &Manifest{
		SchemaVersion: m.SchemaVersion,
		Name:          m.Name,
		Description:   m.Description,
		Root:          m.Root,
		Defaults:      m.Defaults,
		SourcePath:    m.SourcePath,
		Dir:           m.Dir,
	}
	for _, s := range m.Samples {
		if keep(SamplePeriod(s)) {
			out.Samples = append(out.Samples, s)
		}
	}
	return out
}

// TemporalResult is the measurement on both sides of the boundary.
type TemporalResult struct {
	// Split is the period that opens the later half.
	Split string `json:"split"`
	// Periods are every period in the corpus, in order.
	Periods      []string `json:"periods"`
	Early        Counts   `json:"early"`
	Late         Counts   `json:"late"`
	EarlyMetrics Ratios   `json:"early_metrics"`
	LateMetrics  Ratios   `json:"late_metrics"`
	// RecallDrop is the early recall minus the late recall, in points. It is
	// undefined when either side has no positives.
	RecallDrop *float64 `json:"recall_drop,omitempty"`
	// PrecisionDrop is the early precision minus the late precision.
	PrecisionDrop *float64 `json:"precision_drop,omitempty"`
	// FPRRise is the late false-positive rate minus the early one.
	FPRRise *float64 `json:"fpr_rise,omitempty"`
	// PerDetector is the same measurement per detector.
	PerDetector []TemporalDetector `json:"per_detector,omitempty"`
	// Undated counts the samples that declared no period and were left out.
	Undated int `json:"undated,omitempty"`
}

// TemporalDetector is one detector's measurement across the boundary.
type TemporalDetector struct {
	Detector    string `json:"detector"`
	Early       Counts `json:"early"`
	Late        Counts `json:"late"`
	EarlyRecall Ratio  `json:"early_recall"`
	LateRecall  Ratio  `json:"late_recall"`
	// RecallDrop is the early recall minus the late recall, in points.
	RecallDrop *float64 `json:"recall_drop,omitempty"`
}

// MeasureTemporal scores a run on both sides of the boundary.
//
// The run is measured once and split: the samples' results are partitioned by
// the period their manifest sample declared, so both halves are scored by the
// same scan.
func MeasureTemporal(m *Manifest, run *Run, split *TemporalSplit) *TemporalResult {
	res := &TemporalResult{
		Split:   split.Split,
		Periods: split.Periods,
		Undated: split.Undated,
	}
	earlyKeys := map[string]bool{}
	for _, s := range split.Early.Samples {
		earlyKeys[s.Key()] = true
	}
	var early, late []SampleResult
	for _, sr := range run.Samples {
		if earlyKeys[sr.Key()] {
			early = append(early, sr)
			continue
		}
		late = append(late, sr)
	}
	res.Early = countsFor(early)
	res.Late = countsFor(late)
	res.EarlyMetrics = ComputeRatios(res.Early)
	res.LateMetrics = ComputeRatios(res.Late)
	res.RecallDrop = drop(res.EarlyMetrics.Recall, res.LateMetrics.Recall)
	res.PrecisionDrop = drop(res.EarlyMetrics.Precision, res.LateMetrics.Precision)
	res.FPRRise = rise(res.EarlyMetrics.FPR, res.LateMetrics.FPR)

	for _, name := range detectorNames(run) {
		e := countsForDetector(early, name)
		l := countsForDetector(late, name)
		td := TemporalDetector{
			Detector:    name,
			Early:       e,
			Late:        l,
			EarlyRecall: ComputeRatios(e).Recall,
			LateRecall:  ComputeRatios(l).Recall,
		}
		td.RecallDrop = drop(td.EarlyRecall, td.LateRecall)
		res.PerDetector = append(res.PerDetector, td)
	}
	return res
}

// countsFor counts the confusion matrix of a set of sample results.
func countsFor(samples []SampleResult) Counts {
	var c Counts
	for _, s := range samples {
		if !s.Scored {
			continue
		}
		benign := IsBenign(s.Expected)
		switch {
		case s.Detected && benign:
			c.FP++
		case s.Detected && !benign:
			c.TP++
		case !s.Detected && benign:
			c.TN++
		default:
			c.FN++
		}
	}
	return c
}

// countsForDetector counts one detector's matrix over a set of samples.
func countsForDetector(samples []SampleResult, detector string) Counts {
	var c Counts
	for _, s := range samples {
		if !s.Scored {
			continue
		}
		benign := IsBenign(s.Expected)
		fired := false
		for _, sig := range s.Signals {
			if sig.Detector == detector {
				fired = true
				break
			}
		}
		switch {
		case fired && benign:
			c.FP++
		case fired && !benign:
			c.TP++
		case !fired && benign:
			c.TN++
		default:
			c.FN++
		}
	}
	return c
}

// detectorNames lists the detectors a run used, in order.
func detectorNames(run *Run) []string {
	if run == nil {
		return nil
	}
	out := make([]string, 0, len(run.Info.Detectors))
	for _, d := range run.Info.Detectors {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// drop is the difference between two ratios, undefined when either is.
func drop(early, late Ratio) *float64 {
	if !early.Defined || !late.Defined {
		return nil
	}
	v := early.Value - late.Value
	return &v
}

// rise is the difference between two ratios, undefined when either is.
func rise(early, late Ratio) *float64 {
	if !early.Defined || !late.Defined {
		return nil
	}
	v := late.Value - early.Value
	return &v
}

// TemporalDecision is the gate's verdict on a temporal measurement.
type TemporalDecision struct {
	Pass       bool        `json:"pass"`
	Violations []Violation `json:"violations"`
	Notes      []string    `json:"notes,omitempty"`
}

// Err returns nil on pass, otherwise an error listing every violation.
func (d TemporalDecision) Err() error {
	if d.Pass {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "eval: temporal gate failed with %d violation(s)", len(d.Violations))
	for _, v := range d.Violations {
		fmt.Fprintf(&b, "\n  %s", v.String())
	}
	return fmt.Errorf("%s", b.String())
}

// WriteText renders the decision.
func (d TemporalDecision) WriteText(w io.Writer) error {
	if d.Pass {
		fmt.Fprintln(w, "temporal gate: PASS")
	} else {
		fmt.Fprintf(w, "temporal gate: FAIL (%d violation(s))\n", len(d.Violations))
	}
	for _, v := range d.Violations {
		fmt.Fprintf(w, "  ✗ %s\n", v.String())
	}
	for _, n := range d.Notes {
		fmt.Fprintf(w, "  · %s\n", n)
	}
	return nil
}

// TemporalGate evaluates a temporal measurement under a policy.
//
// The rule is the policy's max_recall_drop, applied across the period
// boundary: the content must not lose more than that much recall between the
// earlier periods and the later ones. A per-detector max_recall_drop is
// applied the same way.
//
// An undefined metric is never a violation: a period with no malware in it
// says nothing about recall.
func TemporalGate(res *TemporalResult, p Policy) TemporalDecision {
	d := TemporalDecision{Pass: true, Violations: []Violation{}}
	if res == nil {
		d.Pass = false
		d.Violations = append(d.Violations, Violation{Rule: "temporal", Scope: "overall", Message: "no temporal measurement"})
		return d
	}
	allowed := -1.0
	if p.MaxRecallDrop != nil {
		allowed = *p.MaxRecallDrop
	}
	if allowed >= 0 {
		switch {
		case res.RecallDrop == nil:
			d.Notes = append(d.Notes, "recall is undefined on one side of the boundary: the rule was skipped")
		case *res.RecallDrop > allowed+1e-12:
			d.Pass = false
			d.Violations = append(d.Violations, Violation{
				Rule:      "max_recall_drop",
				Scope:     "temporal",
				Message:   fmt.Sprintf("recall dropped %.2f pt across the %s boundary, at most %.2f pt allowed", *res.RecallDrop*100, res.Split, allowed*100),
				Baseline:  res.EarlyMetrics.Recall.Percent(),
				Candidate: res.LateMetrics.Recall.Percent(),
			})
		}
	}
	for _, td := range res.PerDetector {
		dp, ok := p.PerDetector[td.Detector]
		if !ok || dp.MaxRecallDrop == nil {
			continue
		}
		switch {
		case td.RecallDrop == nil:
			d.Notes = append(d.Notes, fmt.Sprintf("%s: recall is undefined on one side of the boundary: the rule was skipped", td.Detector))
		case *td.RecallDrop > *dp.MaxRecallDrop+1e-12:
			d.Pass = false
			d.Violations = append(d.Violations, Violation{
				Rule:      "max_recall_drop",
				Scope:     "detector:" + td.Detector,
				Message:   fmt.Sprintf("recall dropped %.2f pt across the %s boundary, at most %.2f pt allowed", *td.RecallDrop*100, res.Split, *dp.MaxRecallDrop*100),
				Baseline:  td.EarlyRecall.Percent(),
				Candidate: td.LateRecall.Percent(),
			})
		}
	}
	return d
}

// WriteText renders the measurement.
func (r *TemporalResult) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "temporal generalization\n")
	fmt.Fprintf(w, "  periods : %s\n", strings.Join(r.Periods, ", "))
	fmt.Fprintf(w, "  split   : %s (earlier periods before it, later periods from it)\n", r.Split)
	if r.Undated > 0 {
		fmt.Fprintf(w, "  undated : %d sample(s) declare no period and were left out\n", r.Undated)
	}
	fmt.Fprintf(w, "  earlier : %s  recall %s  precision %s\n", r.Early.String(), r.EarlyMetrics.Recall.Percent(), r.EarlyMetrics.Precision.Percent())
	fmt.Fprintf(w, "  later   : %s  recall %s  precision %s\n", r.Late.String(), r.LateMetrics.Recall.Percent(), r.LateMetrics.Precision.Percent())
	switch {
	case r.RecallDrop == nil:
		fmt.Fprintln(w, "  recall drop across the boundary: undefined (one side has no positives)")
	case *r.RecallDrop > 0:
		fmt.Fprintf(w, "  recall drop across the boundary: %.2f pt\n", *r.RecallDrop*100)
	default:
		fmt.Fprintf(w, "  recall drop across the boundary: %.2f pt (the later period did better)\n", *r.RecallDrop*100)
	}
	if len(r.PerDetector) > 0 {
		fmt.Fprintln(w, "  per detector:")
		for _, td := range r.PerDetector {
			drop := "undefined"
			if td.RecallDrop != nil {
				drop = fmt.Sprintf("%.2f pt", *td.RecallDrop*100)
			}
			fmt.Fprintf(w, "    %-14s earlier %-8s later %-8s drop %s\n", td.Detector,
				td.EarlyRecall.Percent(), td.LateRecall.Percent(), drop)
		}
	}
	return nil
}

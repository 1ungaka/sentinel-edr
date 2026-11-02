package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReportSchemaVersion versions the persisted report/baseline format.
const ReportSchemaVersion = "1"

// Ratio is a metric value that may legitimately not exist.
//
// "Precision" over a run that flagged nothing is not 0% — it is undefined, and
// reporting it as 0% would invent a regression on every rule change that
// happens to touch no benign sample. Undefined values serialise as JSON null
// and print as "n/a", and the regression policy treats them as "no
// information" rather than as a number.
type Ratio struct {
	Value   float64 `json:"value"`
	Defined bool    `json:"defined"`
}

// NewRatio computes num/den, yielding an undefined Ratio when den == 0.
func NewRatio(num, den int) Ratio {
	if den == 0 {
		return Ratio{}
	}
	return Ratio{Value: float64(num) / float64(den), Defined: true}
}

// DefinedRatio wraps a float as a defined Ratio.
func DefinedRatio(v float64) Ratio { return Ratio{Value: v, Defined: true} }

// UndefinedRatio is the zero Ratio.
func UndefinedRatio() Ratio { return Ratio{} }

func (r Ratio) String() string {
	if !r.Defined {
		return "n/a"
	}
	return fmt.Sprintf("%.4f", r.Value)
}

// Percent renders the ratio as a percentage, or "n/a".
func (r Ratio) Percent() string { return percentString(r) }

// MarshalJSON emits a bare number, or null when undefined, so baselines stay
// readable and diffable.
func (r Ratio) MarshalJSON() ([]byte, error) {
	if !r.Defined {
		return []byte("null"), nil
	}
	return []byte(strconvFormat(r.Value)), nil
}

// UnmarshalJSON accepts both forms so a saved baseline reloads losslessly.
func (r *Ratio) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if bytes.Equal(trimmed, []byte("null")) {
		*r = Ratio{}
		return nil
	}
	var v float64
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return fmt.Errorf("eval: bad ratio %q: %w", string(trimmed), err)
	}
	*r = Ratio{Value: v, Defined: true}
	return nil
}

func strconvFormat(v float64) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "0"
	}
	return string(b)
}

// Counts is a confusion matrix.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

// Total returns the number of scored samples.
func (c Counts) Total() int { return c.TP + c.FP + c.TN + c.FN }

// Positives returns the samples that really are malicious (TP + FN).
func (c Counts) Positives() int { return c.TP + c.FN }

// Negatives returns the samples that really are benign (TN + FP).
func (c Counts) Negatives() int { return c.TN + c.FP }

// PredictedPositive returns the samples something flagged (TP + FP).
func (c Counts) PredictedPositive() int { return c.TP + c.FP }

func (c Counts) String() string {
	return fmt.Sprintf("tp=%d fp=%d tn=%d fn=%d", c.TP, c.FP, c.TN, c.FN)
}

// Ratios derives every headline metric from a confusion matrix.
//
// Conventions (each has a unit test):
//
//	precision   = TP/(TP+FP)  undefined when nothing was flagged
//	recall      = TP/(TP+FN)  undefined when the corpus holds no malware
//	f1          = 2PR/(P+R)   undefined when P or R is undefined
//	specificity = TN/(TN+FP)  undefined when the corpus holds no benign samples
//	fpr         = FP/(FP+TN)  undefined when the corpus holds no benign samples
//	accuracy    = (TP+TN)/N   undefined when nothing was scored
type Ratios struct {
	Precision   Ratio `json:"precision"`
	Recall      Ratio `json:"recall"`
	F1          Ratio `json:"f1"`
	Specificity Ratio `json:"specificity"`
	FPR         Ratio `json:"fpr"`
	Accuracy    Ratio `json:"accuracy"`
}

// ComputeRatios derives the metric set from a confusion matrix.
func ComputeRatios(c Counts) Ratios {
	r := Ratios{
		Precision:   NewRatio(c.TP, c.PredictedPositive()),
		Recall:      NewRatio(c.TP, c.Positives()),
		Specificity: NewRatio(c.TN, c.Negatives()),
		FPR:         NewRatio(c.FP, c.Negatives()),
		Accuracy:    NewRatio(c.TP+c.TN, c.Total()),
	}
	r.F1 = f1(r.Precision, r.Recall)
	return r
}

// f1 is the harmonic mean of precision and recall. With both defined and
// summing to zero (P == R == 0) the result is exactly 0, not a division error.
func f1(p, r Ratio) Ratio {
	if !p.Defined || !r.Defined {
		return Ratio{}
	}
	sum := p.Value + r.Value
	if sum == 0 {
		return Ratio{Value: 0, Defined: true}
	}
	return Ratio{Value: 2 * p.Value * r.Value / sum, Defined: true}
}

// RunInfo records how a run was produced. It travels into the report so a
// baseline carries its own provenance.
type RunInfo struct {
	Tool        string    `json:"tool,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	Corpus      string    `json:"corpus,omitempty"`
	CorpusName  string    `json:"corpus_name,omitempty"`
	CorpusRoot  string    `json:"corpus_root,omitempty"`
	Detectors   []string  `json:"detectors,omitempty"`
	Concurrency int       `json:"concurrency,omitempty"`
	OnError     string    `json:"on_error,omitempty"`
	MaxFileSize int64     `json:"max_file_size,omitempty"`
}

// SampleResult is the scored outcome of one sample.
type SampleResult struct {
	ID       string `json:"id,omitempty"`
	Path     string `json:"path"`
	FullPath string `json:"full_path,omitempty"`
	Expected string `json:"expected"`
	Family   string `json:"family,omitempty"`
	Size     int64  `json:"size,omitempty"`

	Detected  bool     `json:"detected"`
	Verdict   Verdict  `json:"verdict"`
	Signals   []Signal `json:"signals,omitempty"`
	Detectors []string `json:"detectors,omitempty"`

	// Scores carries the sub-threshold numeric scores of the scored
	// detectors. It is what the near-miss metric reads: a benign sample that
	// scored just below a threshold is a latent false positive.
	Scores []DetectorScore `json:"scores,omitempty"`

	// Scored reports whether the sample entered the confusion matrix.
	Scored bool `json:"scored"`
	// SkipReason explains a non-scored, non-errored sample.
	SkipReason string `json:"skip_reason,omitempty"`
	// Error is a non-empty scan error message.
	Error string `json:"error,omitempty"`
	// CountedAsMiss is true for an errored malicious sample that the run was
	// configured to charge to the FN column (OnErrorMiss). Such a sample is
	// Scored, not Detected, and also listed under Errors so a baseline can
	// explain its own numbers.
	CountedAsMiss bool `json:"counted_as_miss,omitempty"`

	// Duration is the scan time. It is persisted for the perf section but is
	// ignored by Diff and by the byte-stability contract of a report.
	Duration time.Duration `json:"duration_ns,omitempty"`

	// notConfigured marks an error that wraps ErrNotConfigured; the runner
	// turns it into a run-level failure.
	notConfigured bool
}

// Key is the identity used to match a sample across runs.
func (s SampleResult) Key() string {
	if s.ID != "" {
		return s.ID
	}
	return s.Path
}

// Run is the raw record produced by the runner, before metrics.
type Run struct {
	SchemaVersion string         `json:"schema_version"`
	Info          RunInfo        `json:"run"`
	Samples       []SampleResult `json:"samples"`
}

// DetectorStat is one detector's slice of the work.
//
// Exclusive counts samples that only this detector caught: removing the
// detector would turn exactly those true positives into misses. Without it,
// "yara contributed 40% of the hits" and "yara is redundant" look identical.
type DetectorStat struct {
	Detector  string `json:"detector"`
	Counts    Counts `json:"counts"`
	Metrics   Ratios `json:"metrics"`
	Fires     int    `json:"fires"`
	Exclusive int    `json:"exclusive_hits"`
}

// FamilyStat is the per-family view: how much of each family we miss, plus how
// often benign files get blamed on that family.
type FamilyStat struct {
	Family             string   `json:"family"`
	Samples            int      `json:"samples"`
	Detected           int      `json:"detected"`
	Missed             int      `json:"missed"`
	Recall             Ratio    `json:"recall"`
	FalsePositives     int      `json:"false_positives"`
	FalsePositivePaths []string `json:"false_positive_paths,omitempty"`
}

// RuleStat is the per-rule view. Rules that never fire on anything are absent;
// rules that only ever fire on benign samples are the ones worth reading.
type RuleStat struct {
	Rule               string   `json:"rule"`
	Detectors          []string `json:"detectors,omitempty"`
	Families           []string `json:"families,omitempty"`
	Fires              int      `json:"fires"`
	TruePositives      int      `json:"true_positives"`
	FalsePositives     int      `json:"false_positives"`
	FalsePositivePaths []string `json:"false_positive_paths,omitempty"`
}

// MarginBucket is one point of a near-miss histogram: how many benign samples
// scored exactly this far below a detector's firing threshold.
type MarginBucket struct {
	Margin int `json:"margin"`
	Count  int `json:"count"`
}

// NearMissStat answers, for one scored detector, the question a clean corpus
// cannot answer on its own: not "how many benign files did we flag" (that is
// the false-positive count) but "how many came close". A detector whose
// nearest benign file sits one point under the line is one threshold nudge
// away from a false-positive storm; one whose nearest benign file is far below
// has headroom. Only benign samples the detector actually scored (score > 0,
// below threshold) are counted — a file the detector never scored is not a
// near miss, it is a non-event.
type NearMissStat struct {
	Detector  string `json:"detector"`
	Threshold int    `json:"threshold"`
	// Scored is the number of benign samples this detector gave a non-zero
	// sub-threshold score.
	Scored int `json:"benign_scored"`
	// Band is the near-threshold width used for NearThreshold (a quarter of
	// the threshold, at least 1).
	Band int `json:"band"`
	// NearThreshold counts benign samples within Band of firing.
	NearThreshold int `json:"near_threshold"`
	// MinMargin is the smallest margin seen — how close the corpus came to a
	// false positive. -1 when the detector scored no benign sample.
	MinMargin int `json:"min_margin"`
	// Histogram is every observed margin and its count, ascending by margin.
	Histogram []MarginBucket `json:"histogram,omitempty"`
}

// FlaggedSample is a sample on the wrong side of the line, with enough context
// to fix it: which file, what was expected, which detector fired and why.
type FlaggedSample struct {
	Key       string   `json:"key"`
	Path      string   `json:"path"`
	FullPath  string   `json:"full_path,omitempty"`
	Expected  string   `json:"expected"`
	Family    string   `json:"family,omitempty"`
	Detectors []string `json:"detectors,omitempty"`
	Signals   []Signal `json:"signals,omitempty"`
	// ClaimedFamilies are the families the rules claimed. A clean file blamed
	// on "wannacry" is the most actionable line in the whole report.
	ClaimedFamilies []string `json:"claimed_families,omitempty"`
	Notes           string   `json:"notes,omitempty"`
}

// SampleError is a sample that could not be scored.
type SampleError struct {
	Key     string `json:"key"`
	Path    string `json:"path"`
	Message string `json:"message"`
	// CountedAsMiss is true when the run was configured to treat the error as
	// a miss rather than excluding it from the matrix.
	CountedAsMiss bool `json:"counted_as_miss,omitempty"`
}

// SkippedSample is a sample deliberately not scored.
type SkippedSample struct {
	Key    string `json:"key"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// SlowSample is one entry of the perf top list.
type SlowSample struct {
	Key      string        `json:"key"`
	Path     string        `json:"path"`
	Duration time.Duration `json:"duration_ns"`
}

// Perf summarises the cost of a run. Durations are per-sample scan times
// summed over samples, not wall-clock: with concurrency the wall clock is
// shorter, but the per-sample cost is what a budget gate should track.
type Perf struct {
	Samples       int           `json:"samples"`
	TotalDuration time.Duration `json:"total_duration_ns"`
	MeanDuration  time.Duration `json:"mean_duration_ns"`
	P50           time.Duration `json:"p50_ns"`
	P95           time.Duration `json:"p95_ns"`
	MaxDuration   time.Duration `json:"max_duration_ns"`
	BytesScanned  int64         `json:"bytes_scanned"`
	// Throughput is bytes per second of scan time.
	Throughput float64      `json:"throughput_bytes_per_s"`
	Slowest    []SlowSample `json:"slowest,omitempty"`
}

// Report is the complete, persistable measurement of one corpus run.
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Info          RunInfo        `json:"run"`
	Samples       []SampleResult `json:"samples"`

	Totals  Counts `json:"totals"`
	Metrics Ratios `json:"metrics"`

	ByDetector []DetectorStat `json:"by_detector"`
	ByFamily   []FamilyStat   `json:"by_family"`
	ByRule     []RuleStat     `json:"by_rule"`

	// NearMiss reports, per scored detector, how close benign samples came to
	// firing — the margin the clean false-positive count cannot show.
	NearMiss []NearMissStat `json:"near_miss,omitempty"`

	FalsePositives []FlaggedSample `json:"false_positives"`
	FalseNegatives []FlaggedSample `json:"false_negatives"`
	Errors         []SampleError   `json:"errors"`
	Skipped        []SkippedSample `json:"skipped"`

	Perf Perf `json:"perf"`
}

// NewReport computes the full metric set for a run. Every breakdown is sorted
// by key so two reports of the same corpus diff cleanly.
func NewReport(run *Run) *Report {
	if run == nil {
		run = &Run{}
	}
	rep := &Report{
		SchemaVersion:  ReportSchemaVersion,
		Info:           run.Info,
		Samples:        append([]SampleResult(nil), run.Samples...),
		FalsePositives: []FlaggedSample{},
		FalseNegatives: []FlaggedSample{},
		Errors:         []SampleError{},
		Skipped:        []SkippedSample{},
	}
	sort.SliceStable(rep.Samples, func(i, j int) bool { return rep.Samples[i].Key() < rep.Samples[j].Key() })

	byDetector := make(map[string]*DetectorStat, len(run.Info.Detectors))
	for _, d := range run.Info.Detectors {
		byDetector[d] = &DetectorStat{Detector: d}
	}
	byFamily := map[string]*FamilyStat{}
	familyFP := map[string][]string{}
	byRule := map[string]*RuleStat{}

	// Near-miss accumulators: detector -> margin -> count over benign samples
	// the detector scored but did not fire on, plus each detector's threshold.
	nearHist := map[string]map[int]int{}
	nearThreshold := map[string]int{}

	for _, s := range rep.Samples {
		if s.Error != "" {
			rep.Errors = append(rep.Errors, SampleError{
				Key: s.Key(), Path: s.Path, Message: s.Error, CountedAsMiss: s.CountedAsMiss,
			})
		}
		if !s.Scored {
			if s.Error == "" && s.SkipReason != "" {
				rep.Skipped = append(rep.Skipped, SkippedSample{Key: s.Key(), Path: s.Path, Reason: s.SkipReason})
			}
			continue
		}

		benign := IsBenign(s.Expected)
		switch {
		case s.Detected && benign:
			rep.Totals.FP++
			rep.FalsePositives = append(rep.FalsePositives, flagged(s))
		case s.Detected && !benign:
			rep.Totals.TP++
		case !s.Detected && benign:
			rep.Totals.TN++
		default:
			rep.Totals.FN++
			rep.FalseNegatives = append(rep.FalseNegatives, flagged(s))
		}

		// ── near miss ── a benign sample the detector scored but did not fire
		// on. Score > 0 excludes the overwhelming majority of files a scored
		// detector looks at and assigns nothing; margin > 0 excludes the ones
		// that fired (they are false positives, counted above, not near ones).
		if benign {
			for _, sc := range s.Scores {
				nearThreshold[sc.Detector] = sc.Threshold
				if sc.Score > 0 && sc.Margin() > 0 {
					h := nearHist[sc.Detector]
					if h == nil {
						h = map[int]int{}
						nearHist[sc.Detector] = h
					}
					h[sc.Margin()]++
				}
			}
		}

		// ── per detector ──
		fired := map[string]bool{}
		for _, sig := range s.Signals {
			name := sig.Detector
			if name == "" {
				name = "unknown"
			}
			fired[name] = true
			if _, ok := byDetector[name]; !ok {
				// A signal from a detector that was not registered for the
				// run: count it rather than drop it on the floor.
				byDetector[name] = &DetectorStat{Detector: name}
			}
		}
		for name, st := range byDetector {
			if fired[name] {
				st.Fires++
				if benign {
					st.Counts.FP++
				} else {
					st.Counts.TP++
				}
				if len(fired) == 1 && !benign {
					st.Exclusive++
				}
				continue
			}
			if benign {
				st.Counts.TN++
			} else {
				st.Counts.FN++
			}
		}

		// ── per rule ──
		seenRule := map[string]bool{}
		for _, sig := range s.Signals {
			key := sig.Rule
			if key == "" {
				key = "(unnamed)"
			}
			rs, ok := byRule[key]
			if !ok {
				rs = &RuleStat{Rule: key}
				byRule[key] = rs
			}
			rs.Detectors = addUnique(rs.Detectors, sig.Detector)
			rs.Families = addUnique(rs.Families, sig.Family)
			if seenRule[key] {
				continue // one fire per sample per rule
			}
			seenRule[key] = true
			rs.Fires++
			if benign {
				rs.FalsePositives++
				rs.FalsePositivePaths = append(rs.FalsePositivePaths, s.Path)
			} else {
				rs.TruePositives++
			}
		}

		// ── per family ──
		if benign {
			for _, f := range claimedFamilies(s) {
				familyFP[f] = append(familyFP[f], s.Path)
			}
		} else {
			fam := s.Family
			if fam == "" {
				fam = s.Expected
			}
			fs, ok := byFamily[fam]
			if !ok {
				fs = &FamilyStat{Family: fam}
				byFamily[fam] = fs
			}
			fs.Samples++
			if s.Detected {
				fs.Detected++
			} else {
				fs.Missed++
			}
		}
	}

	for fam, paths := range familyFP {
		fs, ok := byFamily[fam]
		if !ok {
			fs = &FamilyStat{Family: fam}
			byFamily[fam] = fs
		}
		sort.Strings(paths)
		fs.FalsePositives = len(paths)
		fs.FalsePositivePaths = paths
	}
	for _, fs := range byFamily {
		fs.Recall = NewRatio(fs.Detected, fs.Samples)
	}

	rep.Metrics = ComputeRatios(rep.Totals)
	rep.ByDetector = sortedDetectors(byDetector)
	rep.ByFamily = sortedFamilies(byFamily)
	rep.ByRule = sortedRules(byRule)
	rep.NearMiss = buildNearMiss(nearThreshold, nearHist)
	rep.Perf = computePerf(rep.Samples)

	sortFlagged(rep.FalsePositives)
	sortFlagged(rep.FalseNegatives)
	sort.SliceStable(rep.Errors, func(i, j int) bool { return rep.Errors[i].Key < rep.Errors[j].Key })
	sort.SliceStable(rep.Skipped, func(i, j int) bool { return rep.Skipped[i].Key < rep.Skipped[j].Key })
	return rep
}

// buildNearMiss turns the per-detector margin histograms into sorted
// NearMissStats. A detector that scored at least one benign sample appears
// even if nothing came near, so a reader can tell "no near misses" from "this
// detector was never exercised". The near band is a quarter of the threshold
// (at least 1): close enough that a routine threshold adjustment would turn
// the sample into a false positive.
func buildNearMiss(thresholds map[string]int, hist map[string]map[int]int) []NearMissStat {
	if len(thresholds) == 0 {
		return nil
	}
	out := make([]NearMissStat, 0, len(thresholds))
	for det, thr := range thresholds {
		band := thr / 4
		if band < 1 {
			band = 1
		}
		st := NearMissStat{Detector: det, Threshold: thr, Band: band, MinMargin: -1}
		margins := hist[det]
		buckets := make([]MarginBucket, 0, len(margins))
		for m, c := range margins {
			buckets = append(buckets, MarginBucket{Margin: m, Count: c})
			st.Scored += c
			if st.MinMargin == -1 || m < st.MinMargin {
				st.MinMargin = m
			}
			if m <= band {
				st.NearThreshold += c
			}
		}
		sort.Slice(buckets, func(i, j int) bool { return buckets[i].Margin < buckets[j].Margin })
		st.Histogram = buckets
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Detector < out[j].Detector })
	return out
}

// computePerf derives the perf section from per-sample durations. Only
// samples that were actually scanned (scored or errored, not skipped) count.
func computePerf(samples []SampleResult) Perf {
	var p Perf
	var durs []time.Duration
	var slow []SlowSample
	for _, s := range samples {
		if !s.Scored && s.Error == "" {
			continue
		}
		p.Samples++
		p.TotalDuration += s.Duration
		p.BytesScanned += s.Size
		durs = append(durs, s.Duration)
		if s.Duration > p.MaxDuration {
			p.MaxDuration = s.Duration
		}
		slow = append(slow, SlowSample{Key: s.Key(), Path: s.Path, Duration: s.Duration})
	}
	if p.Samples == 0 {
		return p
	}
	p.MeanDuration = p.TotalDuration / time.Duration(p.Samples)
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	p.P50 = percentile(durs, 50)
	p.P95 = percentile(durs, 95)
	if p.TotalDuration > 0 {
		p.Throughput = float64(p.BytesScanned) / p.TotalDuration.Seconds()
	}
	sort.SliceStable(slow, func(i, j int) bool {
		if slow[i].Duration != slow[j].Duration {
			return slow[i].Duration > slow[j].Duration
		}
		return slow[i].Key < slow[j].Key
	})
	if len(slow) > 5 {
		slow = slow[:5]
	}
	p.Slowest = slow
	return p
}

// percentile uses nearest-rank on a sorted slice.
func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := (pct*len(sorted) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// flagged builds a triage entry from a sample result.
func flagged(s SampleResult) FlaggedSample {
	notes := s.SkipReason
	if s.CountedAsMiss {
		notes = "scan error counted as miss: " + s.Error
	}
	return FlaggedSample{
		Key:             s.Key(),
		Path:            s.Path,
		FullPath:        s.FullPath,
		Expected:        s.Expected,
		Family:          s.Family,
		Detectors:       s.Detectors,
		Signals:         s.Signals,
		ClaimedFamilies: claimedFamilies(s),
		Notes:           notes,
	}
}

func claimedFamilies(s SampleResult) []string {
	var out []string
	for _, sig := range s.Signals {
		if sig.Family != "" {
			out = addUnique(out, sig.Family)
		}
	}
	sort.Strings(out)
	return out
}

func sortFlagged(fs []FlaggedSample) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Key != fs[j].Key {
			return fs[i].Key < fs[j].Key
		}
		return fs[i].Path < fs[j].Path
	})
}

func sortedDetectors(m map[string]*DetectorStat) []DetectorStat {
	out := make([]DetectorStat, 0, len(m))
	for _, st := range m {
		st.Metrics = ComputeRatios(st.Counts)
		out = append(out, *st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Detector < out[j].Detector })
	return out
}

func sortedFamilies(m map[string]*FamilyStat) []FamilyStat {
	out := make([]FamilyStat, 0, len(m))
	for _, fs := range m {
		out = append(out, *fs)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func sortedRules(m map[string]*RuleStat) []RuleStat {
	out := make([]RuleStat, 0, len(m))
	for _, rs := range m {
		sort.Strings(rs.Detectors)
		sort.Strings(rs.Families)
		sort.Strings(rs.FalsePositivePaths)
		out = append(out, *rs)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FalsePositives != out[j].FalsePositives {
			return out[i].FalsePositives > out[j].FalsePositives // worst first
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

func addUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

// ── small helpers shared by the text renderers ─────────────────────────────

// percentString renders a ratio as a percentage, or "n/a".
func percentString(r Ratio) string {
	if !r.Defined {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", r.Value*100)
}

// pointsDiff renders a signed change in percentage points, or "n/a".
func pointsDiff(r Ratio) string {
	if !r.Defined {
		return "n/a"
	}
	return fmt.Sprintf("%+.2f pt", r.Value*100)
}

// detectorStat finds a detector's stats in a report.
func (r *Report) detectorStat(name string) (DetectorStat, bool) {
	for _, d := range r.ByDetector {
		if d.Detector == name {
			return d, true
		}
	}
	return DetectorStat{}, false
}

// familyStat finds a family's stats in a report.
func (r *Report) familyStat(name string) (FamilyStat, bool) {
	for _, f := range r.ByFamily {
		if strings.EqualFold(f.Family, name) {
			return f, true
		}
	}
	return FamilyStat{}, false
}

// sampleByKey indexes a report's samples by Key.
func (r *Report) sampleByKey() map[string]SampleResult {
	out := make(map[string]SampleResult, len(r.Samples))
	for _, s := range r.Samples {
		out[s.Key()] = s
	}
	return out
}

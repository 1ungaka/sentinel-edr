package eval

import "testing"

// A corpus with three periods is cut at the median, so both halves hold
// samples.
func TestSplitByPeriodCutsAtTheMedian(t *testing.T) {
	m := manifestWithPeriods(map[string]string{
		"a": "2026-01", "b": "2026-01", "c": "2026-02", "d": "2026-02", "e": "2026-03",
	})
	split, err := SplitByPeriod(m, "")
	if err != nil {
		t.Fatal(err)
	}
	if split.Split != "2026-02" {
		t.Errorf("split = %q, want 2026-02", split.Split)
	}
	if len(split.Early.Samples) != 2 {
		t.Errorf("earlier half holds %d samples, want 2", len(split.Early.Samples))
	}
	if len(split.Late.Samples) != 3 {
		t.Errorf("later half holds %d samples, want 3", len(split.Late.Samples))
	}
}

// An explicit split names the period that opens the later half.
func TestSplitByPeriodHonoursAnExplicitSplit(t *testing.T) {
	m := manifestWithPeriods(map[string]string{
		"a": "2026-01", "b": "2026-02", "c": "2026-03", "d": "2026-04",
	})
	split, err := SplitByPeriod(m, "2026-03")
	if err != nil {
		t.Fatal(err)
	}
	if split.Split != "2026-03" {
		t.Errorf("split = %q", split.Split)
	}
	if len(split.Early.Samples) != 2 || len(split.Late.Samples) != 2 {
		t.Errorf("halves hold %d and %d samples", len(split.Early.Samples), len(split.Late.Samples))
	}
}

// A corpus with one period has no boundary to measure.
func TestSplitByPeriodNeedsTwoPeriods(t *testing.T) {
	m := manifestWithPeriods(map[string]string{"a": "2026-01", "b": "2026-01"})
	if _, err := SplitByPeriod(m, ""); err == nil {
		t.Fatal("a corpus with one period was split")
	}
}

// Samples with no period are left out of both halves and counted.
func TestSplitByPeriodCountsTheUndatedSamples(t *testing.T) {
	m := manifestWithPeriods(map[string]string{
		"a": "2026-01", "b": "2026-02", "c": "",
	})
	split, err := SplitByPeriod(m, "")
	if err != nil {
		t.Fatal(err)
	}
	if split.Undated != 1 {
		t.Errorf("undated = %d, want 1", split.Undated)
	}
	for _, s := range append(split.Early.Samples, split.Late.Samples...) {
		if s.ID == "c" {
			t.Error("an undated sample was put on one side of the boundary")
		}
	}
}

// The measurement scores both sides, and the drop is the difference.
func TestMeasureTemporalScoresBothSides(t *testing.T) {
	m := manifestWithPeriods(map[string]string{
		"m1": "2026-01", "m2": "2026-01", "m3": "2026-02", "b1": "2026-02",
	})
	split, err := SplitByPeriod(m, "")
	if err != nil {
		t.Fatal(err)
	}
	run := &Run{
		Info: RunInfo{Detectors: []string{"yara"}},
		Samples: []SampleResult{
			{ID: "m1", Expected: "mal", Detected: true, Scored: true, Signals: []Signal{{Detector: "yara"}}},
			{ID: "m2", Expected: "mal", Detected: true, Scored: true, Signals: []Signal{{Detector: "yara"}}},
			{ID: "m3", Expected: "mal", Detected: false, Scored: true},
			{ID: "b1", Expected: "clean", Detected: false, Scored: true},
		},
	}
	res := MeasureTemporal(m, run, split)
	if res.Early.TP != 2 || res.Late.TP != 0 || res.Late.FN != 1 {
		t.Errorf("counts: early %s late %s", res.Early.String(), res.Late.String())
	}
	if res.RecallDrop == nil {
		t.Fatal("no recall drop measured")
	}
	if *res.RecallDrop != 1 {
		t.Errorf("recall drop = %v, want 1", *res.RecallDrop)
	}
}

// The gate fails when the content loses recall across the boundary.
func TestTemporalGateFailsOnARecallDrop(t *testing.T) {
	allowed := 0.5
	res := &TemporalResult{
		Split:        "2026-02",
		EarlyMetrics: Ratios{Recall: NewRatio(10, 10)},
		LateMetrics:  Ratios{Recall: NewRatio(5, 10)},
	}
	drop := 0.5
	res.RecallDrop = &drop
	policy := Policy{MaxRecallDrop: &allowed}
	if d := TemporalGate(res, policy); !d.Pass {
		t.Error("a recall drop at the limit failed the gate")
	}
	over := 0.6
	res.RecallDrop = &over
	d := TemporalGate(res, policy)
	if d.Pass {
		t.Error("a recall drop over the limit passed the gate")
	}
	if len(d.Violations) == 0 {
		t.Error("the failure said nothing")
	}
}

// An undefined metric is no information, not a regression.
func TestTemporalGateSkipsAnUndefinedRecall(t *testing.T) {
	res := &TemporalResult{Split: "2026-02"}
	allowed := 0.0
	d := TemporalGate(res, Policy{MaxRecallDrop: &allowed})
	if !d.Pass {
		t.Error("an undefined recall failed the gate")
	}
	if len(d.Notes) == 0 {
		t.Error("the skipped rule was not noted")
	}
}

// A per-detector drop is gated when the policy declares one.
func TestTemporalGateAppliesThePerDetectorRule(t *testing.T) {
	allowed := 0.2
	drop := 0.3
	res := &TemporalResult{
		Split: "2026-02",
		PerDetector: []TemporalDetector{{
			Detector:   "yara",
			RecallDrop: &drop,
		}},
	}
	policy := Policy{PerDetector: map[string]DetectorPolicy{"yara": {MaxRecallDrop: &allowed}}}
	d := TemporalGate(res, policy)
	if d.Pass {
		t.Error("a per-detector drop over the limit passed the gate")
	}
}

// manifestWithPeriods builds a manifest whose samples carry the given periods.
func manifestWithPeriods(periods map[string]string) *Manifest {
	m := &Manifest{SchemaVersion: SchemaVersion, Name: "t"}
	for id, p := range periods {
		m.Samples = append(m.Samples, Sample{ID: id, Path: id, Label: "mal", Period: p})
	}
	return m
}

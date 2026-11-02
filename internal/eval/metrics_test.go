package eval

import (
	"math"
	"testing"
	"time"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestRatioConventions(t *testing.T) {
	r := ComputeRatios(Counts{TP: 0, FP: 0, TN: 5, FN: 0})
	if r.Precision.Defined {
		t.Error("precision must be undefined when nothing was flagged")
	}
	if r.Recall.Defined {
		t.Error("recall must be undefined when there is no malware")
	}
	if r.F1.Defined {
		t.Error("f1 must be undefined when P or R is undefined")
	}
	if !r.FPR.Defined || r.FPR.Value != 0 {
		t.Errorf("fpr = %v, want defined 0", r.FPR)
	}
	if !r.Accuracy.Defined || r.Accuracy.Value != 1 {
		t.Errorf("accuracy = %v, want 1", r.Accuracy)
	}

	r = ComputeRatios(Counts{TP: 3, FP: 1, TN: 6, FN: 2})
	if !approx(r.Precision.Value, 0.75) || !approx(r.Recall.Value, 0.6) || !approx(r.FPR.Value, 1.0/7) {
		t.Errorf("ratios = %+v", r)
	}
	if !approx(r.F1.Value, 2*0.75*0.6/(0.75+0.6)) {
		t.Errorf("f1 = %v", r.F1)
	}

	r = ComputeRatios(Counts{FP: 1, FN: 1})
	if !r.F1.Defined || r.F1.Value != 0 {
		t.Errorf("f1 with P=R=0 must be defined 0, got %v", r.F1)
	}
	if ComputeRatios(Counts{}).Accuracy.Defined {
		t.Error("accuracy must be undefined when nothing was scored")
	}
}

func TestRatioJSONRoundTrip(t *testing.T) {
	for _, r := range []Ratio{{}, DefinedRatio(0), DefinedRatio(0.5)} {
		b, err := r.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var back Ratio
		if err := back.UnmarshalJSON(b); err != nil {
			t.Fatal(err)
		}
		if back != r {
			t.Errorf("round trip %v -> %s -> %v", r, b, back)
		}
	}
	if b, _ := (Ratio{}).MarshalJSON(); string(b) != "null" {
		t.Errorf("undefined ratio marshals to %s, want null", b)
	}
}

func sample(id, expected string, detected bool, sigs ...Signal) SampleResult {
	s := SampleResult{ID: id, Path: id + ".bin", Expected: expected, Scored: true, Detected: detected, Signals: sigs}
	if expected != LabelClean {
		s.Family = expected
	}
	for _, sg := range sigs {
		s.Detectors = addUnique(s.Detectors, sg.Detector)
	}
	return s
}

func TestNewReportPlacement(t *testing.T) {
	run := &Run{Info: RunInfo{Detectors: []string{"hash", "yara"}}, Samples: []SampleResult{
		sample("tp1", "wannacry", true, Signal{Detector: "yara", Rule: "wannacry_ransomware", Family: "wannacry"}),
		sample("tp2", "wannacry", true, Signal{Detector: "hash", Rule: "WannaCry"}, Signal{Detector: "yara", Rule: "wannacry_ransomware"}),
		sample("fn1", "emotet", false),
		sample("tn1", LabelClean, false),
		sample("fp1", LabelClean, true, Signal{Detector: "yara", Rule: "noisy_rule", Family: "lokibot"}),
		{ID: "err1", Path: "err1.bin", Expected: "emotet", Family: "emotet", Error: "boom"},
		{ID: "skip1", Path: "skip1.bin", Expected: LabelClean, SkipReason: "too big"},
	}}
	rep := NewReport(run)

	if rep.Totals != (Counts{TP: 2, FP: 1, TN: 1, FN: 1}) {
		t.Fatalf("totals = %s", rep.Totals)
	}
	if len(rep.FalsePositives) != 1 || rep.FalsePositives[0].Key != "fp1" {
		t.Errorf("false positives = %+v", rep.FalsePositives)
	}
	if len(rep.FalseNegatives) != 1 || rep.FalseNegatives[0].Key != "fn1" {
		t.Errorf("false negatives = %+v", rep.FalseNegatives)
	}
	if got := rep.FalsePositives[0].ClaimedFamilies; len(got) != 1 || got[0] != "lokibot" {
		t.Errorf("claimed families = %v", got)
	}
	if len(rep.Errors) != 1 || rep.Errors[0].Key != "err1" || rep.Errors[0].CountedAsMiss {
		t.Errorf("errors = %+v", rep.Errors)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Key != "skip1" {
		t.Errorf("skipped = %+v", rep.Skipped)
	}

	// per detector: yara fired on tp1, tp2, fp1; hash on tp2 only.
	yara, _ := rep.detectorStat("yara")
	hash, _ := rep.detectorStat("hash")
	if yara.Counts != (Counts{TP: 2, FP: 1, TN: 1, FN: 1}) {
		t.Errorf("yara counts = %s", yara.Counts)
	}
	if hash.Counts != (Counts{TP: 1, FP: 0, TN: 2, FN: 2}) {
		t.Errorf("hash counts = %s", hash.Counts)
	}
	if yara.Exclusive != 1 || hash.Exclusive != 0 {
		t.Errorf("exclusive: yara=%d hash=%d, want 1/0", yara.Exclusive, hash.Exclusive)
	}

	// rules: worst (most FPs) first.
	if rep.ByRule[0].Rule != "noisy_rule" || rep.ByRule[0].FalsePositives != 1 {
		t.Errorf("worst rule = %+v", rep.ByRule[0])
	}
	for _, rs := range rep.ByRule {
		if rs.Rule == "wannacry_ransomware" && (rs.Fires != 2 || rs.TruePositives != 2) {
			t.Errorf("wannacry_ransomware = %+v", rs)
		}
	}

	// families: emotet 0/1 (fn1; err1 not scored), wannacry 2/2, lokibot blamed once.
	em, _ := rep.familyStat("emotet")
	if em.Samples != 1 || em.Missed != 1 || em.Recall.Value != 0 {
		t.Errorf("emotet = %+v", em)
	}
	lk, _ := rep.familyStat("lokibot")
	if lk.FalsePositives != 1 || lk.Samples != 0 {
		t.Errorf("lokibot = %+v", lk)
	}
	if !approx(rep.Metrics.Recall.Value, 2.0/3) {
		t.Errorf("recall = %v", rep.Metrics.Recall)
	}
}

func TestNewReportCountedAsMiss(t *testing.T) {
	run := &Run{Samples: []SampleResult{
		{ID: "e", Path: "e", Expected: "emotet", Family: "emotet", Scored: true, Error: "unreadable", CountedAsMiss: true},
		{ID: "b", Path: "b", Expected: LabelClean, Scored: true, Error: "unreadable"},
	}}
	rep := NewReport(run)
	if rep.Totals != (Counts{FN: 1, TN: 1}) {
		t.Fatalf("totals = %s", rep.Totals)
	}
	if len(rep.Errors) != 2 || !rep.Errors[1].CountedAsMiss || rep.Errors[0].CountedAsMiss {
		t.Errorf("errors = %+v", rep.Errors)
	}
	if len(rep.FalseNegatives) != 1 || rep.FalseNegatives[0].Notes == "" {
		t.Errorf("false negatives = %+v", rep.FalseNegatives)
	}
}

func TestPerf(t *testing.T) {
	var samples []SampleResult
	for i := 1; i <= 20; i++ {
		samples = append(samples, SampleResult{ID: string(rune('a' + i - 1)), Expected: LabelClean, Scored: true,
			Duration: time.Duration(i) * time.Millisecond, Size: 1000})
	}
	samples = append(samples, SampleResult{ID: "skipped", Expected: LabelClean, SkipReason: "x", Duration: time.Hour})
	p := NewReport(&Run{Samples: samples}).Perf
	if p.Samples != 20 || p.TotalDuration != 210*time.Millisecond || p.MaxDuration != 20*time.Millisecond {
		t.Errorf("perf = %+v", p)
	}
	if p.P50 != 10*time.Millisecond || p.P95 != 19*time.Millisecond {
		t.Errorf("p50=%s p95=%s", p.P50, p.P95)
	}
	if p.BytesScanned != 20000 || !approx(p.Throughput, 20000/0.21) {
		t.Errorf("bytes=%d throughput=%v", p.BytesScanned, p.Throughput)
	}
	if len(p.Slowest) != 5 || p.Slowest[0].Key != "t" {
		t.Errorf("slowest = %+v", p.Slowest)
	}
}

func TestNearMiss(t *testing.T) {
	// Benign samples a scored detector looked at but did not fire on. The
	// near-miss metric must count how close each came, not merely that it was
	// clean. Threshold 8 -> band 2 (a quarter, at least 1).
	mk := func(id string, expected string, score int) SampleResult {
		return SampleResult{
			ID: id, Path: id, Expected: expected, Scored: true, Verdict: VerdictClean,
			Scores: []DetectorScore{{Detector: DetectorHeuristic, Score: score, Threshold: 8}},
		}
	}
	run := &Run{
		SchemaVersion: ReportSchemaVersion,
		Info:          RunInfo{Detectors: []string{DetectorHeuristic}},
		Samples: []SampleResult{
			mk("near1", "clean", 7),  // margin 1 -> near
			mk("near2", "clean", 6),  // margin 2 -> near
			mk("far", "clean", 2),    // margin 6 -> scored, not near
			mk("zero", "clean", 0),   // not scored (score 0), still records threshold
			mk("mal", "wannacry", 7), // malicious: excluded from near miss
		},
	}
	rep := NewReport(run)
	if len(rep.NearMiss) != 1 {
		t.Fatalf("want 1 near-miss stat, got %d", len(rep.NearMiss))
	}
	nm := rep.NearMiss[0]
	if nm.Detector != DetectorHeuristic || nm.Threshold != 8 || nm.Band != 2 {
		t.Errorf("detector/threshold/band = %q/%d/%d, want heuristic/8/2", nm.Detector, nm.Threshold, nm.Band)
	}
	if nm.Scored != 3 {
		t.Errorf("scored = %d, want 3 (near1, near2, far)", nm.Scored)
	}
	if nm.NearThreshold != 2 {
		t.Errorf("near_threshold = %d, want 2 (margin<=2)", nm.NearThreshold)
	}
	if nm.MinMargin != 1 {
		t.Errorf("min_margin = %d, want 1", nm.MinMargin)
	}
	want := []MarginBucket{{1, 1}, {2, 1}, {6, 1}}
	if len(nm.Histogram) != len(want) {
		t.Fatalf("histogram = %+v, want %+v", nm.Histogram, want)
	}
	for i, b := range want {
		if nm.Histogram[i] != b {
			t.Errorf("histogram[%d] = %+v, want %+v", i, nm.Histogram[i], b)
		}
	}
}

func TestNearMissEmptyWhenNoScores(t *testing.T) {
	// A binary-only run (hash/yara) records no scores, so there is no
	// near-miss section rather than a misleading empty one.
	run := &Run{
		SchemaVersion: ReportSchemaVersion,
		Info:          RunInfo{Detectors: []string{DetectorYara}},
		Samples: []SampleResult{
			{ID: "a", Path: "a", Expected: "clean", Scored: true, Verdict: VerdictClean},
		},
	}
	if nm := NewReport(run).NearMiss; nm != nil {
		t.Errorf("near miss = %+v, want nil for a scoreless run", nm)
	}
}

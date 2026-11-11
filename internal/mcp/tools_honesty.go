package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/coverage"
	"github.com/1ungaka/sentinel-edr/internal/eval"
	"github.com/1ungaka/sentinel-edr/internal/honesty"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
)

// ── honesty_index ────────────────────────────────────────────────────────────
//
// The index is assembled by internal/honesty from plain inputs. Gathering the
// inputs is what `cau honesty` (package main) does by calling the coverage,
// eval and selftest packages; the same calls are made here against the
// server's already-loaded content. Nothing below reads a client-supplied
// path: the expectation, report, manifest and key are operator configuration.

// honestyView is the index with its long tables capped. The embedded index is
// flattened into the same JSON keys `cau honesty --format json` writes, with
// the cuts reported beside them.
type honestyView struct {
	*honesty.Index
	Truncated bool           `json:"truncated"`
	Omitted   map[string]int `json:"omitted,omitempty"`
}

func (s *Server) toolHonestyIndex(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct{}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	return jsonResult(s.buildHonesty())
}

// buildHonesty assembles the bounded index.
func (s *Server) buildHonesty() honestyView {
	ix := honesty.Build(honesty.Inputs{
		Tool:      s.deps.Info.Name,
		Version:   s.deps.Info.Version,
		Generated: time.Now(),
		Coverage:  s.honestyCoverage(),
		Eval:      s.honestyEval(),
		Selftest:  s.honestySelftest(),
	})
	view := honestyView{Index: ix, Omitted: map[string]int{}}
	cut := func(name string, n int) {
		if n > 0 {
			view.Omitted[name] = n
			view.Truncated = true
		}
	}
	if n := len(ix.Evaluation.Detectors) - maxListItems; n > 0 {
		ix.Evaluation.Detectors = ix.Evaluation.Detectors[:maxListItems]
		cut("evaluation.detectors", n)
	}
	if n := len(ix.Coverage.UnmappedLabels) - maxListItems; n > 0 {
		ix.Coverage.UnmappedLabels = ix.Coverage.UnmappedLabels[:maxListItems]
		cut("coverage.unmapped_labels", n)
	}
	if ix.Coverage.Expectation != nil {
		if n := len(ix.Coverage.Expectation.Problems) - maxListItems; n > 0 {
			ix.Coverage.Expectation.Problems = ix.Coverage.Expectation.Problems[:maxListItems]
			cut("coverage.expectation.problems", n)
		}
	}
	if n := len(ix.Selftest.Drift) - maxListItems; n > 0 {
		ix.Selftest.Drift = ix.Selftest.Drift[:maxListItems]
		cut("selftest.drift", n)
	}
	if len(view.Omitted) == 0 {
		view.Omitted = nil
	}
	return view
}

// honestyCoverage builds the matrix from the server's loaded content and
// compares it against the expectation, the way cau honesty does.
func (s *Server) honestyCoverage() honesty.CoverageInput {
	out := honesty.CoverageInput{ExpectPath: s.deps.ExpectPath}
	if s.deps.Yara == nil {
		out.Notes = append(out.Notes, "No YARA ruleset was loaded, so the matrix lists no rule-based content.")
	}
	m := s.buildMatrix()
	if out.ExpectPath != "" {
		prev, err := coverage.LoadExpect(out.ExpectPath)
		if err != nil {
			out.ExpectErr = err.Error()
		} else {
			for _, p := range coverage.Compare(m, prev) {
				out.Problems = append(out.Problems, honesty.Problem{ID: p.ID, Kind: p.Kind, Text: p.Text})
			}
		}
	}
	for _, t := range m.Techniques {
		out.Techniques = append(out.Techniques, honesty.Technique{ID: t.ID, Name: t.Name, Partial: t.Partial})
	}
	for _, g := range m.Gaps {
		out.Gaps = append(out.Gaps, honesty.Gap{ID: g.ID, Name: g.Name, State: g.State, Note: g.Note})
	}
	for _, e := range m.Unmapped {
		out.Unmapped = append(out.Unmapped, e.Label)
	}
	for _, src := range m.Sources {
		out.Sources = append(out.Sources, honesty.Source{Name: src.Name, Entries: src.Entries, Mapped: src.Mapped, Content: src.Content, Note: src.Note})
	}
	return out
}

func honestyRatio(r eval.Ratio) *float64 {
	if !r.Defined {
		return nil
	}
	v := r.Value
	return &v
}

func honestyMetrics(r eval.Ratios) honesty.Metrics {
	return honesty.Metrics{
		Precision:         honestyRatio(r.Precision),
		Recall:            honestyRatio(r.Recall),
		FalsePositiveRate: honestyRatio(r.FPR),
	}
}

func honestyCounts(c eval.Counts) honesty.Counts {
	return honesty.Counts{TP: c.TP, FP: c.FP, TN: c.TN, FN: c.FN}
}

// honestyEval loads the operator-configured evaluation report. No path means
// not measured.
func (s *Server) honestyEval() *honesty.EvalInput {
	path := s.deps.EvalPath
	if path == "" {
		return nil
	}
	rep, err := eval.LoadReport(path)
	if err != nil {
		return &honesty.EvalInput{ReportPath: path, Err: err.Error()}
	}
	if msg := reportAddsUp(rep); msg != "" {
		return &honesty.EvalInput{ReportPath: path, Err: msg}
	}
	in := &honesty.EvalInput{
		ReportPath:     path,
		Tool:           rep.Info.Tool,
		Generated:      rep.Info.GeneratedAt,
		CorpusName:     rep.Info.CorpusName,
		CorpusManifest: rep.Info.Corpus,
		Samples:        len(rep.Samples),
		Errors:         len(rep.Errors),
		Skipped:        len(rep.Skipped),
		Totals:         honestyCounts(rep.Totals),
		Metrics:        honestyMetrics(rep.Metrics),
	}
	for _, d := range rep.ByDetector {
		in.Detectors = append(in.Detectors, honesty.Detector{
			Name:          d.Detector,
			Counts:        honestyCounts(d.Counts),
			Metrics:       honestyMetrics(d.Metrics),
			Fires:         d.Fires,
			ExclusiveHits: d.Exclusive,
		})
	}
	// The manifest the report names says what the samples are (provenance).
	// It is read when it is still where the report says and is that corpus.
	if rep.Info.Corpus != "" {
		if m, err := eval.LoadManifest(rep.Info.Corpus); err == nil && m.Name == rep.Info.CorpusName {
			seen := map[string]bool{}
			for _, smp := range m.Samples {
				src := smp.Provenance.Source
				if src == "" {
					src = "(undeclared)"
				}
				if !seen[src] {
					seen[src] = true
					in.ProvenanceSources = append(in.ProvenanceSources, src)
				}
			}
			sort.Strings(in.ProvenanceSources)
			in.ManifestRead = true
		}
	}
	return in
}

// reportAddsUp recomputes a report's totals from its own sample records with
// the harness's code. A report is a file anyone can edit; headline numbers
// that do not follow from the samples are not reported from. It returns the
// reason, or "" when the report is consistent.
func reportAddsUp(rep *eval.Report) string {
	again := eval.NewReport(&eval.Run{SchemaVersion: rep.SchemaVersion, Info: rep.Info, Samples: rep.Samples})
	if again.Totals != rep.Totals {
		return fmt.Sprintf("the report's totals (%s) do not follow from its own sample records (%s)", rep.Totals, again.Totals)
	}
	return ""
}

// honestySelftest checks the integrity baseline with the selftest package. A
// missing baseline is the no-baseline state, never a failure.
func (s *Server) honestySelftest() honesty.SelftestInput {
	in := honesty.SelftestInput{ManifestPath: s.deps.ManifestPath}
	if in.ManifestPath == "" {
		if s.deps.SigDBPath == "" {
			in.Notes = append(in.Notes, "The signature database path is not known, so there is no default baseline location to look in.")
			return in
		}
		in.ManifestPath = filepath.Join(filepath.Dir(s.deps.SigDBPath), "integrity.json")
	}
	baseline, err := selftest.ReadManifest(in.ManifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return in
	}
	if err != nil {
		in.Err = err.Error()
		return in
	}
	in.Found = true
	for _, e := range baseline.Entries {
		in.Resources = append(in.Resources, honesty.Resource{Name: e.Name, Path: e.Path, SHA256: e.SHA256})
	}
	switch {
	case s.deps.PubKey != nil:
		switch err := baseline.VerifySignature(s.deps.PubKey); {
		case err == nil:
			in.Signature = honesty.SignatureVerified
		case errors.Is(err, selftest.ErrUnsigned):
			in.Signature = honesty.SignatureMissing
		default:
			in.Signature = honesty.SignatureBad
		}
	case baseline.Signature != "":
		in.Signature = honesty.SignatureNotChecked
	default:
		in.Signature = honesty.SignatureUnsigned
	}
	if s.deps.PubKey == nil && s.deps.PubKeyErr != "" {
		in.Err = "A public key was supplied but could not be read as a hex Ed25519 key, so the baseline's signature was not checked: " + s.deps.PubKeyErr
	}
	drift, err := selftest.Verify(baseline)
	if err != nil {
		in.Err = trimJoin(in.Err, "The content digests could not be recomputed: "+err.Error())
		return in
	}
	in.Checked = true
	for _, d := range drift {
		in.Drift = append(in.Drift, honesty.Drift{Name: d.Name, Reason: d.Reason})
	}
	// A baseline verifies the paths it recorded; a resource the server loaded
	// from elsewhere was not checked by it.
	for _, r := range []struct{ name, path string }{
		{"signatures", s.deps.SigDBPath}, {"rules", s.deps.RulesPath},
	} {
		if r.path == "" || baselined(baseline, r.name, r.path) {
			continue
		}
		in.Notes = append(in.Notes, fmt.Sprintf(
			"The baseline does not cover the %s resource this server loaded (%s): that content was not checked.", r.name, r.path))
	}
	return in
}

func trimJoin(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

// baselined reports whether the baseline has an entry of that name recorded
// for the same file.
func baselined(m selftest.Manifest, name, path string) bool {
	want, err := filepath.Abs(path)
	if err != nil {
		want = filepath.Clean(path)
	}
	for _, e := range m.Entries {
		got, err := filepath.Abs(e.Path)
		if err != nil {
			got = filepath.Clean(e.Path)
		}
		if e.Name == name && got == want {
			return true
		}
	}
	return false
}

// ── eval_report ──────────────────────────────────────────────────────────────

type evalDetectorRow struct {
	Detector  string      `json:"detector"`
	Counts    eval.Counts `json:"counts"`
	Precision *float64    `json:"precision"`
	Recall    *float64    `json:"recall"`
	FPR       *float64    `json:"fpr"`
	Fires     int         `json:"fires"`
	Exclusive int         `json:"exclusive_hits"`
}

type evalSampleRow struct {
	ID        string   `json:"id,omitempty"`
	Path      string   `json:"path"`
	Expected  string   `json:"expected"`
	Family    string   `json:"family,omitempty"`
	Scored    bool     `json:"scored"`
	Detected  bool     `json:"detected"`
	Verdict   string   `json:"verdict,omitempty"`
	Detectors []string `json:"detectors,omitempty"`
	Error     string   `json:"error,omitempty"`
	Skipped   string   `json:"skip_reason,omitempty"`
}

func (s *Server) toolEvalReport(raw json.RawMessage) (interface{}, *rpcError) {
	var args struct {
		Path           string `json:"path"`
		IncludeSamples bool   `json:"include_samples"`
		Limit          int    `json:"limit"`
	}
	if e := unmarshalArgs(raw, &args); e != nil {
		return nil, e
	}
	real, _, err := s.deps.Sandbox.ResolveFile(args.Path)
	if err != nil {
		return toolErr("eval_report: %v", err)
	}
	data, _, err := safefs.ReadFileNoFollow(real, s.deps.Sandbox.MaxBytes())
	if err != nil {
		return toolErr("eval_report: %v", err)
	}
	rep, err := eval.ParseReport(data)
	if err != nil {
		return toolErr("eval_report: %v", err)
	}
	limit := args.Limit
	if limit <= 0 || limit > maxListItems {
		limit = maxListItems
	}

	class, basis := honesty.ClassifyCorpus(rep.Info.CorpusName, rep.Info.Corpus, false, nil)
	out := map[string]interface{}{
		"path":           args.Path,
		"schema_version": rep.SchemaVersion,
		"run": map[string]interface{}{
			"tool":         rep.Info.Tool,
			"generated_at": rep.Info.GeneratedAt,
			"corpus":       boundStr(rep.Info.Corpus),
			"corpus_name":  boundStr(rep.Info.CorpusName),
			"detectors":    rep.Info.Detectors,
			"on_error":     rep.Info.OnError,
		},
		"corpus_class":       class,
		"corpus_class_basis": basis,
		"samples": map[string]int{
			"total":     len(rep.Samples),
			"scored":    rep.Totals.Total(),
			"malicious": rep.Totals.Positives(),
			"benign":    rep.Totals.Negatives(),
			"errors":    len(rep.Errors),
			"skipped":   len(rep.Skipped),
		},
		"totals": rep.Totals,
		"metrics": map[string]*float64{
			"precision":   honestyRatio(rep.Metrics.Precision),
			"recall":      honestyRatio(rep.Metrics.Recall),
			"f1":          honestyRatio(rep.Metrics.F1),
			"specificity": honestyRatio(rep.Metrics.Specificity),
			"fpr":         honestyRatio(rep.Metrics.FPR),
			"accuracy":    honestyRatio(rep.Metrics.Accuracy),
		},
		"false_positives": len(rep.FalsePositives),
		"false_negatives": len(rep.FalseNegatives),
		"perf": map[string]interface{}{
			"samples":         rep.Perf.Samples,
			"mean_ms":         rep.Perf.MeanDuration.Milliseconds(),
			"p95_ms":          rep.Perf.P95.Milliseconds(),
			"max_ms":          rep.Perf.MaxDuration.Milliseconds(),
			"bytes_scanned":   rep.Perf.BytesScanned,
			"throughput_bps":  rep.Perf.Throughput,
			"slowest_listed":  len(rep.Perf.Slowest),
			"durations_note":  "per-sample scan time summed over samples, not wall clock",
			"total_scan_time": rep.Perf.TotalDuration.String(),
		},
	}
	if msg := reportAddsUp(rep); msg != "" {
		out["totals_consistent"] = false
		out["totals_problem"] = msg
	} else {
		out["totals_consistent"] = true
	}

	caveats := []string{"These numbers are read from a recorded report; this call did not re-run the evaluation."}
	if class == honesty.CorpusSynthetic {
		caveats = append(caveats, "SYNTHETIC CORPUS: recall on the committed smoke corpus is a plumbing check, not a detection rate.")
	} else {
		caveats = append(caveats, "The corpus is unclassified: read these numbers against the corpus's own documentation.")
	}
	if len(rep.ByDetector) > 0 {
		caveats = append(caveats, "Per-detector rows count every malicious sample the detector did not fire on as a miss, including samples outside its file type.")
	}
	out["caveats"] = caveats

	var dets []evalDetectorRow
	for i, d := range rep.ByDetector {
		if i >= limit {
			out["by_detector_omitted"] = len(rep.ByDetector) - limit
			out["truncated"] = true
			break
		}
		dets = append(dets, evalDetectorRow{
			Detector:  boundStr(d.Detector),
			Counts:    d.Counts,
			Precision: honestyRatio(d.Metrics.Precision),
			Recall:    honestyRatio(d.Metrics.Recall),
			FPR:       honestyRatio(d.Metrics.FPR),
			Fires:     d.Fires,
			Exclusive: d.Exclusive,
		})
	}
	out["by_detector"] = dets

	if args.IncludeSamples {
		var rows []evalSampleRow
		for i, smp := range rep.Samples {
			if i >= limit {
				out["samples_omitted"] = len(rep.Samples) - limit
				out["truncated"] = true
				break
			}
			dl, _ := boundStrs(smp.Detectors)
			rows = append(rows, evalSampleRow{
				ID:        boundStr(smp.ID),
				Path:      boundStr(smp.Path),
				Expected:  boundStr(smp.Expected),
				Family:    boundStr(smp.Family),
				Scored:    smp.Scored,
				Detected:  smp.Detected,
				Verdict:   boundStr(string(smp.Verdict)),
				Detectors: dl,
				Error:     boundStr(smp.Error),
				Skipped:   boundStr(smp.SkipReason),
			})
		}
		out["sample_rows"] = rows
	} else {
		out["sample_rows"] = nil
		out["note"] = "per-sample rows omitted; pass include_samples=true for a capped list"
	}
	if _, ok := out["truncated"]; !ok {
		out["truncated"] = false
	}
	return jsonResult(out)
}

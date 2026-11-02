package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// WriteJSON persists the report. The document is byte-stable across two runs
// of the same corpus with the same detectors except for run.generated_at and
// the duration fields, which Diff ignores.
func (r *Report) WriteJSON(w io.Writer, indent bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("eval: encode report: %w", err)
	}
	return nil
}

// WriteJSON persists a raw run.
func (r *Run) WriteJSON(w io.Writer, indent bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("eval: encode run: %w", err)
	}
	return nil
}

// LoadReport reads a persisted report (a baseline) from disk.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("eval: read report: %w", err)
	}
	rep, err := ParseReport(data)
	if err != nil {
		return nil, fmt.Errorf("eval: report %s: %w", path, err)
	}
	return rep, nil
}

// ParseReport decodes a report, rejecting other schema versions.
func ParseReport(data []byte) (*Report, error) {
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	if rep.SchemaVersion != ReportSchemaVersion {
		return nil, fmt.Errorf("parse report: unsupported schema_version %q (this build understands %q)", rep.SchemaVersion, ReportSchemaVersion)
	}
	return &rep, nil
}

// LoadRun reads a persisted raw run.
func LoadRun(path string) (*Run, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("eval: read run: %w", err)
	}
	var run Run
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("eval: run %s: %w", path, err)
	}
	if run.SchemaVersion != ReportSchemaVersion {
		return nil, fmt.Errorf("eval: run %s: unsupported schema_version %q", path, run.SchemaVersion)
	}
	return &run, nil
}

// WriteText renders the report for humans.
func (r *Report) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "eval report: %s\n", describeRun(r.Info))
	if r.Info.CorpusRoot != "" {
		fmt.Fprintf(w, "  root: %s\n", r.Info.CorpusRoot)
	}
	fmt.Fprintf(w, "  samples: %d scored, %d errors, %d skipped\n", r.Totals.Total(), len(r.Errors), len(r.Skipped))

	fmt.Fprintln(w, "\nconfusion matrix")
	fmt.Fprintf(w, "                    flagged   not flagged\n")
	fmt.Fprintf(w, "  malicious     %9d   %11d\n", r.Totals.TP, r.Totals.FN)
	fmt.Fprintf(w, "  benign        %9d   %11d\n", r.Totals.FP, r.Totals.TN)

	fmt.Fprintln(w, "\nmetrics")
	fmt.Fprintf(w, "  precision   %8s\n  recall      %8s\n  f1          %8s\n  specificity %8s\n  fpr         %8s\n  accuracy    %8s\n",
		r.Metrics.Precision.Percent(), r.Metrics.Recall.Percent(), r.Metrics.F1.Percent(),
		r.Metrics.Specificity.Percent(), r.Metrics.FPR.Percent(), r.Metrics.Accuracy.Percent())

	if len(r.ByDetector) > 0 {
		fmt.Fprintln(w, "\nper detector            tp    fp    tn    fn   recall      fpr  exclusive")
		for _, d := range r.ByDetector {
			fmt.Fprintf(w, "  %-20s %5d %5d %5d %5d %8s %8s  %9d\n", d.Detector,
				d.Counts.TP, d.Counts.FP, d.Counts.TN, d.Counts.FN, d.Metrics.Recall.Percent(), d.Metrics.FPR.Percent(), d.Exclusive)
		}
	}
	if len(r.ByFamily) > 0 {
		fmt.Fprintln(w, "\nper family              samples  detected  missed   recall  blamed-on-benign")
		for _, f := range r.ByFamily {
			fmt.Fprintf(w, "  %-20s %8d %9d %7d %8s %17d\n", f.Family, f.Samples, f.Detected, f.Missed, f.Recall.Percent(), f.FalsePositives)
		}
	}
	if len(r.ByRule) > 0 {
		fmt.Fprintln(w, "\nrules (worst first)     fires    tp    fp  detectors")
		max := 25
		for i, rs := range r.ByRule {
			if i == max {
				fmt.Fprintf(w, "  +%d more\n", len(r.ByRule)-max)
				break
			}
			fmt.Fprintf(w, "  %-20s %6d %5d %5d  %s\n", rs.Rule, rs.Fires, rs.TruePositives, rs.FalsePositives, strings.Join(rs.Detectors, ","))
		}
	}

	if len(r.NearMiss) > 0 {
		fmt.Fprintln(w, "\nnear miss (benign files that scored but did not fire)")
		fmt.Fprintf(w, "  detector             thr  band  scored  near  nearest  histogram (margin×count)\n")
		for _, nm := range r.NearMiss {
			nearest := "-"
			if nm.MinMargin >= 0 {
				nearest = fmt.Sprintf("%d", nm.MinMargin)
			}
			var hb []string
			for _, b := range nm.Histogram {
				hb = append(hb, fmt.Sprintf("%d×%d", b.Margin, b.Count))
			}
			fmt.Fprintf(w, "  %-20s %3d %5d %7d %5d %8s  %s\n",
				nm.Detector, nm.Threshold, nm.Band, nm.Scored, nm.NearThreshold, nearest, strings.Join(hb, " "))
		}
	}

	writeFlaggedList(w, "false positives", r.FalsePositives, 50)
	writeFlaggedList(w, "false negatives", r.FalseNegatives, 50)

	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "\nerrors (%d)\n", len(r.Errors))
		for i, e := range r.Errors {
			if i == 50 {
				fmt.Fprintf(w, "  +%d more\n", len(r.Errors)-50)
				break
			}
			suffix := ""
			if e.CountedAsMiss {
				suffix = "  [counted as miss]"
			}
			fmt.Fprintf(w, "  %s: %s%s\n", e.Key, e.Message, suffix)
		}
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "\nskipped (%d)\n", len(r.Skipped))
		for i, s := range r.Skipped {
			if i == 50 {
				fmt.Fprintf(w, "  +%d more\n", len(r.Skipped)-50)
				break
			}
			fmt.Fprintf(w, "  %s: %s\n", s.Key, s.Reason)
		}
	}

	p := r.Perf
	fmt.Fprintln(w, "\nperf")
	fmt.Fprintf(w, "  scanned     %d samples, %s\n", p.Samples, humanBytes(float64(p.BytesScanned)))
	fmt.Fprintf(w, "  scan time   total %s, mean %s, p50 %s, p95 %s, max %s\n",
		p.TotalDuration.Round(time.Microsecond), p.MeanDuration.Round(time.Microsecond),
		p.P50.Round(time.Microsecond), p.P95.Round(time.Microsecond), p.MaxDuration.Round(time.Microsecond))
	fmt.Fprintf(w, "  throughput  %s/s\n", humanBytes(p.Throughput))
	for _, s := range p.Slowest {
		fmt.Fprintf(w, "  slow        %-30s %s\n", s.Key, s.Duration.Round(time.Microsecond))
	}
	return nil
}

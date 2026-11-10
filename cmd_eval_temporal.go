package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/internal/report"
)

// evalTemporal measures the shipped content across a time boundary.
//
// Temporal snooping is the field's most widespread evaluation flaw: content
// (or a model) tuned on everything at once looks best in distribution and is
// often the worst across a time boundary. A corpus that declares the period
// each sample belongs to makes the boundary explicit, and this subcommand
// scores both sides of it.
//
// The rule is the policy's max_recall_drop, applied across the boundary: the
// content must not lose more than that much recall between the earlier
// periods and the later ones. A period with no malware in it says nothing
// about recall, so an undefined metric never fails the gate.
func evalTemporal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval temporal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpus := fs.String("corpus", "", "corpus manifest (JSON)")
	sf := evalScanFlagSet(fs)
	split := fs.String("split", "", "the period that opens the later half (default: the median period)")
	policyPath := fs.String("policy", "", "regression policy JSON (default: built-in policy)")
	maxDrop := fs.Float64("max-drop", -1, "the recall drop across the boundary that fails the gate, in percentage points (default: the policy's max_recall_drop)")
	format := fs.String("format", "text", "stdout rendering: text or json")
	out := fs.String("out", "", "write the JSON measurement here")
	quiet := fs.Bool("quiet", false, "no progress on stderr")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *corpus == "" {
		fs.Usage()
		return fail(stderr, report.ExitUsage, "--corpus is required")
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}

	m, err := eval.LoadManifest(*corpus)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	parts, err := eval.SplitByPeriod(m, *split)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if !*quiet {
		fmt.Fprintf(stderr, "[*] temporal: %d period(s), split at %s (%d earlier, %d later)\n",
			len(parts.Periods), parts.Split, len(parts.Early.Samples), len(parts.Late.Samples))
	}

	detectors, closer, err := evalDetectors(sf, m, stderr, *quiet)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	defer closer()

	ropts := eval.RunOptions{
		Concurrency: 0,
		OnError:     eval.OnErrorExclude,
		Tool:        toolName + " " + version,
	}
	if !*quiet {
		last := time.Now()
		ropts.Progress = func(done, total int) {
			if done == total || time.Since(last) > 2*time.Second {
				last = time.Now()
				fmt.Fprintf(stderr, "[*] %d/%d samples\n", done, total)
			}
		}
	}
	runRec, err := eval.NewRunner(detectors, ropts).Run(m)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	res := eval.MeasureTemporal(m, runRec, parts)

	policy := eval.DefaultPolicy()
	if *policyPath != "" {
		p, err := eval.LoadPolicy(*policyPath)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		policy = p
	}
	if *maxDrop >= 0 {
		v := *maxDrop / 100
		policy.MaxRecallDrop = &v
	}
	decision := eval.TemporalGate(res, policy)

	if *format == "json" {
		payload := map[string]any{
			"measurement": res,
			"decision":    decision,
		}
		if err := writeJSON(stdout, payload); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		if err := res.WriteText(stdout); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fmt.Fprintln(stdout)
		if err := decision.WriteText(stdout); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(mustJSON(map[string]any{
			"measurement": res,
			"decision":    decision,
		})), 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	}
	if !decision.Pass {
		return report.ExitThreat
	}
	return report.ExitOK
}

// mustJSON renders a value as JSON, or an empty document when it cannot.
func mustJSON(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "{}"
	}
	return b.String()
}

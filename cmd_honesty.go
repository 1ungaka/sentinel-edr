package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/coverage"
	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/internal/honesty"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/selftest"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/static"
)

// Defaults the honesty index reads when they exist in the working directory:
// the committed evaluation baseline and the committed coverage expectation.
const (
	honestyDefaultEval   = "baselines/smoke.json"
	honestyDefaultExpect = "baselines/attack-coverage.txt"
)

// envSourceDateEpoch pins the document timestamp for reproducible output.
const envSourceDateEpoch = "SOURCE_DATE_EPOCH"

// honestyNow is the clock; tests replace it.
var honestyNow = time.Now

func honestyUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau honesty [flags]

Renders the honesty index: one document stating what the detection content
covers, what an evaluation run measured, and whether the content still matches
its integrity baseline. It is meant to be run by whoever wants to check the
engine's claims: a buyer, an auditor, an insurer.

  coverage    the ATT&CK matrix of the shipped content, compared against the
              committed expectation. Declared gaps are listed.
  evaluation  precision, recall and false-positive counts from a report
              written by "cau eval run --out". The corpus is classified: the
              committed smoke corpus is synthetic, so recall on it is a
              plumbing check, not a detection rate.
  selftest    whether the detection content matches its recorded baseline, and
              whether that baseline's signature was verified.

Each section has a state: measured, not-measured, mismatch, no-baseline,
tampered or error. A missing baseline or report is a state of its own, never a
pass and never a row of zeros. There is no overall score.

Flags:
  --format <fmt>     text, json or markdown (default text)
  --output <file>    write the index to this file instead of stdout
  --eval <file>      evaluation report (default: %s if present)
  --expect <file>    coverage expectation (default: %s if present)
  --db / --rules / --fuzzy-db <path>   override resource locations
  --manifest <file>  integrity baseline (default: integrity.json next to the
                     signature DB)
  --pubkey <file>    Ed25519 public key (hex) to verify the baseline signature
                     (also read from $%s)
  --no-timestamp     leave the generated timestamp out, for reproducible
                     output ($%s sets it instead)
  --strict           exit 1 when any section is mismatch, tampered or error

Exit codes: 0 the index was produced, whatever it says; 1 with --strict, a
section is mismatch, tampered or error; 3 the index could not be produced;
4 usage.
`, honestyDefaultEval, honestyDefaultExpect, envSelftestKey, envSourceDateEpoch)
}

func cmdHonesty(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("honesty", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { honestyUsage(stderr) }
	format := fs.String("format", "text", "output format: "+strings.Join(honesty.Formats, ", "))
	output := fs.String("output", "", "write the index to this file instead of stdout")
	evalPath := fs.String("eval", "", "evaluation report written by `cau eval run --out`")
	expect := fs.String("expect", "", "coverage expectation file")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	fuzzyDB := fs.String("fuzzy-db", "", "fuzzy signature database (default: auto-discovered)")
	manifest := fs.String("manifest", "", "integrity baseline (default: next to the signature DB)")
	pubKeyFile := fs.String("pubkey", "", "Ed25519 public key (hex) to verify the baseline signature")
	noTimestamp := fs.Bool("no-timestamp", false, "leave the generated timestamp out")
	strict := fs.Bool("strict", false, "exit 1 when any section is mismatch, tampered or error")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "honesty takes no positional arguments (got %q)", fs.Arg(0))
	}
	var write func(io.Writer, *honesty.Index) error
	switch strings.ToLower(*format) {
	case "text":
		write = honesty.WriteText
	case "markdown":
		write = honesty.WriteMarkdown
	case "json":
		write = func(w io.Writer, ix *honesty.Index) error { return writeJSON(w, ix) }
	default:
		return fail(stderr, report.ExitUsage, "unknown format %q (want one of %s)", *format, strings.Join(honesty.Formats, ", "))
	}
	generated, err := honestyClock(*noTimestamp)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}

	// A default that is absent leaves its section in a "nothing to compare
	// against" state. A path the caller named and that cannot be read is an
	// error in that section, not a silent fallback.
	if *evalPath == "" && fileExists(honestyDefaultEval) {
		*evalPath = honestyDefaultEval
	}
	if *expect == "" && fileExists(honestyDefaultExpect) {
		*expect = honestyDefaultExpect
	}

	warn := func(f string, a ...interface{}) { fmt.Fprintf(stderr, "[WARN] "+f+"\n", a...) }
	ix := honesty.Build(honesty.Inputs{
		Tool:      toolName,
		Version:   version,
		Generated: generated,
		Coverage:  honestyCoverage(*rules, *db, *fuzzyDB, *expect, warn),
		Eval:      honestyEval(*evalPath),
		Selftest:  honestySelftest(*manifest, *pubKeyFile, *db, *rules, *fuzzyDB),
	})

	// Render before touching the output so a failed render leaves no
	// half-written index behind.
	var buf bytes.Buffer
	if err := write(&buf, ix); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *output != "" {
		if err := os.WriteFile(*output, buf.Bytes(), 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "cannot write %s: %v", *output, err)
		}
	} else if _, err := stdout.Write(buf.Bytes()); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	if failing := ix.Failing(); *strict && len(failing) > 0 {
		for _, f := range failing {
			fmt.Fprintf(stderr, "[STRICT] %s\n", f)
		}
		return report.ExitThreat
	}
	return report.ExitOK
}

// honestyClock returns the document timestamp: none with --no-timestamp, the
// SOURCE_DATE_EPOCH second when set, the wall clock otherwise.
func honestyClock(noTimestamp bool) (time.Time, error) {
	if noTimestamp {
		return time.Time{}, nil
	}
	if v := os.Getenv(envSourceDateEpoch); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil || sec < 0 {
			return time.Time{}, fmt.Errorf("$%s must be a non-negative number of seconds, got %q", envSourceDateEpoch, v)
		}
		return time.Unix(sec, 0).UTC(), nil
	}
	return honestyNow().UTC(), nil
}

// honestyCoverage builds the coverage matrix the way `cau coverage` does and
// compares it against the expectation. Nothing here fails the run: what goes
// wrong becomes the section's state.
func honestyCoverage(rules, db, fuzzyDB, expect string, warn func(string, ...interface{})) honesty.CoverageInput {
	out := honesty.CoverageInput{ExpectPath: expect}
	in := coverage.Inputs{Tool: toolName, Version: version, HashCount: -1, FuzzyCount: -1}

	rulesPath, _ := findResource(rules, envRules, relRules)
	if rulesPath == "" {
		out.Notes = append(out.Notes, "No YARA ruleset was found, so the matrix lists no rule-based content.")
	} else {
		ys, _, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(warn))
		if err != nil {
			out.Err = fmt.Sprintf("YARA: %v", err)
			return out
		}
		defer ys.Close()
		in.Rules = ys.RuleInfos()
		in.YaraLoaded = true
	}
	if dbPath, _ := findResource(db, envSignatures, relSignatures); dbPath != "" {
		if sdb, err := scanner.LoadSignatures(dbPath); err == nil {
			in.HashCount = sdb.Count()
		} else if db != "" {
			out.Err = err.Error()
			return out
		}
	}
	if fzPath, _ := findResource(fuzzyDB, envFuzzy, relFuzzy); fzPath != "" {
		if fdb, err := static.LoadFuzzyDB(fzPath); err == nil {
			in.FuzzyCount = fdb.Count()
		} else if fuzzyDB != "" {
			out.Err = err.Error()
			return out
		}
	}

	m := coverage.Build(in)
	if expect != "" {
		prev, err := coverage.LoadExpect(expect)
		if err != nil {
			out.ExpectErr = err.Error()
		} else {
			// Compare also marks the partial techniques and attaches the
			// declared gaps to the matrix.
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
	for _, s := range m.Sources {
		out.Sources = append(out.Sources, honesty.Source{Name: s.Name, Entries: s.Entries, Mapped: s.Mapped, Content: s.Content, Note: s.Note})
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

// honestyEval loads an evaluation report. An empty path means there is no
// report, which the index renders as not-measured.
func honestyEval(path string) *honesty.EvalInput {
	if path == "" {
		return nil
	}
	rep, err := eval.LoadReport(path)
	if err != nil {
		return &honesty.EvalInput{ReportPath: path, Err: err.Error()}
	}
	// A report is a file anyone can edit. Its totals are recomputed from its
	// own sample records with the harness's code; a report whose headline
	// numbers do not follow from its samples is not reported from.
	if again := eval.NewReport(&eval.Run{SchemaVersion: rep.SchemaVersion, Info: rep.Info, Samples: rep.Samples}); again.Totals != rep.Totals {
		return &honesty.EvalInput{ReportPath: path, Err: fmt.Sprintf(
			"the report's totals (%s) do not follow from its own sample records (%s)", rep.Totals, again.Totals)}
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

	// The report records the corpus name and manifest path but not what the
	// samples are. The manifest does: each sample has a provenance source.
	// It is read when it is still where the report says and is the corpus
	// the report names.
	if rep.Info.Corpus != "" {
		if m, err := eval.LoadManifest(rep.Info.Corpus); err == nil && m.Name == rep.Info.CorpusName {
			seen := map[string]bool{}
			for _, s := range m.Samples {
				src := s.Provenance.Source
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

// honestySelftest checks the integrity baseline with the selftest package.
// Unlike `cau selftest` it never fails on a missing baseline: that is the
// no-baseline state.
func honestySelftest(manifest, pubKeyFile, db, rules, fuzzyDB string) honesty.SelftestInput {
	dbPath, _ := findResource(db, envSignatures, relSignatures)
	rulesPath, _ := findResource(rules, envRules, relRules)
	fuzzyPath, _ := findResource(fuzzyDB, envFuzzy, relFuzzy)

	in := honesty.SelftestInput{ManifestPath: manifest}
	if in.ManifestPath == "" {
		if dbPath == "" {
			in.Notes = append(in.Notes, "The signature database was not found, so there is no default baseline location to look in.")
			return in
		}
		in.ManifestPath = filepath.Join(filepath.Dir(dbPath), "integrity.json")
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

	// resolveSelftestPubkey now reports an unusable key rather than returning
	// "no key", so a signature check can no longer be quietly downgraded to a
	// digest check. This report says so in its own words instead of failing,
	// because describing the state of the host honestly is the whole job here.
	key, keyErr := resolveSelftestPubkey(pubKeyFile)
	keyWanted := pubKeyFile != "" || os.Getenv(envSelftestKey) != ""
	switch {
	case key.set:
		switch err := baseline.VerifySignature(key.key); {
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
	if keyWanted && !key.set {
		in.Err = "A public key was supplied but could not be read as a hex Ed25519 key, so the baseline's signature was not checked."
		if keyErr != nil {
			// Same sentence, plus the specific reason now that there is one.
			in.Err = "A public key was supplied but could not be read as a hex Ed25519 key, so the baseline's signature was not checked: " + keyErr.Error()
		}
	}

	drift, err := selftest.Verify(baseline)
	if err != nil {
		in.Err = strings.TrimSpace(in.Err + " The content digests could not be recomputed: " + err.Error())
		return in
	}
	in.Checked = true
	for _, d := range drift {
		in.Drift = append(in.Drift, honesty.Drift{Name: d.Name, Reason: d.Reason})
	}

	// A baseline verifies the paths it recorded. If the engine now resolves
	// a resource somewhere else, an intact baseline says nothing about it.
	for _, r := range []struct{ name, path string }{
		{"signatures", dbPath}, {"rules", rulesPath}, {"fuzzy", fuzzyPath},
	} {
		if r.path == "" || honestyBaselined(baseline, r.name, r.path) {
			continue
		}
		in.Notes = append(in.Notes, fmt.Sprintf(
			"The baseline does not cover the %s resource this run resolved (%s): that content was not checked.", r.name, r.path))
	}
	return in
}

// honestyBaselined reports whether the baseline has an entry of that name
// recorded for the same file.
func honestyBaselined(m selftest.Manifest, name, path string) bool {
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

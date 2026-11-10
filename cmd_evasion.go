package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/evasion"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
)

// The evasion report is the credibility instrument the plan asks for: a
// measurement of how far the shipped detections are from being wrong. It says
// how many bytes have to change for each detector to stop firing, and it says
// nothing else: no patched sample, no offsets, no byte values. The distance
// is the number a detection author needs; the patch is not this tool's job.
func evasionUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau evasion <subcommand> [flags]

  report   measure how fragile the detections on one file are
  bench    measure the same across a corpus, per detector

The evasion report answers one question per detector that fired: how many
bytes have to change for that detector to stop firing on this file? It comes
from the detection's own evidence — the matched hash, the rule's condition,
the invisible codepoints — and never from a guess. A detector whose distance
cannot be derived is reported as not derivable, with the reason.

What the report deliberately does not do is produce a patched file. It
describes the change ("breaking the rule needs at least one byte changed")
and never the bytes to write: this measures how much work the detection
content still needs, and it is not a kit for making a sample quiet.

Flags:
  --file <path>      the file to measure (report)
  --corpus <path>    a corpus manifest to measure (bench)
  --rules <path>     the YARA rules directory
  --db <path>        the signature database
  --format <fmt>     text or json (default text)
  --limit <n>        cap the per-sample rows in the bench report

Examples:
  cau evasion report --file /tmp/sample.bin
  cau evasion bench --corpus corpus/smoke/manifest.json --format json
`)
}

func cmdEvasion(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return fail(stderr, report.ExitUsage, "usage: cau evasion report|bench [flags]")
	}
	switch args[0] {
	case "report":
		return evasionReport(args[1:], stdout, stderr)
	case "bench":
		return evasionBench(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		evasionUsage(stdout)
		return report.ExitOK
	default:
		return fail(stderr, report.ExitUsage, "unknown evasion subcommand %q", args[0])
	}
}

// evasionFlags are the flags both subcommands take.
type evasionFlags struct {
	file   *string
	corpus *string
	rules  *string
	db     *string
	format *string
	limit  *int
}

func newEvasionFlags(name string, fs *flag.FlagSet) evasionFlags {
	return evasionFlags{
		file:   fs.String("file", "", "the file to measure"),
		corpus: fs.String("corpus", "", "a corpus manifest to measure"),
		rules:  fs.String("rules", "", "the YARA rules directory"),
		db:     fs.String("db", "", "the signature database"),
		format: fs.String("format", "text", "text or json"),
		limit:  fs.Int("limit", 50, "cap the per-sample rows in the bench report"),
	}
}

// evasionEngine builds the engine the report measures, with the same
// detectors the CLI scans with.
func evasionEngine(rulesPath, dbPath string, stderr io.Writer) (*scanner.Engine, func(), error) {
	e := &scanner.Engine{
		Heuristics: true,
		Static:     true,
		Stego:      true,
		EncChain:   true,
		LNK:        true,
		OLE:        true,
		PDF:        true,
		ISO:        true,
		LinuxPkg:   true,
		Peel:       true,
		// The decoded layers are rescanned with the same rules, so the
		// report says how fragile a decoded detection is too.
		PeelIndicators: true,
		Archive:        true,
		CHM:            true,
		Tradecraft:     true,
	}
	closer := func() {}
	if dbPath != "" {
		db, err := scanner.LoadSignatures(dbPath)
		if err != nil {
			return nil, closer, fmt.Errorf("signature database: %w", err)
		}
		e.DB = db
	}
	if rulesPath != "" {
		ys, _, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(func(f string, a ...interface{}) {
			fmt.Fprintf(stderr, "[WARN] "+f+"\n", a...)
		}))
		if err != nil {
			return nil, closer, fmt.Errorf("YARA rules: %w", err)
		}
		e.Yara = ys
		closer = func() { ys.Close() }
	}
	return e, closer, nil
}

// evasionReport measures one file.
func evasionReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evasion report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newEvasionFlags("report", fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *f.file == "" {
		return fail(stderr, report.ExitUsage, "evasion report: --file is required")
	}
	switch *f.format {
	case "text", "json":
	default:
		return fail(stderr, report.ExitUsage, "evasion report: unknown format %q (want text or json)", *f.format)
	}
	if _, err := os.Stat(*f.file); err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion report: %v", err)
	}

	rulesPath, _ := findResource(*f.rules, envRules, relRules)
	dbPath, _ := findResource(*f.db, envSignatures, relSignatures)
	e, closer, err := evasionEngine(rulesPath, dbPath, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion report: %v", err)
	}
	defer closer()

	res, _ := e.ScanFile(*f.file)
	sources, err := evasion.ReadRuleSources(rulesPath)
	if err != nil {
		// The report still works without the rule sources; the YARA
		// distances are then not derivable, and the report says so.
		fmt.Fprintf(stderr, "[WARN] %v\n", err)
		sources = nil
	}
	rep := evasion.Analyze(&res, evasion.Options{Sources: sources})

	if *f.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fail(stderr, report.ExitRunFailed, "evasion report: %v", err)
		}
		return report.ExitOK
	}
	if err := rep.WriteText(stdout); err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion report: %v", err)
	}
	return report.ExitOK
}

// evasionBench measures a corpus and reports the fragility per detector.
//
// The corpus is the user's: this ships no attacks and generates none. What it
// does is measure the shipped content against whatever suite it is pointed at,
// because a detector that cannot be attacked has not been tested.
func evasionBench(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evasion bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := newEvasionFlags("bench", fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *f.corpus == "" {
		return fail(stderr, report.ExitUsage, "evasion bench: --corpus is required")
	}
	switch *f.format {
	case "text", "json":
	default:
		return fail(stderr, report.ExitUsage, "evasion bench: unknown format %q (want text or json)", *f.format)
	}

	rulesPath, _ := findResource(*f.rules, envRules, relRules)
	dbPath, _ := findResource(*f.db, envSignatures, relSignatures)
	e, closer, err := evasionEngine(rulesPath, dbPath, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion bench: %v", err)
	}
	defer closer()

	sources, err := evasion.ReadRuleSources(rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] %v\n", err)
		sources = nil
	}

	bench, err := evasion.RunBench(e, *f.corpus, evasion.BenchOptions{Sources: sources})
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion bench: %v", err)
	}
	if *f.limit > 0 && len(bench.Samples) > *f.limit {
		bench.Samples = bench.Samples[:*f.limit]
		bench.Truncated = true
	}

	if *f.format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(bench); err != nil {
			return fail(stderr, report.ExitRunFailed, "evasion bench: %v", err)
		}
		return report.ExitOK
	}
	if err := bench.WriteText(stdout); err != nil {
		return fail(stderr, report.ExitRunFailed, "evasion bench: %v", err)
	}
	return report.ExitOK
}

// evasionCorpusRoot resolves a corpus path that is a directory of samples or
// a manifest, so the bench takes either.
func evasionCorpusRoot(p string) string {
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return filepath.Clean(p)
	}
	return filepath.Dir(p)
}

// evasionSortDetectors orders detector names for a stable report.
func evasionSortDetectors(names []string) []string {
	sort.Strings(names)
	return names
}

// evasionJoin renders a list for a message.
func evasionJoin(items []string) string {
	return strings.Join(evasionSortDetectors(items), ", ")
}

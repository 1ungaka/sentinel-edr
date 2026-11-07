package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/internal/eval/scannerbridge"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
)

func evalUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau eval <subcommand> [flags]

  validate  check a corpus manifest: paths, labels, hashes, provenance
  run       scan a corpus and write a measured report (optionally gate it)
  report    render a saved report as text or JSON
  diff      compare two reports ("this change adds 0.4 pt recall and 3x the FPs")
  gate      fail (exit 1) when a candidate report regresses against a baseline
  policy    print the default regression policy as JSON

Typical CI flow:
  cau eval validate --corpus corpus/smoke/manifest.json --verify-hashes
  cau eval run      --corpus corpus/smoke/manifest.json --rules rules --out report.json
  cau eval gate     --baseline baselines/smoke.json --candidate report.json

Exit codes: 0 ok, 1 validation errors / gate failed, 3 the run failed, 4 usage.
`)
}

func cmdEval(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		evalUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "validate":
		return evalValidate(args[1:], stdout, stderr)
	case "run":
		return evalRun(args[1:], stdout, stderr)
	case "report":
		return evalReport(args[1:], stdout, stderr)
	case "diff":
		return evalDiff(args[1:], stdout, stderr)
	case "gate":
		return evalGate(args[1:], stdout, stderr)
	case "policy":
		if err := eval.DefaultPolicy().WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "[ERROR] %v\n", err)
			return report.ExitRunFailed
		}
		return report.ExitOK
	case "help", "-h", "--help":
		evalUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown eval subcommand %q\n\n", args[0])
		evalUsage(stderr)
		return report.ExitUsage
	}
}

func fail(stderr io.Writer, code int, format string, a ...interface{}) int {
	fmt.Fprintf(stderr, "[ERROR] "+format+"\n", a...)
	return code
}

func writeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ── validate ─────────────────────────────────────────────────────────────────

func evalValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpus := fs.String("corpus", "", "corpus manifest (JSON)")
	verify := fs.Bool("verify-hashes", false, "recompute SHA-256 of samples that declare one")
	requireProv := fs.Bool("require-provenance", false, "malware samples without a provenance source are errors, not warnings")
	maxSize := fs.Int64("max-file-size", 0, "warn about samples larger than this many bytes")
	asJSON := fs.Bool("json", false, "print the validation result as JSON")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *corpus == "" {
		fs.Usage()
		return fail(stderr, report.ExitUsage, "--corpus is required")
	}
	m, err := eval.LoadManifest(*corpus)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	v := m.Validate(eval.ValidateOptions{VerifyHashes: *verify, RequireProvenance: *requireProv, MaxFileSize: *maxSize})
	if *asJSON {
		_ = writeJSON(stdout, v)
	} else {
		_ = v.WriteText(stdout)
	}
	if !v.OK() {
		return report.ExitThreat
	}
	return report.ExitOK
}

// ── run ──────────────────────────────────────────────────────────────────────

func evalRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	corpus := fs.String("corpus", "", "corpus manifest (JSON)")
	dbFlag := fs.String("db", "", "signature database (default: <manifest dir>/hashes.txt, else auto-discovered)")
	rulesFlag := fs.String("rules", "", "YARA rules (default: auto-discovered)")
	noHash := fs.Bool("no-hash", false, "disable the hash detector")
	noYara := fs.Bool("no-yara", false, "disable the YARA detector")
	noHeur := fs.Bool("no-heuristics", false, "disable the heuristic detector")
	threshold := fs.Int("heuristic-threshold", scanner.HeuristicThreshold, "heuristic detection threshold")
	noStatic := fs.Bool("no-static", false, "disable the static structural detector")
	staticThreshold := fs.Int("static-threshold", static.Threshold, "static detection threshold")
	fuzzyFlag := fs.String("fuzzy-db", "", "fuzzy signature database for the static detector (default: <manifest dir>/fuzzy.txt, else auto-discovered, else none)")
	noStego := fs.Bool("no-stego", false, "disable the invisible-codepoint (stego) detector")
	noEncChain := fs.Bool("no-encchain", false, "disable the encoded-executable detector")
	stegoThreshold := fs.Int("stego-threshold", stego.Threshold, "stego detection threshold")
	encChainThreshold := fs.Int("encchain-threshold", encchain.Threshold, "encoded-executable detection threshold")
	noFormats := fs.Bool("no-format-passes", false, "disable the format passes (.lnk, OLE, PDF, ISO, Linux package, peeler, archive, CHM, tradecraft)")
	noFusion := fs.Bool("no-fusion", false, "disable the fusion detector (corroboration of sub-threshold detectors)")
	jobs := fs.Int("jobs", 0, "samples scanned concurrently (default: number of CPUs)")
	onError := fs.String("on-error", string(eval.OnErrorExclude), "unscannable samples: exclude, miss (count as FN) or fail")
	maxSize := fs.Int64("max-file-size", 0, "skip samples larger than this many bytes")
	out := fs.String("out", "", "write the JSON report here (this is what you commit as a baseline)")
	format := fs.String("format", "text", "stdout rendering: text or json")
	baseline := fs.String("baseline", "", "also gate the run against this baseline report")
	policyPath := fs.String("policy", "", "regression policy JSON for --baseline (default: built-in policy)")
	verify := fs.Bool("verify-hashes", true, "validate the corpus (with hash verification) before running")
	quiet := fs.Bool("quiet", false, "no progress on stderr")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *corpus == "" {
		fs.Usage()
		return fail(stderr, report.ExitUsage, "--corpus is required")
	}
	mode, err := eval.ParseOnErrorMode(*onError)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}

	m, err := eval.LoadManifest(*corpus)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	v := m.Validate(eval.ValidateOptions{VerifyHashes: *verify})
	if !v.OK() {
		_ = v.WriteText(stderr)
		return fail(stderr, report.ExitRunFailed, "corpus is not usable for measurement")
	}
	if !*quiet {
		for _, w := range v.Warnings() {
			fmt.Fprintf(stderr, "[WARN] corpus: %s\n", w)
		}
	}

	// ── detectors ──
	var db *scanner.SignatureDB
	if !*noHash {
		dbPath := *dbFlag
		if dbPath == "" {
			if local := filepath.Join(m.Dir, "hashes.txt"); fileExists(local) {
				dbPath = local
			} else {
				dbPath, _ = findResource("", envSignatures, relSignatures)
			}
		}
		if dbPath == "" {
			return fail(stderr, report.ExitRunFailed, "no signature database found; pass --db or --no-hash")
		}
		if db, err = scanner.LoadSignatures(dbPath); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		if !*quiet {
			fmt.Fprintf(stderr, "[*] hash: %d signatures from %s\n", db.Count(), dbPath)
		}
	}
	var ys *scanner.YaraScanner
	if !*noYara {
		rulesPath, searched := findResource(*rulesFlag, envRules, relRules)
		if rulesPath == "" {
			return fail(stderr, report.ExitRunFailed, "no YARA rules found; pass --rules or --no-yara (searched: %s)", strings.Join(searched, ", "))
		}
		warn := func(format string, a ...interface{}) {
			if !*quiet {
				fmt.Fprintf(stderr, "[WARN] "+format+"\n", a...)
			}
		}
		var files int
		if ys, files, err = scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(warn)); err != nil {
			return fail(stderr, report.ExitRunFailed, "YARA: %v", err)
		}
		defer ys.Close()
		if !*quiet {
			fmt.Fprintf(stderr, "[*] yara: %d rules from %d file(s) at %s\n", ys.RuleCount(), files, rulesPath)
		}
	}
	th := *threshold
	if *noHeur {
		th = -1
	}
	detectors := scannerbridge.Engine(db, ys, th)
	var fuzzy *static.FuzzyDB
	if !*noStatic {
		fuzzyPath := *fuzzyFlag
		if fuzzyPath == "" {
			if local := filepath.Join(m.Dir, "fuzzy.txt"); fileExists(local) {
				fuzzyPath = local
			} else {
				fuzzyPath, _ = findResource("", envFuzzy, relFuzzy)
			}
		}
		if fuzzyPath != "" {
			if fuzzy, err = static.LoadFuzzyDB(fuzzyPath); err != nil {
				return fail(stderr, report.ExitRunFailed, "%v", err)
			}
			if !*quiet {
				fmt.Fprintf(stderr, "[*] static: %d fuzzy signatures from %s\n", fuzzy.Count(), fuzzyPath)
			}
		} else if !*quiet {
			fmt.Fprintln(stderr, "[*] static: no fuzzy database, similarity lookups off")
		}
		detectors = append(detectors, scannerbridge.StaticDetector(*staticThreshold, fuzzy))
	}
	if !*noStego {
		detectors = append(detectors, scannerbridge.StegoDetector(*stegoThreshold))
	}
	if !*noEncChain {
		detectors = append(detectors, scannerbridge.EncChainDetector(*encChainThreshold))
	}
	if !*noFormats {
		detectors = append(detectors, scannerbridge.PassDetectors()...)
	}
	if !*noFusion {
		// The fusion detector runs the same engine the CLI runs and reports
		// only what corroboration adds.
		fe := &scanner.Engine{
			DB:                 db,
			Yara:               ys,
			Heuristics:         !*noHeur,
			HeuristicThreshold: *threshold,
			Static:             !*noStatic,
			StaticThreshold:    *staticThreshold,
			FuzzyDB:            fuzzy,
			Stego:              !*noStego,
			StegoThreshold:     *stegoThreshold,
			EncChain:           !*noEncChain,
			EncChainThreshold:  *encChainThreshold,
		}
		if !*noFormats {
			scannerbridge.EnableFormatPasses(fe)
		}
		detectors = append(detectors, scannerbridge.FusionDetector(fe))
	}
	if len(detectors) == 0 {
		return fail(stderr, report.ExitUsage, "every detector is disabled")
	}

	// ── run ──
	ropts := eval.RunOptions{
		Concurrency: *jobs,
		OnError:     mode,
		MaxFileSize: *maxSize,
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
	rep := eval.NewReport(runRec)

	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fh, err := os.Create(*out)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		werr := rep.WriteJSON(fh, true)
		cerr := fh.Close()
		if werr != nil || cerr != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v %v", *out, werr, cerr)
		}
		if !*quiet {
			fmt.Fprintf(stderr, "[*] report written to %s\n", *out)
		}
	}
	if *format == "json" {
		if err := rep.WriteJSON(stdout, true); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else if err := rep.WriteText(stdout); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	if *baseline != "" {
		return gate(*baseline, rep, *policyPath, *format == "json", stdout, stderr)
	}
	return report.ExitOK
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// ── report / diff / gate ─────────────────────────────────────────────────────

func evalReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("report", "", "saved report JSON")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *path == "" {
		if fs.NArg() == 1 {
			*path = fs.Arg(0)
		} else {
			fs.Usage()
			return fail(stderr, report.ExitUsage, "--report is required")
		}
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	rep, err := eval.LoadReport(*path)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *format == "json" {
		err = rep.WriteJSON(stdout, true)
	} else {
		err = rep.WriteText(stdout)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return report.ExitOK
}

func evalDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("baseline", "", "baseline report JSON")
	cand := fs.String("candidate", "", "candidate report JSON")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *base == "" && *cand == "" && fs.NArg() == 2 {
		*base, *cand = fs.Arg(0), fs.Arg(1)
	}
	if *base == "" || *cand == "" {
		fs.Usage()
		return fail(stderr, report.ExitUsage, "--baseline and --candidate are required")
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	b, err := eval.LoadReport(*base)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	c, err := eval.LoadReport(*cand)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	d := eval.Diff(b, c)
	if *format == "json" {
		err = writeJSON(stdout, d)
	} else {
		err = d.WriteText(stdout)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return report.ExitOK
}

func evalGate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eval gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("baseline", "", "baseline report JSON (omit to apply absolute rules only)")
	cand := fs.String("candidate", "", "candidate report JSON")
	policyPath := fs.String("policy", "", "regression policy JSON (default: built-in policy)")
	format := fs.String("format", "text", "text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *cand == "" {
		fs.Usage()
		return fail(stderr, report.ExitUsage, "--candidate is required")
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	c, err := eval.LoadReport(*cand)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return gate(*base, c, *policyPath, *format == "json", stdout, stderr)
}

// gate evaluates candidate against baseline (optional) under the policy and
// prints the decision. Exit 1 on regression.
func gate(baselinePath string, candidate *eval.Report, policyPath string, asJSON bool, stdout, stderr io.Writer) int {
	var baseline *eval.Report
	if baselinePath != "" {
		b, err := eval.LoadReport(baselinePath)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		baseline = b
	}
	policy := eval.DefaultPolicy()
	if policyPath != "" {
		p, err := eval.LoadPolicy(policyPath)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		policy = p
	}
	dec := eval.IsRegression(baseline, candidate, policy)
	if asJSON {
		_ = writeJSON(stdout, struct {
			Decision eval.Decision    `json:"decision"`
			Diff     *eval.ReportDiff `json:"diff,omitempty"`
		}{dec, diffOrNil(baseline, candidate)})
	} else {
		if baseline != nil {
			fmt.Fprintln(stdout, eval.Diff(baseline, candidate).Summary())
		}
		_ = dec.WriteText(stdout)
	}
	if !dec.Pass {
		return report.ExitThreat
	}
	return report.ExitOK
}

func diffOrNil(b, c *eval.Report) *eval.ReportDiff {
	if b == nil {
		return nil
	}
	return eval.Diff(b, c)
}

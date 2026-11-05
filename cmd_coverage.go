package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s-b-repo/cau/internal/coverage"
	"github.com/s-b-repo/cau/internal/frameworks"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/static"
)

// ── coverage ─────────────────────────────────────────────────────────────────

func cmdCoverage(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	noYara := fs.Bool("no-yara", false, "leave YARA rules out of the matrix")
	db := fs.String("db", "", "signature database, counted only (default: auto-discovered)")
	fuzzyDB := fs.String("fuzzy-db", "", "fuzzy signature database, counted only (default: auto-discovered)")
	format := fs.String("format", "text", "output format: "+strings.Join(coverage.Formats, ", "))
	output := fs.String("output", "", "write the matrix to this file instead of stdout")
	pretty := fs.Bool("pretty", false, "indent JSON output")
	expect := fs.String("expect", "", "expectation file to compare the matrix against (exit 1 on any difference)")
	record := fs.Bool("record", false, "rewrite --expect from the current content, keeping its declared gaps")
	includeInfo := fs.Bool("include-info", false, "list weight-0 informational static classes under unmapped content")
	frameworksView := fs.Bool("frameworks", false, "append the Unified Kill Chain sequencing view (text format)")
	quiet := fs.Bool("quiet", false, "suppress progress lines on stderr")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "[ERROR] unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return report.ExitUsage
	}
	if *record && *expect == "" {
		fmt.Fprintln(stderr, "[ERROR] --record needs --expect")
		return report.ExitUsage
	}
	var write func(io.Writer, *coverage.Matrix) error
	switch strings.ToLower(*format) {
	case "text":
		write = coverage.WriteText
	case "json":
		write = func(w io.Writer, m *coverage.Matrix) error { return coverage.WriteJSON(w, m, *pretty) }
	case "navigator":
		write = func(w io.Writer, m *coverage.Matrix) error { return coverage.WriteNavigator(w, m, *pretty) }
	case "sarif":
		write = func(w io.Writer, m *coverage.Matrix) error { return coverage.WriteSARIF(w, m, *pretty) }
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown format %q (want one of %s)\n", *format, strings.Join(coverage.Formats, ", "))
		return report.ExitUsage
	}
	status := func(f string, a ...interface{}) {
		if !*quiet {
			fmt.Fprintf(stderr, f+"\n", a...)
		}
	}

	in := coverage.Inputs{Tool: toolName, Version: version, HashCount: -1, FuzzyCount: -1, IncludeInfo: *includeInfo}

	if !*noYara {
		rulesPath, searched := findResource(*rules, envRules, relRules)
		switch {
		case rulesPath == "" && *rules == "":
			status("[*] YARA rules not found; the matrix lists no rules (searched: %s)", strings.Join(searched, ", "))
		case rulesPath == "":
			return fail(stderr, report.ExitRunFailed, "YARA rules not found at %s", *rules)
		default:
			ys, files, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(func(f string, a ...interface{}) {
				status("[WARN] "+f, a...)
			}))
			if err != nil {
				return fail(stderr, report.ExitRunFailed, "YARA: %v", err)
			}
			defer ys.Close()
			in.Rules = ys.RuleInfos()
			in.YaraLoaded = true
			status("[*] %d YARA rules from %d file(s) at %s", ys.RuleCount(), files, rulesPath)
		}
	}
	if dbPath, _ := findResource(*db, envSignatures, relSignatures); dbPath != "" {
		if sdb, err := scanner.LoadSignatures(dbPath); err == nil {
			in.HashCount = sdb.Count()
		} else if *db != "" {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else if *db != "" {
		return fail(stderr, report.ExitRunFailed, "signature database not found at %s", *db)
	}
	if fzPath, _ := findResource(*fuzzyDB, envFuzzy, relFuzzy); fzPath != "" {
		if fdb, err := static.LoadFuzzyDB(fzPath); err == nil {
			in.FuzzyCount = fdb.Count()
		} else if *fuzzyDB != "" {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else if *fuzzyDB != "" {
		return fail(stderr, report.ExitRunFailed, "fuzzy database not found at %s", *fuzzyDB)
	}

	m := coverage.Build(in)

	code := report.ExitOK
	if *expect != "" {
		prev, err := coverage.LoadExpect(*expect)
		if err != nil && !(*record && os.IsNotExist(err)) {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		if *record {
			if err := os.WriteFile(*expect, coverage.Record(m, prev), 0o644); err != nil {
				return fail(stderr, report.ExitRunFailed, "%v", err)
			}
			status("[+] Recorded %d covered technique(s) to %s", len(m.Techniques), *expect)
			prev, err = coverage.LoadExpect(*expect)
			if err != nil {
				return fail(stderr, report.ExitRunFailed, "%v", err)
			}
		}
		problems := coverage.Compare(m, prev)
		for _, p := range problems {
			fmt.Fprintf(stderr, "[GATE] %s: %s\n", p.Kind, p.Text)
		}
		if len(problems) > 0 {
			fmt.Fprintf(stderr, "[GATE] FAIL: %d difference(s) between the content and %s (re-record on purpose with --record)\n", len(problems), *expect)
			code = report.ExitThreat
		} else {
			status("[*] Coverage matches %s: %d covered, %d declared gap(s)", *expect, len(m.Techniques), len(m.Gaps))
		}
	}

	if *output != "" {
		fh, err := os.Create(*output)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "cannot write %s: %v", *output, err)
		}
		// Check the close error too: on a written file it can be the only
		// signal of a truncated or failed flush.
		werr := write(fh, m)
		if cerr := fh.Close(); werr != nil || cerr != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v %v", *output, werr, cerr)
		}
		return code
	}
	if err := write(stdout, m); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *frameworksView {
		if strings.ToLower(*format) != "text" {
			return fail(stderr, report.ExitUsage, "--frameworks is only available with --format text")
		}
		writeFrameworks(stdout, m.TechniqueIDs())
	}
	return code
}

// writeFrameworks renders the Unified Kill Chain sequencing view of the covered
// techniques: which phases of an intrusion's progression the shipped content
// can observe, grouped by stage, with the empty phases named as honest gaps.
func writeFrameworks(w io.Writer, ids []string) {
	seq := frameworks.Sequence(ids)
	covered := make(map[string]frameworks.PhaseCoverage, len(seq))
	for _, pc := range seq {
		covered[pc.Phase] = pc
	}
	fmt.Fprintln(w, "\nUnified Kill Chain — sequencing view of the shipped content")
	fmt.Fprintln(w, "(ATT&CK mapped phase-wise alongside the matrix; empty phases are honest gaps)")
	fmt.Fprintln(w)
	lastStage := ""
	for _, phase := range frameworks.Phases() {
		stage := frameworks.StageForPhase(phase)
		if stage != lastStage {
			fmt.Fprintf(w, "  %s\n", strings.ToUpper(stage))
			lastStage = stage
		}
		if pc, ok := covered[phase]; ok {
			fmt.Fprintf(w, "    [x] %-20s %d technique(s): %s\n", phase, len(pc.Techniques), strings.Join(pc.Techniques, ", "))
		} else {
			fmt.Fprintf(w, "    [ ] %-20s —\n", phase)
		}
	}
	fmt.Fprintf(w, "\n%d of %d UKC phases have detection content.\n", len(seq), len(frameworks.Phases()))
}

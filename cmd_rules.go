package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/rulelint"
	"github.com/s-b-repo/cau/scanner"
)

func rulesUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau rules <subcommand> [flags]

  lint   check rule files: compile, required meta, technique ids, dead and
         short strings, trivial conditions (exit 1 on errors; --strict on warnings)
  list   print every compiled rule with its namespace, meta and technique

Examples:
  cau rules lint                              # the auto-discovered rules
  cau rules lint --rules ./signature-base --profile generic --format json
  cau rules list --format json

Exit codes: 0 ok, 1 lint failed, 3 the run failed, 4 usage.
`)
}

func cmdRules(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		rulesUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "lint":
		return rulesLint(args[1:], stdout, stderr)
	case "list":
		return rulesList(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		rulesUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown rules subcommand %q\n\n", args[0])
		rulesUsage(stderr)
		return report.ExitUsage
	}
}

func resolveRules(explicit string, stderr io.Writer) (string, int) {
	rulesPath, searched := findResource(explicit, envRules, relRules)
	if rulesPath == "" {
		if explicit != "" {
			return "", fail(stderr, report.ExitRunFailed, "YARA rules not found at %s", explicit)
		}
		return "", fail(stderr, report.ExitUsage, "YARA rules not found; pass --rules or set %s (searched: %s)", envRules, strings.Join(searched, ", "))
	}
	return rulesPath, report.ExitOK
}

func rulesLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	profile := fs.String("profile", rulelint.ProfileCAU, "lint profile: cau (bundled-content conventions) or generic (third-party rule sets)")
	format := fs.String("format", "text", "output format: text or json")
	output := fs.String("output", "", "write the report to this file instead of stdout")
	strict := fs.Bool("strict", false, "exit 1 on warnings too")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	rulesPath, code := resolveRules(*rules, stderr)
	if code != report.ExitOK {
		return code
	}
	rep, err := rulelint.Lint(rulesPath, rulelint.Options{Profile: *profile})
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	render := func(w io.Writer) error {
		if *format == "json" {
			return rep.WriteJSON(w, true)
		}
		return rep.WriteText(w)
	}
	if *output != "" {
		fh, ferr := os.Create(*output)
		if ferr != nil {
			return fail(stderr, report.ExitRunFailed, "cannot write %s: %v", *output, ferr)
		}
		// A close error on a written file can be the only sign of a failed
		// flush, so it is checked alongside the write.
		werr := render(fh)
		if cerr := fh.Close(); werr != nil || cerr != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v %v", *output, werr, cerr)
		}
	} else if err := render(stdout); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if rep.Failed(*strict) {
		fmt.Fprintf(stderr, "[LINT] FAIL: %d error(s), %d warning(s) in %d rule(s) from %s\n", rep.Errors, rep.Warnings, rep.Rules, rulesPath)
		return report.ExitThreat
	}
	return report.ExitOK
}

type ruleListing struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Tags      []string          `json:"tags,omitempty"`
	Private   bool              `json:"private,omitempty"`
	Global    bool              `json:"global,omitempty"`
	Strings   int               `json:"strings"`
	Technique []string          `json:"technique,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

func rulesList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "", "YARA rule file or directory (default: auto-discovered)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	rulesPath, code := resolveRules(*rules, stderr)
	if code != report.ExitOK {
		return code
	}
	ys, _, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(func(f string, a ...interface{}) {
		fmt.Fprintf(stderr, "[WARN] "+f+"\n", a...)
	}))
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "YARA: %v", err)
	}
	defer ys.Close()
	var listing []ruleListing
	for _, r := range ys.RuleInfos() {
		listing = append(listing, ruleListing{
			Name: r.Name, Namespace: r.Namespace, Tags: r.Tags, Private: r.Private, Global: r.Global,
			Strings: r.Strings, Technique: r.MetaTechnique(), Meta: r.Meta,
		})
	}
	if *format == "json" {
		if err := writeJSON(stdout, listing); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		return report.ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Namespace\tRule\tLevel\tFamily\tTechnique\tStrings\tDescription")
	for _, r := range listing {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.Namespace, r.Name, r.Meta["threat_level"], r.Meta["family"],
			strings.Join(r.Technique, ","), r.Strings, r.Meta["description"])
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d rule(s) from %s\n", len(listing), rulesPath)
	return report.ExitOK
}

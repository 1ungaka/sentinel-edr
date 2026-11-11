package main

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/1ungaka/sentinel-edr/internal/canary"
	"github.com/1ungaka/sentinel-edr/internal/report"
)

func canaryUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau canary <subcommand> [flags]

  plant   write decoy files into a directory and record their baseline manifest
  check   compare the decoys against the manifest and report any that tripped

Canaries are cheap ground truth: nothing legitimate opens a decoy the operator
planted and never advertised, so a canary that was rewritten, deleted, or
re-permissioned is a high-signal, near-zero-false-positive event. The engine
does not watch files at runtime (that is the sensor's job); 'check' is a
point-in-time comparison a cron job or task hook can run.

Flags:
  --dir <dir>        directory to plant decoys in / check (required)
  --manifest <path>  baseline manifest file (required)
  --count <n>        'plant' how many decoys (default 5, capped at the name set)
  --format <fmt>     'check' output: text or json

Examples:
  cau canary plant --dir /srv/share/.decoys --manifest ~/.cau/canary.json --count 8
  cau canary check --dir /srv/share/.decoys --manifest ~/.cau/canary.json

Exit codes (check): 0 all intact, 1 at least one canary tripped, 3 the run
failed, 4 usage.
`)
}

func cmdCanary(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		canaryUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "plant":
		return canaryPlant(args[1:], stdout, stderr)
	case "check":
		return canaryCheck(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		canaryUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown canary subcommand %q\n\n", args[0])
		canaryUsage(stderr)
		return report.ExitUsage
	}
}

func canaryPlant(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary plant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory to plant decoys in")
	manifest := fs.String("manifest", "", "baseline manifest file to write")
	count := fs.Int("count", 5, "how many decoys to plant")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *dir == "" || *manifest == "" {
		return fail(stderr, report.ExitUsage, "canary plant requires --dir and --manifest")
	}
	m, err := canary.Plant(*dir, *count)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := canary.WriteManifest(*manifest, m); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "planted %d decoy(s) in %s; baseline written to %s\n", len(m.Canaries), *dir, *manifest)
	return report.ExitOK
}

func canaryCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("canary check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifest := fs.String("manifest", "", "baseline manifest file to check against")
	format := fs.String("format", "text", "output format: text or json")
	// --dir is accepted for symmetry with plant but the manifest records
	// absolute paths, so it is not required; a mismatch warning would be
	// misleading. Kept undocumented-as-required, parsed to avoid a usage error.
	_ = fs.String("dir", "", "directory the decoys live in (informational; manifest paths are authoritative)")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *manifest == "" {
		return fail(stderr, report.ExitUsage, "canary check requires --manifest")
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	m, err := canary.ReadManifest(*manifest)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	results := canary.SortByPath(canary.Check(m))
	tripped := canary.Tripped(results)

	if *format == "json" {
		type row struct {
			Path   string `json:"path"`
			Status string `json:"status"`
			Detail string `json:"detail,omitempty"`
		}
		var rows []row
		for _, r := range results {
			rows = append(rows, row{Path: r.Canary.Path, Status: string(r.Status), Detail: r.Detail})
		}
		if err := writeJSON(stdout, rows); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "Status\tPath\tDetail")
		for _, r := range results {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Status, r.Canary.Path, r.Detail)
		}
		tw.Flush()
		fmt.Fprintf(stdout, "\n%d canary(ies), %d tripped\n", len(results), len(tripped))
	}

	if len(tripped) > 0 {
		return report.ExitThreat
	}
	return report.ExitOK
}

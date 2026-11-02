package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/intake"
	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/scanner"
)

func intakeUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau intake --format <fmt> (--input <file> | --url <url>) [flags]

Parses a threat-intelligence feed into hash signatures and appends the new ones
to the signature database, so the database is fed from machine-readable sources
instead of being hand-typed. Hashes already in the database are skipped (intake
never re-labels an existing entry).

Formats:
  stix           STIX 2.1 bundle (indicator SDOs with a file:hashes pattern)
  misp           MISP event JSON (CIRCL) — md5/sha1/sha256 attributes
  malwarebazaar  MalwareBazaar query/dump JSON (abuse.ch)
  loldrivers     LOLDrivers catalog JSON (known-malicious driver hashes)

Flags:
  --format <fmt>  feed format (required; one of the above)
  --input <file>  read the feed from a file ('-' for stdin)
  --url <url>     fetch the feed over HTTP(S) instead (explicit; never automatic)
  --db <path>     signature database (default: auto-discovered)
  --dry-run       print the new signatures instead of writing them
  --output <file> write the new signatures here instead of appending to --db

Examples:
  cau intake --format loldrivers --input drivers.json
  cau intake --format malwarebazaar --url https://mb-api.abuse.ch/... --dry-run
  curl -s https://example/stix.json | cau intake --format stix --input -

Exit codes: 0 ok (even if nothing new), 3 the run failed, 4 usage.
`)
}

func cmdIntake(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("intake", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "feed format: "+strings.Join(intake.Formats(), ", "))
	input := fs.String("input", "", "feed file ('-' for stdin)")
	url := fs.String("url", "", "fetch the feed from this URL instead")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	dryRun := fs.Bool("dry-run", false, "print new signatures instead of writing them")
	output := fs.String("output", "", "write new signatures here instead of appending to the database")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format == "" {
		return fail(stderr, report.ExitUsage, "--format is required (one of %s)", strings.Join(intake.Formats(), ", "))
	}
	if (*input == "") == (*url == "") {
		return fail(stderr, report.ExitUsage, "give exactly one of --input or --url")
	}

	// Read the feed.
	var data []byte
	var err error
	switch {
	case *url != "":
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		data, err = intake.Fetch(ctx, *url)
	case *input == "-":
		data, err = readStdinCapped(maxInputBytes)
	default:
		data, err = readFileCapped(*input, maxInputBytes)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	iocs, err := intake.Parse(*format, data)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stderr, "[*] parsed %d indicator(s) from the %s feed\n", len(iocs), *format)

	// Resolve the database for dedup (missing is fine for a fresh DB).
	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	var existing *scanner.SignatureDB
	if dbPath != "" {
		existing, err = scanner.LoadSignatures(dbPath)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "loading %s: %v", dbPath, err)
		}
	} else if !*dryRun && *output == "" {
		return fail(stderr, report.ExitUsage, "signature database not found; pass --db, or use --dry-run/--output (searched: %s)", strings.Join(searched, ", "))
	}

	res := intake.Apply(existing, iocs)
	rendered := intake.Render(res.Signatures)

	switch {
	case *dryRun:
		stdout.Write(rendered)
		fmt.Fprintf(stderr, "[*] dry-run: %d new, %d already present\n", res.Added, res.Skipped)
		return report.ExitOK
	case *output != "":
		if err := os.WriteFile(*output, rendered, 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v", *output, err)
		}
		fmt.Fprintf(stdout, "[+] wrote %d new signature(s) to %s (%d already present)\n", res.Added, *output, res.Skipped)
		return report.ExitOK
	default:
		if res.Added == 0 {
			fmt.Fprintf(stdout, "[*] nothing new: all %d indicator(s) already in %s\n", res.Skipped, dbPath)
			return report.ExitOK
		}
		if err := appendSignatures(dbPath, rendered); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fmt.Fprintf(stdout, "[+] appended %d new signature(s) to %s (%d already present)\n", res.Added, dbPath, res.Skipped)
		return report.ExitOK
	}
}

// appendSignatures appends rendered lines to the database file, ensuring the
// file ends with a newline first so a new entry never joins the last line.
func appendSignatures(path string, rendered []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("could not open %s for writing: %w", path, err)
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil && fi.Size() > 0 {
		buf := make([]byte, 1)
		if r, rerr := os.Open(path); rerr == nil {
			if _, rerr = r.ReadAt(buf, fi.Size()-1); rerr == nil && buf[0] != '\n' {
				if _, werr := f.WriteString("\n"); werr != nil {
					r.Close()
					return werr
				}
			}
			r.Close()
		}
	}
	if _, err := f.Write(rendered); err != nil {
		return fmt.Errorf("writing to %s: %w", path, err)
	}
	return nil
}

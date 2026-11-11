package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/intake"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/scanner"
)

func intakeUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau intake --format <fmt> (--input <file> | --url <url> | --taxii <collection>) [flags]

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
  --taxii <url>   poll a TAXII 2.1 collection (…/collections/<id>/) for STIX
                  objects; implies --format stix
  --added-after <ts>   with --taxii: only objects added after this RFC 3339 time
  --taxii-state <file> with --taxii: keep the polling cursor here, so each run
                  asks only for what was added since the last one that wrote
  --auth-env <VAR> environment variable holding the Authorization header value
                  for --taxii (default CAU_INTAKE_AUTH; never on argv)
  --allow-http    permit a cleartext http:// TAXII collection (off by default)
  --provenance <file>  append one JSON line per new signature: source, origin,
                  retrieved-at and the confidence the source stated
  --db <path>     signature database (default: auto-discovered)
  --dry-run       print the new signatures instead of writing them
  --output <file> write the new signatures here instead of appending to --db

Examples:
  cau intake --format loldrivers --input drivers.json
  cau intake --format malwarebazaar --url https://mb-api.abuse.ch/... --dry-run
  curl -s https://example/stix.json | cau intake --format stix --input -
  cau intake --taxii https://intel.example/api/collections/<id>/ \
      --taxii-state /var/lib/cau/taxii.state --provenance /var/lib/cau/intake.jsonl

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
	taxii := fs.String("taxii", "", "poll this TAXII 2.1 collection for STIX objects")
	addedAfter := fs.String("added-after", "", "with --taxii: only objects added after this RFC 3339 time")
	taxiiState := fs.String("taxii-state", "", "with --taxii: file holding the polling cursor between runs")
	authEnv := fs.String("auth-env", "CAU_INTAKE_AUTH", "environment variable holding the Authorization header value for --taxii")
	allowHTTP := fs.Bool("allow-http", false, "permit a cleartext http:// TAXII collection")
	provenance := fs.String("provenance", "", "append a JSON-lines provenance record per new signature to this file")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *taxii != "" {
		if *format == "" {
			*format = intake.FormatSTIX
		}
		if !strings.EqualFold(strings.TrimSpace(*format), intake.FormatSTIX) {
			return fail(stderr, report.ExitUsage, "--taxii serves STIX; --format must be stix (or omitted)")
		}
	} else if *addedAfter != "" || *taxiiState != "" || *allowHTTP {
		return fail(stderr, report.ExitUsage, "--added-after, --taxii-state and --allow-http need --taxii")
	}
	if *format == "" {
		return fail(stderr, report.ExitUsage, "--format is required (one of %s)", strings.Join(intake.Formats(), ", "))
	}
	sources := 0
	for _, v := range []string{*input, *url, *taxii} {
		if v != "" {
			sources++
		}
	}
	if sources != 1 {
		return fail(stderr, report.ExitUsage, "give exactly one of --input, --url or --taxii")
	}
	if *addedAfter != "" && *taxiiState != "" {
		return fail(stderr, report.ExitUsage, "--added-after and --taxii-state both set the cursor; give one")
	}

	// Read the feed.
	var data []byte
	var err error
	var origin string
	var cursor intake.TAXIIState // the polling cursor to persist after a write
	saveCursor := false
	retrieved := time.Now()
	switch {
	case *taxii != "":
		origin = *taxii
		opts := intake.TAXIIOptions{
			CollectionURL: *taxii, AddedAfter: *addedAfter,
			Authorization: os.Getenv(*authEnv), AllowHTTP: *allowHTTP,
		}
		if *taxiiState != "" {
			if cursor, err = intake.LoadTAXIIState(*taxiiState, *taxii); err != nil {
				return fail(stderr, report.ExitRunFailed, "%v", err)
			}
			opts.AddedAfter = cursor.AddedAfter
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		res, ferr := intake.FetchTAXII(ctx, opts)
		if ferr != nil {
			return fail(stderr, report.ExitRunFailed, "%v", ferr)
		}
		since := "the whole collection"
		if opts.AddedAfter != "" {
			since = "added after " + opts.AddedAfter
		}
		fmt.Fprintf(stderr, "[*] TAXII: %d object(s) in %d page(s), %s\n", len(res.Objects), res.Pages, since)
		if res.Truncated {
			fmt.Fprintln(stderr, "[WARN] TAXII: the poll hit its page or object bound with more on the server; run again to continue (the cursor was not advanced, so the objects left behind are asked for again)")
		}
		if *taxiiState != "" && res.LastAdded != "" {
			cursor.AddedAfter, saveCursor = res.LastAdded, true
		}
		data = res.Bundle()
	case *url != "":
		origin = *url
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		data, err = intake.Fetch(ctx, *url)
	case *input == "-":
		origin = "stdin"
		data, err = readStdinCapped(maxInputBytes)
	default:
		origin = *input
		data, err = readFileCapped(*input, maxInputBytes)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	iocs, err := intake.Parse(*format, data)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	intake.Stamp(iocs, origin, retrieved)
	fmt.Fprintf(stderr, "[*] parsed %d indicator(s) from the %s feed\n", len(iocs), *format)

	// writeProvenance appends the provenance records of the newly accepted
	// indicators. It runs BEFORE the signatures are committed: an intake run
	// that wrote them first and then lost the provenance append could never
	// repair it, because the next run sees those hashes as already present and
	// Apply returns nothing to write records for. Failure here leaves nothing
	// committed — the database and the provenance log both stay as they were,
	// so the run can simply be repeated.
	writeProvenance := func(res intake.ApplyResult) error {
		if *provenance == "" || len(res.Accepted) == 0 {
			return nil
		}
		rec, err := intake.Provenance(res.Accepted)
		if err != nil {
			return err
		}
		return appendFile(*provenance, rec)
	}

	// recordWrite runs after the new signatures have been written somewhere
	// durable: it advances the TAXII cursor. A dry run does neither, so it can
	// be repeated and shows the same thing.
	recordWrite := func() int {
		if saveCursor {
			if serr := intake.SaveTAXIIState(*taxiiState, cursor, time.Now()); serr != nil {
				return fail(stderr, report.ExitRunFailed, "signatures written, but the TAXII cursor was not saved (the next run will re-read them and skip them as present): %v", serr)
			}
		}
		return report.ExitOK
	}

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
		// Provenance first, commit second: a failed provenance append leaves
		// nothing written, so the run can be repeated and nothing is lost.
		if err := writeProvenance(res); err != nil {
			return fail(stderr, report.ExitRunFailed, "nothing written, the provenance record was not either: %v", err)
		}
		if err := os.WriteFile(*output, rendered, 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "writing %s: %v", *output, err)
		}
		fmt.Fprintf(stdout, "[+] wrote %d new signature(s) to %s (%d already present)\n", res.Added, *output, res.Skipped)
		return recordWrite()
	default:
		if res.Added == 0 {
			fmt.Fprintf(stdout, "[*] nothing new: all %d indicator(s) already in %s\n", res.Skipped, dbPath)
			return recordWrite()
		}
		if err := writeProvenance(res); err != nil {
			return fail(stderr, report.ExitRunFailed, "nothing appended, the provenance record was not either: %v", err)
		}
		if err := appendSignatures(dbPath, rendered); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fmt.Fprintf(stdout, "[+] appended %d new signature(s) to %s (%d already present)\n", res.Added, dbPath, res.Skipped)
		return recordWrite()
	}
}

// appendFile appends data to path, creating it owner-readable only: a
// provenance log names intel sources, which is not for every local user.
func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
	if err := f.Close(); err != nil { // the deferred one is then a no-op
		return fmt.Errorf("writing to %s: %w", path, err)
	}
	return nil
}

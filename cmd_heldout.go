package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/1ungaka/sentinel-edr/internal/heldout"
	"github.com/1ungaka/sentinel-edr/internal/report"
)

const defaultHeldoutDB = "corpus/heldout/hashes.db"

func heldoutUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau heldout <subcommand> [flags]

  init      create a new, empty encrypted hash database
  pull      download a full feed + intel (MalwareBazaar) into the database,
            incrementally, resuming an interrupted run
  add       add (or replace) a sample hash
  remove    drop a sample hash
  list      print the records (decrypts in memory; hashes never hit disk)
  manifest  emit a live eval corpus manifest for the recorded hashes

The held-out recall corpus is the set of real malware samples the detectors
are measured against but were NOT authored from. Their SHA-256 hashes are the
only identity stored, encrypted at rest with AES-256-GCM under a passphrase
(PBKDF2). The ciphertext database is safe to commit; the hashes and the
samples are not. 'manifest' produces, on demand, the source manifest that
scripts/fetch-heldout.sh consumes to re-download and verify the bytes.

Passphrase: set CAU_HELDOUT_KEY, or pass --key-file <path>.

Flags:
  --db <path>        encrypted database (default `+defaultHeldoutDB+`)
  --key-file <path>  read the passphrase from a file instead of the env
  --sha256 <hex>     (add/remove) the sample's SHA-256, 64 hex chars
  --family <name>    (add) the malware family, e.g. "lokibot"
  --label <name>     (add) positive label; defaults to the family
  --url <url>        (add) provenance URL
  --license <id>     (add) provenance licence
  --notes <text>     (add) free-form note
  --root <dir>       (manifest) where the fetched samples live
                     (default: the database's directory + /samples)
  --out <path>       (manifest) write here instead of stdout

Pull flags:
  --source <full|recent>  which MalwareBazaar export (default full)
  --url <url>             override the export URL
  --limit <n>             stop after n new records (0 = all)
  --family <name>         keep only rows whose signature matches
  --batch <n>             records between encrypted checkpoints (default 20000)
  --retries <n>           download attempts before giving up (default 5)

Examples:
  export CAU_HELDOUT_KEY=...                     # or --key-file
  cau heldout init
  cau heldout pull --source full                 # full DB + intel, resumable
  cau heldout pull --source recent               # fast daily top-up
  cau heldout add --sha256 <64hex> --family lokibot --url https://bazaar.abuse.ch/sample/<64hex>/
  cau heldout list
  cau heldout manifest --out corpus/heldout/manifest.json

A pull is incremental and self-recovering: it checkpoints the encrypted
database every --batch new records, resumes an interrupted download, and skips
hashes already present, so re-running after a crash continues where it left
off rather than starting over.

Exit codes: 0 ok, 3 run failed (incl. wrong passphrase), 4 usage.
`)
}

func cmdHeldout(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		heldoutUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "init":
		return heldoutInit(args[1:], stdout, stderr)
	case "add":
		return heldoutAdd(args[1:], stdout, stderr)
	case "pull", "sync":
		return heldoutPull(args[1:], stdout, stderr)
	case "remove", "rm":
		return heldoutRemove(args[1:], stdout, stderr)
	case "list", "ls":
		return heldoutList(args[1:], stdout, stderr)
	case "manifest":
		return heldoutManifest(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		heldoutUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown heldout subcommand %q\n\n", args[0])
		heldoutUsage(stderr)
		return report.ExitUsage
	}
}

// heldoutCommon parses the --db/--key-file flags every subcommand shares and
// resolves the passphrase.
func heldoutFlags(fs *flag.FlagSet) (db, keyFile *string) {
	db = fs.String("db", defaultHeldoutDB, "encrypted database path")
	keyFile = fs.String("key-file", "", "passphrase file")
	return db, keyFile
}

func heldoutInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	if _, err := os.Stat(*db); err == nil {
		return fail(stderr, report.ExitUsage, "%s already exists; refusing to overwrite", *db)
	}
	if err := os.MkdirAll(filepath.Dir(*db), 0o755); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if err := heldout.Save(*db, &heldout.DB{}, key); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "created empty encrypted database %s\n", *db)
	return report.ExitOK
}

func heldoutAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	sha := fs.String("sha256", "", "sample SHA-256 (64 hex)")
	family := fs.String("family", "", "malware family")
	label := fs.String("label", "", "positive label (defaults to family)")
	url := fs.String("url", "", "provenance URL")
	license := fs.String("license", "", "provenance licence")
	notes := fs.String("notes", "", "free-form note")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *sha == "" || *family == "" {
		return fail(stderr, report.ExitUsage, "heldout add requires --sha256 and --family")
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	d, code := heldoutLoad(*db, key, stderr)
	if code != report.ExitOK {
		return code
	}
	if err := d.Add(heldout.Record{
		SHA256: *sha, Family: *family, Label: *label,
		URL: *url, License: *license, Notes: *notes,
	}); err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	if err := heldout.Save(*db, d, key); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "recorded %s (%s); %d sample(s) in %s\n", *sha, *family, len(d.Records), *db)
	return report.ExitOK
}

func heldoutPull(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout pull", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	source := fs.String("source", "full", "MalwareBazaar export: full or recent")
	url := fs.String("url", "", "override the export URL")
	limit := fs.Int("limit", 0, "stop after n new records (0 = all)")
	family := fs.String("family", "", "keep only rows whose signature matches")
	batch := fs.Int("batch", 20000, "records between encrypted checkpoints")
	retries := fs.Int("retries", 5, "download attempts before giving up")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	feedURL := *url
	if feedURL == "" {
		switch *source {
		case "full":
			feedURL = heldout.MBFullCSV
		case "recent":
			feedURL = heldout.MBRecentCSV
		default:
			return fail(stderr, report.ExitUsage, "unknown --source %q (want full or recent)", *source)
		}
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}

	// Load an existing database so present hashes are skipped (this is what
	// makes a re-run resume); start empty if there is none yet.
	d, err := heldout.Load(*db, key)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if mkErr := os.MkdirAll(filepath.Dir(*db), 0o755); mkErr != nil {
			return fail(stderr, report.ExitRunFailed, "%v", mkErr)
		}
		d = &heldout.DB{}
	case errors.Is(err, heldout.ErrWrongKey):
		return fail(stderr, report.ExitRunFailed, "%v", err)
	case err != nil:
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	before := d.Len()

	cache := filepath.Join(filepath.Dir(*db), ".heldout-download.zip")
	lastPrint := 0
	opts := heldout.PullOptions{
		URL:     feedURL,
		Cache:   cache,
		Limit:   *limit,
		Family:  *family,
		Batch:   *batch,
		Retries: *retries,
		Progress: func(added, seen int) {
			if added-lastPrint >= 5000 {
				lastPrint = added
				fmt.Fprintf(stderr, "\r  %d new, %d seen…", added, seen)
			}
		},
	}
	save := func(cur *heldout.DB) error { return heldout.Save(*db, cur, key) }

	stats, perr := heldout.Pull(context.Background(), d, save, opts)
	if lastPrint > 0 {
		fmt.Fprintln(stderr)
	}
	if perr != nil {
		// Whatever was checkpointed is on disk; the cache is left for resume.
		return fail(stderr, report.ExitRunFailed,
			"%v (progress saved: %d sample(s) in %s; re-run to resume)", perr, d.Len(), *db)
	}
	// Success: the stale download cache is no longer needed.
	_ = os.Remove(cache)
	fmt.Fprintf(stdout, "pulled %s: %d new, %d updated, %d rows seen; database now holds %d sample(s) (was %d)\n",
		*source, stats.Added, stats.Updated, stats.Seen, d.Len(), before)
	return report.ExitOK
}

func heldoutRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	sha := fs.String("sha256", "", "sample SHA-256 to remove")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *sha == "" {
		return fail(stderr, report.ExitUsage, "heldout remove requires --sha256")
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	d, code := heldoutLoad(*db, key, stderr)
	if code != report.ExitOK {
		return code
	}
	ok, err := d.Remove(*sha)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	if !ok {
		return fail(stderr, report.ExitRunFailed, "%s is not in the database", *sha)
	}
	if err := heldout.Save(*db, d, key); err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	fmt.Fprintf(stdout, "removed %s; %d sample(s) remain\n", *sha, len(d.Records))
	return report.ExitOK
}

func heldoutList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	d, code := heldoutLoad(*db, key, stderr)
	if code != report.ExitOK {
		return code
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SHA256\tFAMILY\tADDED\tURL")
	for _, r := range d.Records {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.SHA256, r.Family, r.Added, r.URL)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "%d sample(s)\n", len(d.Records))
	return report.ExitOK
}

func heldoutManifest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heldout manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	db, keyFile := heldoutFlags(fs)
	root := fs.String("root", "", "directory the fetched samples live in")
	out := fs.String("out", "", "write here instead of stdout")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	key, err := heldout.ReadKey(*keyFile)
	if err != nil {
		return fail(stderr, report.ExitUsage, "%v", err)
	}
	d, code := heldoutLoad(*db, key, stderr)
	if code != report.ExitOK {
		return code
	}
	r := *root
	if r == "" {
		r = filepath.Join(filepath.Dir(*db), "samples")
	}
	m, err := d.Manifest(r)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, m, 0o644); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		fmt.Fprintf(stderr, "wrote %s (%d sample(s))\n", *out, len(d.Records))
		return report.ExitOK
	}
	stdout.Write(m)
	return report.ExitOK
}

// heldoutLoad loads the database, turning a missing file and a wrong
// passphrase into distinct, actionable messages.
func heldoutLoad(db string, key []byte, stderr io.Writer) (*heldout.DB, int) {
	d, err := heldout.Load(db, key)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fail(stderr, report.ExitRunFailed, "%s does not exist; run 'cau heldout init' first", db)
	case errors.Is(err, heldout.ErrWrongKey):
		return nil, fail(stderr, report.ExitRunFailed, "%v", err)
	case err != nil:
		return nil, fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return d, report.ExitOK
}

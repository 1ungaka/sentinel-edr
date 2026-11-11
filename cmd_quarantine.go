package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/quarantine"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/scanner"
	"github.com/1ungaka/sentinel-edr/scanner/fusion"
)

// envQuarantine overrides the default vault location.
const envQuarantine = "CAU_QUARANTINE_DIR"

func quarantineUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: cau quarantine <subcommand> [flags]

  add      <path>      move a file into the vault (neutralized, integrity-sealed)
  list                 list vault entries (newest first)
  restore  <id>        restore an entry to its original path or --to <path>
  verify   [id]        verify one entry, or the whole vault, against its digests
  delete   <id>        permanently purge an entry from the vault

The vault is a local, neutralized store for files a scan flagged: each entry is
XOR-masked at rest (never a runnable PE/ELF on disk, never re-flagged by a
scanner) and sealed with the SHA-256 of both the original and the stored bytes,
so a restore that cannot reproduce the original digest fails closed.

Flags:
  --store <dir>   vault directory (default: %s, or $%s)
  --threat <name> label for 'add' (default: "manual")
  --keep          'add' copies instead of moving (leaves the original in place)
  --to <path>     'restore' destination (default: the recorded original path)
  --force         'restore' overwrites an existing destination
  --format <fmt>  'list' output: text or json

Examples:
  cau quarantine add ./suspicious.exe --threat Win.Trojan.Agent
  cau quarantine list --format json
  cau quarantine verify
  cau quarantine restore 1a2b... --to ./recovered.exe

Exit codes: 0 ok, 1 integrity failure, 3 the run failed, 4 usage.
`, defaultQuarantineDir(), envQuarantine)
}

// defaultQuarantineDir resolves the vault path: $CAU_QUARANTINE_DIR, else
// $XDG_DATA_HOME/cau/quarantine, else ~/.local/share/cau/quarantine, else a
// ./cau-quarantine fallback when the home directory is unknown.
func defaultQuarantineDir() string {
	if env := os.Getenv(envQuarantine); env != "" {
		return env
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "cau", "quarantine")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "cau", "quarantine")
	}
	return "cau-quarantine"
}

func cmdQuarantine(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		quarantineUsage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "add":
		return quarantineAdd(args[1:], stdout, stderr)
	case "list":
		return quarantineList(args[1:], stdout, stderr)
	case "restore":
		return quarantineRestore(args[1:], stdout, stderr)
	case "verify":
		return quarantineVerify(args[1:], stdout, stderr)
	case "delete":
		return quarantineDelete(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		quarantineUsage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown quarantine subcommand %q\n\n", args[0])
		quarantineUsage(stderr)
		return report.ExitUsage
	}
}

// openVault resolves --store (consumed from the flag set by the caller) and
// opens it. It is called after flag parsing.
func openVault(store string, stderr io.Writer) (*quarantine.Store, int) {
	if store == "" {
		store = defaultQuarantineDir()
	}
	s, err := quarantine.Open(store)
	if err != nil {
		return nil, fail(stderr, report.ExitRunFailed, "%v", err)
	}
	return s, report.ExitOK
}

func quarantineAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quarantine add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	store := fs.String("store", "", "vault directory")
	threat := fs.String("threat", "manual", "threat label for the entry")
	keep := fs.Bool("keep", false, "copy into the vault instead of moving")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 1 {
		return fail(stderr, report.ExitUsage, "quarantine add takes exactly one path")
	}
	s, code := openVault(*store, stderr)
	if code != report.ExitOK {
		return code
	}
	e, err := s.Quarantine(fs.Arg(0), *threat, *keep)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	action := "moved"
	if *keep {
		action = "copied"
	}
	fmt.Fprintf(stdout, "%s %s into the vault as %s (%s, %d bytes)\n", action, report.TermSafe(e.OriginalPath), e.ID, report.TermSafe(e.ThreatName), e.Size)
	return report.ExitOK
}

func quarantineList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quarantine list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	store := fs.String("store", "", "vault directory")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	s, code := openVault(*store, stderr)
	if code != report.ExitOK {
		return code
	}
	entries, err := s.List()
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if *format == "json" {
		if err := writeJSON(stdout, entries); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		return report.ExitOK
	}
	if len(entries) == 0 {
		fmt.Fprintf(stdout, "Vault is empty (%s)\n", s.Dir())
		return report.ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tThreat\tSize\tQuarantined\tOriginal")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", e.ID, report.TermSafe(e.ThreatName), e.Size, e.QuarantinedAt.Format(time.RFC3339), report.TermSafe(e.OriginalPath))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d entr%s in %s\n", len(entries), plural(len(entries)), s.Dir())
	return report.ExitOK
}

func quarantineRestore(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quarantine restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	store := fs.String("store", "", "vault directory")
	to := fs.String("to", "", "destination path (default: the recorded original)")
	force := fs.Bool("force", false, "overwrite the destination if it exists")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 1 {
		return fail(stderr, report.ExitUsage, "quarantine restore takes exactly one entry id")
	}
	s, code := openVault(*store, stderr)
	if code != report.ExitOK {
		return code
	}
	dest, err := s.Restore(fs.Arg(0), *to, *force)
	if err != nil {
		return quarantineErrCode(stderr, err)
	}
	fmt.Fprintf(stdout, "restored %s to %s\n", fs.Arg(0), dest)
	return report.ExitOK
}

func quarantineVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quarantine verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	store := fs.String("store", "", "vault directory")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() > 1 {
		return fail(stderr, report.ExitUsage, "quarantine verify takes at most one entry id")
	}
	s, code := openVault(*store, stderr)
	if code != report.ExitOK {
		return code
	}
	if fs.NArg() == 1 {
		if err := s.Verify(fs.Arg(0)); err != nil {
			return quarantineErrCode(stderr, err)
		}
		fmt.Fprintf(stdout, "%s: intact\n", fs.Arg(0))
		return report.ExitOK
	}
	failed, err := s.VerifyAll()
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	if len(failed) == 0 {
		fmt.Fprintf(stdout, "vault intact (%s)\n", s.Dir())
		return report.ExitOK
	}
	for _, id := range failed {
		fmt.Fprintf(stderr, "[INTEGRITY] %s failed verification\n", id)
	}
	return report.ExitThreat
}

func quarantineDelete(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quarantine delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	store := fs.String("store", "", "vault directory")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 1 {
		return fail(stderr, report.ExitUsage, "quarantine delete takes exactly one entry id")
	}
	s, code := openVault(*store, stderr)
	if code != report.ExitOK {
		return code
	}
	if err := s.Delete(fs.Arg(0)); err != nil {
		return quarantineErrCode(stderr, err)
	}
	fmt.Fprintf(stdout, "deleted %s\n", fs.Arg(0))
	return report.ExitOK
}

// quarantineErrCode maps a library error to the right exit code: an integrity
// failure is ExitThreat (1), anything else is ExitRunFailed (3).
func quarantineErrCode(stderr io.Writer, err error) int {
	if errors.Is(err, quarantine.ErrIntegrity) {
		return fail(stderr, report.ExitThreat, "%v", err)
	}
	return fail(stderr, report.ExitRunFailed, "%v", err)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// autoQuarantine moves every MALICIOUS-verdict result into the vault, returning
// the number moved. It is the free-prevention path for `cau scan --quarantine`:
// it acts only on the high-confidence tier (hash/YARA hits), never on
// sub-threshold suspicions, because the move is destructive. A per-file failure
// is reported and skipped, not fatal — one unwritable file never aborts the
// rest.
// level selects what auto-quarantine acts on:
//   - "malicious": only the hard MALICIOUS tier (a hash or YARA hit).
//   - "suspicious": also files the fusion lattice places at the SUSPICIOUS tier
//     — i.e. the fused, multi-indicator score (each indicator at its own
//     weighted level) crossed the fusion threshold, with or without a single
//     detector crossing on its own. This is score-based blocking.
func autoQuarantine(store, level string, results []scanner.ScanResult, status func(string, ...interface{})) (int, error) {
	if store == "" {
		store = defaultQuarantineDir()
	}
	var s *quarantine.Store
	moved := 0
	for _, r := range results {
		reason, hit := quarantineReason(r, level)
		if !hit {
			continue
		}
		if s == nil {
			var err error
			if s, err = quarantine.Open(store); err != nil {
				return moved, err
			}
		}
		if _, err := s.Quarantine(r.FilePath, reason, false); err != nil {
			status("[WARN] could not quarantine %s: %s", report.TermSafe(r.FilePath), report.TermSafe(err.Error()))
			continue
		}
		moved++
		status("[*] quarantined %s (%s)", report.TermSafe(r.FilePath), report.TermSafe(reason))
	}
	return moved, nil
}

// quarantineReason decides whether a result should be blocked at the given
// level and returns the threat label to record. The label names the indicators
// that drove the decision, so the vault entry carries the evidence.
func quarantineReason(r scanner.ScanResult, level string) (string, bool) {
	if r.Verdict == scanner.VerdictMalicious {
		return maliciousName(r), true
	}
	if level == "suspicious" && r.Fusion != nil &&
		(r.Fusion.Tier == fusion.TierSuspicious || r.Fusion.Tier == fusion.TierMalicious) {
		label := fmt.Sprintf("suspicious score %.2f/%.2f", r.Fusion.Score, r.Fusion.Threshold)
		if len(r.Fusion.Agreed) > 0 {
			label += " [" + strings.Join(r.Fusion.Agreed, "+") + "]"
		}
		if len(r.Fusion.Techniques) > 0 {
			label += " (" + strings.Join(r.Fusion.Techniques, ",") + ")"
		}
		return label, true
	}
	return "", false
}

// maliciousName derives a threat label for a quarantined file: the hash
// signature's name, else the matched YARA rule names, else a generic fallback.
func maliciousName(r scanner.ScanResult) string {
	if n := strings.TrimSpace(r.ThreatName); n != "" {
		return n
	}
	if len(r.YaraMatches) > 0 {
		names := make([]string, 0, len(r.YaraMatches))
		for _, m := range r.YaraMatches {
			names = append(names, m.RuleName)
		}
		return "YARA:" + strings.Join(names, ",")
	}
	return "malicious"
}

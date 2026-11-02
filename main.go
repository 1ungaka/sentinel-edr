// Command cau is the CAU EDR command line: a transparent, open-source malware
// detection engine (hash signatures, YARA, string/API heuristics, static
// structure, invisible-codepoint steganography, and a fusion lattice over all
// of them) with machine-readable output, CI exit codes and a measured
// evaluation harness.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/cau-edr/cau/internal/harden"
	"github.com/cau-edr/cau/internal/peeler"
	"github.com/cau-edr/cau/internal/release"
	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/internal/sdnotify"
	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/archive"
	"github.com/cau-edr/cau/scanner/chm"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/linuxpkg"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "0.4.0-dev"

const (
	toolName    = "CAU EDR"
	toolTagline = "Certs Are Useless — detection that trusts no certificate"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `%s %s
%s

Usage:
  cau scan      [flags] [path ...]     scan files and directories
  cau hash      [flags] <path ...>     print SHA-256, imphash, TLSH and ssdeep digests
  cau cluster   [flags] <path ...>     group PE files by import-table similarity
  cau add-hash  [flags]                append a hash signature to the database
  cau add-fuzzy [flags]                append a TLSH / ssdeep / imphash signature
  cau eval      <subcommand> [flags]   corpus evaluation harness (see "cau eval help")
  cau heldout   <subcommand> [flags]   encrypted held-out recall-corpus hash database
  cau rules     lint|list [flags]      lint the YARA rules, or list them with their meta
  cau coverage  [flags]                ATT&CK coverage matrix of the shipped content
                                       (text, JSON or ATT&CK Navigator layer; gate with --expect)
  cau quarantine <subcommand>          vault flagged files (add/list/restore/verify/delete)
  cau canary    plant|check [flags]    plant decoy files and detect tampering
  cau peel      [flags] <file>         walk an obfuscation chain, depth as signal
  cau firmware  [flags] <image>        parse a UEFI firmware image (FV/FFS inventory, integrity, implant blocklist)
  cau ps        [flags]                scan the live process table (/proc) for fileless/masquerade/injection
  cau installed [flags]                audit installed-package maintainer scripts (dpkg/pacman) for tradecraft
  cau feed      <subcommand>           manage the abuse-intel feed (list/check/update; offline cache + opt-in fetch)
  cau intake    --format <fmt> [flags] ingest a threat-intel feed into the signature DB
  cau update    (--from|--url) [flags] install a signed signature-DB bundle (fail-closed)
  cau selftest  [--record] [flags]     verify detection content has not been tampered with
  cau verify-self (--from|--url) [flags] verify this binary against the signed release manifest
  cau bundle    update|checksums [flags] produce signed release artifacts (CI)
  cau version                          print the version

Scan examples:
  cau scan --file suspicious.exe
  cau scan --dir ./samples --format sarif --output cau.sarif
  cau scan ./build --format json --fail-on heuristic
  cau scan ./dist --format ocsf --output findings.json   # OCSF Detection Findings
  cau scan --dir /mnt/usb --quarantine                    # detect AND prevent in one pass
  cau scan --dir / --interval 1h --quiet                  # run as a background daemon (systemd: packaging/)
  cau scan --dir / --jobs 16 --no-heuristics --no-static --quiet

Detectors: hash signatures, YARA, string/API heuristics, the static
structural pass (entropy, packer, section/entry-point/signature anomalies,
TLSH/ssdeep/imphash similarity) and the stego pass (zero-width and other
invisible codepoints in text and code). Heuristic, static and stego breaches
are the SUSPICIOUS tier; hash and YARA hits are MALICIOUS. The fusion lattice
joins every detector's evidence: sub-threshold sources that corroborate each
other are reported SUSPICIOUS with the sources that agreed named.

Exit codes (scan): 0 clean, 1 findings at or above --fail-on, 2 some files
could not be scanned, 3 the run itself failed, 4 usage error.

Resources: the signature database, the YARA rules and the fuzzy database are
found automatically (next to the binary, <prefix>/share/cau, /usr/share/cau,
or the working directory); override with --db / --rules / --fuzzy-db or
%s / %s / %s.
`, toolName, version, toolTagline, envSignatures, envRules, envFuzzy)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return report.ExitUsage
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "add-hash":
		return cmdAddHash(args[1:], stdout, stderr)
	case "add-fuzzy":
		return cmdAddFuzzy(args[1:], stdout, stderr)
	case "hash":
		return cmdHash(args[1:], stdout, stderr)
	case "cluster":
		return cmdCluster(args[1:], stdout, stderr)
	case "eval":
		return cmdEval(args[1:], stdout, stderr)
	case "heldout":
		return cmdHeldout(args[1:], stdout, stderr)
	case "rules":
		return cmdRules(args[1:], stdout, stderr)
	case "coverage":
		return cmdCoverage(args[1:], stdout, stderr)
	case "quarantine":
		return cmdQuarantine(args[1:], stdout, stderr)
	case "canary":
		return cmdCanary(args[1:], stdout, stderr)
	case "peel":
		return cmdPeel(args[1:], stdout, stderr)
	case "firmware":
		return cmdFirmware(args[1:], stdout, stderr)
	case "ps":
		return cmdPs(args[1:], stdout, stderr)
	case "feed":
		return cmdFeed(args[1:], stdout, stderr)
	case "installed":
		return cmdInstalled(args[1:], stdout, stderr)
	case "intake":
		return cmdIntake(args[1:], stdout, stderr)
	case "update":
		return cmdUpdate(args[1:], stdout, stderr)
	case "selftest":
		return cmdSelftest(args[1:], stdout, stderr)
	case "verify-self":
		return cmdVerifySelf(args[1:], stdout, stderr)
	case "bundle":
		return cmdBundle(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s %s\n", toolName, version)
		return report.ExitOK
	case "help", "-h", "--help":
		usage(stdout)
		return report.ExitOK
	default:
		fmt.Fprintf(stderr, "[ERROR] unknown command %q\n\n", args[0])
		usage(stderr)
		return report.ExitUsage
	}
}

// ── scan ─────────────────────────────────────────────────────────────────────

type scanFlags struct {
	file, dir         string
	db, rules         string
	noYara, noHeur    bool
	noStatic, noFuzzy bool
	noStego, noFusion bool
	noEncChain        bool
	noLNK             bool
	noOLE             bool
	noPDF             bool
	noISO             bool
	noPkg             bool
	noPeel            bool
	noArchive         bool
	noCHM             bool
	quarantine        bool
	quarantineStore   string
	quarantineLevel   string
	interval          time.Duration
	fuzzyDB           string
	signers           string
	heurThreshold     int
	staticThreshold   int
	stegoThreshold    int
	encChainThreshold int
	lnkThreshold      int
	oleThreshold      int
	pdfThreshold      int
	isoThreshold      int
	pkgThreshold      int
	feed              string
	peelThreshold     int
	archiveThreshold  int
	chmThreshold      int
	format, output    string
	pretty            bool
	failOn            string
	noFailOnScanError bool
	jobs              int
	followSymlinks    bool
	maxInMemoryMiB    int64
	yaraTimeout       time.Duration
	quiet             bool
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.file, "file", "", "a single file to scan (positional paths are accepted too)")
	fs.StringVar(&f.dir, "dir", "", "a directory to scan recursively")
	fs.StringVar(&f.db, "db", "", "signature database (default: auto-discovered, see 'cau help')")
	fs.StringVar(&f.rules, "rules", "", "YARA rule file or directory (default: auto-discovered)")
	fs.BoolVar(&f.noYara, "no-yara", false, "disable YARA scanning")
	fs.BoolVar(&f.noHeur, "no-heuristics", false, "disable string & API heuristics")
	fs.IntVar(&f.heurThreshold, "heuristic-threshold", scanner.HeuristicThreshold, "heuristic score at which a file is reported suspicious")
	fs.BoolVar(&f.noStatic, "no-static", false, "disable the static structural analysis (entropy, packer, PE anomalies, similarity)")
	fs.IntVar(&f.staticThreshold, "static-threshold", static.Threshold, "static anomaly score at which a file is reported suspicious")
	fs.StringVar(&f.fuzzyDB, "fuzzy-db", "", "fuzzy signature database (TLSH/ssdeep/imphash; default: auto-discovered, optional)")
	fs.StringVar(&f.signers, "signers", "", "known-abused code-signing certificate blocklist (lolcerts; optional)")
	fs.BoolVar(&f.noFuzzy, "no-fuzzy", false, "skip TLSH/ssdeep computation (faster on large files; disables similarity lookups)")
	fs.BoolVar(&f.noStego, "no-stego", false, "disable the invisible-codepoint (stego) pass over text and code artifacts")
	fs.IntVar(&f.stegoThreshold, "stego-threshold", stego.Threshold, "stego score at which a text artifact is reported suspicious (default is presence-based)")
	fs.BoolVar(&f.noEncChain, "no-encchain", false, "disable the encoded-executable (base64/hex layers decoding to a PE/ELF) pass")
	fs.IntVar(&f.encChainThreshold, "encchain-threshold", encchain.Threshold, "score at which an encoded-executable match is reported suspicious")
	fs.BoolVar(&f.noLNK, "no-lnk", false, "disable the Windows Shell Link (.lnk) pass")
	fs.IntVar(&f.lnkThreshold, "lnk-threshold", lnk.Threshold, "score at which a Shell Link (.lnk) match is reported suspicious")
	fs.BoolVar(&f.noOLE, "no-ole", false, "disable the OLE compound-file (VBA macro) pass")
	fs.IntVar(&f.oleThreshold, "ole-threshold", ole.Threshold, "score at which an OLE macro match is reported suspicious")
	fs.BoolVar(&f.noPDF, "no-pdf", false, "disable the PDF malicious-document pass")
	fs.IntVar(&f.pdfThreshold, "pdf-threshold", pdf.Threshold, "score at which a PDF document match is reported suspicious")
	fs.BoolVar(&f.noISO, "no-iso", false, "disable the ISO 9660 malicious-container pass")
	fs.IntVar(&f.isoThreshold, "iso-threshold", iso.Threshold, "score at which an ISO container match is reported suspicious")
	fs.BoolVar(&f.noPkg, "no-pkg", false, "disable the Linux software-package pass (.deb/.rpm/Arch/Flatpak/AppImage/PKGBUILD install scripts)")
	fs.IntVar(&f.pkgThreshold, "pkg-threshold", linuxpkg.Threshold, "score at which a Linux package's install scripts are reported suspicious")
	fs.StringVar(&f.feed, "feed", "", "abuse-intel feed file to match indicators against (default: search path; empty if none)")
	fs.BoolVar(&f.noPeel, "no-peel", false, "disable the obfuscation-chain peeler (NOVEL-012)")
	fs.IntVar(&f.peelThreshold, "peel-threshold", peeler.Threshold, "score at which an obfuscation chain is reported suspicious")
	fs.BoolVar(&f.noArchive, "no-archive", false, "disable the compressed-container pass (ZIP/TAR/gzip: bombs, Zip-Slip, lure/payload members)")
	fs.IntVar(&f.archiveThreshold, "archive-threshold", archive.Threshold, "score at which a compressed container is reported suspicious")
	fs.BoolVar(&f.noCHM, "no-chm", false, "disable the Compiled HTML Help (CHM) pass (embedded executables, shortcuts, dangerous scripts)")
	fs.IntVar(&f.chmThreshold, "chm-threshold", chm.Threshold, "score at which a CHM file is reported suspicious")
	fs.BoolVar(&f.quarantine, "quarantine", false, "after scanning, move files with a MALICIOUS verdict into the quarantine vault (free prevention; default off)")
	fs.StringVar(&f.quarantineStore, "quarantine-store", "", "vault directory for --quarantine (default: the cau quarantine default)")
	fs.StringVar(&f.quarantineLevel, "quarantine-level", "malicious", "what --quarantine blocks: 'malicious' (hash/YARA only) or 'suspicious' (also the fused multi-indicator score)")
	fs.DurationVar(&f.interval, "interval", 0, "daemon mode: re-scan every interval (e.g. 15m, 1h) until a termination signal; 0 scans once and exits")
	fs.BoolVar(&f.noFusion, "no-fusion", false, "disable the fusion lattice (corroboration of sub-threshold detectors)")
	fs.StringVar(&f.format, "format", "text", "output format: "+strings.Join(report.Formats, ", "))
	fs.StringVar(&f.output, "output", "", "write the report to this file instead of stdout")
	fs.BoolVar(&f.pretty, "pretty", false, "indent JSON/SARIF output")
	fs.StringVar(&f.failOn, "fail-on", string(report.FailOnMalicious), "exit 1 at this finding level: none, malicious, heuristic, clean")
	fs.BoolVar(&f.noFailOnScanError, "no-fail-on-scan-error", false, "do not exit 2 when some files could not be scanned")
	fs.IntVar(&f.jobs, "jobs", 0, "files scanned concurrently (default: number of CPUs)")
	fs.BoolVar(&f.followSymlinks, "follow-symlinks", false, "scan the targets of symlinks to files (directory symlinks are never followed)")
	fs.Int64Var(&f.maxInMemoryMiB, "max-in-memory", scanner.DefaultMaxInMemory>>20, "largest file (MiB) read into memory; bigger files are streamed and skip heuristics")
	fs.DurationVar(&f.yaraTimeout, "yara-timeout", scanner.DefaultScanTimeout, "per-file YARA scan budget")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress the banner and progress lines on stderr")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}

	var targets []string
	if f.file != "" {
		targets = append(targets, f.file)
	}
	if f.dir != "" {
		targets = append(targets, f.dir)
	}
	targets = append(targets, fs.Args()...)
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "[ERROR] nothing to scan: give --file, --dir or a path")
		fs.Usage()
		return report.ExitUsage
	}

	level, err := report.ParseFailOn(f.failOn)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitUsage
	}
	if f.heurThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --heuristic-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.staticThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --static-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.stegoThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --stego-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.encChainThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --encchain-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.lnkThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --lnk-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.oleThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --ole-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.pdfThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --pdf-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.pkgThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --pkg-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.isoThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --iso-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.peelThreshold < 1 {
		fmt.Fprintln(stderr, "[ERROR] --peel-threshold must be at least 1")
		return report.ExitUsage
	}
	if f.quarantineLevel != "malicious" && f.quarantineLevel != "suspicious" {
		fmt.Fprintln(stderr, "[ERROR] --quarantine-level must be 'malicious' or 'suspicious'")
		return report.ExitUsage
	}

	opts := []report.Option{
		report.WithToolName(toolName),
		report.WithToolVersion(version),
		report.WithFailOn(level),
		report.WithFailOnScanError(!f.noFailOnScanError),
		report.WithHeuristicThreshold(f.heurThreshold),
		report.WithStaticThreshold(f.staticThreshold),
		report.WithStegoThreshold(f.stegoThreshold),
		report.WithEncChainThreshold(f.encChainThreshold),
		report.WithLNKThreshold(f.lnkThreshold),
		report.WithOLEThreshold(f.oleThreshold),
		report.WithPDFThreshold(f.pdfThreshold),
		report.WithISOThreshold(f.isoThreshold),
		report.WithLinuxPkgThreshold(f.pkgThreshold),
		report.WithPeelThreshold(f.peelThreshold),
		report.WithIndent(f.pretty),
	}
	if f.dir != "" && len(targets) == 1 {
		opts = append(opts, report.WithRoot(f.dir))
	}
	reporter, err := report.NewReporter(f.format, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitUsage
	}
	policy := report.NewExitPolicy(opts...)

	status := func(format string, a ...interface{}) {
		if !f.quiet {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}
	if !f.quiet {
		printBanner(stderr)
	}

	// finish writes the report (even when the run failed, so JSON/SARIF
	// consumers always get a document) and returns the exit code.
	finish := func(in report.Input) int {
		if f.output != "" {
			fh, err := os.Create(f.output)
			if err != nil {
				fmt.Fprintf(stderr, "[ERROR] cannot write %s: %v\n", f.output, err)
				return report.ExitRunFailed
			}
			// Check the close error too: on a written file it can be the
			// only sign of a truncated or failed flush.
			werr := reporter.Write(fh, in)
			cerr := fh.Close()
			if werr != nil || cerr != nil {
				fmt.Fprintf(stderr, "[ERROR] writing %s: %v %v\n", f.output, werr, cerr)
				return report.ExitRunFailed
			}
			if in.RunError != nil {
				fmt.Fprintf(stderr, "[ERROR] %v\n", in.RunError)
			}
			status("[*] %s", policy.Explain(in))
			return policy.Code(in)
		}
		if err := reporter.Write(stdout, in); err != nil {
			fmt.Fprintf(stderr, "[ERROR] writing report: %v\n", err)
			return report.ExitRunFailed
		}
		if in.RunError != nil {
			fmt.Fprintf(stderr, "[ERROR] %v\n", in.RunError)
		}
		status("[*] %s", policy.Explain(in))
		return policy.Code(in)
	}

	// ── resources ──
	dbPath, searched := findResource(f.db, envSignatures, relSignatures)
	if dbPath == "" {
		return finish(report.Input{RunError: fmt.Errorf("signature database not found; pass --db or set %s (searched: %s)",
			envSignatures, strings.Join(searched, ", "))})
	}
	db, err := scanner.LoadSignatures(dbPath)
	if err != nil {
		return finish(report.Input{RunError: err})
	}
	for _, w := range db.Warnings() {
		status("[WARN] %s", w)
	}
	status("[*] Loaded %d hash signatures from %s", db.Count(), dbPath)

	var ys *scanner.YaraScanner
	if !f.noYara {
		rulesPath, searched := findResource(f.rules, envRules, relRules)
		switch {
		case rulesPath == "" && f.rules == "":
			status("[*] YARA rules not found, YARA disabled (pass --rules or set %s; searched: %s)",
				envRules, strings.Join(searched, ", "))
		case rulesPath == "":
			return finish(report.Input{RunError: fmt.Errorf("YARA rules not found at %s", f.rules)})
		default:
			yopts := []scanner.YaraOption{scanner.WithTimeout(f.yaraTimeout)}
			if f.quiet {
				yopts = append(yopts, scanner.WithWarnFunc(func(string, ...interface{}) {}))
			} else {
				yopts = append(yopts, scanner.WithWarnFunc(func(format string, a ...interface{}) {
					fmt.Fprintf(stderr, "[WARN] "+format+"\n", a...)
				}))
			}
			var files int
			ys, files, err = scanner.LoadYaraRules(rulesPath, yopts...)
			if err != nil {
				return finish(report.Input{RunError: fmt.Errorf("YARA: %w", err)})
			}
			defer ys.Close()
			status("[*] Compiled %d YARA rules from %d file(s) at %s (%d warning(s))",
				ys.RuleCount(), files, rulesPath, len(ys.Warnings()))
		}
	} else {
		status("[*] YARA disabled")
	}
	if f.noHeur {
		status("[*] Heuristics disabled")
	} else {
		status("[*] Heuristics enabled (threshold %d)", f.heurThreshold)
	}

	var fuzzy *static.FuzzyDB
	switch {
	case f.noStatic:
		status("[*] Static analysis disabled")
	default:
		fuzzyPath, searched := findResource(f.fuzzyDB, envFuzzy, relFuzzy)
		switch {
		case fuzzyPath == "" && f.fuzzyDB == "":
			status("[*] Static analysis enabled (threshold %d); no fuzzy database found, similarity lookups off (searched: %s)",
				f.staticThreshold, strings.Join(searched, ", "))
		case fuzzyPath == "":
			return finish(report.Input{RunError: fmt.Errorf("fuzzy database not found at %s", f.fuzzyDB)})
		case f.noFuzzy:
			status("[*] Static analysis enabled (threshold %d); --no-fuzzy set, similarity lookups off", f.staticThreshold)
		default:
			fuzzy, err = static.LoadFuzzyDB(fuzzyPath)
			if err != nil {
				return finish(report.Input{RunError: err})
			}
			for _, w := range fuzzy.Warnings() {
				status("[WARN] %s", w)
			}
			status("[*] Static analysis enabled (threshold %d); %d fuzzy signatures from %s", f.staticThreshold, fuzzy.Count(), fuzzyPath)
		}
	}

	var signerBL *static.SignerBlocklist
	if path := f.signers; path != "" || os.Getenv(envSigners) != "" {
		if path == "" {
			path = os.Getenv(envSigners)
		}
		signerBL, err = static.LoadSignerBlocklist(path)
		if err != nil {
			return finish(report.Input{RunError: err})
		}
		status("[*] Signer blocklist enabled: %d known-abused certificate(s) from %s", signerBL.Count(), path)
	}

	if f.noStego {
		status("[*] Stego pass disabled")
	} else {
		status("[*] Stego pass enabled (threshold %d)", f.stegoThreshold)
	}
	if f.noEncChain {
		status("[*] Encoded-executable pass disabled")
	} else {
		status("[*] Encoded-executable pass enabled (threshold %d)", f.encChainThreshold)
	}
	if f.noLNK {
		status("[*] Shell Link (.lnk) pass disabled")
	} else {
		status("[*] Shell Link (.lnk) pass enabled (threshold %d)", f.lnkThreshold)
	}
	if f.noOLE {
		status("[*] OLE macro pass disabled")
	} else {
		status("[*] OLE macro pass enabled (threshold %d)", f.oleThreshold)
	}
	if f.noPDF {
		status("[*] PDF document pass disabled")
	} else {
		status("[*] PDF document pass enabled (threshold %d)", f.pdfThreshold)
	}
	if f.noISO {
		status("[*] ISO container pass disabled")
	} else {
		status("[*] ISO container pass enabled (threshold %d)", f.isoThreshold)
	}
	if f.noPkg {
		status("[*] Linux software-package pass disabled")
	} else {
		status("[*] Linux software-package pass enabled (threshold %d)", f.pkgThreshold)
	}
	if f.noPeel {
		status("[*] Obfuscation-chain peeler disabled")
	} else {
		status("[*] Obfuscation-chain peeler enabled (threshold %d)", f.peelThreshold)
	}
	if f.noFusion {
		status("[*] Fusion disabled")
	}

	feed := loadFeedQuiet(f.feed)
	if feed != nil {
		status("[*] Abuse-intel feed loaded (%d indicators from %s)", feed.Count(), feed.Source())
	}

	engine := &scanner.Engine{
		DB:                 db,
		Yara:               ys,
		Heuristics:         !f.noHeur,
		HeuristicThreshold: f.heurThreshold,
		Static:             !f.noStatic,
		StaticThreshold:    f.staticThreshold,
		FuzzyDB:            fuzzy,
		StaticNoFuzzy:      f.noFuzzy,
		SignerBlocklist:    signerBL,
		Stego:              !f.noStego,
		StegoThreshold:     f.stegoThreshold,
		EncChain:           !f.noEncChain,
		EncChainThreshold:  f.encChainThreshold,
		LNK:                !f.noLNK,
		LNKThreshold:       f.lnkThreshold,
		OLE:                !f.noOLE,
		OLEThreshold:       f.oleThreshold,
		PDF:                !f.noPDF,
		PDFThreshold:       f.pdfThreshold,
		ISO:                !f.noISO,
		ISOThreshold:       f.isoThreshold,
		LinuxPkg:           !f.noPkg,
		LinuxPkgThreshold:  f.pkgThreshold,
		Intel:              feed,
		Peel:               !f.noPeel,
		PeelThreshold:      f.peelThreshold,
		Archive:            !f.noArchive,
		ArchiveThreshold:   f.archiveThreshold,
		CHM:                !f.noCHM,
		CHMThreshold:       f.chmThreshold,
		NoFusion:           f.noFusion,
		MaxInMemory:        f.maxInMemoryMiB << 20,
		Jobs:               f.jobs,
		FollowSymlinks:     f.followSymlinks,
	}

	// scanOnce runs every target through the engine once and returns the report
	// Input (with prevention applied). It is the unit the daemon loop repeats.
	scanOnce := func() report.Input {
		start := time.Now()
		in := report.Input{}
		for _, target := range targets {
			info, err := os.Stat(target)
			if err != nil {
				in.Results = append(in.Results, scanner.ScanResult{FilePath: target, Verdict: scanner.VerdictError, Error: err})
				continue
			}
			if info.IsDir() {
				status("[*] Scanning directory %s", target)
				rs, hs := engine.ScanDirectory(target, nil)
				in.Results = append(in.Results, rs...)
				in.Heuristics = append(in.Heuristics, hs...)
				continue
			}
			status("[*] Scanning %s", target)
			r, h := engine.ScanFile(target)
			in.Results = append(in.Results, r)
			if h != nil {
				in.Heuristics = append(in.Heuristics, *h)
			}
		}
		in.Elapsed = time.Since(start)

		// Prevention (free): move flagged files into the vault. Explicit
		// --quarantine only; destructive. --quarantine-level chooses the bar:
		// 'malicious' (hash/YARA) or 'suspicious' (the fused multi-indicator
		// score). Auto-detect → score → block, in one pass.
		if f.quarantine {
			moved, qerr := autoQuarantine(f.quarantineStore, f.quarantineLevel, in.Results, status)
			if qerr != nil {
				fmt.Fprintf(stderr, "[ERROR] quarantine: %v\n", qerr)
			}
			status("[*] Quarantined %d file(s) at the %s level", moved, f.quarantineLevel)
		}
		return in
	}

	// One-shot (default): scan once and exit with the policy's code.
	if f.interval <= 0 {
		return finish(scanOnce())
	}

	// Daemon mode: an automated background run. Re-scan every --interval until a
	// termination signal, writing the report each cycle (the latest cycle's
	// report, when --output is set). A per-cycle finding never exits the daemon;
	// the loop exits 0 on a clean shutdown. This is the portable scheduled
	// scanner — register it as a systemd service (see packaging/systemd) or a
	// Windows service wrapper; real-time kernel monitoring is the sensor's job.
	return runScanDaemon(f.interval, scanOnce, finish, status, stderr)
}

// runScanDaemon runs scanOnce on a fixed interval until SIGINT/SIGTERM, writing
// the report each cycle via finish. It is the engine's automated background run:
// a resident, scheduled scanner with no external dependency, suitable to run
// under a systemd service, a container entrypoint, or a Windows service wrapper.
// It returns ExitOK on a clean shutdown; a per-cycle finding is logged, not
// fatal, because a daemon must keep running.
//
// Resilience and self-protection, applied here because a long-lived privileged
// process is a target:
//   - Self-protection: the process is made non-dumpable and no-new-privs
//     (harden.Apply) so its in-memory state — the pinned trust anchor, the
//     signature set — cannot be read out via ptrace/core dump, and a coerced
//     exec cannot escalate.
//   - Tamper-evidence: the running binary's own SHA-256 is logged at startup,
//     so the operator can compare it to the signed release (cau verify-self).
//   - Crash recovery: every scan cycle runs under a panic barrier, so a bug on
//     one cycle is logged and the daemon continues rather than dying.
//   - Hang/death recovery: when run under a systemd notify+watchdog unit, it
//     pings the watchdog on its own cadence (independent of the scan interval),
//     so a deadlock, a wedged call, or a crash trips an automatic restart.
func runScanDaemon(interval time.Duration, scanOnce func() report.Input, finish func(report.Input) int, status func(string, ...interface{}), stderr io.Writer) int {
	status("[*] %s", harden.Apply().Summary())
	if digest, name, err := release.SelfDigest(); err == nil {
		status("[*] Running binary: %s sha256=%s (compare with the signed release via 'cau verify-self')", name, digest)
	} else {
		status("[WARN] could not self-measure the running binary: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	stop := make(chan struct{})
	go func() { <-sig; close(stop) }()

	// Watchdog keep-alive, driven by the unit's WatchdogSec (WATCHDOG_USEC).
	// It runs on its own ticker so the long sleep between scans is never
	// mistaken for a hang; it stops as soon as shutdown begins.
	startWatchdog(stop, status)
	if sdnotify.Enabled() {
		_ = sdnotify.Ready()
		_ = sdnotify.Status(fmt.Sprintf("ready; scanning every %s", interval))
	}

	status("[*] Daemon mode: scanning every %s (Ctrl-C or SIGTERM to stop)", interval)
	var cycles, crashes uint64
	cycle := func() {
		cycles++
		if sdnotify.Enabled() {
			_ = sdnotify.Status(fmt.Sprintf("scanning (cycle %d)", cycles))
		}
		crashed := runCycle(func() {
			code := finish(scanOnce())
			status("[*] Cycle %d complete (exit code would be %d in one-shot mode); next scan in %s", cycles, code, interval)
		}, status)
		if crashed {
			crashes++
			status("[WARN] cycle %d crashed and was recovered; daemon continues (%d crash(es) so far)", cycles, crashes)
		}
		if sdnotify.Enabled() {
			_ = sdnotify.Watchdog() // a completed cycle is proof of liveness
			_ = sdnotify.Status(fmt.Sprintf("idle; %d cycle(s), %d recovered crash(es)", cycles, crashes))
		}
	}
	scanLoop(interval, cycle, stop)

	if sdnotify.Enabled() {
		_ = sdnotify.Stopping()
	}
	status("[*] Shutting down the scan daemon (%d cycle(s), %d recovered crash(es))", cycles, crashes)
	return report.ExitOK
}

// runCycle executes one scan cycle behind a panic barrier. A panic anywhere in
// the cycle (a detector, report writing, quarantine) is caught, logged with its
// stack, and reported as crashed — the daemon must survive one bad cycle. It
// returns true when it recovered a panic.
func runCycle(cycle func(), status func(string, ...interface{})) (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			crashed = true
			status("[ERROR] recovered from a cycle panic: %v\n%s", r, debug.Stack())
		}
	}()
	cycle()
	return false
}

// startWatchdog begins pinging the systemd watchdog on the recommended cadence
// (half the WatchdogSec window) until stop is closed. It is a no-op when the
// unit has no watchdog configured, so a hand-run daemon spawns no goroutine.
func startWatchdog(stop <-chan struct{}, status func(string, ...interface{})) {
	every := sdnotify.WatchdogInterval()
	if every <= 0 {
		return
	}
	status("[*] systemd watchdog active: pinging every %s", every)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = sdnotify.Watchdog()
			}
		}
	}()
}

// scanLoop runs cycle immediately, then once per interval, until stop is closed.
// It is the testable core of the scan daemon (no signals, no process state).
// cycle is expected to contain its own panic barrier (see runCycle), so a
// crashing cycle never breaks the loop.
func scanLoop(interval time.Duration, cycle func(), stop <-chan struct{}) {
	cycle() // scan immediately, then on each tick
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cycle()
		}
	}
}

func printBanner(w io.Writer) {
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, " %s %s\n", toolName, version)
	fmt.Fprintf(w, " %s\n", toolTagline)
	fmt.Fprintln(w, " Detection: Hash + YARA + Heuristics + Static + Stego + EncChain, fused")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintln(w)
}

// ── add-hash ─────────────────────────────────────────────────────────────────

func cmdAddHash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add-hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hash := fs.String("hash", "", "hash value to add")
	typ := fs.String("type", "", "hash type: MD5, SHA1 or SHA256 (default: inferred from the length)")
	name := fs.String("name", "", "threat name (e.g. \"WannaCry Ransomware\")")
	db := fs.String("db", "", "signature database (default: auto-discovered)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *hash == "" || *name == "" {
		fmt.Fprintln(stderr, "[ERROR] --hash and --name are required")
		fs.Usage()
		return report.ExitUsage
	}
	hashType := *typ
	if hashType == "" {
		t, ok := scanner.HashTypeFor(*hash)
		if !ok {
			fmt.Fprintf(stderr, "[ERROR] cannot infer the hash type of %q from its length; pass --type\n", *hash)
			return report.ExitUsage
		}
		hashType = t
	}
	dbPath, searched := findResource(*db, envSignatures, relSignatures)
	if dbPath == "" {
		fmt.Fprintf(stderr, "[ERROR] signature database not found; pass --db (searched: %s)\n", strings.Join(searched, ", "))
		return report.ExitUsage
	}
	if err := scanner.AddSignature(dbPath, hashType, *hash, *name); err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitRunFailed
	}
	t, h, _ := scanner.ValidateHash(hashType, *hash)
	fmt.Fprintf(stdout, "[+] Added to %s: %s|%s|%s\n", filepath.Clean(dbPath), t, h, strings.TrimSpace(*name))
	return report.ExitOK
}

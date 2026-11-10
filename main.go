// Command cau is the CAU EDR command line: a transparent, open-source malware
// detection engine (hash signatures, YARA, string/API heuristics, static
// structure, invisible-codepoint steganography, and a fusion lattice over all
// of them) with machine-readable output, CI exit codes and a measured
// evaluation harness.
package main

import (
	"bytes"
	"context"
	jsonpkg "encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/forward/collector"
	"github.com/s-b-repo/cau/internal/forward/wazuh"
	"github.com/s-b-repo/cau/internal/harden"
	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/provenance"
	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/sdnotify"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/archive"
	"github.com/s-b-repo/cau/scanner/chm"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/iso"
	"github.com/s-b-repo/cau/scanner/linuxpkg"
	"github.com/s-b-repo/cau/scanner/lnk"
	"github.com/s-b-repo/cau/scanner/ole"
	"github.com/s-b-repo/cau/scanner/pdf"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
	"github.com/s-b-repo/cau/scanner/tradecraft"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "0.1.0-dev"

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
  cau honesty   [flags]                one document of what is covered, what was measured and whether the
                                       detection content is intact, with gaps shown and no overall score
  cau quarantine <subcommand>          vault flagged files (add/list/restore/verify/delete)
  cau canary    plant|check [flags]    plant decoy files and detect tampering
  cau peel      [flags] <file>...      walk obfuscation chains, depth as signal
  cau evasion  report|bench [flags]    measure how fragile the shipped detections are: the bytes that
                                        must change for each detector to stop firing, never a patched sample
  cau firmware  [flags] <image>        parse a UEFI firmware image (FV/FFS inventory, integrity, implant blocklist)
  cau boot-scan [flags]                read the boot chain, read-only: MBR/GPT/boot sectors, the EFI System Partition,
                                       Secure Boot state and boot entries, WPBT, option ROMs
  cau hwid      [flags]                snapshot the hardware identity (DMI, NIC addresses, TPM PCRs) and compare it
                                       with a recorded baseline; what cannot be verified is listed, never assumed
  cau ps        [flags]                scan the live process table (/proc) for fileless/masquerade/injection/network shells; --respond stops or kills confirmed ones
  cau net       [flags] | block|unblock|blocks|clear
                                       scan the network plane (/proc sockets attributed to processes, resolver, neighbours) for
                                       fileless egress, bind shells, known-bad peers, DNS escape, sweeps, beaconing; --respond blocks
  cau defend    [flags]                chain every layer: correlate incidents, watch files in real time, respond to confirmed attacks
  cau persist   [flags]                audit the host for persistence (preload, cron, systemd, rc files, keys, accounts, PAM, SUID)
  cau installed [flags]                audit installed-package maintainer scripts (dpkg/pacman) for tradecraft
  cau feed      <subcommand>           manage the abuse-intel feed (list/check/update; offline cache + opt-in fetch)
  cau intake    --format <fmt> [flags] ingest a threat-intel feed into the signature DB
  cau update    (--from|--url) [flags] install a signed signature-DB bundle (fail-closed)
  cau selftest  [--record] [flags]     verify detection content has not been tampered with
  cau verify-self (--from|--url) [flags] verify this binary against the signed release manifest
  cau bundle    update|checksums|sbom [flags] produce signed release artifacts (CI)
  cau completion <shell>                 print a shell completion script (bash|zsh|fish)
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
	case "honesty":
		return cmdHonesty(args[1:], stdout, stderr)
	case "quarantine":
		return cmdQuarantine(args[1:], stdout, stderr)
	case "canary":
		return cmdCanary(args[1:], stdout, stderr)
	case "peel":
		return cmdPeel(args[1:], stdout, stderr)
	case "evasion":
		return cmdEvasion(args[1:], stdout, stderr)
	case "firmware":
		return cmdFirmware(args[1:], stdout, stderr)
	case "boot-scan":
		return cmdBootScan(args[1:], stdout, stderr)
	case "hwid":
		return cmdHwid(args[1:], stdout, stderr)
	case "persist":
		return cmdPersist(args[1:], stdout, stderr)
	case "defend":
		return cmdDefend(args[1:], stdout, stderr)
	case "ps":
		return cmdPs(args[1:], stdout, stderr)
	case "net":
		return cmdNet(args[1:], stdout, stderr)
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
	case "completion":
		return cmdCompletion(args[1:], stdout, stderr)
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
	file, dir           string
	db, rules           string
	noYara, noHeur      bool
	noStatic, noFuzzy   bool
	noStego, noFusion   bool
	noEncChain          bool
	noLNK               bool
	noOLE               bool
	noPDF               bool
	noISO               bool
	noPkg               bool
	noPeel              bool
	noArchive           bool
	noCHM               bool
	noTradecraft        bool
	quarantine          bool
	quarantineStore     string
	quarantineLevel     string
	interval            time.Duration
	fuzzyDB             string
	signers             string
	heurThreshold       int
	staticThreshold     int
	stegoThreshold      int
	encChainThreshold   int
	lnkThreshold        int
	oleThreshold        int
	pdfThreshold        int
	isoThreshold        int
	pkgThreshold        int
	feed                string
	peelThreshold       int
	archiveThreshold    int
	chmThreshold        int
	tradecraftThreshold int
	format, output      string
	pretty              bool
	failOn              string
	noFailOnScanError   bool
	jobs                int
	followSymlinks      bool
	maxInMemoryMiB      int64
	yaraTimeout         time.Duration
	quiet               bool
	// Package-manager provenance (internal/provenance): off by default, it
	// loads the host's dpkg/pacman database once per scan. provenanceRoot is
	// the test override for the database tree (default "/").
	provenance     bool
	provenanceRoot string

	// Wazuh forwarder: free SIEM sink. See internal/forward/wazuh.
	wazuhURL         string
	wazuhUser        string
	wazuhPasswordEnv string
	wazuhCA          string
	wazuhInsecure    bool
	wazuhTimeout     time.Duration
	// Generic SIEM sink forwarder. See internal/forward/collector.
	sinkURL      string
	sinkFormat   string
	sinkIndex    string
	sinkAuthEnv  string
	sinkCA       string
	sinkInsecure bool
	sinkTimeout  time.Duration
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
	fs.BoolVar(&f.noTradecraft, "no-tradecraft", false, "disable the behavioural pass over scripts and payload bytes (web shells, network shells, in-memory loaders, shellcode)")
	fs.IntVar(&f.tradecraftThreshold, "tradecraft-threshold", tradecraft.Threshold, "score at which a tradecraft match is reported suspicious")
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
	fs.BoolVar(&f.provenance, "provenance", false, "resolve every scanned file against the host's package database (dpkg/pacman): owner, version, and whether the content still matches what the package shipped; costs one database load per scan, about one to three seconds of CPU on a 4,400-package Debian install")
	fs.StringVar(&f.provenanceRoot, "provenance-root", "/", "root under which var/lib/dpkg and var/lib/pacman/local are read for --provenance (testing)")

	// ── Free SIEM forwarder: Wazuh Manager API (see docs/pricing.md). ──
	fs.StringVar(&f.wazuhURL, "wazuh-url", "", "Wazuh Manager API base (e.g. https://wazuh.example.com:55000); forwards OCSF findings over /events")
	fs.StringVar(&f.wazuhUser, "wazuh-user", "", "Wazuh API user for --wazuh-url")
	fs.StringVar(&f.wazuhPasswordEnv, "wazuh-password-env", "WAZUH_PASSWORD", "environment variable holding the Wazuh API password (never on argv)")
	fs.StringVar(&f.wazuhCA, "wazuh-ca", "", "PEM CA bundle to trust the Wazuh manager's TLS certificate")
	fs.BoolVar(&f.wazuhInsecure, "wazuh-insecure", false, "skip Wazuh TLS verification (explicit opt-in; also allows http://)")
	fs.DurationVar(&f.wazuhTimeout, "wazuh-timeout", wazuh.DefaultTimeout, "per-request timeout for the Wazuh forwarder")

	// ── Free SIEM forwarder: any collector that takes a sink format. ──
	fs.StringVar(&f.sinkURL, "sink-url", "", "forward findings to a collector: udp://, tcp://, tls://host:port (syslog, CEF, LEEF, GELF, ECS) or https://host/path (OTLP /v1/logs, OpenSearch _bulk, GELF HTTP)")
	fs.StringVar(&f.sinkFormat, "sink-format", "", "sink format for --sink-url: "+strings.Join(report.SinkFormats(), ", ")+" (default: --format when it is one of these)")
	fs.StringVar(&f.sinkIndex, "sink-index", "", "with an https:// --sink-url and the ecs format: send an OpenSearch/Elasticsearch _bulk body creating into this index or data stream")
	fs.StringVar(&f.sinkAuthEnv, "sink-auth-env", "CAU_SINK_AUTH", "environment variable holding the HTTP Authorization header value for --sink-url (never on argv)")
	fs.StringVar(&f.sinkCA, "sink-ca", "", "PEM CA bundle to trust the collector's TLS certificate")
	fs.BoolVar(&f.sinkInsecure, "sink-insecure", false, "skip collector TLS verification (explicit opt-in; also allows http://)")
	fs.DurationVar(&f.sinkTimeout, "sink-timeout", collector.DefaultTimeout, "per-connection and per-request timeout for --sink-url")

	if err := fs.Parse(interspersed(fs, args)); err != nil {
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
		report.WithTradecraftThreshold(f.tradecraftThreshold),
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
	// A mistyped collector is a usage error before the scan starts, not a
	// warning after it: only a transport failure at send time is best-effort.
	sinkFwd, err := newSinkForwarder(f, opts)
	if err != nil {
		fmt.Fprintf(stderr, "[ERROR] %v\n", err)
		return report.ExitUsage
	}

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
			forwardWazuh(f, in, status, stderr)
			sinkFwd.forward(in, status, stderr)
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
		forwardWazuh(f, in, status, stderr)
		sinkFwd.forward(in, status, stderr)
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
		DB:                  db,
		Yara:                ys,
		Heuristics:          !f.noHeur,
		HeuristicThreshold:  f.heurThreshold,
		Static:              !f.noStatic,
		StaticThreshold:     f.staticThreshold,
		FuzzyDB:             fuzzy,
		StaticNoFuzzy:       f.noFuzzy,
		SignerBlocklist:     signerBL,
		Stego:               !f.noStego,
		StegoThreshold:      f.stegoThreshold,
		EncChain:            !f.noEncChain,
		EncChainThreshold:   f.encChainThreshold,
		LNK:                 !f.noLNK,
		LNKThreshold:        f.lnkThreshold,
		OLE:                 !f.noOLE,
		OLEThreshold:        f.oleThreshold,
		PDF:                 !f.noPDF,
		PDFThreshold:        f.pdfThreshold,
		ISO:                 !f.noISO,
		ISOThreshold:        f.isoThreshold,
		LinuxPkg:            !f.noPkg,
		LinuxPkgThreshold:   f.pkgThreshold,
		Intel:               feed,
		Peel:                !f.noPeel,
		PeelThreshold:       f.peelThreshold,
		Archive:             !f.noArchive,
		ArchiveThreshold:    f.archiveThreshold,
		CHM:                 !f.noCHM,
		CHMThreshold:        f.chmThreshold,
		Tradecraft:          !f.noTradecraft,
		TradecraftThreshold: f.tradecraftThreshold,
		NoFusion:            f.noFusion,
		MaxInMemory:         f.maxInMemoryMiB << 20,
		Jobs:                f.jobs,
		FollowSymlinks:      f.followSymlinks,
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
		// Provenance (--provenance): after the scan, resolve each result
		// against the host's package database using the digests the engine
		// already computed. The index loads once, on the first lookup, and is
		// rebuilt per cycle in daemon mode so an upgrade is seen. It never
		// changes a verdict: it is context on every row plus the
		// modified-system-binary observation.
		if f.provenance {
			resolver := provenance.New(f.provenanceRoot)
			in.Provenance = make(map[string]provenance.Provenance, len(in.Results))
			for _, r := range in.Results {
				if r.Error != nil {
					continue
				}
				in.Provenance[r.FilePath] = resolver.Lookup(r.FilePath, provenance.Digests{MD5: r.MD5, SHA1: r.SHA1, SHA256: r.SHA256})
			}
			status("[*] Provenance: %s", resolver.Summary())
			for _, n := range resolver.Notes() {
				status("[WARN] provenance: %s", report.TermSafe(n))
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
	if err := fs.Parse(interspersed(fs, args)); err != nil {
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

// ── Wazuh forwarder (free: see docs/pricing.md) ──────────────────────────────

// forwardWazuh posts the OCSF findings of the finished scan to a Wazuh
// Manager through its REST API, when --wazuh-url is set. It is called after
// the local report has been written and runs on a best-effort basis: a
// transport error is logged and dropped, never promoted to an exit code,
// because a SIEM outage must not break a CI gate.
func forwardWazuh(f scanFlags, in report.Input, status func(string, ...interface{}), stderr io.Writer) {
	if strings.TrimSpace(f.wazuhURL) == "" {
		return
	}
	// Dont attempt a forward on a run that produced no scan output at all;
	// the Wazuh side would just see a 400 on an empty events array.
	if in.Empty() && in.RunError == nil {
		return
	}
	password := os.Getenv(f.wazuhPasswordEnv)
	if password == "" {
		fmt.Fprintf(stderr, "[WARN] wazuh forward skipped: $%s is empty (set --wazuh-password-env to the variable holding the API password)\n", f.wazuhPasswordEnv)
		return
	}
	client, err := wazuh.New(wazuh.Options{
		URL: f.wazuhURL, User: f.wazuhUser, Password: password,
		CAFile: f.wazuhCA, Insecure: f.wazuhInsecure, Timeout: f.wazuhTimeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] wazuh forward skipped: %v\n", err)
		return
	}
	// Reuse the OCSF reporter so what Wazuh sees is byte-identical to
	// `cau scan --format ocsf`. The double-encode here is one-per-scan, not
	// per-finding, so the cost is negligible.
	ocsfRep, err := report.NewReporter("ocsf")
	if err != nil {
		fmt.Fprintf(stderr, "[WARN] wazuh forward skipped: %v\n", err)
		return
	}
	var buf strings.Builder
	if err := ocsfRep.Write(&buf, in); err != nil {
		fmt.Fprintf(stderr, "[WARN] wazuh forward skipped: build ocsf: %v\n", err)
		return
	}
	var findings []map[string]any
	if err := jsonUnmarshal(buf.String(), &findings); err != nil {
		fmt.Fprintf(stderr, "[WARN] wazuh forward skipped: decode ocsf: %v\n", err)
		return
	}
	if len(findings) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*f.wazuhTimeout+10*time.Second)
	defer cancel()
	res := client.Send(ctx, findings)
	if res.Err != nil {
		fmt.Fprintf(stderr, "[WARN] wazuh forward: %d/%d delivered: %v\n", res.Delivered, res.Attempted, res.Err)
		return
	}
	status("[*] wazuh forward: %d/%d findings delivered", res.Delivered, res.Attempted)
}

// ── Generic SIEM sink forwarder (free: see docs/pricing.md) ──────────────────

// sinkForwarder delivers the finished scan's findings to a collector in one of
// the SIEM sink formats, when --sink-url is set. The zero value (no URL) does
// nothing.
type sinkForwarder struct {
	client   *collector.Client
	reporter report.Reporter
	format   string
	dest     string
}

// newSinkForwarder validates the --sink-* flags and builds the client and the
// reporter whose bytes it will send. It opens no connection.
func newSinkForwarder(f scanFlags, opts []report.Option) (*sinkForwarder, error) {
	if strings.TrimSpace(f.sinkURL) == "" {
		if f.sinkFormat != "" || f.sinkIndex != "" {
			return nil, errors.New("--sink-format and --sink-index need --sink-url")
		}
		return &sinkForwarder{}, nil
	}
	format := strings.ToLower(strings.TrimSpace(f.sinkFormat))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(f.format))
	}
	if !slices.Contains(report.SinkFormats(), format) {
		return nil, fmt.Errorf("--sink-url needs a sink format: set --sink-format to one of %s", strings.Join(report.SinkFormats(), ", "))
	}
	// The forwarded bytes are never indented: one event per line is the
	// framing every transport relies on.
	rep, err := report.NewSinkReporter(format, append(append([]report.Option(nil), opts...), report.WithIndent(false))...)
	if err != nil {
		return nil, err
	}
	client, err := collector.New(collector.Options{
		URL: f.sinkURL, Format: format, BulkIndex: f.sinkIndex,
		Authorization: os.Getenv(f.sinkAuthEnv),
		CAFile:        f.sinkCA, Insecure: f.sinkInsecure, Timeout: f.sinkTimeout,
	})
	if err != nil {
		return nil, err
	}
	dest := f.sinkURL
	if u, perr := url.Parse(f.sinkURL); perr == nil {
		dest = u.Redacted()
	}
	return &sinkForwarder{client: client, reporter: rep, format: format, dest: dest}, nil
}

// forward sends the findings. Like the Wazuh forwarder it is best-effort: a
// collector outage is logged and dropped, never promoted to an exit code.
func (s *sinkForwarder) forward(in report.Input, status func(string, ...interface{}), stderr io.Writer) {
	if s == nil || s.client == nil {
		return
	}
	var buf bytes.Buffer
	if err := s.reporter.Write(&buf, in); err != nil {
		fmt.Fprintf(stderr, "[WARN] sink forward skipped: build %s: %v\n", s.format, err)
		return
	}
	timeout := s.client.Budget()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res := s.client.Send(ctx, buf.Bytes())
	if res.Attempted == 0 {
		return
	}
	if res.Err != nil {
		fmt.Fprintf(stderr, "[WARN] sink forward (%s): %d/%d delivered: %s\n", s.format, res.Delivered, res.Attempted, report.TermSafe(res.Err.Error()))
		return
	}
	note := ""
	if s.client.Cleartext() {
		note = " (cleartext transport)"
	}
	status("[*] sink forward (%s): %d/%d findings delivered to %s%s", s.format, res.Delivered, res.Attempted, report.TermSafe(s.dest), note)
}

// jsonUnmarshal decodes a JSON string into v. Kept as a one-liner so main.go
// does not grow a `json.*` surface outside the Wazuh forwarder.
func jsonUnmarshal(s string, v any) error { return jsonpkg.Unmarshal([]byte(s), v) }

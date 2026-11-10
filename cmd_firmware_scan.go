package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/firmware"
)

// The firmware scan is the "at the scan node" half of the firmware phase: the
// image is a container, and what is inside it is what the ordinary detectors
// have to see. A router image that is one squashfs blob finds nothing when it
// is scanned as a blob; the point of this command is to look inside first.
func firmwareScanUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau firmware scan [flags] <image>...

Looks inside a firmware image and runs the ordinary detectors over what it
finds there: the container formats present in the image (squashfs, cramfs,
jffs2, ext, FAT, gzip, zip, tar, xz, zstd, LZMA, uImage, ISO), and the
members of the formats this build can open (gzip, zip and tar) extracted and
scanned like any other file.

A container this build cannot open is reported with its offset and the reason
it was not opened. It is never reported as an empty result: an image whose
filesystem was not unpacked is an image nothing was measured in.

Flags:
  --format <fmt>    text or json (default text)
  --rules <path>     YARA rules directory (default: auto-discovered)
  --db <path>        signature database (default: auto-discovered)
  --no-static        skip the structural pass over the members
  --max-members <n>  cap the members extracted per image (default 512)
  --fail-on <tier>   exit non-zero at this tier: none, heuristic, malicious
                     (default none)

Examples:
  cau firmware scan ./openwrt-x86-generic.bin
  cau firmware scan --format json ./router-firmware.bin
`)
}

// firmwareScanResult is what one image's scan produced.
type firmwareScanResult struct {
	Path       string               `json:"path"`
	Size       int64                `json:"size"`
	Containers []firmware.Container `json:"containers"`
	Members    []firmwareScanMember `json:"members"`
	Notes      []string             `json:"notes,omitempty"`
	Truncated  bool                 `json:"truncated,omitempty"`
}

// firmwareScanMember is one extracted member and what the detectors said
// about it.
type firmwareScanMember struct {
	Container string   `json:"container"`
	Path      string   `json:"path"`
	Size      int64    `json:"size"`
	Verdict   string   `json:"verdict"`
	Detected  bool     `json:"detected"`
	Threat    string   `json:"threat,omitempty"`
	RuleHits  []string `json:"rule_hits,omitempty"`
	Anomalies []string `json:"anomalies,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func cmdFirmwareScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("firmware scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	rulesFlag := fs.String("rules", "", "YARA rules directory (default: auto-discovered)")
	dbFlag := fs.String("db", "", "signature database (default: auto-discovered)")
	noStatic := fs.Bool("no-static", false, "skip the structural pass over the members")
	maxMembers := fs.Int("max-members", 512, "cap the members extracted per image")
	failOn := fs.String("fail-on", "none", "exit non-zero at this tier: none, heuristic, malicious")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() == 0 {
		return fail(stderr, report.ExitUsage, "firmware scan takes at least one image file")
	}

	limits := firmware.DefaultLimits()
	if *maxMembers > 0 {
		limits.MaxMembers = *maxMembers
	}

	e, closer, err := firmwareScanEngine(*dbFlag, *rulesFlag, *noStatic, stderr)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	defer closer()

	results := make([]firmwareScanResult, 0, fs.NArg())
	detected := false
	for _, path := range fs.Args() {
		res, hit, err := scanFirmwareImage(e, path, limits)
		if err != nil {
			fmt.Fprintf(stderr, "[ERROR] %v\n", err)
			detected = true
			continue
		}
		results = append(results, *res)
		if hit {
			detected = true
		}
	}

	if *format == "json" {
		if err := writeJSON(stdout, results); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		for _, r := range results {
			writeFirmwareScanText(stdout, r)
		}
	}
	switch *failOn {
	case "none":
	case "heuristic", "malicious":
		if detected {
			return report.ExitThreat
		}
	default:
		return fail(stderr, report.ExitUsage, "--fail-on must be none, heuristic or malicious")
	}
	return report.ExitOK
}

// firmwareScanEngine builds the engine the members are scanned with.
func firmwareScanEngine(dbFlag, rulesFlag string, noStatic bool, stderr io.Writer) (*scanner.Engine, func(), error) {
	closer := func() {}
	e := &scanner.Engine{Heuristics: true, Static: !noStatic}
	if dbPath, _ := findResource(dbFlag, envSignatures, relSignatures); dbPath != "" {
		db, err := scanner.LoadSignatures(dbPath)
		if err != nil {
			return nil, closer, fmt.Errorf("signature database: %w", err)
		}
		e.DB = db
	}
	if rulesPath, _ := findResource(rulesFlag, envRules, relRules); rulesPath != "" {
		ys, _, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(func(string, ...interface{}) {}))
		if err != nil {
			return nil, closer, fmt.Errorf("YARA rules: %w", err)
		}
		e.Yara = ys
		closer = func() { ys.Close() }
	} else if rulesFlag != "" {
		return nil, closer, fmt.Errorf("YARA rules not found at %s", rulesFlag)
	}
	return e, closer, nil
}

// scanFirmwareImage looks inside one image and scans what came out.
func scanFirmwareImage(e *scanner.Engine, path string, limits firmware.Limits) (*firmwareScanResult, bool, error) {
	data, err := readFileCapped(path, maxInputBytes)
	if err != nil {
		return nil, false, err
	}
	img := firmware.Analyze(data, path, limits)
	res := &firmwareScanResult{
		Path:       path,
		Size:       img.Size,
		Containers: img.Containers,
		Notes:      img.Notes,
		Truncated:  img.Truncated,
	}
	if len(img.Members) == 0 {
		return res, false, nil
	}

	// The engine reads from disk, so the members are written to a temporary
	// directory under generated names: a member's own path is attacker-chosen
	// and must never become a file name.
	dir, err := os.MkdirTemp("", "cau-fw-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(dir)

	detected := false
	for i, m := range img.Members {
		name := filepath.Join(dir, fmt.Sprintf("member-%04d.bin", i))
		if err := os.WriteFile(name, m.Data, 0o600); err != nil {
			return res, detected, err
		}
		row := firmwareScanMember{Container: m.Container, Path: m.Path, Size: m.Size}
		sr, _ := e.ScanFile(name)
		row.Verdict = string(sr.Verdict)
		row.Detected = sr.Detected
		row.Threat = sr.ThreatName
		for _, ym := range sr.YaraMatches {
			row.RuleHits = append(row.RuleHits, ym.RuleName)
		}
		if sr.Static != nil {
			for _, a := range sr.Static.Anomalies {
				if a.Score > 0 {
					row.Anomalies = append(row.Anomalies, a.Class+": "+a.Detail)
				}
			}
		}
		if sr.Error != nil {
			row.Error = sr.Error.Error()
		}
		sort.Strings(row.RuleHits)
		if row.Detected || len(row.RuleHits) > 0 || len(row.Anomalies) > 0 {
			detected = true
		}
		res.Members = append(res.Members, row)
	}
	return res, detected, nil
}

// writeFirmwareScanText renders one image's scan.
func writeFirmwareScanText(w io.Writer, r firmwareScanResult) {
	fmt.Fprintf(w, "firmware scan: %s (%d bytes)\n", r.Path, r.Size)
	if len(r.Containers) == 0 {
		fmt.Fprintln(w, "  no container found: the image was scanned as it is")
		return
	}
	fmt.Fprintln(w, "  containers:")
	for _, c := range r.Containers {
		state := "not opened"
		if c.Opened {
			state = fmt.Sprintf("opened, %d member(s)", c.Members)
		}
		fmt.Fprintf(w, "    %-10s at %-10d %s", c.Format, c.Offset, state)
		if c.Note != "" {
			fmt.Fprintf(w, " (%s)", c.Note)
		}
		fmt.Fprintln(w)
	}
	if len(r.Members) > 0 {
		fmt.Fprintln(w, "  members:")
		for _, m := range r.Members {
			mark := " "
			if m.Detected || len(m.RuleHits) > 0 || len(m.Anomalies) > 0 {
				mark = "!"
			}
			fmt.Fprintf(w, "    %s %-10s %-34s %8d  %s\n", mark, m.Container, truncatePath(m.Path, 34), m.Size, m.Verdict)
			for _, hit := range m.RuleHits {
				fmt.Fprintf(w, "        rule: %s\n", hit)
			}
			for _, a := range m.Anomalies {
				fmt.Fprintf(w, "        %s\n", a)
			}
			if m.Error != "" {
				fmt.Fprintf(w, "        error: %s\n", m.Error)
			}
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// truncatePath shortens a member path for the report.
func truncatePath(p string, n int) string {
	if len(p) <= n {
		return p
	}
	if n <= 1 {
		return p[:n]
	}
	return "…" + p[len(p)-(n-1):]
}

// firmwareScanHelp prints the subcommand's usage.
func firmwareScanHelp(w io.Writer) { firmwareScanUsage(w) }

// joinNonEmpty joins the non-empty parts.
func joinNonEmpty(parts []string, sep string) string {
	var out []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

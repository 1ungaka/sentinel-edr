package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/uefi"
)

func firmwareUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau firmware [flags] <image>

Parses a UEFI firmware image — its Firmware Volumes and the FFS files and
sections inside them, including volumes nested inside LZMA-compressed sections —
and reports a module inventory, the FV header integrity, any module GUID on an
operator-supplied implant blocklist, and any module whose executable body
matches a detection rule.

This is the Phase-8 firmware wedge and it is honest about its boundary: the
engine ships NO implant truth set, because firmware is overwhelmingly
legitimate PEI/DXE/SMM drivers and scoring module shapes would be a
false-positive machine. What it reports is the structural parse, a genuine
tamper signal (an FV header whose 16-bit checksum does not validate), and any
match against a blocklist you load with --implants. Module bodies are
inventoried and run through the YARA rules, not disassembled. LZMA-compressed
sections are opened; sections in the EFI/Tiano compression or another
GUID-defined encoding are not, and the report says how many could not be
opened. The bundled rules were written for operating-system malware: a hit on
a firmware module is strong evidence, and no hit says little.

Flags:
  --format <fmt>   text or json (default text)
  --threshold <n>  score at which the image is reported suspicious (default 8)
  --implants <f>   implant-GUID blocklist file: one "guid" or "guid|name" per
                   line, '#' comments (empty/omitted = structural only)
  --rules <dir>    YARA rules to run over module bodies (default: the bundled
                   rules, found the way 'cau scan' finds them)
  --no-yara        do not run rules over module bodies

Exit codes: 0 clean, 1 suspicious, 3 the run failed, 4 usage.
`)
}

func cmdFirmware(args []string, stdout, stderr io.Writer) int {
	// A bare first word is a subcommand; an existing file is an image, the
	// form this command shipped with. Anything else is neither, and says so
	// rather than guessing.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "scan":
			return cmdFirmwareScan(args[1:], stdout, stderr)
		default:
			if !fileExists(args[0]) {
				return fail(stderr, report.ExitUsage,
					"cau firmware: %q is neither a subcommand (scan) nor an existing image", args[0])
			}
		}
	}
	fs := flag.NewFlagSet("firmware", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", 0, "score at which the image is reported suspicious (0 = default)")
	implants := fs.String("implants", "", "implant-GUID blocklist file (optional)")
	rules := fs.String("rules", "", "YARA rules directory (default: auto-discovered)")
	noYara := fs.Bool("no-yara", false, "do not run YARA rules over module bodies")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() != 1 {
		return fail(stderr, report.ExitUsage, "firmware takes exactly one image file")
	}
	opts := uefi.Options{Threshold: *threshold}
	if *implants != "" {
		blocklist, err := loadImplantBlocklist(*implants)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		opts.ImplantGUIDs = blocklist
	}

	data, err := readFileCapped(fs.Arg(0), maxInputBytes)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}
	r := uefi.Analyze(data, opts)
	r.FilePath = fs.Arg(0)

	ruleNote, code := firmwareRules(r, *rules, *noYara, stderr)
	if code != report.ExitOK {
		return code
	}
	if r.Parsed != nil && ruleNote != "" {
		r.Parsed.NotInspected += "; " + ruleNote
	}

	if *format == "json" {
		if err := writeJSON(stdout, r); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		writeFirmwareText(stdout, r)
	}
	if r.Detected() {
		return report.ExitThreat
	}
	return report.ExitOK
}

// firmwareRules runs the YARA rules over every executable section the parse
// found and records the hits on the result. It returns a note for the report
// when rules were not run or did not cover everything, so the absence of a
// rule finding is never read as "the rules found nothing" when they did not
// look. An explicitly named rules path that cannot be loaded fails the run;
// rules that are merely not installed do not.
func firmwareRules(r *uefi.Result, rulesFlag string, noYara bool, stderr io.Writer) (note string, code int) {
	sections, truncated := r.ExecutableSections()
	if noYara {
		return "detection rules were not run over module bodies (--no-yara)", report.ExitOK
	}
	if len(sections) == 0 {
		return "", report.ExitOK
	}
	rulesPath, _ := findResource(rulesFlag, envRules, relRules)
	if rulesPath == "" {
		if rulesFlag != "" {
			return "", fail(stderr, report.ExitRunFailed, "YARA rules not found at %s", rulesFlag)
		}
		return "detection rules were not run over module bodies: no rules found (pass --rules)", report.ExitOK
	}
	ys, _, err := scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		return "", fail(stderr, report.ExitRunFailed, "YARA: %v", err)
	}
	defer ys.Close()

	var matches []uefi.RuleMatch
	failed := 0
	for _, sec := range sections {
		hits, err := ys.ScanMemYara(sec.Data)
		if err != nil {
			failed++
			continue
		}
		for _, h := range hits {
			matches = append(matches, uefi.RuleMatch{Rule: h.RuleName, Section: sec})
		}
	}
	r.AddRuleMatches(matches)

	var notes []string
	if truncated {
		notes = append(notes, "the image holds more executable-section bytes than are kept for rule scanning, so some module bodies were not scanned")
	}
	if failed > 0 {
		notes = append(notes, fmt.Sprintf("the rule scan failed on %d of %d module bodies", failed, len(sections)))
	}
	return strings.Join(notes, "; "), report.ExitOK
}

func writeFirmwareText(w io.Writer, r *uefi.Result) {
	fmt.Fprintf(w, "File        : %s\n", report.TermSafe(r.FilePath))
	if r.Parsed == nil {
		fmt.Fprintln(w, "Firmware    : not a UEFI firmware image")
		return
	}
	fmt.Fprintf(w, "Volumes     : %d\n", r.Parsed.Volumes)
	fmt.Fprintf(w, "Modules     : %d\n", r.Parsed.Modules)
	if r.Parsed.Decompressed > 0 || r.Parsed.DecompressFailed > 0 {
		fmt.Fprintf(w, "Compressed  : %d LZMA section(s) opened, %d could not be\n", r.Parsed.Decompressed, r.Parsed.DecompressFailed)
	}
	if secs, _ := r.ExecutableSections(); len(secs) > 0 {
		fmt.Fprintf(w, "Executables : %d module bodies (PE32/TE)\n", len(secs))
	}
	fmt.Fprintf(w, "FV checksum : %s\n", map[bool]string{true: "valid", false: "INVALID"}[r.Parsed.ChecksumValid])
	fmt.Fprintf(w, "Score       : %d / %d threshold\n", r.Score, r.EffectiveThreshold())
	if r.Detected() {
		fmt.Fprintln(w, "Verdict     : SUSPICIOUS")
	}
	for _, f := range r.Findings {
		tag := ""
		if f.Technique != "" {
			tag = "  (" + f.Technique + ")"
		}
		fmt.Fprintf(w, "  [%s] %d%s\n", f.Class, f.Score, tag)
		detail := f.Detail
		if f.Evidence != "" {
			detail += ": " + report.TermSafe(f.Evidence)
		}
		fmt.Fprintf(w, "    %s\n", detail)
	}
	// Bounded inventory.
	const maxShown = 40
	for i, m := range r.Parsed.Inventory {
		if i >= maxShown {
			fmt.Fprintf(w, "  ... +%d more modules\n", len(r.Parsed.Inventory)-maxShown)
			break
		}
		name := m.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(w, "  %s  %-20s  %s\n", m.GUID, m.Type, report.TermSafe(name))
	}
	if r.Parsed.NotInspected != "" {
		fmt.Fprintf(w, "Note        : %s\n", r.Parsed.NotInspected)
	}
}

// loadImplantBlocklist reads a GUID blocklist: one "guid" or "guid|name" per
// line, '#' comments, blank lines ignored. GUIDs are lower-cased.
func loadImplantBlocklist(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open implant blocklist: %w", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		guid, name, _ := strings.Cut(line, "|")
		guid = strings.ToLower(strings.TrimSpace(guid))
		if len(guid) != 36 {
			return nil, fmt.Errorf("%s:%d: %q is not a 36-char GUID", path, n, guid)
		}
		out[guid] = strings.TrimSpace(name)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading implant blocklist: %w", err)
	}
	return out, nil
}

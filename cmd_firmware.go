package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cau-edr/cau/internal/report"
	"github.com/cau-edr/cau/scanner/uefi"
)

func firmwareUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau firmware [flags] <image>

Parses a UEFI firmware image — its Firmware Volumes and the FFS files and
sections inside them — and reports a module inventory, the FV header integrity,
and any module GUID on an operator-supplied implant blocklist.

This is the Phase-8 firmware wedge and it is honest about its boundary: the
engine ships NO implant truth set, because firmware is overwhelmingly
legitimate PEI/DXE/SMM drivers and scoring module shapes would be a
false-positive machine. What it reports is the structural parse, a genuine
tamper signal (an FV header whose 16-bit checksum does not validate), and any
match against a blocklist you load with --implants. Module bodies are
inventoried, not disassembled; compressed/GUIDed sections are not decompressed.

Flags:
  --format <fmt>   text or json (default text)
  --threshold <n>  score at which the image is reported suspicious (default 8)
  --implants <f>   implant-GUID blocklist file: one "guid" or "guid|name" per
                   line, '#' comments (empty/omitted = structural only)

Exit codes: 0 clean, 1 suspicious, 3 the run failed, 4 usage.
`)
}

func cmdFirmware(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("firmware", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	threshold := fs.Int("threshold", 0, "score at which the image is reported suspicious (0 = default)")
	implants := fs.String("implants", "", "implant-GUID blocklist file (optional)")
	if err := fs.Parse(args); err != nil {
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

func writeFirmwareText(w io.Writer, r *uefi.Result) {
	fmt.Fprintf(w, "File        : %s\n", r.FilePath)
	if r.Parsed == nil {
		fmt.Fprintln(w, "Firmware    : not a UEFI firmware image")
		return
	}
	fmt.Fprintf(w, "Volumes     : %d\n", r.Parsed.Volumes)
	fmt.Fprintf(w, "Modules     : %d\n", r.Parsed.Modules)
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
			detail += ": " + f.Evidence
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
		fmt.Fprintf(w, "  %s  %-20s  %s\n", m.GUID, m.Type, name)
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

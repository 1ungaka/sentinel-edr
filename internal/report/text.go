package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/provenance"
	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/archive"
	"github.com/s-b-repo/cau/scanner/chm"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/fusion"
	"github.com/s-b-repo/cau/scanner/iso"
	"github.com/s-b-repo/cau/scanner/linuxpkg"
	"github.com/s-b-repo/cau/scanner/lnk"
	"github.com/s-b-repo/cau/scanner/ole"
	"github.com/s-b-repo/cau/scanner/pdf"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
	"github.com/s-b-repo/cau/scanner/tradecraft"
)

// Reporter is the common shape of every output format.
type Reporter interface {
	Write(w io.Writer, in Input) error
}

// Formats lists the names NewReporter accepts: the five report formats, then
// the SIEM sink profiles (see siem.go).
var Formats = append([]string{"text", "json", "sarif", "ocsf", "stix"}, SinkFormats()...)

// NewReporter selects a reporter by format name ("text", "json", "sarif",
// "ocsf", "stix", or a SIEM sink profile from SinkFormats).
func NewReporter(format string, opts ...Option) (Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return NewTextReporter(opts...), nil
	case "json":
		return NewJSONReporter(opts...), nil
	case "sarif":
		return NewSARIFReporter(opts...), nil
	case "ocsf":
		return NewOCSFReporter(opts...), nil
	case "stix":
		return NewSTIXReporter(opts...), nil
	default:
		if _, ok := sinkProfileFor(strings.ToLower(strings.TrimSpace(format))); ok {
			return NewSinkReporter(format, opts...)
		}
		return nil, fmt.Errorf("unknown output format %q (want one of %s)", format, strings.Join(Formats, ", "))
	}
}

// TextReporter renders the human-readable output: one block per file followed
// by a summary. It does not print the startup banner; main owns that.
type TextReporter struct {
	cfg config
}

// NewTextReporter builds a reporter from the shared options.
func NewTextReporter(opts ...Option) *TextReporter {
	return &TextReporter{cfg: buildConfig(opts)}
}

// Write renders the run to w.
func (r *TextReporter) Write(w io.Writer, in Input) error {
	bw := bufio.NewWriter(w)
	c := r.cfg

	if in.RunError != nil {
		fmt.Fprintf(bw, " [ERR] %s\n\n", c.textError(in.RunError))
	}

	byPath := in.HeuristicsByPath()
	results := make(map[string]scanner.ScanResult, len(in.Results))
	for _, res := range in.Results {
		results[res.FilePath] = res
	}

	for _, p := range in.AllPaths() {
		res, hasResult := results[p]
		h, hasHeur := byPath[p]
		if hasResult {
			c.writeResult(bw, res)
		}
		if hasHeur {
			c.writeHeuristic(bw, h, !hasResult)
		}
		if hasResult && res.Static != nil {
			c.writeStatic(bw, res.Static)
		}
		if hasResult && res.Stego != nil {
			c.writeStego(bw, res.Stego)
		}
		if hasResult && res.EncChain != nil {
			c.writeEncChain(bw, res.EncChain)
		}
		if hasResult && res.LNK != nil {
			c.writeLNK(bw, res.LNK)
		}
		if hasResult && res.OLE != nil {
			c.writeOLE(bw, res.OLE)
		}
		if hasResult && res.PDF != nil {
			c.writePDF(bw, res.PDF)
		}
		if hasResult && res.LinuxPkg != nil {
			c.writeLinuxPkg(bw, res.LinuxPkg)
		}
		if hasResult && res.ISO != nil {
			c.writeISO(bw, res.ISO)
		}
		if hasResult && res.Peel != nil {
			c.writePeel(bw, res.Peel)
		}
		if hasResult && res.Archive != nil {
			c.writeArchive(bw, res.Archive)
		}
		if hasResult && res.CHM != nil {
			c.writeCHM(bw, res.CHM)
		}
		if hasResult && res.Tradecraft != nil {
			c.writeTradecraft(bw, res.Tradecraft)
		}
		if hasResult && res.Fusion != nil {
			c.writeFusion(bw, res.FilePath, res.Fusion)
		}
		if hasResult {
			if prov, ok := in.ProvenanceFor(p); ok {
				c.writeProvenance(bw, prov)
			}
		}
	}

	c.writeSummary(bw, in)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("report: write text: %w", err)
	}
	return nil
}

func (c config) writeResult(w io.Writer, r scanner.ScanResult) {
	path := c.textField(r.FilePath)
	if r.Error != nil {
		fmt.Fprintf(w, " [ERR] %s\n      %s\n\n", path, c.textError(r.Error))
		return
	}

	// ── Hash match ──
	if r.Detected {
		fmt.Fprintln(w, " [!] DETECTED (Hash) —", path)
		fmt.Fprintf(w, "     %-10s: %s\n", c.textField(r.MatchType), c.boundedHash(r.MatchHash))
		fmt.Fprintf(w, "     %-10s: %s\n", "Match", c.textField(r.ThreatName))
		fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", r.Verdict)
		fmt.Fprintf(w, "     %-10s: %s\n\n", "Scan time", elapsedString(r.ScanTime))
	}

	// ── YARA matches ──
	if len(r.YaraMatches) > 0 {
		if !r.Detected {
			fmt.Fprintln(w, " [!] DETECTED (YARA) —", path)
			fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", r.Verdict)
		} else {
			fmt.Fprintf(w, "     Also matched %d YARA rule(s):\n", len(r.YaraMatches))
		}

		for _, m := range r.YaraMatches {
			tags := ""
			if len(m.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", TermSafe(strings.Join(boundedList(c, m.Tags), ", ")))
			}
			fmt.Fprintf(w, "     [YARA] %s::%s%s\n", c.textField(m.Namespace), c.textField(m.RuleName), tags)
			if meta := c.metaLine(m); meta != "" {
				fmt.Fprintf(w, "            %s\n", meta)
			}
			for _, s := range m.Strings {
				data, cut := truncateBytes(s.Data, 32)
				suffix := ""
				if cut {
					suffix = "..."
				}
				fmt.Fprintf(w, "            %s @ 0x%x : %q%s\n", c.textField(s.Name), s.Offset, data, suffix)
			}
		}
		fmt.Fprintf(w, "     %-10s: %s\n\n", "Scan time", elapsedString(r.ScanTime))
	}

	// ── Clean ──
	if !r.Detected && len(r.YaraMatches) == 0 {
		fmt.Fprintf(w, " [CLEAN] %s\n", path)
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "     [WARN] %s\n", c.textField(warn))
	}
}

// metaLine renders the meta fields an analyst wants at a glance.
func (c config) metaLine(m scanner.YaraMatch) string {
	var parts []string
	if a := m.MetaString("author"); a != "" {
		parts = append(parts, "author="+c.textField(a))
	}
	if tl, ok := m.MetaInt("threat_level"); ok {
		parts = append(parts, fmt.Sprintf("threat_level=%d", tl))
	}
	if meta, ok := m.Meta("in_the_wild"); ok {
		parts = append(parts, "in_the_wild="+c.textField(meta.String()))
	}
	if d := m.MetaString("description"); d != "" {
		parts = append(parts, "desc="+strconvQuote(c.textField(d)))
	}
	return strings.Join(parts, " ")
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

// textField is boundedMessage for terminal output. Every attacker-reachable
// string in this file goes through it or textError.
func (c config) textField(s string) string { return TermSafe(c.boundedMessage(s)) }

func (c config) textError(err error) string { return TermSafe(c.errorString(err)) }

func (c config) writeHeuristic(w io.Writer, h scanner.HeuristicResult, standalone bool) {
	path := c.textField(h.FilePath)
	if h.Error != nil {
		fmt.Fprintf(w, " [ERR] Heuristics on %s: %s\n\n", path, c.textError(h.Error))
		return
	}

	if h.Skipped != "" {
		fmt.Fprintf(w, " [~] SKIPPED heuristics on %s: %s\n", path, c.textField(h.Skipped))
		return
	}

	threshold := thresholdFor(h, c.heuristicThreshold)
	switch {
	case h.Score >= threshold:
		fmt.Fprintf(w, " [!] DETECTED (Heuristics) — %s\n", path)
		fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
		fmt.Fprintf(w, "     %-10s: %d / %d threshold\n\n", "Score", h.Score, threshold)

		byCategory := make(map[string][]scanner.HeuristicMatch)
		var order []string
		for _, m := range h.Matches {
			if _, ok := byCategory[m.Category]; !ok {
				order = append(order, m.Category)
			}
			byCategory[m.Category] = append(byCategory[m.Category], m)
		}
		for _, cat := range order {
			tech := ""
			if t := scanner.CategoryTechnique(cat); t != "" {
				tech = "  (" + c.textField(t) + ")"
			}
			fmt.Fprintf(w, "     [%s]%s\n", c.textField(cat), tech)
			for _, hit := range byCategory[cat] {
				extra := ""
				if hit.Hits > 1 {
					extra = fmt.Sprintf("  (x%d)", hit.Hits)
				}
				fmt.Fprintf(w, "       %-14s %s%s\n", "["+c.textField(hit.Source)+"]", c.textField(hit.Indicator), extra)
			}
		}
		fmt.Fprintln(w)

	case len(h.Matches) > 0:
		fmt.Fprintf(w, " [~] LOW SUSPICION — %s (score: %d)\n", path, h.Score)

	case standalone:
		// No ScanResult printed a verdict for this path, so say something.
		fmt.Fprintf(w, " [CLEAN] %s\n", path)
	}
}

// writeStatic renders the structural analysis. A breach gets a full block;
// scored evidence below the threshold gets one line naming the classes, so a
// "packed with UPX" is visible even when it does not alert; a spotless
// structure prints nothing (the hash/YARA line already said CLEAN).
func (c config) writeStatic(w io.Writer, s *static.Result) {
	path := c.textField(s.FilePath)
	if s.Error != nil {
		fmt.Fprintf(w, " [ERR] Static analysis on %s: %s\n\n", path, c.textError(s.Error))
		return
	}
	if s.Skipped != "" {
		fmt.Fprintf(w, " [~] SKIPPED static analysis on %s: %s\n", path, c.textField(s.Skipped))
		return
	}
	threshold := staticThresholdFor(s, c.staticThreshold)
	var scored []static.Anomaly
	for _, a := range s.Anomalies {
		if a.Score > 0 {
			scored = append(scored, a)
		}
	}
	switch {
	case s.Score >= threshold:
		fmt.Fprintf(w, " [!] DETECTED (Static) — %s\n", path)
		fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
		fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", s.Score, threshold)
		if p := s.PE; p != nil {
			fmt.Fprintf(w, "     %-10s: %s %s, %d imports, imphash %s\n", "Image", p.Format, c.textField(p.MachineName), p.ImportCount, c.boundedHash(p.Imphash))
			if p.Packer != nil {
				fmt.Fprintf(w, "     %-10s: %s\n", "Packer", c.textField(p.Packer.Name))
			}
		}
		if e := s.ELF; e != nil {
			image := fmt.Sprintf("%s %s %s, %d imports", e.Class, c.textField(e.MachineName), c.textField(e.TypeName), e.ImportCount)
			switch {
			case e.Interp != "":
				image += ", interp " + c.textField(e.Interp)
			case e.Static:
				image += ", static"
			}
			if e.ImportHash != "" {
				image += ", import hash " + c.boundedHash(e.ImportHash)
			}
			fmt.Fprintf(w, "     %-10s: %s\n", "Image", image)
			if e.Packer != nil {
				fmt.Fprintf(w, "     %-10s: %s\n", "Packer", c.textField(e.Packer.Name))
			}
			if m := e.Module; m != nil {
				signed := "unsigned"
				if m.Signed {
					signed = "signature present, not verified"
				}
				fmt.Fprintf(w, "     %-10s: kernel module %s, vermagic %s, %s\n", "Module", c.textField(m.Name), c.textField(m.Vermagic), signed)
			}
		}
		fmt.Fprintln(w)
		for _, cs := range s.Categories {
			if cs.Applied == 0 {
				continue
			}
			fmt.Fprintf(w, "     [%s] %d/%d\n", c.textField(cs.Category), cs.Applied, cs.Cap)
			for _, a := range scored {
				if a.Category != cs.Category {
					continue
				}
				tech := ""
				if a.Technique != "" {
					tech = "  (" + c.textField(a.Technique) + ")"
				}
				fmt.Fprintf(w, "       %-34s %s%s\n", c.textField(a.Class), c.textField(a.Detail), tech)
			}
		}
		if sig := s.PE; sig != nil && sig.Authenticode != nil {
			fmt.Fprintf(w, "     [Signature] %s\n", c.textField(sig.Authenticode.Note))
		}
		fmt.Fprintln(w)
	case len(scored) > 0:
		names := make([]string, 0, len(scored))
		for _, a := range scored {
			names = append(names, c.textField(a.Class))
		}
		fmt.Fprintf(w, " [~] LOW SUSPICION (static) — %s (score: %d): %s\n", path, s.Score, strings.Join(names, ", "))
	}
}

// writeStego renders the invisible-codepoint analysis. A breach gets a full
// block naming every codepoint, where it first appears and an example with
// the invisibles made visible; excused codepoints (emoji joiners, joining
// scripts, a BOM) print nothing, because they are not evidence.
func (c config) writeStego(w io.Writer, s *stego.Result) {
	path := c.textField(s.FilePath)
	if s.Error != nil {
		fmt.Fprintf(w, " [ERR] Stego analysis on %s: %s\n\n", path, c.textError(s.Error))
		return
	}
	if s.Skipped != "" || !stegoBreached(s, c.stegoThreshold) {
		return
	}
	threshold := stegoThresholdFor(s, c.stegoThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Stego) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", s.Score, threshold)
	fmt.Fprintf(w, "     %-10s: %s, %d line(s), %d invisible codepoint(s) scored, %d excused by context\n", "Text", c.textField(s.Encoding), s.Lines, s.Suspicious, s.Benign)
	fmt.Fprintln(w)
	for _, f := range s.Findings {
		tags := ""
		if f.Technique != "" || f.Novel != "" {
			tags = "  (" + strings.TrimSpace(strings.Join([]string{c.textField(f.Technique), c.textField(f.Novel)}, " ")) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d\n", c.textField(f.Class), f.Score)
		fmt.Fprintf(w, "       %s%s\n", c.textField(f.Detail), tags)
	}
	for _, cp := range s.Codepoints {
		for _, ex := range cp.Examples {
			fmt.Fprintf(w, "       %s %s\n", c.textField(cp.Code), c.textField(ex))
		}
	}
	fmt.Fprintln(w)
}

// writeEncChain renders the encoded-executable analysis when it fired: every
// decoded PE/ELF with its encoding, layer depth and offset.
func (c config) writeEncChain(w io.Writer, e *encchain.Result) {
	if e.Skipped != "" || !encChainBreached(e, c.encChainThreshold) {
		return
	}
	path := c.textField(e.FilePath)
	threshold := encChainThresholdFor(e, c.encChainThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Encoded executable) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", e.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range e.Findings {
		tags := ""
		if f.Technique != "" || f.Novel != "" {
			tags = "  (" + strings.TrimSpace(strings.Join([]string{c.textField(f.Technique), c.textField(f.Novel)}, " ")) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		fmt.Fprintf(w, "       %s (%s, layer %d, at offset %d)\n", c.textField(f.Detail), c.textField(f.Encoding), f.Depth, f.Offset)
	}
	fmt.Fprintln(w)
}

// writeLNK renders the Shell Link analysis when it fired: each detection
// signal with its class and ATT&CK technique.
func (c config) writeLNK(w io.Writer, l *lnk.Result) {
	if l.Skipped != "" || !lnkBreached(l, c.lnkThreshold) {
		return
	}
	path := c.textField(l.FilePath)
	threshold := lnkThresholdFor(l, c.lnkThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Shell Link) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", l.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range l.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeOLE renders the OLE compound-file (VBA macro) analysis when it fired.
func (c config) writeOLE(w io.Writer, o *ole.Result) {
	if o.Skipped != "" || !oleBreached(o, c.oleThreshold) {
		return
	}
	path := c.textField(o.FilePath)
	threshold := oleThresholdFor(o, c.oleThreshold)
	fmt.Fprintf(w, " [!] DETECTED (OLE macro) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", o.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range o.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writePDF renders the PDF malicious-document analysis when it fired.
func (c config) writePDF(w io.Writer, p *pdf.Result) {
	if p.Skipped != "" || !pdfBreached(p, c.pdfThreshold) {
		return
	}
	path := c.textField(p.FilePath)
	threshold := pdfThresholdFor(p, c.pdfThreshold)
	fmt.Fprintf(w, " [!] DETECTED (PDF document) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", p.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range p.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeISO renders the ISO 9660 malicious-container analysis when it fired.
func (c config) writeISO(w io.Writer, i *iso.Result) {
	if i.Skipped != "" || !isoBreached(i, c.isoThreshold) {
		return
	}
	path := c.textField(i.FilePath)
	threshold := isoThresholdFor(i, c.isoThreshold)
	fmt.Fprintf(w, " [!] DETECTED (ISO container) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", i.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range i.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeLinuxPkg renders the Linux software-package analysis when it fired.
func (c config) writeLinuxPkg(w io.Writer, p *linuxpkg.Result) {
	if p.Skipped != "" || !linuxPkgBreached(p, c.linuxPkgThreshold) {
		return
	}
	path := c.textField(p.FilePath)
	threshold := linuxPkgThresholdFor(p, c.linuxPkgThreshold)
	format := ""
	if p.Parsed != nil {
		format = " " + p.Parsed.Format
	}
	fmt.Fprintf(w, " [!] DETECTED (Linux package%s) — %s\n", format, path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", p.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range p.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeArchive renders the compressed-container analysis when it fired.
func (c config) writeArchive(w io.Writer, a *archive.Result) {
	if a.Skipped != "" || !archiveBreached(a, c.archiveThreshold) {
		return
	}
	path := c.textField(a.FilePath)
	threshold := archiveThresholdFor(a, c.archiveThreshold)
	format := ""
	if a.Parsed != nil {
		format = " " + a.Parsed.Format
	}
	fmt.Fprintf(w, " [!] DETECTED (archive%s) — %s\n", format, path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", a.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range a.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		if f.Via != "" {
			detail += " (via " + c.textField(f.Via) + ")"
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeCHM renders the Compiled HTML Help analysis when it fired.
func (c config) writeCHM(w io.Writer, h *chm.Result) {
	if h.Skipped != "" || !chmBreached(h, c.chmThreshold) {
		return
	}
	path := c.textField(h.FilePath)
	threshold := chmThresholdFor(h, c.chmThreshold)
	fmt.Fprintf(w, " [!] DETECTED (CHM help file) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", h.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range h.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writeTradecraft renders the behavioural analysis when it fired.
func (c config) writeTradecraft(w io.Writer, t *tradecraft.Result) {
	if t.Skipped != "" || !tradecraftBreached(t, c.tradecraftThreshold) {
		return
	}
	path := c.textField(t.FilePath)
	threshold := tradecraftThresholdFor(t, c.tradecraftThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Tradecraft) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", t.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range t.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		detail := c.textField(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.textField(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
	}
	fmt.Fprintln(w)
}

// writePeel renders the obfuscation-chain analysis when it fired.
func (c config) writePeel(w io.Writer, p *peeler.Result) {
	if p.Skipped != "" || !peelBreached(p, c.peelThreshold) {
		return
	}
	path := c.textField(p.FilePath)
	threshold := peelThresholdFor(p, c.peelThreshold)
	fmt.Fprintf(w, " [!] DETECTED (obfuscation chain) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", p.Score, threshold)
	fmt.Fprintf(w, "     %-10s: %s (depth %d)\n", "Outcome", c.textField(string(p.Outcome)), p.MaxDepth)
	if p.PrimarySignature != "" {
		fmt.Fprintf(w, "     %-10s: %s\n", "Chain", c.textField(p.PrimarySignature))
	}
	fmt.Fprintln(w)
	for _, f := range p.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.textField(f.Technique)
			if f.Novel != "" {
				tags += ", " + c.textField(f.Novel)
			}
			tags += ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.textField(f.Class), f.Score, tags)
		fmt.Fprintf(w, "       %s\n", c.textField(f.Detail))
	}
	fmt.Fprintln(w)
}

// writeFusion renders the lattice's verdict when it adds something to what
// the detectors already printed: a detection reached only by corroboration,
// or a verdict several sources agreed on. A fused verdict that restates one
// detector's own breach, or a clean file, prints nothing.
func (c config) writeFusion(w io.Writer, path string, v *fusion.Verdict) {
	if !v.Detected() || (len(v.Agreed) < 2 && !v.Corroborated) {
		return
	}
	path = c.textField(path)
	if v.Corroborated {
		fmt.Fprintf(w, " [!] DETECTED (Fusion) — %s\n", path)
	} else {
		fmt.Fprintf(w, " [+] Fusion — %s\n", path)
	}
	fmt.Fprintf(w, "     %-10s: %s (fused %.2f / %.2f, %s confidence)\n", "Verdict", strings.ToUpper(string(v.Tier)), v.Score, v.Threshold, v.Confidence)
	agreed := make([]string, 0, len(v.Agreed)) // strongest first: not boundedList, which sorts
	for _, a := range v.Agreed {
		agreed = append(agreed, c.textField(a))
	}
	fmt.Fprintf(w, "     %-10s: %s\n", "Agreed", strings.Join(agreed, ", "))
	if len(v.Techniques) > 0 || len(v.Novel) > 0 {
		fmt.Fprintf(w, "     %-10s: %s\n", "Techniques", strings.Join(boundedList(c, append(append([]string{}, v.Techniques...), v.Novel...)), ", "))
	}
	for _, src := range v.Sources {
		if !src.Counted {
			continue
		}
		switch src.Role {
		case fusion.RoleDefinitive:
			fmt.Fprintf(w, "     [%s] %s\n", c.textField(src.Name), src.Role)
		default:
			fmt.Fprintf(w, "     [%s] %d/%d, ratio %.2f, %s\n", c.textField(src.Name), src.Score, src.Threshold, src.Ratio, src.Role)
		}
		for _, e := range src.Evidence {
			tech := ""
			if e.Technique != "" {
				tech = "  (" + c.textField(e.Technique) + ")"
			}
			fmt.Fprintf(w, "       %-34s %s%s\n", c.textField(e.Label), c.textField(e.Detail), tech)
		}
	}
	fmt.Fprintln(w)
}

// writeProvenance prints one line of package-manager context under a file:
//
//	provenance: dpkg coreutils 9.4-3 (intact, per the host's dpkg database)
//	provenance: dpkg coreutils 9.4-3 (MODIFIED: shipped md5 … differs, per the host's dpkg database)
//
// and, for a modified package-owned executable, the observation line. The
// wording names the database on purpose: the answer is only as good as the
// host's own package database, which root can rewrite.
func (c config) writeProvenance(w io.Writer, p provenance.Provenance) {
	var line string
	switch {
	case p.State.Owned():
		who := c.textField(p.Manager) + " " + c.textField(p.Package)
		if p.Version != "" {
			who += " " + c.textField(p.Version)
		}
		switch p.State {
		case provenance.OwnedIntact:
			line = fmt.Sprintf("%s (intact, per the host's %s database)", who, c.textField(p.Manager))
		case provenance.OwnedModified:
			line = fmt.Sprintf("%s (MODIFIED: shipped %s %s differs from the scanned file, per the host's %s database)",
				who, c.textField(p.DigestAlgo), TermSafe(c.boundedHash(p.ShippedDigest)), c.textField(p.Manager))
		case provenance.OwnedConffile:
			line = fmt.Sprintf("%s (conffile: an administrator-edited file, not compared, per the host's %s database)", who, c.textField(p.Manager))
		default:
			line = fmt.Sprintf("%s (owned, no digest recorded to verify against, per the host's %s database)", who, c.textField(p.Manager))
		}
	case p.State == provenance.Unowned:
		line = fmt.Sprintf("no package owns this path, per the host's %s database", c.textField(p.Manager))
	case p.State == provenance.Unsupported:
		line = fmt.Sprintf("%s database present but unsupported (rpm keeps its file manifest in the rpmdb, not loose files)", c.textField(p.Manager))
	default:
		line = "unknown (no package database found, or the index was truncated)"
	}
	fmt.Fprintf(w, "     provenance: %s\n", line)
	if f := p.Finding; f != nil {
		fmt.Fprintf(w, "     [OBS] %s: %s (%s); an observation beside the verdict, not scored\n",
			c.textField(f.Class), c.textField(f.Detail), c.textField(f.Technique))
	}
}

func (c config) writeSummary(w io.Writer, in Input) {
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	hash := in.HashDetectionCount()
	yara := in.YaraDetectionCount()
	heur := len(in.HeuristicBreach(c.heuristicThreshold))
	stat := len(in.StaticBreach(c.staticThreshold))
	steg := len(in.StegoBreach(c.stegoThreshold))
	enc := len(in.EncChainBreach(c.encChainThreshold))
	lnkHits := len(in.LNKBreach(c.lnkThreshold))
	oleHits := len(in.OLEBreach(c.oleThreshold))
	pdfHits := len(in.PDFBreach(c.pdfThreshold))
	isoHits := len(in.ISOBreach(c.isoThreshold))
	pkgHits := len(in.LinuxPkgBreach(c.linuxPkgThreshold))
	peelHits := len(in.PeelBreach(c.peelThreshold))
	archiveHits := len(in.ArchiveBreach(c.archiveThreshold))
	chmHits := len(in.CHMBreach(c.chmThreshold))
	tradecraftHits := len(in.TradecraftBreach(c.tradecraftThreshold))
	fused := len(in.FusionCorroborated())

	fmt.Fprintln(w)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	fmt.Fprintf(w, " Scan complete         : %s\n", elapsedString(in.Elapsed))
	fmt.Fprintf(w, " Files scanned         : %d\n", len(in.AllPaths()))
	fmt.Fprintf(w, " Hash detections       : %d\n", hash)
	fmt.Fprintf(w, " YARA detections       : %d\n", yara)
	fmt.Fprintf(w, " Heuristic detections  : %d\n", heur)
	fmt.Fprintf(w, " Static detections     : %d\n", stat)
	fmt.Fprintf(w, " Stego detections      : %d\n", steg)
	fmt.Fprintf(w, " Encoded-exe detections: %d\n", enc)
	fmt.Fprintf(w, " Shell-link detections : %d\n", lnkHits)
	fmt.Fprintf(w, " OLE-macro detections  : %d\n", oleHits)
	fmt.Fprintf(w, " PDF detections        : %d\n", pdfHits)
	fmt.Fprintf(w, " ISO detections        : %d\n", isoHits)
	fmt.Fprintf(w, " Linux-pkg detections  : %d\n", pkgHits)
	fmt.Fprintf(w, " Chain-peel detections : %d\n", peelHits)
	fmt.Fprintf(w, " Archive detections    : %d\n", archiveHits)
	fmt.Fprintf(w, " CHM detections        : %d\n", chmHits)
	fmt.Fprintf(w, " Tradecraft detections : %d\n", tradecraftHits)
	fmt.Fprintf(w, " Fused-only detections : %d\n", fused)
	if in.Provenance != nil {
		fmt.Fprintf(w, " Provenance resolved   : %d (modified package binaries: %d, observations only)\n",
			in.ProvenanceResolvedCount(), len(in.ProvenanceModifiedBinaries()))
	}
	fmt.Fprintf(w, " Errors                : %d\n", in.ErrorCount())
	fmt.Fprintf(w, " Exit code             : %d (%s)\n", code, reason)
	fmt.Fprintln(w, strings.Repeat("-", 60))

	if hash+yara+heur+stat+steg+enc+fused > 0 {
		fmt.Fprintln(w, "\n *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***")
	} else if in.RunError != nil {
		fmt.Fprintln(w, "\n Scan did not run.")
	} else {
		fmt.Fprintln(w, "\n No threats detected.")
	}
}

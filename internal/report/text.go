package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/fusion"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// Reporter is the common shape of every output format.
type Reporter interface {
	Write(w io.Writer, in Input) error
}

// Formats lists the names NewReporter accepts.
var Formats = []string{"text", "json", "sarif", "ocsf"}

// NewReporter selects a reporter by format name ("text", "json", "sarif",
// "ocsf").
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
	default:
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
		fmt.Fprintf(bw, " [ERR] %s\n\n", c.errorString(in.RunError))
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
		if hasResult && res.ISO != nil {
			c.writeISO(bw, res.ISO)
		}
		if hasResult && res.Fusion != nil {
			c.writeFusion(bw, res.FilePath, res.Fusion)
		}
	}

	c.writeSummary(bw, in)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("report: write text: %w", err)
	}
	return nil
}

func (c config) writeResult(w io.Writer, r scanner.ScanResult) {
	path := c.boundedMessage(r.FilePath)
	if r.Error != nil {
		fmt.Fprintf(w, " [ERR] %s\n      %s\n\n", path, c.errorString(r.Error))
		return
	}

	// ── Hash match ──
	if r.Detected {
		fmt.Fprintln(w, " [!] DETECTED (Hash) —", path)
		fmt.Fprintf(w, "     %-10s: %s\n", c.boundedMessage(r.MatchType), c.boundedHash(r.MatchHash))
		fmt.Fprintf(w, "     %-10s: %s\n", "Match", c.boundedMessage(r.ThreatName))
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
				tags = fmt.Sprintf(" [%s]", strings.Join(boundedList(c, m.Tags), ", "))
			}
			fmt.Fprintf(w, "     [YARA] %s::%s%s\n", c.boundedMessage(m.Namespace), c.boundedMessage(m.RuleName), tags)
			if meta := c.metaLine(m); meta != "" {
				fmt.Fprintf(w, "            %s\n", meta)
			}
			for _, s := range m.Strings {
				data, cut := truncateBytes(s.Data, 32)
				suffix := ""
				if cut {
					suffix = "..."
				}
				fmt.Fprintf(w, "            %s @ 0x%x : %q%s\n", c.boundedMessage(s.Name), s.Offset, data, suffix)
			}
		}
		fmt.Fprintf(w, "     %-10s: %s\n\n", "Scan time", elapsedString(r.ScanTime))
	}

	// ── Clean ──
	if !r.Detected && len(r.YaraMatches) == 0 {
		fmt.Fprintf(w, " [CLEAN] %s\n", path)
	}

	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "     [WARN] %s\n", c.boundedMessage(warn))
	}
}

// metaLine renders the meta fields an analyst wants at a glance.
func (c config) metaLine(m scanner.YaraMatch) string {
	var parts []string
	if a := m.MetaString("author"); a != "" {
		parts = append(parts, "author="+c.boundedMessage(a))
	}
	if tl, ok := m.MetaInt("threat_level"); ok {
		parts = append(parts, fmt.Sprintf("threat_level=%d", tl))
	}
	if meta, ok := m.Meta("in_the_wild"); ok {
		parts = append(parts, "in_the_wild="+c.boundedMessage(meta.String()))
	}
	if d := m.MetaString("description"); d != "" {
		parts = append(parts, "desc="+strconvQuote(c.boundedMessage(d)))
	}
	return strings.Join(parts, " ")
}

func strconvQuote(s string) string { return fmt.Sprintf("%q", s) }

func (c config) writeHeuristic(w io.Writer, h scanner.HeuristicResult, standalone bool) {
	path := c.boundedMessage(h.FilePath)
	if h.Error != nil {
		fmt.Fprintf(w, " [ERR] Heuristics on %s: %s\n\n", path, c.errorString(h.Error))
		return
	}

	if h.Skipped != "" {
		fmt.Fprintf(w, " [~] SKIPPED heuristics on %s: %s\n", path, c.boundedMessage(h.Skipped))
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
				tech = "  (" + c.boundedMessage(t) + ")"
			}
			fmt.Fprintf(w, "     [%s]%s\n", c.boundedMessage(cat), tech)
			for _, hit := range byCategory[cat] {
				extra := ""
				if hit.Hits > 1 {
					extra = fmt.Sprintf("  (x%d)", hit.Hits)
				}
				fmt.Fprintf(w, "       %-14s %s%s\n", "["+c.boundedMessage(hit.Source)+"]", c.boundedMessage(hit.Indicator), extra)
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
	path := c.boundedMessage(s.FilePath)
	if s.Error != nil {
		fmt.Fprintf(w, " [ERR] Static analysis on %s: %s\n\n", path, c.errorString(s.Error))
		return
	}
	if s.Skipped != "" {
		fmt.Fprintf(w, " [~] SKIPPED static analysis on %s: %s\n", path, c.boundedMessage(s.Skipped))
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
			fmt.Fprintf(w, "     %-10s: %s %s, %d imports, imphash %s\n", "Image", p.Format, c.boundedMessage(p.MachineName), p.ImportCount, c.boundedHash(p.Imphash))
			if p.Packer != nil {
				fmt.Fprintf(w, "     %-10s: %s\n", "Packer", c.boundedMessage(p.Packer.Name))
			}
		}
		if e := s.ELF; e != nil {
			image := fmt.Sprintf("%s %s %s, %d imports", e.Class, c.boundedMessage(e.MachineName), c.boundedMessage(e.TypeName), e.ImportCount)
			switch {
			case e.Interp != "":
				image += ", interp " + c.boundedMessage(e.Interp)
			case e.Static:
				image += ", static"
			}
			if e.ImportHash != "" {
				image += ", import hash " + c.boundedHash(e.ImportHash)
			}
			fmt.Fprintf(w, "     %-10s: %s\n", "Image", image)
			if e.Packer != nil {
				fmt.Fprintf(w, "     %-10s: %s\n", "Packer", c.boundedMessage(e.Packer.Name))
			}
			if m := e.Module; m != nil {
				signed := "unsigned"
				if m.Signed {
					signed = "signature present, not verified"
				}
				fmt.Fprintf(w, "     %-10s: kernel module %s, vermagic %s, %s\n", "Module", c.boundedMessage(m.Name), c.boundedMessage(m.Vermagic), signed)
			}
		}
		fmt.Fprintln(w)
		for _, cs := range s.Categories {
			if cs.Applied == 0 {
				continue
			}
			fmt.Fprintf(w, "     [%s] %d/%d\n", c.boundedMessage(cs.Category), cs.Applied, cs.Cap)
			for _, a := range scored {
				if a.Category != cs.Category {
					continue
				}
				tech := ""
				if a.Technique != "" {
					tech = "  (" + c.boundedMessage(a.Technique) + ")"
				}
				fmt.Fprintf(w, "       %-34s %s%s\n", c.boundedMessage(a.Class), c.boundedMessage(a.Detail), tech)
			}
		}
		if sig := s.PE; sig != nil && sig.Authenticode != nil {
			fmt.Fprintf(w, "     [Signature] %s\n", c.boundedMessage(sig.Authenticode.Note))
		}
		fmt.Fprintln(w)
	case len(scored) > 0:
		names := make([]string, 0, len(scored))
		for _, a := range scored {
			names = append(names, c.boundedMessage(a.Class))
		}
		fmt.Fprintf(w, " [~] LOW SUSPICION (static) — %s (score: %d): %s\n", path, s.Score, strings.Join(names, ", "))
	}
}

// writeStego renders the invisible-codepoint analysis. A breach gets a full
// block naming every codepoint, where it first appears and an example with
// the invisibles made visible; excused codepoints (emoji joiners, joining
// scripts, a BOM) print nothing, because they are not evidence.
func (c config) writeStego(w io.Writer, s *stego.Result) {
	path := c.boundedMessage(s.FilePath)
	if s.Error != nil {
		fmt.Fprintf(w, " [ERR] Stego analysis on %s: %s\n\n", path, c.errorString(s.Error))
		return
	}
	if s.Skipped != "" || !stegoBreached(s, c.stegoThreshold) {
		return
	}
	threshold := stegoThresholdFor(s, c.stegoThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Stego) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", s.Score, threshold)
	fmt.Fprintf(w, "     %-10s: %s, %d line(s), %d invisible codepoint(s) scored, %d excused by context\n", "Text", c.boundedMessage(s.Encoding), s.Lines, s.Suspicious, s.Benign)
	fmt.Fprintln(w)
	for _, f := range s.Findings {
		tags := ""
		if f.Technique != "" || f.Novel != "" {
			tags = "  (" + strings.TrimSpace(strings.Join([]string{c.boundedMessage(f.Technique), c.boundedMessage(f.Novel)}, " ")) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d\n", c.boundedMessage(f.Class), f.Score)
		fmt.Fprintf(w, "       %s%s\n", c.boundedMessage(f.Detail), tags)
	}
	for _, cp := range s.Codepoints {
		for _, ex := range cp.Examples {
			fmt.Fprintf(w, "       %s %s\n", c.boundedMessage(cp.Code), c.boundedMessage(ex))
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
	path := c.boundedMessage(e.FilePath)
	threshold := encChainThresholdFor(e, c.encChainThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Encoded executable) â %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", e.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range e.Findings {
		tags := ""
		if f.Technique != "" || f.Novel != "" {
			tags = "  (" + strings.TrimSpace(strings.Join([]string{c.boundedMessage(f.Technique), c.boundedMessage(f.Novel)}, " ")) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.boundedMessage(f.Class), f.Score, tags)
		fmt.Fprintf(w, "       %s (%s, layer %d, at offset %d)\n", c.boundedMessage(f.Detail), c.boundedMessage(f.Encoding), f.Depth, f.Offset)
	}
	fmt.Fprintln(w)
}

// writeLNK renders the Shell Link analysis when it fired: each detection
// signal with its class and ATT&CK technique.
func (c config) writeLNK(w io.Writer, l *lnk.Result) {
	if l.Skipped != "" || !lnkBreached(l, c.lnkThreshold) {
		return
	}
	path := c.boundedMessage(l.FilePath)
	threshold := lnkThresholdFor(l, c.lnkThreshold)
	fmt.Fprintf(w, " [!] DETECTED (Shell Link) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", l.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range l.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.boundedMessage(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.boundedMessage(f.Class), f.Score, tags)
		detail := c.boundedMessage(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.boundedMessage(f.Evidence)
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
	path := c.boundedMessage(o.FilePath)
	threshold := oleThresholdFor(o, c.oleThreshold)
	fmt.Fprintf(w, " [!] DETECTED (OLE macro) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", o.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range o.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.boundedMessage(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.boundedMessage(f.Class), f.Score, tags)
		detail := c.boundedMessage(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.boundedMessage(f.Evidence)
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
	path := c.boundedMessage(p.FilePath)
	threshold := pdfThresholdFor(p, c.pdfThreshold)
	fmt.Fprintf(w, " [!] DETECTED (PDF document) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", p.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range p.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.boundedMessage(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.boundedMessage(f.Class), f.Score, tags)
		detail := c.boundedMessage(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.boundedMessage(f.Evidence)
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
	path := c.boundedMessage(i.FilePath)
	threshold := isoThresholdFor(i, c.isoThreshold)
	fmt.Fprintf(w, " [!] DETECTED (ISO container) — %s\n", path)
	fmt.Fprintf(w, "     %-10s: %s\n", "Verdict", "SUSPICIOUS")
	fmt.Fprintf(w, "     %-10s: %d / %d threshold\n", "Score", i.Score, threshold)
	fmt.Fprintln(w)
	for _, f := range i.Findings {
		tags := ""
		if f.Technique != "" {
			tags = "  (" + c.boundedMessage(f.Technique) + ")"
		}
		fmt.Fprintf(w, "     [%s] %d%s\n", c.boundedMessage(f.Class), f.Score, tags)
		detail := c.boundedMessage(f.Detail)
		if f.Evidence != "" {
			detail += ": " + c.boundedMessage(f.Evidence)
		}
		fmt.Fprintf(w, "       %s\n", detail)
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
	path = c.boundedMessage(path)
	if v.Corroborated {
		fmt.Fprintf(w, " [!] DETECTED (Fusion) — %s\n", path)
	} else {
		fmt.Fprintf(w, " [+] Fusion — %s\n", path)
	}
	fmt.Fprintf(w, "     %-10s: %s (fused %.2f / %.2f, %s confidence)\n", "Verdict", strings.ToUpper(string(v.Tier)), v.Score, v.Threshold, v.Confidence)
	agreed := make([]string, 0, len(v.Agreed)) // strongest first: not boundedList, which sorts
	for _, a := range v.Agreed {
		agreed = append(agreed, c.boundedMessage(a))
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
			fmt.Fprintf(w, "     [%s] %s\n", c.boundedMessage(src.Name), src.Role)
		default:
			fmt.Fprintf(w, "     [%s] %d/%d, ratio %.2f, %s\n", c.boundedMessage(src.Name), src.Score, src.Threshold, src.Ratio, src.Role)
		}
		for _, e := range src.Evidence {
			tech := ""
			if e.Technique != "" {
				tech = "  (" + c.boundedMessage(e.Technique) + ")"
			}
			fmt.Fprintf(w, "       %-34s %s%s\n", c.boundedMessage(e.Label), c.boundedMessage(e.Detail), tech)
		}
	}
	fmt.Fprintln(w)
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
	fmt.Fprintf(w, " Fused-only detections : %d\n", fused)
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

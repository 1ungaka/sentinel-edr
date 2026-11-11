package honesty

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// Formats are the renderings of the index. "json" is the document itself.
var Formats = []string{"text", "json", "markdown"}

// The renderings below print strings that come from files the engine did not
// write: an expectation note, a corpus name, a manifest path, an error text.
// Every one of them goes through safe (terminal) or md / code (markdown), so a
// name cannot erase its own line, forge a section or inject markup.

// safe renders untrusted text for a terminal.
func safe(s string) string { return report.TermSafe(s) }

// mdEscaper backslash-escapes the characters that start markdown or HTML
// constructs inline. Line-start constructs (#, -, >, digits) cannot occur:
// safe has already turned every newline into a visible escape.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`,
	`<`, `\<`, `>`, `\>`, `|`, `\|`, `~`, `\~`, `&`, `&amp;`,
	// Bare URLs autolink in GitHub-flavoured markdown.
	`:`, `\:`, `www.`, `www\.`,
)

// md renders untrusted prose for markdown.
func md(s string) string { return mdEscaper.Replace(safe(s)) }

// code renders an untrusted value (an id, a path, a name) as a markdown code
// span, where no markup is interpreted. A backtick would end the span and a
// pipe would end a table cell, so both are shown escaped.
func code(s string) string {
	if s == "" {
		return ""
	}
	s = strings.NewReplacer("`", `\x60`, `|`, `\x7c`).Replace(safe(s))
	return "`" + s + "`"
}

func pct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", *v*100)
}

func num(v *int) string {
	if v == nil {
		return "unknown"
	}
	return fmt.Sprint(*v)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// wrap breaks text at width columns, prefixing the first line with first and
// the others with rest.
func wrap(b *strings.Builder, first, rest, text string, width int) {
	prefix, col := first, len(first)
	b.WriteString(prefix)
	fresh := true
	for _, word := range strings.Fields(text) {
		if !fresh && col+1+len(word) > width {
			b.WriteString("\n")
			b.WriteString(rest)
			col, fresh = len(rest), true
		}
		if !fresh {
			b.WriteString(" ")
			col++
		}
		b.WriteString(word)
		col += len(word)
		fresh = false
	}
	b.WriteString("\n")
}

const textWidth = 78

func textHeader(b *strings.Builder, title, state string) {
	fmt.Fprintf(b, "\n%-44s state: %s\n", title, safe(state))
}

func textField(b *strings.Builder, key, value string) {
	fmt.Fprintf(b, "  %-24s: %s\n", key, value)
}

func textCaveats(b *strings.Builder, caveats []string) {
	if len(caveats) == 0 {
		return
	}
	b.WriteString("  Caveats:\n")
	for _, c := range caveats {
		wrap(b, "    - ", "      ", safe(c), textWidth)
	}
}

func textTable(b *strings.Builder, rows [][]string) {
	tw := tabwriter.NewWriter(b, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintln(tw, "    "+strings.Join(r, "\t"))
	}
	tw.Flush()
}

// WriteText renders the index for a terminal.
func WriteText(w io.Writer, ix *Index) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s honesty index (schema %s)\n", safe(ix.Tool.Name), safe(ix.Tool.Version), safe(ix.SchemaVersion))
	if ix.Generated != nil {
		fmt.Fprintf(&b, "Generated: %s\n", safe(*ix.Generated))
	} else {
		b.WriteString("Generated: (timestamp suppressed)\n")
	}
	b.WriteString("\n")
	wrap(&b, "", "", "Three sections, each with its own state. There is no overall score: "+
		"a gap in one section is not offset by a result in another.", textWidth)

	textCoverage(&b, &ix.Coverage)
	textEvaluation(&b, &ix.Evaluation)
	textSelftest(&b, &ix.Selftest)

	b.WriteString("\nNot claimed by this index:\n")
	for _, n := range ix.NotClaimed {
		wrap(&b, "  - ", "    ", safe(n), textWidth)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func safeJoin(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = safe(s)
	}
	return strings.Join(out, ", ")
}

func textCoverage(b *strings.Builder, c *Coverage) {
	textHeader(b, "ATT&CK COVERAGE", c.State)
	switch {
	case c.TechniquesWithContent == nil:
		textField(b, "Techniques with content", "not measured")
	case c.Covered == nil:
		textField(b, "Techniques with content", num(c.TechniquesWithContent)+" (covered/partial split unknown)")
	default:
		textField(b, "Techniques with content", fmt.Sprintf("%s (%s covered, %s partial)",
			num(c.TechniquesWithContent), num(c.Covered), num(c.Partial)))
	}
	if len(c.PartialIDs) > 0 {
		wrap(b, fmt.Sprintf("  %-24s: ", "Partial by design"), strings.Repeat(" ", 28), safeJoin(c.PartialIDs), textWidth)
	}
	if c.TechniquesWithContent != nil {
		if c.DeclaredGaps == nil {
			textField(b, "Declared gaps", "unknown (no expectation to read them from)")
		} else {
			textField(b, "Declared gaps", fmt.Sprintf("%d (%s planned, %s owned by sensor/console)",
				len(c.DeclaredGaps), num(c.GapsPlanned), num(c.GapsNone)))
			rows := make([][]string, 0, len(c.DeclaredGaps))
			for _, g := range c.DeclaredGaps {
				rows = append(rows, []string{safe(g.ID), safe(g.State), safe(orDash(g.Name)), safe(g.Note)})
			}
			textTable(b, rows)
		}
		textField(b, "Content, no technique", num(c.UnmappedContent)+" entries, listed in the JSON, never padded with a loose fit")
	}
	if x := c.Expectation; x != nil {
		if x.Matches {
			textField(b, "Expectation", safe(x.Path)+" (matches)")
		} else {
			textField(b, "Expectation", fmt.Sprintf("%s (%d DIFFERENCE(S))", safe(x.Path), len(x.Problems)))
			rows := make([][]string, 0, len(x.Problems))
			for _, p := range x.Problems {
				rows = append(rows, []string{safe(p.ID), safe(p.Kind), safe(p.Text)})
			}
			textTable(b, rows)
		}
	} else if c.TechniquesWithContent != nil {
		textField(b, "Expectation", "none compared")
	}
	textCaveats(b, c.Caveats)
}

func textEvaluation(b *strings.Builder, e *Evaluation) {
	textHeader(b, "EVALUATION (Phase 1 harness)", e.State)
	if e.Report != nil {
		textField(b, "Report", safe(e.Report.Path))
		if e.Report.Generated != "" || e.Report.Tool != "" {
			textField(b, "Recorded", safe(orDash(e.Report.Generated))+" by "+safe(orDash(e.Report.Tool)))
		}
	}
	if e.Totals == nil {
		textField(b, "Precision / recall", "not measured")
		textCaveats(b, e.Caveats)
		return
	}
	synthetic := e.CorpusClass != nil && *e.CorpusClass == CorpusSynthetic
	if c := e.Corpus; c != nil {
		textField(b, "Corpus", safe(orDash(c.Name))+" ("+safe(orDash(c.Manifest))+")")
	}
	if e.CorpusClass != nil {
		class := safe(*e.CorpusClass)
		if synthetic {
			class = strings.ToUpper(class)
		}
		basis := ""
		if e.CorpusClassBasis != nil {
			basis = safe(*e.CorpusClassBasis)
		}
		wrap(b, fmt.Sprintf("  %-24s: ", "Corpus class"), strings.Repeat(" ", 28), class+": "+basis, textWidth)
	}
	if s := e.Samples; s != nil {
		textField(b, "Samples", fmt.Sprintf("%d scored of %d (%d malicious, %d benign), %d error(s), %d skipped",
			s.Scored, s.Total, s.Malicious, s.Benign, s.Errors, s.Skipped))
	}
	textField(b, "Counts", fmt.Sprintf("TP %d  FP %d  TN %d  FN %d", e.Totals.TP, e.Totals.FP, e.Totals.TN, e.Totals.FN))
	if m := e.Metrics; m != nil {
		textField(b, "Precision", pct(m.Precision))
		recall := pct(m.Recall)
		if synthetic {
			recall += "  (synthetic corpus: a plumbing check, not a detection rate)"
		}
		textField(b, "Recall", recall)
		textField(b, "False-positive rate", pct(m.FalsePositiveRate))
	}
	if len(e.Detectors) > 0 {
		b.WriteString("  Per detector:\n")
		rows := [][]string{{"detector", "TP", "FP", "TN", "FN", "precision", "recall", "fires", "exclusive"}}
		for _, d := range e.Detectors {
			rows = append(rows, []string{safe(d.Name),
				fmt.Sprint(d.Counts.TP), fmt.Sprint(d.Counts.FP), fmt.Sprint(d.Counts.TN), fmt.Sprint(d.Counts.FN),
				pct(d.Metrics.Precision), pct(d.Metrics.Recall), fmt.Sprint(d.Fires), fmt.Sprint(d.ExclusiveHits)})
		}
		textTable(b, rows)
	}
	textCaveats(b, e.Caveats)
}

func intactWord(v *bool) string {
	switch {
	case v == nil:
		return "not checked"
	case *v:
		return "every baselined resource matches"
	}
	return "DRIFTED from the baseline"
}

func textSelftest(b *strings.Builder, s *Selftest) {
	textHeader(b, "SELFTEST (detection-content integrity)", s.State)
	textField(b, "Baseline", safe(orDash(s.Manifest)))
	if s.Signature != nil {
		textField(b, "Signature", safe(*s.Signature))
	} else {
		textField(b, "Signature", "n/a")
	}
	textField(b, "Content", intactWord(s.Intact))
	if len(s.Resources) > 0 {
		rows := make([][]string, 0, len(s.Resources))
		for _, r := range s.Resources {
			rows = append(rows, []string{safe(r.Name), safe(r.Path), safe(r.SHA256)})
		}
		textTable(b, rows)
	}
	if len(s.Drift) > 0 {
		b.WriteString("  Drift:\n")
		rows := make([][]string, 0, len(s.Drift))
		for _, d := range s.Drift {
			rows = append(rows, []string{safe(d.Name), safe(d.Reason)})
		}
		textTable(b, rows)
	}
	textCaveats(b, s.Caveats)
}

// ── markdown ─────────────────────────────────────────────────────────────────

func mdCaveats(b *strings.Builder, caveats []string) {
	if len(caveats) == 0 {
		return
	}
	b.WriteString("\nCaveats:\n\n")
	for _, c := range caveats {
		fmt.Fprintf(b, "- %s\n", md(c))
	}
}

func mdTable(b *strings.Builder, header []string, rows [][]string) {
	b.WriteString("\n| " + strings.Join(header, " | ") + " |\n|")
	for range header {
		b.WriteString(" --- |")
	}
	b.WriteString("\n")
	for _, r := range rows {
		b.WriteString("| " + strings.Join(r, " | ") + " |\n")
	}
}

func codeJoin(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = code(s)
	}
	return strings.Join(out, ", ")
}

// WriteMarkdown renders the index as a markdown document.
func WriteMarkdown(w io.Writer, ix *Index) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s honesty index\n\n", md(ix.Tool.Name), md(ix.Tool.Version))
	fmt.Fprintf(&b, "- Schema: %s\n", code(ix.SchemaVersion))
	if ix.Generated != nil {
		fmt.Fprintf(&b, "- Generated: %s\n", code(*ix.Generated))
	} else {
		b.WriteString("- Generated: timestamp suppressed\n")
	}
	b.WriteString("\nThree sections, each with its own state. There is no overall score: " +
		"a gap in one section is not offset by a result in another.\n")
	mdTable(&b, []string{"Section", "State"}, [][]string{
		{"ATT&amp;CK coverage", code(ix.Coverage.State)},
		{"Evaluation", code(ix.Evaluation.State)},
		{"Selftest", code(ix.Selftest.State)},
	})

	mdCoverage(&b, &ix.Coverage)
	mdEvaluation(&b, &ix.Evaluation)
	mdSelftest(&b, &ix.Selftest)

	b.WriteString("\n## Not claimed by this index\n\n")
	for _, n := range ix.NotClaimed {
		fmt.Fprintf(&b, "- %s\n", md(n))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdCoverage(b *strings.Builder, c *Coverage) {
	fmt.Fprintf(b, "\n## ATT&amp;CK coverage\n\nState: %s\n\n", code(c.State))
	if c.TechniquesWithContent == nil {
		b.WriteString("- Techniques with content: not measured\n")
		mdCaveats(b, c.Caveats)
		return
	}
	fmt.Fprintf(b, "- Techniques with content: %s\n", num(c.TechniquesWithContent))
	fmt.Fprintf(b, "- Covered: %s\n", num(c.Covered))
	fmt.Fprintf(b, "- Partial by design: %s", num(c.Partial))
	if len(c.PartialIDs) > 0 {
		b.WriteString(" (" + codeJoin(c.PartialIDs) + ")")
	}
	b.WriteString("\n")
	if c.DeclaredGaps == nil {
		b.WriteString("- Declared gaps: unknown (no expectation to read them from)\n")
	} else {
		fmt.Fprintf(b, "- Declared gaps: %d (%s planned, %s owned by sensor/console)\n",
			len(c.DeclaredGaps), num(c.GapsPlanned), num(c.GapsNone))
	}
	fmt.Fprintf(b, "- Content with no technique: %s entries, never padded with a loose fit\n", num(c.UnmappedContent))
	switch x := c.Expectation; {
	case x == nil:
		b.WriteString("- Expectation: none compared\n")
	case x.Matches:
		fmt.Fprintf(b, "- Expectation: %s (matches)\n", code(x.Path))
	default:
		fmt.Fprintf(b, "- Expectation: %s (**%d difference(s)**)\n", code(x.Path), len(x.Problems))
	}
	if len(c.DeclaredGaps) > 0 {
		b.WriteString("\n### Declared gaps\n")
		rows := make([][]string, 0, len(c.DeclaredGaps))
		for _, g := range c.DeclaredGaps {
			rows = append(rows, []string{code(g.ID), code(g.State), md(g.Name), md(g.Note)})
		}
		mdTable(b, []string{"Technique", "State", "Name", "Note"}, rows)
	}
	if x := c.Expectation; x != nil && len(x.Problems) > 0 {
		b.WriteString("\n### Differences from the expectation\n")
		rows := make([][]string, 0, len(x.Problems))
		for _, p := range x.Problems {
			rows = append(rows, []string{code(p.ID), code(p.Kind), md(p.Text)})
		}
		mdTable(b, []string{"Technique", "Kind", "Detail"}, rows)
	}
	mdCaveats(b, c.Caveats)
}

func mdEvaluation(b *strings.Builder, e *Evaluation) {
	fmt.Fprintf(b, "\n## Evaluation (Phase 1 harness)\n\nState: %s\n\n", code(e.State))
	if e.Report != nil {
		fmt.Fprintf(b, "- Report: %s\n", code(e.Report.Path))
		if e.Report.Generated != "" || e.Report.Tool != "" {
			fmt.Fprintf(b, "- Recorded: %s by %s\n", orDash(code(e.Report.Generated)), orDash(code(e.Report.Tool)))
		}
	}
	if e.Totals == nil {
		b.WriteString("- Precision / recall: not measured\n")
		mdCaveats(b, e.Caveats)
		return
	}
	synthetic := e.CorpusClass != nil && *e.CorpusClass == CorpusSynthetic
	if c := e.Corpus; c != nil {
		fmt.Fprintf(b, "- Corpus: %s (%s)\n", orDash(code(c.Name)), orDash(code(c.Manifest)))
	}
	if e.CorpusClass != nil {
		basis := ""
		if e.CorpusClassBasis != nil {
			basis = md(*e.CorpusClassBasis)
		}
		fmt.Fprintf(b, "- Corpus class: **%s** (%s)\n", md(*e.CorpusClass), basis)
	}
	if s := e.Samples; s != nil {
		fmt.Fprintf(b, "- Samples: %d scored of %d (%d malicious, %d benign), %d error(s), %d skipped\n",
			s.Scored, s.Total, s.Malicious, s.Benign, s.Errors, s.Skipped)
	}
	fmt.Fprintf(b, "- Counts: TP %d, FP %d, TN %d, FN %d\n", e.Totals.TP, e.Totals.FP, e.Totals.TN, e.Totals.FN)
	if m := e.Metrics; m != nil {
		fmt.Fprintf(b, "- Precision: %s\n", pct(m.Precision))
		recall := pct(m.Recall)
		if synthetic {
			recall += " (synthetic corpus: a plumbing check, not a detection rate)"
		}
		fmt.Fprintf(b, "- Recall: %s\n", recall)
		fmt.Fprintf(b, "- False-positive rate: %s\n", pct(m.FalsePositiveRate))
	}
	if len(e.Detectors) > 0 {
		b.WriteString("\n### Per detector\n")
		rows := make([][]string, 0, len(e.Detectors))
		for _, d := range e.Detectors {
			rows = append(rows, []string{code(d.Name),
				fmt.Sprint(d.Counts.TP), fmt.Sprint(d.Counts.FP), fmt.Sprint(d.Counts.TN), fmt.Sprint(d.Counts.FN),
				pct(d.Metrics.Precision), pct(d.Metrics.Recall), fmt.Sprint(d.Fires), fmt.Sprint(d.ExclusiveHits)})
		}
		mdTable(b, []string{"Detector", "TP", "FP", "TN", "FN", "Precision", "Recall", "Fires", "Exclusive"}, rows)
	}
	mdCaveats(b, e.Caveats)
}

func mdSelftest(b *strings.Builder, s *Selftest) {
	fmt.Fprintf(b, "\n## Selftest (detection-content integrity)\n\nState: %s\n\n", code(s.State))
	fmt.Fprintf(b, "- Baseline: %s\n", orDash(code(s.Manifest)))
	if s.Signature != nil {
		fmt.Fprintf(b, "- Signature: %s\n", code(*s.Signature))
	} else {
		b.WriteString("- Signature: n/a\n")
	}
	fmt.Fprintf(b, "- Content: %s\n", intactWord(s.Intact))
	if len(s.Resources) > 0 {
		rows := make([][]string, 0, len(s.Resources))
		for _, r := range s.Resources {
			rows = append(rows, []string{code(r.Name), code(r.Path), code(r.SHA256)})
		}
		mdTable(b, []string{"Resource", "Path", "SHA-256"}, rows)
	}
	if len(s.Drift) > 0 {
		b.WriteString("\n### Drift\n")
		rows := make([][]string, 0, len(s.Drift))
		for _, d := range s.Drift {
			rows = append(rows, []string{code(d.Name), md(d.Reason)})
		}
		mdTable(b, []string{"Resource", "Reason"}, rows)
	}
	mdCaveats(b, s.Caveats)
}

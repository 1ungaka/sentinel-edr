package scanner

import (
	"fmt"

	"github.com/s-b-repo/cau/internal/peeler"
)

// The decode-to-indicator pass. The peeler reveals what a chain hid; this
// asks the detection rules and the heuristic indicators what they make of it.
// A base64-wrapped mimikatz or a PowerShell cradle is caught even when the
// decode is a script and not an executable, which is the case the peeler's own
// "revealed script" verdict deliberately does not flag on its own.
//
// The cost is capped per file, because the leaves are attacker-shaped: at most
// maxLeafRescan leaves, at most maxLeafRescanBytes of leaf bytes in all, and
// at most maxLeafRescanLeafBytes for one leaf. What the cap cut is said in the
// report, so a scan that did not look everywhere says so.
const (
	// maxLeafRescan is how many decoded layers are rescanned per file.
	maxLeafRescan = 8
	// maxLeafRescanBytes is how many leaf bytes are rescanned per file.
	maxLeafRescanBytes = 4 << 20
	// maxLeafRescanLeafBytes is the largest single leaf that is rescanned.
	maxLeafRescanLeafBytes = 1 << 20
)

// rescanLeaves runs the rules and the indicators over the peeler's leaves.
//
// The evidence is attributed to the peel result as peel.rule-match and
// peel.indicator-match: the content only appears after the layers are peeled,
// and that is what the finding says.
func (e *Engine) rescanLeaves(pr *peeler.Result, path string, res *ScanResult) {
	leaves := pr.Leaves
	if len(leaves) > maxLeafRescan {
		leaves = leaves[:maxLeafRescan]
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the decoded layers were not all rescanned: %d of %d leaves were, under the %d leaf cap",
			len(leaves), len(pr.Leaves), maxLeafRescan))
	}
	budget := int64(maxLeafRescanBytes)
	for _, leaf := range leaves {
		if leaf.Terminal != peeler.OutcomeRevealedScript && leaf.Terminal != peeler.OutcomeRevealedExecutable {
			// Only what the peeler took for code is rescanned. A decoded
			// document is not a script, and a rule that matches a document's
			// prose is a false positive about the document, not about the
			// sample.
			continue
		}
		if !leaf.Encoded() {
			// Compression alone is packaging: a gzipped document that
			// mentions a payload is a document, and the peeler's own rule
			// says so. Only a chain with a deliberate encoding or a
			// substitution in it is worth rescanning.
			continue
		}
		if budget <= 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"the decoded layers were not all rescanned: the %d byte rescan budget was spent", maxLeafRescanBytes))
			return
		}
		data := leaf.Data
		if int64(len(data)) > maxLeafRescanLeafBytes {
			data = data[:maxLeafRescanLeafBytes]
		}
		budget -= int64(len(data))
		e.rescanLeaf(pr, path, leaf.Signature, data)
	}
}

// rescanLeaf runs one leaf's content past the rules and the indicators.
func (e *Engine) rescanLeaf(pr *peeler.Result, path, signature string, data []byte) {
	if len(data) == 0 {
		return
	}
	if e.Yara != nil {
		hits, err := e.Yara.ScanMemYara(data)
		if err == nil {
			for _, h := range hits {
				f := peeler.Finding{
					Class: "peel.rule-match",
					// A rule match is the shipped content saying the decoded
					// layer is malware-like, and it flags on its own: a
					// base64-wrapped script that trips a rule is the case
					// this pass exists for.
					Score:  60,
					Detail: fmt.Sprintf("rule %s matched the layer decoded through %s", h.RuleName, signature),
				}
				if tech := h.MetaString("mitre_attack"); tech != "" {
					f.Technique = tech
				} else if tech := h.MetaString("technique"); tech != "" {
					f.Technique = tech
				}
				pr.AddEvidence(f)
			}
		}
	}
	if e.Heuristics {
		hr := ScanHeuristicsData(path, data, HeuristicOptions{Threshold: e.threshold()})
		if hr.Detected() {
			pr.AddEvidence(peeler.Finding{
				Class:  "peel.indicator-match",
				Score:  25,
				Detail: fmt.Sprintf("a heuristic indicator matched the layer decoded through %s", signature),
			})
		}
	}
}

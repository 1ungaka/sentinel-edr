// Package scannerbridge adapts the CAU EDR scanner to the eval.Detector
// interface. It is the only place where the evaluation harness and the
// scanner meet: internal/eval stays standard-library-only, and the scanner
// never learns about corpora or metrics.
package scannerbridge

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cau-edr/cau/internal/eval"
	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// HashDetector wraps the signature database. It is not configured when db is
// nil or empty: a hash detector with nothing to match would silently score
// zero recall.
func HashDetector(db *scanner.SignatureDB) eval.Detector {
	return hashDetector{db: db}
}

type hashDetector struct{ db *scanner.SignatureDB }

func (hashDetector) Name() string { return eval.DetectorHash }

func (d hashDetector) ScanFile(path string) (eval.Finding, error) {
	if d.db == nil || d.db.Count() == 0 {
		return eval.Finding{Path: path, Verdict: eval.VerdictError}, fmt.Errorf("%w: hash detector has no signatures", eval.ErrNotConfigured)
	}
	start := time.Now()
	r := scanner.ScanFile(path, d.db, nil)
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if r.Error != nil {
		f.Verdict = eval.VerdictError
		f.Err = r.Error
		return f, r.Error
	}
	if r.Detected {
		f.Verdict = eval.VerdictMalicious
		f.Signals = []eval.Signal{{
			Detector: eval.DetectorHash,
			Rule:     r.ThreatName,
			Family:   familyFromThreatName(r.ThreatName),
			Detail:   strings.ToLower(r.MatchType) + ":" + r.MatchHash,
		}}
	}
	return f, nil
}

// familyFromThreatName derives a family label from a signature's threat name
// ("WannaCry Ransomware" -> "wannacry"): the first word, lowercased.
func familyFromThreatName(name string) string {
	fields := strings.Fields(strings.ToLower(name))
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "/-_.")
}

// YaraDetector wraps a compiled ruleset. The scanner is shared, so the caller
// keeps ownership and closes it after the run.
func YaraDetector(ys *scanner.YaraScanner) eval.Detector {
	return yaraDetector{ys: ys}
}

type yaraDetector struct{ ys *scanner.YaraScanner }

func (yaraDetector) Name() string { return eval.DetectorYara }

func (d yaraDetector) ScanFile(path string) (eval.Finding, error) {
	if d.ys == nil || d.ys.RuleCount() == 0 {
		return eval.Finding{Path: path, Verdict: eval.VerdictError}, fmt.Errorf("%w: yara detector has no rules", eval.ErrNotConfigured)
	}
	start := time.Now()
	matches, err := d.ys.ScanFileYaraStrict(path)
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	for _, m := range matches {
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorYara,
			Rule:     ruleName(m),
			Family:   strings.ToLower(m.MetaString("family")),
			Detail:   yaraDetail(m),
		})
	}
	if len(f.Signals) > 0 {
		f.Verdict = eval.VerdictMalicious
	}
	if err != nil {
		f.Err = err
		if len(f.Signals) == 0 {
			f.Verdict = eval.VerdictError
			return f, err
		}
		// Partial scan with detections: keep them, surface the error.
	}
	return f, nil
}

func ruleName(m scanner.YaraMatch) string {
	if m.Namespace != "" && m.Namespace != "default" {
		return m.Namespace + "/" + m.RuleName
	}
	return m.RuleName
}

func yaraDetail(m scanner.YaraMatch) string {
	var parts []string
	if len(m.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(m.Tags, ","))
	}
	if tl := m.MetaString("threat_level"); tl != "" {
		parts = append(parts, "threat_level="+tl)
	}
	parts = append(parts, fmt.Sprintf("strings=%d", len(m.Strings)))
	return strings.Join(parts, " ")
}

// HeuristicDetector wraps the string/API heuristics. It fires only when the
// score reaches threshold, exactly like the CLI; a threshold <= 0 uses the
// scanner's own default.
func HeuristicDetector(threshold int) eval.Detector {
	if threshold <= 0 {
		threshold = scanner.HeuristicThreshold
	}
	return heuristicDetector{threshold: threshold}
}

type heuristicDetector struct{ threshold int }

func (heuristicDetector) Name() string { return eval.DetectorHeuristic }

func (d heuristicDetector) ScanFile(path string) (eval.Finding, error) {
	start := time.Now()
	h := scanner.ScanHeuristics(path)
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if h.Error != nil {
		f.Verdict = eval.VerdictError
		f.Err = h.Error
		return f, h.Error
	}
	f.Scores = []eval.DetectorScore{{Detector: eval.DetectorHeuristic, Score: h.Score, Threshold: d.threshold}}
	if h.Score < d.threshold {
		return f, nil
	}
	f.Verdict = eval.VerdictSuspicious
	f.Signals = []eval.Signal{{
		Detector: eval.DetectorHeuristic,
		Rule:     "heuristic/score",
		Detail:   fmt.Sprintf("score %d/threshold %d; %s", h.Score, d.threshold, topCategories(h.Matches, 3)),
	}}
	for _, c := range categoryList(h.Matches) {
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorHeuristic,
			Rule:     "heuristic/" + slug(c),
			Detail:   c,
		})
	}
	return f, nil
}

func categoryList(ms []scanner.HeuristicMatch) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if !seen[m.Category] {
			seen[m.Category] = true
			out = append(out, m.Category)
		}
	}
	sort.Strings(out)
	return out
}

func topCategories(ms []scanner.HeuristicMatch, n int) string {
	count := map[string]int{}
	for _, m := range ms {
		count[m.Category]++
	}
	cats := make([]string, 0, len(count))
	for c := range count {
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool {
		if count[cats[i]] != count[cats[j]] {
			return count[cats[i]] > count[cats[j]]
		}
		return cats[i] < cats[j]
	})
	if len(cats) > n {
		cats = cats[:n]
	}
	parts := make([]string, 0, len(cats))
	for _, c := range cats {
		parts = append(parts, fmt.Sprintf("%s(%d)", c, count[c]))
	}
	return strings.Join(parts, " ")
}

func slug(s string) string {
	var b strings.Builder
	last := '-'
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			last = r
		default:
			if last != '-' {
				b.WriteRune('-')
				last = '-'
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// StaticDetector wraps the structural analysis (entropy, fuzzy hashes, PE
// anatomy). It fires when the static score reaches threshold; a threshold
// <= 0 uses the package default. db may be nil (no similarity lookups).
//
// Signals: one "static/score" summary, one "static/<class>" per scored
// anomaly so per-rule metrics can show which structural class carries the
// recall, and one "static/fuzzy/<type>" per similarity match carrying the
// matched threat as the family.
func StaticDetector(threshold int, db *static.FuzzyDB) eval.Detector {
	if threshold <= 0 {
		threshold = static.Threshold
	}
	return staticDetector{threshold: threshold, db: db}
}

type staticDetector struct {
	threshold int
	db        *static.FuzzyDB
}

func (staticDetector) Name() string { return eval.DetectorStatic }

func (d staticDetector) ScanFile(path string) (eval.Finding, error) {
	start := time.Now()
	r := static.AnalyzeFile(path, static.Options{Threshold: d.threshold, FuzzyDB: d.db})
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if r.Error != nil {
		f.Verdict = eval.VerdictError
		f.Err = r.Error
		return f, r.Error
	}
	if r.Skipped == "" {
		f.Scores = []eval.DetectorScore{{Detector: eval.DetectorStatic, Score: r.Score, Threshold: d.threshold}}
	}
	if r.Skipped != "" || r.Score < d.threshold {
		return f, nil
	}
	f.Verdict = eval.VerdictSuspicious
	var top []string
	for _, cs := range r.Categories {
		if cs.Applied > 0 && len(top) < 3 {
			top = append(top, fmt.Sprintf("%s(%d)", cs.Category, cs.Applied))
		}
	}
	f.Signals = []eval.Signal{{
		Detector: eval.DetectorStatic,
		Rule:     "static/score",
		Detail:   fmt.Sprintf("score %d/threshold %d; %s", r.Score, d.threshold, strings.Join(top, " ")),
	}}
	for _, a := range r.Anomalies {
		if a.Score == 0 {
			continue
		}
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorStatic,
			Rule:     "static/" + a.Class,
			Detail:   a.Detail,
		})
	}
	for _, m := range r.FuzzyMatches {
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorStatic,
			Rule:     "static/fuzzy/" + strings.ToLower(m.Type),
			Family:   familyFromThreatName(m.ThreatName),
			Detail:   fmt.Sprintf("%s distance=%d score=%d", m.ThreatName, m.Distance, m.Score),
		})
	}
	return f, nil
}

// Engine returns the full detector set the CLI runs. Nil db disables the
// hash detector, nil ys disables YARA, heuristicThreshold < 0 disables the
// heuristics (0 means the scanner default).
func Engine(db *scanner.SignatureDB, ys *scanner.YaraScanner, heuristicThreshold int) []eval.Detector {
	var out []eval.Detector
	if db != nil {
		out = append(out, HashDetector(db))
	}
	if ys != nil {
		out = append(out, YaraDetector(ys))
	}
	if heuristicThreshold >= 0 {
		out = append(out, HeuristicDetector(heuristicThreshold))
	}
	return out
}

// StegoDetector wraps the invisible-codepoint detector for text and code
// artifacts. It fires when the stego score reaches threshold (presence-based
// at the default); a threshold <= 0 uses the package default.
//
// Signals: one "stego/score" summary and one "stego/<class>" per scored
// finding, so per-rule metrics show whether zero-width carriers or bidi
// controls carry the recall.
func StegoDetector(threshold int) eval.Detector {
	if threshold <= 0 {
		threshold = stego.Threshold
	}
	return stegoDetector{threshold: threshold}
}

type stegoDetector struct{ threshold int }

func (stegoDetector) Name() string { return eval.DetectorStego }

func (d stegoDetector) ScanFile(path string) (eval.Finding, error) {
	start := time.Now()
	r := stego.ScanFile(path, stego.Options{Threshold: d.threshold})
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if r.Error != nil {
		f.Verdict = eval.VerdictError
		f.Err = r.Error
		return f, r.Error
	}
	if r.Skipped == "" {
		f.Scores = []eval.DetectorScore{{Detector: eval.DetectorStego, Score: r.Score, Threshold: d.threshold}}
	}
	if r.Skipped != "" || r.Score < d.threshold {
		return f, nil
	}
	f.Verdict = eval.VerdictSuspicious
	f.Signals = []eval.Signal{{
		Detector: eval.DetectorStego,
		Rule:     "stego/score",
		Detail:   fmt.Sprintf("score %d/threshold %d; %d scored, %d excused, run %d", r.Score, d.threshold, r.Suspicious, r.Benign, r.LongestRun),
	}}
	for _, fd := range r.Findings {
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorStego,
			Rule:     "stego/" + strings.TrimPrefix(fd.Class, "stego."),
			Detail:   fd.Detail,
		})
	}
	return f, nil
}

// EncChainDetector wraps the encoded-executable detector (base64/hex layers
// decoding to a PE/ELF header). It fires when the score reaches threshold.
func EncChainDetector(threshold int) eval.Detector {
	if threshold <= 0 {
		threshold = encchain.Threshold
	}
	return encChainDetector{threshold: threshold}
}

type encChainDetector struct{ threshold int }

func (encChainDetector) Name() string { return eval.DetectorEncChain }

func (d encChainDetector) ScanFile(path string) (eval.Finding, error) {
	start := time.Now()
	r := encchain.ScanFile(path, encchain.Options{Threshold: d.threshold})
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if r.Skipped == "" {
		f.Scores = []eval.DetectorScore{{Detector: eval.DetectorEncChain, Score: r.Score, Threshold: d.threshold}}
	}
	if r.Skipped != "" || r.Score < d.threshold {
		return f, nil
	}
	f.Verdict = eval.VerdictSuspicious
	f.Signals = []eval.Signal{{Detector: eval.DetectorEncChain, Rule: "encchain/score",
		Detail: fmt.Sprintf("score %d/threshold %d; %d candidate(s), %d layer(s) peeled", r.Score, d.threshold, r.Candidates, r.LayersPeeled)}}
	for _, fd := range r.Findings {
		f.Signals = append(f.Signals, eval.Signal{Detector: eval.DetectorEncChain,
			Rule: "encchain/" + strings.TrimPrefix(fd.Class, "encchain."), Detail: fd.Detail})
	}
	return f, nil
}

// FusionDetector runs the whole engine and fires only when the fusion
// lattice reaches the suspicious tier by corroboration: no single detector
// crossed its own threshold. The detections it reports are therefore
// exactly the ones fusion adds on top of the other detectors, which is the
// number the plan asks every improvement to publish.
//
// The engine is shared and must be fully configured by the caller (hash
// database, YARA, heuristics, static, stego); its own per-detector verdicts
// are not reported here, the individual detectors do that.
func FusionDetector(e *scanner.Engine) eval.Detector {
	return fusionDetector{e: e}
}

type fusionDetector struct{ e *scanner.Engine }

func (fusionDetector) Name() string { return eval.DetectorFusion }

func (d fusionDetector) ScanFile(path string) (eval.Finding, error) {
	if d.e == nil {
		return eval.Finding{Path: path, Verdict: eval.VerdictError}, fmt.Errorf("%w: fusion detector has no engine", eval.ErrNotConfigured)
	}
	start := time.Now()
	r, _ := d.e.ScanFile(path)
	f := eval.Finding{Path: path, Verdict: eval.VerdictClean, Duration: time.Since(start)}
	if r.Error != nil {
		f.Verdict = eval.VerdictError
		f.Err = r.Error
		return f, r.Error
	}
	v := r.Fusion
	if v == nil || !v.Corroborated || !v.Detected() {
		return f, nil
	}
	f.Verdict = eval.VerdictSuspicious
	f.Signals = []eval.Signal{{
		Detector: eval.DetectorFusion,
		Rule:     "fusion/corroborated",
		Detail:   v.Explanation,
	}}
	for _, s := range v.Sources {
		if !s.Counted {
			continue
		}
		f.Signals = append(f.Signals, eval.Signal{
			Detector: eval.DetectorFusion,
			Rule:     "fusion/agreed/" + s.Name,
			Detail:   fmt.Sprintf("%d/%d ratio %.2f (%s)", s.Score, s.Threshold, s.Ratio, s.Role),
		})
	}
	return f, nil
}

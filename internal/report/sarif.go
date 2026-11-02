package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/fusion"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/stego"
)

// SARIF 2.1.0 constants.
const (
	SARIFSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	SARIFVersion = "2.1.0"
	// SARIFSrcRoot is the uriBaseId used for paths relative to WithRoot.
	SARIFSrcRoot = "%SRCROOT%"

	// Fixed rule ids. Hash and YARA rules are derived per finding.
	SARIFRuleHeuristic = "heuristic/score"
	SARIFRuleStatic    = "static/score"
	SARIFRuleScanError = "scan/error"
	// SARIFRuleFusion is the corroborated-only fused verdict.
	SARIFRuleFusion = "fusion/corroborated"
	// SARIFRuleStegoPrefix prefixes one rule per scored stego class
	// ("stego/zero-width", "stego/bidi-control", ...).
	SARIFRuleStegoPrefix    = "stego/"
	SARIFRuleEncChainPrefix = "encchain/"
	// SARIFRuleLNKPrefix prefixes one rule per Shell Link class
	// ("lnk/command.powershell", "lnk/obfuscation.encoded", ...).
	SARIFRuleLNKPrefix = "lnk/"
	// SARIFRuleOLEPrefix prefixes one rule per OLE macro class
	// ("ole/vba.autoexec", "ole/exec.powershell", ...).
	SARIFRuleOLEPrefix = "ole/"
	// SARIFRulePDFPrefix prefixes one rule per PDF class
	// ("pdf/action.openaction", "pdf/javascript", ...).
	SARIFRulePDFPrefix = "pdf/"
	// SARIFRuleISOPrefix prefixes one rule per ISO class
	// ("iso/lure.lnk-and-payload", "iso/autorun.inf", ...).
	SARIFRuleISOPrefix = "iso/"
)

// ── SARIF object model (only the subset the reporter emits) ──────────────────

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                   `json:"tool"`
	Invocations        []sarifInvocation           `json:"invocations"`
	OriginalURIBaseIDs map[string]sarifArtifactLoc `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult               `json:"results"`
	Properties         map[string]interface{}      `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	ShortDescription *sarifMessage          `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage          `json:"fullDescription,omitempty"`
	DefaultConfig    *sarifRuleConfig       `json:"defaultConfiguration,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ExitCode                   int                 `json:"exitCode"`
	ExitCodeDescription        string              `json:"exitCodeDescription,omitempty"`
	EndTimeUTC                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifMessage           `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           *sarifRegion     `json:"region,omitempty"`
}

type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine  int           `json:"startLine,omitempty"`
	ByteOffset int64         `json:"byteOffset"`
	ByteLength int           `json:"byteLength"`
	Snippet    *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text   string `json:"text,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// SARIFReporter writes a SARIF 2.1.0 log.
type SARIFReporter struct {
	cfg config
}

// NewSARIFReporter builds a reporter from the shared options.
func NewSARIFReporter(opts ...Option) *SARIFReporter {
	return &SARIFReporter{cfg: buildConfig(opts)}
}

// Write encodes the log to w.
func (r *SARIFReporter) Write(w io.Writer, in Input) error {
	log := r.build(in)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if r.cfg.indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("report: encode sarif: %w", err)
	}
	return nil
}

// ruleTable assigns a stable index to every rule id. Rules are sorted so the
// table (and therefore every ruleIndex) does not depend on scan order.
type ruleTable struct {
	rules []sarifRule
	index map[string]int
}

func (t *ruleTable) add(rule sarifRule) {
	if t.index == nil {
		t.index = make(map[string]int)
	}
	if _, ok := t.index[rule.ID]; ok {
		return
	}
	t.index[rule.ID] = len(t.rules)
	t.rules = append(t.rules, rule)
}

func (t *ruleTable) sorted() {
	sort.SliceStable(t.rules, func(i, j int) bool { return t.rules[i].ID < t.rules[j].ID })
	for i, r := range t.rules {
		t.index[r.ID] = i
	}
}

func (r *SARIFReporter) build(in Input) sarifLog {
	c := r.cfg
	policy := &ExitPolicy{cfg: c}
	code, reason := policy.decide(in)

	// ── pass 1: rules ──
	var table ruleTable
	for _, res := range in.Results {
		if res.Detected {
			table.add(c.hashRule(res))
		}
		for _, m := range res.YaraMatches {
			table.add(c.yaraRule(m))
		}
	}
	if c.sarifIncludeHeuristics && len(in.HeuristicBreach(c.heuristicThreshold)) > 0 {
		table.add(sarifRule{
			ID:               SARIFRuleHeuristic,
			Name:             "HeuristicScore",
			ShortDescription: &sarifMessage{Text: "String and API heuristic score reached the alert threshold"},
			FullDescription: &sarifMessage{Text: fmt.Sprintf(
				"The file's imported APIs and embedded strings scored at or above the heuristic threshold (%d). "+
					"This is evidence of suspicious capability, not a confirmed detection.", c.heuristicThreshold)},
			DefaultConfig: &sarifRuleConfig{Level: c.levelHeuristic},
			Properties:    map[string]interface{}{"threshold": c.heuristicThreshold},
		})
	}
	if c.sarifIncludeHeuristics && len(in.StaticBreach(c.staticThreshold)) > 0 {
		table.add(sarifRule{
			ID:               SARIFRuleStatic,
			Name:             "StaticStructureScore",
			ShortDescription: &sarifMessage{Text: "Structural (static) anomaly score reached the alert threshold"},
			FullDescription: &sarifMessage{Text: fmt.Sprintf(
				"The file's structure (packing, section layout, entry point, build record, signature chain, appended data, "+
					"or similarity to a known sample) scored at or above the static threshold (%d). "+
					"This is evidence that the content is hiding or resembles known content, not a confirmed detection.", c.staticThreshold)},
			DefaultConfig: &sarifRuleConfig{Level: c.levelHeuristic},
			Properties:    map[string]interface{}{"threshold": c.staticThreshold},
		})
	}
	if c.sarifIncludeHeuristics {
		for _, res := range in.Results {
			if !stegoBreached(res.Stego, c.stegoThreshold) {
				continue
			}
			for _, f := range res.Stego.Findings {
				if rule, ok := c.stegoRule(f); ok {
					table.add(rule)
				}
			}
		}
		for _, res := range in.Results {
			if !encChainBreached(res.EncChain, c.encChainThreshold) {
				continue
			}
			for _, f := range res.EncChain.Findings {
				table.add(c.encChainRule(f))
			}
		}
		for _, res := range in.Results {
			if !lnkBreached(res.LNK, c.lnkThreshold) {
				continue
			}
			for _, f := range res.LNK.Findings {
				table.add(c.lnkRule(f))
			}
		}
		for _, res := range in.Results {
			if !oleBreached(res.OLE, c.oleThreshold) {
				continue
			}
			for _, f := range res.OLE.Findings {
				table.add(c.oleRule(f))
			}
		}
		for _, res := range in.Results {
			if !pdfBreached(res.PDF, c.pdfThreshold) {
				continue
			}
			for _, f := range res.PDF.Findings {
				table.add(c.pdfRule(f))
			}
		}
		for _, res := range in.Results {
			if !isoBreached(res.ISO, c.isoThreshold) {
				continue
			}
			for _, f := range res.ISO.Findings {
				table.add(c.isoRule(f))
			}
		}
		if len(in.FusionCorroborated()) > 0 {
			table.add(sarifRule{
				ID:               SARIFRuleFusion,
				Name:             "FusionCorroborated",
				ShortDescription: &sarifMessage{Text: "Independent detectors below their own thresholds corroborated each other"},
				FullDescription: &sarifMessage{Text: fmt.Sprintf(
					"No single detector crossed its threshold, but the fused score of several independent sources reached %.2f. "+
						"The result names which sources agreed and the techniques their evidence carries. "+
						"This is evidence of suspicious capability from more than one angle, not a confirmed detection.", fusion.Default.Threshold)},
				DefaultConfig: &sarifRuleConfig{Level: c.levelHeuristic},
				Properties:    map[string]interface{}{"threshold": fusion.Default.Threshold, "floor": fusion.Default.Floor, "weight": fusion.Default.Weight},
			})
		}
	}
	if c.sarifIncludeScanErrors && in.FileErrorCount() > 0 {
		table.add(sarifRule{
			ID:               SARIFRuleScanError,
			Name:             "ScanError",
			ShortDescription: &sarifMessage{Text: "The engine could not scan this file"},
			FullDescription:  &sarifMessage{Text: "An unscanned artifact is a coverage gap, not a clean bill of health."},
			DefaultConfig:    &sarifRuleConfig{Level: c.levelScanError},
		})
	}
	table.sorted()

	// ── pass 2: results ──
	results := []sarifResult{}
	byPath := in.HeuristicsByPath()
	seenHeur := make(map[string]bool)

	for _, res := range in.Results {
		loc := c.location(res.FilePath, nil)

		if res.Detected {
			rule := c.hashRule(res)
			results = append(results, sarifResult{
				RuleID:    rule.ID,
				RuleIndex: table.index[rule.ID],
				Level:     c.levelHash,
				Message: sarifMessage{Text: c.boundedMessage(fmt.Sprintf(
					"%s signature match: %s (%s)", res.MatchType, res.ThreatName, res.MatchHash))},
				Locations:           []sarifLocation{loc},
				PartialFingerprints: c.fingerprints(res),
				Properties: map[string]interface{}{
					"hashType": c.boundedMessage(res.MatchType),
					"hash":     c.boundedHash(res.MatchHash),
					"threat":   c.boundedMessage(res.ThreatName),
				},
			})
		}

		for _, m := range res.YaraMatches {
			rule := c.yaraRule(m)
			locs := make([]sarifLocation, 0, len(m.Strings))
			for _, s := range m.Strings {
				locs = append(locs, c.location(res.FilePath, &s))
			}
			if len(locs) == 0 {
				locs = append(locs, loc)
			}
			text := fmt.Sprintf("YARA rule %s::%s matched", m.Namespace, m.RuleName)
			if d := m.MetaString("description"); d != "" {
				text += ": " + d
			}
			if len(m.Strings) > 0 {
				text += fmt.Sprintf(" (%d string(s))", len(m.Strings))
			}
			props := map[string]interface{}{
				"rule":      c.boundedMessage(m.RuleName),
				"namespace": c.boundedMessage(m.Namespace),
			}
			if len(m.Tags) > 0 {
				props["tags"] = boundedList(c, m.Tags)
			}
			if tl, ok := m.MetaInt("threat_level"); ok {
				props["threat_level"] = tl
			}
			results = append(results, sarifResult{
				RuleID:              rule.ID,
				RuleIndex:           table.index[rule.ID],
				Level:               c.levelYara,
				Message:             sarifMessage{Text: c.boundedMessage(text)},
				Locations:           locs,
				PartialFingerprints: c.fingerprints(res),
				Properties:          props,
			})
		}

		if res.Error != nil && c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("scan failed: " + res.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}

		if h, ok := byPath[res.FilePath]; ok && !seenHeur[res.FilePath] {
			seenHeur[res.FilePath] = true
			results = c.appendHeuristic(results, &table, h)
		}
		if res.Static != nil {
			results = c.appendStatic(results, &table, res)
		}
		if res.Stego != nil {
			results = c.appendStego(results, &table, res)
		}
		if res.EncChain != nil {
			results = c.appendEncChain(results, &table, res)
		}
		if res.LNK != nil {
			results = c.appendLNK(results, &table, res)
		}
		if res.OLE != nil {
			results = c.appendOLE(results, &table, res)
		}
		if res.PDF != nil {
			results = c.appendPDF(results, &table, res)
		}
		if res.ISO != nil {
			results = c.appendISO(results, &table, res)
		}
		if res.Fusion != nil {
			results = c.appendFusion(results, &table, res)
		}
	}

	// Heuristic-only paths (no ScanResult), in the sorted tail order AllPaths
	// produces.
	for _, p := range in.AllPaths() {
		if seenHeur[p] {
			continue
		}
		if h, ok := byPath[p]; ok {
			seenHeur[p] = true
			results = c.appendHeuristic(results, &table, h)
		}
	}

	// ── invocation ──
	inv := sarifInvocation{
		ExecutionSuccessful: in.RunError == nil,
		ExitCode:            code,
		ExitCodeDescription: reason,
		EndTimeUTC:          c.timestamp(),
	}
	if in.RunError != nil {
		inv.ToolExecutionNotifications = []sarifNotification{{
			Level:   LevelError,
			Message: sarifMessage{Text: c.errorString(in.RunError)},
		}}
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           c.toolName,
			Version:        c.toolVersion,
			InformationURI: c.informationURI,
			Rules:          table.rules,
		}},
		Invocations: []sarifInvocation{inv},
		Results:     results,
		Properties: map[string]interface{}{
			"filesScanned":        len(in.AllPaths()),
			"hashDetections":      in.HashDetectionCount(),
			"yaraDetections":      in.YaraDetectionCount(),
			"heuristicDetections": len(in.HeuristicBreach(c.heuristicThreshold)),
			"staticDetections":    len(in.StaticBreach(c.staticThreshold)),
			"stegoDetections":     len(in.StegoBreach(c.stegoThreshold)),
			"fusionDetections":    len(in.FusionCorroborated()),
			"errors":              in.ErrorCount(),
			"elapsedMs":           in.Elapsed.Milliseconds(),
			"failOn":              c.failOn.String(),
		},
	}
	if base := rootURI(c.root); base != "" {
		run.OriginalURIBaseIDs = map[string]sarifArtifactLoc{SARIFSrcRoot: {URI: base}}
	}
	if table.rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}

	return sarifLog{Schema: SARIFSchema, Version: SARIFVersion, Runs: []sarifRun{run}}
}

func (c config) appendHeuristic(results []sarifResult, table *ruleTable, h scanner.HeuristicResult) []sarifResult {
	loc := c.location(h.FilePath, nil)
	if h.Error != nil {
		if c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("heuristics failed: " + h.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}
		return results
	}
	if !c.sarifIncludeHeuristics || !heuristicBreached(h, c.heuristicThreshold) {
		return results
	}

	threshold := thresholdFor(h, c.heuristicThreshold)
	cats := categories(h)
	text := fmt.Sprintf("heuristic score %d reached threshold %d", h.Score, threshold)
	if len(cats) > 0 {
		text += ": " + strings.Join(cats, ", ")
	}
	indicators := make([]map[string]interface{}, 0, len(h.Matches))
	for _, m := range h.Matches {
		ind := map[string]interface{}{
			"indicator": c.boundedMessage(m.Indicator),
			"category":  c.boundedMessage(m.Category),
			"source":    c.boundedMessage(m.Source),
		}
		if m.Score != 0 {
			ind["score"] = m.Score
		}
		if m.Hits > 1 {
			ind["hits"] = m.Hits
		}
		indicators = append(indicators, ind)
	}
	return append(results, sarifResult{
		RuleID:    SARIFRuleHeuristic,
		RuleIndex: table.index[SARIFRuleHeuristic],
		Level:     c.levelHeuristic,
		Message:   sarifMessage{Text: c.boundedMessage(text)},
		Locations: []sarifLocation{loc},
		Properties: map[string]interface{}{
			"score":      h.Score,
			"threshold":  threshold,
			"indicators": indicators,
		},
	})
}

func (c config) appendStatic(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	s := res.Static
	loc := c.location(res.FilePath, nil)
	if s.Error != nil {
		if c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("static analysis failed: " + s.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}
		return results
	}
	if !c.sarifIncludeHeuristics || !staticBreached(s, c.staticThreshold) {
		return results
	}
	threshold := staticThresholdFor(s, c.staticThreshold)
	var classes []string
	anomalies := make([]map[string]interface{}, 0, len(s.Anomalies))
	for _, a := range s.Anomalies {
		if a.Score == 0 {
			continue
		}
		classes = append(classes, c.boundedMessage(a.Class))
		m := map[string]interface{}{
			"class":    c.boundedMessage(a.Class),
			"category": c.boundedMessage(a.Category),
			"score":    a.Score,
			"detail":   c.boundedMessage(a.Detail),
		}
		if a.Technique != "" {
			m["technique"] = c.boundedMessage(a.Technique)
		}
		anomalies = append(anomalies, m)
	}
	text := fmt.Sprintf("static score %d reached threshold %d", s.Score, threshold)
	if len(classes) > 0 {
		text += ": " + strings.Join(classes, ", ")
	}
	props := map[string]interface{}{
		"score":     s.Score,
		"threshold": threshold,
		"anomalies": anomalies,
	}
	if p := s.PE; p != nil {
		props["imphash"] = c.boundedHash(p.Imphash)
		if p.Packer != nil {
			props["packer"] = c.boundedMessage(p.Packer.Name)
		}
	}
	if e := s.ELF; e != nil {
		if e.ImportHash != "" {
			props["import_hash"] = c.boundedHash(e.ImportHash)
		}
		if e.Packer != nil {
			props["packer"] = c.boundedMessage(e.Packer.Name)
		}
		if e.Interp != "" {
			props["interp"] = c.boundedMessage(e.Interp)
		}
	}
	if s.Fuzzy.TLSH != "" {
		props["tlsh"] = c.boundedHash(s.Fuzzy.TLSH)
	}
	return append(results, sarifResult{
		RuleID:              SARIFRuleStatic,
		RuleIndex:           table.index[SARIFRuleStatic],
		Level:               c.levelHeuristic,
		Message:             sarifMessage{Text: c.boundedMessage(text)},
		Locations:           []sarifLocation{loc},
		PartialFingerprints: c.fingerprints(res),
		Properties:          props,
	})
}

// stegoRule builds the rule for one scored stego class. Modifier findings
// (payload run, ASCII carrier) are not rules of their own; they ride along
// as properties of the class result.
func (c config) stegoRule(f stego.Finding) (sarifRule, bool) {
	class := strings.TrimPrefix(f.Class, "stego.")
	var short, full string
	switch class {
	case stego.ClassZeroWidth:
		short, full = "Zero-width codepoints in a text or code artifact",
			"Zero-width codepoints (ZERO WIDTH SPACE, JOINER, NON-JOINER, WORD JOINER, ...) occur where no script or emoji sequence needs them. This is the carrier alphabet of zero-width steganography: README dead-drop command channels and payloads hidden between the words of a comment."
	case stego.ClassBidiControl:
		short, full = "Bidirectional override controls in a text or code artifact",
			"Explicit directional embeddings, overrides or isolates reorder how source code is displayed versus how it is compiled (Trojan Source, CVE-2021-42574)."
	case stego.ClassTag:
		short, full = "Unicode TAG characters in a text or code artifact",
			"TAG characters are invisible copies of ASCII used to smuggle instructions past filters and into language models."
	case stego.ClassVariationSelector:
		short, full = "Variation selectors without a base character",
			"Variation selectors following a character that takes none, or several in a row, encode data (one of 256 invisible values per selector)."
	default:
		return sarifRule{}, false
	}
	props := map[string]interface{}{"kind": "stego", "class": class}
	if f.Technique != "" {
		props["technique"] = f.Technique
	}
	if f.Novel != "" {
		props["novel"] = f.Novel
	}
	return sarifRule{
		ID:               SARIFRuleStegoPrefix + class,
		Name:             "InvisibleCodepoints",
		ShortDescription: &sarifMessage{Text: short},
		FullDescription:  &sarifMessage{Text: full},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       props,
	}, true
}

func (c config) appendStego(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	s := res.Stego
	loc := c.location(res.FilePath, nil)
	if s.Error != nil {
		if c.sarifIncludeScanErrors {
			results = append(results, sarifResult{
				RuleID:    SARIFRuleScanError,
				RuleIndex: table.index[SARIFRuleScanError],
				Level:     c.levelScanError,
				Message:   sarifMessage{Text: c.boundedMessage("stego analysis failed: " + s.Error.Error())},
				Locations: []sarifLocation{loc},
			})
		}
		return results
	}
	if !c.sarifIncludeHeuristics || !stegoBreached(s, c.stegoThreshold) {
		return results
	}
	var modifiers []map[string]interface{}
	for _, f := range s.Findings {
		if _, isClass := c.stegoRule(f); !isClass {
			modifiers = append(modifiers, map[string]interface{}{"class": c.boundedMessage(f.Class), "score": f.Score, "detail": c.boundedMessage(f.Detail)})
		}
	}
	unit := 1
	switch s.Encoding {
	case "utf-16le", "utf-16be":
		unit = 2
	}
	for _, f := range s.Findings {
		rule, ok := c.stegoRule(f)
		if !ok {
			continue
		}
		class := strings.TrimPrefix(f.Class, "stego.")
		var cps []map[string]interface{}
		region := (*sarifRegion)(nil)
		for _, cp := range s.Codepoints {
			if cp.Class != class || cp.Count-cp.Benign == 0 {
				continue
			}
			m := map[string]interface{}{
				"codepoint": c.boundedMessage(cp.Code), "name": c.boundedMessage(cp.Name),
				"count": cp.Count - cp.Benign, "firstLine": cp.FirstLine, "firstOffset": cp.FirstOffset,
			}
			if cp.Benign > 0 {
				m["benignContext"] = cp.Benign
			}
			if len(cp.Examples) > 0 {
				m["examples"] = boundedList(c, cp.Examples)
			}
			cps = append(cps, m)
			if region == nil || cp.FirstOffset < int(region.ByteOffset) {
				n := len(string(cp.Rune))
				if unit == 2 {
					n = 2
					if cp.Rune > 0xFFFF {
						n = 4
					}
				}
				region = &sarifRegion{StartLine: cp.FirstLine, ByteOffset: int64(cp.FirstOffset), ByteLength: n}
			}
		}
		l := loc
		if region != nil {
			l.PhysicalLocation.Region = region
		}
		props := map[string]interface{}{
			"score":      s.Score,
			"threshold":  stegoThresholdFor(s, c.stegoThreshold),
			"classScore": f.Score,
			"encoding":   c.boundedMessage(s.Encoding),
			"suspicious": s.Suspicious,
			"benign":     s.Benign,
			"longestRun": s.LongestRun,
			"codepoints": cps,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Novel != "" {
			props["novel"] = f.Novel
		}
		if len(modifiers) > 0 {
			props["modifiers"] = modifiers
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(strings.TrimPrefix(f.Class, "stego.") + ": " + f.Detail)},
			Locations:           []sarifLocation{l},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) encChainRule(f encchain.Finding) sarifRule {
	class := strings.TrimPrefix(f.Class, "encchain.")
	return sarifRule{
		ID:               SARIFRuleEncChainPrefix + class,
		Name:             "EncodedExecutable_" + strings.ToUpper(class),
		ShortDescription: &sarifMessage{Text: "Executable hidden behind text encoding (" + class + ")"},
		FullDescription:  &sarifMessage{Text: "A base64/hex run decodes, possibly through several layers, to a valid PE or ELF header. The signal is the decoded content, which an attacker cannot shed without losing the payload; it is suspicious capability, not a confirmed detection."},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       map[string]interface{}{"kind": "encchain"},
	}
}

func (c config) appendEncChain(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	e := res.EncChain
	if !c.sarifIncludeHeuristics || !encChainBreached(e, c.encChainThreshold) {
		return results
	}
	for _, f := range e.Findings {
		rule := c.encChainRule(f)
		l := c.location(res.FilePath, nil)
		l.PhysicalLocation.Region = &sarifRegion{ByteOffset: int64(f.Offset), ByteLength: f.RunBytes}
		props := map[string]interface{}{
			"score":      e.Score,
			"threshold":  encChainThresholdFor(e, c.encChainThreshold),
			"classScore": f.Score,
			"encoding":   c.boundedMessage(f.Encoding),
			"depth":      f.Depth,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Novel != "" {
			props["novel"] = f.Novel
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(f.Detail)},
			Locations:           []sarifLocation{l},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) lnkRule(f lnk.Finding) sarifRule {
	class := strings.TrimPrefix(f.Class, "lnk.")
	return sarifRule{
		ID:               SARIFRuleLNKPrefix + class,
		Name:             "ShellLink_" + strings.ToUpper(strings.ReplaceAll(class, ".", "_")),
		ShortDescription: &sarifMessage{Text: "Malicious Windows shortcut signal (" + class + ")"},
		FullDescription:  &sarifMessage{Text: "A Windows Shell Link (.lnk) carries a signal of weaponised-shortcut delivery — an interpreter or LOLBin in its arguments, encoded or hidden-window flags, environment-variable path obfuscation, an executable target, a document-icon lure or appended data. Suspicious capability read from the structure, not a confirmed detection."},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       map[string]interface{}{"kind": "lnk"},
	}
}

func (c config) appendLNK(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	l := res.LNK
	if !c.sarifIncludeHeuristics || !lnkBreached(l, c.lnkThreshold) {
		return results
	}
	for _, f := range l.Findings {
		rule := c.lnkRule(f)
		props := map[string]interface{}{
			"score":      l.Score,
			"threshold":  lnkThresholdFor(l, c.lnkThreshold),
			"classScore": f.Score,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Evidence != "" {
			props["evidence"] = c.boundedMessage(f.Evidence)
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(f.Detail)},
			Locations:           []sarifLocation{c.location(res.FilePath, nil)},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) oleRule(f ole.Finding) sarifRule {
	class := strings.TrimPrefix(f.Class, "ole.")
	return sarifRule{
		ID:               SARIFRuleOLEPrefix + class,
		Name:             "OLEMacro_" + strings.ToUpper(strings.ReplaceAll(class, ".", "_")),
		ShortDescription: &sarifMessage{Text: "Malicious OLE/VBA macro signal (" + class + ")"},
		FullDescription:  &sarifMessage{Text: "An OLE compound-file document carries a VBA-macro signal of malicious intent — an auto-executing entry point, a shell/interpreter or download call in the decompressed macro source, heavy obfuscation, or an embedded-object/exploit lure. Suspicious capability read from the document, not a confirmed detection."},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       map[string]interface{}{"kind": "ole"},
	}
}

func (c config) appendOLE(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	o := res.OLE
	if !c.sarifIncludeHeuristics || !oleBreached(o, c.oleThreshold) {
		return results
	}
	for _, f := range o.Findings {
		rule := c.oleRule(f)
		props := map[string]interface{}{
			"score":      o.Score,
			"threshold":  oleThresholdFor(o, c.oleThreshold),
			"classScore": f.Score,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Evidence != "" {
			props["evidence"] = c.boundedMessage(f.Evidence)
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(f.Detail)},
			Locations:           []sarifLocation{c.location(res.FilePath, nil)},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) pdfRule(f pdf.Finding) sarifRule {
	class := strings.TrimPrefix(f.Class, "pdf.")
	return sarifRule{
		ID:               SARIFRulePDFPrefix + class,
		Name:             "PDFDocument_" + strings.ToUpper(strings.ReplaceAll(class, ".", "_")),
		ShortDescription: &sarifMessage{Text: "Malicious PDF document signal (" + class + ")"},
		FullDescription:  &sarifMessage{Text: "A PDF document carries a malicious-document signal — an auto-run action, embedded JavaScript, a Launch action, an embedded-file payload, or name obfuscation that hex-escapes a sensitive keyword. Suspicious capability read from the structure, not a confirmed detection."},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       map[string]interface{}{"kind": "pdf"},
	}
}

func (c config) appendPDF(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	p := res.PDF
	if !c.sarifIncludeHeuristics || !pdfBreached(p, c.pdfThreshold) {
		return results
	}
	for _, f := range p.Findings {
		rule := c.pdfRule(f)
		props := map[string]interface{}{
			"score":      p.Score,
			"threshold":  pdfThresholdFor(p, c.pdfThreshold),
			"classScore": f.Score,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Evidence != "" {
			props["evidence"] = c.boundedMessage(f.Evidence)
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(f.Detail)},
			Locations:           []sarifLocation{c.location(res.FilePath, nil)},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) isoRule(f iso.Finding) sarifRule {
	class := strings.TrimPrefix(f.Class, "iso.")
	return sarifRule{
		ID:               SARIFRuleISOPrefix + class,
		Name:             "ISOContainer_" + strings.ToUpper(strings.ReplaceAll(class, ".", "_")),
		ShortDescription: &sarifMessage{Text: "Malicious ISO container signal (" + class + ")"},
		FullDescription:  &sarifMessage{Text: "An ISO 9660 image shows the mark-of-the-web-bypass delivery shape — a shortcut paired with an executable payload, a hidden payload, or an autorun.inf. Suspicious container shape read from the directory tree, not a confirmed detection."},
		DefaultConfig:    &sarifRuleConfig{Level: c.levelHeuristic},
		Properties:       map[string]interface{}{"kind": "iso"},
	}
}

func (c config) appendISO(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	i := res.ISO
	if !c.sarifIncludeHeuristics || !isoBreached(i, c.isoThreshold) {
		return results
	}
	for _, f := range i.Findings {
		rule := c.isoRule(f)
		props := map[string]interface{}{
			"score":      i.Score,
			"threshold":  isoThresholdFor(i, c.isoThreshold),
			"classScore": f.Score,
		}
		if f.Technique != "" {
			props["technique"] = f.Technique
		}
		if f.Evidence != "" {
			props["evidence"] = c.boundedMessage(f.Evidence)
		}
		results = append(results, sarifResult{
			RuleID:              rule.ID,
			RuleIndex:           table.index[rule.ID],
			Level:               c.levelHeuristic,
			Message:             sarifMessage{Text: c.boundedMessage(f.Detail)},
			Locations:           []sarifLocation{c.location(res.FilePath, nil)},
			PartialFingerprints: c.fingerprints(res),
			Properties:          props,
		})
	}
	return results
}

func (c config) appendFusion(results []sarifResult, table *ruleTable, res scanner.ScanResult) []sarifResult {
	v := res.Fusion
	if !c.sarifIncludeHeuristics || !fusionCorroborated(v) {
		return results
	}
	sources := make([]map[string]interface{}, 0, len(v.Sources))
	for _, s := range v.Sources {
		if !s.Counted {
			continue
		}
		m := map[string]interface{}{
			"name": c.boundedMessage(s.Name), "role": string(s.Role), "score": s.Score, "threshold": s.Threshold, "ratio": round3(s.Ratio),
		}
		labels := make([]string, 0, len(s.Evidence))
		for _, e := range s.Evidence {
			labels = append(labels, c.boundedMessage(e.Label))
		}
		if len(labels) > 0 {
			m["evidence"] = labels
		}
		sources = append(sources, m)
	}
	props := map[string]interface{}{
		"score":      v.Score,
		"threshold":  v.Threshold,
		"confidence": v.Confidence,
		"agreed":     boundedList(c, v.Agreed),
		"sources":    sources,
	}
	if len(v.Techniques) > 0 {
		props["techniques"] = boundedList(c, v.Techniques)
	}
	if len(v.Novel) > 0 {
		props["novel"] = boundedList(c, v.Novel)
	}
	return append(results, sarifResult{
		RuleID:              SARIFRuleFusion,
		RuleIndex:           table.index[SARIFRuleFusion],
		Level:               c.levelHeuristic,
		Message:             sarifMessage{Text: c.boundedMessage(v.Explanation)},
		Locations:           []sarifLocation{c.location(res.FilePath, nil)},
		PartialFingerprints: c.fingerprints(res),
		Properties:          props,
	})
}

// categories lists the distinct heuristic categories in first-seen order.
func categories(h scanner.HeuristicResult) []string {
	var out []string
	seen := make(map[string]bool)
	for _, m := range h.Matches {
		if !seen[m.Category] {
			seen[m.Category] = true
			out = append(out, m.Category)
		}
	}
	return out
}

func (c config) hashRule(res scanner.ScanResult) sarifRule {
	threat := c.boundedMessage(res.ThreatName)
	return sarifRule{
		ID:               "hash/" + slug(res.ThreatName),
		Name:             "HashSignature",
		ShortDescription: &sarifMessage{Text: "Known-malware hash signature: " + threat},
		FullDescription: &sarifMessage{Text: fmt.Sprintf(
			"The file's cryptographic digest is listed in the signature database as %q.", threat)},
		DefaultConfig: &sarifRuleConfig{Level: c.levelHash},
		Properties:    map[string]interface{}{"threat": threat, "kind": "hash"},
	}
}

func (c config) yaraRule(m scanner.YaraMatch) sarifRule {
	ns := m.Namespace
	if ns == "" {
		ns = "default"
	}
	rule := sarifRule{
		ID:            "yara/" + slug(ns) + "/" + c.boundedMessage(m.RuleName),
		Name:          c.boundedMessage(m.RuleName),
		DefaultConfig: &sarifRuleConfig{Level: c.levelYara},
		Properties: map[string]interface{}{
			"kind":      "yara",
			"namespace": c.boundedMessage(ns),
		},
	}
	if d := m.MetaString("description"); d != "" {
		rule.ShortDescription = &sarifMessage{Text: c.boundedMessage(d)}
	} else {
		rule.ShortDescription = &sarifMessage{Text: "YARA rule " + c.boundedMessage(m.RuleName)}
	}
	if len(m.Tags) > 0 {
		rule.Properties["tags"] = boundedList(c, m.Tags)
	}
	if tl, ok := m.MetaInt("threat_level"); ok {
		rule.Properties["threat_level"] = tl
	}
	if a := m.MetaString("author"); a != "" {
		rule.Properties["author"] = c.boundedMessage(a)
	}
	return rule
}

func boundedList(c config, in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, c.boundedMessage(s))
	}
	sort.Strings(out)
	return out
}

// location builds a physicalLocation for a path and, when s is non-nil, a
// byte region for a matched string.
func (c config) location(p string, s *scanner.YaraMatchString) sarifLocation {
	uri, rel := relativeURI(c.root, p)
	art := sarifArtifactLoc{URI: uri}
	if rel {
		art.URIBaseID = SARIFSrcRoot
	}
	pl := sarifPhysicalLocation{ArtifactLocation: art}
	if s != nil {
		data, _ := truncateBytes(s.Data, c.maxMatchStringBytes)
		pl.Region = &sarifRegion{
			ByteOffset: int64(s.Offset),
			ByteLength: len(s.Data),
			Snippet:    &sarifSnippet{Binary: hexString(data)},
		}
		if pv := preview(s.Data, c.maxPreviewBytes); pv != "" {
			pl.Region.Snippet.Text = pv
		}
	}
	return sarifLocation{PhysicalLocation: pl}
}

// fingerprints lets a code-scanning UI recognise the same file across runs
// even when it moves: the content hash is the identity.
func (c config) fingerprints(res scanner.ScanResult) map[string]string {
	if res.SHA256 == "" {
		return nil
	}
	return map[string]string{"sha256/v1": c.boundedHash(res.SHA256)}
}

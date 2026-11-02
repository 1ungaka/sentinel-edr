// Package coverage builds the engine's ATT&CK coverage matrix: for every
// technique id the detection content maps to, which detectors and which
// content entries are evidence for it, and which content maps to nothing.
//
// The matrix is the honest counterfactual to a coverage claim: it is derived
// from the shipped content (heuristic categories, static anomaly classes,
// stego finding classes, the compiled YARA rules' meta), never typed in, and
// a committed expectation file (see Expect) turns it into a gate so content
// cannot lose a technique silently or gain one undocumented.
//
// Every source also carries its Pyramid of Pain level (Bianco): hash
// signatures sit at the bottom (trivial for an adversary to change), YARA and
// heuristics name tools, the structural and stego passes catch techniques.
// A file scanner never reaches the IP-address or domain-name layers; the
// matrix says so instead of implying otherwise.
package coverage

import (
	"sort"
	"strings"

	"github.com/cau-edr/cau/internal/attack"
	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/encchain"
	"github.com/cau-edr/cau/scanner/iso"
	"github.com/cau-edr/cau/scanner/lnk"
	"github.com/cau-edr/cau/scanner/ole"
	"github.com/cau-edr/cau/scanner/pdf"
	"github.com/cau-edr/cau/scanner/static"
	"github.com/cau-edr/cau/scanner/stego"
)

// Source names, identical to the fusion lattice's.
const (
	SourceHash       = "hash"
	SourceYara       = "yara"
	SourceHeuristic  = "heuristic"
	SourceStatic     = "static"
	SourceSimilarity = "similarity"
	SourceStego      = "stego"
	SourceEncChain   = "encchain"
	SourceLNK        = "lnk"
	SourceOLE        = "ole"
	SourcePDF        = "pdf"
	SourceISO        = "iso"
)

// Pyramid of Pain levels (David J. Bianco). Only the levels a file scanner
// can occupy are listed; IP addresses and domain names are network
// telemetry, which lives outside this engine.
const (
	PyramidHash      = "hash values"
	PyramidArtifacts = "host artifacts"
	PyramidTools     = "tools"
	PyramidTTPs      = "TTPs"
)

// Verdict tiers a source can produce on its own.
const (
	TierMalicious  = "malicious"
	TierSuspicious = "suspicious"
)

// Per-technique coverage states, as the SARIF and text renderings label them.
const (
	StateDetected = "detected" // content maps to it
	StatePartialS = "partial"  // content maps, acknowledged incomplete
	StatePlanned  = "planned"  // no content, on the roadmap (expectation gap)
	StateNoneS    = "none"     // no content, owned by sensor/console
)

// State returns a technique's coverage state for rendering.
func (t Technique) State() string {
	if t.Partial {
		return StatePartialS
	}
	return StateDetected
}

// Entry is one piece of detection content: a heuristic category, a static
// or stego class, a YARA rule.
type Entry struct {
	Source string `json:"source"`
	// Label is the stable content identifier, in the form the fusion lattice
	// and SARIF use ("heuristic/credential-access", "static/section.rwx",
	// "yara/default/mimikatz_strings", "stego.zero-width").
	Label string `json:"label"`
	// Name is the human-readable name (the category, class or rule name).
	Name string `json:"name"`
	// Technique is one ATT&CK id; an entry that maps to several is listed
	// once per id. Empty for unmapped content.
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	// Weight is the cap (heuristics) or the weight (static, stego) or the
	// threat_level (YARA).
	Weight int    `json:"weight,omitempty"`
	Tier   string `json:"tier"`
	// Weak marks a heuristic category in the shared weak budget.
	Weak        bool   `json:"weak,omitempty"`
	Description string `json:"description,omitempty"`
}

// Technique is one row of the matrix.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Tactics []string `json:"tactics,omitempty"`
	// Sources lists the detectors with content for the technique, sorted.
	Sources []string `json:"sources"`
	// Tier is the strongest verdict tier any source reaches on its own.
	Tier string `json:"tier"`
	// Partial is set when the expectation declares the technique's coverage
	// acknowledged-incomplete (partial by design).
	Partial bool    `json:"partial,omitempty"`
	Entries []Entry `json:"entries"`
}

// SourceSummary describes one detector in the matrix.
type SourceSummary struct {
	Name    string `json:"name"`
	Pyramid string `json:"pyramid_of_pain"`
	Tier    string `json:"tier"`
	// Entries is the number of content entries the source contributes;
	// Mapped how many carry a technique; Content the number of database
	// entries or rules behind them (hash signatures, fuzzy digests, rules).
	Entries int    `json:"entries"`
	Mapped  int    `json:"mapped"`
	Content int    `json:"content,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Matrix is the coverage document.
type Matrix struct {
	Tool       string          `json:"tool"`
	Version    string          `json:"version"`
	Sources    []SourceSummary `json:"sources"`
	Techniques []Technique     `json:"techniques"`
	// Unmapped is content that maps to no technique: listed, never padded
	// with a loose fit.
	Unmapped []Entry `json:"unmapped,omitempty"`
	// Gaps are techniques the expectation file declares as not covered.
	Gaps []Gap `json:"gaps,omitempty"`
}

// Inputs are the run-time parts of the matrix: the compiled rules and the
// database sizes. The heuristic, static and stego catalogs come from the
// packages themselves.
type Inputs struct {
	Tool    string
	Version string
	// Rules are the compiled YARA rules (nil when YARA is disabled).
	Rules []scanner.RuleInfo
	// YaraLoaded is false when no ruleset was loaded; the yara source is
	// then listed as absent rather than empty.
	YaraLoaded bool
	// HashCount and FuzzyCount are database sizes (-1 when not loaded).
	HashCount  int
	FuzzyCount int
	// IncludeInfo lists weight-0 informational static classes under
	// unmapped content. Off by default: they are observations, not evidence.
	IncludeInfo bool
}

// Build derives the matrix from the shipped content and the inputs.
func Build(in Inputs) *Matrix {
	m := &Matrix{Tool: in.Tool, Version: in.Version}
	var entries []Entry

	// Heuristic categories.
	for _, cs := range scanner.Categories() {
		entries = append(entries, Entry{
			Source: SourceHeuristic, Label: "heuristic/" + slug(cs.Category), Name: cs.Category,
			Technique: cs.Technique, Weight: cs.Cap, Weak: cs.Weak, Tier: TierSuspicious,
			Description: "capability named by imports or strings",
		})
	}

	// Static anomaly classes.
	for _, c := range static.Classes() {
		if c.Weight == 0 && !in.IncludeInfo {
			continue
		}
		src := SourceStatic
		if c.Category == static.CatFuzzy {
			src = SourceSimilarity
		}
		entries = append(entries, Entry{
			Source: src, Label: "static/" + c.Class, Name: c.Class,
			Technique: c.Technique, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description + " [" + strings.Join(c.Formats, ", ") + "]",
		})
	}

	// Stego finding classes.
	for _, c := range stego.Classes() {
		entries = append(entries, Entry{
			Source: SourceStego, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// Encoded-executable classes.
	for _, c := range encchain.Classes() {
		entries = append(entries, Entry{
			Source: SourceEncChain, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// Windows Shell Link (.lnk) classes.
	for _, c := range lnk.Classes() {
		entries = append(entries, Entry{
			Source: SourceLNK, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// OLE compound-file (VBA macro) classes.
	for _, c := range ole.Classes() {
		entries = append(entries, Entry{
			Source: SourceOLE, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// PDF malicious-document classes.
	for _, c := range pdf.Classes() {
		entries = append(entries, Entry{
			Source: SourcePDF, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// ISO 9660 malicious-container classes.
	for _, c := range iso.Classes() {
		entries = append(entries, Entry{
			Source: SourceISO, Label: c.Class, Name: c.Class,
			Technique: c.Technique, Novel: c.Novel, Weight: c.Weight, Tier: TierSuspicious,
			Description: c.Description,
		})
	}

	// YARA rules: one entry per declared technique, or one unmapped entry.
	for _, r := range in.Rules {
		if r.Private {
			continue
		}
		ns := r.Namespace
		if ns == "" {
			ns = "default"
		}
		base := Entry{
			Source: SourceYara, Label: "yara/" + slug(ns) + "/" + r.Name, Name: r.Name,
			Tier: TierMalicious, Description: r.Meta["description"],
		}
		if tl, ok := atoi(r.Meta["threat_level"]); ok {
			base.Weight = tl
		}
		techs := r.MetaTechnique()
		if len(techs) == 0 {
			entries = append(entries, base)
			continue
		}
		for _, t := range techs {
			e := base
			e.Technique = t
			entries = append(entries, e)
		}
	}

	// Group by technique.
	byTech := map[string]*Technique{}
	for _, e := range entries {
		if e.Technique == "" {
			m.Unmapped = append(m.Unmapped, e)
			continue
		}
		t, ok := byTech[e.Technique]
		if !ok {
			t = &Technique{ID: e.Technique, Name: attack.Name(e.Technique), Tactics: attack.Tactics(e.Technique)}
			byTech[e.Technique] = t
		}
		t.Entries = append(t.Entries, e)
	}
	for _, t := range byTech {
		seen := map[string]bool{}
		for _, e := range t.Entries {
			seen[e.Source] = true
			if e.Tier == TierMalicious {
				t.Tier = TierMalicious
			}
		}
		if t.Tier == "" {
			t.Tier = TierSuspicious
		}
		t.Sources = sortedKeys(seen)
		sort.SliceStable(t.Entries, func(i, j int) bool {
			if t.Entries[i].Source != t.Entries[j].Source {
				return t.Entries[i].Source < t.Entries[j].Source
			}
			return t.Entries[i].Label < t.Entries[j].Label
		})
		m.Techniques = append(m.Techniques, *t)
	}
	sort.Slice(m.Techniques, func(i, j int) bool { return m.Techniques[i].ID < m.Techniques[j].ID })
	sort.SliceStable(m.Unmapped, func(i, j int) bool {
		if m.Unmapped[i].Source != m.Unmapped[j].Source {
			return m.Unmapped[i].Source < m.Unmapped[j].Source
		}
		return m.Unmapped[i].Label < m.Unmapped[j].Label
	})

	// Source summaries.
	counts := map[string]*SourceSummary{}
	for _, e := range entries {
		s := counts[e.Source]
		if s == nil {
			s = &SourceSummary{Name: e.Source}
			counts[e.Source] = s
		}
		s.Entries++
		if e.Technique != "" {
			s.Mapped++
		}
	}
	for _, name := range []string{SourceHash, SourceYara, SourceHeuristic, SourceStatic, SourceSimilarity, SourceStego, SourceEncChain, SourceLNK, SourceOLE, SourcePDF, SourceISO} {
		s := counts[name]
		if s == nil {
			s = &SourceSummary{Name: name}
		}
		s.Pyramid, s.Tier = sourceProfile(name)
		switch name {
		case SourceHash:
			s.Content = in.HashCount
			s.Note = "exact-content signatures carry a threat name, not a technique"
			if in.HashCount < 0 {
				s.Content = 0
				s.Note = "no signature database loaded"
			}
		case SourceSimilarity:
			s.Content = in.FuzzyCount
			s.Note = "fuzzy matches name the sample they resemble, not a technique"
			if in.FuzzyCount < 0 {
				s.Content = 0
				s.Note = "no fuzzy database loaded"
			}
		case SourceYara:
			s.Content = len(in.Rules)
			if !in.YaraLoaded {
				s.Note = "no ruleset loaded"
			} else if s.Mapped < s.Entries {
				s.Note = "rules without mitre_attack meta are listed as unmapped"
			}
		}
		m.Sources = append(m.Sources, *s)
	}
	return m
}

// sourceProfile returns the Pyramid of Pain level and the verdict tier of a
// source. The levels are deliberately modest: a YARA rule on strings is a
// tool indicator (the adversary recompiles with different strings), the
// structural and stego passes catch a technique regardless of the sample.
func sourceProfile(name string) (pyramid, tier string) {
	switch name {
	case SourceHash:
		return PyramidHash, TierMalicious
	case SourceSimilarity:
		return PyramidHash, TierSuspicious
	case SourceYara:
		return PyramidTools, TierMalicious
	case SourceHeuristic:
		return PyramidTools, TierSuspicious
	case SourceStatic:
		return PyramidTTPs, TierSuspicious
	case SourceStego:
		return PyramidTTPs, TierSuspicious
	case SourceEncChain:
		return PyramidTTPs, TierSuspicious
	case SourceLNK:
		return PyramidTTPs, TierSuspicious
	case SourceOLE:
		return PyramidTTPs, TierSuspicious
	case SourcePDF:
		return PyramidTTPs, TierSuspicious
	case SourceISO:
		return PyramidTTPs, TierSuspicious
	}
	return "", ""
}

// Covered reports whether the matrix has content for a technique id.
func (m *Matrix) Covered(id string) bool {
	for _, t := range m.Techniques {
		if t.ID == id {
			return true
		}
	}
	return false
}

// TechniqueIDs lists the covered ids in order.
func (m *Matrix) TechniqueIDs() []string {
	out := make([]string, 0, len(m.Techniques))
	for _, t := range m.Techniques {
		out = append(out, t.ID)
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// slug lower-cases s and replaces every run of non-alphanumerics with "-",
// the same rendering the fusion lattice and SARIF use for labels.
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

package fusion

import "strings"

// Conditional chaining — the dependent half of the hybrid lattice.
//
// The weighted sum in fusion.go is additive by construction: it treats the
// sources as independent votes and so cannot express that two findings on the
// same file reinforce each other. A packed image is suspicious; a packed image
// that also carries process-injection capability is not merely the sum, it is
// a recognisable attack path. A document that also carries an encoded
// executable is a dropper, not two unrelated observations.
//
// A Chain states one such path: a set of predicates that must each match a
// distinct counted source. When they do, the chain adds a bounded bonus to the
// fused score and records itself, so the verdict can say which path it saw.
// Chains only ever add (the lattice stays monotone) and the total bonus is
// capped (DefaultChainCap), so no amount of chaining can run away from the
// evidence. Chains build only on sources that already count — a chain is extra
// weight for a conjunction, never a way to resurrect evidence the lattice
// discarded as below the floor.

// DefaultChainCap bounds the total bonus every fired chain can add, so chaining
// cannot lift a verdict more than one corroborating source would.
const DefaultChainCap = 0.75

// Predicate matches one counted source. An empty field is "don't care"; every
// non-empty field must hold. Technique matches the id or any of its sub-ids
// (T1055 matches T1055.001); Label is a substring of an evidence label.
type Predicate struct {
	Source    string   // exact source name
	AnySource []string // or any name in this set
	Technique string   // counted evidence carries this technique (or a sub-id)
	Label     string   // counted evidence label contains this substring
}

func (p Predicate) matches(sv SourceVerdict) bool {
	if !sv.Counted {
		return false
	}
	if p.Source != "" && sv.Name != p.Source {
		return false
	}
	if len(p.AnySource) > 0 {
		ok := false
		for _, n := range p.AnySource {
			if sv.Name == n {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if p.Technique != "" && !evidenceHasTechnique(sv.Evidence, p.Technique) {
		return false
	}
	if p.Label != "" && !evidenceHasLabel(sv.Evidence, p.Label) {
		return false
	}
	return true
}

func evidenceHasTechnique(ev []Evidence, tech string) bool {
	for _, e := range ev {
		if e.Technique == tech || strings.HasPrefix(e.Technique, tech+".") {
			return true
		}
	}
	return false
}

func evidenceHasLabel(ev []Evidence, sub string) bool {
	for _, e := range ev {
		if strings.Contains(e.Label, sub) {
			return true
		}
	}
	return false
}

// Chain is one attack-path rule. Requires must hold two or more predicates, and
// each binds to a distinct source, so a chain is always genuine multi-source
// corroboration and never a single loud detector dressed up as a path.
type Chain struct {
	Name      string
	Requires  []Predicate
	Bonus     float64
	Technique string // attached to the chain's own report line, when it has no source technique
	Novel     string
	Why       string
}

// ChainHit is a fired chain, recorded on the verdict.
type ChainHit struct {
	Name      string   `json:"name"`
	Bonus     float64  `json:"bonus"`
	Sources   []string `json:"sources"`
	Technique string   `json:"technique,omitempty"`
	Novel     string   `json:"novel,omitempty"`
	Why       string   `json:"why"`
}

// DefaultChains is the shipped attack-path set. It is deliberately small and
// each rule needs two independent detectors, so the false-positive surface is
// the intersection of two detectors' error modes, not their union. Like the
// numeric lattice parameters, the set is fixture-tuned and the honest caveat in
// docs/limitations.md applies: these are measured on one machine's package set.
var DefaultChains = []Chain{
	{
		Name: "packed-and-injects",
		Requires: []Predicate{
			{Source: SourceStatic, Label: "packer"},
			{Source: SourceHeuristic, Technique: "T1055"},
		},
		Bonus: 0.4, Technique: "T1055",
		Why: "a packed image that also carries process-injection capability",
	},
	{
		Name: "document-dropper",
		Requires: []Predicate{
			{AnySource: []string{SourceOLE, SourcePDF, SourceLNK, SourceISO}},
			{Source: SourceEncChain},
		},
		Bonus: 0.4, Technique: "T1027.009",
		Why: "a document or container vector that also carries an encoded executable",
	},
	{
		Name: "peel-revealed",
		Requires: []Predicate{
			{AnySource: []string{SourcePeeler, SourceEncChain}},
			{AnySource: []string{SourceYara, SourceHeuristic, SourceStego}},
		},
		Bonus: 0.4, Technique: "T1027",
		Why: "an obfuscation layer peeled away to reveal content a behavioural detector flagged",
	},
}

// applyChains returns the total bonus (capped) and the chains that fired, in
// declaration order, matching over the counted sources only.
func applyChains(sources []SourceVerdict, chains []Chain, cap float64) (float64, []ChainHit) {
	if len(chains) == 0 {
		return 0, nil
	}
	if cap <= 0 {
		cap = DefaultChainCap
	}
	var counted []SourceVerdict
	for _, sv := range sources {
		if sv.Counted {
			counted = append(counted, sv)
		}
	}
	total := 0.0
	var hits []ChainHit
	for _, c := range chains {
		if len(c.Requires) < 2 || c.Bonus <= 0 {
			continue
		}
		if names, ok := matchChain(counted, c.Requires); ok {
			hit := ChainHit{Name: c.Name, Bonus: c.Bonus, Sources: names, Technique: c.Technique, Novel: c.Novel, Why: c.Why}
			hits = append(hits, hit)
			total += c.Bonus
		}
	}
	if total > cap {
		total = cap
	}
	return round(total, 3), hits
}

// matchChain finds a distinct source for every predicate (a bipartite matching)
// and returns the matched source names in predicate order. Greedy assignment is
// not enough — one source may satisfy two predicates while another satisfies
// only one — so this backtracks.
func matchChain(sources []SourceVerdict, reqs []Predicate) ([]string, bool) {
	used := make([]bool, len(sources))
	names := make([]string, len(reqs))
	var assign func(i int) bool
	assign = func(i int) bool {
		if i == len(reqs) {
			return true
		}
		for j := range sources {
			if used[j] || !reqs[i].matches(sources[j]) {
				continue
			}
			used[j] = true
			names[i] = sources[j].Name
			if assign(i + 1) {
				return true
			}
			used[j] = false
		}
		return false
	}
	if assign(0) {
		return names, true
	}
	return nil, false
}

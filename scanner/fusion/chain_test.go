package fusion

import (
	"math/rand"
	"reflect"
	"testing"
)

func evsrc(name string, score, threshold int, ev ...Evidence) Source {
	return Source{Name: name, Score: score, Threshold: threshold, Evidence: ev}
}

func chained(sources []Source) *Verdict { return FuseChained(sources) }

func TestChainPackedAndInjectsEscalates(t *testing.T) {
	// Neither source crosses its own threshold and the flat sum (0.821) is
	// below the bar; the attack-path chain lifts it over.
	sources := []Source{
		evsrc("static", 4, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
		evsrc("heuristic", 4, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	flat := Fuse(sources)
	if flat.Tier != TierObserved {
		t.Fatalf("flat fusion should be observed, got %+v", flat)
	}
	v := chained(sources)
	if v.Tier != TierSuspicious {
		t.Fatalf("chained verdict = %+v", v)
	}
	if len(v.Chains) != 1 || v.Chains[0].Name != "packed-and-injects" {
		t.Fatalf("chains = %+v", v.Chains)
	}
	if v.ChainBonus != 0.4 || !v.ChainEscalated {
		t.Errorf("bonus=%v escalated=%v", v.ChainBonus, v.ChainEscalated)
	}
	if v.Score != round(flat.Score+0.4, 3) {
		t.Errorf("score = %v, want flat %v + 0.4", v.Score, flat.Score)
	}
	hasTech := false
	for _, tch := range v.Techniques {
		if tch == "T1055" {
			hasTech = true
		}
	}
	if !hasTech {
		t.Errorf("chain technique missing from %v", v.Techniques)
	}
}

func TestChainNeedsDistinctSources(t *testing.T) {
	// A chain whose two predicates could both match one source must not fire
	// on a single source carrying both labels.
	chain := Chain{Name: "two-legs", Bonus: 0.4, Requires: []Predicate{{Label: "aaa"}, {Label: "bbb"}}}
	p := Default
	p.Chains = []Chain{chain}

	one := []Source{evsrc("static", 6, 8, Evidence{Label: "x/aaa"}, Evidence{Label: "x/bbb"})}
	if v := FuseWith(one, p); len(v.Chains) != 0 {
		t.Errorf("single source satisfied a two-leg chain: %+v", v.Chains)
	}
	two := []Source{
		evsrc("static", 6, 8, Evidence{Label: "x/aaa"}),
		evsrc("heuristic", 6, 7, Evidence{Label: "x/bbb"}),
	}
	if v := FuseWith(two, p); len(v.Chains) != 1 {
		t.Errorf("two distinct sources should fire the chain: %+v", v.Chains)
	}
}

func TestChainBonusIsCapped(t *testing.T) {
	// Three chains that each fire, bonus 0.4 -> 1.2, capped to ChainCap.
	mk := func(name, la, lb string) Chain {
		return Chain{Name: name, Bonus: 0.4, Requires: []Predicate{{Label: la}, {Label: lb}}}
	}
	p := Default
	p.ChainCap = 0.75
	p.Chains = []Chain{mk("c1", "aa", "bb"), mk("c2", "aa", "cc"), mk("c3", "bb", "cc")}
	sources := []Source{
		evsrc("static", 6, 8, Evidence{Label: "x/aa"}),
		evsrc("heuristic", 6, 7, Evidence{Label: "x/bb"}),
		evsrc("stego", 3, 4, Evidence{Label: "x/cc"}),
	}
	v := FuseWith(sources, p)
	if len(v.Chains) != 3 {
		t.Fatalf("expected 3 chains, got %+v", v.Chains)
	}
	if v.ChainBonus != 0.75 {
		t.Errorf("bonus = %v, want capped 0.75", v.ChainBonus)
	}
}

func TestChainBuildsOnlyOnCountedSources(t *testing.T) {
	// A below-floor source cannot be a chain leg. static at 2/8 (0.25 < floor)
	// is below-floor, so the packed-and-injects chain does not fire; raising it
	// to 4/8 makes it count and the chain fires (monotone escalation).
	below := []Source{
		evsrc("static", 2, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
		evsrc("heuristic", 5, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	if v := chained(below); len(v.Chains) != 0 {
		t.Errorf("below-floor static should not be a chain leg: %+v", v.Chains)
	}
	above := below
	above[0].Score = 4
	if v := chained(above); len(v.Chains) != 1 {
		t.Errorf("counted static should fire the chain: %+v", v.Chains)
	}
}

func TestChainNeverDowngradesDefinitive(t *testing.T) {
	sources := []Source{
		{Name: "hash", Definitive: true, Hit: true, Evidence: []Evidence{{Label: "hash/sha256", Detail: "Fam"}}},
		evsrc("static", 4, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
		evsrc("heuristic", 4, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	v := chained(sources)
	if v.Tier != TierMalicious || v.Confidence != "high" {
		t.Fatalf("definitive downgraded: %+v", v)
	}
	if len(v.Chains) != 1 || v.Chains[0].Name != "packed-and-injects" {
		t.Errorf("chain should still be recorded next to a definitive hit: %+v", v.Chains)
	}
}

func TestFlatFuseHasNoChains(t *testing.T) {
	// Backward compatibility: the flat entry point never chains, whatever the
	// evidence.
	sources := []Source{
		evsrc("static", 4, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
		evsrc("heuristic", 4, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	v := Fuse(sources)
	if len(v.Chains) != 0 || v.ChainBonus != 0 || v.ChainEscalated {
		t.Errorf("flat Fuse produced chaining: %+v", v)
	}
}

func TestChainedIsMonotone(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	tmpl := func(sa, sb, sc int) []Source {
		return []Source{
			evsrc("static", sa, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
			evsrc("heuristic", sb, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
			evsrc("encchain", sc, 4, Evidence{Label: "encchain/embedded", Technique: "T1027.009"}),
		}
	}
	for i := 0; i < 3000; i++ {
		sa, sb, sc := rng.Intn(12), rng.Intn(12), rng.Intn(6)
		base := chained(tmpl(sa, sb, sc))
		switch rng.Intn(3) {
		case 0:
			sa++
		case 1:
			sb++
		default:
			sc++
		}
		up := chained(tmpl(sa, sb, sc))
		if up.Score < base.Score || up.Tier.Rank() < base.Tier.Rank() {
			t.Fatalf("not monotone: %+v -> %+v", base, up)
		}
	}
}

func TestChainDocumentDropperAndPeel(t *testing.T) {
	// A maldoc that also carries an encoded executable, plus a peeled layer a
	// behavioural detector flagged: two independent attack-path chains.
	sources := []Source{
		evsrc("ole", 3, 6, Evidence{Label: "ole/macro.autoexec", Technique: "T1204"}),
		evsrc("encchain", 3, 4, Evidence{Label: "encchain/embedded-pe", Technique: "T1027.009"}),
		evsrc("heuristic", 4, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	v := chained(sources)
	names := map[string]bool{}
	for _, c := range v.Chains {
		names[c.Name] = true
	}
	if !names["document-dropper"] || !names["peel-revealed"] {
		t.Fatalf("expected document-dropper and peel-revealed, got %+v", v.Chains)
	}
}

func TestPredicateTechniqueSubID(t *testing.T) {
	// T1055 in a predicate matches the sub-technique T1055.001.
	p := Predicate{Source: "heuristic", Technique: "T1055"}
	sv := SourceVerdict{Name: "heuristic", Counted: true, Evidence: []Evidence{{Technique: "T1055.001"}}}
	if !p.matches(sv) {
		t.Error("T1055 should match T1055.001")
	}
	sv.Evidence = []Evidence{{Technique: "T10550"}}
	if p.matches(sv) {
		t.Error("T1055 must not match the unrelated T10550")
	}
}

func TestChainHitShape(t *testing.T) {
	sources := []Source{
		evsrc("static", 5, 8, Evidence{Label: "static/packer.upx", Technique: "T1027.002"}),
		evsrc("heuristic", 5, 7, Evidence{Label: "heuristic/process-injection", Technique: "T1055"}),
	}
	v := chained(sources)
	if len(v.Chains) != 1 {
		t.Fatalf("chains = %+v", v.Chains)
	}
	got := v.Chains[0]
	if !reflect.DeepEqual(got.Sources, []string{"static", "heuristic"}) {
		t.Errorf("chain sources = %v", got.Sources)
	}
	if got.Technique != "T1055" || got.Why == "" {
		t.Errorf("chain hit = %+v", got)
	}
}

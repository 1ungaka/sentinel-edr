package scanner

import (
	"fmt"
	"strings"

	"github.com/cau-edr/cau/scanner/fusion"
	"github.com/cau-edr/cau/scanner/static"
)

// fuse builds the fusion lattice's view of one scan: every detector the
// engine ran becomes a fusion.Source carrying its evidence labels, and the
// lattice says which of them agreed. The verdict is a view over the
// per-detector results, never a replacement for them: ScanResult.Verdict,
// HeuristicResult.Detected() and the static and stego thresholds keep their
// meanings, and the fused verdict is what the reports lead with.
func (e *Engine) fuse(res *ScanResult, h *HeuristicResult) *fusion.Verdict {
	var sources []fusion.Source

	if e.DB != nil {
		src := fusion.Source{Name: fusion.SourceHash, Definitive: true, Hit: res.Detected}
		if res.Detected {
			src.Evidence = []fusion.Evidence{{
				Label:  "hash/" + strings.ToLower(res.MatchType),
				Detail: res.ThreatName,
			}}
		}
		sources = append(sources, src)
	}

	if e.Yara != nil {
		src := fusion.Source{Name: fusion.SourceYara, Definitive: true, Hit: len(res.YaraMatches) > 0}
		for _, m := range res.YaraMatches {
			ns := m.Namespace
			if ns == "" {
				ns = "default"
			}
			ev := fusion.Evidence{Label: "yara/" + slug(ns) + "/" + m.RuleName, Detail: m.MetaString("description")}
			for _, key := range []string{"mitre_attack", "attack", "technique"} {
				if t := m.MetaString(key); t != "" {
					ev.Technique = t
					break
				}
			}
			if tl, ok := m.MetaInt("threat_level"); ok {
				ev.Weight = tl
			}
			src.Evidence = append(src.Evidence, ev)
		}
		sources = append(sources, src)
	}

	if h != nil {
		src := fusion.Source{Name: fusion.SourceHeuristic, Score: h.Score, Threshold: h.EffectiveThreshold(), Skipped: h.Skipped}
		if h.Error != nil {
			src.Skipped = "heuristics failed: " + h.Error.Error()
		}
		for _, cs := range h.Categories {
			if cs.Applied == 0 {
				continue
			}
			src.Evidence = append(src.Evidence, fusion.Evidence{
				Label:     "heuristic/" + slug(cs.Category),
				Detail:    fmt.Sprintf("%s %d/%d", cs.Category, cs.Applied, cs.Cap),
				Technique: cs.Technique,
				Weight:    cs.Applied,
			})
		}
		sources = append(sources, src)
	}

	if s := res.Static; s != nil {
		structural := fusion.Source{Name: fusion.SourceStatic, Threshold: s.EffectiveThreshold(), Skipped: s.Skipped}
		similarity := fusion.Source{Name: fusion.SourceSimilarity, Threshold: s.EffectiveThreshold(), Skipped: s.Skipped}
		if s.Error != nil {
			structural.Skipped = "static analysis failed: " + s.Error.Error()
			similarity.Skipped = structural.Skipped
		}
		// Similarity (fuzzy-hash) matches are their own source: "looks like a
		// known sample" and "is built like something hiding" are independent
		// questions, and the plan wants fuzzy matches to enter the lattice
		// rather than ride on the structural score.
		fuzzyApplied := 0
		for _, cs := range s.Categories {
			if cs.Category == static.CatFuzzy {
				fuzzyApplied = cs.Applied
			}
		}
		structural.Score = s.Score - fuzzyApplied
		similarity.Score = fuzzyApplied
		for _, a := range s.Anomalies {
			if a.Score == 0 {
				continue
			}
			ev := fusion.Evidence{Label: "static/" + a.Class, Detail: a.Detail, Technique: a.Technique, Weight: a.Score}
			if a.Category == static.CatFuzzy {
				similarity.Evidence = append(similarity.Evidence, ev)
			} else {
				structural.Evidence = append(structural.Evidence, ev)
			}
		}
		sources = append(sources, structural)
		if e.FuzzyDB != nil && !e.StaticNoFuzzy && s.Skipped == "" && s.Error == nil {
			sources = append(sources, similarity)
		} else if similarity.Skipped == "" {
			similarity.Skipped = "no fuzzy database"
			sources = append(sources, similarity)
		} else {
			sources = append(sources, similarity)
		}
	}

	if st := res.Stego; st != nil {
		src := fusion.Source{Name: fusion.SourceStego, Score: st.Score, Threshold: st.EffectiveThreshold(), Skipped: st.Skipped}
		if st.Error != nil {
			src.Skipped = "stego scan failed: " + st.Error.Error()
		}
		for _, f := range st.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Novel: f.Novel, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if ec := res.EncChain; ec != nil {
		src := fusion.Source{Name: fusion.SourceEncChain, Score: ec.Score, Threshold: ec.EffectiveThreshold(), Skipped: ec.Skipped}
		for _, f := range ec.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Novel: f.Novel, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if lk := res.LNK; lk != nil {
		src := fusion.Source{Name: fusion.SourceLNK, Score: lk.Score, Threshold: lk.EffectiveThreshold(), Skipped: lk.Skipped}
		for _, f := range lk.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if ol := res.OLE; ol != nil {
		src := fusion.Source{Name: fusion.SourceOLE, Score: ol.Score, Threshold: ol.EffectiveThreshold(), Skipped: ol.Skipped}
		for _, f := range ol.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if pd := res.PDF; pd != nil {
		src := fusion.Source{Name: fusion.SourcePDF, Score: pd.Score, Threshold: pd.EffectiveThreshold(), Skipped: pd.Skipped}
		for _, f := range pd.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if is := res.ISO; is != nil {
		src := fusion.Source{Name: fusion.SourceISO, Score: is.Score, Threshold: is.EffectiveThreshold(), Skipped: is.Skipped}
		for _, f := range is.Findings {
			src.Evidence = append(src.Evidence, fusion.Evidence{Label: f.Class, Detail: f.Detail, Technique: f.Technique, Weight: f.Score})
		}
		sources = append(sources, src)
	}

	if len(sources) == 0 {
		return nil
	}
	return fusion.Fuse(sources)
}

// slug lower-cases s and replaces every run of non-alphanumerics with "-".
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

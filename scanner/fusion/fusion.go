// Package fusion is the detection fusion lattice: it joins the independent
// detectors' outcomes for one file into a single verdict that says which
// sources agreed, how strongly, and which techniques the agreeing evidence
// carries.
//
// # Why
//
// Each detector has its own threshold, tuned so that it alone does not fire
// on ordinary software. That tuning has a cost: a file that scores 5/7 on the
// heuristics and 6/8 on the structural pass was, until now, reported CLEAN,
// although two detectors with uncorrelated error modes both found something.
// Fusion makes that corroboration count. Beating one detector costs an
// attacker little; beating several at once, each below its own floor, costs
// multiplicatively, because every layer must be evaded separately.
//
// # Model
//
// Every source is normalised to a ratio score/threshold, capped at Cap so one
// loud detector cannot pretend to be two. The highest ratio is the primary
// source and counts in full. Every other source whose ratio reaches Floor is
// a corroborating source and contributes Weight × ratio. Sources below the
// floor are reported but do not count: a single Sleep import is not
// corroboration of anything. The fused score reaches Threshold (1.0) when
// one source crosses its own threshold alone, exactly as before, or when the
// corroboration adds up to the same thing.
//
// Definitive sources (a hash-database hit, a YARA match) are not ratios; they
// are a verdict, and fusion never downgrades them. They still take part in
// the lattice so the report can say "hash hit, corroborated by heuristics
// 9/7" or, just as usefully, "hash hit, nothing else saw anything".
//
// # Contracts
//
//   - A fused verdict is never lower than the strongest single source: with
//     Floor and Weight positive, Fuse is monotone in every input.
//   - The output lists every source, including silent and skipped ones, with
//     its role, so the renderer explains silence as well as agreement.
//   - Evidence labels and techniques flow through unchanged; the lattice adds
//     no evidence of its own.
//   - The parameters are published constants, tuned on the same real-binary
//     fixtures as the detectors they combine (see fusion_test.go and PLAN.md).
package fusion

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Tier is the fused verdict band. The ordering is the ordering of the
// constants: clean < observed < suspicious < malicious.
type Tier string

const (
	// TierClean: no source recorded any evidence.
	TierClean Tier = "clean"
	// TierObserved: evidence exists but the fused score is below Threshold.
	TierObserved Tier = "observed"
	// TierSuspicious: the fused score reached Threshold with no definitive hit.
	TierSuspicious Tier = "suspicious"
	// TierMalicious: a definitive source fired.
	TierMalicious Tier = "malicious"
)

// Rank orders tiers for comparisons.
func (t Tier) Rank() int {
	switch t {
	case TierObserved:
		return 1
	case TierSuspicious:
		return 2
	case TierMalicious:
		return 3
	}
	return 0
}

// Role is the part a source played in the fused verdict.
type Role string

const (
	// RoleDefinitive: a definitive source that fired.
	RoleDefinitive Role = "definitive"
	// RolePrimary: the highest-ratio scored source; counts in full.
	RolePrimary Role = "primary"
	// RoleCorroborating: a scored source at or above Floor; counts at Weight.
	RoleCorroborating Role = "corroborating"
	// RoleBelowFloor: scored evidence too weak to corroborate.
	RoleBelowFloor Role = "below-floor"
	// RoleSilent: the source ran and found nothing.
	RoleSilent Role = "silent"
	// RoleSkipped: the source did not run on this file (too large, not text,
	// read error), with the reason recorded.
	RoleSkipped Role = "skipped"
)

// Evidence is one labeled reason a source contributed. Labels are the
// detectors' own stable identifiers ("static/packer.upx",
// "heuristic/process-injection", "yara/default/wannacry_ransomware").
type Evidence struct {
	Label     string `json:"label"`
	Detail    string `json:"detail,omitempty"`
	Technique string `json:"technique,omitempty"`
	// Novel is a NOVEL-xxx id for techniques without an ATT&CK entry.
	Novel string `json:"novel,omitempty"`
	// Weight is the points the evidence contributed to its own source's
	// score, for display; the lattice works on the source totals.
	Weight int `json:"weight,omitempty"`
}

// Source is one detector's outcome for one file, as handed to Fuse.
type Source struct {
	// Name is the detector's stable identifier ("hash", "yara", "heuristic",
	// "static", "similarity", "stego").
	Name string
	// Definitive marks a source whose hit is a verdict in itself. Score and
	// Threshold are ignored for definitive sources; Hit is what counts.
	Definitive bool
	Hit        bool
	// Score and Threshold are the detector's own numbers. A zero threshold
	// means the source is not scored (definitive, or misconfigured) and it
	// never counts.
	Score, Threshold int
	// Skipped is the reason the source did not examine the file.
	Skipped  string
	Evidence []Evidence
}

// SourceVerdict is one source's line in the fused verdict.
type SourceVerdict struct {
	Name      string     `json:"name"`
	Role      Role       `json:"role"`
	Hit       bool       `json:"hit,omitempty"`
	Score     int        `json:"score,omitempty"`
	Threshold int        `json:"threshold,omitempty"`
	Ratio     float64    `json:"ratio,omitempty"`
	Weight    float64    `json:"weight,omitempty"`
	Counted   bool       `json:"counted"`
	Skipped   string     `json:"skipped,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
}

// Verdict is the fused outcome.
type Verdict struct {
	Tier Tier `json:"tier"`
	// Score is the fused score; Threshold is the fused bar (1.0 by default).
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold"`
	// Confidence is "high", "medium" or "low" ("" for clean).
	Confidence string `json:"confidence,omitempty"`
	// Agreed names the sources that counted, strongest first.
	Agreed []string `json:"agreed,omitempty"`
	// Techniques is the de-duplicated union of the counted evidence's ATT&CK
	// ids; Novel the same for NOVEL-xxx ids.
	Techniques []string `json:"techniques,omitempty"`
	Novel      []string `json:"novel,omitempty"`
	// Corroborated is true when the suspicious tier was reached only through
	// corroboration: no single scored source crossed its own threshold and no
	// definitive source fired. These are the detections fusion adds.
	Corroborated bool            `json:"corroborated,omitempty"`
	Sources      []SourceVerdict `json:"sources"`
	// Explanation is one line for humans.
	Explanation string `json:"explanation"`
}

// Detected reports whether the fused tier is suspicious or above.
func (v *Verdict) Detected() bool {
	return v != nil && v.Tier.Rank() >= TierSuspicious.Rank()
}

// Params are the lattice constants.
type Params struct {
	// Threshold is the fused score at which the tier becomes suspicious.
	Threshold float64
	// Floor is the minimum ratio a non-primary source needs to corroborate.
	Floor float64
	// Weight is the share of a corroborating source's ratio that counts.
	Weight float64
	// Cap bounds every ratio so a single very loud source is still one source.
	Cap float64
}

// Default holds the shipped constants. Floor 0.4 means a heuristic score of
// 3/7 or a static score of 4/8 can corroborate; Weight 0.5 means two sources
// at 0.7 of their own thresholds fuse to 1.05 and alert, while one at 0.9 and
// one at 0.2 fuse to 0.9 and do not. The numbers were fixed against the
// 349-file Kali Windows tool set: no benign tool that was below every
// individual threshold crosses the fused one (see PLAN.md, detection-quality
// program).
var Default = Params{Threshold: 1.0, Floor: 0.4, Weight: 0.5, Cap: 1.5}

// Fuse combines sources with the Default parameters.
func Fuse(sources []Source) *Verdict { return FuseWith(sources, Default) }

// FuseWith combines sources with explicit parameters.
func FuseWith(sources []Source, p Params) *Verdict {
	if p.Threshold <= 0 {
		p.Threshold = Default.Threshold
	}
	if p.Cap <= 0 {
		p.Cap = Default.Cap
	}
	if p.Weight < 0 {
		p.Weight = 0
	}
	if p.Floor < 0 {
		p.Floor = 0
	}

	v := &Verdict{Tier: TierClean, Threshold: p.Threshold}
	var scored []SourceVerdict
	var definitive []SourceVerdict
	var rest []SourceVerdict

	for _, s := range sources {
		sv := SourceVerdict{Name: s.Name, Score: s.Score, Threshold: s.Threshold, Skipped: s.Skipped, Evidence: s.Evidence}
		switch {
		case s.Skipped != "":
			sv.Role = RoleSkipped
			rest = append(rest, sv)
		case s.Definitive:
			sv.Hit = s.Hit
			if s.Hit {
				sv.Role = RoleDefinitive
				sv.Counted = true
				definitive = append(definitive, sv)
			} else {
				sv.Role = RoleSilent
				rest = append(rest, sv)
			}
		case s.Threshold <= 0 || s.Score <= 0:
			sv.Role = RoleSilent
			rest = append(rest, sv)
		default:
			sv.Ratio = math.Min(float64(s.Score)/float64(s.Threshold), p.Cap)
			scored = append(scored, sv)
		}
	}

	// Primary first, then the rest by ratio; ties by name so the output is
	// stable across runs.
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Ratio != scored[j].Ratio {
			return scored[i].Ratio > scored[j].Ratio
		}
		return scored[i].Name < scored[j].Name
	})
	fused := 0.0
	anyAlone := false
	for i := range scored {
		sv := &scored[i]
		switch {
		case i == 0:
			sv.Role = RolePrimary
			sv.Weight = 1
			sv.Counted = true
			fused += sv.Ratio
			if sv.Ratio >= 1 {
				anyAlone = true
			}
		case sv.Ratio >= p.Floor && p.Weight > 0:
			sv.Role = RoleCorroborating
			sv.Weight = p.Weight
			sv.Counted = true
			fused += p.Weight * sv.Ratio
			if sv.Ratio >= 1 {
				anyAlone = true
			}
		default:
			sv.Role = RoleBelowFloor
		}
	}
	v.Score = round(fused, 3)

	// Next to a definitive hit there is nothing to be primary of: a scored
	// source either corroborates (at or above the floor) or it does not.
	if len(definitive) > 0 {
		for i := range scored {
			sv := &scored[i]
			if sv.Ratio >= p.Floor {
				sv.Role, sv.Weight, sv.Counted = RoleCorroborating, p.Weight, true
			} else {
				sv.Role, sv.Weight, sv.Counted = RoleBelowFloor, 0, false
			}
		}
	}

	sort.SliceStable(definitive, func(i, j int) bool { return definitive[i].Name < definitive[j].Name })
	sort.SliceStable(rest, func(i, j int) bool {
		if rest[i].Role != rest[j].Role {
			return rest[i].Role == RoleSilent // silent before skipped
		}
		return rest[i].Name < rest[j].Name
	})
	v.Sources = append(append(append(v.Sources, definitive...), scored...), rest...)

	techs := map[string]bool{}
	novel := map[string]bool{}
	for _, sv := range v.Sources {
		if !sv.Counted {
			continue
		}
		v.Agreed = append(v.Agreed, sv.Name)
		for _, e := range sv.Evidence {
			if e.Technique != "" {
				techs[e.Technique] = true
			}
			if e.Novel != "" {
				novel[e.Novel] = true
			}
		}
	}
	v.Techniques = sortedKeys(techs)
	v.Novel = sortedKeys(novel)

	switch {
	case len(definitive) > 0:
		v.Tier = TierMalicious
		v.Confidence = "high"
		if len(v.Agreed) == 1 && definitive[0].Name != "hash" {
			v.Confidence = "medium"
		}
	case fused >= p.Threshold:
		v.Tier = TierSuspicious
		v.Corroborated = !anyAlone
		v.Confidence = "medium"
		if fused >= 1.5*p.Threshold {
			v.Confidence = "high"
		}
	case len(scored) > 0:
		v.Tier = TierObserved
		v.Confidence = "low"
	}
	v.Explanation = explain(v)
	return v
}

func explain(v *Verdict) string {
	var parts []string
	for _, sv := range v.Sources {
		if !sv.Counted {
			continue
		}
		switch sv.Role {
		case RoleDefinitive:
			label := sv.Name
			if len(sv.Evidence) > 0 {
				label += " (" + sv.Evidence[0].Label + ")"
			}
			parts = append(parts, label)
		default:
			parts = append(parts, fmt.Sprintf("%s %d/%d", sv.Name, sv.Score, sv.Threshold))
		}
	}
	switch v.Tier {
	case TierMalicious:
		def := parts[:0:0]
		var corr []string
		for _, sv := range v.Sources {
			if !sv.Counted {
				continue
			}
			if sv.Role == RoleDefinitive {
				label := sv.Name
				if len(sv.Evidence) > 0 {
					label += " (" + sv.Evidence[0].Label + ")"
				}
				def = append(def, label)
			} else {
				corr = append(corr, fmt.Sprintf("%s %d/%d", sv.Name, sv.Score, sv.Threshold))
			}
		}
		s := "MALICIOUS: " + strings.Join(def, " + ")
		if len(corr) > 0 {
			s += ", corroborated by " + strings.Join(corr, " + ")
		} else {
			s += ", no other source saw anything"
		}
		return s
	case TierSuspicious:
		s := fmt.Sprintf("SUSPICIOUS: %s (fused %.2f / %.2f", strings.Join(parts, " + "), v.Score, v.Threshold)
		if v.Corroborated {
			s += ", by corroboration: no single source crossed its own threshold"
		}
		return s + ")"
	case TierObserved:
		return fmt.Sprintf("observed: %s (fused %.2f / %.2f)", strings.Join(parts, " + "), v.Score, v.Threshold)
	}
	return "clean: no source recorded evidence"
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func round(f float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(f*p) / p
}

// Source names used by the engine. They are conventions, not a closed set.
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

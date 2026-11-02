// Package frameworks binds the engine's ATT&CK coverage to complementary
// models so mapping never hinges on a single US registry (Phase 4). The one
// binding the engine can *derive* is the Unified Kill Chain (Paul Pols,
// Fox-IT, NL): a phase-wise sequencing view laid alongside ATT&CK, computed
// from each technique's ATT&CK tactic. The other schemes the plan names — MISP
// galaxy clusters (CIRCL) and Malpedia families (Fraunhofer FKIE) — are
// actor/family tags that an intelligence feed attaches to a specific sample;
// they are not derivable from a technique id, so they are carried as fields an
// intel source populates, never invented here.
//
// The Unified Kill Chain orders 18 phases across three stages. The engine's
// detections touch a subset; the sequencing view shows which parts of an
// attack's progression the shipped content can see, and where the gaps fall —
// the honest counterfactual, like the ATT&CK matrix itself.
package frameworks

import (
	"sort"

	"github.com/cau-edr/cau/internal/attack"
)

// UKC phase names (canonical Unified Kill Chain v2 ordering).
const (
	Reconnaissance    = "Reconnaissance"
	Weaponization     = "Weaponization"
	Delivery          = "Delivery"
	SocialEngineering = "Social Engineering"
	Exploitation      = "Exploitation"
	Persistence       = "Persistence"
	DefenseEvasion    = "Defense Evasion"
	CommandAndControl = "Command & Control"
	Pivoting          = "Pivoting"
	Discovery         = "Discovery"
	PrivilegeEsc      = "Privilege Escalation"
	Execution         = "Execution"
	CredentialAccess  = "Credential Access"
	LateralMovement   = "Lateral Movement"
	Collection        = "Collection"
	Exfiltration      = "Exfiltration"
	Impact            = "Impact"
	Objectives        = "Objectives"
)

// UKC stages group the phases into the three arcs of an intrusion.
const (
	StageInitialFoothold    = "Initial Foothold"
	StageNetworkPropagation = "Network Propagation"
	StageActionOnObjectives = "Action on Objectives"
)

// phaseOrder is the canonical sequence; the index is used to order the view and
// to pick a technique's primary (earliest) phase when it spans several tactics.
var phaseOrder = []string{
	Reconnaissance, Weaponization, Delivery, SocialEngineering, Exploitation,
	Persistence, DefenseEvasion, CommandAndControl,
	Pivoting, Discovery, PrivilegeEsc, Execution, CredentialAccess, LateralMovement,
	Collection, Exfiltration, Impact, Objectives,
}

var phaseIndex = func() map[string]int {
	m := make(map[string]int, len(phaseOrder))
	for i, p := range phaseOrder {
		m[p] = i
	}
	return m
}()

var phaseStage = map[string]string{
	Reconnaissance: StageInitialFoothold, Weaponization: StageInitialFoothold,
	Delivery: StageInitialFoothold, SocialEngineering: StageInitialFoothold,
	Exploitation: StageInitialFoothold, Persistence: StageInitialFoothold,
	DefenseEvasion: StageInitialFoothold, CommandAndControl: StageInitialFoothold,
	Pivoting: StageNetworkPropagation, Discovery: StageNetworkPropagation,
	PrivilegeEsc: StageNetworkPropagation, Execution: StageNetworkPropagation,
	CredentialAccess: StageNetworkPropagation, LateralMovement: StageNetworkPropagation,
	Collection: StageActionOnObjectives, Exfiltration: StageActionOnObjectives,
	Impact: StageActionOnObjectives, Objectives: StageActionOnObjectives,
}

// tacticToPhase maps each ATT&CK tactic the catalog uses onto a UKC phase.
var tacticToPhase = map[string]string{
	attack.InitialAccess:   Delivery,
	attack.Execution:       Execution,
	attack.Persistence:     Persistence,
	attack.PrivEsc:         PrivilegeEsc,
	attack.DefenseEvasion:  DefenseEvasion,
	attack.CredAccess:      CredentialAccess,
	attack.Discovery:       Discovery,
	attack.LateralMovement: LateralMovement,
	attack.Collection:      Collection,
	attack.C2:              CommandAndControl,
	attack.Impact:          Impact,
}

// Binding is the multi-framework view of one technique.
type Binding struct {
	Technique string   `json:"technique"`
	Tactics   []string `json:"tactics,omitempty"`
	// UKCPhase is the primary (earliest-in-sequence) Unified Kill Chain phase.
	UKCPhase string `json:"ukc_phase,omitempty"`
	// UKCPhases is every phase the technique's tactics map to, in sequence.
	UKCPhases []string `json:"ukc_phases,omitempty"`
	// UKCStage is the stage of the primary phase.
	UKCStage string `json:"ukc_stage,omitempty"`
	// MISPCluster and MalpediaFamily are intel-populated, never derived here.
	MISPCluster    string `json:"misp_cluster,omitempty"`
	MalpediaFamily string `json:"malpedia_family,omitempty"`
}

// PhaseForTactic returns the UKC phase for an ATT&CK tactic, or "" if unknown.
func PhaseForTactic(tactic string) string { return tacticToPhase[tactic] }

// StageForPhase returns the UKC stage a phase belongs to, or "".
func StageForPhase(phase string) string { return phaseStage[phase] }

// ForTechnique derives the UKC binding for an ATT&CK technique id. An unknown
// id (or one whose tactics have no mapping) yields a Binding with an empty
// UKCPhase — reported honestly, never guessed.
func ForTechnique(id string) Binding {
	tactics := attack.Tactics(id)
	b := Binding{Technique: id, Tactics: tactics}
	seen := make(map[string]struct{})
	for _, t := range tactics {
		if p := tacticToPhase[t]; p != "" {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				b.UKCPhases = append(b.UKCPhases, p)
			}
		}
	}
	sort.SliceStable(b.UKCPhases, func(i, j int) bool {
		return phaseIndex[b.UKCPhases[i]] < phaseIndex[b.UKCPhases[j]]
	})
	if len(b.UKCPhases) > 0 {
		b.UKCPhase = b.UKCPhases[0]
		b.UKCStage = phaseStage[b.UKCPhase]
	}
	return b
}

// PhaseCoverage is the per-phase roll-up of a set of technique ids: how many of
// the covered techniques land in each UKC phase, in canonical sequence.
type PhaseCoverage struct {
	Phase      string   `json:"phase"`
	Stage      string   `json:"stage"`
	Techniques []string `json:"techniques"`
}

// Sequence maps a set of covered technique ids onto the Unified Kill Chain and
// returns the phases that have at least one covered technique, in canonical
// order. It is the engine's "sequencing view": which parts of an intrusion's
// progression the shipped content can observe.
func Sequence(techniqueIDs []string) []PhaseCoverage {
	byPhase := make(map[string][]string)
	for _, id := range techniqueIDs {
		b := ForTechnique(id)
		for _, p := range b.UKCPhases {
			byPhase[p] = append(byPhase[p], id)
		}
	}
	var out []PhaseCoverage
	for _, p := range phaseOrder {
		ids := byPhase[p]
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		out = append(out, PhaseCoverage{Phase: p, Stage: phaseStage[p], Techniques: dedupeStrings(ids)})
	}
	return out
}

// Phases returns the canonical UKC phase sequence (for callers that want to
// render empty phases too).
func Phases() []string { return append([]string(nil), phaseOrder...) }

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

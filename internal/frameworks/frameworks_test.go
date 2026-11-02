package frameworks

import (
	"testing"

	"github.com/cau-edr/cau/internal/attack"
)

func TestForTechniqueSingleTactic(t *testing.T) {
	// T1027 is Defense Evasion → UKC Defense Evasion, Initial Foothold stage.
	b := ForTechnique("T1027")
	if b.UKCPhase != DefenseEvasion {
		t.Errorf("phase = %q, want %q", b.UKCPhase, DefenseEvasion)
	}
	if b.UKCStage != StageInitialFoothold {
		t.Errorf("stage = %q, want %q", b.UKCStage, StageInitialFoothold)
	}
}

func TestForTechniqueMultiTacticPrimaryIsEarliest(t *testing.T) {
	// T1055 is {Defense Evasion, Privilege Escalation}. Defense Evasion comes
	// earlier in the UKC sequence, so it is the primary phase.
	b := ForTechnique("T1055")
	if b.UKCPhase != DefenseEvasion {
		t.Errorf("primary phase = %q, want %q (earliest in sequence)", b.UKCPhase, DefenseEvasion)
	}
	if len(b.UKCPhases) != 2 {
		t.Fatalf("phases = %v, want 2", b.UKCPhases)
	}
	// Ordered by sequence: Defense Evasion before Privilege Escalation.
	if b.UKCPhases[0] != DefenseEvasion || b.UKCPhases[1] != PrivilegeEsc {
		t.Errorf("phase order wrong: %v", b.UKCPhases)
	}
}

func TestForTechniqueUnknown(t *testing.T) {
	b := ForTechnique("T9999")
	if b.UKCPhase != "" || len(b.UKCPhases) != 0 {
		t.Errorf("unknown technique should map to no phase, got %+v", b)
	}
}

func TestEveryCatalogTacticMaps(t *testing.T) {
	// Every tactic the ATT&CK catalog uses must have a UKC phase, or the
	// sequencing view would silently drop coverage.
	for _, id := range attack.IDs() {
		for _, tac := range attack.Tactics(id) {
			if PhaseForTactic(tac) == "" {
				t.Errorf("tactic %q (from %s) has no UKC phase mapping", tac, id)
			}
		}
	}
}

func TestEveryPhaseHasAStage(t *testing.T) {
	for _, p := range Phases() {
		if StageForPhase(p) == "" {
			t.Errorf("phase %q has no stage", p)
		}
	}
}

func TestSequenceIsOrderedAndDeduped(t *testing.T) {
	ids := []string{"T1486", "T1027", "T1059", "T1027"} // Impact, DefEvasion, Execution, dup
	seq := Sequence(ids)
	if len(seq) == 0 {
		t.Fatal("empty sequence")
	}
	// Phases must appear in canonical order: Defense Evasion < Execution < Impact.
	var lastIdx = -1
	for _, pc := range seq {
		idx := phaseIndex[pc.Phase]
		if idx <= lastIdx {
			t.Errorf("phases out of sequence: %q at idx %d after %d", pc.Phase, idx, lastIdx)
		}
		lastIdx = idx
	}
	// T1027 appears once despite being listed twice.
	for _, pc := range seq {
		if pc.Phase == DefenseEvasion {
			count := 0
			for _, id := range pc.Techniques {
				if id == "T1027" {
					count++
				}
			}
			if count != 1 {
				t.Errorf("T1027 appears %d times in its phase, want 1", count)
			}
		}
	}
}

func TestSequenceStagesConsistent(t *testing.T) {
	for _, pc := range Sequence(attack.IDs()) {
		if pc.Stage != StageForPhase(pc.Phase) {
			t.Errorf("phase %q stage %q inconsistent", pc.Phase, pc.Stage)
		}
	}
}

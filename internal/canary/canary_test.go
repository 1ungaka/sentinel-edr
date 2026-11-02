package canary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlantAndCheckIntact(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, err := Plant(dir, 5)
	if err != nil {
		t.Fatalf("plant: %v", err)
	}
	if len(m.Canaries) != 5 {
		t.Fatalf("planted %d, want 5", len(m.Canaries))
	}
	for _, c := range m.Canaries {
		if _, err := os.Stat(c.Path); err != nil {
			t.Errorf("planted file missing: %v", err)
		}
	}
	for _, r := range Check(m) {
		if r.Tripped() {
			t.Errorf("fresh canary tripped: %s (%s)", r.Canary.Path, r.Status)
		}
	}
	if got := Tripped(Check(m)); len(got) != 0 {
		t.Errorf("Tripped on intact set returned %d", len(got))
	}
}

func TestCheckDetectsModification(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, _ := Plant(dir, 3)
	target := m.Canaries[1].Path
	if err := os.WriteFile(target, []byte("encrypted-by-ransomware"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := Check(m)
	var found bool
	for _, r := range results {
		if r.Canary.Path == target {
			found = true
			if r.Status != StatusModified {
				t.Errorf("status = %s, want modified", r.Status)
			}
		} else if r.Tripped() {
			t.Errorf("unrelated canary tripped: %s", r.Canary.Path)
		}
	}
	if !found {
		t.Fatal("modified target not in results")
	}
}

func TestCheckDetectsDeletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, _ := Plant(dir, 2)
	target := m.Canaries[0].Path
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	for _, r := range Check(m) {
		if r.Canary.Path == target && r.Status != StatusDeleted {
			t.Errorf("status = %s, want deleted", r.Status)
		}
	}
}

func TestCheckDetectsMetaChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, _ := Plant(dir, 1)
	target := m.Canaries[0].Path
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	r := Check(m)[0]
	if r.Status != StatusMetaChanged {
		t.Errorf("status = %s, want meta-changed", r.Status)
	}
}

func TestPlantRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	if _, err := Plant(dir, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := Plant(dir, 2); err == nil {
		t.Error("second Plant overwrote an existing set without error")
	}
}

func TestPlantClampsCount(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, err := Plant(dir, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Canaries) != len(decoyNames) {
		t.Errorf("planted %d, want clamp to %d", len(m.Canaries), len(decoyNames))
	}
}

func TestPlantRejectsNonPositive(t *testing.T) {
	if _, err := Plant(t.TempDir(), 0); err == nil {
		t.Error("Plant accepted count 0")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, _ := Plant(dir, 3)
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := WriteManifest(path, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadManifest(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Canaries) != len(m.Canaries) {
		t.Fatalf("round-trip lost canaries: %d != %d", len(got.Canaries), len(m.Canaries))
	}
	for i := range got.Canaries {
		if got.Canaries[i].SHA256 != m.Canaries[i].SHA256 {
			t.Errorf("canary %d digest changed across round-trip", i)
		}
	}
	// A manifest read back must still check clean against the planted files.
	if n := len(Tripped(Check(got))); n != 0 {
		t.Errorf("round-tripped manifest tripped %d canaries", n)
	}
}

func TestReadManifestRejectsBadVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path); err == nil {
		t.Error("accepted an incompatible manifest version")
	}
}

func TestDecoyContentIsRandom(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decoys")
	m, _ := Plant(dir, 2)
	a, _ := os.ReadFile(m.Canaries[0].Path)
	// Two decoys of the same generator must not be identical filler.
	b, _ := os.ReadFile(m.Canaries[1].Path)
	if string(a) == string(b) {
		t.Error("two decoys have identical content")
	}
	if len(a) == 0 {
		t.Error("decoy is empty")
	}
}

func TestSortByPath(t *testing.T) {
	results := []Result{
		{Canary: Canary{Path: "/z"}},
		{Canary: Canary{Path: "/a"}},
		{Canary: Canary{Path: "/m"}},
	}
	got := SortByPath(results)
	if got[0].Canary.Path != "/a" || got[2].Canary.Path != "/z" {
		t.Errorf("SortByPath order wrong: %v", got)
	}
}

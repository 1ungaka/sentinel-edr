//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/canary"
	"github.com/s-b-repo/cau/internal/report"
)

// An emptied manifest is how a set is silenced: it parses, so the tamper state
// used to be cleared and every canary on the host stopped mattering. It must
// raise instead.
func TestDefendEmptiedCanaryManifestRaisesTamper(t *testing.T) {
	h := newDefendHost(t)
	decoys := filepath.Join(h.dir, "decoys")
	m, err := canary.Plant(decoys, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := canary.WriteManifest(h.canary, m); err != nil {
		t.Fatal(err)
	}
	h.extra = []string{"--canary-manifest", h.canary}

	// The control: a healthy host with planted canaries says nothing about them.
	code, out := h.defend(t)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitThreat, out)
	}
	if strings.Contains(out, tamperCanary) {
		t.Errorf("tamper raised on a healthy canary baseline:\n%s", out)
	}

	// Now the baseline is emptied. The same tamper that an unreadable manifest
	// raises has to stay raised: an empty list is not a clean set.
	put(t, h.canary, `{"version":1,"canaries":[]}`)
	code, out = h.defend(t)
	if !strings.Contains(out, tamperCanary) {
		t.Errorf("an emptied canary baseline was accepted quietly (exit %d):\n%s", code, out)
	}
}

// A decoy rewritten while the daemon runs is still reported, so the guard above
// did not turn the layer into a permanent alarm.
func TestDefendCanaryStillReportsATrippedDecoy(t *testing.T) {
	h := newDefendHost(t)
	decoys := filepath.Join(h.dir, "decoys")
	m, err := canary.Plant(decoys, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := canary.WriteManifest(h.canary, m); err != nil {
		t.Fatal(err)
	}
	h.extra = []string{"--canary-manifest", h.canary}
	if err := os.WriteFile(m.Canaries[0].Path, []byte("encrypted-by-ransomware"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := h.defend(t)
	if code != report.ExitThreat || !strings.Contains(out, "canary.modified") {
		t.Errorf("a rewritten decoy was not reported (exit %d):\n%s", code, out)
	}
}

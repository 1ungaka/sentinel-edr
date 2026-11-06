package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/ingest"
)

// TestRemoteEvidenceExpires: an identification is a statement about an address
// at a moment. Addresses are reassigned, so a sensor that stopped writing a
// month ago must not still be putting a peer on this host's watchlist, where it
// confirms incidents and licenses blocks. Before this, `external` was bounded
// by size alone and a claim survived for the daemon's whole uptime.
func TestRemoteEvidenceExpires(t *testing.T) {
	f := newNetFixture(t)
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	f.d.clock = func() time.Time { return now }
	f.d.ingestMaxAge = 24 * time.Hour

	dir := filepath.Join(f.dir, "sensors")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"host":"fw-1","class":"firewall.c2","score":9,"definitive":true,` +
		`"detail":"203.0.113.9 is a team server","peers":["203.0.113.9"]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "fw-1.jsonl"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.ingestPaths = []string{dir}
	// No MaxAge on the reader: the event carries no timestamp, so this test is
	// about how long the claim is HELD, not about parsing it.
	f.d.feeder = ingest.NewReader(ingest.Options{})

	f.d.ingestLayer()
	if w := f.d.watchlist(); w["203.0.113.9"] == "" {
		t.Fatalf("a fresh identification must be on the watchlist, got %v", w)
	}

	// A day and a minute later, with the sensor gone quiet: no ingest pass
	// happens, so the expiry has to hold in watchlist() too.
	now = now.Add(24*time.Hour + time.Minute)
	if w := f.d.watchlist(); len(w) != 0 {
		t.Fatalf("an identification past --ingest-max-age must be dropped, got %v", w)
	}
	f.d.mu.Lock()
	held := len(f.d.external)
	f.d.mu.Unlock()
	if held != 0 {
		t.Errorf("holding %d aged signals; the watchlist read should have pruned them", held)
	}
}

func TestRemoteEvidenceWithoutAnAgeLimitIsKept(t *testing.T) {
	// --ingest-max-age 0 asks for everything to be kept, and the size cap is
	// what still bounds it.
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	held := []externalEvidence{
		{sig: correlate.Signal{Class: "a"}, at: now.Add(-30 * 24 * time.Hour)},
		{sig: correlate.Signal{Class: "b"}, at: now},
	}
	if got := pruneExternal(held, now, 0); len(got) != 2 {
		t.Fatalf("pruneExternal with no age limit dropped %d of 2", 2-len(got))
	}
	if got := pruneExternal(held, now, 24*time.Hour); len(got) != 1 || got[0].sig.Class != "b" {
		t.Fatalf("pruneExternal kept %+v, want only the fresh one", got)
	}
}

func TestExternalEvidenceStaysBounded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	held := make([]externalEvidence, 0, defendMaxExternal+100)
	for i := range defendMaxExternal + 100 {
		held = append(held, externalEvidence{sig: correlate.Signal{Class: fmt.Sprint("c", i)}, at: now})
	}
	got := pruneExternal(held, now, time.Hour)
	if len(got) != defendMaxExternal {
		t.Fatalf("held %d, want the cap of %d", len(got), defendMaxExternal)
	}
	// The newest are what an operator is about to need, so the oldest go.
	if got[len(got)-1].sig.Class != fmt.Sprint("c", defendMaxExternal+99) {
		t.Errorf("the newest signal was dropped: last is %s", got[len(got)-1].sig.Class)
	}
}

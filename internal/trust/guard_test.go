package trust

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/s-b-repo/cau/internal/selftest"
)

// baseline writes a signed-or-unsigned manifest over one resource file and
// returns the manifest path and the resource path.
func baseline(t *testing.T, priv ed25519.PrivateKey, pins map[string]string) (manifest, resource string) {
	t.Helper()
	dir := t.TempDir()
	resource = filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(resource, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: "feed", Path: resource}})
	if err != nil {
		t.Fatal(err)
	}
	m.Pins = pins
	if priv != nil {
		m.Sign(priv)
	}
	manifest = filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(manifest, m); err != nil {
		t.Fatal(err)
	}
	return manifest, resource
}

// A host where nobody recorded a baseline is unverified, not compromised. The
// guard has to say so rather than report drift on everything, or the alert is
// worthless on exactly the hosts that need it most.
func TestGuardWithNoBaselineVerifiesNothing(t *testing.T) {
	g, err := NewGuard(filepath.Join(t.TempDir(), "absent.json"), nil)
	if err != nil {
		t.Fatalf("a missing baseline must not be an error: %v", err)
	}
	if g.Loaded() || g.Signed() {
		t.Error("nothing was recorded, so nothing is loaded or signed")
	}
	reason, err := g.VerifyResource("feed")
	if err != nil || reason != "" {
		t.Errorf("with no baseline there is nothing to report: %q %v", reason, err)
	}
}

func TestGuardAcceptsUntamperedResource(t *testing.T) {
	man, _ := baseline(t, nil, nil)
	g, err := NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Loaded() {
		t.Fatal("baseline should be loaded")
	}
	if g.Signed() {
		t.Error("no key was pinned, so it must not claim to be signed")
	}
	reason, err := g.VerifyResource("feed")
	if err != nil || reason != "" {
		t.Errorf("an untouched resource must verify: %q %v", reason, err)
	}
}

func TestGuardDetectsModifiedResource(t *testing.T) {
	man, res := baseline(t, nil, nil)
	g, err := NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	// What an attacker would do to the feed: empty it.
	if err := os.WriteFile(res, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	reason, err := g.VerifyResource("feed")
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" {
		t.Error("an emptied feed must be reported as drift")
	}
}

func TestGuardDetectsDeletedResource(t *testing.T) {
	man, res := baseline(t, nil, nil)
	g, _ := NewGuard(man, nil)
	if err := os.Remove(res); err != nil {
		t.Fatal(err)
	}
	reason, err := g.VerifyResource("feed")
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" {
		t.Error("a deleted resource must be reported")
	}
}

// A resource the baseline never recorded has not drifted. Saying otherwise
// would make every optional, not-deployed resource look like an attack.
func TestGuardIgnoresUncoveredResource(t *testing.T) {
	man, _ := baseline(t, nil, nil)
	g, _ := NewGuard(man, nil)
	if !g.Covers("feed") {
		t.Error("feed should be covered")
	}
	if g.Covers("rules") {
		t.Error("rules was never recorded")
	}
	reason, err := g.VerifyResource("rules")
	if err != nil || reason != "" {
		t.Errorf("an uncovered resource is not drift: %q %v", reason, err)
	}
}

// The signed case is the only one that resists an attacker who can rewrite the
// baseline as well as the content, so it has to actually verify.
func TestGuardVerifiesSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	man, _ := baseline(t, priv, nil)
	g, err := NewGuard(man, pub)
	if err != nil {
		t.Fatalf("a correctly signed baseline must verify: %v", err)
	}
	if !g.Signed() {
		t.Error("Signed() should be true")
	}
}

func TestGuardRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	man, _ := baseline(t, priv, nil)
	if _, err := NewGuard(man, other); err == nil {
		t.Error("a baseline signed by another key must be refused")
	}
}

// Re-signing a manifest the attacker edited is the attack the signature exists
// to stop: changing a recorded digest must break it.
func TestGuardRejectsEditedSignedBaseline(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	man, _ := baseline(t, priv, nil)

	m, err := selftest.ReadManifest(man)
	if err != nil {
		t.Fatal(err)
	}
	m.Entries[0].SHA256 = "00000000000000000000000000000000000000000000000000000000deadbeef"
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuard(man, pub); err == nil {
		t.Error("editing a digest in a signed baseline must break the signature")
	}
}

// A pin is signed configuration, so tampering with it must break the signature
// just as editing a digest does.
func TestGuardPinsAreSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	man, _ := baseline(t, priv, map[string]string{selftest.PinSIEM: "10.0.0.5"})

	g, err := NewGuard(man, pub)
	if err != nil {
		t.Fatalf("signed baseline with pins must verify: %v", err)
	}
	if got, ok := g.Pin(selftest.PinSIEM); !ok || got != "10.0.0.5" {
		t.Errorf("Pin = %q,%v want 10.0.0.5", got, ok)
	}

	m, _ := selftest.ReadManifest(man)
	m.Pins[selftest.PinSIEM] = "evil.example.com"
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuard(man, pub); err == nil {
		t.Error("redirecting a pinned SIEM address must break the signature")
	}
}

// A manifest with no pins must sign exactly as it did before pins existed, or
// every baseline recorded by an older build stops verifying on upgrade.
func TestUnpinnedManifestSignatureIsUnchanged(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	man, _ := baseline(t, priv, nil)
	m, err := selftest.ReadManifest(man)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Pins) != 0 {
		t.Fatalf("expected no pins, got %v", m.Pins)
	}
	// Force the v1 header the older build would have written and re-verify
	// with the same signature bytes.
	m.Schema = 1
	m.Sign(priv)
	if err := m.VerifySignature(pub); err != nil {
		t.Errorf("a v1 manifest must still verify: %v", err)
	}
}

// The baseline is what every other check is measured against, so it gets the
// same on-disk scrutiny as the files it describes.
func TestGuardRefusesUnsafeBaseline(t *testing.T) {
	man, _ := baseline(t, nil, nil)
	if err := os.Chmod(man, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuard(man, nil); err == nil {
		t.Error("a world-writable baseline must be refused")
	}
}

// VerifyFile asks both questions a daemon needs before reloading a file while
// it runs: is it safe where it sits, and is it what was trusted.
func TestGuardVerifyFileChecksDiskAndContent(t *testing.T) {
	man, res := baseline(t, nil, nil)
	g, _ := NewGuard(man, nil)

	if reason, err := g.VerifyFile("feed", res); err != nil || reason != "" {
		t.Errorf("a good feed must pass: %q %v", reason, err)
	}
	if err := os.Chmod(res, 0o666); err != nil {
		t.Fatal(err)
	}
	if reason, _ := g.VerifyFile("feed", res); reason == "" {
		t.Error("a world-writable feed must be refused even with a matching digest")
	}
}

// A nil guard is what the engine's own tests and any caller without a baseline
// hold, and it must behave like "nothing to verify" rather than panicking.
func TestNilGuardIsSafe(t *testing.T) {
	var g *Guard
	if g.Loaded() || g.Signed() || g.Covers("feed") || g.Path() != "" {
		t.Error("a nil guard should report nothing")
	}
	if _, ok := g.Pin(selftest.PinSIEM); ok {
		t.Error("a nil guard has no pins")
	}
	if reason, err := g.VerifyResource("feed"); reason != "" || err != nil {
		t.Errorf("a nil guard verifies nothing: %q %v", reason, err)
	}
}

// A baseline covers one path. If the agent is pointed at a different file —
// by an edited `feed =` line or a --feed flag — then digesting the baselined
// path proves nothing about the file actually being read, and the check passes
// while the daemon loads somebody else's content.
func TestGuardRefusesRedirectedPath(t *testing.T) {
	man, res := baseline(t, nil, nil)

	other := filepath.Join(filepath.Dir(res), "attacker-feed.txt")
	if err := os.WriteFile(other, []byte("nothing-to-see\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The baselined file is untouched, so a digest of it still matches.
	if reason, err := g.VerifyFile("feed", res); err != nil || reason != "" {
		t.Fatalf("the baselined path must still verify: %q %v", reason, err)
	}
	reason, err := g.VerifyFile("feed", other)
	if err != nil {
		t.Fatal(err)
	}
	if reason == "" {
		t.Error("a path the baseline does not cover must not be reported as verified")
	}
}

package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/s-b-repo/cau/internal/selftest"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A distrusted guard must vouch for nothing, least of all the pins: this is the
// state an attacker reaches on purpose, and a forged manifest's SIEM address must
// not come back out of it.
func TestDistrustedGuardVouchesForNothing(t *testing.T) {
	pub, priv := keyPair(t)
	manifest, resource := baseline(t, priv, map[string]string{selftest.PinSIEM: "siem.example"})
	g := Distrusted(manifest, pub, errors.New("the key is unusable"))

	if g.Loaded() || g.Signed() {
		t.Errorf("loaded=%v signed=%v, want neither", g.Loaded(), g.Signed())
	}
	if v, ok := g.Pin(selftest.PinSIEM); ok {
		t.Errorf("a distrusted baseline vouched for a pin: %q", v)
	}
	if g.Covers("feed") {
		t.Error("a distrusted baseline claims to cover a resource")
	}
	if g.Fault() == nil {
		t.Error("Fault lost the reason")
	}
	if err := os.WriteFile(resource, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Nothing to compare against, so a change is not drift here; the file still
	// has to be safe where it sits.
	if reason, err := g.VerifyFile("feed", resource); reason != "" || err != nil {
		t.Errorf("reason %q, err %v", reason, err)
	}
	if err := os.Chmod(resource, 0o666); err != nil {
		t.Fatal(err)
	}
	if reason, _ := g.VerifyFile("feed", resource); reason == "" {
		t.Error("a world-writable file passed because the baseline is distrusted")
	}
}

// The downgrade this state exists to stop: with the key broken, a reload must
// not turn the manifest on disk into an unsigned baseline that is believed.
func TestRefreshCannotLeaveTheDistrustedState(t *testing.T) {
	_, priv := keyPair(t)
	manifest, _ := baseline(t, priv, map[string]string{selftest.PinSIEM: "siem.example"})
	g := Distrusted(manifest, nil, errors.New("the key is unusable"))
	if err := g.Refresh(); err != nil {
		t.Fatal(err)
	}
	if g.Fault() == nil || g.Loaded() {
		t.Fatalf("fault=%v loaded=%v: a refresh left the distrusted state", g.Fault(), g.Loaded())
	}
}

func TestRecoverPassesOnlyTheCheckThatFailed(t *testing.T) {
	pub, priv := keyPair(t)
	other, _ := keyPair(t)
	manifest, _ := baseline(t, priv, map[string]string{selftest.PinSIEM: "siem.example"})
	g := Distrusted(manifest, nil, errors.New("the key is unusable"))

	// A valid key that did not sign this baseline changes the reason, not the state.
	if err := g.Recover(other); err == nil {
		t.Fatal("a baseline signed by another key recovered")
	}
	if g.Fault() == nil || g.Signed() {
		t.Fatalf("fault=%v signed=%v", g.Fault(), g.Signed())
	}
	if err := g.Recover(pub); err != nil {
		t.Fatal(err)
	}
	if g.Fault() != nil || !g.Signed() {
		t.Fatalf("fault=%v signed=%v after a repair", g.Fault(), g.Signed())
	}
	if v, ok := g.Pin(selftest.PinSIEM); !ok || v != "siem.example" {
		t.Errorf("pin = %q, %v", v, ok)
	}
}

// The feed loop reads the guard while the selftest loop recovers it.
func TestGuardIsSafeAcrossTheDaemonLoops(t *testing.T) {
	pub, priv := keyPair(t)
	manifest, resource := baseline(t, priv, nil)
	g := Distrusted(manifest, nil, errors.New("the key is unusable"))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				_ = g.Refresh()
				_, _ = g.VerifyFile("feed", resource)
				_, _ = g.Pin(selftest.PinSIEM)
				_ = g.Fault()
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				_ = g.Recover(pub)
			}
		}()
	}
	wg.Wait()
	if g.Fault() != nil || !g.Signed() {
		t.Fatalf("fault=%v signed=%v", g.Fault(), g.Signed())
	}
}

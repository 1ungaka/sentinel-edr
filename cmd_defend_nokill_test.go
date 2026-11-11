//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/canary"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
	"github.com/1ungaka/sentinel-edr/internal/trust"
)

const nokillSample = "Test.Bad.Sample"

// defendHost is a small complete install with everything in good order, so each
// case breaks exactly one thing.
type defendHost struct {
	dir, watch, empty                       string
	db, rules, fuzzy, manifest, key, config string
	feed, canary, signKey                   string
	extra                                   []string
}

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newDefendHost(t *testing.T) *defendHost {
	t.Helper()
	dir := t.TempDir()
	h := &defendHost{
		dir: dir, watch: filepath.Join(dir, "watch"), empty: filepath.Join(dir, "empty"),
		db: filepath.Join(dir, "hashes.txt"), rules: filepath.Join(dir, "ok.yar"),
		fuzzy: filepath.Join(dir, "fuzzy.txt"), manifest: filepath.Join(dir, "integrity.json"),
		key: filepath.Join(dir, "pub.hex"), config: filepath.Join(dir, "cau.conf"),
		feed: filepath.Join(dir, "feed.txt"), canary: filepath.Join(dir, "canary.json"),
		// Elsewhere, because a signing key beside its baseline is its own alert.
		signKey: filepath.Join(t.TempDir(), "priv.hex"),
	}
	for _, d := range []string{h.watch, h.empty} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sample := []byte("a file only a hash can name\n")
	put(t, filepath.Join(h.watch, "sample.bin"), string(sample))
	sum := sha256.Sum256(sample)
	put(t, h.db, "SHA256|"+hex.EncodeToString(sum[:])+"|"+nokillSample+"\n")
	put(t, h.rules, "rule ok { condition: false }\n")
	put(t, h.fuzzy, "")
	put(t, h.feed, "203.0.113.9\n")
	put(t, h.config, "report-only = true\n")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	put(t, h.key, hex.EncodeToString(pub)+"\n")
	put(t, h.signKey, hex.EncodeToString(priv.Seed())+"\n")
	if code, _, errOut := runCLI(t, "selftest", "--record", "--sign-key", h.signKey, "--db", h.db,
		"--rules", h.rules, "--fuzzy-db", h.fuzzy, "--manifest", h.manifest); code != report.ExitOK {
		t.Fatalf("recording the baseline: exit %d\n%s", code, errOut)
	}
	return h
}

func (h *defendHost) defend(t *testing.T) (code int, output string) {
	t.Helper()
	args := []string{"defend", "--once", "--report-only", "--no-process", "--no-persistence",
		"--package-interval", "0", "--netblock=false", "--watch", h.watch,
		"--etc-root", h.empty, "--persist-root", h.empty, "--host-root", h.empty,
		// The behaviour inventories read the process table, and the host's
		// real one is a few hundred processes: under the race detector that
		// is seconds of work the test does not need. The fixture is empty,
		// which is what the test means anyway.
		"--proc-root", h.empty,
		"--dpkg-info", h.empty, "--pacman-local", h.empty,
		"--quarantine-store", filepath.Join(h.dir, "vault"), "--kernel-events", filepath.Join(h.dir, "no-events"),
		"--db", h.db, "--rules", h.rules, "--fuzzy-db", h.fuzzy, "--feed", h.feed,
		"--selftest-manifest", h.manifest, "--selftest-pubkey", h.key, "--config", h.config,
		"--format", "json"}
	type result struct {
		code     int
		out, err string
	}
	done := make(chan result, 1)
	go func() {
		code, out, errOut := runCLI(t, append(args, h.extra...)...)
		done <- result{code, out, errOut}
	}()
	select {
	case r := <-done:
		return r.code, r.out + r.err
	case <-time.After(30 * time.Second):
		t.Fatal("cau defend hung on a file, which at startup is a unit that never comes up")
		return 0, ""
	}
}

func plantFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// The rule the daemon lives by: nothing on disk stops it. Each of these used to
// be a refusal to start or a hang, and with Restart= that is a host with no EDR
// for as long as the planted file stays there, for anyone able to plant one.
//
// Staying up is half of it. The other half is that it is never quiet: each case
// has to come out as tamper, and everything the broken file was not needed for
// has to keep working.
func TestNoFileCanStopTheDaemon(t *testing.T) {
	for _, c := range []struct {
		name  string
		brk   func(t *testing.T, h *defendHost)
		class string
		// hashBlind is the one case that really does lose the detection this test
		// looks for, because the sample is only known by its hash.
		hashBlind bool
	}{
		{name: "key is a FIFO", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.key) }},
		{name: "key is garbage", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { put(t, h.key, "not hex\n") }},
		{name: "key is gone", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { os.Remove(h.key) }},
		{name: "key is a directory", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) {
			os.Remove(h.key)
			os.Mkdir(h.key, 0o755)
		}},
		{name: "key is world-writable", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { os.Chmod(h.key, 0o666) }},
		{name: "key signed nothing here", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			put(t, h.key, hex.EncodeToString(pub)+"\n")
		}},
		{name: "baseline is a FIFO", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.manifest) }},
		{name: "baseline is garbage", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { put(t, h.manifest, "{not json") }},
		{name: "baseline is world-writable", class: tamperIntegrity, brk: func(t *testing.T, h *defendHost) { os.Chmod(h.manifest, 0o666) }},
		{name: "config is a FIFO", class: tamperConfig, brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.config) }},
		{name: "config has a bad value", class: tamperConfig, brk: func(t *testing.T, h *defendHost) { put(t, h.config, "respond = nonsense\n") }},
		{name: "config is world-writable", class: tamperConfig, brk: func(t *testing.T, h *defendHost) { os.Chmod(h.config, 0o666) }},
		{name: "config names a forwarder that cannot run", class: tamperForward, brk: func(t *testing.T, h *defendHost) {
			put(t, h.config, "siem = https://wazuh.example:55000\nsiem-password-env = CAU_NOKILL_TEST_UNSET\n")
		}},
		{name: "signatures are a FIFO", class: tamperContent + "signatures", hashBlind: true, brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.db) }},
		{name: "fuzzy database is a FIFO", class: tamperContent + "fuzzy", brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.fuzzy) }},
		{name: "rules are a FIFO", class: tamperContent + "rules", brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.rules) }},
		{name: "feed is a FIFO", class: tamperFeed, brk: func(t *testing.T, h *defendHost) { plantFIFO(t, h.feed) }},
		{name: "canary manifest is a FIFO", class: tamperCanary, brk: func(t *testing.T, h *defendHost) {
			plantFIFO(t, h.canary)
			h.extra = []string{"--canary-manifest", h.canary}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newDefendHost(t)
			c.brk(t, h)
			code, out := h.defend(t)
			if code != report.ExitThreat {
				t.Fatalf("exit %d, want %d: the daemon must run and report\n%s", code, report.ExitThreat, out)
			}
			if !strings.Contains(out, c.class) {
				t.Errorf("no %s in the output, so this was quiet:\n%s", c.class, out)
			}
			if got := strings.Contains(out, nokillSample); got == c.hashBlind {
				t.Errorf("detected the sample: %v, want %v\n%s", got, !c.hashBlind, out)
			}
			if strings.Contains(out, "verified against the pinned key") && c.class == tamperIntegrity {
				t.Errorf("a broken chain of trust was reported as verified:\n%s", out)
			}
		})
	}
}

// The control: without it every case above could pass by tamper being raised on
// a host where nothing was wrong.
func TestAHealthyHostRaisesNoTamper(t *testing.T) {
	h := newDefendHost(t)
	code, out := h.defend(t)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d for the sample\n%s", code, report.ExitThreat, out)
	}
	if strings.Contains(out, "defend.tamper.") || strings.Contains(out, "[TAMPER]") {
		t.Errorf("tamper on a healthy host:\n%s", out)
	}
	if !strings.Contains(out, nokillSample) || !strings.Contains(out, "verified against the pinned key") {
		t.Errorf("want the sample and a verified baseline:\n%s", out)
	}
}

// A mistake typed on the command line is still the one thing that stops it: no
// attacker is at that keyboard, and the operator is.
func TestACommandLineMistakeStillStopsTheDaemon(t *testing.T) {
	t.Setenv("CAU_NOKILL_TEST_UNSET", "")
	h := newDefendHost(t)
	h.extra = []string{"--wazuh-url", "https://wazuh.example:55000", "--wazuh-password-env", "CAU_NOKILL_TEST_UNSET"}
	if code, out := h.defend(t); code != report.ExitUsage {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitUsage, out)
	}
}

func signedBaseline(t *testing.T, dir string) (manifest, feed string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	feed = filepath.Join(dir, "feed.txt")
	put(t, feed, "203.0.113.9\n198.51.100.7\n")
	m, err := selftest.Compute([]selftest.Resource{{Name: selftestResFeed, Path: feed}})
	if err != nil {
		t.Fatal(err)
	}
	m.Sign(priv)
	manifest = filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(manifest, m); err != nil {
		t.Fatal(err)
	}
	return manifest, feed, pub
}

// A running daemon has to come back by itself, because the alternative is a
// restart, which is a window with no EDR on a host somebody is already in.
func TestRepairingTheKeyRestoresTheSignedStateWithoutARestart(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	manifest, _, pub := signedBaseline(t, dir)
	keyFile := filepath.Join(dir, "pub.hex")
	put(t, keyFile, "not hex\n")

	_, keyErr := defendPubkey(keyFile)
	if keyErr == nil {
		t.Fatal("garbage resolved to a key")
	}
	f.d.selftestManifest, f.d.selftestKeyFile, f.d.selftestKeyErr = manifest, keyFile, keyErr
	f.d.guard = trust.Distrusted(manifest, nil, keyErr)
	f.d.distrust(keyErr)

	f.d.selftestLayer()
	if f.d.guard.Fault() == nil || f.d.guard.Signed() {
		t.Fatal("still broken, but no longer distrusted")
	}
	if !hasClass(f.d.cycle(), tamperIntegrity) {
		t.Fatal("the fault was not raised")
	}

	// Another valid key must not pass as the repair: it did not sign this.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	put(t, keyFile, hex.EncodeToString(other)+"\n")
	f.d.selftestLayer()
	if f.d.guard.Fault() == nil || f.d.guard.Signed() {
		t.Fatal("a key that signed nothing here was accepted")
	}

	put(t, keyFile, hex.EncodeToString(pub)+"\n")
	f.d.selftestLayer()
	if f.d.guard.Fault() != nil || !f.d.guard.Signed() {
		t.Fatalf("fault=%v signed=%v after the repair", f.d.guard.Fault(), f.d.guard.Signed())
	}
	if got := integrityState(f.d.guard); got != "signed+verified" {
		t.Errorf("state = %q", got)
	}
}

// Freezing means keeping what was there. At startup nothing was, and an
// unverified feed still detects where none would not.
func TestDistrustedBaselineLoadsAFeedOnceThenFreezesIt(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	manifest, feed, _ := signedBaseline(t, dir)
	f.d.guard, f.d.feedPath = trust.Distrusted(manifest, nil, os.ErrInvalid), feed

	f.d.feedLayer()
	first := f.d.feed.Load()
	if first == nil || first.Count() != 2 {
		t.Fatalf("the first load should proceed: %v", first)
	}
	put(t, feed, "192.0.2.1\n")
	f.d.feedLayer()
	if f.d.feed.Load() != first {
		t.Error("a feed changed while nothing could verify it, and the change was loaded")
	}
}

// With no key the digests are still worth checking: an attacker who breaks the
// key should not get to change the content unseen as well.
func TestBrokenKeyStillReportsDrift(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	manifest, feed, _ := signedBaseline(t, dir)
	keyFile := filepath.Join(dir, "absent.hex")
	_, keyErr := defendPubkey(keyFile)
	f.d.selftestManifest, f.d.selftestKeyFile, f.d.selftestKeyErr = manifest, keyFile, keyErr
	f.d.guard = trust.Distrusted(manifest, nil, keyErr)
	put(t, feed, "192.0.2.1\n")

	f.d.selftestLayer()
	incidents := f.d.cycle()
	for _, class := range []string{tamperIntegrity, "defend.selftest.drift."} {
		if !hasClass(incidents, class) {
			t.Errorf("no %s", class)
		}
	}
}

func TestUnreadableCanaryManifestIsRaisedAndClears(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "canary.json")
	plantFIFO(t, path)
	f.d.canaryManifest = path
	f.d.canaryLayer()
	if !hasClass(f.d.cycle(), tamperCanary) {
		t.Fatal("no canary can trip and nobody was told")
	}
	if f.d.tamperMemo[tamperCanary] == "" {
		t.Fatal("the fault was not remembered")
	}
	os.Remove(path)
	// A manifest Plant could have written: ReadManifest refuses a baseline it
	// can tell was not recorded (an empty canaries list, no CreatedAt), so the
	// hand-written stub that used to sit here is exactly what it rejects — the
	// fault it keeps raised is the correct one, and the readable manifest this
	// test needs is one written through the production path.
	m, err := canary.Plant(filepath.Join(t.TempDir(), "decoys"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := canary.WriteManifest(path, m); err != nil {
		t.Fatal(err)
	}
	f.d.canaryLayer()
	if _, still := f.d.tamperMemo[tamperCanary]; still {
		t.Error("a readable manifest should clear the fault, so a later one alerts again")
	}
	// And the clear is not a latch: once the manifest goes unreadable again the
	// fault is raised again, which is the whole point of clearing it.
	plantFIFO(t, path)
	f.d.canaryLayer()
	if !hasClass(f.d.cycle(), tamperCanary) {
		t.Error("the fault was not raised again once the manifest went unreadable")
	}
}

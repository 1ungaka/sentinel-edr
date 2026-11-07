package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/selftest"
	"github.com/s-b-repo/cau/internal/trust"
)

func boolp(b bool) *bool { return &b }

// Precedence is built-in default, then the configuration file, then the command
// line. The last of those is the one an operator just typed, so it has to win.
func TestConfigDoesNotOverrideAnExplicitFlag(t *testing.T) {
	respond, quarantine, blockExe, netblock, reportOnly := "stop", true, true, true, false
	feed := ""
	cfg := trust.Config{
		Respond: "kill", Quarantine: boolp(false), BlockExe: boolp(false),
		Netblock: boolp(false), ReportOnly: boolp(true), Feed: "/from/config",
	}
	// The operator typed every one of them, so the file changes nothing.
	given := map[string]bool{
		"respond": true, "quarantine": true, "block-exe": true,
		"netblock": true, "report-only": true, "feed": true,
	}
	applyConfigDefaults(cfg, given, &respond, &quarantine, &blockExe, &netblock, &reportOnly, &feed)
	if respond != "stop" || !quarantine || !blockExe || !netblock || reportOnly || feed != "" {
		t.Errorf("an explicit flag must win over the config file: respond=%q q=%v b=%v n=%v ro=%v feed=%q",
			respond, quarantine, blockExe, netblock, reportOnly, feed)
	}
}

func TestConfigFillsWhatWasNotTyped(t *testing.T) {
	respond, quarantine, blockExe, netblock, reportOnly := "stop", true, true, true, false
	feed := ""
	cfg := trust.Config{
		Respond: "kill", Quarantine: boolp(false), BlockExe: boolp(false),
		Netblock: boolp(false), ReportOnly: boolp(true), Feed: "/from/config",
	}
	applyConfigDefaults(cfg, map[string]bool{}, &respond, &quarantine, &blockExe, &netblock, &reportOnly, &feed)
	if respond != "kill" || quarantine || blockExe || netblock || !reportOnly || feed != "/from/config" {
		t.Errorf("the config file should fill in untyped settings, got respond=%q q=%v b=%v n=%v ro=%v feed=%q",
			respond, quarantine, blockExe, netblock, reportOnly, feed)
	}
}

// An absent setting in the file must leave the built-in default alone, rather
// than reading as "false".
func TestEmptyConfigKeepsDefaults(t *testing.T) {
	respond, quarantine, blockExe, netblock, reportOnly := "stop", true, true, true, false
	feed := ""
	applyConfigDefaults(trust.Config{}, map[string]bool{}, &respond, &quarantine, &blockExe, &netblock, &reportOnly, &feed)
	if respond != "stop" || !quarantine || !blockExe || !netblock || reportOnly {
		t.Errorf("an empty config must change nothing, got respond=%q q=%v b=%v n=%v ro=%v",
			respond, quarantine, blockExe, netblock, reportOnly)
	}
}

func TestReportOnlyDisablesEveryAction(t *testing.T) {
	respond, quarantine, blockExe, netblock := "kill", true, true, true
	applyReportOnly(true, &respond, &quarantine, &blockExe, &netblock)
	if respond != "" || quarantine || blockExe || netblock {
		t.Errorf("--report-only must leave nothing armed: respond=%q q=%v b=%v n=%v",
			respond, quarantine, blockExe, netblock)
	}
}

func TestRespondNoneIsTheEmptyAction(t *testing.T) {
	respond, q, b, n := "none", true, true, true
	applyReportOnly(false, &respond, &q, &b, &n)
	if respond != "" {
		t.Errorf("respond=none should normalise to the empty action, got %q", respond)
	}
	// "none" only disables the process response; the rest stay as configured.
	if !q || !b || !n {
		t.Error("respond=none must not disable quarantine or the blocks")
	}
}

// ── where incidents go, and refusing to be redirected ───────────────────────

func siemFixture(t *testing.T, pin string) *fixture {
	t.Helper()
	f := newFixture(t)
	if pin == "" {
		return f
	}
	dir := t.TempDir()
	res := filepath.Join(dir, "cau.conf")
	if err := os.WriteFile(res, []byte("siem = "+pin+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: selftestResConfig, Path: res}})
	if err != nil {
		t.Fatal(err)
	}
	m.Pins = map[string]string{selftest.PinSIEM: pin}
	man := filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	g, err := trust.NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.d.guard = g
	return f
}

func quiet(string, ...interface{}) {}

func TestSIEMFlagWinsOverEverything(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "10.0.0.9")
	got := f.d.resolveSIEM("10.0.0.7", true, trust.Config{SIEM: "10.0.0.5"}, quiet)
	if got != "10.0.0.7" {
		t.Errorf("resolveSIEM = %q, want the flag 10.0.0.7", got)
	}
}

func TestSIEMEnvBeatsConfig(t *testing.T) {
	f := newFixture(t)
	t.Setenv(envSIEM, "10.0.0.9")
	if got := f.d.resolveSIEM("", false, trust.Config{SIEM: "10.0.0.5"}, quiet); got != "10.0.0.9" {
		t.Errorf("resolveSIEM = %q, want the environment 10.0.0.9", got)
	}
}

func TestSIEMFromConfigWhenItMatchesThePin(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "")
	got := f.d.resolveSIEM("", false, trust.Config{SIEM: "10.0.0.5", Path: "/etc/cau/cau.conf"}, quiet)
	if got != "10.0.0.5" {
		t.Errorf("resolveSIEM = %q, want 10.0.0.5", got)
	}
	if inc := f.d.cycle(); len(inc) != 0 {
		t.Errorf("a config that matches its pin must raise nothing, got %+v", inc)
	}
}

// The attack this pin exists for: rewrite one line of the config and the agent
// both stops telling the real SIEM and starts telling yours.
func TestTamperedSIEMIsIgnoredAndRaised(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "")
	got := f.d.resolveSIEM("", false, trust.Config{SIEM: "evil.example.com", Path: "/etc/cau/cau.conf"}, quiet)
	if got != "10.0.0.5" {
		t.Errorf("resolveSIEM = %q, want the pinned 10.0.0.5, not the edited address", got)
	}
	incidents := f.d.cycle()
	if !hasClass(incidents, "defend.tamper.siem-redirected") {
		t.Fatalf("a redirected SIEM address must be raised, got %+v", incidents)
	}
	for _, inc := range incidents {
		for _, s := range inc.Signals {
			if s.Class == "defend.tamper.siem-redirected" && !inc.Confirmed {
				t.Error("a signed-baseline mismatch is a fact about the host, so it should confirm on its own")
			}
		}
	}
}

// Deleting the address is the quieter version of the same attack.
func TestRemovedSIEMFallsBackToThePinAndIsRaised(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "")
	if got := f.d.resolveSIEM("", false, trust.Config{Path: "/etc/cau/cau.conf"}, quiet); got != "10.0.0.5" {
		t.Errorf("resolveSIEM = %q, want the pinned 10.0.0.5", got)
	}
	if !hasClass(f.d.cycle(), "defend.tamper.siem-removed") {
		t.Error("removing the SIEM address must be raised")
	}
}

// With no pin recorded there is nothing to compare against, so the configured
// address is simply used. An unverified host must not look like an attacked one.
func TestUnpinnedSIEMIsUsedAsConfigured(t *testing.T) {
	f := newFixture(t)
	t.Setenv(envSIEM, "")
	if got := f.d.resolveSIEM("", false, trust.Config{SIEM: "10.0.0.5"}, quiet); got != "10.0.0.5" {
		t.Errorf("resolveSIEM = %q, want 10.0.0.5", got)
	}
	if inc := f.d.cycle(); len(inc) != 0 {
		t.Errorf("no pin means nothing to report, got %+v", inc)
	}
}

// ── the threat feed, which is the cheapest thing to blind ───────────────────

// feedLayer must not install a feed that does not match the baseline, and must
// keep serving the last good one: an attacker who can corrupt the file should
// be able to freeze the intel layer, loudly, not switch it off.
func TestTamperedFeedIsRefusedAndLastGoodKept(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: selftestResFeed, Path: feed}})
	if err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	g, err := trust.NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.d.guard, f.d.feedPath = g, feed

	f.d.feedLayer()
	good := f.d.feed.Load()
	if good == nil || good.Count() != 2 {
		t.Fatalf("the baselined feed should load, got %v", good)
	}

	// Empty it, as an attacker silencing every intel verdict would.
	if err := os.WriteFile(feed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()

	if now := f.d.feed.Load(); now != good {
		t.Error("a feed that fails its integrity check must not replace the last good one")
	}
	if !hasClass(f.d.cycle(), "defend.tamper.feed") {
		t.Error("a tampered feed must be raised as an incident")
	}
}

// Without a baseline the feed still has to load, or adding integrity checking
// would silently disable intel on every host that never recorded one.
func TestFeedLoadsWithNoBaseline(t *testing.T) {
	f := newFixture(t)
	feed := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedPath = feed
	f.d.feedLayer()
	if got := f.d.feed.Load(); got == nil || got.Count() == 0 {
		t.Error("with no baseline the feed should load as before")
	}
}

// A feed anyone can rewrite is refused on its permissions alone, before its
// contents are even considered.
func TestWorldWritableFeedIsRefused(t *testing.T) {
	f := newFixture(t)
	feed := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Explicitly, because the umask would turn a 0o666 create into 0664 and
	// test group- rather than world-writable.
	if err := os.Chmod(feed, 0o666); err != nil {
		t.Fatal(err)
	}
	f.d.feedPath = feed
	f.d.feedLayer()
	if f.d.feed.Load() != nil {
		t.Error("a world-writable feed must not be loaded")
	}
	if !hasClass(f.d.cycle(), "defend.tamper.feed") {
		t.Error("a world-writable feed must be raised")
	}
}

// ── a pinned key that cannot be used must not become "no key" ───────────────

// The pinned key is the only thing that resists an attacker who rewrites the
// content and rebaselines the manifest to match, and it is also what vouches
// for the pinned SIEM address. If an unreadable or malformed key quietly meant
// "digest check only", corrupting one file would downgrade the agent from the
// strong state to the weak one with every later log line still looking healthy.
func TestUnusablePinnedKeyIsAnError(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent.hex")
	if _, err := resolveSelftestPubkey(missing); err == nil {
		t.Error("an unreadable pinned key must be an error, not a silent downgrade")
	}

	garbage := filepath.Join(dir, "garbage.hex")
	if err := os.WriteFile(garbage, []byte("not hex at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSelftestPubkey(garbage); err == nil {
		t.Error("a malformed pinned key must be an error")
	}

	short := filepath.Join(dir, "short.hex")
	if err := os.WriteFile(short, []byte("abcd"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSelftestPubkey(short); err == nil {
		t.Error("a key of the wrong length must be an error")
	}
}

// The same applies to the environment, which is how the service unit supplies it.
func TestUnusablePinnedKeyFromEnvIsAnError(t *testing.T) {
	t.Setenv(envSelftestKey, "nonsense")
	if _, err := resolveSelftestPubkey(""); err == nil {
		t.Errorf("a malformed $%s must be an error", envSelftestKey)
	}
}

// Asking for no key at all is not a failure: most hosts have no baseline, and
// an unsigned digest check is a legitimate state the agent reports honestly.
func TestNoPinnedKeyIsNotAnError(t *testing.T) {
	t.Setenv(envSelftestKey, "")
	key, err := resolveSelftestPubkey("")
	if err != nil {
		t.Fatalf("no key requested must not be an error: %v", err)
	}
	if key.set {
		t.Error("no key was asked for, so none should be set")
	}
}

// hasClass reports whether any incident carries a signal of this class.
func hasClass(incidents []correlate.Incident, class string) bool {
	for _, inc := range incidents {
		for _, s := range inc.Signals {
			if strings.HasPrefix(s.Class, class) {
				return true
			}
		}
	}
	return false
}

// F2: an emptied feed must not silently replace a populated one, even with no
// baseline to catch it by digest. That is how the intel layer goes quiet.
func TestEmptiedFeedDoesNotReplaceAGoodOne(t *testing.T) {
	f := newFixture(t)
	feed := filepath.Join(t.TempDir(), "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedPath = feed
	f.d.feedLayer()
	good := f.d.feed.Load()
	if good == nil || good.Count() != 2 {
		t.Fatalf("the feed should load, got %v", good)
	}
	if err := os.WriteFile(feed, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()
	if f.d.feed.Load() != good {
		t.Error("an empty feed must not replace a populated one")
	}
	if !hasClass(f.d.cycle(), tamperFeed) {
		t.Error("an emptied feed must be raised")
	}
}

// F4: a resource that is tampered with, fixed, then tampered with again must
// alert both times. The incident fingerprint is identical every time, so
// without state tracking everything after the first raise is swallowed.
func TestRepeatTamperAlertsAgainAfterRecovery(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	original := []byte("1.2.3.4\n5.6.7.8\n")
	if err := os.WriteFile(feed, original, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: selftestResFeed, Path: feed}})
	if err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	g, err := trust.NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.d.guard, f.d.feedPath = g, feed

	f.d.feedLayer()
	f.d.cycle() // clean

	// First tamper.
	if err := os.WriteFile(feed, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()
	if !hasClass(f.d.cycle(), tamperFeed) {
		t.Fatal("the first tamper must be raised")
	}

	// Put it back as the baseline describes it: the state is clean again.
	if err := os.WriteFile(feed, original, 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()
	f.d.cycle()

	// Tamper again. This is the raise that used to be swallowed for the rest of
	// the daemon's life.
	if err := os.WriteFile(feed, []byte("8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.d.feedLayer()
	if !hasClass(f.d.cycle(), tamperFeed) {
		t.Error("a second tamper after recovery must be raised again, not suppressed")
	}
}

// F3's other half: re-recording the baseline has to take effect without a
// restart, or an operator who updates the feed and re-records is still told
// their feed is tampered with until they bounce the service.
func TestRebaselinedFeedIsAcceptedWithoutRestart(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record := func() {
		m, err := selftest.Compute([]selftest.Resource{{Name: selftestResFeed, Path: feed}})
		if err != nil {
			t.Fatal(err)
		}
		if err := selftest.WriteManifest(filepath.Join(dir, "integrity.json"), m); err != nil {
			t.Fatal(err)
		}
	}
	record()
	g, err := trust.NewGuard(filepath.Join(dir, "integrity.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.d.guard, f.d.feedPath = g, feed
	f.d.feedLayer()
	if got := f.d.feed.Load(); got == nil || got.Count() != 1 {
		t.Fatalf("the baselined feed should load, got %v", got)
	}

	// A legitimate update: more indicators, and the baseline re-recorded, with
	// no restart in between.
	if err := os.WriteFile(feed, []byte("1.2.3.4\n5.6.7.8\n7.7.7.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record()
	f.d.feedLayer()
	if got := f.d.feed.Load(); got == nil || got.Count() != 3 {
		t.Fatalf("a re-recorded feed must be accepted without a restart, got %v", got)
	}
	if hasClass(f.d.cycle(), tamperFeed) {
		t.Error("a legitimate re-recorded update must not be reported as tampering")
	}
}

// ── weaknesses: guarantees that are not actually in force ───────────────────

// Overriding the pinned SIEM address from the environment is the one way left
// to redirect the stream without the config digest changing. The override is
// honoured, because it is operator intent, but it must never be silent.
func TestOverridingThePinnedSIEMIsReported(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "attacker.example.com")
	got := f.d.resolveSIEM("", false, trust.Config{SIEM: "10.0.0.5", Path: "/etc/cau/cau.conf"}, quiet)
	if got != "attacker.example.com" {
		t.Errorf("resolveSIEM = %q; an explicit override should still win", got)
	}
	incidents := f.d.cycle()
	if !hasClass(incidents, weakSIEMOverridden) {
		t.Fatalf("setting the pin aside must be reported, got %+v", incidents)
	}
	// It is a misconfiguration, not an attack: it must not confirm, because a
	// confirmed incident is one the daemon would act on.
	for _, inc := range incidents {
		for _, s := range inc.Signals {
			if s.Class == weakSIEMOverridden {
				if inc.Confirmed {
					t.Error("a weakness must not confirm on its own")
				}
				if s.Live {
					t.Error("a weakness is not live state")
				}
			}
		}
	}
}

// An override that matches the pin is not a weakness at all.
func TestOverrideMatchingThePinIsQuiet(t *testing.T) {
	f := siemFixture(t, "10.0.0.5")
	t.Setenv(envSIEM, "10.0.0.5")
	if got := f.d.resolveSIEM("", false, trust.Config{SIEM: "10.0.0.5"}, quiet); got != "10.0.0.5" {
		t.Errorf("resolveSIEM = %q", got)
	}
	if hasClass(f.d.cycle(), weakSIEMOverridden) {
		t.Error("an override equal to the pin is not a weakness")
	}
}

// With no pin recorded there is nothing being set aside, so an override is
// simply configuration.
func TestOverrideWithoutAPinIsQuiet(t *testing.T) {
	f := newFixture(t)
	t.Setenv(envSIEM, "10.0.0.9")
	if got := f.d.resolveSIEM("", false, trust.Config{}, quiet); got != "10.0.0.9" {
		t.Errorf("resolveSIEM = %q", got)
	}
	if hasClass(f.d.cycle(), weakSIEMOverridden) {
		t.Error("no pin means no weakness to report")
	}
}

// A weakness is reported once per state, like a tamper, so a long-running
// daemon does not repeat it every cycle.
func TestWeaknessIsReportedOncePerState(t *testing.T) {
	f := newFixture(t)
	f.d.weakness(weakSIEMInsecureTLS, "https://a", "first")
	if !hasClass(f.d.cycle(), weakSIEMInsecureTLS) {
		t.Fatal("the first report must be raised")
	}
	f.d.weakness(weakSIEMInsecureTLS, "https://a", "same state")
	if hasClass(f.d.cycle(), weakSIEMInsecureTLS) {
		t.Error("an unchanged weakness must not be repeated")
	}
	f.d.weakness(weakSIEMInsecureTLS, "https://b", "changed")
	if !hasClass(f.d.cycle(), weakSIEMInsecureTLS) {
		t.Error("a changed weakness must be raised again")
	}
}

// ── the certificate pin: who may answer at the pinned address ───────────────

// certPinFixture baselines a config carrying a cert pin, and signs the pin
// value into the manifest the way `cau selftest --record` does.
func certPinFixture(t *testing.T, pin string) *fixture {
	t.Helper()
	f := newFixture(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "cau.conf")
	if err := os.WriteFile(conf, []byte("siem = 10.0.0.5\nsiem-cert-pin = "+pin+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := selftest.Compute([]selftest.Resource{{Name: selftestResConfig, Path: conf}})
	if err != nil {
		t.Fatal(err)
	}
	m.Pins = map[string]string{selftest.PinSIEM: "10.0.0.5", selftest.PinSIEMCert: pin}
	man := filepath.Join(dir, "integrity.json")
	if err := selftest.WriteManifest(man, m); err != nil {
		t.Fatal(err)
	}
	g, err := trust.NewGuard(man, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.d.guard = g
	return f
}

func TestCertPinFromConfigIsUsedWhenItMatchesThePin(t *testing.T) {
	const pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	f := certPinFixture(t, pin)
	got := f.d.resolveCertPins(trust.Config{SIEMCertPins: []string{pin}, Path: "/etc/cau/cau.conf"}, quiet)
	if len(got) != 1 || got[0] != pin {
		t.Errorf("resolveCertPins = %v, want [%s]", got, pin)
	}
	if inc := f.d.cycle(); len(inc) != 0 {
		t.Errorf("a matching pin must raise nothing, got %+v", inc)
	}
}

// Swapping the pin for your own collector's is the other half of the redirect
// the address pin closes, so the signed value has to win.
func TestSwappedCertPinUsesTheBaselinedOne(t *testing.T) {
	const good = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const evil = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	f := certPinFixture(t, good)
	got := f.d.resolveCertPins(trust.Config{SIEMCertPins: []string{evil}, Path: "/etc/cau/cau.conf"}, quiet)
	if len(got) != 1 || got[0] != good {
		t.Errorf("resolveCertPins = %v, want the baselined [%s]", got, good)
	}
	if !hasClass(f.d.cycle(), "defend.tamper.siem-cert-pin-changed") {
		t.Error("a changed certificate pin must be raised")
	}
}

// Deleting the pin is the quieter version: it would let any certificate the
// host trusts receive the incidents again.
func TestRemovedCertPinUsesTheBaselinedOne(t *testing.T) {
	const good = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	f := certPinFixture(t, good)
	got := f.d.resolveCertPins(trust.Config{Path: "/etc/cau/cau.conf"}, quiet)
	if len(got) != 1 || got[0] != good {
		t.Errorf("resolveCertPins = %v, want the baselined [%s]", got, good)
	}
	if !hasClass(f.d.cycle(), "defend.tamper.siem-cert-pin-removed") {
		t.Error("a removed certificate pin must be raised")
	}
}

// With nothing pinned in the baseline the configured value is simply used: an
// unverified host must not look like an attacked one.
func TestCertPinWithoutABaselineIsUsedAsConfigured(t *testing.T) {
	f := newFixture(t)
	const pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got := f.d.resolveCertPins(trust.Config{SIEMCertPins: []string{pin}}, quiet)
	if len(got) != 1 || got[0] != pin {
		t.Errorf("resolveCertPins = %v, want [%s]", got, pin)
	}
	if inc := f.d.cycle(); len(inc) != 0 {
		t.Errorf("no baseline means nothing to report, got %+v", inc)
	}
}

// A pipe where the public key belongs is refused outright rather than waited on.
//
// `cau defend` resolves the key at startup, before it signals readiness. A pipe
// held open by a silent writer made that read wait 120.1s, against systemd's
// 90s default TimeoutStartSec — so the unit was killed as a failed start and
// restarted into the same wall. An attacker with write access to the directory
// holding the public key had a kill switch needing no edit to the unit file or
// the flags. Pipes stay allowed for --sign-key, where the point is keeping a
// secret off disk; a public key is not a secret and $CAU_SELFTEST_PUBKEY
// already supplies one without a file.
func TestPinnedKeyFromAPipeIsRefusedNotAwaited(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pub.hex")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// A writer that opens and then says nothing: the case that waited.
	w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer w.Close()
	}

	done := make(chan error, 1)
	go func() {
		_, err := resolveSelftestPubkey(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a pipe is not a public key file; it must be refused")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("resolveSelftestPubkey waited on a pipe: at daemon startup that is a failed start, and on retry a kill switch")
	}
}

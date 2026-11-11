package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// hwidSysfs writes a synthetic sysfs where every anchor reads ok: a DMI
// table, one physical NIC with a permanent address, one virtual interface, a
// TPM with PCR 0-7 and an active hardware RNG. Nothing here reads /sys.
func hwidSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, v := range map[string]string{
		"class/dmi/id/sys_vendor":             "LENOVO",
		"class/dmi/id/product_name":           "20XW0055GE",
		"class/dmi/id/product_uuid":           "4c4c4544-0042-3510-8052-b4c04f4a4b32",
		"class/dmi/id/product_serial":         "PF2ABCDE",
		"class/dmi/id/board_vendor":           "LENOVO",
		"class/dmi/id/board_name":             "20XW0055GE",
		"class/dmi/id/board_serial":           "L1HF1A2B3C4",
		"class/dmi/id/chassis_serial":         "CH-0042",
		"class/dmi/id/bios_vendor":            "LENOVO",
		"class/dmi/id/bios_version":           "N32ET75W",
		"class/dmi/id/bios_date":              "12/02/2021",
		"class/net/eth0/address":              "30:13:8b:8d:37:0e",
		"class/net/eth0/addr_assign_type":     "0",
		"class/net/eth0/device":               "",
		"devices/virtual/net/docker0/address": "02:42:ac:11:00:01",
		"class/tpm/tpm0/tpm_version_major":    "2",
		"class/misc/hw_random/rng_current":    "tpm-rng-0",
		"class/misc/hw_random/rng_available":  "tpm-rng-0 none",
		"class/net/bonding_masters":           "",
	} {
		hwidWrite(t, root, rel, v+"\n")
	}
	for i := 0; i < 8; i++ {
		hwidWrite(t, root, fmt.Sprintf("class/tpm/tpm0/pcr-sha256/%d", i), fmt.Sprintf("%064X\n", 0xA0+i))
	}
	if err := os.Symlink("../../devices/virtual/net/docker0", filepath.Join(root, "class/net/docker0")); err != nil {
		t.Fatal(err)
	}
	return root
}

func hwidWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runHwid calls the command directly, the way the dispatcher will.
func runHwid(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = cmdHwid(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHwidTextOutput(t *testing.T) {
	root := hwidSysfs(t)
	code, out, errOut := runHwid("--sysfs", root)
	if code != report.ExitOK || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Sysfs       : " + root,
		"product_uuid    ok          4c4c4544-0042-3510-8052-b4c04f4a4b32",
		"product_serial  ok          PF2ABCDE",
		"Interfaces  : 1 physical, 1 virtual",
		"30:13:8b:8d:37:0e  (permanent, addr_assign_type 0)",
		"virtual (not compared): docker0",
		"TPM         : present, version 2",
		"PCR 0 (sha256) : " + strings.Repeat("0", 62) + "a0",
		"PCR 7 (sha256) : " + strings.Repeat("0", 62) + "a7",
		"quote       : not captured.",
		"/dev/tpm0",
		"Entropy     : hardware RNG tpm-rng-0 (available: tpm-rng-0)",
		// Even this host cannot show a quote, and the report says so.
		"Unverifiable: 1 anchor(s) this host could not prove in this run",
		"tpm.quote",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	for _, never := range []string{"MAC CHANGED", "Baseline", "Verdict", "Not inspected"} {
		if strings.Contains(out, never) {
			t.Errorf("text output contains %q:\n%s", never, out)
		}
	}
}

// A host that can prove little says so field by field. Nothing is padded.
func TestHwidDegradedHostIsLabelled(t *testing.T) {
	root := hwidSysfs(t)
	os.RemoveAll(filepath.Join(root, "class/tpm"))
	os.RemoveAll(filepath.Join(root, "class/dmi/id/chassis_serial"))
	hwidWrite(t, root, "class/dmi/id/board_serial", "Default string\n")
	hwidWrite(t, root, "class/dmi/id/product_uuid", "00000000-0000-0000-0000-000000000000\n")
	hwidWrite(t, root, "class/misc/hw_random/rng_current", "none\n")
	hwidWrite(t, root, "class/net/eth0/addr_assign_type", "3\n")
	unreadable := os.Geteuid() != 0
	if unreadable {
		if err := os.Chmod(filepath.Join(root, "class/dmi/id/product_serial"), 0o000); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errOut := runHwid("--sysfs", root)
	if code != report.ExitOK {
		t.Fatalf("a degraded host is not a failed run: exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"chassis_serial  absent",
		`board_serial    placeholder "Default string": not an identity`,
		"product_uuid    placeholder",
		"TPM         : absent: no class/tpm/tpm0: this host exposes no TPM",
		"Entropy     : hardware RNG none.",
		"software entropy",
		// The MAC-change signal, and what sysfs cannot say about it.
		"(set-by-userspace, addr_assign_type 3)  MAC CHANGED",
		"1 interface(s) carry an address set by userspace",
		"does not expose the",
		"not from what",
		"ethtool ioctl",
		"net.eth0.permanent_address",
		"dmi.board_serial",
		"  rng  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	wantCount := 7 // chassis, board, uuid, NIC, tpm, quote, rng
	if unreadable {
		wantCount++
		if !strings.Contains(out, "product_serial  unreadable  permission denied; reading this needs root") {
			t.Errorf("an unreadable serial is not labelled unreadable:\n%s", out)
		}
	}
	if want := fmt.Sprintf("Unverifiable: %d anchor(s)", wantCount); !strings.Contains(out, want) {
		t.Errorf("text output lacks %q:\n%s", want, out)
	}
}

func TestHwidJSONShape(t *testing.T) {
	root := hwidSysfs(t)
	hwidWrite(t, root, "class/net/eth0/addr_assign_type", "3\n")
	code, out, errOut := runHwid("--format", "json", "--sysfs", root)
	if code != report.ExitOK || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	var snap struct {
		Schema     int    `json:"schema"`
		CapturedAt string `json:"captured_at"`
		Sysfs      string `json:"sysfs"`
		Redacted   *bool  `json:"redacted"`
		DMI        map[string]struct {
			State, Value, Reason string
		} `json:"dmi"`
		Interfaces []struct {
			Name       string `json:"name"`
			Address    struct{ State, Value string }
			AssignType struct{ State, Value string }         `json:"addr_assign_type"`
			Assignment string                                `json:"assignment"`
			Permanent  struct{ State, Value, Reason string } `json:"permanent_address"`
			Divergence *bool                                 `json:"permanent_mac_divergence"`
		} `json:"interfaces"`
		Virtual []struct{ Name, Why string } `json:"virtual_interfaces"`
		TPM     struct {
			State        string                        `json:"state"`
			VersionMajor struct{ State, Value string } `json:"version_major"`
			PCRBank      string                        `json:"pcr_bank"`
			PCRs         []struct {
				Index        *int `json:"index"`
				State, Value string
			} `json:"pcrs"`
			Quote struct{ Status, Reason string } `json:"quote"`
		} `json:"tpm"`
		RNG struct {
			State, Current string
			Available      []string
		} `json:"rng"`
		Unverifiable []struct{ Anchor, State, Reason string } `json:"unverifiable"`
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		t.Fatalf("the JSON does not have the documented shape: %v\n%s", err, out)
	}
	if snap.Schema != 1 || snap.CapturedAt == "" || snap.Sysfs != root || snap.Redacted == nil || *snap.Redacted {
		t.Errorf("header: %+v", snap)
	}
	if len(snap.DMI) != 11 || snap.DMI["product_uuid"].State != "ok" || snap.DMI["product_uuid"].Value != "4c4c4544-0042-3510-8052-b4c04f4a4b32" {
		t.Errorf("dmi: %+v", snap.DMI)
	}
	if len(snap.Interfaces) != 1 {
		t.Fatalf("interfaces: %+v", snap.Interfaces)
	}
	eth := snap.Interfaces[0]
	if eth.Name != "eth0" || eth.Address.Value != "30:13:8b:8d:37:0e" || eth.AssignType.Value != "3" || eth.Assignment != "set-by-userspace" ||
		eth.Divergence == nil || !*eth.Divergence || eth.Permanent.State != "unreadable" || eth.Permanent.Value != "" || eth.Permanent.Reason == "" {
		t.Errorf("eth0: %+v", eth)
	}
	if len(snap.Virtual) != 1 || snap.Virtual[0].Name != "docker0" || snap.Virtual[0].Why != "under devices/virtual" {
		t.Errorf("virtual: %+v", snap.Virtual)
	}
	if snap.TPM.State != "ok" || snap.TPM.VersionMajor.Value != "2" || snap.TPM.PCRBank != "sha256" || len(snap.TPM.PCRs) != 8 ||
		snap.TPM.PCRs[7].Index == nil || *snap.TPM.PCRs[7].Index != 7 || len(snap.TPM.PCRs[7].Value) != 64 {
		t.Errorf("tpm: %+v", snap.TPM)
	}
	if snap.TPM.Quote.Status != "not captured" || snap.TPM.Quote.Reason == "" {
		t.Errorf("quote: %+v", snap.TPM.Quote)
	}
	if snap.RNG.State != "ok" || snap.RNG.Current != "tpm-rng-0" || len(snap.RNG.Available) != 1 {
		t.Errorf("rng: %+v", snap.RNG)
	}
	got := []string{}
	for _, u := range snap.Unverifiable {
		got = append(got, u.Anchor+"="+u.State)
	}
	if want := "net.eth0.permanent_address=unreadable tpm.quote=not-captured"; strings.Join(got, " ") != want {
		t.Errorf("unverifiable = %v, want %s", got, want)
	}
}

func TestHwidUsageErrors(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")
	for name, args := range map[string][]string{
		"bad format":       {"--sysfs", root, "--format", "xml"},
		"positional":       {"--sysfs", root, "extra"},
		"unknown flag":     {"--sysfs", root, "--quote"},
		"record and check": {"--sysfs", root, "--record", base, "--check", base},
		"force alone":      {"--sysfs", root, "--force"},
		"empty sysfs":      {"--sysfs", ""},
		"missing value":    {"--record"},
	} {
		code, out, errOut := runHwid(args...)
		if code != report.ExitUsage {
			t.Errorf("%s: exit %d, want %d\n%s", name, code, report.ExitUsage, errOut)
		}
		if out != "" {
			t.Errorf("%s: a usage error printed a report:\n%s", name, out)
		}
		if errOut == "" {
			t.Errorf("%s: no message on stderr", name)
		}
	}
	if _, err := os.Stat(base); err == nil {
		t.Error("a usage error wrote a baseline")
	}

	var usage bytes.Buffer
	hwidUsage(&usage)
	for _, want := range []string{"Usage: cau hwid", "--sysfs", "--format", "--redact", "--record", "--force", "--check",
		"not-reverified", "not-in-baseline", "entropy-source-changed", "No TPM quote is captured", "ethtool ioctl",
		"Exit codes: 0 ok, 1 identity changed", "4 usage"} {
		if !strings.Contains(usage.String(), want) {
			t.Errorf("usage text lacks %q", want)
		}
	}
}

func TestHwidRunFailed(t *testing.T) {
	root := hwidSysfs(t)
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	os.WriteFile(corrupt, []byte(`{"schema": 1, "dmi": {"sys_vendor": {"state": "veri`), 0o600)
	wrongSchema := filepath.Join(dir, "schema.json")
	os.WriteFile(wrongSchema, []byte(`{"schema": 99, "dmi": {}}`), 0o600)
	notSnapshot := filepath.Join(dir, "other.json")
	os.WriteFile(notSnapshot, []byte(`{"hello": "world"}`), 0o600)
	notSysfs := t.TempDir()

	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"sysfs missing":     {[]string{"--sysfs", filepath.Join(dir, "nope")}, "sysfs root"},
		"sysfs not a sysfs": {[]string{"--sysfs", notSysfs}, "not a sysfs tree"},
		"sysfs is a file":   {[]string{"--sysfs", corrupt}, "not a directory"},
		"baseline missing":  {[]string{"--sysfs", root, "--check", filepath.Join(dir, "nope.json")}, "no such file"},
		"baseline corrupt":  {[]string{"--sysfs", root, "--check", corrupt}, "not a snapshot"},
		"baseline schema":   {[]string{"--sysfs", root, "--check", wrongSchema}, "schema 99"},
		"baseline other":    {[]string{"--sysfs", root, "--check", notSnapshot}, "schema 0"},
		"baseline is a dir": {[]string{"--sysfs", root, "--check", dir}, "not a regular file"},
		"record no dir":     {[]string{"--sysfs", root, "--record", filepath.Join(dir, "no", "such", "base.json")}, "could not create"},
	} {
		code, out, errOut := runHwid(c.args...)
		if code != report.ExitRunFailed {
			t.Errorf("%s: exit %d, want %d\n%s\n%s", name, code, report.ExitRunFailed, out, errOut)
		}
		if !strings.HasPrefix(errOut, "[ERROR] ") || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: stderr %q lacks %q", name, errOut, c.want)
		}
		// A failed run must not print something that reads as a result.
		if out != "" {
			t.Errorf("%s: a failed run printed a report:\n%s", name, out)
		}
	}
}

func TestHwidRecordWritesBaselineOnce(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")

	code, out, errOut := runHwid("--sysfs", root, "--record", base)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "baseline written to "+base) || !strings.Contains(out, "product_serial  ok") {
		t.Errorf("record output:\n%s\n%s", out, errOut)
	}
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("baseline mode %o, want 600", fi.Mode().Perm())
	}
	first, _ := os.ReadFile(base)
	if !json.Valid(first) || !strings.Contains(string(first), `"schema": 1`) || !strings.Contains(string(first), "PF2ABCDE") {
		t.Fatalf("baseline content:\n%s", first)
	}

	// A second record must not replace it.
	hwidWrite(t, root, "class/dmi/id/product_serial", "PF9ZZZZZ\n")
	code, out, errOut = runHwid("--sysfs", root, "--record", base)
	if code != report.ExitRunFailed || !strings.Contains(errOut, "already exists") || !strings.Contains(errOut, "--force") || out != "" {
		t.Errorf("overwrite without --force: exit %d\n%s\n%s", code, out, errOut)
	}
	if now, _ := os.ReadFile(base); !bytes.Equal(now, first) {
		t.Error("the existing baseline was modified without --force")
	}

	// With --force it is replaced, and is 0600 whatever it was before.
	os.Chmod(base, 0o644)
	code, _, errOut = runHwid("--sysfs", root, "--record", base, "--force")
	if code != report.ExitOK {
		t.Fatalf("--force: exit %d\n%s", code, errOut)
	}
	now, _ := os.ReadFile(base)
	if !strings.Contains(string(now), "PF9ZZZZZ") || strings.Contains(string(now), "PF2ABCDE") {
		t.Errorf("--force did not replace the baseline:\n%s", now)
	}
	if fi, _ := os.Stat(base); fi.Mode().Perm() != 0o600 {
		t.Errorf("replaced baseline mode %o, want 600", fi.Mode().Perm())
	}
	// Nothing else is left beside it.
	entries, _ := os.ReadDir(filepath.Dir(base))
	if len(entries) != 1 {
		t.Errorf("%d files beside the baseline, want only the baseline", len(entries))
	}
}

// --record never writes through a symbolic link: without --force the link is
// refused, with --force the link itself is replaced.
func TestHwidRecordDoesNotFollowLinks(t *testing.T) {
	root := hwidSysfs(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep me\n"), 0o644)
	link := filepath.Join(dir, "base.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "dangling.json")
	os.Symlink(filepath.Join(dir, "created-through-a-link"), dangling)

	for _, path := range []string{link, dangling} {
		if code, _, errOut := runHwid("--sysfs", root, "--record", path); code != report.ExitRunFailed {
			t.Errorf("record onto a link: exit %d\n%s", code, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "created-through-a-link")); err == nil {
		t.Error("a baseline was created through a dangling link")
	}
	if code, _, errOut := runHwid("--sysfs", root, "--record", link, "--force"); code != report.ExitOK {
		t.Fatalf("--force onto a link: exit %d\n%s", code, errOut)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep me\n" {
		t.Errorf("the link target was overwritten: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the link was not replaced by the baseline: %v", fi)
	}
}

func TestHwidCheckEqual(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")
	if code, _, errOut := runHwid("--sysfs", root, "--record", base); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	code, out, errOut := runHwid("--sysfs", root, "--check", base)
	if code != report.ExitOK || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"Baseline    : " + base + " (captured ",
		"Differences : 0 changed, 0 could not be re-verified, 0 not in the baseline, 0 entropy source",
		"Verdict     : no identity change among the anchors that could be compared",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "IDENTITY CHANGED") || strings.Contains(out, "Note        :") {
		t.Errorf("an equal check reports a difference:\n%s", out)
	}

	code, out, _ = runHwid("--sysfs", root, "--check", base, "--format", "json")
	var rep struct {
		Baseline           string            `json:"baseline"`
		BaselineCapturedAt string            `json:"baseline_captured_at"`
		IdentityChanged    *bool             `json:"identity_changed"`
		Differences        []json.RawMessage `json:"differences"`
		Snapshot           struct {
			Schema int `json:"schema"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != report.ExitOK || rep.Baseline != base || rep.BaselineCapturedAt == "" || rep.IdentityChanged == nil || *rep.IdentityChanged ||
		rep.Differences == nil || len(rep.Differences) != 0 || rep.Snapshot.Schema != 1 {
		t.Errorf("exit %d, check JSON: %s", code, out)
	}
	if !strings.Contains(out, `"differences": []`) {
		t.Errorf("no differences must encode as [], not null:\n%s", out)
	}
}

func TestHwidCheckChanged(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")
	if code, _, errOut := runHwid("--sysfs", root, "--record", base); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	// Another board, another boot chain, and a NIC whose MAC was changed.
	hwidWrite(t, root, "class/dmi/id/product_uuid", "11111111-2222-3333-4444-555555555555\n")
	hwidWrite(t, root, "class/dmi/id/board_serial", "L1HF9Z9Z9Z9\n")
	hwidWrite(t, root, "class/tpm/tpm0/pcr-sha256/0", strings.Repeat("ab", 32)+"\n")
	hwidWrite(t, root, "class/net/eth0/addr_assign_type", "3\n")
	hwidWrite(t, root, "class/net/eth0/address", "02:de:ad:be:ef:01\n")

	code, out, errOut := runHwid("--sysfs", root, "--check", base)
	if code != report.ExitThreat {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, report.ExitThreat, out, errOut)
	}
	for _, want := range []string{
		"Differences : 4 changed, 0 could not be re-verified",
		"[changed] dmi.product_uuid",
		"baseline 4c4c4544-0042-3510-8052-b4c04f4a4b32, now 11111111-2222-3333-4444-555555555555",
		"[changed] dmi.board_serial",
		"[changed] net.eth0.permanent_address",
		"baseline 30:13:8b:8d:37:0e, now 02:de:ad:be:ef:01",
		"addr_assign_type went from 0 (permanent) to 3 (set by userspace)",
		"[changed] tpm.pcr.0",
		"A firmware update, a boot-configuration change and a boot-chain implant all do this",
		"Verdict     : IDENTITY CHANGED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = runHwid("--sysfs", root, "--check", base, "--format", "json")
	var rep struct {
		IdentityChanged bool `json:"identity_changed"`
		Differences     []struct {
			Kind          string `json:"kind"`
			Anchor        string `json:"anchor"`
			BaselineState string `json:"baseline_state"`
			CurrentState  string `json:"current_state"`
			Baseline      string `json:"baseline"`
			Current       string `json:"current"`
			Detail        string `json:"detail"`
		} `json:"differences"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != report.ExitThreat || !rep.IdentityChanged || len(rep.Differences) != 4 {
		t.Fatalf("exit %d, check JSON: %s", code, out)
	}
	d := rep.Differences[0]
	if d.Kind != "changed" || d.Anchor != "dmi.product_uuid" || d.BaselineState != "ok" || d.CurrentState != "ok" ||
		d.Baseline != "4c4c4544-0042-3510-8052-b4c04f4a4b32" || d.Current != "11111111-2222-3333-4444-555555555555" || d.Detail == "" {
		t.Errorf("first difference: %+v", d)
	}
}

// What could not be read again is printed, is not "changed", and does not
// change the exit code. The text says so.
func TestHwidCheckNotReverifiedKeepsExitZero(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")
	if code, _, errOut := runHwid("--sysfs", root, "--record", base); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	os.Remove(filepath.Join(root, "class/dmi/id/board_serial"))
	hwidWrite(t, root, "class/dmi/id/chassis_serial", "Default string\n")
	hwidWrite(t, root, "class/misc/hw_random/rng_current", "none\n")
	want := []string{
		"[not-reverified] dmi.board_serial",
		"could not be re-verified: now absent",
		"[not-reverified] dmi.chassis_serial",
		"could not be re-verified: now placeholder",
		"[entropy-source-changed] rng",
		"baseline tpm-rng-0, now none",
		"Verdict     : no identity change among the anchors that could be compared",
		"do not affect the exit code",
		"it may be unchanged, and this run",
	}
	count := "Differences : 0 changed, 2 could not be re-verified, 0 not in the baseline, 1 entropy source"
	if os.Geteuid() != 0 {
		os.Chmod(filepath.Join(root, "class/dmi/id/product_uuid"), 0o000)
		want = append(want, "[not-reverified] dmi.product_uuid", "could not be re-verified: now unreadable (permission denied")
		count = "Differences : 0 changed, 3 could not be re-verified, 0 not in the baseline, 1 entropy source"
	}
	code, out, errOut := runHwid("--sysfs", root, "--check", base)
	if code != report.ExitOK {
		t.Fatalf("exit %d: an anchor that could not be re-read changed the exit code\n%s\n%s", code, out, errOut)
	}
	for _, w := range append(want, count) {
		if !strings.Contains(out, w) {
			t.Errorf("text output lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "[changed]") || strings.Contains(out, "IDENTITY CHANGED") {
		t.Errorf("an unreadable anchor was reported as changed:\n%s", out)
	}

	// A real change next to them still decides the exit code.
	hwidWrite(t, root, "class/dmi/id/product_serial", "PF9ZZZZZ\n")
	if code, out, _ := runHwid("--sysfs", root, "--check", base); code != report.ExitThreat || !strings.Contains(out, "[changed] dmi.product_serial") {
		t.Errorf("exit %d with a changed serial:\n%s", code, out)
	}
}

func TestHwidRedact(t *testing.T) {
	root := hwidSysfs(t)
	secrets := []string{"4c4c4544-0042-3510-8052-b4c04f4a4b32", "PF2ABCDE", "L1HF1A2B3C4", "CH-0042", "30:13:8b:8d:37:0e"}

	for _, format := range []string{"text", "json"} {
		code, out, errOut := runHwid("--sysfs", root, "--redact", "--format", format)
		if code != report.ExitOK {
			t.Fatalf("%s: exit %d\n%s", format, code, errOut)
		}
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s: redacted output still contains %q", format, s)
			}
		}
		// printf %s PF2ABCDE | sha256sum
		if !strings.Contains(out, "sha256:") || !strings.Contains(out, "LENOVO") {
			t.Errorf("%s: redacted output:\n%s", format, out)
		}
	}

	dir := t.TempDir()
	redacted, plain := filepath.Join(dir, "redacted.json"), filepath.Join(dir, "plain.json")
	if code, _, errOut := runHwid("--sysfs", root, "--redact", "--record", redacted); code != report.ExitOK {
		t.Fatalf("record redacted: exit %d\n%s", code, errOut)
	}
	if code, _, errOut := runHwid("--sysfs", root, "--record", plain); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}
	raw, _ := os.ReadFile(redacted)
	for _, s := range secrets {
		if strings.Contains(string(raw), s) {
			t.Errorf("the redacted baseline contains %q", s)
		}
	}
	if !strings.Contains(string(raw), `"redacted": true`) {
		t.Errorf("the redacted baseline is not marked:\n%s", raw)
	}

	// Redacted against redacted compares, and still sees a change.
	if code, out, errOut := runHwid("--sysfs", root, "--redact", "--check", redacted); code != report.ExitOK || !strings.Contains(out, "0 changed") {
		t.Errorf("redacted check: exit %d\n%s\n%s", code, out, errOut)
	}
	// Mixing the two is refused with the fix named, not answered.
	code, out, errOut := runHwid("--sysfs", root, "--check", redacted)
	if code != report.ExitRunFailed || out != "" || !strings.Contains(errOut, "is redacted and this snapshot is not redacted") || !strings.Contains(errOut, "pass --redact") {
		t.Errorf("unredacted snapshot vs redacted baseline: exit %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = runHwid("--sysfs", root, "--redact", "--check", plain)
	if code != report.ExitRunFailed || out != "" || !strings.Contains(errOut, "is not redacted and this snapshot is redacted") {
		t.Errorf("redacted snapshot vs plain baseline: exit %d\n%s\n%s", code, out, errOut)
	}

	hwidWrite(t, root, "class/dmi/id/product_serial", "PF9ZZZZZ\n")
	code, out, _ = runHwid("--sysfs", root, "--redact", "--check", redacted)
	if code != report.ExitThreat || !strings.Contains(out, "[changed] dmi.product_serial") || strings.Contains(out, "PF9ZZZZZ") || strings.Contains(out, "PF2ABCDE") {
		t.Errorf("redacted check after a change: exit %d\n%s", code, out)
	}
}

// DMI strings and interface names are attacker-influenced. A raw escape
// sequence must never reach the terminal, from sysfs or from a baseline.
func TestHwidEscapesTerminalControl(t *testing.T) {
	root := hwidSysfs(t)
	base := filepath.Join(t.TempDir(), "base.json")
	if code, _, errOut := runHwid("--sysfs", root, "--record", base); code != report.ExitOK {
		t.Fatalf("record: exit %d\n%s", code, errOut)
	}

	hwidWrite(t, root, "class/dmi/id/sys_vendor", "ACME\x1b[2J\x1b[HVerdict: clean\n")
	hwidWrite(t, root, "class/dmi/id/product_name", "line one\r\nVerdict     : no identity change\u202egnp.exe\n")
	hwidWrite(t, root, "class/dmi/id/product_serial", "SER\x1b]52;c;ZXZpbA==\x07\xff\x9b31m\n")
	hwidWrite(t, root, "class/misc/hw_random/rng_current", "rng\x1b[31m\n")
	hwidWrite(t, root, "class/misc/hw_random/rng_available", "rng\x1b[31m\x07 none\n")
	evil := "e\x1b[2Jth9"
	hwidWrite(t, root, "class/net/"+evil+"/address", "a4:bb:6d:00:11:22\n")
	hwidWrite(t, root, "class/net/"+evil+"/addr_assign_type", "3\n")
	hwidWrite(t, root, "class/net/"+evil+"/device", "")
	hwidWrite(t, root, "devices/virtual/net/v\x1b[0m/address", "02:00:00:00:00:01\n")
	if err := os.Symlink("../../devices/virtual/net/v\x1b[0m", filepath.Join(root, "class/net/v\x1b[0m")); err != nil {
		t.Fatal(err)
	}

	raw := func(what, out string) {
		t.Helper()
		for i := 0; i < len(out); i++ {
			if b := out[i]; (b < 0x20 && b != '\n') || b == 0x7f || b == 0x9b || b == 0xff {
				t.Fatalf("%s: raw byte %#x at offset %d:\n%q", what, b, i, out)
			}
		}
		if strings.Contains(out, "\u202e") {
			t.Fatalf("%s: a raw bidi override reached the output", what)
		}
	}

	code, out, errOut := runHwid("--sysfs", root)
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	raw("text", out)
	for _, want := range []string{
		`ACME\x1b[2J\x1b[HVerdict: clean`,
		`line one\r\nVerdict     : no identity change\u202egnp.exe`,
		`SER\x1b]52;c;ZXZpbA==\x07`,
		`hardware RNG rng\x1b[31m (available: rng\x1b[31m\x07)`,
		`e\x1b[2Jth9`,
		`net.e\x1b[2Jth9.permanent_address`,
		`virtual (not compared): docker0, v\x1b[0m`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks the escaped form %q:\n%s", want, out)
		}
	}
	// The forged verdict stayed inside its own line.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Verdict") {
			t.Errorf("a DMI value forged a report line: %q", line)
		}
	}

	// The comparison prints both sides of a difference: escaped too.
	code, out, errOut = runHwid("--sysfs", root, "--check", base)
	if code != report.ExitThreat {
		t.Fatalf("check: exit %d\n%s\n%s", code, out, errOut)
	}
	raw("check text", out)
	if !strings.Contains(out, `baseline LENOVO, now ACME\x1b[2J\x1b[HVerdict: clean`) {
		t.Errorf("check output lacks the escaped difference:\n%s", out)
	}
	verdicts := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Verdict") {
			verdicts++
			if line != "Verdict     : IDENTITY CHANGED" {
				t.Errorf("forged verdict line: %q", line)
			}
		}
	}
	if verdicts != 1 {
		t.Errorf("%d verdict lines, want 1:\n%s", verdicts, out)
	}

	// A baseline recorded from the hostile tree, read back and printed.
	hostile := filepath.Join(t.TempDir(), "hostile.json")
	if code, _, errOut := runHwid("--sysfs", root, "--record", hostile); code != report.ExitOK {
		t.Fatalf("record hostile: exit %d\n%s", code, errOut)
	}
	if data, _ := os.ReadFile(hostile); true {
		raw("baseline file", strings.ReplaceAll(string(data), "\u202e", ""))
	}
	clean := hwidSysfs(t)
	code, out, errOut = runHwid("--sysfs", clean, "--check", hostile)
	if code != report.ExitThreat {
		t.Fatalf("check against a hostile baseline: exit %d\n%s\n%s", code, out, errOut)
	}
	raw("check against a hostile baseline", out)
	if !strings.Contains(out, `baseline ACME\x1b[2J\x1b[HVerdict: clean, now LENOVO`) {
		t.Errorf("a hostile baseline value was not shown escaped:\n%s", out)
	}

	// JSON escapes by encoding; it must be valid and hold no raw escape.
	code, out, _ = runHwid("--sysfs", root, "--format", "json")
	if code != report.ExitOK || !json.Valid([]byte(out)) {
		t.Fatalf("json: exit %d\n%s", code, out)
	}
	raw("json", strings.ReplaceAll(out, "\u202e", ""))
	if !strings.Contains(out, `ACME\u001b[2J`) {
		t.Errorf("json lacks the encoded value:\n%s", out)
	}

	// An error message naming a hostile path is escaped as well.
	code, _, errOut = runHwid("--sysfs", root, "--check", filepath.Join(t.TempDir(), "no\x1b[2Jne.json"))
	if code != report.ExitRunFailed {
		t.Errorf("exit %d", code)
	}
	raw("stderr", errOut)
	code, _, errOut = runHwid("--sysfs", filepath.Join(t.TempDir(), "sy\x1b[2Js"))
	if code != report.ExitRunFailed {
		t.Errorf("exit %d", code)
	}
	raw("stderr", errOut)
}

// The scan reads. Run against a tree, it must leave the tree exactly as it
// was, and write nothing but the file named with --record.
func TestHwidScanWritesNothing(t *testing.T) {
	root := hwidSysfs(t)
	list := func() string {
		var sb strings.Builder
		filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err == nil {
				fmt.Fprintf(&sb, "%s %s %d %d\n", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
			}
			return nil
		})
		return sb.String()
	}
	before := list()
	cwd := t.TempDir()
	t.Chdir(cwd)
	for _, args := range [][]string{{"--sysfs", root}, {"--sysfs", root, "--format", "json"}, {"--sysfs", root, "--redact"}} {
		if code, _, errOut := runHwid(args...); code != report.ExitOK {
			t.Fatalf("%v: exit %d\n%s", args, code, errOut)
		}
	}
	if after := list(); after != before {
		t.Errorf("the scan changed the tree it read:\n%s\n%s", before, after)
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Errorf("the scan left %d files in the working directory", len(entries))
	}
}

// The one test that touches the real host: whatever this machine has, the
// command completes and labels what it could not read.
func TestHwidRealHost(t *testing.T) {
	if fi, err := os.Stat("/sys/class"); err != nil || !fi.IsDir() {
		t.Skip("no /sys/class on this host")
	}
	code, out, errOut := runHwid()
	if code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"Sysfs       : /sys", "DMI/SMBIOS  :", "Interfaces  :", "TPM         :", "quote       : not captured", "Entropy     :", "Unverifiable:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	t.Logf("cau hwid on this host:\n%s", out)
}

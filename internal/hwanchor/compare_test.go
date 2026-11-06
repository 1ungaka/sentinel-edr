package hwanchor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// kinds is the difference list as "kind anchor", in order.
func kinds(diffs []Difference) []string {
	out := []string{}
	for _, d := range diffs {
		out = append(out, string(d.Kind)+" "+d.Anchor)
	}
	return out
}

func compare(t *testing.T, baseline, current *Snapshot) []Difference {
	t.Helper()
	diffs, err := Compare(baseline, current)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if diffs == nil {
		t.Fatal("Compare returned nil, want an empty list")
	}
	return diffs
}

func TestCompareEqual(t *testing.T) {
	tr := fullTree(t)
	a, b := capture(t, tr), capture(t, tr)
	if diffs := compare(t, a, b); len(diffs) != 0 || IdentityChanged(diffs) {
		t.Errorf("two snapshots of one tree differ: %v", kinds(diffs))
	}
	// A baseline survives being saved and loaded.
	raw, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, a) {
		t.Errorf("Parse(Marshal(s)) != s\n%+v\n%+v", loaded, a)
	}
	if diffs := compare(t, loaded, b); len(diffs) != 0 {
		t.Errorf("a loaded baseline differs from its own tree: %v", kinds(diffs))
	}
}

func TestCompareChanged(t *testing.T) {
	tr := fullTree(t)
	base := capture(t, tr)

	tr.write(dmiDir+"product_uuid", "11111111-2222-3333-4444-555555555555\n")
	tr.write(dmiDir+"product_serial", "PF9ZZZZZ\n")
	tr.write(dmiDir+"board_serial", "L1HF9Z9Z9Z9\n")
	tr.write(tpmDir+"pcr-sha256/0", strings.Repeat("ab", 32)+"\n")
	tr.write(tpmDir+"pcr-sha256/7", strings.Repeat("cd", 32)+"\n")
	diffs := compare(t, base, capture(t, tr))

	want := []string{"changed dmi.product_uuid", "changed dmi.product_serial", "changed dmi.board_serial", "changed tpm.pcr.0", "changed tpm.pcr.7"}
	if got := kinds(diffs); !reflect.DeepEqual(got, want) {
		t.Fatalf("differences = %v\nwant          %v", got, want)
	}
	if !IdentityChanged(diffs) {
		t.Error("IdentityChanged = false")
	}
	d := diffs[0]
	if d.Baseline != testUUID || d.Current != "11111111-2222-3333-4444-555555555555" || d.BaselineState != StateOK || d.CurrentState != StateOK || d.Detail == "" {
		t.Errorf("product_uuid difference: %+v", d)
	}
	// A PCR change is reported without claiming a cause.
	if !strings.Contains(diffs[3].Detail, "firmware update") || !strings.Contains(diffs[3].Detail, "does not say which") {
		t.Errorf("PCR detail: %s", diffs[3].Detail)
	}
}

// Unreadable today against ok in the baseline is "could not be re-verified":
// it is not "changed", and it is not silence.
func TestCompareNotReverified(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	tr := fullTree(t)
	base := capture(t, tr)
	os.Chmod(tr.path(dmiDir+"product_uuid"), 0o000)
	tr.remove(dmiDir + "board_serial")
	tr.write(dmiDir+"product_serial", "To Be Filled By O.E.M.\n")
	tr.remove(tpmDir + "pcr-sha256/4")
	diffs := compare(t, base, capture(t, tr))

	want := []string{"not-reverified dmi.product_uuid", "not-reverified dmi.product_serial", "not-reverified dmi.board_serial", "not-reverified tpm.pcr.4"}
	if got := kinds(diffs); !reflect.DeepEqual(got, want) {
		t.Fatalf("differences = %v\nwant          %v", got, want)
	}
	if IdentityChanged(diffs) {
		t.Error("an anchor that could not be read was reported as a changed identity")
	}
	d := diffs[0]
	if d.Baseline != testUUID || d.Current != "" || d.CurrentState != StateUnreadable || !strings.Contains(d.Detail, "could not be re-verified") {
		t.Errorf("product_uuid difference: %+v", d)
	}
	if diffs[1].CurrentState != StatePlaceholder || diffs[2].CurrentState != StateAbsent {
		t.Errorf("states: %+v", diffs)
	}

	// The other direction: readable now, nothing in the baseline.
	back := compare(t, capture(t, tr), base)
	want = []string{"not-in-baseline dmi.product_uuid", "not-in-baseline dmi.product_serial", "not-in-baseline dmi.board_serial", "not-in-baseline tpm.pcr.4"}
	if got := kinds(back); !reflect.DeepEqual(got, want) {
		t.Errorf("reverse differences = %v", got)
	}
	if IdentityChanged(back) {
		t.Error("an anchor with no baseline was reported as a changed identity")
	}
}

// A placeholder is not an identity and is never compared as one, even
// against a different placeholder.
func TestComparePlaceholderNeverCompared(t *testing.T) {
	tr := fullTree(t)
	tr.write(dmiDir+"board_serial", "Default string\n")
	tr.write(dmiDir+"product_uuid", "00000000-0000-0000-0000-000000000000\n")
	base := capture(t, tr)
	tr.write(dmiDir+"board_serial", "To Be Filled By O.E.M.\n")
	tr.write(dmiDir+"product_uuid", "ffffffff-ffff-ffff-ffff-ffffffffffff\n")
	cur := capture(t, tr)
	if base.DMI["board_serial"].Value == cur.DMI["board_serial"].Value {
		t.Fatal("the fixture does not differ")
	}
	if diffs := compare(t, base, cur); len(diffs) != 0 {
		t.Errorf("two placeholders were compared: %v", kinds(diffs))
	}
	// Placeholder against absent or unreadable: still nothing to say.
	tr.remove(dmiDir + "board_serial")
	if diffs := compare(t, base, capture(t, tr)); len(diffs) != 0 {
		t.Errorf("placeholder vs absent: %v", kinds(diffs))
	}
}

func TestCompareInterfaces(t *testing.T) {
	// Permanent in the baseline, set by userspace now: the MAC was changed.
	tr := fullTree(t)
	base := capture(t, tr)
	tr.write(eth0Dir+"addr_assign_type", "3\n")
	tr.write(eth0Dir+"address", "02:de:ad:be:ef:01\n")
	spoofed := capture(t, tr)
	diffs := compare(t, base, spoofed)
	if got := kinds(diffs); !reflect.DeepEqual(got, []string{"changed net.eth0.permanent_address"}) {
		t.Fatalf("0 -> 3: %v", got)
	}
	d := diffs[0]
	if d.Baseline != testMAC || d.Current != "02:de:ad:be:ef:01" || !strings.Contains(d.Detail, "0 (permanent) to 3 (set by userspace)") {
		t.Errorf("0 -> 3 difference: %+v", d)
	}

	// The other way round the baseline never held a permanent address.
	if got := kinds(compare(t, spoofed, base)); !reflect.DeepEqual(got, []string{"not-in-baseline net.eth0.permanent_address"}) {
		t.Errorf("3 -> 0: %v", got)
	}
	// Set by userspace on both sides: nothing comparable, whatever the MAC.
	tr.write(eth0Dir+"address", "02:de:ad:be:ef:02\n")
	if got := kinds(compare(t, spoofed, capture(t, tr))); len(got) != 0 {
		t.Errorf("3 -> 3 with a different address: %v", got)
	}

	// Permanent on both sides and different: other hardware under the name.
	tr = fullTree(t)
	tr.write(eth0Dir+"address", "a4:bb:6d:00:11:22\n")
	if got := kinds(compare(t, base, capture(t, tr))); !reflect.DeepEqual(got, []string{"changed net.eth0.permanent_address"}) {
		t.Errorf("0 -> 0 with a different address: %v", got)
	}

	// Permanent, then random: not the permanent one any more, and not the
	// userspace-set signal either.
	tr = fullTree(t)
	tr.write(eth0Dir+"addr_assign_type", "1\n")
	if got := kinds(compare(t, base, capture(t, tr))); !reflect.DeepEqual(got, []string{"not-reverified net.eth0.permanent_address"}) {
		t.Errorf("0 -> 1: %v", got)
	}

	// The NIC is gone, and a new one appeared.
	tr = fullTree(t)
	tr.remove("class/net/eth0")
	tr.write("class/net/enp3s0/address", "a4:bb:6d:00:11:22\n")
	tr.write("class/net/enp3s0/addr_assign_type", "0\n")
	tr.mkdir("class/net/enp3s0/device")
	diffs = compare(t, base, capture(t, tr))
	want := []string{"not-in-baseline net.enp3s0.permanent_address", "not-reverified net.eth0.permanent_address"}
	if got := kinds(diffs); !reflect.DeepEqual(got, want) {
		t.Errorf("NIC swapped: %v", got)
	}
	if IdentityChanged(diffs) {
		t.Error("an unplugged NIC was reported as a changed identity")
	}

	// A virtual interface is never compared.
	tr = fullTree(t)
	tr.write("devices/virtual/net/docker0/address", "02:42:ac:11:00:01\n")
	tr.link("class/net/docker0", "../../devices/virtual/net/docker0")
	if got := kinds(compare(t, base, capture(t, tr))); len(got) != 0 {
		t.Errorf("a new virtual interface is a difference: %v", got)
	}
}

func TestCompareTPMAndRNG(t *testing.T) {
	tr := fullTree(t)
	base := capture(t, tr)

	// The TPM is gone: one line, not one per PCR, and not "changed".
	tr.remove("class/tpm")
	gone := capture(t, tr)
	if got := kinds(compare(t, base, gone)); !reflect.DeepEqual(got, []string{"not-reverified tpm"}) {
		t.Errorf("TPM removed: %v", got)
	}
	if got := kinds(compare(t, gone, base)); !reflect.DeepEqual(got, []string{"not-in-baseline tpm"}) {
		t.Errorf("TPM added: %v", got)
	}
	if got := kinds(compare(t, gone, gone)); len(got) != 0 {
		t.Errorf("no TPM on either side: %v", got)
	}

	tr = fullTree(t)
	tr.write(tpmDir+"tpm_version_major", "1\n")
	if got := kinds(compare(t, base, capture(t, tr))); !reflect.DeepEqual(got, []string{"changed tpm.version_major"}) {
		t.Errorf("TPM version: %v", got)
	}

	// The entropy source is health, not identity: reported, never "changed".
	tr = fullTree(t)
	tr.write(rngDir+"rng_current", "none\n")
	diffs := compare(t, base, capture(t, tr))
	if got := kinds(diffs); !reflect.DeepEqual(got, []string{"entropy-source-changed rng"}) {
		t.Fatalf("RNG lost: %v", got)
	}
	if IdentityChanged(diffs) || !strings.Contains(diffs[0].Detail, "degraded") || diffs[0].Baseline != "tpm-rng-0" || diffs[0].Current != "none" {
		t.Errorf("RNG lost: %+v", diffs[0])
	}
	tr.write(rngDir+"rng_current", "virtio_rng.0\n")
	diffs = compare(t, base, capture(t, tr))
	if got := kinds(diffs); !reflect.DeepEqual(got, []string{"entropy-source-changed rng"}) || IdentityChanged(diffs) {
		t.Errorf("RNG switched: %v", got)
	}
}

func TestCompareRefusals(t *testing.T) {
	s := capture(t, fullTree(t))
	if _, err := Compare(nil, s); err == nil {
		t.Error("nil baseline accepted")
	}
	if _, err := Compare(s, nil); err == nil {
		t.Error("nil snapshot accepted")
	}
	old := s.clone()
	old.Schema = SchemaVersion + 1
	if _, err := Compare(old, s); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Errorf("schema mismatch: %v", err)
	}
}

func TestRedact(t *testing.T) {
	tr := fullTree(t)
	tr.write(dmiDir+"chassis_serial", "Default string\n")
	plain := capture(t, tr)
	before, _ := Marshal(plain)
	red := Redact(plain)

	// The input is untouched.
	if after, _ := Marshal(plain); string(after) != string(before) || plain.Redacted {
		t.Fatal("Redact modified its input")
	}
	if !red.Redacted {
		t.Error("the copy is not marked redacted")
	}

	sum := sha256.Sum256([]byte(testUUID))
	wantUUID := "sha256:" + hex.EncodeToString(sum[:])[:16]
	if got := red.DMI["product_uuid"]; got.State != StateOK || got.Value != wantUUID {
		t.Errorf("product_uuid = %+v, want %s", got, wantUUID)
	}
	for _, name := range []string{"product_uuid", "product_serial", "board_serial"} {
		v := red.DMI[name].Value
		if !isRedactedValue(v) || len(v) != len("sha256:")+16 {
			t.Errorf("%s = %q, want sha256: and 16 hex characters", name, v)
		}
	}
	// Not machine-identifying: left readable.
	for _, name := range []string{"sys_vendor", "product_name", "bios_version", "board_name"} {
		if red.DMI[name] != plain.DMI[name] {
			t.Errorf("%s was changed by Redact: %+v", name, red.DMI[name])
		}
	}
	// A placeholder identifies nothing and stays what it is.
	if got := red.DMI["chassis_serial"]; got.State != StatePlaceholder || got.Value != "Default string" {
		t.Errorf("placeholder after Redact: %+v", got)
	}
	eth := iface(t, red, "eth0")
	if !isRedactedValue(eth.Address.Value) || eth.PermanentAddress.Value != eth.Address.Value {
		t.Errorf("eth0 after Redact: %+v", eth)
	}
	// PCRs are measurements, not serials.
	if !reflect.DeepEqual(red.TPM.PCRs, plain.TPM.PCRs) {
		t.Error("PCR values were redacted")
	}

	// No raw identifier survives anywhere in the encoded snapshot.
	raw, err := Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testUUID, "PF2ABCDE", "L1HF1A2B3C4", testMAC} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the redacted snapshot still contains %q", secret)
		}
	}

	// Idempotent: a digest is never hashed again.
	if again := Redact(red); !reflect.DeepEqual(again, red) {
		t.Error("Redact(Redact(s)) != Redact(s)")
	}
	if Redact(nil) != nil {
		t.Error("Redact(nil) != nil")
	}
}

func TestRedactedSnapshotsCompare(t *testing.T) {
	tr := fullTree(t)
	base := Redact(capture(t, tr))

	// Round trip through the baseline format, then compare with a fresh
	// redacted snapshot of the same tree.
	raw, err := Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if diffs := compare(t, loaded, Redact(capture(t, tr))); len(diffs) != 0 {
		t.Errorf("two redacted snapshots of one tree differ: %v", kinds(diffs))
	}

	// A real change is still seen through the digests.
	tr.write(dmiDir+"product_serial", "PF9ZZZZZ\n")
	tr.write(eth0Dir+"addr_assign_type", "3\n")
	diffs := compare(t, loaded, Redact(capture(t, tr)))
	want := []string{"changed dmi.product_serial", "changed net.eth0.permanent_address"}
	if got := kinds(diffs); !reflect.DeepEqual(got, want) {
		t.Fatalf("differences = %v", got)
	}
	for _, d := range diffs {
		if !isRedactedValue(d.Baseline) || !isRedactedValue(d.Current) {
			t.Errorf("a difference between redacted snapshots carries a raw value: %+v", d)
		}
	}
}

func TestCompareRefusesRedactedWithUnredacted(t *testing.T) {
	plain := capture(t, fullTree(t))
	red := Redact(plain)
	for name, pair := range map[string][2]*Snapshot{"redacted baseline": {red, plain}, "redacted snapshot": {plain, red}} {
		diffs, err := Compare(pair[0], pair[1])
		if err == nil || diffs != nil {
			t.Fatalf("%s: Compare = %v, %v; want a refusal", name, kinds(diffs), err)
		}
		for _, want := range []string{"redacted", "not redacted", "both or neither"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error lacks %q: %v", name, want, err)
			}
		}
	}
}

func TestParseRejectsWhatIsNotASnapshot(t *testing.T) {
	good, err := Marshal(capture(t, fullTree(t)))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(old, new string) []byte {
		if !strings.Contains(string(good), old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return []byte(strings.Replace(string(good), old, new, 1))
	}
	manyPCRs := `{"schema":1,"dmi":{},"tpm":{"state":"ok","version_major":{"state":"ok","value":"2"},"pcrs":[` +
		strings.TrimSuffix(strings.Repeat(`{"index":0,"state":"absent"},`, PCRCount+1), ",") + `]},"rng":{"state":"absent"}}`
	cases := map[string][]byte{
		"empty":             nil,
		"not JSON":          []byte("this is not a baseline"),
		"truncated":         good[:len(good)/2],
		"an empty object":   []byte("{}"),
		"another schema":    mutate(`"schema": 1`, `"schema": 2`),
		"no dmi section":    []byte(`{"schema":1,"tpm":{"state":"absent"},"rng":{"state":"absent"}}`),
		"unknown state":     mutate(`"state": "ok"`, `"state": "verified"`),
		"unknown tpm state": []byte(`{"schema":1,"dmi":{},"tpm":{"state":"fine"},"rng":{"state":"absent"}}`),
		"unknown rng state": []byte(`{"schema":1,"dmi":{},"tpm":{"state":"absent"},"rng":{"state":""}}`),
		"PCR out of range":  mutate(`"index": 7`, `"index": 23`),
		"too many PCRs":     []byte(manyPCRs),
		"oversized value":   mutate(`"value": "LENOVO"`, fmt.Sprintf(`"value": %q`, strings.Repeat("A", maxAttrBytes+1))),
		// Marked redacted while still holding the raw serials.
		"falsely redacted": mutate(`"redacted": false`, `"redacted": true`),
		"over the bound":   append(append([]byte{}, good...), make([]byte, MaxSnapshotBytes)...),
	}
	for name, data := range cases {
		if s, err := Parse(data); err == nil || s != nil {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Errorf("the unmodified fixture was rejected: %v", err)
	}
	if _, err := Marshal(nil); err == nil {
		t.Error("Marshal(nil) succeeded")
	}
}

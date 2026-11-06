package hwanchor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// tree is a synthetic sysfs under t.TempDir(). Nothing here reads the real
// /sys.
type tree struct {
	t    *testing.T
	root string
}

func (tr *tree) path(rel string) string { return filepath.Join(tr.root, filepath.FromSlash(rel)) }

func (tr *tree) mkdir(rel string) {
	tr.t.Helper()
	if err := os.MkdirAll(tr.path(rel), 0o755); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) write(rel, content string) {
	tr.t.Helper()
	tr.mkdir(filepath.ToSlash(filepath.Dir(rel)))
	if err := os.WriteFile(tr.path(rel), []byte(content), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) remove(rel string) {
	tr.t.Helper()
	if err := os.RemoveAll(tr.path(rel)); err != nil {
		tr.t.Fatal(err)
	}
}

// link creates rel as a symbolic link to target, the way sysfs links class
// entries to devices.
func (tr *tree) link(rel, target string) {
	tr.t.Helper()
	tr.mkdir(filepath.ToSlash(filepath.Dir(rel)))
	if err := os.Symlink(target, tr.path(rel)); err != nil {
		tr.t.Fatal(err)
	}
}

const (
	dmiDir  = "devices/virtual/dmi/id/"
	eth0Dir = "devices/pci0000:00/0000:00:1c.7/0000:04:00.0/net/eth0/"
	tpmDir  = "devices/platform/NTC0702:00/tpm/tpm0/"
	rngDir  = "devices/virtual/misc/hw_random/"

	testUUID = "4c4c4544-0042-3510-8052-b4c04f4a4b32"
	testMAC  = "30:13:8b:8d:37:0e"
)

// pcrValue is a distinct, valid SHA-256 hex value per index, upper case as
// the kernel prints it.
func pcrValue(i int) string { return fmt.Sprintf("%064X", 0xA0+i) }

// emptyTree is a sysfs with a class directory and nothing in it.
func emptyTree(t *testing.T) *tree {
	t.Helper()
	tr := &tree{t: t, root: t.TempDir()}
	tr.mkdir("class")
	return tr
}

// fullTree is a host where every anchor reads ok, laid out like real sysfs:
// class entries are relative links into devices/.
func fullTree(t *testing.T) *tree {
	t.Helper()
	tr := emptyTree(t)
	for name, v := range map[string]string{
		"sys_vendor": "LENOVO", "product_name": "20XW0055GE", "product_uuid": strings.ToUpper(testUUID),
		"product_serial": "PF2ABCDE", "board_vendor": "LENOVO", "board_name": "20XW0055GE",
		"board_serial": "L1HF1A2B3C4", "chassis_serial": "PF2ABCDE-CH",
		"bios_vendor": "LENOVO", "bios_version": "N32ET75W (1.51 )", "bios_date": "12/02/2021",
	} {
		tr.write(dmiDir+name, v+"\n")
	}
	tr.link("class/dmi/id", "../../devices/virtual/dmi/id")

	tr.write(eth0Dir+"address", testMAC+"\n")
	tr.write(eth0Dir+"addr_assign_type", "0\n")
	tr.link(eth0Dir+"device", "../../../0000:04:00.0")
	tr.link("class/net/eth0", "../../"+strings.TrimSuffix(eth0Dir, "/"))

	tr.write("devices/virtual/net/lo/address", "00:00:00:00:00:00\n")
	tr.link("class/net/lo", "../../devices/virtual/net/lo")

	for i := 0; i < PCRCount; i++ {
		tr.write(fmt.Sprintf("%spcr-sha256/%d", tpmDir, i), pcrValue(i)+"\n")
	}
	tr.write(tpmDir+"tpm_version_major", "2\n")
	tr.link("class/tpm/tpm0", "../../"+strings.TrimSuffix(tpmDir, "/"))

	tr.write(rngDir+"rng_current", "tpm-rng-0\n")
	tr.write(rngDir+"rng_available", "tpm-rng-0 none\n")
	tr.link("class/misc/hw_random", "../../devices/virtual/misc/hw_random")
	return tr
}

var fixedNow = func() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }

func capture(t *testing.T, tr *tree) *Snapshot {
	t.Helper()
	s, err := Capture(Options{Sysfs: tr.root, Now: fixedNow})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	return s
}

// anchors is the Unverifiable list as "anchor=state", sorted.
func anchors(s *Snapshot) []string {
	out := []string{}
	for _, u := range s.Unverifiable {
		out = append(out, u.Anchor+"="+string(u.State))
	}
	sort.Strings(out)
	return out
}

func iface(t *testing.T, s *Snapshot, name string) Interface {
	t.Helper()
	for _, i := range s.Interfaces {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("no physical interface %q in %+v", name, s.Interfaces)
	return Interface{}
}

func TestCaptureFullTree(t *testing.T) {
	s := capture(t, fullTree(t))
	if s.Schema != SchemaVersion || s.CapturedAt != "2026-11-06T12:00:00Z" || s.Redacted {
		t.Errorf("header: %+v", s)
	}
	for _, name := range DMIFields {
		if f := s.DMI[name]; f.State != StateOK || f.Value == "" || f.Reason != "" {
			t.Errorf("dmi %s = %+v, want ok with a value", name, f)
		}
	}
	// Trimmed, and the UUID lower-cased so a kernel that prints it in upper
	// case does not look like different hardware.
	if got := s.DMI["product_uuid"].Value; got != testUUID {
		t.Errorf("product_uuid = %q, want %q", got, testUUID)
	}
	if got := s.DMI["bios_version"].Value; got != "N32ET75W (1.51 )" {
		t.Errorf("bios_version = %q", got)
	}

	if len(s.Interfaces) != 1 || len(s.VirtualInterfaces) != 0 {
		t.Fatalf("interfaces: %+v / %+v (lo must be skipped entirely)", s.Interfaces, s.VirtualInterfaces)
	}
	eth := s.Interfaces[0]
	want := Interface{Name: "eth0", Address: Field{State: StateOK, Value: testMAC},
		AssignType: Field{State: StateOK, Value: "0"}, Assignment: "permanent",
		PermanentAddress: Field{State: StateOK, Value: testMAC}}
	if !reflect.DeepEqual(eth, want) {
		t.Errorf("eth0 = %+v\nwant   %+v", eth, want)
	}

	if s.TPM.State != StateOK || s.TPM.VersionMajor != (Field{State: StateOK, Value: "2"}) || s.TPM.PCRBank != "sha256" {
		t.Errorf("tpm: %+v", s.TPM)
	}
	if len(s.TPM.PCRs) != PCRCount {
		t.Fatalf("got %d PCRs, want %d", len(s.TPM.PCRs), PCRCount)
	}
	for i, p := range s.TPM.PCRs {
		if p.Index != i || p.State != StateOK || p.Value != strings.ToLower(pcrValue(i)) {
			t.Errorf("PCR %d = %+v", i, p)
		}
	}
	if s.RNG.State != StateOK || s.RNG.Current != "tpm-rng-0" || !reflect.DeepEqual(s.RNG.Available, []string{"tpm-rng-0"}) {
		t.Errorf("rng: %+v", s.RNG)
	}
	// Even a host where everything reads cannot show a quote. The list is
	// never empty and never padded.
	if got := anchors(s); !reflect.DeepEqual(got, []string{"tpm.quote=not-captured"}) {
		t.Errorf("unverifiable = %v", got)
	}
	if len(s.Notes) != 0 {
		t.Errorf("notes on a clean tree: %v", s.Notes)
	}
}

// The quote is recorded as not captured on every host, with the reason.
func TestQuoteIsNeverCaptured(t *testing.T) {
	for name, tr := range map[string]*tree{"tpm": fullTree(t), "no tpm": emptyTree(t)} {
		s := capture(t, tr)
		q := s.TPM.Quote
		if q.Status != QuoteNotCaptured || !strings.Contains(q.Reason, "/dev/tpm0") || !strings.Contains(q.Reason, "attestation key") {
			t.Errorf("%s: quote = %+v", name, q)
		}
		found := false
		for _, u := range s.Unverifiable {
			found = found || (u.Anchor == "tpm.quote" && u.State == StateNotCaptured && u.Reason != "")
		}
		if !found {
			t.Errorf("%s: tpm.quote is not in the unverifiable list: %v", name, anchors(s))
		}
	}
}

func TestSnapshotJSONShape(t *testing.T) {
	raw, err := Marshal(capture(t, fullTree(t)))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"captured_at", "dmi", "interfaces", "redacted", "rng", "schema", "sysfs", "tpm", "unverifiable", "virtual_interfaces"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("top-level keys = %v\nwant             %v", keys, want)
	}
	for _, frag := range []string{
		`"product_uuid": {`, `"state": "ok"`, `"addr_assign_type": {`, `"assignment": "permanent"`,
		`"permanent_address": {`, `"permanent_mac_divergence": false`, `"version_major": {`, `"pcr_bank": "sha256"`,
		`"index": 7`, `"status": "not captured"`, `"current": "tpm-rng-0"`, `"anchor": "tpm.quote"`,
	} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("JSON lacks %s", frag)
		}
	}
	// Empty lists are [], never null: a consumer iterates without a guard.
	raw, _ = Marshal(capture(t, emptyTree(t)))
	for _, frag := range []string{`"interfaces": []`, `"virtual_interfaces": []`, `"pcrs": []`, `"available": []`} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("empty-tree JSON lacks %s", frag)
		}
	}
}

func TestDMIStates(t *testing.T) {
	tr := fullTree(t)
	tr.remove(dmiDir + "chassis_serial")
	tr.write(dmiDir+"board_serial", "Default string\n")
	tr.write(dmiDir+"product_serial", "\n")
	tr.write(dmiDir+"product_uuid", "00000000-0000-0000-0000-000000000000\n")
	s := capture(t, tr)

	if f := s.DMI["chassis_serial"]; f.State != StateAbsent || f.Value != "" {
		t.Errorf("removed file: %+v, want absent", f)
	}
	if f := s.DMI["board_serial"]; f.State != StatePlaceholder || f.Value != "Default string" || f.Reason == "" {
		t.Errorf("Default string: %+v, want placeholder keeping the filler", f)
	}
	if f := s.DMI["product_serial"]; f.State != StatePlaceholder {
		t.Errorf("empty file: %+v, want placeholder", f)
	}
	if f := s.DMI["product_uuid"]; f.State != StatePlaceholder {
		t.Errorf("all-zero UUID: %+v, want placeholder", f)
	}
	if f := s.DMI["sys_vendor"]; f.State != StateOK {
		t.Errorf("untouched field: %+v", f)
	}
	want := []string{"dmi.board_serial=placeholder", "dmi.chassis_serial=absent", "dmi.product_serial=placeholder",
		"dmi.product_uuid=placeholder", "tpm.quote=not-captured"}
	if got := anchors(s); !reflect.DeepEqual(got, want) {
		t.Errorf("unverifiable = %v\nwant           %v", got, want)
	}
}

// The serials and the UUID are mode 0400 root on a real host. That is
// "unreadable": not empty, not absent, not unknown hardware.
func TestDMIUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	tr := fullTree(t)
	for _, name := range []string{"product_uuid", "product_serial"} {
		if err := os.Chmod(tr.path(dmiDir+name), 0o000); err != nil {
			t.Fatal(err)
		}
	}
	s := capture(t, tr)
	for _, name := range []string{"product_uuid", "product_serial"} {
		f := s.DMI[name]
		if f.State != StateUnreadable || f.Value != "" || !strings.Contains(f.Reason, "root") {
			t.Errorf("%s = %+v, want unreadable with a reason naming root", name, f)
		}
	}
	want := []string{"dmi.product_serial=unreadable", "dmi.product_uuid=unreadable", "tpm.quote=not-captured"}
	if got := anchors(s); !reflect.DeepEqual(got, want) {
		t.Errorf("unverifiable = %v", got)
	}
}

func TestPlaceholderValues(t *testing.T) {
	for _, v := range []string{
		"", "   ", "To Be Filled By O.E.M.", "to be filled by o.e.m.", "Default string", "DEFAULT STRING",
		"None", "Not Specified", "System Serial Number", "Not Applicable", "N/A", "Unknown",
		"00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "0", "0000000", "XXXXXXXXXX", "........",
		"03000200-0400-0500-0006-000700080009", "123456789",
	} {
		if !isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = false, want true", v)
		}
	}
	for _, v := range []string{
		"PF2ABCDE", testUUID, "LENOVO", "F", "X", "FF", "F20", "1.0", "N32ET75W (1.51 )", "12/02/2021",
		"00000000-0000-0000-0000-000000000001", "Nonesuch", "1",
	} {
		if isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = true, want false", v)
		}
	}
}

func TestNoDMITable(t *testing.T) {
	tr := fullTree(t)
	tr.remove("class/dmi")
	s := capture(t, tr)
	for _, name := range DMIFields {
		if s.DMI[name].State != StateAbsent {
			t.Errorf("%s = %+v, want absent", name, s.DMI[name])
		}
	}
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "no DMI/SMBIOS table") {
		t.Errorf("notes = %v", s.Notes)
	}
	if got := len(s.Unverifiable); got != len(DMIFields)+1 {
		t.Errorf("%d unverifiable entries, want every DMI field and the quote: %v", got, anchors(s))
	}
}

func TestInterfaceClassification(t *testing.T) {
	tr := fullTree(t)
	// Virtual by location.
	tr.write("devices/virtual/net/docker0/address", "02:42:ac:11:00:01\n")
	tr.write("devices/virtual/net/docker0/addr_assign_type", "3\n")
	tr.link("class/net/docker0", "../../devices/virtual/net/docker0")
	// Virtual by having no device entry, wherever it lives.
	tr.write("devices/platform/soc/net/tap0/address", "fe:54:00:aa:bb:cc\n")
	tr.write("devices/platform/soc/net/tap0/addr_assign_type", "3\n")
	tr.link("class/net/tap0", "../../devices/platform/soc/net/tap0")
	// class/net holds a plain file on hosts with the bonding module.
	tr.write("class/net/bonding_masters", "bond0\n")
	// A second physical NIC, as a plain directory with a device entry.
	tr.write("class/net/enp3s0/address", "A4:BB:6D:00:11:22\n")
	tr.write("class/net/enp3s0/addr_assign_type", "0\n")
	tr.mkdir("class/net/enp3s0/device")

	s := capture(t, tr)
	var phys, virt []string
	for _, i := range s.Interfaces {
		phys = append(phys, i.Name)
	}
	for _, v := range s.VirtualInterfaces {
		virt = append(virt, v.Name+": "+v.Why)
	}
	if !reflect.DeepEqual(phys, []string{"enp3s0", "eth0"}) {
		t.Errorf("physical = %v", phys)
	}
	if !reflect.DeepEqual(virt, []string{"docker0: under devices/virtual", "tap0: no device entry"}) {
		t.Errorf("virtual = %v", virt)
	}
	// Addresses are lower-cased so one NIC has one spelling.
	if got := iface(t, s, "enp3s0").PermanentAddress.Value; got != "a4:bb:6d:00:11:22" {
		t.Errorf("enp3s0 permanent address = %q", got)
	}
	// A virtual interface is never scored: its userspace-set address is not
	// a divergence and not an unverifiable anchor.
	for _, a := range anchors(s) {
		if strings.Contains(a, "docker0") || strings.Contains(a, "tap0") || strings.Contains(a, "lo") {
			t.Errorf("a virtual interface reached the unverifiable list: %s", a)
		}
	}
}

func TestAssignTypes(t *testing.T) {
	cases := []struct {
		raw        string // "" removes the file
		assignment string
		diverged   bool
		permanent  State
		reason     string
	}{
		{"0\n", "permanent", false, StateOK, ""},
		{"1\n", "random", false, StateAbsent, "random"},
		{"2\n", "stolen", false, StateUnreadable, "another device"},
		{"3\n", "set-by-userspace", true, StateUnreadable, "ethtool ioctl"},
		{"7\n", "unknown", false, StateUnreadable, "cannot be shown"},
		{"03\n", "unknown", false, StateUnreadable, "cannot be shown"},
		{"three\n", "unknown", false, StateUnreadable, "cannot be shown"},
		{"", "unknown", false, StateUnreadable, "cannot be shown"},
	}
	for _, c := range cases {
		tr := fullTree(t)
		if c.raw == "" {
			tr.remove(eth0Dir + "addr_assign_type")
		} else {
			tr.write(eth0Dir+"addr_assign_type", c.raw)
		}
		s := capture(t, tr)
		eth := iface(t, s, "eth0")
		if eth.Assignment != c.assignment || eth.Divergence != c.diverged || eth.PermanentAddress.State != c.permanent ||
			!strings.Contains(eth.PermanentAddress.Reason, c.reason) {
			t.Errorf("addr_assign_type %q: %+v", c.raw, eth)
		}
		// The configured address is still reported whatever its origin.
		if eth.Address != (Field{State: StateOK, Value: testMAC}) {
			t.Errorf("addr_assign_type %q: address = %+v", c.raw, eth.Address)
		}
		listed := false
		for _, a := range anchors(s) {
			listed = listed || strings.HasPrefix(a, "net.eth0.permanent_address=")
		}
		if listed == (c.permanent == StateOK) {
			t.Errorf("addr_assign_type %q: unverifiable = %v", c.raw, anchors(s))
		}
		if c.permanent != StateOK && eth.PermanentAddress.Value != "" {
			t.Errorf("addr_assign_type %q: a configured address was recorded as the permanent one: %+v", c.raw, eth.PermanentAddress)
		}
	}
}

// The report must say what sysfs can and cannot show about a changed MAC.
func TestDivergenceReasonIsHonest(t *testing.T) {
	tr := fullTree(t)
	tr.write(eth0Dir+"addr_assign_type", "3\n")
	r := iface(t, capture(t, tr), "eth0").PermanentAddress.Reason
	for _, want := range []string{"set by userspace", "not the burned-in one", "does not expose the burned-in address", "not from what", "ethtool ioctl"} {
		if !strings.Contains(r, want) {
			t.Errorf("reason lacks %q: %s", want, r)
		}
	}
}

func TestAddressStates(t *testing.T) {
	cases := []struct {
		raw   string
		state State
	}{
		{testMAC + "\n", StateOK},
		{"00:00:00:00:00:00\n", StatePlaceholder},
		{"ff:ff:ff:ff:ff:ff\n", StatePlaceholder},
		{"\n", StatePlaceholder},
		{"11:11:11:11:11:11\n", StateOK},
		{"not-a-mac\n", StateUnreadable},
		{"30:13:8b:8d:37:0e:\n", StateUnreadable},
		{"30:13:8b:8d:37:zz\n", StateUnreadable},
		// An InfiniBand address is 20 octets.
		{"80:00:02:08:fe:80:00:00:00:00:00:00:00:02:c9:03:00:1e:8b:a1\n", StateOK},
	}
	for _, c := range cases {
		tr := fullTree(t)
		tr.write(eth0Dir+"address", c.raw)
		eth := iface(t, capture(t, tr), "eth0")
		if eth.Address.State != c.state || eth.PermanentAddress.State != c.state {
			t.Errorf("address %q: %+v / permanent %+v, want %s", c.raw, eth.Address, eth.PermanentAddress, c.state)
		}
	}
	tr := fullTree(t)
	tr.remove(eth0Dir + "address")
	if eth := iface(t, capture(t, tr), "eth0"); eth.Address.State != StateAbsent || eth.PermanentAddress.State != StateAbsent {
		t.Errorf("missing address: %+v", eth)
	}
}

func TestTPMAbsent(t *testing.T) {
	tr := fullTree(t)
	tr.remove("class/tpm")
	s := capture(t, tr)
	if s.TPM.State != StateAbsent || s.TPM.Reason == "" || len(s.TPM.PCRs) != 0 || s.TPM.VersionMajor.State != StateAbsent {
		t.Errorf("tpm = %+v, want a first-class absent state", s.TPM)
	}
	if got := anchors(s); !reflect.DeepEqual(got, []string{"tpm.quote=not-captured", "tpm=absent"}) {
		t.Errorf("unverifiable = %v", got)
	}
}

func TestTPMDegraded(t *testing.T) {
	// No pcr-sha256 directory (kernel before 5.12) and no version file.
	tr := fullTree(t)
	tr.remove(tpmDir + "pcr-sha256")
	tr.remove(tpmDir + "tpm_version_major")
	s := capture(t, tr)
	if s.TPM.State != StateOK || s.TPM.VersionMajor.State != StateAbsent || len(s.TPM.PCRs) != PCRCount {
		t.Fatalf("tpm = %+v", s.TPM)
	}
	for _, p := range s.TPM.PCRs {
		if p.State != StateAbsent || p.Value != "" {
			t.Errorf("PCR %d = %+v, want absent", p.Index, p)
		}
	}
	// One line for the missing bank, not eight.
	want := []string{"tpm.pcr-sha256=absent", "tpm.quote=not-captured", "tpm.version_major=absent"}
	if got := anchors(s); !reflect.DeepEqual(got, want) {
		t.Errorf("unverifiable = %v", got)
	}

	// Individual PCRs that are missing or are not a digest.
	tr = fullTree(t)
	tr.remove(tpmDir + "pcr-sha256/3")
	tr.write(tpmDir+"pcr-sha256/5", "deadbeef\n")
	tr.write(tpmDir+"pcr-sha256/6", strings.Repeat("g", 64)+"\n")
	tr.write(tpmDir+"tpm_version_major", "9\n")
	s = capture(t, tr)
	want = []string{"tpm.pcr.3=absent", "tpm.pcr.5=unreadable", "tpm.pcr.6=unreadable", "tpm.quote=not-captured", "tpm.version_major=unreadable"}
	if got := anchors(s); !reflect.DeepEqual(got, want) {
		t.Errorf("unverifiable = %v\nwant           %v", got, want)
	}
	if s.TPM.PCRs[5].Value != "" || s.TPM.PCRs[0].State != StateOK {
		t.Errorf("PCRs = %+v", s.TPM.PCRs)
	}
}

func TestRNGStates(t *testing.T) {
	// The kernel's own "none".
	tr := fullTree(t)
	tr.write(rngDir+"rng_current", "none\n")
	tr.write(rngDir+"rng_available", "none\n")
	s := capture(t, tr)
	if s.RNG.State != StateAbsent || s.RNG.Current != "none" || len(s.RNG.Available) != 0 || !strings.Contains(s.RNG.Reason, "software entropy") {
		t.Errorf("rng_current none: %+v", s.RNG)
	}
	if got := anchors(s); !reflect.DeepEqual(got, []string{"rng=absent", "tpm.quote=not-captured"}) {
		t.Errorf("unverifiable = %v", got)
	}

	// No hw_random interface at all.
	tr = fullTree(t)
	tr.remove("class/misc")
	s = capture(t, tr)
	if s.RNG.State != StateAbsent || s.RNG.Current != "none" || s.RNG.Reason == "" {
		t.Errorf("no hw_random: %+v", s.RNG)
	}

	// Several candidates, one active.
	tr = fullTree(t)
	tr.write(rngDir+"rng_current", "virtio_rng.0\n")
	tr.write(rngDir+"rng_available", "virtio_rng.0 tpm-rng-0 none\n")
	s = capture(t, tr)
	if s.RNG.State != StateOK || s.RNG.Current != "virtio_rng.0" || !reflect.DeepEqual(s.RNG.Available, []string{"virtio_rng.0", "tpm-rng-0"}) {
		t.Errorf("two RNGs: %+v", s.RNG)
	}

	if os.Geteuid() != 0 {
		tr = fullTree(t)
		if err := os.Chmod(tr.path(rngDir+"rng_current"), 0o000); err != nil {
			t.Fatal(err)
		}
		s = capture(t, tr)
		if s.RNG.State != StateUnreadable || s.RNG.Current != "unknown" {
			t.Errorf("unreadable rng_current: %+v", s.RNG)
		}
	}
}

// A host with nothing: every anchor is named, none is "verified".
func TestUnverifiableListOnBareHost(t *testing.T) {
	s := capture(t, emptyTree(t))
	want := []string{"net=absent", "rng=absent", "tpm.quote=not-captured", "tpm=absent"}
	for _, name := range DMIFields {
		want = append(want, "dmi."+name+"=absent")
	}
	sort.Strings(want)
	if got := anchors(s); !reflect.DeepEqual(got, want) {
		t.Errorf("unverifiable = %v\nwant           %v", got, want)
	}
	for _, u := range s.Unverifiable {
		if u.State == StateOK {
			t.Errorf("%s is listed as unverifiable with state ok", u.Anchor)
		}
	}
}

func TestCaptureRejectsWhatIsNotSysfs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "classfile"), 0o755)
	os.WriteFile(filepath.Join(dir, "classfile", "class"), []byte("x"), 0o644)
	for name, root := range map[string]string{
		"missing":         filepath.Join(dir, "nope"),
		"a file":          file,
		"no class dir":    dir,
		"class is a file": filepath.Join(dir, "classfile"),
	} {
		s, err := Capture(Options{Sysfs: root})
		if err == nil || s != nil {
			t.Errorf("%s: Capture = %+v, %v; want an error, not a snapshot of absent anchors", name, s, err)
		}
	}
}

// The root itself may be reached through a symbolic link.
func TestRootViaSymlink(t *testing.T) {
	tr := fullTree(t)
	alias := filepath.Join(t.TempDir(), "sys")
	if err := os.Symlink(tr.root, alias); err != nil {
		t.Fatal(err)
	}
	s, err := Capture(Options{Sysfs: alias, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	if s.Sysfs != alias || s.DMI["product_uuid"].Value != testUUID || len(s.Interfaces) != 1 {
		t.Errorf("snapshot through a linked root: %+v", s)
	}
}

// The one test that touches the real host: it must not fail or panic,
// whatever this machine has.
func TestCaptureRealSysfs(t *testing.T) {
	if fi, err := os.Stat("/sys/class"); err != nil || !fi.IsDir() {
		t.Skip("no /sys/class on this host")
	}
	s, err := Capture(Options{})
	if err != nil {
		t.Fatalf("Capture on /sys: %v", err)
	}
	if s.Sysfs != DefaultSysfs || len(s.DMI) != len(DMIFields) || len(s.Unverifiable) == 0 {
		t.Errorf("real snapshot: sysfs %q, %d dmi fields, %d unverifiable", s.Sysfs, len(s.DMI), len(s.Unverifiable))
	}
	if _, err := Marshal(s); err != nil {
		t.Errorf("Marshal: %v", err)
	}
	if diffs, err := Compare(s, s); err != nil || len(diffs) != 0 {
		t.Errorf("a snapshot differs from itself: %v %v", diffs, err)
	}
}

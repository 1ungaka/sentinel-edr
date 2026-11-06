package hwanchor

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

// SchemaVersion is the snapshot layout. Compare refuses a snapshot of another
// version instead of guessing at its fields.
const SchemaVersion = 1

// DefaultSysfs is where the kernel mounts sysfs.
const DefaultSysfs = "/sys"

// PCRCount is how many PCRs are recorded: 0 to 7, the firmware and boot-chain
// measurements.
const PCRCount = 8

// State says how far one anchor could be read. Only StateOK is an identity.
type State string

const (
	// StateOK: read, and a real value.
	StateOK State = "ok"
	// StateAbsent: the host does not have it (no TPM, no DMI table, no
	// hardware RNG).
	StateAbsent State = "absent"
	// StateUnreadable: it exists and this run could not read or parse it,
	// most often because it needs root.
	StateUnreadable State = "unreadable"
	// StatePlaceholder: read, but the value is a well-known filler the
	// firmware vendor never replaced. Not an identity; never compared.
	StatePlaceholder State = "placeholder"
	// StateNotCaptured is used by the TPM quote only: this package never
	// captures one.
	StateNotCaptured State = "not-captured"
)

// Field is one value read from sysfs and how far it could be read.
type Field struct {
	State State `json:"state"`
	// Value is set for StateOK, and for StatePlaceholder (the filler that was
	// found). It is exactly what sysfs held, trimmed: it may contain control
	// characters and must be escaped before it reaches a terminal.
	Value string `json:"value,omitempty"`
	// Reason says why the state is not ok.
	Reason string `json:"reason,omitempty"`
}

// OK reports whether the field holds an identity.
func (f Field) OK() bool { return f.State == StateOK }

// Interface is one physical network interface.
type Interface struct {
	Name string `json:"name"`
	// Address is the configured hardware address, as sysfs reports it.
	Address Field `json:"address"`
	// AssignType is the kernel's addr_assign_type, "0" to "3".
	AssignType Field `json:"addr_assign_type"`
	// Assignment names AssignType: permanent, random, stolen,
	// set-by-userspace or unknown.
	Assignment string `json:"assignment"`
	// PermanentAddress is the device's permanent address as far as sysfs can
	// show it: the configured address when the kernel says that address is
	// the permanent one (addr_assign_type 0), and not ok otherwise. sysfs
	// never exposes the burned-in address of a device whose address was
	// changed.
	PermanentAddress Field `json:"permanent_address"`
	// Divergence is true when the address was set by userspace
	// (addr_assign_type 3): the configured MAC is not the burned-in one.
	Divergence bool `json:"permanent_mac_divergence"`
}

// VirtualInterface is an interface with no hardware behind it. It is listed
// and never compared.
type VirtualInterface struct {
	Name string `json:"name"`
	// Why says how it was classified: "under devices/virtual" or "no device
	// entry".
	Why string `json:"why"`
}

// PCR is one platform configuration register of the SHA-256 bank.
type PCR struct {
	Index int `json:"index"`
	Field
}

// Quote records that no TPM quote was captured, and why.
type Quote struct {
	// Status is always "not captured".
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// QuoteNotCaptured is the only Quote.Status this package produces.
const QuoteNotCaptured = "not captured"

// TPM is what sysfs shows of the first TPM.
type TPM struct {
	// State is ok when class/tpm/tpm0 exists, absent when the host has no
	// TPM, unreadable when the entry could not be examined.
	State  State  `json:"state"`
	Reason string `json:"reason,omitempty"`
	// VersionMajor is tpm_version_major: "1" or "2".
	VersionMajor Field `json:"version_major"`
	// PCRBank is the bank PCRs come from: always "sha256".
	PCRBank string `json:"pcr_bank"`
	// PCRs holds PCR 0 to 7 when the TPM is present. They are the kernel's
	// unsigned report, lower-case hex.
	PCRs  []PCR `json:"pcrs"`
	Quote Quote `json:"quote"`
}

// RNG is the kernel's hardware entropy source.
type RNG struct {
	// State is ok when a hardware RNG is active, absent when none is (the
	// degraded state), unreadable when it could not be determined.
	State State `json:"state"`
	// Current is the active hardware RNG, "none" when there is none, or
	// "unknown" when it could not be read.
	Current string `json:"current"`
	// Available lists the hardware RNGs the kernel could switch to.
	Available []string `json:"available"`
	Reason    string   `json:"reason,omitempty"`
}

// Unverifiable names one anchor this snapshot could not establish.
type Unverifiable struct {
	// Anchor is the same name Compare uses: "dmi.product_uuid",
	// "net.eth0.permanent_address", "tpm", "tpm.pcr.0", "tpm.quote", "rng".
	Anchor string `json:"anchor"`
	State  State  `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// Snapshot is a host's hardware identity at one moment.
type Snapshot struct {
	Schema     int    `json:"schema"`
	CapturedAt string `json:"captured_at"`
	// Sysfs is the root the snapshot was read from.
	Sysfs string `json:"sysfs"`
	// Redacted is true once Redact has replaced serials, UUIDs and MAC
	// addresses with digests.
	Redacted bool `json:"redacted"`
	// DMI is keyed by the sysfs attribute name; DMIFields is the full list.
	DMI map[string]Field `json:"dmi"`
	// Interfaces are the physical network interfaces, by name.
	Interfaces []Interface `json:"interfaces"`
	// VirtualInterfaces are listed for completeness and never compared.
	VirtualInterfaces []VirtualInterface `json:"virtual_interfaces"`
	TPM               TPM                `json:"tpm"`
	RNG               RNG                `json:"rng"`
	// Unverifiable lists every anchor that is not ok. It is never empty: the
	// TPM quote is never captured.
	Unverifiable []Unverifiable `json:"unverifiable"`
	// Notes are limits this run hit: entries skipped, bounds reached.
	Notes []string `json:"notes,omitempty"`
}

// Options configures Capture.
type Options struct {
	// Sysfs is the sysfs root; empty means DefaultSysfs.
	Sysfs string
	// Now stamps the snapshot; nil means time.Now.
	Now func() time.Time
}

// DMIFields are the DMI/SMBIOS attributes recorded, in report order.
var DMIFields = []string{
	"sys_vendor", "product_name", "product_uuid", "product_serial",
	"board_vendor", "board_name", "board_serial", "chassis_serial",
	"bios_vendor", "bios_version", "bios_date",
}

// sensitiveDMI are the attributes that identify one physical machine. Redact
// replaces them.
var sensitiveDMI = map[string]bool{
	"product_uuid": true, "product_serial": true, "board_serial": true, "chassis_serial": true,
}

// placeholders are values firmware vendors ship in place of an identity,
// lower-cased. A value on this list is the same on thousands of machines.
var placeholders = map[string]bool{
	"to be filled by o.e.m.": true, "to be filled by o.e.m": true,
	"default string": true, "none": true, "not specified": true,
	"not applicable": true, "not available": true, "n/a": true,
	"unknown": true, "unspecified": true, "invalid": true, "empty": true,
	"oem": true, "o.e.m.": true,
	"system serial number": true, "system product name": true,
	"system manufacturer": true, "system version": true,
	"base board serial number": true, "chassis serial number": true,
	"12345678": true, "123456789": true, "1234567890": true, "0123456789": true,
	// The UUID in AMI's reference firmware, shipped unchanged on many boards.
	"03000200-0400-0500-0006-000700080009": true,
}

// isPlaceholder reports a value that is not an identity: empty, on the list
// above, or one filler character repeated (an all-zero or all-F UUID,
// "XXXXXXXX", "........").
func isPlaceholder(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" || placeholders[t] {
		return true
	}
	body := strings.Map(func(r rune) rune {
		switch r {
		case '-', ':', '.', '_', ' ':
			return -1
		}
		return r
	}, t)
	if body == "" {
		return true
	}
	if strings.Trim(body, body[:1]) != "" {
		return false
	}
	switch body[0] {
	case '0':
		return true
	case 'f', 'x':
		// Short runs are left alone: "F" and "X" are plausible revisions.
		return len(body) >= 4
	}
	return false
}

// Capture reads the hardware identity under opts.Sysfs. It fails only when the
// root is not a readable sysfs tree; everything below that degrades field by
// field and is recorded in the snapshot.
func Capture(opts Options) (*Snapshot, error) {
	root := opts.Sysfs
	if root == "" {
		root = DefaultSysfs
	}
	s, err := openSysfs(root)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	snap := &Snapshot{
		Schema:            SchemaVersion,
		CapturedAt:        now().UTC().Format(time.RFC3339),
		Sysfs:             root,
		DMI:               make(map[string]Field, len(DMIFields)),
		Interfaces:        []Interface{},
		VirtualInterfaces: []VirtualInterface{},
		Unverifiable:      []Unverifiable{},
	}
	s.dmi(snap)
	s.net(snap)
	s.tpm(snap)
	s.rng(snap)
	return snap, nil
}

// unverified lists the anchor when its field is not an identity.
func (snap *Snapshot) unverified(anchor string, f Field) {
	if f.State != StateOK {
		snap.Unverifiable = append(snap.Unverifiable, Unverifiable{Anchor: anchor, State: f.State, Reason: f.Reason})
	}
}

// ── DMI / SMBIOS ─────────────────────────────────────────────────────────────

func (s *sysfs) dmi(snap *Snapshot) {
	if _, err := s.lstat("class/dmi/id"); errors.Is(err, fs.ErrNotExist) {
		snap.Notes = append(snap.Notes, "no class/dmi/id: this platform exposes no DMI/SMBIOS table (usual on devicetree hosts)")
	}
	for _, name := range DMIFields {
		f := s.attr("class/dmi/id/" + name)
		if f.State == StateOK {
			if name == "product_uuid" {
				// Older kernels print the UUID in upper case.
				f.Value = strings.ToLower(f.Value)
			}
			if isPlaceholder(f.Value) {
				f.State, f.Reason = StatePlaceholder, "well-known placeholder value, not an identity"
			}
		}
		snap.DMI[name] = f
		snap.unverified("dmi."+name, f)
	}
}

// ── network interfaces ───────────────────────────────────────────────────────

// Reasons a permanent address is not established. They say what sysfs can and
// cannot show; none of them claims intent.
const (
	reasonSetByUserspace = "the address was set by userspace (addr_assign_type 3), so the configured MAC is not the burned-in one; " +
		"sysfs does not expose the burned-in address, so this shows that it was changed, not from what " +
		"(reading the EEPROM address needs an ethtool ioctl this read-only scan does not make)"
	reasonRandom = "the kernel generated a random address for this device (addr_assign_type 1): no permanent address is in use"
	reasonStolen = "the address was taken from another device (addr_assign_type 2); sysfs does not expose this device's own burned-in address"
)

// macField validates a hardware address read from sysfs.
func macField(f Field) Field {
	if f.State != StateOK {
		return f
	}
	v := strings.ToLower(f.Value)
	if v == "" {
		return Field{State: StatePlaceholder, Reason: "empty address"}
	}
	octets := strings.Split(v, ":")
	if len(octets) > 32 { // MAX_ADDR_LEN
		return Field{State: StateUnreadable, Reason: "not a hardware address"}
	}
	for _, o := range octets {
		if len(o) != 2 || strings.Trim(o, "0123456789abcdef") != "" {
			return Field{State: StateUnreadable, Reason: "not a hardware address"}
		}
	}
	if strings.Trim(v, ":"+v[:1]) == "" { // one digit repeated
		switch v[0] {
		case '0':
			return Field{State: StatePlaceholder, Value: v, Reason: "all-zero address, not an identity"}
		case 'f':
			return Field{State: StatePlaceholder, Value: v, Reason: "broadcast address, not an identity"}
		}
	}
	return Field{State: StateOK, Value: v}
}

// assignment names an addr_assign_type value.
func assignment(f Field) string {
	if f.State != StateOK {
		return "unknown"
	}
	switch f.Value {
	case "0":
		return "permanent"
	case "1":
		return "random"
	case "2":
		return "stolen"
	case "3":
		return "set-by-userspace"
	}
	return "unknown"
}

func (s *sysfs) net(snap *Snapshot) {
	names, truncated, err := s.list("class/net", maxInterfaces)
	if err != nil {
		f := failed(err)
		if f.State == StateAbsent {
			f.Reason = "no class/net in sysfs: no network interface could be inventoried"
		}
		snap.unverified("net", f)
		return
	}
	if truncated {
		snap.Notes = append(snap.Notes, fmt.Sprintf("class/net holds more than %d entries; the rest were not inventoried", maxInterfaces))
	}
	oversize, skipped := 0, 0
	for _, raw := range names {
		if raw == "lo" {
			continue
		}
		if len(raw) > maxIfName {
			oversize++
			continue
		}
		rel := "class/net/" + raw
		name := strings.ToValidUTF8(raw, "\uFFFD")
		real, err := s.relPath(rel)
		if err != nil {
			skipped++
			if skipped <= 8 {
				snap.Notes = append(snap.Notes, fmt.Sprintf("class/net/%s was not inventoried: %s", name, failed(err).describe()))
			}
			continue
		}
		fi, err := s.lstat(rel)
		if err != nil || !fi.IsDir() {
			continue // class/net also holds plain files such as bonding_masters
		}
		if strings.HasPrefix(real, "devices/virtual/") {
			snap.VirtualInterfaces = append(snap.VirtualInterfaces, VirtualInterface{Name: name, Why: "under devices/virtual"})
			continue
		}
		// The device entry is only tested for existence, never followed.
		if _, err := s.lstatChild(rel, "device"); err != nil {
			snap.VirtualInterfaces = append(snap.VirtualInterfaces, VirtualInterface{Name: name, Why: "no device entry"})
			continue
		}

		ifc := Interface{Name: name, Address: macField(s.attr(rel + "/address"))}
		ifc.AssignType = s.attr(rel + "/addr_assign_type")
		if v := ifc.AssignType; v.State == StateOK && v.Value != "0" && v.Value != "1" && v.Value != "2" && v.Value != "3" {
			ifc.AssignType = Field{State: StateUnreadable, Reason: "not an addr_assign_type value (0 to 3)"}
		}
		ifc.Assignment = assignment(ifc.AssignType)
		switch ifc.Assignment {
		case "permanent":
			ifc.PermanentAddress = ifc.Address
		case "set-by-userspace":
			ifc.Divergence = true
			ifc.PermanentAddress = Field{State: StateUnreadable, Reason: reasonSetByUserspace}
		case "random":
			ifc.PermanentAddress = Field{State: StateAbsent, Reason: reasonRandom}
		case "stolen":
			ifc.PermanentAddress = Field{State: StateUnreadable, Reason: reasonStolen}
		default:
			ifc.PermanentAddress = Field{State: StateUnreadable,
				Reason: "addr_assign_type is " + ifc.AssignType.describe() + ", so the configured address cannot be shown to be the permanent one"}
		}
		snap.Interfaces = append(snap.Interfaces, ifc)
		snap.unverified("net."+name+".permanent_address", ifc.PermanentAddress)
	}
	if skipped > 8 {
		snap.Notes = append(snap.Notes, fmt.Sprintf("%d more class/net entries were not inventoried", skipped-8))
	}
	if oversize > 0 {
		snap.Notes = append(snap.Notes, fmt.Sprintf("%d class/net entries have names longer than %d bytes, which no interface can have; skipped", oversize, maxIfName))
	}
}

// describe is a field's state with its reason, for a sentence.
func (f Field) describe() string {
	if f.Reason == "" {
		return string(f.State)
	}
	return string(f.State) + " (" + f.Reason + ")"
}

// ── TPM ──────────────────────────────────────────────────────────────────────

const (
	reasonQuote = "a signed TPM2_Quote needs /dev/tpm0 access and an attestation key; this scan only reads sysfs, " +
		"so the PCR values here are the kernel's unsigned report"
	reasonNoPCRs = "no pcr-sha256 directory: the kernel is older than 5.12 or the device has no SHA-256 bank"
)

func (s *sysfs) tpm(snap *Snapshot) {
	t := TPM{PCRBank: "sha256", PCRs: []PCR{}, Quote: Quote{Status: QuoteNotCaptured, Reason: reasonQuote}}
	defer func() {
		snap.TPM = t
		snap.Unverifiable = append(snap.Unverifiable, Unverifiable{Anchor: "tpm.quote", State: StateNotCaptured, Reason: t.Quote.Reason})
	}()

	const dev = "class/tpm/tpm0"
	fi, err := s.lstat(dev)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		t.State, t.Reason = StateAbsent, "no class/tpm/tpm0: this host exposes no TPM"
	case err != nil:
		f := failed(err)
		t.State, t.Reason = f.State, f.Reason
	case !fi.IsDir():
		t.State, t.Reason = StateUnreadable, "class/tpm/tpm0 is not a directory"
	default:
		t.State = StateOK
	}
	if t.State != StateOK {
		t.VersionMajor = Field{State: t.State}
		t.Quote.Reason = reasonQuote + "; and no TPM could be read on this host"
		snap.unverified("tpm", Field{State: t.State, Reason: t.Reason})
		return
	}

	t.VersionMajor = s.attr(dev + "/tpm_version_major")
	if v := t.VersionMajor; v.State == StateOK && v.Value != "1" && v.Value != "2" {
		t.VersionMajor = Field{State: StateUnreadable, Reason: "not a TPM major version"}
	}
	snap.unverified("tpm.version_major", t.VersionMajor)

	_, dirErr := s.lstat(dev + "/pcr-sha256")
	noBank := errors.Is(dirErr, fs.ErrNotExist)
	for i := 0; i < PCRCount; i++ {
		f := s.attr(fmt.Sprintf("%s/pcr-sha256/%d", dev, i))
		switch {
		case noBank:
			f = Field{State: StateAbsent, Reason: reasonNoPCRs}
		case f.State == StateOK:
			v := strings.ToLower(f.Value)
			if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
				f = Field{State: StateUnreadable, Reason: "not a SHA-256 value"}
			} else {
				f.Value = v
			}
		}
		t.PCRs = append(t.PCRs, PCR{Index: i, Field: f})
		if !noBank {
			snap.unverified(fmt.Sprintf("tpm.pcr.%d", i), f)
		}
	}
	if noBank {
		// One line for the missing bank, not eight.
		snap.unverified("tpm.pcr-sha256", Field{State: StateAbsent, Reason: reasonNoPCRs})
	}
}

// ── entropy source ───────────────────────────────────────────────────────────

func (s *sysfs) rng(snap *Snapshot) {
	const dir = "class/misc/hw_random/"
	r := RNG{Available: []string{}}
	cur := s.attr(dir + "rng_current")
	switch {
	case cur.State == StateAbsent:
		r.State, r.Current = StateAbsent, "none"
		r.Reason = "no class/misc/hw_random in sysfs: the kernel has no hardware RNG driver loaded; the host runs on software entropy"
	case cur.State != StateOK:
		r.State, r.Current, r.Reason = StateUnreadable, "unknown", cur.Reason
	case cur.Value == "" || cur.Value == "none":
		r.State, r.Current = StateAbsent, "none"
		r.Reason = "the kernel reports no active hardware RNG; the host runs on software entropy"
	default:
		r.State, r.Current = StateOK, cur.Value
	}
	if avail := s.attr(dir + "rng_available"); avail.State == StateOK {
		for _, name := range strings.Fields(avail.Value) {
			if name != "none" && len(r.Available) < 64 {
				r.Available = append(r.Available, name)
			}
		}
	}
	snap.RNG = r
	snap.unverified("rng", Field{State: r.State, Reason: r.Reason})
}

package bootscan

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Comparing a scan with a baseline. The rules are in the package comment;
// this file is their implementation, one function per surface. Every rule
// has the same first step: a value that is unknown on either side is never
// compared. Unknown now is "not-reverified", unknown then is
// "not-in-baseline", and neither is ever "removed" or "added".

// DiffKind is what happened to an item between the baseline and now.
type DiffKind string

const (
	// KindAdded: the item is there now and the baseline, which covered the
	// place it is in, did not have it.
	KindAdded DiffKind = "added"
	// KindRemoved: the baseline had the item and it is gone from a place
	// that was read completely this time.
	KindRemoved DiffKind = "removed"
	// KindChanged: the item is on both sides with different values.
	KindChanged DiffKind = "changed"
	// KindNotReverified: the baseline has the item and this run could not
	// read it (the ESP without root, a disk that was not named, a variable
	// that is unreadable). It may be unchanged; this run cannot say.
	KindNotReverified DiffKind = "not-reverified"
	// KindNotInBaseline: readable now, and the baseline did not cover it, so
	// there is nothing to compare it with. Not a change.
	KindNotInBaseline DiffKind = "not-in-baseline"
)

// Severity is what a difference means for the verdict.
type Severity string

const (
	// SeveritySecurity: a change an implant makes. It sets the exit code.
	SeveritySecurity Severity = "security"
	// SeverityExpectedUpdate: a change that only tightens the boot chain or
	// moves it forward, which a vendor or OS update produces. Reported; does
	// not set the exit code.
	SeverityExpectedUpdate Severity = "expected-update"
	// SeverityInfo: reported for completeness. Removals that introduce
	// nothing, relabelling, hardening, and everything that could not be
	// compared.
	SeverityInfo Severity = "info"
)

// Difference is one item that does not compare equal.
type Difference struct {
	Kind     DiffKind `json:"kind"`
	Severity Severity `json:"severity"`
	// Surface is efi, esp, disk, acpi, pci or esrt.
	Surface string `json:"surface"`
	// Item names what differs: efi.boot.0003, esp:EFI/debian/shimx64.efi,
	// efi.dbx, disk:<path>.gpt.partition.2, acpi.table.WPBT,
	// pci.rom.0000:01:00.0.
	Item string `json:"item"`
	// Old and New are the two values, where the side held one.
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	Detail string `json:"detail"`
}

// SecurityRelevant reports whether any difference is SeveritySecurity.
func SecurityRelevant(diffs []Difference) bool {
	for _, d := range diffs {
		if d.Severity == SeveritySecurity {
			return true
		}
	}
	return false
}

// protectionTables are ACPI tables whose disappearance weakens the OS: the
// DMA-remapping tables (without one the kernel cannot confine a device's
// memory access) and the TPM tables (without one there is no measured boot).
var protectionTables = map[string]bool{"DMAR": true, "IVRS": true, "TPM2": true, "TCPA": true}

// Compare lists how current differs from baseline, most serious first. Both
// are baselines: derive current from the scan just made with NewBaseline.
// The result is empty, not nil, when nothing differs.
func Compare(baseline, current *Baseline) ([]Difference, error) {
	if baseline == nil || current == nil {
		return nil, errors.New("bootscan: nothing to compare")
	}
	if baseline.Schema != BaselineSchema || current.Schema != BaselineSchema {
		return nil, fmt.Errorf("bootscan: cannot compare schema %d with schema %d (this build reads schema %d)",
			baseline.Schema, current.Schema, BaselineSchema)
	}
	d := &differ{out: []Difference{}}
	d.efi(baseline.EFI, current.EFI)
	d.esp(baseline.ESP, current.ESP)
	d.disks(baseline.Disks, current.Disks)
	d.firmware(baseline.Firmware, current.Firmware)

	rank := func(x Difference) int {
		n := map[Severity]int{SeveritySecurity: 0, SeverityExpectedUpdate: 10, SeverityInfo: 20}[x.Severity]
		switch x.Kind {
		case KindNotReverified:
			n += 1
		case KindNotInBaseline:
			n += 2
		}
		return n
	}
	sort.SliceStable(d.out, func(i, j int) bool { return rank(d.out[i]) < rank(d.out[j]) })
	return d.out, nil
}

type differ struct{ out []Difference }

func (d *differ) add(kind DiffKind, sev Severity, surface, item, old, new, detail string) {
	d.out = append(d.out, Difference{Kind: kind, Severity: sev, Surface: surface, Item: item, Old: old, New: new, Detail: detail})
}

const (
	detailNotReverified = "could not be re-verified: the baseline holds a value and this run could not read one. It may be unchanged"
	detailNotInBaseline = "readable now, and the baseline could not read it: there is nothing to compare the current value with"
	detailUpdate        = "A vendor or OS update produces this. "
)

// known applies the rule every value shares and reports whether both sides
// hold one. Unknown on one side is reported; unknown on both is nothing.
func (d *differ) known(surface, item, b, c string) bool {
	switch {
	case b == StateUnknown && c == StateUnknown:
		return false
	case b == StateUnknown:
		d.add(KindNotInBaseline, SeverityInfo, surface, item, "", c, detailNotInBaseline)
		return false
	case c == StateUnknown:
		d.add(KindNotReverified, SeverityInfo, surface, item, b, "", detailNotReverified)
		return false
	}
	return true
}

// surface handles a whole surface that one side did not read. It reports
// whether both sides have it.
func (d *differ) surface(name, item string, b, c bool, bSummary, cSummary, what string) bool {
	switch {
	case b && c:
		return true
	case b:
		d.add(KindNotReverified, SeverityInfo, name, item, bSummary, "",
			"could not be re-verified: the baseline records "+what+" and this run did not read it. Nothing in it was compared, and nothing in it is reported as removed")
	case c:
		d.add(KindNotInBaseline, SeverityInfo, name, item, "", cSummary,
			what+" was read in this run and the baseline does not cover it. Nothing in it was compared; record a new baseline to cover it")
	}
	return false
}

// ── firmware variables ───────────────────────────────────────────────────────

func (d *differ) efi(b, c *BaselineEFI) {
	summary := func(e *BaselineEFI) string {
		if e == nil {
			return ""
		}
		return fmt.Sprintf("Secure Boot %s, %d boot entries", e.SecureBoot, len(e.BootEntries))
	}
	if !d.surface("efi", "efi", b != nil, c != nil, summary(b), summary(c), "the firmware variables") {
		return
	}

	if d.known("efi", "efi.secure_boot", b.SecureBoot, c.SecureBoot) && b.SecureBoot != c.SecureBoot {
		if c.SecureBoot == stateDisabled {
			d.add(KindChanged, SeveritySecurity, "efi", "efi.secure_boot", b.SecureBoot, c.SecureBoot,
				"Secure Boot was enabled when the baseline was recorded and is disabled now: the firmware starts any boot loader, signed or not")
		} else {
			d.add(KindChanged, SeverityInfo, "efi", "efi.secure_boot", b.SecureBoot, c.SecureBoot,
				"Secure Boot was disabled when the baseline was recorded and is enabled now")
		}
	}
	if d.known("efi", "efi.setup_mode", b.SetupMode, c.SetupMode) && b.SetupMode != c.SetupMode {
		if c.SetupMode == stateOn {
			d.add(KindChanged, SeveritySecurity, "efi", "efi.setup_mode", b.SetupMode, c.SetupMode,
				"the platform has entered setup mode: Secure Boot keys can now be enrolled without authorisation")
		} else {
			d.add(KindChanged, SeverityInfo, "efi", "efi.setup_mode", b.SetupMode, c.SetupMode,
				"the platform has left setup mode; if a platform key was enrolled, efi.pk says so")
		}
	}

	d.sigVar("efi.pk", "the platform key (PK)", b.PK, c.PK)
	d.sigVar("efi.kek", "the key-exchange key list (KEK)", b.KEK, c.KEK)
	d.sigVar("efi.db", "the allowed-signature database (db)", b.DB, c.DB)
	d.dbx(b.DBX, c.DBX)
	d.sigVar("efi.mok", "the shim machine-owner-key list (MOK)", b.MOK, c.MOK)
	d.sbat(b.SBAT, c.SBAT)
	d.bootOrder(b, c)
	d.bootEntries(b, c)
}

func describeVar(v BaselineVar) string {
	if v.State != StatePresent {
		return v.State
	}
	s := fmt.Sprintf("%d SHA-256 hashes, %d certificates", v.Hashes, v.Certificates)
	if v.Other > 0 {
		s += fmt.Sprintf(", %d other entries", v.Other)
	}
	if v.Unparsed {
		s = "not a well-formed signature list"
	}
	return fmt.Sprintf("%s, %d bytes, sha256 %s", s, v.Bytes, v.SHA256)
}

// sigVar compares a key or allow-list variable. Any change to one is
// security-relevant: these variables decide what the firmware and shim will
// run, and nothing that updates them routinely is known to this scan.
func (d *differ) sigVar(item, what string, b, c BaselineVar) {
	if !d.known("efi", item, b.State, c.State) {
		return
	}
	old, cur := describeVar(b), describeVar(c)
	switch {
	case b.State == StateAbsent && c.State == StateAbsent:
	case b.State == StateAbsent:
		d.add(KindAdded, SeveritySecurity, "efi", item, old, cur,
			what+" was absent when the baseline was recorded and is present now: keys were enrolled")
	case c.State == StateAbsent:
		detail := what + " was present when the baseline was recorded and is gone"
		if item == "efi.pk" {
			detail += ": without a platform key the firmware is in setup mode, where every Secure Boot key can be replaced without authorisation"
		}
		d.add(KindRemoved, SeveritySecurity, "efi", item, old, cur, detail)
	case b.SHA256 != c.SHA256:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			what+" has different content: what the boot chain trusts has changed. A firmware or OS key update does this too (the Microsoft 2023 certificate rollover, a new shim vendor certificate), and so does enrolling an attacker's key; it has to be confirmed either way")
	}
}

// dbx is the one variable with an expected direction: it is meant to grow.
func (d *differ) dbx(b, c BaselineVar) {
	const item = "efi.dbx"
	if !d.known("efi", item, b.State, c.State) {
		return
	}
	old, cur := describeVar(b), describeVar(c)
	switch {
	case b.State == StateAbsent && c.State == StateAbsent:
	case b.State == StateAbsent:
		d.add(KindAdded, SeverityExpectedUpdate, "efi", item, old, cur,
			detailUpdate+"The revocation list (dbx) was absent when the baseline was recorded and is present now: revocations were added")
	case c.State == StateAbsent:
		d.add(KindRemoved, SeveritySecurity, "efi", item, old, cur,
			"the revocation list (dbx) is gone: every boot loader it revoked is trusted again")
	case b.SHA256 == c.SHA256:
	case b.Unparsed || c.Unparsed:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			"the revocation list (dbx) changed and is not a well-formed signature list on at least one side, so its entries cannot be counted")
	case c.Hashes < b.Hashes || c.Certificates < b.Certificates || c.Other < b.Other:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			"the revocation list (dbx) SHRANK: revocations were removed, so boot loaders that had been revoked are trusted again. Restoring factory keys in firmware setup does this, and so does a rollback made to boot a vulnerable loader")
	case c.Hashes > b.Hashes || c.Certificates > b.Certificates || c.Other > b.Other:
		d.add(KindChanged, SeverityExpectedUpdate, "efi", item, old, cur,
			detailUpdate+"The revocation list (dbx) grew and lost nothing by count: a dbx update from the firmware vendor, the OS or fwupd. Counts cannot show one entry replaced by another; --dbx-reference checks the content against a published list")
	default:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			"the revocation list (dbx) has the same number of entries and different content: revocations were replaced, not added")
	}
}

func describeSBAT(s BaselineSBAT) string {
	if s.State != StatePresent {
		return s.State
	}
	if s.Unparsed {
		return "unparsed, sha256 " + s.SHA256
	}
	var parts []string
	for _, e := range s.Entries {
		p := e.Component + "," + strconv.FormatUint(e.Generation, 10)
		if e.Date != "" {
			p += "," + e.Date
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// sbatDirection compares two entries of one component: -1 the level fell,
// +1 it rose, 0 it is the same.
func sbatDirection(b, c SBATEntry) int {
	switch {
	case c.Generation < b.Generation:
		return -1
	case c.Generation > b.Generation:
		return 1
	case b.Date == c.Date:
		return 0
	}
	bd, berr := strconv.ParseUint(b.Date, 10, 64)
	cd, cerr := strconv.ParseUint(c.Date, 10, 64)
	if berr != nil || cerr != nil || cd < bd {
		return -1 // a datestamp that cannot be ordered is not assumed to be newer
	}
	return 1
}

func (d *differ) sbat(b, c BaselineSBAT) {
	const item = "efi.sbat"
	if !d.known("efi", item, b.State, c.State) {
		return
	}
	old, cur := describeSBAT(b), describeSBAT(c)
	switch {
	case b.State == StateAbsent && c.State == StateAbsent:
		return
	case b.State == StateAbsent:
		d.add(KindAdded, SeverityExpectedUpdate, "efi", item, old, cur,
			detailUpdate+"Shim publishes an SBAT revocation level now and did not when the baseline was recorded: a shim update, or the first boot through shim")
		return
	case c.State == StateAbsent:
		d.add(KindRemoved, SeveritySecurity, "efi", item, old, cur,
			"the SBAT revocation level is no longer published: this boot did not go through shim, or the level was cleared")
		return
	case b.SHA256 == c.SHA256:
		return
	case b.Unparsed || c.Unparsed:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			"the SBAT revocation level changed and is not in shim's format on at least one side, so the direction of the change cannot be told")
		return
	}
	have := map[string]SBATEntry{}
	for _, e := range c.Entries {
		have[e.Component] = e
	}
	var fell, rose []string
	seen := map[string]bool{}
	for _, e := range b.Entries {
		seen[e.Component] = true
		now, ok := have[e.Component]
		switch {
		case !ok:
			fell = append(fell, e.Component+" (no longer listed)")
		case sbatDirection(e, now) < 0:
			fell = append(fell, e.Component)
		case sbatDirection(e, now) > 0:
			rose = append(rose, e.Component)
		}
	}
	for _, e := range c.Entries {
		if !seen[e.Component] {
			rose = append(rose, e.Component+" (new)")
		}
	}
	switch {
	case len(fell) > 0:
		d.add(KindChanged, SeveritySecurity, "efi", item, old, cur,
			"the SBAT revocation level FELL for "+strings.Join(fell, ", ")+": shim accepts older, revoked generations of these components again")
	case len(rose) > 0:
		d.add(KindChanged, SeverityExpectedUpdate, "efi", item, old, cur,
			detailUpdate+"The SBAT revocation level rose for "+strings.Join(rose, ", ")+" and fell for nothing: a shim or distribution revocation update")
	default:
		d.add(KindChanged, SeverityInfo, "efi", item, old, cur,
			"the SBAT variable's bytes differ and every component's level is the same")
	}
}

// firstStarted is the entry the firmware starts first: the first id in the
// boot order that exists and is active. An empty id with ok set means none
// does, so the firmware falls back to its own default. ok is false when the
// answer depends on something that was not read.
func firstStarted(e *BaselineEFI) (id string, ok bool) {
	if e.BootOrderState == StateUnknown {
		return "", false
	}
	entries := map[string]BaselineBootEntry{}
	for _, be := range e.BootEntries {
		entries[be.ID] = be
	}
	for _, id := range e.BootOrder {
		be, have := entries[id]
		switch {
		case !have && !e.BootEntriesComplete, have && be.Unread:
			return "", false
		case have && be.Active:
			return id, true
		}
	}
	return "", true
}

func (d *differ) bootOrder(b, c *BaselineEFI) {
	const item = "efi.boot_order"
	if !d.known("efi", item, b.BootOrderState, c.BootOrderState) {
		return
	}
	show := func(e *BaselineEFI) string {
		if len(e.BootOrder) == 0 {
			return "(none: firmware default order)"
		}
		return strings.Join(e.BootOrder, ",")
	}
	name := func(id string) string {
		if id == "" {
			return "the firmware's default"
		}
		return "Boot" + id
	}
	first := func(e *BaselineEFI) string {
		if len(e.BootOrder) == 0 {
			return ""
		}
		return e.BootOrder[0]
	}
	same := strings.Join(b.BootOrder, ",") == strings.Join(c.BootOrder, ",")
	bStart, bOK := firstStarted(b)
	cStart, cOK := firstStarted(c)
	switch {
	case first(b) != first(c):
		d.add(KindChanged, SeveritySecurity, "efi", item, show(b), show(c),
			"a different entry is first in the boot order: "+name(first(b))+" when the baseline was recorded, "+name(first(c))+" now")
	case bOK && cOK && bStart != cStart:
		detail := "the entry the firmware starts first has changed from " + name(bStart) + " to " + name(cStart)
		if same {
			detail += ": the order is the same, and the entry that was first in it is now inactive or gone"
		}
		d.add(KindChanged, SeveritySecurity, "efi", item, show(b), show(c), detail)
	case !same:
		d.add(KindChanged, SeverityInfo, "efi", item, show(b), show(c),
			"the boot order changed after its first entry; the entry started first is the same")
	}
}

func describeEntry(e BaselineBootEntry) string {
	if e.Unread {
		return "(unreadable)"
	}
	target := e.FilePath
	if target == "" {
		target = "(no file path)"
	}
	state := "active"
	if !e.Active {
		state = "inactive"
	}
	return fmt.Sprintf("%q -> %s (%s)", e.Description, target, state)
}

func (d *differ) bootEntries(b, c *BaselineEFI) {
	base, cur := map[string]BaselineBootEntry{}, map[string]BaselineBootEntry{}
	var ids []string
	for _, e := range b.BootEntries {
		base[e.ID] = e
		ids = append(ids, e.ID)
	}
	for _, e := range c.BootEntries {
		cur[e.ID] = e
		if _, ok := base[e.ID]; !ok {
			ids = append(ids, e.ID)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		item := "efi.boot." + id
		be, inBase := base[id]
		ce, inCur := cur[id]
		switch {
		case !inBase && !b.BootEntriesComplete:
			d.add(KindNotInBaseline, SeverityInfo, "efi", item, "", describeEntry(ce),
				"the baseline's list of boot entries was partial, so this entry may already have existed")
		case !inBase:
			d.add(KindAdded, SeveritySecurity, "efi", item, "", describeEntry(ce),
				"a boot entry exists that the baseline does not have. Installing an OS or a boot loader adds one, and so does a bootkit that wants the firmware to start it")
		case !inCur && !c.BootEntriesComplete:
			d.add(KindNotReverified, SeverityInfo, "efi", item, describeEntry(be), "",
				"could not be re-verified: the list of boot entries read in this run is partial")
		case !inCur:
			d.add(KindRemoved, SeverityInfo, "efi", item, describeEntry(be), "",
				"the boot entry is gone. Removing an entry starts nothing new: if it changes which entry boots first, efi.boot_order reports that")
		case be.Unread && ce.Unread:
		case be.Unread:
			d.add(KindNotInBaseline, SeverityInfo, "efi", item, "", describeEntry(ce), detailNotInBaseline)
		case ce.Unread:
			d.add(KindNotReverified, SeverityInfo, "efi", item, describeEntry(be), "", detailNotReverified)
		default:
			var what []string
			if be.FilePath != ce.FilePath {
				what = append(what, "the file it starts")
			}
			if be.Active != ce.Active {
				what = append(what, "whether it is active")
			}
			if be.TargetSHA256 != ce.TargetSHA256 && be.FilePath == ce.FilePath {
				what = append(what, "its device path, attributes or the data passed to the loader (the same file name on another partition, or other arguments)")
			}
			switch {
			case len(what) > 0:
				d.add(KindChanged, SeveritySecurity, "efi", item, describeEntry(be), describeEntry(ce),
					"the boot entry changed in "+strings.Join(what, ", and in ")+": what the firmware starts under this entry is not what the baseline recorded")
			case be.Description != ce.Description && be.TargetSHA256 == ce.TargetSHA256:
				d.add(KindChanged, SeverityInfo, "efi", item, describeEntry(be), describeEntry(ce),
					"only the entry's label changed; what it starts is the same")
			case be.SHA256 != ce.SHA256:
				d.add(KindChanged, SeveritySecurity, "efi", item, describeEntry(be), describeEntry(ce),
					"the load option's bytes differ from the baseline (sha256 "+be.SHA256+" then, "+ce.SHA256+" now) in a part the scan does not decode")
			}
		}
	}
}

// ── EFI System Partition ─────────────────────────────────────────────────────

// espIndex keys binaries by case-folded path: FAT does not distinguish case,
// so a directory recreated as "Boot" instead of "BOOT" holds the same file.
// Two paths that fold to one name (possible only on something that is not a
// FAT volume) keep their exact spelling.
func espIndex(bins []BaselineBinary) (map[string]BaselineBinary, []string) {
	m := map[string]BaselineBinary{}
	var keys []string
	for _, bin := range bins {
		k := "fold:" + strings.ToLower(bin.Path)
		if _, dup := m[k]; dup {
			k = "exact:" + bin.Path
		}
		m[k] = bin
		keys = append(keys, k)
	}
	return m, keys
}

func describeBinary(b BaselineBinary) string {
	sig := "unsigned"
	if b.Signed {
		sig = "signature present"
	}
	digest := b.SHA256
	if digest == "" {
		digest = "(too large to hash)"
	}
	return fmt.Sprintf("sha256 %s, %d bytes, %s", digest, b.Size, sig)
}

func (d *differ) esp(b, c *BaselineESP) {
	summary := func(e *BaselineESP) string {
		if e == nil {
			return ""
		}
		return fmt.Sprintf("%d EFI binaries", len(e.Binaries))
	}
	if !d.surface("esp", "esp", b != nil, c != nil, summary(b), summary(c), "the EFI System Partition") {
		return
	}
	base, baseKeys := espIndex(b.Binaries)
	cur, curKeys := espIndex(c.Binaries)
	byDigest := map[string]string{}
	for _, bin := range b.Binaries {
		if bin.SHA256 != "" {
			byDigest[bin.SHA256] = bin.Path
		}
	}

	for _, k := range baseKeys {
		bb := base[k]
		item := "esp:" + bb.Path
		cb, ok := cur[k]
		switch {
		case !ok && !c.Complete:
			d.add(KindNotReverified, SeverityInfo, "esp", item, describeBinary(bb), "",
				"could not be re-verified: part of the EFI System Partition could not be read in this run, so the file may still be there")
		case !ok:
			d.add(KindRemoved, SeverityInfo, "esp", item, describeBinary(bb), "",
				"the EFI binary is gone. A removal starts nothing new: whatever runs in its place is either in the baseline or reported as added or changed")
		case bb.SHA256 != "" && cb.SHA256 != "":
			if bb.SHA256 == cb.SHA256 {
				continue
			}
			detail := "the EFI binary's content differs from the baseline. A boot loader or kernel update does this, and so does a bootkit that replaces the loader"
			switch {
			case bb.Signed && !cb.Signed:
				detail += "; the signature the baseline recorded is gone"
			case cb.Signed:
				detail += "; a signature is present, which this scan cannot verify, so the change is not treated as an update"
			}
			if bb.Subsystem != cb.Subsystem {
				detail += fmt.Sprintf("; the PE subsystem changed from %q to %q", bb.Subsystem, cb.Subsystem)
			}
			d.add(KindChanged, SeveritySecurity, "esp", item, describeBinary(bb), describeBinary(cb), detail)
		case bb.Size != cb.Size:
			d.add(KindChanged, SeveritySecurity, "esp", item, describeBinary(bb), describeBinary(cb),
				"the EFI binary's size differs from the baseline (it is too large to hash on at least one side)")
		default:
			d.add(KindNotReverified, SeverityInfo, "esp", item, describeBinary(bb), describeBinary(cb),
				"could not be re-verified: the file is too large to hash on at least one side; its size is unchanged")
		}
	}
	for _, k := range curKeys {
		if _, ok := base[k]; ok {
			continue
		}
		cb := cur[k]
		item := "esp:" + cb.Path
		if !b.Complete {
			d.add(KindNotInBaseline, SeverityInfo, "esp", item, "", describeBinary(cb),
				"the baseline's inventory of the EFI System Partition was partial, so this file may already have been there")
			continue
		}
		detail := "an EFI binary is on the EFI System Partition that the baseline does not have. A package or kernel update adds one, and so does a bootkit"
		if from, ok := byDigest[cb.SHA256]; ok && cb.SHA256 != "" {
			detail += "; its content is identical to " + from + " in the baseline (a copy or a move)"
		}
		d.add(KindAdded, SeveritySecurity, "esp", item, "", describeBinary(cb), detail)
	}
}

// ── disks ────────────────────────────────────────────────────────────────────

func describePartition(p BaselinePartition) string {
	s := fmt.Sprintf("type %s, start %d, %d sectors", p.Type, p.StartLBA, p.Sectors)
	if p.BootSector != "" {
		s += ", boot sector " + p.BootSector
	}
	if p.ESP {
		s += ", ESP"
	}
	if p.Active {
		s += ", active"
	}
	return s
}

func orNone(s, none string) string {
	if s == "" {
		return none
	}
	return s
}

func (d *differ) disks(b, c []BaselineDisk) {
	cur := map[string]BaselineDisk{}
	for _, disk := range c {
		cur[disk.Path] = disk
	}
	base := map[string]bool{}
	for _, bd := range b {
		base[bd.Path] = true
		item := "disk:" + bd.Path
		cd, ok := cur[bd.Path]
		if !ok {
			d.add(KindNotReverified, SeverityInfo, "disk", item, fmt.Sprintf("%s, %d partitions", bd.Scheme, len(bd.Partitions)), "",
				"could not be re-verified: the baseline records this disk and it was not read in this run (name it with --disk; reading a device usually needs root). Disks are never opened because a baseline names them")
			continue
		}
		d.disk(item, bd, cd)
	}
	for _, cd := range c {
		if !base[cd.Path] {
			d.add(KindNotInBaseline, SeverityInfo, "disk", "disk:"+cd.Path, "", fmt.Sprintf("%s, %d partitions", cd.Scheme, len(cd.Partitions)),
				"this disk was read in this run and the baseline does not record it under this path; nothing on it was compared")
		}
	}
}

func (d *differ) disk(item string, b, c BaselineDisk) {
	if b.Scheme != c.Scheme {
		d.add(KindChanged, SeveritySecurity, "disk", item+".partition_table", b.Scheme, c.Scheme,
			"the disk's partition scheme changed: the table was destroyed, converted or replaced")
	}
	if b.BootCodeSHA256 != c.BootCodeSHA256 {
		d.add(KindChanged, SeveritySecurity, "disk", item+".mbr.boot_code",
			orNone(b.BootCodeSHA256, "(no boot code)"), orNone(c.BootCodeSHA256, "(no boot code)"),
			"the code in the master boot record changed. Reinstalling a BIOS boot loader does this, and it is exactly where an MBR bootkit goes")
	}
	if b.DiskSignature != c.DiskSignature {
		d.add(KindChanged, SeveritySecurity, "disk", item+".mbr.disk_signature", orNone(b.DiskSignature, "(none)"), orNone(c.DiskSignature, "(none)"),
			"the MBR disk signature changed: the first sector was rewritten, or this path now names a different disk (device names are not stable; a /dev/disk/by-id path is)")
	}
	if b.DiskGUID != c.DiskGUID {
		d.add(KindChanged, SeveritySecurity, "disk", item+".gpt.disk_guid", orNone(b.DiskGUID, "(none)"), orNone(c.DiskGUID, "(none)"),
			"the GPT disk GUID changed: the partition table was recreated, or this path now names a different disk (device names are not stable; a /dev/disk/by-id path is)")
	}

	key := func(p BaselinePartition) string { return p.Scheme + ".partition." + strconv.Itoa(p.Index) }
	cur := map[string]BaselinePartition{}
	for _, p := range c.Partitions {
		cur[key(p)] = p
	}
	base := map[string]bool{}
	unread := func(p BaselinePartition) bool { return p.BootSector == "" || p.BootSector == "unread" }
	for _, bp := range b.Partitions {
		base[key(bp)] = true
		pitem := item + "." + key(bp)
		cp, ok := cur[key(bp)]
		if !ok {
			d.add(KindRemoved, SeveritySecurity, "disk", pitem, describePartition(bp), "",
				"the partition table changed: this partition is no longer in it")
			continue
		}
		// The boot-sector kind is compared only when both sides read it.
		bsDiffers := !unread(bp) && !unread(cp) && bp.BootSector != cp.BootSector
		switch {
		case bp.Type != cp.Type || bp.StartLBA != cp.StartLBA || bp.Sectors != cp.Sectors || bp.ESP != cp.ESP || bp.Active != cp.Active || bsDiffers:
			detail := "the partition table changed: this entry's type, position, size or flags differ from the baseline"
			if bsDiffers && bp.Type == cp.Type && bp.StartLBA == cp.StartLBA && bp.Sectors == cp.Sectors && bp.ESP == cp.ESP && bp.Active == cp.Active {
				detail = "the partition's first sector is a different kind of volume than the baseline recorded: it was reformatted or overwritten"
			}
			d.add(KindChanged, SeveritySecurity, "disk", pitem, describePartition(bp), describePartition(cp), detail)
		case !unread(bp) && unread(cp):
			d.add(KindNotReverified, SeverityInfo, "disk", pitem, describePartition(bp), describePartition(cp),
				"could not be re-verified: the partition's first sector was not read in this run; the table entry is unchanged")
		}
	}
	for _, cp := range c.Partitions {
		if !base[key(cp)] {
			d.add(KindAdded, SeveritySecurity, "disk", item+"."+key(cp), "", describePartition(cp),
				"the partition table changed: this partition is not in the baseline")
		}
	}
}

// ── firmware inventory ───────────────────────────────────────────────────────

func (d *differ) firmware(b, c *BaselineFirmware) {
	if b == nil {
		b = &BaselineFirmware{}
	}
	if c == nil {
		c = &BaselineFirmware{}
	}

	count := func(n int, what string) string { return fmt.Sprintf("%d %s", n, what) }
	if d.surface("acpi", "acpi", b.ACPIRead, c.ACPIRead, count(len(b.ACPITables), "ACPI tables"), count(len(c.ACPITables), "ACPI tables"), "the ACPI table list") {
		d.acpi(b, c)
	}
	if d.surface("pci", "pci", b.PCIRead, c.PCIRead, count(len(b.OptionROMs), "option ROMs"), count(len(c.OptionROMs), "option ROMs"), "the PCI option-ROM inventory") {
		d.optionROMs(b.OptionROMs, c.OptionROMs)
	}
	if d.surface("esrt", "esrt", b.ESRTRead, c.ESRTRead, count(len(b.ESRT), "firmware components"), count(len(c.ESRT), "firmware components"), "the firmware resource table (root only)") {
		d.esrt(b.ESRT, c.ESRT)
	}
}

func describeWPBT(w *BaselineWPBT) string {
	switch {
	case w == nil:
		return ""
	case !w.SizeKnown:
		return "present, declared size not readable"
	}
	return fmt.Sprintf("present, declared platform binary size %d bytes", w.HandoffSize)
}

func (d *differ) acpi(b, c *BaselineFirmware) {
	base, cur := map[string]bool{}, map[string]bool{}
	for _, t := range b.ACPITables {
		base[t] = true
	}
	for _, t := range c.ACPITables {
		cur[t] = true
		if base[t] {
			continue
		}
		item := "acpi.table." + t
		if t == "WPBT" {
			d.add(KindAdded, SeveritySecurity, "acpi", item, "", describeWPBT(c.WPBT),
				"a WPBT table appeared: the firmware now hands Windows a binary to run at every boot. A firmware update or a setup option (vendor anti-theft or management agents) adds one, and so does a firmware implant")
			continue
		}
		d.add(KindAdded, SeveritySecurity, "acpi", item, "", "present",
			"the firmware publishes an ACPI table the baseline does not have. ACPI tables carry code the kernel runs; a firmware update or a changed setup option adds tables, and so does modified firmware")
	}
	for _, t := range b.ACPITables {
		if cur[t] {
			continue
		}
		item := "acpi.table." + t
		if protectionTables[t] {
			d.add(KindRemoved, SeveritySecurity, "acpi", item, "present", "",
				"an ACPI table the OS relies on for protection is gone: without DMAR or IVRS the kernel cannot confine device memory access, without TPM2 or TCPA there is no measured boot. Turning the feature off in firmware setup does this")
			continue
		}
		d.add(KindRemoved, SeverityInfo, "acpi", item, describeOr(t == "WPBT", describeWPBT(b.WPBT), "present"), "",
			"the firmware no longer publishes this ACPI table (a firmware update or a changed setup option)")
	}
	if bw, cw := b.WPBT, c.WPBT; bw != nil && cw != nil {
		const item = "acpi.table.WPBT"
		switch {
		case bw.SizeKnown && cw.SizeKnown && bw.HandoffSize != cw.HandoffSize:
			d.add(KindChanged, SeveritySecurity, "acpi", item, describeWPBT(bw), describeWPBT(cw),
				"the binary the firmware hands to Windows through the WPBT table has a different size than the baseline recorded")
		case bw.SizeKnown && !cw.SizeKnown:
			d.add(KindNotReverified, SeverityInfo, "acpi", item, describeWPBT(bw), describeWPBT(cw),
				"could not be re-verified: the table is still published, and its content needs root to read")
		case !bw.SizeKnown && cw.SizeKnown:
			d.add(KindNotInBaseline, SeverityInfo, "acpi", item, describeWPBT(bw), describeWPBT(cw), detailNotInBaseline)
		}
	}
}

func describeOr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// differs reports two values that were both read and are not the same.
func differs(a, b string) bool { return a != "" && b != "" && a != b }

func describeROM(r BaselineROM) string {
	return fmt.Sprintf("vendor %s device %s, %d bytes", orNone(r.Vendor, "?"), orNone(r.Device, "?"), r.Size)
}

func (d *differ) optionROMs(b, c []BaselineROM) {
	cur := map[string]BaselineROM{}
	for _, r := range c {
		cur[r.Address] = r
	}
	base := map[string]bool{}
	for _, br := range b {
		base[br.Address] = true
		item := "pci.rom." + br.Address
		cr, ok := cur[br.Address]
		switch {
		case !ok:
			d.add(KindRemoved, SeverityInfo, "pci", item, describeROM(br), "",
				"no device at this address exposes an option ROM any more (the device was removed, or its ROM disabled)")
		// An empty vendor or device id was not read; it is unknown, not a value.
		case differs(br.Vendor, cr.Vendor) || differs(br.Device, cr.Device):
			d.add(KindChanged, SeveritySecurity, "pci", item, describeROM(br), describeROM(cr),
				"a different device exposes an option ROM at this address: the firmware runs that device's ROM code at boot")
		case br.Size != cr.Size:
			d.add(KindChanged, SeveritySecurity, "pci", item, describeROM(br), describeROM(cr),
				"the device's option ROM changed size: it was reflashed. A device firmware update does this, and so does an option-ROM implant; the contents are not read")
		case (br.Vendor != "" && cr.Vendor == "") || (br.Device != "" && cr.Device == ""):
			d.add(KindNotReverified, SeverityInfo, "pci", item, describeROM(br), describeROM(cr),
				"could not be re-verified: the device's vendor or device id could not be read in this run; the ROM's size is unchanged")
		}
	}
	for _, cr := range c {
		if !base[cr.Address] {
			d.add(KindAdded, SeveritySecurity, "pci", "pci.rom."+cr.Address, "", describeROM(cr),
				"a device exposes an option ROM that the baseline does not have: code the firmware runs at boot. A newly fitted card does this")
		}
	}
}

func (d *differ) esrt(b, c []BaselineESRT) {
	cur := map[string]BaselineESRT{}
	for _, e := range c {
		cur[e.Class] = e
	}
	base := map[string]bool{}
	for _, be := range b {
		base[be.Class] = true
		item := "esrt." + be.Class
		ce, ok := cur[be.Class]
		if !ok {
			d.add(KindRemoved, SeverityInfo, "esrt", item, "version "+be.Version, "",
				"the platform no longer lists this updatable firmware component (a device was detached, or a firmware update changed what is reported)")
			continue
		}
		switch {
		case be.Version == ce.Version:
			continue
		case ce.Version == "": // the class was read and the version was not
			d.add(KindNotReverified, SeverityInfo, "esrt", item, "version "+be.Version, "", detailNotReverified)
			continue
		case be.Version == "":
			d.add(KindNotInBaseline, SeverityInfo, "esrt", item, "", "version "+ce.Version, detailNotInBaseline)
			continue
		}
		bv, berr := strconv.ParseUint(be.Version, 10, 64)
		cv, cerr := strconv.ParseUint(ce.Version, 10, 64)
		switch {
		case berr != nil || cerr != nil:
			d.add(KindChanged, SeveritySecurity, "esrt", item, "version "+be.Version, "version "+ce.Version,
				"the firmware component's version changed and is not a number on at least one side, so the direction cannot be told")
		case cv < bv:
			d.add(KindChanged, SeveritySecurity, "esrt", item, "version "+be.Version, "version "+ce.Version,
				"the firmware component's version went DOWN: firmware was rolled back to an older release, which is how a fixed firmware vulnerability is made exploitable again")
		default:
			d.add(KindChanged, SeverityExpectedUpdate, "esrt", item, "version "+be.Version, "version "+ce.Version,
				detailUpdate+"The firmware component's version went up: a firmware update was installed")
		}
	}
	for _, ce := range c {
		if !base[ce.Class] {
			d.add(KindAdded, SeverityInfo, "esrt", "esrt."+ce.Class, "", "version "+ce.Version,
				"the platform lists an updatable firmware component the baseline does not have (a device was attached, or a firmware update changed what is reported)")
		}
	}
}

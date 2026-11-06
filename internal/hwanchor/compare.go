package hwanchor

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// DiffKind is the type of one difference between a baseline and a snapshot.
type DiffKind string

const (
	// KindChanged: the anchor was an identity in the baseline and is a
	// different identity now, or a physical NIC whose address was the
	// permanent one now carries a userspace-set address. This is the only
	// kind that means "not the same hardware".
	KindChanged DiffKind = "changed"
	// KindNotReverified: the anchor was an identity in the baseline and
	// could not be read as one now (absent, unreadable, placeholder). It may
	// be unchanged; this run cannot say.
	KindNotReverified DiffKind = "not-reverified"
	// KindNotInBaseline: the anchor is an identity now and the baseline holds
	// nothing to compare it with.
	KindNotInBaseline DiffKind = "not-in-baseline"
	// KindEntropySourceChanged: the active hardware RNG differs. That is the
	// host's entropy health, selectable at run time, and not an identity.
	KindEntropySourceChanged DiffKind = "entropy-source-changed"
)

// DiffKinds lists every kind, in report order.
var DiffKinds = []DiffKind{KindChanged, KindNotReverified, KindNotInBaseline, KindEntropySourceChanged}

// Difference is one anchor that does not compare equal.
type Difference struct {
	Kind DiffKind `json:"kind"`
	// Anchor names what differs, with the names Snapshot.Unverifiable uses.
	Anchor        string `json:"anchor"`
	BaselineState State  `json:"baseline_state"`
	CurrentState  State  `json:"current_state"`
	// Baseline and Current are the two values, where the side held one.
	Baseline string `json:"baseline,omitempty"`
	Current  string `json:"current,omitempty"`
	Detail   string `json:"detail"`
}

// IdentityChanged reports whether any difference is KindChanged.
func IdentityChanged(diffs []Difference) bool {
	for _, d := range diffs {
		if d.Kind == KindChanged {
			return true
		}
	}
	return false
}

// Compare lists how current differs from baseline. Only anchors that are
// StateOK on both sides are compared as identities; a placeholder is never
// one. The result is empty, not nil, when nothing differs.
//
// It refuses two snapshots that cannot be compared: different schema
// versions, or one redacted and the other not.
func Compare(baseline, current *Snapshot) ([]Difference, error) {
	if baseline == nil || current == nil {
		return nil, errors.New("hwanchor: nothing to compare")
	}
	if baseline.Schema != SchemaVersion || current.Schema != SchemaVersion {
		return nil, fmt.Errorf("hwanchor: cannot compare schema %d with schema %d (this build reads schema %d)",
			baseline.Schema, current.Schema, SchemaVersion)
	}
	if baseline.Redacted != current.Redacted {
		side := func(s *Snapshot) string {
			if s.Redacted {
				return "redacted"
			}
			return "not redacted"
		}
		return nil, fmt.Errorf("hwanchor: the baseline is %s and the current snapshot is %s; "+
			"a digest cannot be compared with a raw value, so redact both or neither",
			side(baseline), side(current))
	}

	diffs := []Difference{}
	add := func(d *Difference) {
		if d != nil {
			diffs = append(diffs, *d)
		}
	}

	// ── DMI ──
	for _, name := range DMIFields {
		d := compareField("dmi."+name, field(baseline.DMI, name), field(current.DMI, name))
		if d != nil && d.Kind == KindChanged && strings.HasPrefix(name, "bios_") {
			d.Detail = "the firmware identification differs from the baseline; a firmware update does this"
		}
		add(d)
	}

	// ── physical network interfaces, by name ──
	base, cur := byName(baseline.Interfaces), byName(current.Interfaces)
	names := make([]string, 0, len(base)+len(cur))
	for n := range base {
		names = append(names, n)
	}
	for n := range cur {
		if _, ok := base[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		anchor := "net." + n + ".permanent_address"
		b, inBase := base[n]
		c, inCur := cur[n]
		switch {
		case inBase && !inCur:
			if b.PermanentAddress.OK() {
				add(&Difference{Kind: KindNotReverified, Anchor: anchor,
					BaselineState: StateOK, CurrentState: StateAbsent, Baseline: b.PermanentAddress.Value,
					Detail: "could not be re-verified: the interface is not present as a physical interface now"})
			}
		case !inBase:
			if c.PermanentAddress.OK() {
				add(&Difference{Kind: KindNotInBaseline, Anchor: anchor,
					BaselineState: StateAbsent, CurrentState: StateOK, Current: c.PermanentAddress.Value,
					Detail: "the baseline has no physical interface of this name"})
			}
		default:
			d := compareField(anchor, b.PermanentAddress, c.PermanentAddress)
			switch {
			case d == nil:
			case d.Kind == KindNotReverified && c.Divergence:
				// Permanent in the baseline, set by userspace now: the one
				// divergence sysfs can witness.
				d.Kind = KindChanged
				if c.Address.OK() {
					d.Current = c.Address.Value
				}
				d.Detail = "addr_assign_type went from 0 (permanent) to 3 (set by userspace): the configured MAC is no longer the burned-in one. " +
					"sysfs shows that it was changed, not what the burned-in address is now"
			case d.Kind == KindChanged:
				d.Detail = "the permanent address under this interface name differs from the baseline: a different NIC, or the interface was renamed"
			}
			add(d)
		}
	}

	// ── TPM ──
	bt, ct := baseline.TPM, current.TPM
	switch {
	case bt.State == StateOK && ct.State != StateOK:
		add(&Difference{Kind: KindNotReverified, Anchor: "tpm", BaselineState: bt.State, CurrentState: ct.State,
			Detail: "could not be re-verified: the baseline had a TPM and it is now " + Field{State: ct.State, Reason: ct.Reason}.describe()})
	case bt.State != StateOK && ct.State == StateOK:
		add(&Difference{Kind: KindNotInBaseline, Anchor: "tpm", BaselineState: bt.State, CurrentState: ct.State,
			Detail: "a TPM is present now and the baseline recorded none (" + string(bt.State) + ")"})
	case bt.State == StateOK:
		add(compareField("tpm.version_major", bt.VersionMajor, ct.VersionMajor))
		for i := 0; i < PCRCount; i++ {
			d := compareField(fmt.Sprintf("tpm.pcr.%d", i), pcr(bt.PCRs, i), pcr(ct.PCRs, i))
			if d != nil && d.Kind == KindChanged {
				d.Detail = "the measured boot chain differs from the baseline. A firmware update, a boot-configuration change and a " +
					"boot-chain implant all do this; the PCR does not say which"
			}
			add(d)
		}
	}

	// ── entropy source: health, not identity ──
	br, cr := baseline.RNG, current.RNG
	switch {
	case br.State == StateOK && cr.State == StateUnreadable:
		add(&Difference{Kind: KindNotReverified, Anchor: "rng", BaselineState: br.State, CurrentState: cr.State, Baseline: br.Current,
			Detail: "could not be re-verified: the active hardware RNG is now " + Field{State: cr.State, Reason: cr.Reason}.describe()})
	case br.State == StateUnreadable && cr.State == StateOK:
		add(&Difference{Kind: KindNotInBaseline, Anchor: "rng", BaselineState: br.State, CurrentState: cr.State, Current: cr.Current,
			Detail: "the baseline holds no value to compare (unreadable)"})
	case br.State == StateUnreadable || cr.State == StateUnreadable:
	case br.State == StateOK && cr.State == StateAbsent:
		add(&Difference{Kind: KindEntropySourceChanged, Anchor: "rng", BaselineState: br.State, CurrentState: cr.State, Baseline: br.Current, Current: cr.Current,
			Detail: "degraded: the baseline had an active hardware RNG and none is active now; the host runs on software entropy"})
	case br.State != cr.State || br.Current != cr.Current:
		add(&Difference{Kind: KindEntropySourceChanged, Anchor: "rng", BaselineState: br.State, CurrentState: cr.State, Baseline: br.Current, Current: cr.Current,
			Detail: "the active hardware RNG differs from the baseline"})
	}
	return diffs, nil
}

// compareField applies the one rule every anchor shares.
func compareField(anchor string, b, c Field) *Difference {
	d := &Difference{Anchor: anchor, BaselineState: b.State, CurrentState: c.State}
	switch {
	case b.OK() && c.OK():
		if b.Value == c.Value {
			return nil
		}
		d.Kind, d.Baseline, d.Current = KindChanged, b.Value, c.Value
		d.Detail = "the value differs from the baseline"
	case b.OK():
		d.Kind, d.Baseline = KindNotReverified, b.Value
		d.Detail = "could not be re-verified: now " + c.describe()
	case c.OK():
		d.Kind, d.Current = KindNotInBaseline, c.Value
		d.Detail = "the baseline holds no value to compare (" + string(b.State) + ")"
	default:
		// Neither side is an identity: nothing to say. Two placeholders
		// are not compared even when they differ.
		return nil
	}
	return d
}

// field is a DMI field, absent when the snapshot does not hold it.
func field(m map[string]Field, name string) Field {
	if f, ok := m[name]; ok && f.State != "" {
		return f
	}
	return Field{State: StateAbsent}
}

// pcr is the PCR with the given index, absent when the snapshot has none.
func pcr(list []PCR, index int) Field {
	for _, p := range list {
		if p.Index == index && p.State != "" {
			return p.Field
		}
	}
	return Field{State: StateAbsent}
}

func byName(list []Interface) map[string]Interface {
	out := make(map[string]Interface, len(list))
	for _, i := range list {
		out[i.Name] = i
	}
	return out
}

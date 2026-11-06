package hwanchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxSnapshotBytes bounds an encoded snapshot. A full one (1024 interfaces,
// every attribute a whole page of escaped bytes) stays well under it.
const MaxSnapshotBytes = 8 << 20

// Marshal encodes a snapshot as indented JSON with a trailing newline. This
// is the baseline format: what Parse reads back. Writing it anywhere is the
// caller's decision; this package never writes a file.
func Marshal(s *Snapshot) ([]byte, error) {
	if s == nil {
		return nil, errors.New("hwanchor: no snapshot to encode")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Parse decodes a snapshot written by Marshal and checks that it is one: the
// schema version, every state, the bounds Capture keeps, and that a snapshot
// marked redacted holds no raw identifying value.
func Parse(data []byte) (*Snapshot, error) {
	if len(data) > MaxSnapshotBytes {
		return nil, fmt.Errorf("hwanchor: snapshot is %d bytes, over the %d-byte bound", len(data), MaxSnapshotBytes)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("hwanchor: not a snapshot: %w", err)
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("hwanchor: snapshot schema %d is not supported (this build reads schema %d)", s.Schema, SchemaVersion)
	}
	if s.DMI == nil {
		return nil, errors.New("hwanchor: not a snapshot: no dmi section")
	}
	if len(s.Interfaces) > maxInterfaces || len(s.VirtualInterfaces) > maxInterfaces {
		return nil, fmt.Errorf("hwanchor: snapshot lists more than %d interfaces", maxInterfaces)
	}
	if len(s.TPM.PCRs) > PCRCount {
		return nil, fmt.Errorf("hwanchor: snapshot lists more than %d PCRs", PCRCount)
	}

	check := func(what string, f Field, sensitive bool) error {
		switch f.State {
		case StateOK, StateAbsent, StateUnreadable, StatePlaceholder:
		default:
			return fmt.Errorf("hwanchor: %s has unknown state %q", what, string(f.State))
		}
		if len(f.Value) > maxAttrBytes || len(f.Reason) > maxAttrBytes {
			return fmt.Errorf("hwanchor: %s is longer than %d bytes", what, maxAttrBytes)
		}
		if sensitive && s.Redacted && f.State == StateOK && !isRedactedValue(f.Value) {
			return fmt.Errorf("hwanchor: the snapshot is marked redacted but %s holds a raw value", what)
		}
		return nil
	}
	for name, f := range s.DMI {
		if len(name) > 64 {
			return nil, errors.New("hwanchor: a dmi field name is longer than 64 bytes")
		}
		if err := check("dmi."+name, f, sensitiveDMI[name]); err != nil {
			return nil, err
		}
	}
	for _, i := range s.Interfaces {
		if len(i.Name) > 4*maxIfName { // a replaced invalid byte takes three
			return nil, errors.New("hwanchor: an interface name is longer than any interface name")
		}
		what := "net." + i.Name
		if err := check(what+".address", i.Address, true); err != nil {
			return nil, err
		}
		if err := check(what+".addr_assign_type", i.AssignType, false); err != nil {
			return nil, err
		}
		if err := check(what+".permanent_address", i.PermanentAddress, true); err != nil {
			return nil, err
		}
	}
	switch s.TPM.State {
	case StateOK, StateAbsent, StateUnreadable:
	default:
		return nil, fmt.Errorf("hwanchor: tpm has unknown state %q", string(s.TPM.State))
	}
	if s.TPM.State == StateOK {
		if err := check("tpm.version_major", s.TPM.VersionMajor, false); err != nil {
			return nil, err
		}
	}
	for _, p := range s.TPM.PCRs {
		if p.Index < 0 || p.Index >= PCRCount {
			return nil, fmt.Errorf("hwanchor: PCR index %d is outside 0 to %d", p.Index, PCRCount-1)
		}
		if err := check(fmt.Sprintf("tpm.pcr.%d", p.Index), p.Field, false); err != nil {
			return nil, err
		}
	}
	switch s.RNG.State {
	case StateOK, StateAbsent, StateUnreadable:
	default:
		return nil, fmt.Errorf("hwanchor: rng has unknown state %q", string(s.RNG.State))
	}
	return &s, nil
}

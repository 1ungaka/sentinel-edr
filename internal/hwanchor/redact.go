package hwanchor

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redactedPrefix marks a value Redact has replaced.
const redactedPrefix = "sha256:"

// RedactValue is the digest Redact stores in place of a value: "sha256:" and
// the first 16 hex characters of the SHA-256 of the value as recorded. It is
// unsalted on purpose, so the same serial redacts to the same digest in two
// snapshots; `printf %s VALUE | sha256sum` reproduces it.
func RedactValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return redactedPrefix + hex.EncodeToString(sum[:])[:16]
}

// isRedactedValue reports the shape RedactValue produces.
func isRedactedValue(v string) bool {
	rest, ok := strings.CutPrefix(v, redactedPrefix)
	return ok && len(rest) == 16 && strings.Trim(rest, "0123456789abcdef") == ""
}

// Redact returns a copy of the snapshot with every machine-identifying value
// replaced by its digest: the DMI product UUID and the product, board and
// chassis serials, and the configured and permanent address of each physical
// interface. Only StateOK values are replaced; a placeholder identifies
// nothing and is left readable. PCR values are measurements, not serials, and
// are kept.
//
// The input is not modified. Redacting a redacted snapshot returns an equal
// copy: a digest is never hashed again.
func Redact(s *Snapshot) *Snapshot {
	if s == nil {
		return nil
	}
	out := s.clone()
	if s.Redacted {
		return out
	}
	out.Redacted = true
	for name, f := range out.DMI {
		if sensitiveDMI[name] {
			out.DMI[name] = redactField(f)
		}
	}
	for i := range out.Interfaces {
		out.Interfaces[i].Address = redactField(out.Interfaces[i].Address)
		out.Interfaces[i].PermanentAddress = redactField(out.Interfaces[i].PermanentAddress)
	}
	return out
}

func redactField(f Field) Field {
	if f.State == StateOK {
		f.Value = RedactValue(f.Value)
	}
	return f
}

// clone is a deep copy.
func (s *Snapshot) clone() *Snapshot {
	out := *s
	out.DMI = make(map[string]Field, len(s.DMI))
	for k, v := range s.DMI {
		out.DMI[k] = v
	}
	out.Interfaces = append([]Interface{}, s.Interfaces...)
	out.VirtualInterfaces = append([]VirtualInterface{}, s.VirtualInterfaces...)
	out.TPM.PCRs = append([]PCR{}, s.TPM.PCRs...)
	out.RNG.Available = append([]string{}, s.RNG.Available...)
	out.Unverifiable = append([]Unverifiable{}, s.Unverifiable...)
	if s.Notes != nil {
		out.Notes = append([]string{}, s.Notes...)
	}
	return &out
}

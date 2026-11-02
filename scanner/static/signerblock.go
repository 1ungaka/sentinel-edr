package static

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SignerEntry is one known-abused code-signing certificate. A binary whose
// Authenticode chain contains a certificate matching any identifier here is
// flagged — the ground truth behind the "Certs Are Useless" thesis: a valid
// signature from a stolen or abused key is still malicious.
type SignerEntry struct {
	// Thumbprint is the SHA-1 hex of the certificate DER (the lolcerts key).
	Thumbprint string `json:"thumbprint,omitempty"`
	// ThumbprintSHA256 is the SHA-256 hex of the DER, when the source has it.
	ThumbprintSHA256 string `json:"thumbprint_sha256,omitempty"`
	// Serial + Issuer identify a certificate when no fingerprint is published.
	Serial string `json:"serial,omitempty"`
	Issuer string `json:"issuer,omitempty"`
	// Reason is a short label for the report (family, incident, source).
	Reason string `json:"reason,omitempty"`
}

// SignerBlocklist indexes abused-certificate identifiers for O(1) lookup. It is
// built from a feed (e.g. lolcerts) via the intake package, or loaded from a
// file with LoadSignerBlocklist.
type SignerBlocklist struct {
	bySHA1   map[string]SignerEntry
	bySHA256 map[string]SignerEntry
	bySerial map[string]SignerEntry // key: lower(serial)|lower(issuer)
	count    int
}

// NewSignerBlocklist indexes the entries. Empty identifiers are ignored; an
// entry with no usable identifier is dropped. Keys are lowercased and have any
// colons/spaces stripped so "AA:BB" and "aabb" match.
func NewSignerBlocklist(entries []SignerEntry) *SignerBlocklist {
	b := &SignerBlocklist{
		bySHA1:   map[string]SignerEntry{},
		bySHA256: map[string]SignerEntry{},
		bySerial: map[string]SignerEntry{},
	}
	for _, e := range entries {
		used := false
		if k := normFP(e.Thumbprint); k != "" {
			b.bySHA1[k] = e
			used = true
		}
		if k := normFP(e.ThumbprintSHA256); k != "" {
			b.bySHA256[k] = e
			used = true
		}
		if e.Serial != "" && e.Issuer != "" {
			b.bySerial[serialKey(e.Serial, e.Issuer)] = e
			used = true
		}
		if used {
			b.count++
		}
	}
	return b
}

// Count returns the number of indexed entries.
func (b *SignerBlocklist) Count() int {
	if b == nil {
		return 0
	}
	return b.count
}

// Match reports the first blocklisted certificate in certs, if any. It checks
// SHA-1, then SHA-256, then serial+issuer, so a feed that publishes any one of
// them still matches.
func (b *SignerBlocklist) Match(certs []CertInfo) (SignerEntry, CertInfo, bool) {
	if b == nil {
		return SignerEntry{}, CertInfo{}, false
	}
	for _, c := range certs {
		if e, ok := b.bySHA1[normFP(c.Thumbprint)]; ok && c.Thumbprint != "" {
			return e, c, true
		}
		if e, ok := b.bySHA256[normFP(c.ThumbprintSHA256)]; ok && c.ThumbprintSHA256 != "" {
			return e, c, true
		}
		if c.Serial != "" && c.Issuer != "" {
			if e, ok := b.bySerial[serialKey(c.Serial, c.Issuer)]; ok {
				return e, c, true
			}
		}
	}
	return SignerEntry{}, CertInfo{}, false
}

// LoadSignerBlocklist reads a blocklist from a file. Two formats are accepted:
// a JSON array of SignerEntry objects, or a line format
// "<thumbprint-or-serial>|<issuer-or-empty>|<reason>" with '#' comments.
func LoadSignerBlocklist(path string) (*SignerBlocklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("static: read signer blocklist: %w", err)
	}
	entries, err := ParseSignerBlocklist(data)
	if err != nil {
		return nil, err
	}
	return NewSignerBlocklist(entries), nil
}

// ParseSignerBlocklist parses the JSON or line format into entries.
func ParseSignerBlocklist(data []byte) ([]SignerEntry, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var entries []SignerEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("static: parse signer blocklist JSON: %w", err)
		}
		return entries, nil
	}
	return parseSignerLines(strings.NewReader(trimmed))
}

// parseSignerLines reads the "id|issuer|reason" line format. An id of 40 hex
// chars is treated as a SHA-1 thumbprint, 64 hex chars as a SHA-256 thumbprint,
// anything else as a serial (then issuer is required in field 2).
func parseSignerLines(r io.Reader) ([]SignerEntry, error) {
	var entries []SignerEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "|", 3)
		id := strings.TrimSpace(fields[0])
		var issuer, reason string
		if len(fields) > 1 {
			issuer = strings.TrimSpace(fields[1])
		}
		if len(fields) > 2 {
			reason = strings.TrimSpace(fields[2])
		}
		e := SignerEntry{Reason: reason, Issuer: issuer}
		switch n := len(normFP(id)); {
		case n == 40 && isHex(id):
			e.Thumbprint = id
		case n == 64 && isHex(id):
			e.ThumbprintSHA256 = id
		default:
			e.Serial = id
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("static: read signer blocklist: %w", err)
	}
	return entries, nil
}

// signerBlockAnomaly returns the "known-abused-signer" anomaly when any cert in
// certs is on the blocklist. It is the glue between the blocklist and the static
// pass, kept here so its one anomaly literal has a single home.
func signerBlockAnomaly(bl *SignerBlocklist, certs []CertInfo) (Anomaly, bool) {
	e, c, ok := bl.Match(certs)
	if !ok {
		return Anomaly{}, false
	}
	detail := fmt.Sprintf("signed by a known-abused certificate: %s", c.Subject)
	if e.Reason != "" {
		detail += " (" + e.Reason + ")"
	}
	a := Anomaly{Class: "authenticode.known-abused-signer", Category: CatSignature, Score: 9, Technique: techCodeSigning}
	a.Detail = detail
	return a, true
}

func normFP(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func serialKey(serial, issuer string) string {
	return normFP(serial) + "|" + strings.ToLower(strings.TrimSpace(issuer))
}

func isHex(s string) bool {
	s = normFP(s)
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

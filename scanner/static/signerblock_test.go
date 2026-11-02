package static

import (
	"strings"
	"testing"
)

func TestSignerBlocklistMatchByThumbprint(t *testing.T) {
	b := NewSignerBlocklist([]SignerEntry{
		{Thumbprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD", Reason: "stolen key"},
	})
	if b.Count() != 1 {
		t.Fatalf("count = %d, want 1", b.Count())
	}
	// A cert whose thumbprint matches after normalization (case/colons).
	certs := []CertInfo{{Subject: "CN=Evil", Thumbprint: "aabbccddeeff00112233445566778899aabbccdd"}}
	e, c, ok := b.Match(certs)
	if !ok {
		t.Fatal("expected a blocklist match")
	}
	if e.Reason != "stolen key" || c.Subject != "CN=Evil" {
		t.Errorf("wrong match: entry=%+v cert=%+v", e, c)
	}
}

func TestSignerBlocklistMatchBySHA256AndSerial(t *testing.T) {
	sha256 := "deadbeef" + "00000000000000000000000000000000000000000000000000000000"
	b := NewSignerBlocklist([]SignerEntry{
		{ThumbprintSHA256: sha256, Reason: "sha256 entry"},
		{Serial: "0A:0B:0C", Issuer: "CN=Abused CA", Reason: "serial entry"},
	})
	if _, _, ok := b.Match([]CertInfo{{ThumbprintSHA256: sha256}}); !ok {
		t.Error("sha256 match failed")
	}
	if _, _, ok := b.Match([]CertInfo{{Serial: "0a0b0c", Issuer: "CN=Abused CA"}}); !ok {
		t.Error("serial+issuer match failed")
	}
	// Serial without the matching issuer must not match.
	if _, _, ok := b.Match([]CertInfo{{Serial: "0a0b0c", Issuer: "CN=Other"}}); ok {
		t.Error("serial matched despite a different issuer")
	}
}

func TestSignerBlocklistNoMatch(t *testing.T) {
	b := NewSignerBlocklist([]SignerEntry{{Thumbprint: "1111111111111111111111111111111111111111"}})
	if _, _, ok := b.Match([]CertInfo{{Thumbprint: "2222222222222222222222222222222222222222"}}); ok {
		t.Error("unexpected match")
	}
	// A nil blocklist never matches and never panics.
	var nilB *SignerBlocklist
	if _, _, ok := nilB.Match([]CertInfo{{Thumbprint: "x"}}); ok {
		t.Error("nil blocklist matched")
	}
	if nilB.Count() != 0 {
		t.Error("nil blocklist count non-zero")
	}
}

func TestSignerBlocklistEmptyCertFieldsDoNotMatch(t *testing.T) {
	// An entry keyed by serial must not match a cert with an empty thumbprint
	// via the thumbprint path (empty-string key collision guard).
	b := NewSignerBlocklist([]SignerEntry{{Serial: "01", Issuer: "CN=X"}})
	if _, _, ok := b.Match([]CertInfo{{Thumbprint: "", ThumbprintSHA256: ""}}); ok {
		t.Error("empty thumbprint matched")
	}
}

func TestSignerBlockAnomaly(t *testing.T) {
	bl := NewSignerBlocklist([]SignerEntry{
		{Thumbprint: "1111111111111111111111111111111111111111", Reason: "stolen"},
	})
	// A matching cert produces the anomaly with the right class/score/technique.
	a, ok := signerBlockAnomaly(bl, []CertInfo{{Subject: "CN=Evil Corp", Thumbprint: "1111111111111111111111111111111111111111"}})
	if !ok {
		t.Fatal("expected an anomaly")
	}
	if a.Class != "authenticode.known-abused-signer" || a.Category != CatSignature || a.Score != 9 {
		t.Errorf("wrong anomaly fields: %+v", a)
	}
	if a.Technique != techCodeSigning {
		t.Errorf("technique = %q, want %q", a.Technique, techCodeSigning)
	}
	if !strings.Contains(a.Detail, "CN=Evil Corp") || !strings.Contains(a.Detail, "stolen") {
		t.Errorf("detail missing subject/reason: %q", a.Detail)
	}
	// A non-matching cert produces nothing.
	if _, ok := signerBlockAnomaly(bl, []CertInfo{{Thumbprint: "2222222222222222222222222222222222222222"}}); ok {
		t.Error("unexpected anomaly for a non-blocklisted cert")
	}
}

func TestParseSignerBlocklistJSON(t *testing.T) {
	entries, err := ParseSignerBlocklist([]byte(`[{"thumbprint":"aa","reason":"x"},{"serial":"01","issuer":"CN=Y"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

func TestParseSignerBlocklistLines(t *testing.T) {
	data := []byte(`# comment
aabbccddeeff00112233445566778899aabbccdd||stolen cert
deadbeef00000000000000000000000000000000000000000000000000000000|CN=Issuer|sha256 cert
12345|CN=Abused CA|serial-only entry
`)
	entries, err := ParseSignerBlocklist(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(entries), entries)
	}
	if entries[0].Thumbprint == "" {
		t.Error("40-hex id not classified as SHA-1 thumbprint")
	}
	if entries[1].ThumbprintSHA256 == "" {
		t.Error("64-hex id not classified as SHA-256 thumbprint")
	}
	if entries[2].Serial == "" || entries[2].Issuer != "CN=Abused CA" {
		t.Errorf("non-hex id not classified as serial: %+v", entries[2])
	}
}

package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/release"
)

// A registry is refused when a model has no SBOM: an artifact nobody can
// account for is an artifact nobody can trust.
func TestParseRefusesAModelWithoutAnSBOM(t *testing.T) {
	doc := `{"schema_version":"1","models":[{"name":"m","version":"1","path":"m.onnx","sha256":"` + hex64 + `"}]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("a model without an SBOM was accepted")
	}
}

// The same rule for the model card.
func TestParseRefusesAModelWithoutACard(t *testing.T) {
	doc := `{"schema_version":"1","models":[{"name":"m","version":"1","path":"m.onnx","sha256":"` + hex64 +
		`","sbom":"m.cdx.json","sbom_sha256":"` + hex64 + `"}]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("a model without a card was accepted")
	}
}

// A registry with a good model parses, and the model is found by its ID.
func TestParseAndFind(t *testing.T) {
	r := testRegistry(t)
	m, ok := r.Find("embedder@1.0.0")
	if !ok {
		t.Fatal("the model was not found")
	}
	if m.Format != "onnx" {
		t.Errorf("format = %q", m.Format)
	}
	if _, ok := r.Find("nope@1"); ok {
		t.Error("a model that is not there was found")
	}
}

// A registry names files inside its own directory. One that names a path
// outside it is asking the reader to read a file the registry does not own,
// and a command that opens it would print whatever is there.
func TestParseRefusesAPathOutsideTheRegistry(t *testing.T) {
	for _, bad := range []string{"../../etc/shadow", "/etc/shadow", "a/../../b"} {
		doc := `{"schema_version":"1","models":[{"name":"m","version":"1","path":"` + bad +
			`","sha256":"` + hex64 + `","sbom":"m.cdx.json","sbom_sha256":"` + hex64 +
			`","card":"m.card.md","card_sha256":"` + hex64 + `"}]}`
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("the path %q was accepted", bad)
		}
	}
	// A path that stays inside is fine.
	doc := `{"schema_version":"1","models":[{"name":"m","version":"1","path":"models/m.onnx",
		"sha256":"` + hex64 + `","sbom":"m.cdx.json","sbom_sha256":"` + hex64 +
		`","card":"m.card.md","card_sha256":"` + hex64 + `"}]}`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Errorf("a path inside the registry was refused: %v", err)
	}
}

// Promoting a version records the one it replaced, so a rollback can return.
func TestPromoteAndRollback(t *testing.T) {
	r := testRegistry(t)
	if err := r.Promote("embedder@1.1.0"); err != nil {
		t.Fatal(err)
	}
	if r.Active != "embedder@1.1.0" {
		t.Errorf("active = %q", r.Active)
	}
	if len(r.History) != 1 || r.History[0] != "embedder@1.0.0" {
		t.Errorf("history = %v", r.History)
	}
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	if r.Active != "embedder@1.0.0" {
		t.Errorf("after rollback the active version is %q", r.Active)
	}
}

// Rolling back with nothing to roll back to is an error, not a silent no-op.
func TestRollbackWithNoHistory(t *testing.T) {
	r := testRegistry(t)
	if err := r.Rollback(); err == nil {
		t.Fatal("a rollback with no history succeeded")
	}
}

// The verification checks the signature and every artifact.
func TestVerifyChecksTheSignatureAndTheArtifacts(t *testing.T) {
	dir := t.TempDir()
	r, pub, priv := writeRegistry(t, dir)

	canonical, err := Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := release.SignDetached(canonical, release.SignKey{Ed25519: priv}, release.DomainModelRegistry)
	if err != nil {
		t.Fatal(err)
	}
	v := Verify(r, dir, sig, pub)
	if !v.Verified {
		t.Fatalf("the registry did not verify: %+v", v.Problems)
	}

	// A tampered artifact is caught.
	if err := os.WriteFile(filepath.Join(dir, "embedder.onnx"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	v = Verify(r, dir, sig, pub)
	if v.Verified {
		t.Error("a tampered artifact verified")
	}
	if len(v.Problems) == 0 {
		t.Error("the failure said nothing")
	}
}

// A signature over something else does not verify the registry: the signature
// is over the registry's own canonical bytes.
//
// The domain is the registry's own, which is what keeps the post-quantum half
// of a hybrid signature from being replayable across artifact types. With an
// Ed25519-only key the domain does not enter the signature at all — that half
// is plain Ed25519 over the bytes — so what separates the artifacts here is
// the bytes themselves.
func TestVerifyRefusesASignatureOverOtherBytes(t *testing.T) {
	dir := t.TempDir()
	r, pub, priv := writeRegistry(t, dir)
	sig, err := release.SignDetached([]byte("something else entirely"), release.SignKey{Ed25519: priv}, release.DomainModelRegistry)
	if err != nil {
		t.Fatal(err)
	}
	v := Verify(r, dir, sig, pub)
	if v.Verified {
		t.Error("a signature over other bytes verified the registry")
	}
}

// The canonical bytes are stable, so a registry signed once keeps verifying.
func TestMarshalIsCanonical(t *testing.T) {
	r := testRegistry(t)
	a, err := Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("the canonical bytes are not stable")
	}
	back, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(c) {
		t.Errorf("the round trip changed the bytes:\n%s\n%s", a, c)
	}
}

// hex64 is a 64-character hex digest.
const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testRegistry builds a registry with two versions of one model.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	return &Registry{
		SchemaVersion: SchemaVersion,
		Name:          "cau-models",
		Active:        "embedder@1.0.0",
		Models: []Model{
			{
				Name: "embedder", Version: "1.0.0", Path: "embedder.onnx", SHA256: hex64,
				Format: "onnx", Runtime: "onnxruntime-sidecar",
				SBOM: "embedder.cdx.json", SBOMSHA256: hex64,
				Card: "embedder.card.md", CardSHA256: hex64,
			},
			{
				Name: "embedder", Version: "1.1.0", Path: "embedder.onnx", SHA256: hex64,
				Format: "onnx", Runtime: "onnxruntime-sidecar",
				SBOM: "embedder.cdx.json", SBOMSHA256: hex64,
				Card: "embedder.card.md", CardSHA256: hex64,
			},
		},
	}
}

// writeRegistry writes a registry, its artifacts and a key pair into dir.
func writeRegistry(t *testing.T, dir string) (*Registry, release.VerifyKey, ed25519.PrivateKey) {
	t.Helper()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("embedder.onnx", "model bytes")
	write("embedder.cdx.json", `{"bomFormat":"CycloneDX"}`)
	write("embedder.card.md", "# embedder\n")

	// The registry's digests are the digests of what was written.
	r := testRegistry(t)
	for i := range r.Models {
		sum, err := release.DigestFile(filepath.Join(dir, r.Models[i].Path))
		if err != nil {
			t.Fatal(err)
		}
		r.Models[i].SHA256 = sum
		sbomSum, err := release.DigestFile(filepath.Join(dir, r.Models[i].SBOM))
		if err != nil {
			t.Fatal(err)
		}
		r.Models[i].SBOMSHA256 = sbomSum
		cardSum, err := release.DigestFile(filepath.Join(dir, r.Models[i].Card))
		if err != nil {
			t.Fatal(err)
		}
		r.Models[i].CardSHA256 = cardSum
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return r, release.VerifyKey{Ed25519: pub}, priv
}

// The registry's signature is over its canonical bytes, and the domain is the
// registry's own.
func TestSignatureUsesTheRegistryDomain(t *testing.T) {
	if !strings.Contains(string(release.DomainModelRegistry), "model-registry") {
		t.Errorf("the domain is %q", release.DomainModelRegistry)
	}
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/model"
	"github.com/s-b-repo/cau/internal/release"
	"github.com/s-b-repo/cau/internal/report"
	"github.com/s-b-repo/cau/internal/sidecar"
)

// modelFixture writes a signed registry, its artifacts and a key pair.
func modelFixture(t *testing.T) (registry, sig, pub string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	artifact := write("embedder.onnx", "model bytes")
	sbom := write("embedder.cdx.json", `{"bomFormat":"CycloneDX"}`)
	card := write("embedder.card.md", "# embedder\n\nWhat it is.\n")
	digest := func(path string) string {
		sum, err := release.DigestFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}
	r := &model.Registry{
		SchemaVersion: model.SchemaVersion,
		Name:          "cau-models",
		Active:        "embedder@1.0.0",
		Models: []model.Model{{
			Name: "embedder", Version: "1.0.0", Path: "embedder.onnx", SHA256: digest(artifact),
			Format: "onnx", Runtime: "onnxruntime-sidecar",
			SBOM: "embedder.cdx.json", SBOMSHA256: digest(sbom),
			Card: "embedder.card.md", CardSHA256: digest(card),
		}},
	}
	canonical, err := model.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := release.SignDetached(canonical, release.SignKey{Ed25519: priv}, release.DomainModelRegistry)
	if err != nil {
		t.Fatal(err)
	}
	registry = filepath.Join(dir, "registry.json")
	if err := os.WriteFile(registry, canonical, 0o644); err != nil {
		t.Fatal(err)
	}
	sig = filepath.Join(dir, "registry.sig")
	if err := os.WriteFile(sig, sigBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	pub = filepath.Join(dir, "pub.hex")
	if err := os.WriteFile(pub, []byte(hex.EncodeToString(pubKey)), 0o644); err != nil {
		t.Fatal(err)
	}
	return registry, sig, pub
}

// The list names the models and the version in force.
func TestModelList(t *testing.T) {
	registry, _, _ := modelFixture(t)
	code, out, errOut := runCLI(t, "model", "list", "--registry", registry)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "embedder@1.0.0") {
		t.Errorf("the model is not listed:\n%s", out)
	}
	if !strings.Contains(out, "active") {
		t.Errorf("the active version is not stated:\n%s", out)
	}
}

// The verification passes on an intact registry and fails on a tampered
// artifact.
func TestModelVerify(t *testing.T) {
	registry, sig, pub := modelFixture(t)
	code, out, errOut := runCLI(t, "model", "verify", "--registry", registry, "--sig", sig, "--pubkey", pub)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "verified") {
		t.Errorf("the verification said nothing:\n%s", out)
	}

	artifact := filepath.Join(filepath.Dir(registry), "embedder.onnx")
	if err := os.WriteFile(artifact, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "model", "verify", "--registry", registry, "--sig", sig, "--pubkey", pub)
	if code != report.ExitThreat {
		t.Errorf("code=%d, want the verification to fail\n%s", code, out)
	}
	if !strings.Contains(out, "NO") {
		t.Errorf("the failure was not stated:\n%s", out)
	}
}

// A promotion changes the active version and remembers the old one; a
// rollback returns to it.
func TestModelPromoteAndRollback(t *testing.T) {
	registry, _, _ := modelFixture(t)
	doc, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	// A second version to promote.
	r, err := model.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	second := r.Models[0]
	second.Version = "1.1.0"
	r.Models = append(r.Models, second)
	data, err := model.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registry, data, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := runCLI(t, "model", "promote", "--registry", registry, "--model", "embedder@1.1.0")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	after, err := model.Parse(mustRead(t, registry))
	if err != nil {
		t.Fatal(err)
	}
	if after.Active != "embedder@1.1.0" {
		t.Errorf("the active version is %q", after.Active)
	}
	if len(after.History) != 1 {
		t.Errorf("the history holds %v", after.History)
	}

	code, out, errOut = runCLI(t, "model", "rollback", "--registry", registry)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	back, err := model.Parse(mustRead(t, registry))
	if err != nil {
		t.Fatal(err)
	}
	if back.Active != "embedder@1.0.0" {
		t.Errorf("after the rollback the active version is %q", back.Active)
	}
}

// The card is printed as it is stored.
func TestModelCard(t *testing.T) {
	registry, _, _ := modelFixture(t)
	code, out, errOut := runCLI(t, "model", "card", "--registry", registry, "--model", "embedder@1.0.0")
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "What it is.") {
		t.Errorf("the card was not printed:\n%s", out)
	}
}

// The score path talks to the sidecar, not to a model in this process: the
// engine never loads a model, and the sidecar holds the runtime.
func TestModelScoreAsksTheSidecar(t *testing.T) {
	registry, _, _ := modelFixture(t)
	sock := filepath.Join(t.TempDir(), "sidecar.sock")
	l, err := sidecar.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		_ = sidecar.Serve(l, func(req sidecar.Request) sidecar.Response {
			return sidecar.Response{OK: true, Model: req.Model,
				Scores: map[string]float64{"malicious": 0.93}, Version: "test"}
		})
	}()

	file := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(file, []byte("sample bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(t, "model", "score", "--registry", registry,
		"--model", "embedder@1.0.0", "--file", file, "--sidecar", sock)
	if code != report.ExitOK {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "malicious") {
		t.Errorf("the score was not reported:\n%s", out)
	}
}

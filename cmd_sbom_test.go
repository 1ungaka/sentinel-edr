package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

func sbomInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.27.3",
		Main:      debug.Module{Path: "github.com/1ungaka/sentinel-edr", Version: "v0.4.0"},
		Deps: []*debug.Module{
			{Path: "golang.org/x/sys", Version: "v0.30.0", Sum: "h1:zzz="},
			{Path: "github.com/hillu/go-yara/v4", Version: "v4.3.3", Sum: "h1:aaa="},
			{Path: "example.com/old", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1", Sum: "h1:fff="}},
		},
		Settings: []debug.BuildSetting{
			{Key: "CGO_ENABLED", Value: "1"}, {Key: "vcs.revision", Value: "abc123"},
			{Key: "-ldflags", Value: "-X main.secret=1"}, // not a provenance setting; must not be copied
		},
	}
}

func TestBuildSBOM(t *testing.T) {
	doc := buildSBOM(sbomInfo(), "cau")
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Version != 1 {
		t.Errorf("envelope: %+v", doc)
	}
	mc := doc.Metadata.Component
	if mc.Type != "application" || mc.Name != "cau" || mc.Version != "v0.4.0" || mc.PURL != "pkg:golang/github.com/1ungaka/sentinel-edr@v0.4.0" {
		t.Errorf("main component: %+v", mc)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("components: %+v", doc.Components)
	}
	// Sorted, so the document is the same bytes for the same binary.
	var refs []string
	for _, c := range doc.Components {
		refs = append(refs, c.BOMRef)
		if c.Type != "library" || c.PURL != c.BOMRef || !strings.HasPrefix(c.PURL, "pkg:golang/") {
			t.Errorf("component: %+v", c)
		}
	}
	want := "pkg:golang/example.com/fork@v1.0.1,pkg:golang/github.com/hillu/go-yara/v4@v4.3.3,pkg:golang/golang.org/x/sys@v0.30.0"
	if strings.Join(refs, ",") != want {
		t.Errorf("order: %v", refs)
	}
	// A replaced module is listed as what was actually linked, and says so.
	fork := doc.Components[0]
	props := map[string]string{}
	for _, p := range fork.Properties {
		props[p.Name] = p.Value
	}
	if fork.Name != "example.com/fork" || props["cau:go.replaces"] != "example.com/old@v1.0.0" || props["cau:go.sum"] != "h1:fff=" {
		t.Errorf("replaced module: %+v", fork)
	}
	meta := map[string]string{}
	for _, p := range doc.Metadata.Properties {
		meta[p.Name] = p.Value
	}
	if meta["cau:go.version"] != "go1.27.3" || meta["cau:build.vcs.revision"] != "abc123" || meta["cau:build.CGO_ENABLED"] != "1" {
		t.Errorf("metadata: %v", meta)
	}
	if !strings.Contains(meta["cau:not-listed"], "libyara") {
		t.Errorf("a cgo build must state that the C libraries are not listed: %v", meta)
	}
	for k := range meta {
		if strings.Contains(k, "ldflags") {
			t.Errorf("linker flags are not provenance and must not be copied: %v", meta)
		}
	}

	// Deterministic: no timestamp, no serial number.
	a, _ := json.Marshal(doc)
	b, _ := json.Marshal(buildSBOM(sbomInfo(), "cau"))
	if string(a) != string(b) || strings.Contains(string(a), "timestamp") || strings.Contains(string(a), "serialNumber") {
		t.Errorf("the SBOM must be reproducible: %s", a)
	}

	// A development build has no version to claim.
	dev := sbomInfo()
	dev.Main.Version = "(devel)"
	if d := buildSBOM(dev, "cau"); d.Metadata.Component.Version != "" || d.Metadata.Component.PURL != "pkg:golang/github.com/1ungaka/sentinel-edr" {
		t.Errorf("devel build: %+v", d.Metadata.Component)
	}
}

func TestCLIBundleSBOM(t *testing.T) {
	// The test binary carries its own build information, so the default
	// (describe this binary) works under `go test`.
	code, out, errOut := runCLI(t, "bundle", "sbom")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var doc sbomDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.BOMFormat != "CycloneDX" {
		t.Fatalf("stdout is not a CycloneDX document: %v\n%.200s", err, out)
	}
	found := false
	for _, c := range doc.Components {
		if c.Name == "github.com/hillu/go-yara/v4" && c.Version != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the YARA binding is linked into every build and must be listed: %+v", doc.Components)
	}

	path := filepath.Join(t.TempDir(), "cau.cdx.json")
	code, out, errOut = runCLI(t, "bundle", "sbom", "--output", path)
	if code != report.ExitOK || !strings.Contains(out, "components -> "+path) {
		t.Fatalf("--output: exit %d out %q err %q", code, out, errOut)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), `"bomFormat": "CycloneDX"`) {
		t.Errorf("file: %v %.100s", err, raw)
	}

	notGo := filepath.Join(t.TempDir(), "plain.txt")
	os.WriteFile(notGo, []byte("not a binary"), 0o644)
	if code, _, _ := runCLI(t, "bundle", "sbom", "--binary", notGo); code != report.ExitRunFailed {
		t.Errorf("a non-Go file: exit %d, want %d", code, report.ExitRunFailed)
	}
	if code, _, _ := runCLI(t, "bundle", "sbom", "extra"); code != report.ExitUsage {
		t.Errorf("positional argument: exit %d", code)
	}
}

package main

import (
	"debug/buildinfo"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// A software bill of materials for a released binary, in CycloneDX 1.5 JSON.
//
// The source is the build information the Go linker embeds in every binary:
// the exact module versions that were linked, with the go.sum hash each was
// verified against. That makes the SBOM a statement about the artifact, not
// about a manifest that may or may not match it, and it needs no tool beyond
// the binary itself. It is deterministic: no timestamp and no random serial
// number, so the same binary always yields the same bytes and the document
// can be signed alongside it in SHA256SUMS.
//
// What it does not list: libyara and the C library, which are linked through
// cgo and are not Go modules. They are named as a property so the gap is in
// the document rather than left for the reader to discover.

const cycloneDXVersion = "1.5"

type sbomDoc struct {
	BOMFormat   string          `json:"bomFormat"`
	SpecVersion string          `json:"specVersion"`
	Version     int             `json:"version"`
	Metadata    sbomMetadata    `json:"metadata"`
	Components  []sbomComponent `json:"components"`
}

type sbomMetadata struct {
	Component  sbomComponent  `json:"component"`
	Properties []sbomProperty `json:"properties,omitempty"`
}

type sbomComponent struct {
	Type       string         `json:"type"`
	BOMRef     string         `json:"bom-ref,omitempty"`
	Name       string         `json:"name"`
	Version    string         `json:"version,omitempty"`
	PURL       string         `json:"purl,omitempty"`
	Properties []sbomProperty `json:"properties,omitempty"`
}

type sbomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// purlGolang renders a package URL for a Go module. Upper-case letters in a
// module path are significant, so the path is kept as written.
func purlGolang(path, version string) string {
	if version == "" {
		return "pkg:golang/" + path
	}
	return "pkg:golang/" + path + "@" + version
}

// buildSBOM turns embedded build information into a CycloneDX document.
func buildSBOM(info *debug.BuildInfo, name string) sbomDoc {
	mainVersion := info.Main.Version
	if mainVersion == "(devel)" {
		mainVersion = ""
	}
	doc := sbomDoc{
		BOMFormat: "CycloneDX", SpecVersion: cycloneDXVersion, Version: 1,
		Metadata: sbomMetadata{
			Component: sbomComponent{
				Type: "application", BOMRef: purlGolang(info.Main.Path, mainVersion),
				Name: name, Version: mainVersion, PURL: purlGolang(info.Main.Path, mainVersion),
			},
			Properties: []sbomProperty{{"cau:go.version", info.GoVersion}},
		},
		Components: []sbomComponent{},
	}
	cgo := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision", "vcs.time", "vcs.modified", "GOOS", "GOARCH", "-trimpath", "-buildmode":
			doc.Metadata.Properties = append(doc.Metadata.Properties, sbomProperty{"cau:build." + s.Key, s.Value})
		case "CGO_ENABLED":
			cgo = s.Value == "1"
			doc.Metadata.Properties = append(doc.Metadata.Properties, sbomProperty{"cau:build.CGO_ENABLED", s.Value})
		}
	}
	if cgo {
		doc.Metadata.Properties = append(doc.Metadata.Properties, sbomProperty{
			"cau:not-listed", "libraries linked through cgo (libyara, the C library) are not Go modules and do not appear in components",
		})
	}
	for _, dep := range info.Deps {
		m := dep
		var props []sbomProperty
		if dep.Replace != nil {
			props = append(props, sbomProperty{"cau:go.replaces", dep.Path + "@" + dep.Version})
			m = dep.Replace
		}
		if m.Sum != "" {
			props = append(props, sbomProperty{"cau:go.sum", m.Sum})
		}
		purl := purlGolang(m.Path, m.Version)
		doc.Components = append(doc.Components, sbomComponent{
			Type: "library", BOMRef: purl, Name: m.Path, Version: m.Version, PURL: purl, Properties: props,
		})
	}
	sort.Slice(doc.Components, func(i, j int) bool { return doc.Components[i].BOMRef < doc.Components[j].BOMRef })
	sort.SliceStable(doc.Metadata.Properties, func(i, j int) bool {
		return doc.Metadata.Properties[i].Name < doc.Metadata.Properties[j].Name
	})
	return doc
}

func bundleSBOM(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	binary := fs.String("binary", "", "Go binary to describe (default: this cau binary)")
	output := fs.String("output", "", "write the SBOM here instead of stdout")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "bundle sbom takes no positional arguments")
	}
	var info *debug.BuildInfo
	name := "cau"
	if *binary != "" {
		bi, err := buildinfo.ReadFile(*binary)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "reading build information from %s: %v", *binary, err)
		}
		info = bi
		if i := strings.LastIndexAny(*binary, `/\`); i >= 0 {
			name = (*binary)[i+1:]
		} else {
			name = *binary
		}
	} else {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			return fail(stderr, report.ExitRunFailed, "this binary carries no build information")
		}
		info = bi
	}
	doc := buildSBOM(info, name)
	if *output == "" {
		if err := writeJSON(stdout, doc); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		return report.ExitOK
	}
	f, err := os.Create(*output)
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "cannot write %s: %v", *output, err)
	}
	werr := writeJSON(f, doc)
	if cerr := f.Close(); werr != nil || cerr != nil {
		return fail(stderr, report.ExitRunFailed, "writing %s: %v %v", *output, werr, cerr)
	}
	fmt.Fprintf(stdout, "[+] wrote CycloneDX %s SBOM for %s: %d components -> %s\n", cycloneDXVersion, name, len(doc.Components), *output)
	return report.ExitOK
}

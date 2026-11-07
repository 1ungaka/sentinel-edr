package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/provenance"
	"github.com/s-b-repo/cau/scanner"
)

// provenanceInput is a run with --provenance: a clean, intact binary; a
// clean but modified package-owned ELF (the observation, no verdict change);
// a conffile; an unowned file; and a YARA hit on an intact file (so the
// finding-shaped formats carry provenance too).
func provenanceInput() Input {
	intact := cleanResult("/usr/bin/ls")
	modified := cleanResult("/usr/bin/cat")
	conf := cleanResult("/etc/adduser.conf")
	stray := cleanResult("/usr/local/bin/stray")
	hit := yaraResult("/usr/bin/evil-but-shipped")
	return Input{
		Results: []scanner.ScanResult{intact, modified, conf, stray, hit},
		Provenance: map[string]provenance.Provenance{
			"/usr/bin/ls": {Manager: "dpkg", Package: "coreutils", Version: "9.4-3", State: provenance.OwnedIntact,
				ShippedDigest: intact.MD5, DigestAlgo: "md5"},
			"/usr/bin/cat": {Manager: "dpkg", Package: "coreutils", Version: "9.4-3", State: provenance.OwnedModified,
				ShippedDigest: "00112233445566778899aabbccddeeff", DigestAlgo: "md5",
				Finding: &provenance.Finding{Class: provenance.ClassModifiedSystemBinary, Technique: provenance.TechniqueModifiedSystemBinary,
					Kind: "elf", Detail: "ELF executable or library owned by dpkg coreutils no longer matches the package's recorded md5 (shipped 00112233445566778899aabbccddeeff); not a conffile"}},
			"/etc/adduser.conf": {Manager: "dpkg", Package: "adduser", Version: "3.137", State: provenance.OwnedConffile,
				ShippedDigest: "ffeeddccbbaa99887766554433221100", DigestAlgo: "md5"},
			"/usr/local/bin/stray":      {Manager: "dpkg", State: provenance.Unowned},
			"/usr/bin/evil-but-shipped": {Manager: "dpkg", Package: "evilpkg", Version: "1.0", State: provenance.OwnedIntact, ShippedDigest: hit.MD5, DigestAlgo: "md5"},
		},
	}
}

func TestJSONProvenanceShape(t *testing.T) {
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, provenanceInput()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary map[string]any `json:"summary"`
		Files   []struct {
			Path       string          `json:"path"`
			Verdict    string          `json:"verdict"`
			Provenance json.RawMessage `json:"provenance"`
		} `json:"files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary["provenance_resolved"] != float64(5) || doc.Summary["provenance_modified_binaries"] != float64(1) {
		t.Errorf("summary provenance counts: %v", doc.Summary)
	}
	want := map[string]string{
		"/usr/bin/ls":          `{"manager":"dpkg","package":"coreutils","version":"9.4-3","state":"owned-intact","shipped_digest":"d41d8cd98f00b204e9800998ecf8427e","digest_algo":"md5"}`,
		"/usr/bin/cat":         `{"manager":"dpkg","package":"coreutils","version":"9.4-3","state":"owned-modified","shipped_digest":"00112233445566778899aabbccddeeff","digest_algo":"md5","finding":{"class":"provenance.modified-system-binary","technique":"T1554","kind":"elf","detail":"ELF executable or library owned by dpkg coreutils no longer matches the package\u0026#39;s recorded md5 (shipped 00112233445566778899aabbccddeeff); not a conffile"}}`,
		"/etc/adduser.conf":    `{"manager":"dpkg","package":"adduser","version":"3.137","state":"owned-conffile","shipped_digest":"ffeeddccbbaa99887766554433221100","digest_algo":"md5"}`,
		"/usr/local/bin/stray": `{"manager":"dpkg","state":"unowned"}`,
	}
	for _, f := range doc.Files {
		w, ok := want[f.Path]
		if !ok {
			continue
		}
		got := string(f.Provenance)
		// The JSON encoder HTML-escapes; compare the decoded objects.
		var a, b any
		if err := json.Unmarshal([]byte(got), &a); err != nil {
			t.Fatalf("%s: %v", f.Path, err)
		}
		if err := json.Unmarshal([]byte(strings.ReplaceAll(w, `\u0026#39;`, `'`)), &b); err != nil {
			t.Fatal(err)
		}
		ga, _ := json.Marshal(a)
		gb, _ := json.Marshal(b)
		if string(ga) != string(gb) {
			t.Errorf("%s provenance:\n got %s\nwant %s", f.Path, ga, gb)
		}
		// The observation never changes the verdict.
		if f.Path == "/usr/bin/cat" && f.Verdict != JSONVerdictClean {
			t.Errorf("modified binary verdict = %s, want clean (observation only)", f.Verdict)
		}
	}
	// A run without provenance has no provenance object and no summary field.
	buf.Reset()
	if err := NewJSONReporter(testOpts()...).Write(&buf, Input{Results: []scanner.ScanResult{cleanResult("/x")}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "provenance") {
		t.Errorf("run without provenance mentions it: %s", buf.String())
	}
}

func TestProvenanceNeverMovesExitCode(t *testing.T) {
	in := provenanceInput()
	in.Results = in.Results[:4] // drop the YARA hit
	delete(in.Provenance, "/usr/bin/evil-but-shipped")
	for _, level := range []FailOn{FailOnMalicious, FailOnHeuristic, FailOnClean} {
		p := NewExitPolicy(testOpts(WithFailOn(level))...)
		if code := p.Code(in); code != ExitOK {
			t.Errorf("fail-on %s: exit %d with only a provenance observation, want %d", level, code, ExitOK)
		}
	}
}

func TestTextProvenanceLines(t *testing.T) {
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, provenanceInput()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"provenance: dpkg coreutils 9.4-3 (intact, per the host's dpkg database)",
		"provenance: dpkg coreutils 9.4-3 (MODIFIED: shipped md5 00112233445566778899aabbccddeeff differs from the scanned file, per the host's dpkg database)",
		"[OBS] provenance.modified-system-binary: ELF executable or library owned by dpkg coreutils",
		"(T1554); an observation beside the verdict, not scored",
		"provenance: dpkg adduser 3.137 (conffile: an administrator-edited file, not compared, per the host's dpkg database)",
		"provenance: no package owns this path, per the host's dpkg database",
		"Provenance resolved   : 5 (modified package binaries: 1, observations only)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "[CLEAN] /usr/bin/cat") {
		t.Error("the modified binary must still print as CLEAN: provenance is an observation")
	}

	// Hostile package names are terminal-safe.
	in := Input{
		Results:    []scanner.ScanResult{cleanResult("/x")},
		Provenance: map[string]provenance.Provenance{"/x": {Manager: "dpkg", Package: "evil\x1b[31m\u202e", Version: "1", State: provenance.OwnedIntact}},
	}
	buf.Reset()
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b") || strings.Contains(buf.String(), "\u202e") {
		t.Errorf("control or bidi character reached the terminal: %q", buf.String())
	}
}

func TestSARIFProvenance(t *testing.T) {
	var buf bytes.Buffer
	if err := NewSARIFReporter(testOpts()...).Write(&buf, provenanceInput()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID            string `json:"id"`
						DefaultConfig struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string         `json:"ruleId"`
				Level      string         `json:"level"`
				Properties map[string]any `json:"properties"`
				Locations  []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	ruleLevel := ""
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == SARIFRuleProvenanceModified {
			ruleLevel = r.DefaultConfig.Level
		}
	}
	if ruleLevel != LevelNote {
		t.Errorf("rule %s level = %q, want note", SARIFRuleProvenanceModified, ruleLevel)
	}
	sawObs, sawYaraProv := false, false
	for _, r := range run.Results {
		switch r.RuleID {
		case SARIFRuleProvenanceModified:
			sawObs = true
			if r.Level != LevelNote || !strings.HasSuffix(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "usr/bin/cat") {
				t.Errorf("observation result: %+v", r)
			}
			if r.Properties["technique"] != "T1554" || r.Properties["kind"] != "elf" {
				t.Errorf("observation properties: %v", r.Properties)
			}
		default:
			if strings.HasSuffix(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "evil-but-shipped") {
				sawYaraProv = true
				p, _ := r.Properties["provenance"].(map[string]any)
				if p["package"] != "evilpkg" || p["state"] != "owned-intact" || p["shippedDigest"] == "" {
					t.Errorf("YARA result properties.provenance = %v", p)
				}
			}
		}
	}
	if !sawObs || !sawYaraProv {
		t.Errorf("sawObs=%v sawYaraProv=%v", sawObs, sawYaraProv)
	}
}

func TestOCSFAndSinksCarryProvenance(t *testing.T) {
	in := provenanceInput()
	findings := NewOCSFReporter(testOpts()...).Build(in)
	if len(findings) != 1 {
		t.Fatalf("OCSF findings = %d, want 1 (the observation is not a finding)", len(findings))
	}
	p, ok := findings[0].Unmapped["provenance"].(*Provenance)
	if !ok || p.Package != "evilpkg" || p.State != "owned-intact" {
		t.Errorf("unmapped.provenance = %#v", findings[0].Unmapped["provenance"])
	}

	// Every sink profile carries it, as cau.provenance / _provenance /
	// provenance=.
	want := map[string]string{
		"ecs":    `"provenance":{"manager":"dpkg","package":"evilpkg","state":"owned-intact","version":"1.0"}`,
		"gelf":   `"_provenance":"dpkg evilpkg 1.0 owned-intact"`,
		"cef":    `flexString1=dpkg evilpkg 1.0 owned-intact flexString1Label=provenance`,
		"leef":   "provenance=dpkg evilpkg 1.0 owned-intact",
		"syslog": `provenance="dpkg evilpkg 1.0 owned-intact"`,
		"otlp":   `{"key":"cau.provenance","value":{"stringValue":"dpkg evilpkg 1.0 owned-intact"}}`,
	}
	for format, w := range want {
		out := string(renderFormat(t, format, in))
		if !strings.Contains(out, w) {
			t.Errorf("%s lacks %q:\n%s", format, w, out)
		}
	}
	// The map path (the defend daemon's queue) renders the same bytes.
	raw := renderFormat(t, "ocsf", in)
	var maps []map[string]any
	if err := json.Unmarshal(raw, &maps); err != nil {
		t.Fatal(err)
	}
	for format := range want {
		direct := string(renderFormat(t, format, in))
		viaMap, _, err := RenderSinkEvents(format, maps, sinkOpts()...)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if strings.TrimSpace(string(viaMap)) != strings.TrimSpace(direct) {
			t.Errorf("%s: map path differs from the reporter\n got: %s\nwant: %s", format, viaMap, direct)
		}
	}
}

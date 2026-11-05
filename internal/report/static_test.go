package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/scanner"
	"github.com/s-b-repo/cau/scanner/static"
)

// Hermetic static fixtures: hand-built static.Result values, no parsing.

func staticClean(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Static = &static.Result{FilePath: path, Size: 1000, Entropy: 4.2, Fuzzy: static.FuzzyHashes{TLSH: strings.Repeat("A", 70), SSDeep: "3:abc:def"}}
	return r
}

func staticLow(path string) scanner.ScanResult {
	r := staticClean(path)
	r.Static.IsPE = true
	r.Static.PE = &static.PE{Format: "pe32", MachineName: "i386", SubsystemName: "windows-cui", Imphash: strings.Repeat("b", 32),
		Sections: []static.Section{{Name: ".text", Perms: "r-x", RawSize: 512, Entropy: 6.1, Entry: true}},
		Packer:   &static.Packer{Name: "UPX", Evidence: []string{"section UPX0"}}}
	r.Static.Anomalies = []static.Anomaly{{Class: "packer.upx", Category: static.CatPacker, Score: 2, Detail: "packed with UPX", Technique: "T1027.002"}}
	r.Static.Categories = []static.CategoryScore{{Category: static.CatPacker, Raw: 2, Applied: 2, Cap: 4}}
	r.Static.Score = 2
	return r
}

func staticBreach(path string) scanner.ScanResult {
	r := staticLow(path)
	r.Static.Anomalies = append(r.Static.Anomalies,
		static.Anomaly{Class: "section.rwx", Category: static.CatSections, Score: 3, Detail: "writable+executable section(s): UPX1", Technique: "T1027.009"},
		static.Anomaly{Class: "imports.loader-only", Category: static.CatImports, Score: 2, Detail: "import table is only the loader stub", Technique: "T1027.007"},
		static.Anomaly{Class: "fuzzy.tlsh", Category: static.CatFuzzy, Score: 8, Detail: "TLSH distance 12 to \"Example Family\""},
		static.Anomaly{Class: "authenticode.unverified", Category: static.CatInfo, Score: 0, Detail: "signature present and parsed; chain not verified"},
	)
	r.Static.Categories = append(r.Static.Categories,
		static.CategoryScore{Category: static.CatSections, Raw: 3, Applied: 3, Cap: 5},
		static.CategoryScore{Category: static.CatImports, Raw: 2, Applied: 2, Cap: 3},
		static.CategoryScore{Category: static.CatFuzzy, Raw: 8, Applied: 8, Cap: 8},
	)
	r.Static.FuzzyMatches = []static.FuzzyMatch{{Type: static.FuzzyTLSH, Hash: strings.Repeat("C", 70), ThreatName: "Example Family", Distance: 12}}
	r.Static.PE.Authenticode = &static.Authenticode{Parsed: true, Note: "signature present and parsed; chain not verified against a trust store and image digest not checked",
		SignerSubject: "CN=<script>evil</script>", Certificates: []static.CertInfo{{Subject: "CN=<script>evil</script>", Issuer: "CN=root", SelfSigned: true, Signer: true}}}
	r.Static.Score = 15
	return r
}

func staticError(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Static = &static.Result{FilePath: path, Error: errors.New("could not read file: EIO")}
	return r
}

func staticSkipped(path string) scanner.ScanResult {
	r := cleanResult(path)
	r.Static = &static.Result{FilePath: path, Score: 99, Skipped: "file is too big"}
	return r
}

func TestStaticBreachSemantics(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{staticClean("a"), staticLow("b"), staticBreach("c"), staticError("d"), staticSkipped("e")}}
	if got := in.StaticBreach(DefaultStaticThreshold); len(got) != 1 || got[0].FilePath != "c" {
		t.Errorf("breach = %v", got)
	}
	// A per-result threshold overrides the fallback.
	r := staticLow("x")
	r.Static.Threshold = 2
	if got := (Input{Results: []scanner.ScanResult{r}}).StaticBreach(100); len(got) != 1 {
		t.Error("per-result threshold ignored")
	}
	if !in.HasStaticObservation() {
		t.Error("low static evidence not observed")
	}
	if (Input{Results: []scanner.ScanResult{staticClean("a"), staticSkipped("e")}}).HasStaticObservation() {
		t.Error("clean/skipped counted as observation")
	}
	// Static errors are coverage gaps.
	if in.ErrorCount() != 1 || in.FileErrorCount() != 1 {
		t.Errorf("errors = %d/%d", in.ErrorCount(), in.FileErrorCount())
	}
}

func TestExitPolicyStaticTiers(t *testing.T) {
	breach := Input{Results: []scanner.ScanResult{staticBreach("c")}}
	low := Input{Results: []scanner.ScanResult{staticLow("b")}}
	clean := Input{Results: []scanner.ScanResult{staticClean("a")}}
	cases := []struct {
		name string
		in   Input
		fail FailOn
		want int
	}{
		{"breach/malicious", breach, FailOnMalicious, ExitOK},
		{"breach/heuristic", breach, FailOnHeuristic, ExitThreat},
		{"breach/clean", breach, FailOnClean, ExitThreat},
		{"breach/none", breach, FailOnNone, ExitOK},
		{"low/heuristic", low, FailOnHeuristic, ExitOK},
		{"low/clean", low, FailOnClean, ExitThreat},
		{"clean/clean", clean, FailOnClean, ExitOK},
	}
	for _, tc := range cases {
		p := NewExitPolicy(testOpts(WithFailOn(tc.fail))...)
		if got := p.Code(tc.in); got != tc.want {
			t.Errorf("%s: exit %d want %d (%s)", tc.name, got, tc.want, p.Explain(tc.in))
		}
	}
	p := NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic))...)
	if why := p.Explain(breach); !strings.Contains(why, "static") {
		t.Errorf("explanation does not name the static tier: %s", why)
	}
	// A raised threshold through the option turns the breach off.
	p = NewExitPolicy(testOpts(WithFailOn(FailOnHeuristic), WithStaticThreshold(100))...)
	if p.Code(breach) != ExitOK {
		t.Error("WithStaticThreshold ignored")
	}
}

func TestJSONStatic(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{staticClean("clean.bin"), staticLow("low.exe"), staticBreach("bad.exe"), staticError("err.bin"), staticSkipped("big.bin")}}
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("HTML escaping is off: hostile subject rendered raw")
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != JSONSchemaVersion {
		t.Errorf("schema = %s", doc.SchemaVersion)
	}
	if doc.Summary.StaticDetections != 1 || doc.Summary.StaticThreshold != DefaultStaticThreshold || doc.Summary.Verdict != JSONVerdictSuspicious {
		t.Errorf("summary = %+v", doc.Summary)
	}
	files := map[string]File{}
	for _, f := range doc.Files {
		files[f.Path] = f
	}
	c := files["clean.bin"].Static
	if c == nil || c.Detected || c.IsPE || c.TLSH == "" || c.SSDeep == "" || c.PE != nil || files["clean.bin"].Verdict != JSONVerdictClean {
		t.Errorf("clean static = %+v", c)
	}
	l := files["low.exe"].Static
	if l == nil || l.Detected || !l.IsPE || l.Score != 2 || l.PE == nil || l.PE.Packer == nil || l.PE.Packer.Name != "UPX" || files["low.exe"].Verdict != JSONVerdictClean {
		t.Errorf("low static = %+v", l)
	}
	b := files["bad.exe"].Static
	if b == nil || !b.Detected || b.Score != 15 || b.Threshold != DefaultStaticThreshold || files["bad.exe"].Verdict != JSONVerdictSuspicious {
		t.Errorf("breach static = %+v verdict %s", b, files["bad.exe"].Verdict)
	}
	if len(b.Anomalies) != 5 || b.Anomalies[1].Technique != "T1027.009" || len(b.Categories) != 4 || len(b.FuzzyMatches) != 1 || b.FuzzyMatches[0].Distance != 12 {
		t.Errorf("breach detail = %+v", b)
	}
	if b.PE.Signature == nil || b.PE.Signature.Verified || !strings.Contains(b.PE.Signature.Note, "not verified") || !b.PE.Signature.Certificates[0].SelfSigned {
		t.Errorf("signature = %+v", b.PE.Signature)
	}
	if e := files["err.bin"]; e.Static == nil || e.Static.Error == "" || e.Verdict != JSONVerdictError {
		t.Errorf("error file = %+v", e)
	}
	if s := files["big.bin"]; s.Static == nil || s.Static.Skipped == "" || s.Static.Detected || s.Verdict != JSONVerdictClean {
		t.Errorf("skipped file = %+v", s)
	}
	// Static never promotes to malicious; a hash hit plus static stays malicious.
	h := hashResult("mal.bin")
	h.Static = staticBreach("mal.bin").Static
	doc = NewJSONReporter(testOpts()...).Build(Input{Results: []scanner.ScanResult{h}})
	if doc.Files[0].Verdict != JSONVerdictMalicious || doc.Summary.Verdict != JSONVerdictMalicious {
		t.Errorf("malicious + static = %s", doc.Files[0].Verdict)
	}
}

func TestTextStatic(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{staticClean("clean.bin"), staticLow("low.exe"), staticBreach("bad.exe"), staticError("err.bin"), staticSkipped("big.bin")}}
	var buf bytes.Buffer
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"[CLEAN] clean.bin",
		"[~] LOW SUSPICION (static) — low.exe (score: 2): packer.upx",
		"[!] DETECTED (Static) — bad.exe",
		"15 / 8 threshold",
		"Packer    : UPX",
		"[Similarity] 8/8",
		"fuzzy.tlsh",
		"section.rwx",
		"(T1027.009)",
		"[Signature] signature present and parsed; chain not verified",
		"[ERR] Static analysis on err.bin",
		"[~] SKIPPED static analysis on big.bin",
		"Static detections     : 1",
		"THREATS DETECTED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "authenticode.unverified") {
		t.Error("zero-score info anomaly rendered as a scored finding")
	}
}

func TestSARIFStatic(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{staticLow("low.exe"), staticBreach("bad.exe"), staticError("err.bin")}}
	var buf bytes.Buffer
	if err := NewSARIFReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string                 `json:"ruleId"`
				Level      string                 `json:"level"`
				Message    struct{ Text string }  `json:"message"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
			Properties map[string]interface{} `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	ids := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ids[r.ID] = true
	}
	if !ids[SARIFRuleStatic] || !ids[SARIFRuleScanError] {
		t.Errorf("rules = %v", ids)
	}
	var static, errs int
	for _, r := range run.Results {
		switch r.RuleID {
		case SARIFRuleStatic:
			static++
			if r.Level != LevelNote || !strings.Contains(r.Message.Text, "static score 15 reached threshold 8") || r.Properties["imphash"] == nil || r.Properties["packer"] != "UPX" {
				t.Errorf("static result = %+v", r)
			}
			if an, ok := r.Properties["anomalies"].([]interface{}); !ok || len(an) != 4 {
				t.Errorf("anomalies = %v", r.Properties["anomalies"])
			}
		case SARIFRuleScanError:
			errs++
		}
	}
	if static != 1 || errs != 1 {
		t.Errorf("static results %d, error results %d", static, errs)
	}
	if run.Properties["staticDetections"] != float64(1) {
		t.Errorf("run properties = %v", run.Properties)
	}
	// Opting out of heuristic-tier results drops static results too.
	buf.Reset()
	_ = NewSARIFReporter(testOpts(WithSARIFHeuristics(false))...).Write(&buf, in)
	if strings.Contains(buf.String(), SARIFRuleStatic) {
		t.Error("static results emitted with heuristics disabled")
	}
}

// ── ELF ──────────────────────────────────────────────────────────────────────

func staticELFBreach(path string) scanner.ScanResult {
	r := staticClean(path)
	r.Static.IsELF = true
	r.Static.ELF = &static.ELF{Class: "elf64", ByteOrder: "little", TypeName: "dyn", MachineName: "x86-64", OSABIName: "sysv",
		Entry: 0x401000, EntrySection: ".text", Interp: "/tmp/.x/ld.so", IsPIE: true, ImportCount: 4, ImportHash: strings.Repeat("e", 32),
		Needed: []string{"libc.so.6"}, RunPath: []string{"/tmp/lib"},
		Segments: []static.ELFSegment{{Type: "LOAD", Perms: "rwx", FileSize: 4096, MemSize: 4096, Entropy: 7.9, Entry: true}},
		Sections: []static.ELFSection{{Name: ".text", TypeName: "PROGBITS", Perms: "r-x", Size: 4096, Entropy: 7.9, Entry: true}},
		Packer:   &static.Packer{Name: "UPX", Evidence: []string{"UPX! marker in the loader header"}},
		Module:   &static.ELFModule{Name: "<script>evil</script>", Vermagic: "6.1.0 SMP", License: "GPL", InfoPresent: true}}
	r.Static.Anomalies = []static.Anomaly{
		{Class: "segment.rwx", Category: static.CatSections, Score: 3, Detail: "writable+executable segment(s): LOAD[0](rwx)", Technique: "T1027.009"},
		{Class: "segment.exec-high-entropy", Category: static.CatSections, Score: 2, Detail: "executable segment(s) above 7.0 bits/byte: LOAD[0](7.90)", Technique: "T1027"},
		{Class: "dynamic.interp-unusual", Category: static.CatDynamic, Score: 2, Detail: `program interpreter "/tmp/.x/ld.so" is not a system loader path`, Technique: "T1574"},
		{Class: "dynamic.rpath-insecure", Category: static.CatDynamic, Score: 2, Detail: "RPATH/RUNPATH searches attacker-writable or relative location(s): /tmp/lib", Technique: "T1574"},
		{Class: "imports.loader-only", Category: static.CatImports, Score: 2, Detail: "imports are only the loader stub (dlopen, dlsym)", Technique: "T1027.007"},
		{Class: "packer.upx", Category: static.CatPacker, Score: 2, Detail: "packed with UPX (UPX! marker in the loader header)", Technique: "T1027.002"},
		{Class: "module.kernel", Category: static.CatInfo, Score: 0, Detail: "Linux kernel module"},
	}
	r.Static.Categories = []static.CategoryScore{
		{Category: static.CatSections, Raw: 5, Applied: 5, Cap: 5},
		{Category: static.CatDynamic, Raw: 4, Applied: 4, Cap: 4},
		{Category: static.CatImports, Raw: 2, Applied: 2, Cap: 3},
		{Category: static.CatPacker, Raw: 2, Applied: 2, Cap: 4},
	}
	r.Static.Score = 13
	return r
}

func TestReportsELF(t *testing.T) {
	in := Input{Results: []scanner.ScanResult{staticELFBreach("dropper.elf"), staticClean("clean.bin")}}

	// JSON
	var buf bytes.Buffer
	if err := NewJSONReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("HTML escaping is off: hostile module name rendered raw")
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var f File
	for _, x := range doc.Files {
		if x.Path == "dropper.elf" {
			f = x
		}
	}
	s := f.Static
	if s == nil || !s.IsELF || s.IsPE || s.PE != nil || s.ELF == nil || !s.Detected || s.Score != 13 || f.Verdict != JSONVerdictSuspicious {
		t.Fatalf("elf static = %+v verdict %s", s, f.Verdict)
	}
	if s.ImportHash != strings.Repeat("e", 32) || s.Imphash != "" {
		t.Errorf("hashes: import_hash=%q imphash=%q", s.ImportHash, s.Imphash)
	}
	e := s.ELF
	if e.Class != "elf64" || e.Type != "dyn" || e.Machine != "x86-64" || e.Interp != "/tmp/.x/ld.so" || !e.PIE || e.ImportCount != 4 ||
		len(e.Segments) != 1 || e.Segments[0].Perms != "rwx" || len(e.Sections) != 1 || e.Sections[0].Name != ".text" ||
		e.Packer == nil || e.Packer.Name != "UPX" || len(e.RunPath) != 1 || len(e.Needed) != 1 {
		t.Errorf("elf anatomy = %+v", e)
	}
	if e.Module == nil || e.Module.Signed || !strings.Contains(e.Module.Note, "not verified") || e.Module.Name != "<script>evil</script>" {
		t.Errorf("module = %+v", e.Module)
	}
	if len(s.Anomalies) != 7 || s.Anomalies[2].Technique != "T1574" || len(s.Categories) != 4 {
		t.Errorf("anomalies = %+v", s.Anomalies)
	}
	if c := doc.Files[1].Static; c == nil || c.IsELF || c.ELF != nil || c.ImportHash != "" {
		t.Errorf("clean static = %+v", c)
	}

	// Text
	buf.Reset()
	if err := NewTextReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"[!] DETECTED (Static) — dropper.elf",
		"13 / 8 threshold",
		"Image     : elf64 x86-64 dyn, 4 imports, interp /tmp/.x/ld.so, import hash eeeeeeee",
		"Packer    : UPX",
		"Module    : kernel module",
		"vermagic 6.1.0 SMP, unsigned",
		"[Dynamic Linking] 4/4",
		"dynamic.interp-unusual",
		"(T1574)",
		"segment.rwx",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "module.kernel ") {
		t.Errorf("zero-score info anomaly rendered as a scored finding: %s", out)
	}

	// SARIF
	buf.Reset()
	if err := NewSARIFReporter(testOpts()...).Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID     string                 `json:"ruleId"`
				Properties map[string]interface{} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range log.Runs[0].Results {
		if r.RuleID != SARIFRuleStatic {
			continue
		}
		found = true
		if r.Properties["import_hash"] != strings.Repeat("e", 32) || r.Properties["packer"] != "UPX" || r.Properties["interp"] != "/tmp/.x/ld.so" || r.Properties["imphash"] != nil {
			t.Errorf("sarif properties = %v", r.Properties)
		}
	}
	if !found {
		t.Error("no static SARIF result for the ELF breach")
	}
}

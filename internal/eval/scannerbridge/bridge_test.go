package scannerbridge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/eval"
	"github.com/1ungaka/sentinel-edr/scanner"
	"github.com/1ungaka/sentinel-edr/scanner/static"
)

const (
	smokeManifest = "../../../corpus/smoke/manifest.json"
	smokeHashes   = "../../../corpus/smoke/hashes.txt"
	repoRules     = "../../../rules/rule_list.yar"
)

func loadEngine(t *testing.T) ([]eval.Detector, *eval.Manifest) {
	t.Helper()
	m, err := eval.LoadManifest(smokeManifest)
	if err != nil {
		t.Fatal(err)
	}
	if v := m.Validate(eval.ValidateOptions{VerifyHashes: true}); !v.OK() {
		t.Fatalf("smoke corpus invalid:\n%s", v)
	}
	db, err := scanner.LoadSignatures(smokeHashes)
	if err != nil {
		t.Fatal(err)
	}
	ys, _, err := scanner.LoadYaraRules(repoRules, scanner.WithWarnFunc(func(string, ...interface{}) {}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ys.Close() })
	return append(Engine(db, ys, 0), StaticDetector(0, nil), StegoDetector(0), EncChainDetector(0)), m
}

func TestEngineOnSmokeCorpus(t *testing.T) {
	dets, m := loadEngine(t)
	run, err := eval.NewRunner(dets, eval.RunOptions{Concurrency: 4, Tool: "bridge-test"}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	rep := eval.NewReport(run)
	var text strings.Builder
	_ = rep.WriteText(&text)
	t.Log(text.String())

	if !rep.Metrics.Recall.Defined || rep.Metrics.Recall.Value != 1 {
		t.Errorf("recall = %v, want 1.0; false negatives: %+v", rep.Metrics.Recall, rep.FalseNegatives)
	}
	if rep.Totals.FP != 0 {
		t.Errorf("false positives = %d: %+v", rep.Totals.FP, rep.FalsePositives)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	if rep.Totals != (eval.Counts{TP: 8, TN: 10}) {
		t.Errorf("totals = %s", rep.Totals)
	}

	fired := map[string]bool{}
	for _, rs := range rep.ByRule {
		fired[rs.Rule] = true
		if rs.FalsePositives != 0 {
			t.Errorf("rule %s fired on benign samples: %v", rs.Rule, rs.FalsePositivePaths)
		}
	}
	for _, want := range []string{"wannacry_ransomware", "mimikatz_strings", "lokibot_stealer", "generic_ransomware_extensions", "Smoke_Hash Synthetic Sample", "stego/zero-width",
		"static/segment.rwx", "static/dynamic.interp-unusual", "static/imports.loader-only", "encchain/elf"} {
		if !fired[want] {
			t.Errorf("rule %q did not fire; fired: %v", want, fired)
		}
	}
	for _, d := range rep.ByDetector {
		switch d.Detector {
		case eval.DetectorHash:
			if d.Counts.TP != 1 || d.Exclusive != 1 {
				t.Errorf("hash detector: %+v", d)
			}
		case eval.DetectorYara:
			if d.Counts.TP != 4 || d.Exclusive < 3 { // heuristics also catch the mimikatz sample
				t.Errorf("yara detector: %+v", d)
			}
		case eval.DetectorHeuristic:
			if d.Counts.FP != 0 {
				t.Errorf("heuristic detector flagged benign files: %+v", d)
			}
		case eval.DetectorStatic:
			// The ELF dropper profile is the structural pass's own true
			// positive: nothing else in the corpus sees it.
			if d.Counts.TP != 1 || d.Exclusive != 1 || d.Counts.FP != 0 {
				t.Errorf("static detector: %+v", d)
			}
		case eval.DetectorEncChain:
			// The base64-encoded ELF is the encoded-executable pass's own
			// exclusive true positive.
			if d.Counts.TP != 1 || d.Exclusive != 1 || d.Counts.FP != 0 {
				t.Errorf("encchain detector: %+v", d)
			}
		}
	}
	// Per-family breakdown is populated from the manifest families.
	if len(rep.ByFamily) != 8 {
		t.Errorf("families = %+v", rep.ByFamily)
	}
}

func TestDetectorsRefuseEmptyConfig(t *testing.T) {
	if _, err := HashDetector(nil).ScanFile("x"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("nil db: %v", err)
	}
	if _, err := YaraDetector(nil).ScanFile("x"); err == nil {
		t.Error("nil yara scanner accepted")
	}
	if got := len(Engine(nil, nil, -1)); got != 0 {
		t.Errorf("Engine(nil,nil,-1) = %d detectors", got)
	}
	if got := len(Engine(nil, nil, 0)); got != 1 {
		t.Errorf("Engine(nil,nil,0) = %d detectors, want heuristic only", got)
	}
}

func TestYaraSignalNaming(t *testing.T) {
	ys, _, err := scanner.LoadYaraRuleFiles([]scanner.RuleSource{
		{Text: "rule ns_rule { meta: family = \"Fam\" threat_level = 4 strings: $a = \"BRIDGE_NS\" condition: $a }", Namespace: "custom"},
		{Text: "rule plain_rule { strings: $a = \"BRIDGE_PLAIN\" condition: $a }"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "s.bin")
	if err := writeFile(path, "BRIDGE_NS BRIDGE_PLAIN"); err != nil {
		t.Fatal(err)
	}
	f, err := YaraDetector(ys).ScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]eval.Signal{}
	for _, s := range f.Signals {
		got[s.Rule] = s
	}
	if s, ok := got["custom/ns_rule"]; !ok || s.Family != "fam" || !strings.Contains(s.Detail, "threat_level=4") {
		t.Errorf("namespaced signal = %+v (all: %+v)", s, f.Signals)
	}
	if _, ok := got["plain_rule"]; !ok {
		t.Errorf("default-namespace rule not plain: %+v", f.Signals)
	}
	if f.Duration <= 0 {
		t.Error("duration not measured")
	}
}

func TestStaticDetector(t *testing.T) {
	dir := t.TempDir()
	// Plain text: static runs, nothing fires.
	text := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(text, []byte(strings.Repeat("plain\n", 1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	d := StaticDetector(0, nil)
	if d.Name() != eval.DetectorStatic {
		t.Errorf("name = %s", d.Name())
	}
	f, err := d.ScanFile(text)
	if err != nil || f.Detected() || f.Verdict != eval.VerdictClean {
		t.Errorf("text: %+v %v", f, err)
	}
	// Similarity hit through a fuzzy database: fires with per-rule and family signals.
	data := make([]byte, 20000)
	for i := range data {
		data[i] = byte(i*31 + i/7)
	}
	sample := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(sample, data, 0o600); err != nil {
		t.Fatal(err)
	}
	h := static.ComputeFuzzy(data)
	if h.TLSH == "" {
		t.Fatal(h.TLSHNote)
	}
	fdb, err := static.ParseFuzzyDB(strings.NewReader("TLSH|"+h.TLSH+"|Synthetic Family\n"), "mem")
	if err != nil {
		t.Fatal(err)
	}
	f, err = StaticDetector(0, fdb).ScanFile(sample)
	if err != nil || !f.Detected() || f.Verdict != eval.VerdictSuspicious {
		t.Fatalf("fuzzy: %+v %v", f, err)
	}
	rules := map[string]eval.Signal{}
	for _, s := range f.Signals {
		rules[s.Rule] = s
		if s.Detector != eval.DetectorStatic {
			t.Errorf("signal detector = %s", s.Detector)
		}
	}
	if _, ok := rules["static/score"]; !ok {
		t.Error("summary signal missing")
	}
	if _, ok := rules["static/fuzzy.tlsh"]; !ok {
		t.Errorf("anomaly signal missing: %v", rules)
	}
	if fz, ok := rules["static/fuzzy/tlsh"]; !ok || fz.Family != "synthetic" {
		t.Errorf("fuzzy family signal = %+v", fz)
	}
	// Unreadable file is a scan error, not a miss.
	if _, err := d.ScanFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file scanned")
	}
	// Threshold is honoured.
	f, _ = StaticDetector(1000, fdb).ScanFile(sample)
	if f.Detected() {
		t.Error("threshold 1000 still fired")
	}
}

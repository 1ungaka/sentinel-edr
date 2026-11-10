package scanner

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A base64-wrapped script that trips a detection rule is caught even though
// the decode is a script and not an executable. The peeler's own verdict
// ("revealed script") does not fire on its own; the rule does.
func TestPeelIndicatorsCatchARuleInADecodedLayer(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `rule test_decoded_marker
{
    meta:
        description = "a marker that only appears after decoding"
        author = "test"
        threat_level = 5
        family = "test"
    strings:
        $m = "DECODED_MARKER_STRING"
    condition:
        $m
}
`
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	ys, _, err := LoadYaraRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	payload := "#!/bin/sh\necho DECODED_MARKER_STRING"
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	sample := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(sample, []byte(encoded), 0o644); err != nil {
		t.Fatal(err)
	}

	e := &Engine{Yara: ys, Peel: true, PeelIndicators: true}
	res, _ := e.ScanFile(sample)
	if res.Peel == nil {
		t.Fatal("the peel did not run")
	}
	var ruleMatch bool
	for _, f := range res.Peel.Findings {
		if f.Class == "peel.rule-match" {
			ruleMatch = true
			if !strings.Contains(f.Detail, "test_decoded_marker") {
				t.Errorf("the finding does not name the rule: %+v", f)
			}
		}
	}
	if !ruleMatch {
		t.Fatalf("the rule that matched the decoded layer was not reported: %+v", res.Peel.Findings)
	}
	if !res.Peel.Detected() {
		t.Errorf("the peel result does not flag the file: score %d", res.Peel.Score)
	}
}

// Without the indicators the peel pays nothing for them and the file stays
// where it was: the pass is opt-in.
func TestPeelIndicatorsAreOffUnlessAskedFor(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `rule test_decoded_marker
{
    meta:
        description = "a marker that only appears after decoding"
        author = "test"
        threat_level = 5
        family = "test"
    strings:
        $m = "DECODED_MARKER_STRING"
    condition:
        $m
}
`
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	ys, _, err := LoadYaraRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	payload := "#!/bin/sh\necho DECODED_MARKER_STRING"
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	sample := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(sample, []byte(encoded), 0o644); err != nil {
		t.Fatal(err)
	}

	e := &Engine{Yara: ys, Peel: true}
	res, _ := e.ScanFile(sample)
	if res.Peel == nil {
		t.Fatal("the peel did not run")
	}
	for _, f := range res.Peel.Findings {
		if f.Class == "peel.rule-match" {
			t.Errorf("the rule was run over the leaves although the pass is off: %+v", f)
		}
	}
}

// The leaves are not kept when nobody rescans them: the peel must not cost
// what the rescan would cost.
func TestPeelKeepsNoLeavesWhenNobodyRescansThem(t *testing.T) {
	dir := t.TempDir()
	sample := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(sample, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Peel: true}
	res, _ := e.ScanFile(sample)
	if res.Peel == nil {
		t.Fatal("the peel did not run")
	}
	if len(res.Peel.Leaves) != 0 {
		t.Errorf("leaves were kept for nobody: %d", len(res.Peel.Leaves))
	}
}

// A gzipped document that mentions a payload is a document: compression alone
// is packaging, and the peeler's own rule says so. Rescanning it would be a
// false positive about the file.
func TestPeelIndicatorsSkipCompressionOnlyChains(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	rule := `rule test_decoded_marker
{
    meta:
        description = "a marker that only appears after decoding"
        author = "test"
        threat_level = 5
        family = "test"
    strings:
        $m = "DECODED_MARKER_STRING"
    condition:
        $m
}
`
	if err := os.WriteFile(filepath.Join(rules, "test.yar"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	ys, _, err := LoadYaraRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	defer ys.Close()

	// A gzipped script that quotes the marker: the chain is compression only.
	doc := "#!/bin/sh\n# DECODED_MARKER_STRING\n"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(doc))
	zw.Close()
	sample := filepath.Join(dir, "doc.gz")
	if err := os.WriteFile(sample, gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	e := &Engine{Yara: ys, Peel: true, PeelIndicators: true}
	res, _ := e.ScanFile(sample)
	if res.Peel == nil {
		t.Fatal("the peel did not run")
	}
	for _, f := range res.Peel.Findings {
		if f.Class == "peel.rule-match" {
			t.Errorf("a compression-only chain was rescanned: %+v", f)
		}
	}
}

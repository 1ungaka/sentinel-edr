package honesty

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var fixedClock = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func f64(v float64) *float64 { return &v }

// smokeEval is an evaluation input shaped like the committed smoke baseline.
func smokeEval() *EvalInput {
	return &EvalInput{
		ReportPath:        "baselines/smoke.json",
		Tool:              "CAU EDR 0.1.0-dev",
		Generated:         time.Date(2026, 11, 6, 2, 8, 37, 311817786, time.UTC),
		CorpusName:        "smoke",
		CorpusManifest:    "corpus/smoke/manifest.json",
		ManifestRead:      true,
		ProvenanceSources: []string{"synthetic"},
		Samples:           18,
		Totals:            Counts{TP: 8, TN: 10},
		Metrics:           Metrics{Precision: f64(1), Recall: f64(1), FalsePositiveRate: f64(0)},
		Detectors: []Detector{
			{Name: "yara", Counts: Counts{TP: 5, TN: 10, FN: 3}, Metrics: Metrics{Precision: f64(1), Recall: f64(0.625), FalsePositiveRate: f64(0)}, Fires: 5, ExclusiveHits: 4},
			{Name: "archive", Counts: Counts{TN: 10, FN: 8}, Metrics: Metrics{Recall: f64(0), FalsePositiveRate: f64(0)}},
		},
	}
}

// fullInputs is a tree where every section was measured and nothing disagreed.
func fullInputs() Inputs {
	return Inputs{
		Tool:      "CAU EDR",
		Version:   "0.1.0-dev",
		Generated: fixedClock,
		Coverage: CoverageInput{
			Techniques: []Technique{
				{ID: "T1059.001", Name: "PowerShell"},
				{ID: "T1003", Name: "OS Credential Dumping"},
				{ID: "T1082", Name: "System Information Discovery", Partial: true},
			},
			Unmapped: []string{"static/overlay.large", "heuristic/misc"},
			Sources: []Source{
				{Name: "yara", Entries: 4, Mapped: 3, Content: 4},
				{Name: "hash", Content: 12, Note: "exact-content signatures carry a threat name, not a technique"},
			},
			ExpectPath: "baselines/attack-coverage.txt",
			Gaps: []Gap{
				{ID: "T1140", Name: "Deobfuscate/Decode Files or Information", State: "planned", Note: "no static decode analytic yet"},
				{ID: "T1046", Name: "Network Service Discovery", State: "none", Note: "network telemetry; the sensor owns it"},
			},
		},
		Eval: smokeEval(),
		Selftest: SelftestInput{
			ManifestPath: "signatures/integrity.json",
			Found:        true,
			Signature:    SignatureVerified,
			Checked:      true,
			Resources: []Resource{
				{Name: "signatures", Path: "signatures/hashes.txt", SHA256: strings.Repeat("a", 64)},
				{Name: "rules", Path: "rules", SHA256: strings.Repeat("b", 64)},
			},
		},
	}
}

func mustJSON(t *testing.T, ix *Index) []byte {
	t.Helper()
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func hasCaveat(caveats []string, sub string) bool {
	for _, c := range caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestBuildFixedClockAndHeader(t *testing.T) {
	ix := Build(fullInputs())
	if ix.SchemaVersion != "0.1.0" {
		t.Errorf("schema_version = %q, want 0.1.0", ix.SchemaVersion)
	}
	if ix.Tool != (Tool{Name: "CAU EDR", Version: "0.1.0-dev"}) {
		t.Errorf("tool = %+v", ix.Tool)
	}
	if ix.Generated == nil || *ix.Generated != "2026-01-02T03:04:05Z" {
		t.Errorf("generated = %v, want 2026-01-02T03:04:05Z", ix.Generated)
	}

	// A non-UTC clock is still rendered in UTC.
	in := fullInputs()
	in.Generated = time.Date(2026, 1, 2, 5, 4, 5, 0, time.FixedZone("x", 2*3600))
	if got := Build(in).Generated; got == nil || *got != "2026-01-02T03:04:05Z" {
		t.Errorf("non-UTC clock rendered as %v", got)
	}

	// The zero time suppresses the timestamp: the key stays, the value is null.
	in.Generated = time.Time{}
	ix = Build(in)
	if ix.Generated != nil {
		t.Errorf("suppressed timestamp = %q, want nil", *ix.Generated)
	}
	if !bytes.Contains(mustJSON(t, ix), []byte(`"generated": null`)) {
		t.Error("suppressed timestamp is not rendered as null")
	}
}

func TestCoverageStates(t *testing.T) {
	base := fullInputs().Coverage
	cases := []struct {
		name   string
		mutate func(*CoverageInput)
		state  string
		caveat string
		check  func(*testing.T, Coverage)
	}{
		{"measured", func(*CoverageInput) {}, StateMeasured, "not a measured detection rate", func(t *testing.T, c Coverage) {
			if *c.TechniquesWithContent != 3 || *c.Covered != 2 || *c.Partial != 1 {
				t.Errorf("counts = %d/%d/%d, want 3/2/1", *c.TechniquesWithContent, *c.Covered, *c.Partial)
			}
			if hasCaveat(c.Caveats, "declares no gaps") {
				t.Error("the no-gaps caveat is shown although gaps are declared")
			}
			if *c.GapsPlanned != 1 || *c.GapsNone != 1 || *c.UnmappedContent != 2 {
				t.Errorf("gaps %d planned %d none, %d unmapped", *c.GapsPlanned, *c.GapsNone, *c.UnmappedContent)
			}
			if c.Expectation == nil || !c.Expectation.Matches || len(c.Expectation.Problems) != 0 {
				t.Errorf("expectation = %+v", c.Expectation)
			}
			if !reflect.DeepEqual(c.PartialIDs, []string{"T1082"}) {
				t.Errorf("partial ids = %v", c.PartialIDs)
			}
		}},
		{"mismatch", func(c *CoverageInput) {
			c.Problems = []Problem{{ID: "T1003", Kind: "undeclared", Text: "T1003 is covered but not declared"}}
		}, StateMismatch, "differs from the expectation in 1 place", func(t *testing.T, c Coverage) {
			if c.Expectation == nil || c.Expectation.Matches || len(c.Expectation.Problems) != 1 {
				t.Errorf("expectation = %+v", c.Expectation)
			}
			// A mismatch still reports the live content: it is a state, not a blank.
			if c.TechniquesWithContent == nil || *c.TechniquesWithContent != 3 {
				t.Error("mismatch dropped the live counts")
			}
		}},
		{"measured, no gaps declared", func(c *CoverageInput) { c.Gaps = nil }, StateMeasured, "absence of a declaration, not of gaps", func(t *testing.T, c Coverage) {
			// Zero declared gaps is a known zero (an empty list), unlike the
			// no-baseline case below where the list is unknown (null).
			if c.DeclaredGaps == nil || len(c.DeclaredGaps) != 0 || *c.GapsPlanned != 0 || *c.GapsNone != 0 {
				t.Errorf("gaps = %v", c.DeclaredGaps)
			}
		}},
		{"no-baseline", func(c *CoverageInput) { c.ExpectPath = ""; c.Gaps = nil }, StateNoBaseline, "unknown, not absent", func(t *testing.T, c Coverage) {
			if c.TechniquesWithContent == nil || *c.TechniquesWithContent != 3 {
				t.Error("no-baseline dropped the technique count")
			}
			if c.Covered != nil || c.Partial != nil || c.DeclaredGaps != nil || c.GapsPlanned != nil || c.Expectation != nil {
				t.Errorf("no-baseline must leave the expectation-derived fields null: %+v", c)
			}
		}},
		{"unreadable expectation", func(c *CoverageInput) { c.ExpectErr = "line 3: bad state" }, StateError, "line 3: bad state", func(t *testing.T, c Coverage) {
			if c.Covered != nil || c.DeclaredGaps != nil {
				t.Error("an unreadable expectation must not yield a covered/gap split")
			}
		}},
		{"matrix error", func(c *CoverageInput) { c.Err = "YARA: syntax error" }, StateError, "YARA: syntax error", func(t *testing.T, c Coverage) {
			if c.TechniquesWithContent != nil || c.TechniqueIDs != nil || c.UnmappedContent != nil {
				t.Errorf("a failed matrix must report nothing, got %+v", c)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			c := buildCoverage(in)
			if c.State != tc.state {
				t.Fatalf("state = %q, want %q", c.State, tc.state)
			}
			if !hasCaveat(c.Caveats, tc.caveat) {
				t.Errorf("caveats lack %q: %q", tc.caveat, c.Caveats)
			}
			tc.check(t, c)
		})
	}
}

func TestEvaluationStates(t *testing.T) {
	t.Run("not-measured", func(t *testing.T) {
		e := buildEvaluation(nil, "CAU EDR 0.1.0-dev")
		if e.State != StateNotMeasured {
			t.Fatalf("state = %q", e.State)
		}
		if e.Totals != nil || e.Metrics != nil || e.Samples != nil || e.Detectors != nil || e.CorpusClass != nil || e.Report != nil {
			t.Errorf("not-measured must carry no numbers: %+v", e)
		}
		if !hasCaveat(e.Caveats, "not measured; they are not zero") {
			t.Errorf("caveats = %q", e.Caveats)
		}
		// In the JSON the numbers are null, never zero.
		ix := Build(Inputs{Tool: "CAU EDR", Version: "x"})
		js := string(mustJSON(t, ix))
		for _, want := range []string{`"totals": null`, `"metrics": null`, `"samples": null`, `"corpus_class": null`} {
			if !strings.Contains(js, want) {
				t.Errorf("JSON lacks %s", want)
			}
		}
		if strings.Contains(js, `"tp": 0`) {
			t.Error("not-measured rendered a zero count")
		}
	})
	t.Run("error", func(t *testing.T) {
		e := buildEvaluation(&EvalInput{ReportPath: "r.json", Err: "unsupported schema_version"}, "x")
		if e.State != StateError || e.Totals != nil || e.Metrics != nil {
			t.Errorf("error state = %q totals = %v", e.State, e.Totals)
		}
		if e.Report == nil || e.Report.Path != "r.json" || !hasCaveat(e.Caveats, "unsupported schema_version") {
			t.Errorf("error section = %+v", e)
		}
	})
	t.Run("measured", func(t *testing.T) {
		e := buildEvaluation(smokeEval(), "CAU EDR 0.1.0-dev")
		if e.State != StateMeasured {
			t.Fatalf("state = %q", e.State)
		}
		if *e.Totals != (Counts{TP: 8, TN: 10}) {
			t.Errorf("totals = %+v", *e.Totals)
		}
		if want := (SampleCounts{Total: 18, Scored: 18, Malicious: 8, Benign: 10}); *e.Samples != want {
			t.Errorf("samples = %+v, want %+v", *e.Samples, want)
		}
		if e.Report.Generated != "2026-11-06T02:08:37Z" {
			t.Errorf("report generated = %q", e.Report.Generated)
		}
		if len(e.Detectors) != 2 || e.Detectors[0].Name != "archive" {
			t.Errorf("detectors not sorted: %+v", e.Detectors)
		}
		// An undefined ratio stays null; it is not rendered as 0.
		if e.Detectors[0].Metrics.Precision != nil {
			t.Error("undefined precision became a number")
		}
		if hasCaveat(e.Caveats, "this build is") {
			t.Errorf("same build flagged as different: %q", e.Caveats)
		}
		if !hasCaveat(e.Caveats, "did not re-run the evaluation") {
			t.Errorf("caveats = %q", e.Caveats)
		}
	})
	t.Run("measured by another build", func(t *testing.T) {
		e := buildEvaluation(smokeEval(), "CAU EDR 9.9.9")
		if !hasCaveat(e.Caveats, `this build is "CAU EDR 9.9.9"`) {
			t.Errorf("caveats = %q", e.Caveats)
		}
	})
	t.Run("one-sided corpora", func(t *testing.T) {
		in := smokeEval()
		in.Totals = Counts{TN: 10}
		in.Metrics = Metrics{FalsePositiveRate: f64(0)}
		in.Errors, in.Skipped = 2, 1
		e := buildEvaluation(in, "CAU EDR 0.1.0-dev")
		for _, want := range []string{"no malicious samples: recall is undefined, not zero", "2 sample(s) could not be scanned and 1 were skipped"} {
			if !hasCaveat(e.Caveats, want) {
				t.Errorf("caveats lack %q: %q", want, e.Caveats)
			}
		}
		in.Totals = Counts{TP: 3}
		if e := buildEvaluation(in, "x"); !hasCaveat(e.Caveats, "no benign samples") {
			t.Errorf("caveats = %q", e.Caveats)
		}
	})
}

func TestSyntheticCorpusCaveat(t *testing.T) {
	const plumbing = "plumbing check, not a detection rate"
	cases := []struct {
		name     string
		corpus   string
		manifest string
		read     bool
		sources  []string
		class    string
	}{
		{"manifest declares synthetic", "anything", "c/manifest.json", true, []string{"synthetic"}, CorpusSynthetic},
		{"manifest synthetic, case", "anything", "c/manifest.json", true, []string{"Synthetic", " synthetic "}, CorpusSynthetic},
		{"smoke by name, manifest gone", "smoke", "", false, nil, CorpusSynthetic},
		{"smoke by name, case", "Smoke", "elsewhere/m.json", false, nil, CorpusSynthetic},
		{"smoke by path", "", "corpus/smoke/manifest.json", false, nil, CorpusSynthetic},
		{"smoke by name beats mixed sources", "smoke", "x/m.json", true, []string{"synthetic", "malwarebazaar"}, CorpusSynthetic},
		{"real corpus", "lab-heldout", "corpus/lab/manifest-heldout.json", true, []string{"msfvenom", "local-install"}, CorpusUnclassified},
		{"mixed sources", "mixed", "c/m.json", true, []string{"synthetic", "malwarebazaar"}, CorpusUnclassified},
		{"nothing known", "", "", false, nil, CorpusUnclassified},
		{"smoke as a substring is not smoke", "smokescreen", "corpus/smokeless/m.json", false, nil, CorpusUnclassified},
		{"manifest unread, sources ignored", "x", "c/m.json", false, []string{"synthetic"}, CorpusUnclassified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, basis := ClassifyCorpus(tc.corpus, tc.manifest, tc.read, tc.sources)
			if class != tc.class {
				t.Fatalf("class = %q, want %q", class, tc.class)
			}
			if basis == "" {
				t.Error("no basis given for the classification")
			}

			in := fullInputs()
			in.Eval.CorpusName, in.Eval.CorpusManifest = tc.corpus, tc.manifest
			in.Eval.ManifestRead, in.Eval.ProvenanceSources = tc.read, tc.sources
			ix := Build(in)
			e := ix.Evaluation
			if e.CorpusClass == nil || *e.CorpusClass != tc.class || e.CorpusClassBasis == nil || *e.CorpusClassBasis != basis {
				t.Fatalf("section class = %v basis = %v", e.CorpusClass, e.CorpusClassBasis)
			}
			var text, mdown bytes.Buffer
			if err := WriteText(&text, ix); err != nil {
				t.Fatal(err)
			}
			if err := WriteMarkdown(&mdown, ix); err != nil {
				t.Fatal(err)
			}
			synthetic := tc.class == CorpusSynthetic
			if got := hasCaveat(e.Caveats, plumbing); got != synthetic {
				t.Errorf("plumbing caveat present = %v, want %v: %q", got, synthetic, e.Caveats)
			}
			if got := hasCaveat(e.Caveats, "unclassified"); got == synthetic {
				t.Errorf("unclassified caveat present = %v for class %s", got, tc.class)
			}
			// The warning sits on the recall line itself, in both renderings.
			const onRecall = "(synthetic corpus: a plumbing check, not a detection rate)"
			for name, out := range map[string]string{"text": text.String(), "markdown": mdown.String()} {
				if got := strings.Contains(out, onRecall); got != synthetic {
					t.Errorf("%s: recall-line warning present = %v, want %v", name, got, synthetic)
				}
			}
			if synthetic && !strings.Contains(text.String(), "SYNTHETIC") {
				t.Error("text does not name the corpus class")
			}
		})
	}
}

func TestSelftestStates(t *testing.T) {
	ok := fullInputs().Selftest
	cases := []struct {
		name   string
		in     SelftestInput
		state  string
		caveat string
		intact *bool
	}{
		{"verified", ok, StateMeasured, "verifies against the public key supplied", boolPtr(true)},
		{"unsigned", with(ok, func(s *SelftestInput) { s.Signature = SignatureUnsigned }), StateMeasured, "digest check only", boolPtr(true)},
		{"signed, no key", with(ok, func(s *SelftestInput) { s.Signature = SignatureNotChecked }), StateMeasured, "signature was not checked", boolPtr(true)},
		{"no baseline", SelftestInput{ManifestPath: "signatures/integrity.json"}, StateNoBaseline, "this is not a pass", nil},
		{"no baseline, no location", SelftestInput{Notes: []string{"The signature database was not found."}}, StateNoBaseline, "signature database was not found", nil},
		{"unreadable baseline", SelftestInput{ManifestPath: "m.json", Err: "parse manifest: bad"}, StateError, "parse manifest: bad", nil},
		{"drift", with(ok, func(s *SelftestInput) {
			s.Drift = []Drift{{Name: "rules", Reason: "content changed since the baseline"}}
		}), StateTampered, "1 resource(s) no longer match", boolPtr(false)},
		{"bad signature", with(ok, func(s *SelftestInput) { s.Signature = SignatureBad }), StateTampered, "does not verify", boolPtr(true)},
		{"signature required, absent", with(ok, func(s *SelftestInput) { s.Signature = SignatureMissing }), StateTampered, "carries no signature", boolPtr(true)},
		{"unusable key", with(ok, func(s *SelftestInput) {
			s.Signature = SignatureNotChecked
			s.Err = "A public key was supplied but could not be read."
		}), StateError, "could not be read", boolPtr(true)},
		{"unusable key does not mask drift", with(ok, func(s *SelftestInput) {
			s.Err = "A public key was supplied but could not be read."
			s.Drift = []Drift{{Name: "signatures", Reason: "content changed since the baseline"}}
		}), StateTampered, "no longer match", boolPtr(false)},
		{"digests not recomputed", with(ok, func(s *SelftestInput) { s.Checked = false; s.Err = "stat: permission denied" }), StateError, "permission denied", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := buildSelftest(tc.in)
			if s.State != tc.state {
				t.Fatalf("state = %q, want %q", s.State, tc.state)
			}
			if !hasCaveat(s.Caveats, tc.caveat) {
				t.Errorf("caveats lack %q: %q", tc.caveat, s.Caveats)
			}
			if (s.Intact == nil) != (tc.intact == nil) || (s.Intact != nil && *s.Intact != *tc.intact) {
				t.Errorf("intact = %v, want %v", s.Intact, tc.intact)
			}
			if s.State == StateNoBaseline && (s.Signature != nil || s.Resources != nil || s.Drift != nil) {
				t.Errorf("no-baseline must carry no result: %+v", s)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func with(s SelftestInput, f func(*SelftestInput)) SelftestInput {
	f(&s)
	return s
}

func TestEveryStateIsInTheVocabulary(t *testing.T) {
	known := map[string]bool{}
	for _, s := range States {
		known[s] = true
	}
	inputs := []Inputs{fullInputs(), {}, {Coverage: CoverageInput{Err: "x"}, Eval: &EvalInput{Err: "x"}, Selftest: SelftestInput{Err: "x"}}}
	mismatch := fullInputs()
	mismatch.Coverage.Problems = []Problem{{ID: "T1", Kind: "regression"}}
	mismatch.Selftest.Drift = []Drift{{Name: "rules", Reason: "changed"}}
	inputs = append(inputs, mismatch)
	seen := map[string]bool{}
	for _, in := range inputs {
		ix := Build(in)
		for _, s := range []string{ix.Coverage.State, ix.Evaluation.State, ix.Selftest.State} {
			if !known[s] {
				t.Errorf("state %q is outside the vocabulary %v", s, States)
			}
			seen[s] = true
		}
	}
	for _, s := range States {
		if !seen[s] {
			t.Errorf("state %q was never produced", s)
		}
	}
}

func TestFailing(t *testing.T) {
	if got := Build(fullInputs()).Failing(); len(got) != 0 {
		t.Errorf("clean tree failing = %v", got)
	}
	// Absent baselines and a missing report are not strict failures: they are
	// states to read, and a fresh install has all three.
	if got := Build(Inputs{}).Failing(); len(got) != 0 {
		t.Errorf("empty tree failing = %v", got)
	}
	in := fullInputs()
	in.Coverage.Problems = []Problem{{ID: "T1003", Kind: "regression"}}
	in.Eval = &EvalInput{Err: "bad"}
	in.Selftest.Drift = []Drift{{Name: "rules", Reason: "changed"}}
	want := []string{"coverage: mismatch", "evaluation: error", "selftest: tampered"}
	if got := Build(in).Failing(); !reflect.DeepEqual(got, want) {
		t.Errorf("failing = %v, want %v", got, want)
	}
}

// collectKeys walks decoded JSON and returns every object key, by path.
func collectKeys(v interface{}, path string, out map[string]bool) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, child := range x {
			out[path+k] = true
			collectKeys(child, path+k+".", out)
		}
	case []interface{}:
		for _, child := range x {
			collectKeys(child, path, out)
		}
	}
}

func TestNoCompositeScore(t *testing.T) {
	for name, in := range map[string]Inputs{"full": fullInputs(), "empty": {}} {
		t.Run(name, func(t *testing.T) {
			var doc map[string]interface{}
			if err := json.Unmarshal(mustJSON(t, Build(in)), &doc); err != nil {
				t.Fatal(err)
			}
			top := make([]string, 0, len(doc))
			for k := range doc {
				top = append(top, k)
			}
			sort.Strings(top)
			want := []string{"coverage", "evaluation", "generated", "not_claimed", "schema_version", "selftest", "tool"}
			if !reflect.DeepEqual(top, want) {
				t.Errorf("top-level keys = %v, want exactly %v", top, want)
			}

			keys := map[string]bool{}
			collectKeys(doc, "", keys)
			for k := range keys {
				// Compare whole words of the key: "samples.scored" is a count of
				// scored samples, not a score.
				for _, word := range strings.Split(k[strings.LastIndex(k, ".")+1:], "_") {
					for _, banned := range []string{"score", "grade", "rating", "rank", "composite", "overall", "summary", "index", "f1", "accuracy"} {
						if word == banned {
							t.Errorf("key %q looks like a summarising number (%q)", k, banned)
						}
					}
				}
			}
			// Every section carries a state and a caveat list, and nothing else
			// sits beside the sections that could summarise them.
			for _, sec := range []string{"coverage", "evaluation", "selftest"} {
				if !keys[sec+".state"] || !keys[sec+".caveats"] {
					t.Errorf("section %s lacks state/caveats", sec)
				}
			}
		})
	}

	// The full key set of a measured document, pinned: adding a field is a
	// deliberate act that has to touch this list.
	var doc map[string]interface{}
	if err := json.Unmarshal(mustJSON(t, Build(fullInputs())), &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	collectKeys(doc, "", keys)
	got := make([]string, 0, len(keys))
	for k := range keys {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{
		"coverage", "coverage.caveats", "coverage.covered", "coverage.declared_gaps",
		"coverage.declared_gaps.id", "coverage.declared_gaps.name", "coverage.declared_gaps.note", "coverage.declared_gaps.state",
		"coverage.expectation", "coverage.expectation.matches", "coverage.expectation.path", "coverage.expectation.problems",
		"coverage.gaps_none", "coverage.gaps_planned", "coverage.partial", "coverage.partial_ids",
		"coverage.sources", "coverage.sources.content", "coverage.sources.entries", "coverage.sources.mapped",
		"coverage.sources.name", "coverage.sources.note",
		"coverage.state", "coverage.technique_ids", "coverage.techniques_with_content",
		"coverage.unmapped_content", "coverage.unmapped_labels",
		"evaluation", "evaluation.caveats", "evaluation.corpus", "evaluation.corpus.manifest", "evaluation.corpus.name",
		"evaluation.corpus.provenance_sources", "evaluation.corpus_class", "evaluation.corpus_class_basis",
		"evaluation.detectors", "evaluation.detectors.counts",
		"evaluation.detectors.counts.fn", "evaluation.detectors.counts.fp", "evaluation.detectors.counts.tn", "evaluation.detectors.counts.tp",
		"evaluation.detectors.detector", "evaluation.detectors.exclusive_hits", "evaluation.detectors.fires",
		"evaluation.detectors.metrics", "evaluation.detectors.metrics.false_positive_rate",
		"evaluation.detectors.metrics.precision", "evaluation.detectors.metrics.recall",
		"evaluation.metrics", "evaluation.metrics.false_positive_rate", "evaluation.metrics.precision", "evaluation.metrics.recall",
		"evaluation.report", "evaluation.report.generated", "evaluation.report.path", "evaluation.report.tool",
		"evaluation.samples", "evaluation.samples.benign", "evaluation.samples.errors", "evaluation.samples.malicious",
		"evaluation.samples.scored", "evaluation.samples.skipped", "evaluation.samples.total",
		"evaluation.state", "evaluation.totals", "evaluation.totals.fn", "evaluation.totals.fp", "evaluation.totals.tn", "evaluation.totals.tp",
		"generated", "not_claimed", "schema_version",
		"selftest", "selftest.caveats", "selftest.drift", "selftest.intact", "selftest.manifest",
		"selftest.resources", "selftest.resources.name", "selftest.resources.path", "selftest.resources.sha256",
		"selftest.signature", "selftest.state",
		"tool", "tool.name", "tool.version",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("key set changed.\n got: %v\nwant: %v", got, want)
	}
}

func TestNotClaimedIsFixed(t *testing.T) {
	full, empty := Build(fullInputs()), Build(Inputs{})
	if !reflect.DeepEqual(full.NotClaimed, empty.NotClaimed) {
		t.Error("not_claimed depends on the inputs; it must be a fixed list")
	}
	joined := strings.Join(full.NotClaimed, "\n")
	for _, want := range []string{"third-party", "real-malware recall", "runtime or sensor coverage", "signature on the index itself", "overall score"} {
		if !strings.Contains(joined, want) {
			t.Errorf("not_claimed lacks %q", want)
		}
	}
	// The list handed out is a copy: a caller cannot edit the package's own.
	full.NotClaimed[0] = "edited"
	if Build(Inputs{}).NotClaimed[0] == "edited" {
		t.Error("not_claimed is shared between documents")
	}
}

func TestDeterministic(t *testing.T) {
	a, b := mustJSON(t, Build(fullInputs())), mustJSON(t, Build(fullInputs()))
	if !bytes.Equal(a, b) {
		t.Fatal("two builds of the same inputs differ")
	}

	// Input order does not reach the output: lists are sorted.
	shuffled := fullInputs()
	c := &shuffled.Coverage
	c.Techniques[0], c.Techniques[2] = c.Techniques[2], c.Techniques[0]
	c.Gaps[0], c.Gaps[1] = c.Gaps[1], c.Gaps[0]
	c.Unmapped[0], c.Unmapped[1] = c.Unmapped[1], c.Unmapped[0]
	c.Sources[0], c.Sources[1] = c.Sources[1], c.Sources[0]
	shuffled.Eval.Detectors[0], shuffled.Eval.Detectors[1] = shuffled.Eval.Detectors[1], shuffled.Eval.Detectors[0]
	shuffled.Selftest.Resources[0], shuffled.Selftest.Resources[1] = shuffled.Selftest.Resources[1], shuffled.Selftest.Resources[0]
	if got := mustJSON(t, Build(shuffled)); !bytes.Equal(a, got) {
		t.Errorf("input order changed the document:\n%s\n---\n%s", a, got)
	}

	// Build leaves its inputs alone.
	in, ref := fullInputs(), fullInputs()
	Build(in)
	if !reflect.DeepEqual(in, ref) {
		t.Error("Build modified its inputs")
	}

	// Apart from the timestamp, a timestamped and an untimestamped run agree.
	in.Generated = time.Time{}
	var with, without map[string]interface{}
	json.Unmarshal(a, &with)
	json.Unmarshal(mustJSON(t, Build(in)), &without)
	delete(with, "generated")
	delete(without, "generated")
	if !reflect.DeepEqual(with, without) {
		t.Error("the timestamp changed something other than the generated field")
	}

	// The renderings are deterministic too.
	for name, render := range map[string]func(*bytes.Buffer, *Index) error{
		"text":     func(b *bytes.Buffer, ix *Index) error { return WriteText(b, ix) },
		"markdown": func(b *bytes.Buffer, ix *Index) error { return WriteMarkdown(b, ix) },
	} {
		var x, y bytes.Buffer
		if err := render(&x, Build(fullInputs())); err != nil {
			t.Fatal(err)
		}
		if err := render(&y, Build(shuffled)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x.Bytes(), y.Bytes()) {
			t.Errorf("%s rendering is not deterministic", name)
		}
	}
}

func TestRenderingsCarryGapsAndCaveats(t *testing.T) {
	in := fullInputs()
	in.Coverage.Problems = []Problem{{ID: "T1505.003", Kind: "regression", Text: "T1505.003 is declared covered but no detection content maps to it any more"}}
	in.Selftest.Drift = []Drift{{Name: "rules", Reason: "content changed since the baseline"}}
	ix := Build(in)

	var text, mdown bytes.Buffer
	if err := WriteText(&text, ix); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&mdown, ix); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "markdown": mdown.String()} {
		for _, want := range []string{
			"T1140", "T1046", "planned", "none", // the declared gaps and their states
			"T1082",                   // the partial technique
			"T1505.003", "regression", // the difference from the expectation
			"mismatch", "measured", "tampered", // the three section states
			"baselines/smoke.json", "smoke", "2026-11-06T02:08:37Z",
			"100.00%", "n/a", // a defined and an undefined ratio
			"content changed since the baseline",
			"2026-01-02T03:04:05Z",
			"no overall score",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}

	// Every caveat and every not-claimed line reaches the text rendering.
	// Wrapping breaks lines, so compare with whitespace collapsed.
	flat := strings.Join(strings.Fields(text.String()), " ")
	var all []string
	all = append(all, ix.Coverage.Caveats...)
	all = append(all, ix.Evaluation.Caveats...)
	all = append(all, ix.Selftest.Caveats...)
	all = append(all, ix.NotClaimed...)
	if len(all) < 12 {
		t.Fatalf("only %d caveat lines; the fixture should exercise more", len(all))
	}
	for _, c := range all {
		if !strings.Contains(flat, strings.Join(strings.Fields(c), " ")) {
			t.Errorf("text lacks the caveat %q", c)
		}
	}
	// Markdown escapes punctuation, so check a punctuation-free stretch of each.
	for _, c := range all {
		words := strings.FieldsFunc(c, func(r rune) bool { return !(r == ' ' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') })
		longest := ""
		for _, w := range words {
			if w = strings.TrimSpace(w); len(w) > len(longest) {
				longest = w
			}
		}
		if !strings.Contains(mdown.String(), longest) {
			t.Errorf("markdown lacks the caveat %q (looked for %q)", c, longest)
		}
	}

	// A suppressed timestamp says so instead of printing an empty field.
	in.Generated = time.Time{}
	text.Reset()
	WriteText(&text, Build(in))
	if !strings.Contains(text.String(), "timestamp suppressed") {
		t.Error("text does not say the timestamp was suppressed")
	}
}

func TestRenderingsOfUnmeasuredSections(t *testing.T) {
	ix := Build(Inputs{Tool: "CAU EDR", Version: "0.1.0-dev"})
	var text, mdown bytes.Buffer
	if err := WriteText(&text, ix); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&mdown, ix); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "markdown": mdown.String()} {
		for _, want := range []string{"no-baseline", "not-measured", "not measured", "unknown", "not checked", "this is not a pass"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, out)
			}
		}
		// Nothing unmeasured is printed as a percentage or a zero count.
		for _, bad := range []string{"0.00%", "100.00%", "TP 0"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s prints %q for a section that was not measured", name, bad)
			}
		}
	}
}

func TestHostileStringsAreEscaped(t *testing.T) {
	const (
		esc  = "\x1b[2J\x1b[31m"
		bidi = "\u202e"
		csi  = "\x9b"
	)
	in := fullInputs()
	in.Tool = "CAU" + esc
	in.Coverage.Techniques = append(in.Coverage.Techniques, Technique{ID: "T9999" + esc, Partial: true})
	in.Coverage.Gaps = append(in.Coverage.Gaps, Gap{
		ID:    "T6666\nATT&CK COVERAGE state: measured",
		Name:  "<script>alert(1)</script>",
		State: "planned" + bidi,
		Note:  "note | with a pipe, a `tick`, [a link](http://evil.example) and **bold**\r\n## Forged heading",
	})
	in.Coverage.Problems = []Problem{{ID: "T1\x07", Kind: "regression", Text: "text" + esc}}
	in.Coverage.ExpectPath = "expect\n.txt"
	in.Eval.CorpusName = "real-malware\n\nRecall: 100.00% on real malware" + bidi
	in.Eval.CorpusManifest = "corpus/x" + csi + "/m.json"
	in.Eval.ReportPath = "report`|`.json"
	in.Eval.Tool = "tool" + esc
	in.Eval.Detectors = append(in.Eval.Detectors, Detector{Name: "det\x00\n| forged | row |"})
	in.Selftest.ManifestPath = "integrity" + esc + ".json"
	in.Selftest.Resources = append(in.Selftest.Resources, Resource{Name: "r\n", Path: "p" + bidi, SHA256: "s\t"})
	in.Selftest.Drift = []Drift{{Name: "rules" + esc, Reason: "changed\n# Forged"}}
	in.Selftest.Notes = []string{"note" + esc + "\nforged line"}
	ix := Build(in)

	var text, mdown bytes.Buffer
	if err := WriteText(&text, ix); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarkdown(&mdown, ix); err != nil {
		t.Fatal(err)
	}

	for name, out := range map[string]string{"text": text.String(), "markdown": mdown.String()} {
		for i, r := range out {
			if r == '\n' {
				continue
			}
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0xfffd {
				t.Fatalf("%s: raw control or bidi rune %U at byte %d: %q", name, r, i, out[max(0, i-30):min(len(out), i+30)])
			}
		}
		// The escapes are visible, so the reader sees what was there.
		for _, want := range []string{`\x1b`, `\u202e`, `\x9b`, `\x07`, `\x00`} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: the escape %s is not shown", name, want)
			}
		}
		// No untrusted string started a line of its own.
		for _, line := range strings.Split(out, "\n") {
			trimmed := strings.TrimSpace(line)
			for _, forged := range []string{"ATT&CK COVERAGE state: measured", "Recall: 100.00% on real malware", "## Forged", "# Forged", "forged line", "| forged | row |"} {
				if strings.HasPrefix(trimmed, forged) {
					t.Errorf("%s: a forged line was rendered: %q", name, line)
				}
			}
		}
	}

	m := mdown.String()
	for _, raw := range []string{"<script>", "[a link](http://evil.example)", "**bold**", "http://evil.example"} {
		if strings.Contains(m, raw) {
			t.Errorf("markdown carries live markup %q", raw)
		}
	}
	// Table structure survives: every table row has the cell count of its header.
	lines := strings.Split(m, "\n")
	cells := func(s string) int { return strings.Count(strings.ReplaceAll(s, `\|`, ""), "|") }
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i+1], "| ---") {
			continue
		}
		want := cells(lines[i])
		for j := i + 2; j < len(lines) && strings.HasPrefix(lines[j], "|"); j++ {
			if got := cells(lines[j]); got != want {
				t.Errorf("markdown table row has %d cell separators, header has %d: %q", got, want, lines[j])
			}
		}
	}
	// A code span cannot be closed from inside.
	for _, line := range lines {
		if strings.Count(line, "`")%2 != 0 && !strings.Contains(line, "\\`") {
			t.Errorf("markdown line has an unbalanced code span: %q", line)
		}
	}

	// The JSON carries the exact strings: its encoder escapes, and its
	// consumers need the real bytes.
	var back Index
	if err := json.Unmarshal(mustJSON(t, ix), &back); err != nil {
		t.Fatal(err)
	}
	if back.Evaluation.Corpus.Name != in.Eval.CorpusName {
		t.Errorf("JSON altered the corpus name: %q", back.Evaluation.Corpus.Name)
	}
	if bytes.ContainsAny(mustJSON(t, ix), "\x1b\x00\x07") {
		t.Error("JSON carries a raw control byte")
	}
}

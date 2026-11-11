package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/internal/eval"
	"github.com/1ungaka/sentinel-edr/internal/honesty"
	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/selftest"
)

var honestyTestClock = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// runHonesty calls the command directly, with a fixed clock and no inherited
// SOURCE_DATE_EPOCH or selftest key.
func runHonesty(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	prev := honestyNow
	honestyNow = func() time.Time { return honestyTestClock }
	t.Cleanup(func() { honestyNow = prev })
	if os.Getenv(envSourceDateEpoch) != "" {
		t.Setenv(envSourceDateEpoch, "")
	}
	if os.Getenv(envSelftestKey) != "" {
		t.Setenv(envSelftestKey, "")
	}
	var out, errb bytes.Buffer
	code := cmdHonesty(args, &out, &errb)
	return code, out.String(), errb.String()
}

// honestyRepoArgs names the repo tree's resources explicitly, and a baseline
// path that does not exist, so the run does not depend on discovery order or
// on a stray integrity.json.
func honestyRepoArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	args := []string{
		"--rules", "rules", "--db", "signatures/hashes.txt", "--fuzzy-db", "signatures/fuzzy.txt",
		"--manifest", filepath.Join(t.TempDir(), "integrity.json"),
	}
	return append(args, extra...)
}

func honestyIndex(t *testing.T, out string) honesty.Index {
	t.Helper()
	var ix honesty.Index
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ix); err != nil {
		t.Fatalf("the index is not valid JSON: %v\n%s", err, out)
	}
	return ix
}

func honestyHasCaveat(caveats []string, sub string) bool {
	for _, c := range caveats {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestHonestyRepoTreeJSON(t *testing.T) {
	code, out, errOut := runHonesty(t, honestyRepoArgs(t, "--format", "json")...)
	if code != report.ExitOK {
		t.Fatalf("exit %d, want %d\nstderr:\n%s", code, report.ExitOK, errOut)
	}
	ix := honestyIndex(t, out)

	if ix.SchemaVersion != "0.1.0" || ix.Tool.Name != toolName || ix.Tool.Version != version {
		t.Errorf("header = schema %q tool %+v", ix.SchemaVersion, ix.Tool)
	}
	if ix.Generated == nil || *ix.Generated != "2026-03-04T05:06:07Z" {
		t.Errorf("generated = %v, want the fixed clock", ix.Generated)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "tool", "generated", "coverage", "evaluation", "selftest", "not_claimed"} {
		if _, ok := top[k]; !ok {
			t.Errorf("top-level key %q is missing", k)
		}
	}
	if len(top) != 7 {
		t.Errorf("%d top-level keys, want 7: a summarising field has no place here", len(top))
	}
	if len(ix.NotClaimed) == 0 {
		t.Error("not_claimed is empty")
	}

	// Coverage: measured, and equal to the committed expectation.
	c := ix.Coverage
	if c.State != honesty.StateMeasured {
		t.Fatalf("coverage state = %q, want measured; caveats %q", c.State, c.Caveats)
	}
	if c.Expectation == nil || !c.Expectation.Matches || len(c.Expectation.Problems) != 0 || c.Expectation.Path != honestyDefaultExpect {
		t.Errorf("expectation = %+v", c.Expectation)
	}
	// The numbers are the ones `cau coverage` reports for the same tree.
	var covOut, covErr bytes.Buffer
	if code := cmdCoverage([]string{"--quiet", "--rules", "rules", "--db", "signatures/hashes.txt", "--fuzzy-db", "signatures/fuzzy.txt",
		"--format", "json", "--expect", honestyDefaultExpect}, &covOut, &covErr); code != report.ExitOK {
		t.Fatalf("cau coverage: exit %d: %s", code, covErr.String())
	}
	var matrix struct {
		Techniques []struct {
			ID      string `json:"id"`
			Partial bool   `json:"partial"`
		} `json:"techniques"`
		Unmapped []json.RawMessage `json:"unmapped"`
		Gaps     []struct {
			ID string `json:"id"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(covOut.Bytes(), &matrix); err != nil {
		t.Fatal(err)
	}
	partial := 0
	for _, tq := range matrix.Techniques {
		if tq.Partial {
			partial++
		}
	}
	if len(matrix.Techniques) == 0 {
		t.Fatal("the repo matrix has no techniques; the comparison below would be vacuous")
	}
	if *c.TechniquesWithContent != len(matrix.Techniques) || *c.Partial != partial || *c.Covered != len(matrix.Techniques)-partial {
		t.Errorf("techniques %d covered %d partial %d; cau coverage says %d techniques, %d partial",
			*c.TechniquesWithContent, *c.Covered, *c.Partial, len(matrix.Techniques), partial)
	}
	if len(c.DeclaredGaps) != len(matrix.Gaps) || *c.GapsPlanned+*c.GapsNone != len(matrix.Gaps) {
		t.Errorf("%d declared gaps, cau coverage says %d", len(c.DeclaredGaps), len(matrix.Gaps))
	}
	for i, g := range matrix.Gaps {
		if i < len(c.DeclaredGaps) && c.DeclaredGaps[i].ID != g.ID {
			t.Errorf("gap %d = %s, cau coverage says %s", i, c.DeclaredGaps[i].ID, g.ID)
		}
	}
	// A committed expectation with no gap rows is reported as that, with the
	// caveat that an undeclared gap is not a covered technique.
	if c.DeclaredGaps == nil {
		t.Error("declared_gaps is null although an expectation was compared")
	}
	if got := honestyHasCaveat(c.Caveats, "The expectation declares no gaps"); got != (len(matrix.Gaps) == 0) {
		t.Errorf("no-gaps caveat present = %v with %d declared gap(s)", got, len(matrix.Gaps))
	}
	if *c.UnmappedContent != len(matrix.Unmapped) {
		t.Errorf("unmapped content = %d, cau coverage says %d", *c.UnmappedContent, len(matrix.Unmapped))
	}

	// Evaluation: the committed smoke baseline, flagged as synthetic.
	e := ix.Evaluation
	if e.State != honesty.StateMeasured {
		t.Fatalf("evaluation state = %q, want measured; caveats %q", e.State, e.Caveats)
	}
	if e.CorpusClass == nil || *e.CorpusClass != honesty.CorpusSynthetic {
		t.Fatalf("corpus_class = %v, want synthetic", e.CorpusClass)
	}
	if !honestyHasCaveat(e.Caveats, "SYNTHETIC CORPUS") || !honestyHasCaveat(e.Caveats, "plumbing check, not a detection rate") {
		t.Errorf("the synthetic-corpus caveat is missing: %q", e.Caveats)
	}
	if e.Report.Path != honestyDefaultEval || e.Corpus.Name != "smoke" {
		t.Errorf("report %q corpus %q", e.Report.Path, e.Corpus.Name)
	}
	rep, err := eval.LoadReport(honestyDefaultEval)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := *e.Totals, honestyCounts(rep.Totals); got != want {
		t.Errorf("totals = %+v, the report says %+v", got, want)
	}
	if e.Samples.Total != len(rep.Samples) || e.Samples.Scored != rep.Totals.Total() {
		t.Errorf("samples = %+v, the report has %d (%d scored)", *e.Samples, len(rep.Samples), rep.Totals.Total())
	}
	if len(e.Detectors) != len(rep.ByDetector) || len(e.Detectors) == 0 {
		t.Errorf("%d detectors, the report has %d", len(e.Detectors), len(rep.ByDetector))
	}
	if (e.Metrics.Recall == nil) != !rep.Metrics.Recall.Defined || (e.Metrics.Recall != nil && *e.Metrics.Recall != rep.Metrics.Recall.Value) {
		t.Errorf("recall = %v, the report says %v", e.Metrics.Recall, rep.Metrics.Recall)
	}

	// Selftest: no baseline at the path given, which is a state and not a pass.
	s := ix.Selftest
	if s.State != honesty.StateNoBaseline || s.Intact != nil || s.Signature != nil {
		t.Errorf("selftest = %+v, want no-baseline with nothing claimed", s)
	}
}

func TestHonestyTextAndMarkdown(t *testing.T) {
	code, out, errOut := runHonesty(t, honestyRepoArgs(t)...)
	if code != report.ExitOK {
		t.Fatalf("text: exit %d\n%s", code, errOut)
	}
	t.Logf("text rendering of the repo tree:\n%s", out)
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		toolName + " " + version + " honesty index",
		"Generated: 2026-03-04T05:06:07Z",
		"There is no overall score",
		"ATT&CK COVERAGE", "state: measured",
		honestyDefaultExpect + " (matches)",
		"SYNTHETIC",
		"(synthetic corpus: a plumbing check, not a detection rate)",
		"Recall on a synthetic smoke corpus is a plumbing check, not a detection rate",
		"state: no-baseline", "this is not a pass",
		"Not claimed by this index:",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	code, mdOut, errOut := runHonesty(t, honestyRepoArgs(t, "--format", "markdown")...)
	if code != report.ExitOK {
		t.Fatalf("markdown: exit %d\n%s", code, errOut)
	}
	for _, want := range []string{"# " + toolName, "## ATT&amp;CK coverage", "**synthetic**",
		"a plumbing check, not a detection rate", "`no-baseline`", "## Not claimed by this index"} {
		if !strings.Contains(mdOut, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}

	// Declared gaps are listed by id in both renderings. The committed
	// expectation may declare none, so add two rows to a copy of it: a planned
	// gap and one owned by the sensor.
	committed, err := os.ReadFile(honestyDefaultExpect)
	if err != nil {
		t.Fatal(err)
	}
	withGaps := filepath.Join(t.TempDir(), "expect.txt")
	rows := "T1200  gap   hardware additions: no content yet\nT1046  none  network telemetry; the sensor owns it\n"
	if err := os.WriteFile(withGaps, append(committed, rows...), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "markdown"} {
		code, out, errOut := runHonesty(t, honestyRepoArgs(t, "--strict", "--format", format, "--expect", withGaps)...)
		if code != report.ExitOK {
			t.Fatalf("%s with declared gaps: exit %d\n%s\n%s", format, code, errOut, out)
		}
		for _, want := range []string{"T1200", "T1046", "planned", "none", "hardware additions", "the sensor owns it", "2 (1 planned, 1 owned by sensor/console)"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s does not show the declared gap detail %q", format, want)
			}
		}
		if strings.Contains(out, "declares no gaps") {
			t.Errorf("%s shows the no-gaps caveat next to two declared gaps", format)
		}
	}
}

func TestHonestyStrict(t *testing.T) {
	// The clean tree passes --strict: a missing integrity baseline is a state
	// to read, not a strict failure.
	code, _, errOut := runHonesty(t, honestyRepoArgs(t, "--strict", "--format", "json")...)
	if code != report.ExitOK {
		t.Fatalf("--strict on the clean tree: exit %d, want %d\n%s", code, report.ExitOK, errOut)
	}

	// A deliberately wrong expectation: one covered technique declared a gap,
	// everything else undeclared.
	wrong := filepath.Join(t.TempDir(), "expect.txt")
	if err := os.WriteFile(wrong, []byte("# wrong on purpose\nT1003  gap  declared missing, but the content covers it\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without --strict the index is still produced and exits 0: it is a
	// report, and the mismatch is in it.
	code, out, errOut := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--expect", wrong)...)
	if code != report.ExitOK {
		t.Fatalf("mismatch without --strict: exit %d, want %d\n%s", code, report.ExitOK, errOut)
	}
	ix := honestyIndex(t, out)
	c := ix.Coverage
	if c.State != honesty.StateMismatch || c.Expectation == nil || c.Expectation.Matches || c.Expectation.Path != wrong {
		t.Fatalf("coverage = state %q expectation %+v, want a mismatch", c.State, c.Expectation)
	}
	kinds := map[string]int{}
	for _, p := range c.Expectation.Problems {
		kinds[p.Kind]++
	}
	if kinds["gap-closed"] != 1 || kinds["undeclared"] != *c.TechniquesWithContent-1 {
		t.Errorf("problems by kind = %v with %d techniques", kinds, *c.TechniquesWithContent)
	}

	code, out, errOut = runHonesty(t, honestyRepoArgs(t, "--strict", "--expect", wrong)...)
	if code != report.ExitThreat {
		t.Fatalf("--strict on a mismatch: exit %d, want %d\n%s", code, report.ExitThreat, errOut)
	}
	if !strings.Contains(errOut, "[STRICT] coverage: mismatch") {
		t.Errorf("stderr does not name the failing section: %q", errOut)
	}
	// The index is still written in full before the strict exit.
	if !strings.Contains(out, "state: mismatch") || !strings.Contains(out, "DIFFERENCE(S)") || !strings.Contains(out, "gap-closed") {
		t.Errorf("the strict run did not print the mismatching index:\n%s", out)
	}
}

func TestHonestyTimestampIsReproducible(t *testing.T) {
	args := honestyRepoArgs(t, "--format", "json", "--no-timestamp")
	_, a, _ := runHonesty(t, args...)
	_, b, _ := runHonesty(t, args...)
	if a != b {
		t.Fatal("two --no-timestamp runs on the same tree differ")
	}
	if !strings.Contains(a, `"generated": null`) {
		t.Error("--no-timestamp did not null the timestamp")
	}

	// With a timestamp, only that field differs.
	_, c, _ := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--manifest", args[7])...)
	if strings.ReplaceAll(c, `"generated": "2026-03-04T05:06:07Z"`, `"generated": null`) != a {
		t.Error("the timestamped run differs from the untimestamped one in more than the timestamp")
	}

	t.Run("SOURCE_DATE_EPOCH", func(t *testing.T) {
		var out, errb bytes.Buffer
		t.Setenv(envSourceDateEpoch, "86400")
		if code := cmdHonesty(honestyRepoArgs(t, "--format", "json"), &out, &errb); code != report.ExitOK {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		if ix := honestyIndex(t, out.String()); ix.Generated == nil || *ix.Generated != "1970-01-02T00:00:00Z" {
			t.Errorf("generated = %v, want 1970-01-02T00:00:00Z", ix.Generated)
		}
		// --no-timestamp wins over the environment.
		out.Reset()
		cmdHonesty(honestyRepoArgs(t, "--format", "json", "--no-timestamp"), &out, &errb)
		if ix := honestyIndex(t, out.String()); ix.Generated != nil {
			t.Errorf("--no-timestamp left %q", *ix.Generated)
		}
		t.Setenv(envSourceDateEpoch, "yesterday")
		out.Reset()
		if code := cmdHonesty(honestyRepoArgs(t), &out, &errb); code != report.ExitUsage || out.Len() != 0 {
			t.Errorf("bad SOURCE_DATE_EPOCH: exit %d with %d bytes of output, want %d and none", code, out.Len(), report.ExitUsage)
		}
	})
}

func TestHonestyEvalStates(t *testing.T) {
	// A report the caller named and that is not there is an error in the
	// section, never a quiet fall back to "not measured".
	code, out, _ := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--eval", "/no/such/report.json")...)
	if code != report.ExitOK {
		t.Fatalf("missing --eval: exit %d, want %d (the index is still produced)", code, report.ExitOK)
	}
	e := honestyIndex(t, out).Evaluation
	if e.State != honesty.StateError || e.Totals != nil || e.Metrics != nil || e.CorpusClass != nil {
		t.Errorf("missing report: %+v", e)
	}
	if code, _, _ := runHonesty(t, honestyRepoArgs(t, "--strict", "--eval", "/no/such/report.json")...); code != report.ExitThreat {
		t.Errorf("--strict with an unreadable report: exit %d, want %d", code, report.ExitThreat)
	}

	raw, err := os.ReadFile(honestyDefaultEval)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(t *testing.T, f func(doc map[string]interface{})) string {
		t.Helper()
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "report.json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("totals that do not follow from the samples", func(t *testing.T) {
		p := edit(t, func(doc map[string]interface{}) {
			totals := doc["totals"].(map[string]interface{})
			totals["tp"] = totals["tp"].(float64) + 500
		})
		_, out, _ := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--eval", p)...)
		e := honestyIndex(t, out).Evaluation
		if e.State != honesty.StateError || e.Totals != nil || !honestyHasCaveat(e.Caveats, "do not follow from its own sample records") {
			t.Errorf("an edited report was reported from: %+v", e)
		}
	})

	t.Run("a corpus that is not the smoke corpus", func(t *testing.T) {
		p := edit(t, func(doc map[string]interface{}) {
			run := doc["run"].(map[string]interface{})
			run["corpus_name"] = "fieldset"
			run["corpus"] = "/no/such/corpus/manifest.json"
			run["tool"] = "CAU EDR 0.0.1-older"
		})
		_, out, _ := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--eval", p)...)
		e := honestyIndex(t, out).Evaluation
		if e.State != honesty.StateMeasured || e.CorpusClass == nil || *e.CorpusClass != honesty.CorpusUnclassified {
			t.Fatalf("state %q class %v, want measured/unclassified", e.State, e.CorpusClass)
		}
		if e.Corpus.ProvenanceSources != nil {
			t.Errorf("provenance sources = %v for a manifest that was not read", e.Corpus.ProvenanceSources)
		}
		if honestyHasCaveat(e.Caveats, "SYNTHETIC") || !honestyHasCaveat(e.Caveats, "unclassified") {
			t.Errorf("caveats = %q", e.Caveats)
		}
		if !honestyHasCaveat(e.Caveats, `recorded by "CAU EDR 0.0.1-older"`) {
			t.Errorf("a report from another build is not flagged: %q", e.Caveats)
		}
	})

	t.Run("smoke renamed, manifest still says synthetic", func(t *testing.T) {
		// The name is what the report claims; the manifest is what the samples
		// are. A manifest that does not carry the report's corpus name is not
		// trusted to classify it, so this one falls back to the path.
		p := edit(t, func(doc map[string]interface{}) {
			doc["run"].(map[string]interface{})["corpus_name"] = "production-fleet"
		})
		_, out, _ := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--eval", p)...)
		e := honestyIndex(t, out).Evaluation
		if e.CorpusClass == nil || *e.CorpusClass != honesty.CorpusSynthetic || !honestyHasCaveat(e.Caveats, "plumbing check") {
			t.Errorf("a renamed smoke report lost its synthetic label: class %v caveats %q", e.CorpusClass, e.Caveats)
		}
	})

	t.Run("no report and no expectation in the working directory", func(t *testing.T) {
		repo, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		manifest := filepath.Join(t.TempDir(), "integrity.json")
		t.Chdir(t.TempDir())
		code, out, errOut := runHonesty(t, "--format", "json", "--strict",
			"--rules", filepath.Join(repo, "rules"), "--db", filepath.Join(repo, "signatures", "hashes.txt"),
			"--fuzzy-db", filepath.Join(repo, "signatures", "fuzzy.txt"), "--manifest", manifest)
		if code != report.ExitOK {
			t.Fatalf("exit %d, want %d\n%s", code, report.ExitOK, errOut)
		}
		ix := honestyIndex(t, out)
		if ix.Evaluation.State != honesty.StateNotMeasured || ix.Evaluation.Totals != nil || ix.Evaluation.Report != nil {
			t.Errorf("evaluation = %+v, want not-measured with no numbers", ix.Evaluation)
		}
		if strings.Contains(out, `"tp"`) {
			t.Error("a not-measured evaluation printed counts")
		}
		c := ix.Coverage
		if c.State != honesty.StateNoBaseline || c.Expectation != nil || c.DeclaredGaps != nil || c.Covered != nil {
			t.Errorf("coverage = %+v, want no-baseline with the split unknown", c)
		}
		if c.TechniquesWithContent == nil || *c.TechniquesWithContent == 0 {
			t.Error("coverage without an expectation lost the live technique count")
		}
		if ix.Selftest.State != honesty.StateNoBaseline {
			t.Errorf("selftest = %q", ix.Selftest.State)
		}
	})
}

func TestHonestySelftestStates(t *testing.T) {
	work := t.TempDir()
	db := filepath.Join(work, "hashes.txt")
	good := []byte("SHA256|" + strings.Repeat("a", 64) + "|X\n")
	manifest := filepath.Join(work, "integrity.json")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyFile := func(name string, body string) string {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pubFile := keyFile("pub.hex", hex.EncodeToString(pub))
	otherFile := keyFile("other.hex", hex.EncodeToString(otherPub))
	junkFile := keyFile("junk.hex", "not a key")

	// record writes a baseline of the temp DB the way `cau selftest --record`
	// does, signed or not.
	record := func(t *testing.T, sign bool) {
		t.Helper()
		if err := os.WriteFile(db, good, 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := selftest.Compute([]selftest.Resource{{Name: "signatures", Path: db}})
		if err != nil {
			t.Fatal(err)
		}
		if sign {
			m.Sign(priv)
		}
		if err := selftest.WriteManifest(manifest, m); err != nil {
			t.Fatal(err)
		}
	}
	run := func(t *testing.T, extra ...string) (int, honesty.Selftest) {
		t.Helper()
		args := append([]string{"--format", "json", "--strict", "--rules", "rules", "--db", db, "--manifest", manifest}, extra...)
		code, out, errOut := runHonesty(t, args...)
		if code != report.ExitOK && code != report.ExitThreat {
			t.Fatalf("exit %d\n%s", code, errOut)
		}
		return code, honestyIndex(t, out).Selftest
	}
	check := func(t *testing.T, code int, s honesty.Selftest, wantCode int, state, sig, caveat string) {
		t.Helper()
		if code != wantCode || s.State != state {
			t.Fatalf("exit %d state %q, want exit %d state %q; caveats %q", code, s.State, wantCode, state, s.Caveats)
		}
		if sig != "" && (s.Signature == nil || *s.Signature != sig) {
			t.Errorf("signature = %v, want %q", s.Signature, sig)
		}
		if !honestyHasCaveat(s.Caveats, caveat) {
			t.Errorf("caveats lack %q: %q", caveat, s.Caveats)
		}
	}

	t.Run("unsigned baseline, intact", func(t *testing.T) {
		record(t, false)
		code, s := run(t)
		check(t, code, s, report.ExitOK, honesty.StateMeasured, honesty.SignatureUnsigned, "digest check only")
		if s.Intact == nil || !*s.Intact || len(s.Resources) != 1 || s.Resources[0].Path != db {
			t.Errorf("selftest = %+v", s)
		}
		// The baseline covers the temp DB only. The rules this run resolved
		// are not in it, and the index says so instead of implying they were
		// checked.
		if !honestyHasCaveat(s.Caveats, "does not cover the rules resource") {
			t.Errorf("an uncovered resource is not flagged: %q", s.Caveats)
		}
		if honestyHasCaveat(s.Caveats, "does not cover the signatures resource") {
			t.Errorf("the baselined DB is flagged as uncovered: %q", s.Caveats)
		}
	})
	t.Run("unsigned baseline, key required", func(t *testing.T) {
		record(t, false)
		code, s := run(t, "--pubkey", pubFile)
		check(t, code, s, report.ExitThreat, honesty.StateTampered, honesty.SignatureMissing, "carries no signature")
	})
	t.Run("signed and verified", func(t *testing.T) {
		record(t, true)
		code, s := run(t, "--pubkey", pubFile)
		check(t, code, s, report.ExitOK, honesty.StateMeasured, honesty.SignatureVerified, "verifies against the public key")
	})
	t.Run("signed, key from the environment", func(t *testing.T) {
		record(t, true)
		// Set after runHonesty's own cleanup of the variable would run, so
		// call the command directly.
		t.Setenv(envSelftestKey, hex.EncodeToString(pub))
		var out, errb bytes.Buffer
		if code := cmdHonesty([]string{"--format", "json", "--no-timestamp", "--rules", "rules", "--db", db, "--manifest", manifest}, &out, &errb); code != report.ExitOK {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		if s := honestyIndex(t, out.String()).Selftest; s.Signature == nil || *s.Signature != honesty.SignatureVerified {
			t.Errorf("signature = %v, want verified", s.Signature)
		}
	})
	t.Run("signed, no key", func(t *testing.T) {
		record(t, true)
		code, s := run(t)
		check(t, code, s, report.ExitOK, honesty.StateMeasured, honesty.SignatureNotChecked, "signature was not checked")
	})
	t.Run("signed, wrong key", func(t *testing.T) {
		record(t, true)
		code, s := run(t, "--pubkey", otherFile)
		check(t, code, s, report.ExitThreat, honesty.StateTampered, honesty.SignatureBad, "does not verify")
	})
	t.Run("unusable key is an error, not a downgrade", func(t *testing.T) {
		record(t, true)
		for _, key := range []string{junkFile, filepath.Join(work, "absent.hex")} {
			code, s := run(t, "--pubkey", key)
			check(t, code, s, report.ExitThreat, honesty.StateError, honesty.SignatureNotChecked, "A public key was supplied but could not be")
			for _, c := range s.Caveats {
				if strings.Contains(c, "no public key was supplied") {
					t.Errorf("a key was supplied; the caveat must not say otherwise: %q", c)
				}
			}
		}
	})
	t.Run("content changed", func(t *testing.T) {
		record(t, true)
		if err := os.WriteFile(db, []byte("SHA256|"+strings.Repeat("b", 64)+"|Evil\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		code, s := run(t, "--pubkey", pubFile)
		check(t, code, s, report.ExitThreat, honesty.StateTampered, honesty.SignatureVerified, "no longer match the baseline")
		if s.Intact == nil || *s.Intact || len(s.Drift) != 1 || s.Drift[0].Name != "signatures" {
			t.Errorf("drift = %+v intact = %v", s.Drift, s.Intact)
		}
	})
	t.Run("baseline that does not parse", func(t *testing.T) {
		if err := os.WriteFile(manifest, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		code, s := run(t)
		check(t, code, s, report.ExitThreat, honesty.StateError, "", "could not be read")
		if s.Intact != nil || s.Signature != nil {
			t.Errorf("an unreadable baseline claimed a result: %+v", s)
		}
	})
	t.Run("no baseline", func(t *testing.T) {
		if err := os.Remove(manifest); err != nil {
			t.Fatal(err)
		}
		code, s := run(t)
		check(t, code, s, report.ExitOK, honesty.StateNoBaseline, "", "this is not a pass")
		if s.Manifest != manifest {
			t.Errorf("manifest = %q, want the path that was looked for", s.Manifest)
		}
	})
}

func TestHonestyCoverageErrorIsAState(t *testing.T) {
	// Rules that cannot be loaded do not stop the index: the coverage section
	// says error, the others are still reported.
	code, out, errOut := runHonesty(t, "--format", "json", "--rules", "/no/such/rules", "--db", "signatures/hashes.txt",
		"--manifest", filepath.Join(t.TempDir(), "integrity.json"))
	if code != report.ExitOK {
		t.Fatalf("exit %d, want %d\n%s", code, report.ExitOK, errOut)
	}
	ix := honestyIndex(t, out)
	if c := ix.Coverage; c.State != honesty.StateError || c.TechniquesWithContent != nil || c.Expectation != nil {
		t.Errorf("coverage = %+v, want error with no numbers", c)
	}
	if ix.Evaluation.State != honesty.StateMeasured {
		t.Errorf("evaluation = %q; one failed section took another down", ix.Evaluation.State)
	}

	// An expectation that does not parse: the matrix was built, the gate was not.
	bad := filepath.Join(t.TempDir(), "expect.txt")
	os.WriteFile(bad, []byte("T1003 sometimes\n"), 0o644)
	_, out, _ = runHonesty(t, honestyRepoArgs(t, "--format", "json", "--expect", bad)...)
	if c := honestyIndex(t, out).Coverage; c.State != honesty.StateError || c.TechniquesWithContent == nil || c.Covered != nil {
		t.Errorf("coverage with an unparseable expectation = %+v", c)
	}
}

func TestHonestyOutputAndUsage(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "index.json")
	code, out, errOut := runHonesty(t, honestyRepoArgs(t, "--format", "json", "--output", dest)...)
	if code != report.ExitOK || out != "" {
		t.Fatalf("--output: exit %d, %d bytes on stdout\n%s", code, len(out), errOut)
	}
	written, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if ix := honestyIndex(t, string(written)); ix.Coverage.State != honesty.StateMeasured {
		t.Errorf("the written index has coverage state %q", ix.Coverage.State)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"unwritable output", honestyRepoArgs(t, "--output", filepath.Join(t.TempDir(), "no", "such", "dir", "x.json")), report.ExitRunFailed},
		{"bad format", []string{"--format", "xml"}, report.ExitUsage},
		{"positional", []string{"extra"}, report.ExitUsage},
		{"unknown flag", []string{"--score"}, report.ExitUsage},
		{"help", []string{"--help"}, report.ExitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := runHonesty(t, tc.args...)
			if code != tc.want {
				t.Errorf("exit %d, want %d\nstderr:\n%s", code, tc.want, errOut)
			}
			if out != "" {
				t.Errorf("a failed run wrote %d bytes to stdout", len(out))
			}
			if errOut == "" {
				t.Error("a failed run said nothing on stderr")
			}
		})
	}

	var usage bytes.Buffer
	honestyUsage(&usage)
	for _, want := range []string{"Usage: cau honesty", "--strict", "--no-timestamp", "--eval", "--expect", "--pubkey", "no overall score", "Exit codes"} {
		if !strings.Contains(usage.String(), want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

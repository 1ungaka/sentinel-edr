// Package honesty assembles the honesty index: one scriptable document that
// states what the engine's detection content covers, what an evaluation run
// measured, and whether that content still matches its integrity baseline.
//
// It is the PLAN's "Honesty-index v0". A buyer, an auditor or an insurer runs
// it themselves and reads three sections, each with its own state. The rules
// the document follows:
//
//   - A gap is shown, never padded. A section that could not be measured says
//     "not-measured" or "no-baseline"; it never reports zeros.
//   - There is no composite score, grade or overall number. A gap in one
//     section is not offset by a result in another.
//   - Every number travels with the caveats that bound what it means. Recall
//     on the committed smoke corpus is the standing example: that corpus is
//     synthetic, so the number is a plumbing check and not a detection rate.
//
// The package takes plain data. The command that feeds it (cau honesty) calls
// the coverage, eval and selftest packages and maps their results onto the
// input types here, so this package can be tested without any of them.
package honesty

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SchemaVersion versions the document. v1 adds the third-party columns.
const SchemaVersion = "0.1.0"

// Section states. The vocabulary is closed: a consumer can switch on it.
const (
	// StateMeasured: the section was measured and nothing disagreed.
	StateMeasured = "measured"
	// StateNotMeasured: there was nothing to read the measurement from.
	StateNotMeasured = "not-measured"
	// StateMismatch: the measurement disagrees with its committed expectation.
	StateMismatch = "mismatch"
	// StateNoBaseline: measured, or measurable, but there is no baseline to
	// hold it against. Absence of a baseline is not a pass.
	StateNoBaseline = "no-baseline"
	// StateTampered: the detection content, or the baseline's signature, does
	// not match what was recorded.
	StateTampered = "tampered"
	// StateError: the section could not be produced.
	StateError = "error"
)

// States lists the vocabulary in a fixed order.
var States = []string{StateMeasured, StateNotMeasured, StateMismatch, StateNoBaseline, StateTampered, StateError}

// Corpus classes. The index never asserts that a corpus is real malware: it
// can recognise the synthetic one, and everything else is unclassified.
const (
	CorpusSynthetic    = "synthetic"
	CorpusUnclassified = "unclassified"
)

// Signature states of the integrity baseline.
const (
	// SignatureVerified: signed, and the signature verifies against the key
	// supplied to this run.
	SignatureVerified = "verified"
	// SignatureUnsigned: no signature, and none was required.
	SignatureUnsigned = "unsigned"
	// SignatureNotChecked: signed, but no key was supplied to check it with.
	SignatureNotChecked = "not-checked"
	// SignatureBad: signed, and the signature does not verify.
	SignatureBad = "bad"
	// SignatureMissing: a key was supplied, so a signature was required, and
	// the baseline carries none.
	SignatureMissing = "missing"
)

// syntheticSource is the provenance source the committed smoke corpus
// declares for its samples.
const syntheticSource = "synthetic"

// ── document ─────────────────────────────────────────────────────────────────

// Index is the honesty index document. Field order is the JSON key order.
type Index struct {
	SchemaVersion string `json:"schema_version"`
	Tool          Tool   `json:"tool"`
	// Generated is an RFC 3339 UTC timestamp, or null when the caller
	// suppressed it for reproducible output.
	Generated  *string    `json:"generated"`
	Coverage   Coverage   `json:"coverage"`
	Evaluation Evaluation `json:"evaluation"`
	Selftest   Selftest   `json:"selftest"`
	// NotClaimed is the fixed list of what this version does not measure.
	NotClaimed []string `json:"not_claimed"`
}

// Tool names the build that produced the index.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Coverage is the ATT&CK coverage section. A null count means "not known",
// which is different from zero.
type Coverage struct {
	State   string   `json:"state"`
	Caveats []string `json:"caveats"`
	// TechniquesWithContent counts techniques some detection content maps to.
	TechniquesWithContent *int `json:"techniques_with_content"`
	// Covered and Partial split that count. The split comes from the
	// expectation file, so both are null without one.
	Covered      *int     `json:"covered"`
	Partial      *int     `json:"partial"`
	TechniqueIDs []string `json:"technique_ids"`
	PartialIDs   []string `json:"partial_ids"`
	// DeclaredGaps are techniques the expectation declares as not covered.
	// Null without an expectation: the gaps are then unknown, not absent.
	DeclaredGaps []Gap `json:"declared_gaps"`
	GapsPlanned  *int  `json:"gaps_planned"`
	GapsNone     *int  `json:"gaps_none"`
	// UnmappedContent counts content entries that map to no technique.
	UnmappedContent *int         `json:"unmapped_content"`
	UnmappedLabels  []string     `json:"unmapped_labels"`
	Sources         []Source     `json:"sources"`
	Expectation     *Expectation `json:"expectation"`
}

// Technique is one technique with detection content.
type Technique struct {
	ID      string
	Name    string
	Partial bool
}

// Gap is a technique the expectation declares as not covered. State is
// "planned" (on the roadmap) or "none" (owned by the sensor or console).
type Gap struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Note  string `json:"note"`
}

// Source is one detector's share of the content.
type Source struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
	Mapped  int    `json:"mapped"`
	Content int    `json:"content"`
	Note    string `json:"note"`
}

// Expectation is the comparison against the committed coverage expectation.
type Expectation struct {
	Path     string    `json:"path"`
	Matches  bool      `json:"matches"`
	Problems []Problem `json:"problems"`
}

// Problem is one disagreement between the live matrix and the expectation.
type Problem struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Evaluation is the evaluation section: what a recorded eval report says.
type Evaluation struct {
	State   string   `json:"state"`
	Caveats []string `json:"caveats"`
	// CorpusClass is "synthetic" or "unclassified"; null when not measured.
	CorpusClass *string `json:"corpus_class"`
	// CorpusClassBasis says how the class was decided.
	CorpusClassBasis *string       `json:"corpus_class_basis"`
	Report           *EvalReport   `json:"report"`
	Corpus           *Corpus       `json:"corpus"`
	Samples          *SampleCounts `json:"samples"`
	Totals           *Counts       `json:"totals"`
	Metrics          *Metrics      `json:"metrics"`
	Detectors        []Detector    `json:"detectors"`
}

// EvalReport identifies the report the numbers were read from.
type EvalReport struct {
	Path string `json:"path"`
	Tool string `json:"tool"`
	// Generated is when the report was recorded, or "" when it does not say.
	Generated string `json:"generated"`
}

// Corpus identifies the corpus the report measured.
type Corpus struct {
	Name     string `json:"name"`
	Manifest string `json:"manifest"`
	// ProvenanceSources are the distinct provenance sources the corpus
	// manifest declares. Null when the manifest could not be read.
	ProvenanceSources []string `json:"provenance_sources"`
}

// SampleCounts are the report's sample counts.
type SampleCounts struct {
	Total     int `json:"total"`
	Scored    int `json:"scored"`
	Malicious int `json:"malicious"`
	Benign    int `json:"benign"`
	Errors    int `json:"errors"`
	Skipped   int `json:"skipped"`
}

// Counts is a confusion matrix.
type Counts struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	TN int `json:"tn"`
	FN int `json:"fn"`
}

// Metrics are the ratios the report carries. Null means undefined (precision
// over a run that flagged nothing is not 0%).
type Metrics struct {
	Precision         *float64 `json:"precision"`
	Recall            *float64 `json:"recall"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
}

// Detector is one detector's slice of the run.
type Detector struct {
	Name          string  `json:"detector"`
	Counts        Counts  `json:"counts"`
	Metrics       Metrics `json:"metrics"`
	Fires         int     `json:"fires"`
	ExclusiveHits int     `json:"exclusive_hits"`
}

// Selftest is the content-integrity section.
type Selftest struct {
	State   string   `json:"state"`
	Caveats []string `json:"caveats"`
	// Manifest is the baseline file that was looked for; "" when no location
	// could be worked out.
	Manifest string `json:"manifest"`
	// Signature is one of the Signature* values; null without a baseline.
	Signature *string `json:"signature"`
	// Intact reports whether every baselined resource still matches. Null
	// when the content was not checked.
	Intact    *bool      `json:"intact"`
	Resources []Resource `json:"resources"`
	Drift     []Drift    `json:"drift"`
}

// Resource is one baselined resource.
type Resource struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Drift is one resource that no longer matches the baseline.
type Drift struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// ── inputs ───────────────────────────────────────────────────────────────────

// Inputs is everything Build needs.
type Inputs struct {
	Tool    string
	Version string
	// Generated is the document timestamp. The zero time suppresses it.
	Generated time.Time
	Coverage  CoverageInput
	// Eval is nil when no evaluation report was available.
	Eval     *EvalInput
	Selftest SelftestInput
}

// CoverageInput is the coverage matrix and its comparison.
type CoverageInput struct {
	// Err is set when the matrix could not be built at all.
	Err        string
	Techniques []Technique
	// Unmapped are the labels of content entries with no technique.
	Unmapped []string
	Sources  []Source
	// Notes become caveats (for example "no YARA ruleset was loaded").
	Notes []string
	// ExpectPath is the expectation file; "" when there is none.
	ExpectPath string
	// ExpectErr is set when the expectation file could not be read.
	ExpectErr string
	// Gaps and Problems are the result of the comparison.
	Gaps     []Gap
	Problems []Problem
}

// EvalInput is a loaded evaluation report.
type EvalInput struct {
	// Err is set when the report could not be read or does not add up.
	Err        string
	ReportPath string
	// Tool and Generated are the report's own provenance.
	Tool      string
	Generated time.Time
	// CorpusName and CorpusManifest are what the report records.
	CorpusName     string
	CorpusManifest string
	// ManifestRead is true when the corpus manifest the report names was
	// found and read; ProvenanceSources are then the distinct provenance
	// sources of its samples.
	ManifestRead      bool
	ProvenanceSources []string
	// Samples is every sample in the report; Errors and Skipped are the ones
	// that were not scored.
	Samples   int
	Errors    int
	Skipped   int
	Totals    Counts
	Metrics   Metrics
	Detectors []Detector
}

// SelftestInput is the result of checking the integrity baseline.
type SelftestInput struct {
	// ManifestPath is the baseline that was looked for.
	ManifestPath string
	// Found is true when the baseline exists and was parsed.
	Found bool
	// Err is set when the baseline or the key could not be used.
	Err string
	// Signature is one of the Signature* values (when Found).
	Signature string
	// Checked is true when the content digests were recomputed.
	Checked   bool
	Resources []Resource
	Drift     []Drift
	// Notes become caveats.
	Notes []string
}

// ── build ────────────────────────────────────────────────────────────────────

// notClaimed is the fixed list of what v0 does not measure.
var notClaimed = []string{
	"No third-party columns: no other engine, rule pack or vendor coverage claim is measured here. That is v1.",
	"No real-malware recall, unless an evaluation report from a real held-out corpus is supplied. The committed smoke corpus is synthetic.",
	"No runtime or sensor coverage: the coverage section describes file-scanning detection content, not what a deployed sensor observes.",
	"No drop accounting: event loss in a running sensor is not measured.",
	"No signature on the index itself: nothing here proves who produced it or that it was not edited afterwards.",
	"No overall score or grade: the three sections are not combined into one number.",
}

// Build assembles the index. It does not modify its inputs, and two calls
// with equal inputs return equal documents.
func Build(in Inputs) *Index {
	ix := &Index{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: in.Tool, Version: in.Version},
		NotClaimed:    append([]string(nil), notClaimed...),
	}
	if !in.Generated.IsZero() {
		ts := in.Generated.UTC().Format(time.RFC3339)
		ix.Generated = &ts
	}
	ix.Coverage = buildCoverage(in.Coverage)
	ix.Evaluation = buildEvaluation(in.Eval, strings.TrimSpace(in.Tool+" "+in.Version))
	ix.Selftest = buildSelftest(in.Selftest)
	return ix
}

// Failing lists the sections whose state a strict caller treats as a failure
// (mismatch, tampered, error), as "section: state".
func (ix *Index) Failing() []string {
	var out []string
	for _, s := range []struct{ name, state string }{
		{"coverage", ix.Coverage.State},
		{"evaluation", ix.Evaluation.State},
		{"selftest", ix.Selftest.State},
	} {
		switch s.state {
		case StateMismatch, StateTampered, StateError:
			out = append(out, s.name+": "+s.state)
		}
	}
	return out
}

func intPtr(n int) *int       { return &n }
func strPtr(s string) *string { return &s }

func buildCoverage(in CoverageInput) Coverage {
	c := Coverage{Caveats: []string{}}
	if in.Err != "" {
		c.State = StateError
		c.Caveats = append(c.Caveats, "The coverage matrix could not be built: "+in.Err)
		return c
	}

	ids := make([]string, 0, len(in.Techniques))
	partial := []string{}
	for _, t := range in.Techniques {
		ids = append(ids, t.ID)
		if t.Partial {
			partial = append(partial, t.ID)
		}
	}
	sort.Strings(ids)
	sort.Strings(partial)
	c.TechniquesWithContent = intPtr(len(ids))
	c.TechniqueIDs = ids

	labels := append([]string{}, in.Unmapped...)
	sort.Strings(labels)
	c.UnmappedContent = intPtr(len(labels))
	c.UnmappedLabels = labels

	c.Sources = append([]Source{}, in.Sources...)
	sort.SliceStable(c.Sources, func(i, j int) bool { return c.Sources[i].Name < c.Sources[j].Name })

	c.Caveats = append(c.Caveats,
		"A technique counts as covered when shipped detection content maps to it. That describes the content; it is not a measured detection rate for the technique.")
	c.Caveats = append(c.Caveats, in.Notes...)

	switch {
	case in.ExpectPath == "":
		c.State = StateNoBaseline
		c.Caveats = append(c.Caveats,
			"No coverage expectation file was found, so the matrix was not compared against a committed baseline. Declared gaps and partial marks are unknown, not absent.")
		return c
	case in.ExpectErr != "":
		c.State = StateError
		c.Caveats = append(c.Caveats,
			"The coverage expectation could not be read, so the matrix was not compared and declared gaps and partial marks are unknown: "+in.ExpectErr)
		return c
	}

	c.PartialIDs = partial
	c.Partial = intPtr(len(partial))
	c.Covered = intPtr(len(ids) - len(partial))

	c.DeclaredGaps = append([]Gap{}, in.Gaps...)
	sort.SliceStable(c.DeclaredGaps, func(i, j int) bool { return c.DeclaredGaps[i].ID < c.DeclaredGaps[j].ID })
	planned, none := 0, 0
	for _, g := range c.DeclaredGaps {
		if g.State == "none" {
			none++
		} else {
			planned++
		}
	}
	c.GapsPlanned, c.GapsNone = intPtr(planned), intPtr(none)
	if len(c.DeclaredGaps) == 0 {
		c.Caveats = append(c.Caveats,
			"The expectation declares no gaps. That is the absence of a declaration, not of gaps: a technique with no content and no row in the expectation is not listed anywhere in this section.")
	}

	problems := append([]Problem{}, in.Problems...)
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].ID != problems[j].ID {
			return problems[i].ID < problems[j].ID
		}
		return problems[i].Kind < problems[j].Kind
	})
	c.Expectation = &Expectation{Path: in.ExpectPath, Matches: len(problems) == 0, Problems: problems}

	if len(partial) > 0 {
		c.Caveats = append(c.Caveats, fmt.Sprintf(
			"%d technique(s) are partial by design: content maps to them and the coverage is acknowledged incomplete.", len(partial)))
	}
	if len(problems) > 0 {
		c.State = StateMismatch
		c.Caveats = append(c.Caveats, fmt.Sprintf(
			"The live matrix differs from the expectation in %d place(s). The counts describe the live content; the differences are listed.", len(problems)))
		return c
	}
	c.State = StateMeasured
	return c
}

// ClassifyCorpus decides the corpus class of an evaluation report and says
// how. The only class it can positively identify is the synthetic one:
//
//  1. the corpus manifest the report names was read and declares every
//     sample's provenance source as "synthetic";
//  2. the report's corpus name is "smoke";
//  3. the report's corpus path has a "smoke" path element.
//
// Anything else is unclassified. Nothing is ever classified as real malware:
// the index cannot verify that, and a mislabel in that direction would turn a
// plumbing check into a published detection rate.
func ClassifyCorpus(name, manifestPath string, manifestRead bool, sources []string) (class, basis string) {
	if manifestRead && len(sources) > 0 {
		all := true
		for _, s := range sources {
			if !strings.EqualFold(strings.TrimSpace(s), syntheticSource) {
				all = false
				break
			}
		}
		if all {
			return CorpusSynthetic, "the corpus manifest declares every sample's provenance source as synthetic"
		}
	}
	if strings.EqualFold(strings.TrimSpace(name), "smoke") {
		return CorpusSynthetic, "the report's corpus name is smoke, the committed synthetic corpus"
	}
	for _, el := range strings.Split(filepath.ToSlash(manifestPath), "/") {
		if strings.EqualFold(el, "smoke") {
			return CorpusSynthetic, "the report's corpus path names the smoke corpus"
		}
	}
	return CorpusUnclassified, "nothing in the report or its corpus manifest identifies what the samples are"
}

func buildEvaluation(in *EvalInput, thisBuild string) Evaluation {
	e := Evaluation{Caveats: []string{}}
	if in == nil {
		e.State = StateNotMeasured
		e.Caveats = append(e.Caveats,
			"No evaluation report was supplied or found. Precision, recall and false-positive counts are not measured; they are not zero.")
		return e
	}
	if in.Err != "" {
		e.State = StateError
		e.Report = &EvalReport{Path: in.ReportPath}
		e.Caveats = append(e.Caveats, "The evaluation report could not be used, so nothing is reported from it: "+in.Err)
		return e
	}

	e.State = StateMeasured
	e.Report = &EvalReport{Path: in.ReportPath, Tool: in.Tool}
	if !in.Generated.IsZero() {
		e.Report.Generated = in.Generated.UTC().Format(time.RFC3339)
	}
	e.Corpus = &Corpus{Name: in.CorpusName, Manifest: in.CorpusManifest}
	if in.ManifestRead {
		e.Corpus.ProvenanceSources = append([]string{}, in.ProvenanceSources...)
		sort.Strings(e.Corpus.ProvenanceSources)
	}
	class, basis := ClassifyCorpus(in.CorpusName, in.CorpusManifest, in.ManifestRead, in.ProvenanceSources)
	e.CorpusClass, e.CorpusClassBasis = strPtr(class), strPtr(basis)

	totals := in.Totals
	metrics := in.Metrics
	e.Totals, e.Metrics = &totals, &metrics
	e.Samples = &SampleCounts{
		Total:     in.Samples,
		Scored:    totals.TP + totals.FP + totals.TN + totals.FN,
		Malicious: totals.TP + totals.FN,
		Benign:    totals.TN + totals.FP,
		Errors:    in.Errors,
		Skipped:   in.Skipped,
	}
	e.Detectors = append([]Detector{}, in.Detectors...)
	sort.SliceStable(e.Detectors, func(i, j int) bool { return e.Detectors[i].Name < e.Detectors[j].Name })

	if class == CorpusSynthetic {
		e.Caveats = append(e.Caveats,
			"SYNTHETIC CORPUS. The samples are harmless files written to carry what the shipped detectors look for. Recall on a synthetic smoke corpus is a plumbing check, not a detection rate: it proves the pipeline runs, and says nothing about recall on real malware.")
	} else {
		e.Caveats = append(e.Caveats,
			"The corpus is unclassified: the index could not tell what the samples are. Recall is a detection rate only on real malware the detectors were not authored from; read these numbers against the corpus's own documentation.")
	}
	e.Caveats = append(e.Caveats,
		"These numbers are read from a recorded report. This run did not re-run the evaluation.")
	if in.Tool != "" && thisBuild != "" && in.Tool != thisBuild {
		e.Caveats = append(e.Caveats, fmt.Sprintf(
			"The report was recorded by %q; this build is %q. The numbers describe the build that recorded them.", in.Tool, thisBuild))
	}
	if e.Samples.Malicious == 0 {
		e.Caveats = append(e.Caveats, "The corpus holds no malicious samples: recall is undefined, not zero.")
	}
	if e.Samples.Benign == 0 {
		e.Caveats = append(e.Caveats, "The corpus holds no benign samples: the false-positive rate is undefined, not zero.")
	}
	if in.Errors > 0 || in.Skipped > 0 {
		e.Caveats = append(e.Caveats, fmt.Sprintf(
			"%d sample(s) could not be scanned and %d were skipped. See the report for whether errors were excluded or counted as misses.", in.Errors, in.Skipped))
	}
	if len(e.Detectors) > 0 {
		e.Caveats = append(e.Caveats,
			"Per-detector rows count every malicious sample a detector did not fire on as a miss, including samples outside its file type. Read them as contribution to the verdict, not as that detector's own detection rate.")
	}
	return e
}

func buildSelftest(in SelftestInput) Selftest {
	s := Selftest{Caveats: []string{}, Manifest: in.ManifestPath}
	const record = "Record one on a known-good install with: cau selftest --record --sign-key <key>"

	if !in.Found {
		if in.Err != "" {
			s.State = StateError
			s.Caveats = append(s.Caveats, "The integrity baseline could not be read, so the detection content was not checked: "+in.Err)
		} else {
			s.State = StateNoBaseline
			where := "No integrity baseline was found"
			if in.ManifestPath != "" {
				where += " at " + in.ManifestPath
			}
			s.Caveats = append(s.Caveats, where+". The detection content was not checked against anything; this is not a pass. "+record)
		}
		s.Caveats = append(s.Caveats, in.Notes...)
		return s
	}

	s.Signature = strPtr(in.Signature)
	s.Resources = append([]Resource{}, in.Resources...)
	sort.SliceStable(s.Resources, func(i, j int) bool { return s.Resources[i].Name < s.Resources[j].Name })
	if in.Checked {
		s.Drift = append([]Drift{}, in.Drift...)
		sort.SliceStable(s.Drift, func(i, j int) bool {
			if s.Drift[i].Name != s.Drift[j].Name {
				return s.Drift[i].Name < s.Drift[j].Name
			}
			return s.Drift[i].Reason < s.Drift[j].Reason
		})
		intact := len(s.Drift) == 0
		s.Intact = &intact
	}

	badSig := in.Signature == SignatureBad || in.Signature == SignatureMissing
	switch {
	case badSig || len(s.Drift) > 0:
		s.State = StateTampered
	case in.Err != "":
		s.State = StateError
	case !in.Checked:
		s.State = StateError
	default:
		s.State = StateMeasured
	}

	if len(s.Drift) > 0 {
		s.Caveats = append(s.Caveats, fmt.Sprintf(
			"%d resource(s) no longer match the baseline: the detection content may have been altered.", len(s.Drift)))
	}
	switch in.Signature {
	case SignatureBad:
		s.Caveats = append(s.Caveats, "The baseline's signature does not verify against the supplied key: the baseline itself cannot be trusted.")
	case SignatureMissing:
		s.Caveats = append(s.Caveats, "A key was supplied, so a signed baseline is required, and this baseline carries no signature.")
	case SignatureUnsigned:
		s.Caveats = append(s.Caveats, "The baseline is unsigned: this is a digest check only. Someone who can rewrite the detection content can rewrite the baseline too.")
	case SignatureNotChecked:
		if in.Err == "" {
			s.Caveats = append(s.Caveats, "The baseline is signed but no public key was supplied, so the signature was not checked. Treat this as a digest check only.")
		} else {
			// A key was supplied and was unusable: the reason is in the error
			// caveat. Saying "no key was supplied" beside it would be false.
			s.Caveats = append(s.Caveats, "The baseline is signed and its signature was not checked. Treat this as a digest check only.")
		}
	case SignatureVerified:
		s.Caveats = append(s.Caveats, "The signature verifies against the public key supplied to this run. The index does not establish who holds the signing key.")
	}
	if in.Err != "" {
		s.Caveats = append(s.Caveats, in.Err)
	} else if !in.Checked {
		s.Caveats = append(s.Caveats, "The content digests were not recomputed.")
	}
	s.Caveats = append(s.Caveats,
		"The baseline covers the detection content it names (signature database, rules, fuzzy database), not the engine binary.")
	s.Caveats = append(s.Caveats, in.Notes...)
	return s
}

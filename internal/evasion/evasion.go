// Package evasion measures how fragile the shipped detections are.
//
// For one file it answers one question per detector that fired: how many
// bytes have to change for that detector to stop firing? The answer comes
// from the detection's own evidence — the matched hash, the rule's condition,
// the invisible codepoints — and never from a guess. A detector whose
// distance cannot be derived is reported as not derivable, with the reason,
// rather than given a number nobody checked.
//
// The report describes the change ("break the matched string $s1") and never
// the bytes to write. This is a measurement of how strong the detection
// content is, the same kind of number the evaluation harness publishes for
// recall and false positives: it says how much work a detector's author still
// has to do, and it is deliberately not a kit for making a sample quiet.
//
// The bounds are bounds. One edit can break several detectors at once — a byte
// inside a string two rules share — so the number of bytes that must change
// for the whole verdict to move is given as a range: the largest single
// detector's distance is the lower bound (one edit could break them all), and
// the sum of the distances is the upper bound (breaking them one at a time
// always works).
package evasion

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/scanner"
)

// Detector names one detector's fragility on one file.
type Detector struct {
	// Name is the detector: "hash", "yara", "static", "stego", "encchain", …
	Name string `json:"name"`
	// Class is the specific thing that fired: the rule name, the anomaly
	// class, the threat name.
	Class string `json:"class,omitempty"`
	// Detail is what fired, in the detector's own words.
	Detail string `json:"detail,omitempty"`
	// Distance is how many bytes have to change for this detector to stop
	// firing. It is a lower bound: a detector that matched in several places
	// may need more. It is only meaningful when Derivable is true.
	Distance int `json:"distance_bytes,omitempty"`
	// Derivable is false when the distance could not be derived from the
	// evidence. The report says so instead of inventing a number.
	Derivable bool `json:"distance_derivable"`
	// Edit says what the change is, in words. It never carries an offset or
	// a byte value: this is a description of the change, not a patch.
	Edit string `json:"edit,omitempty"`
	// Technique is the ATT&CK technique the detection maps to, when it does.
	Technique string `json:"technique,omitempty"`
}

// Report is the fragility of one file.
type Report struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Verdict string `json:"verdict"`
	// Detectors are the detectors that fired, cheapest first: the ones a byte
	// away from silence come first, because they are the ones to fix.
	Detectors []Detector `json:"detectors"`
	// Lower and Upper bound the bytes that must change for the verdict to
	// move. Lower is the largest single detector's distance (one edit can
	// break several at once); Upper is their sum (breaking them one at a time
	// always works). Both are zero when nothing fired.
	Lower int `json:"lower_bound_bytes"`
	Upper int `json:"upper_bound_bytes"`
	// Notes carry what the analysis could not settle.
	Notes []string `json:"notes,omitempty"`
}

// Options configures the analysis.
type Options struct {
	// Sources maps a YARA rule name to what the analysis needs to know about
	// it. Without it the YARA distance cannot be derived (the report says so)
	// because a rule's condition decides how many of its strings have to
	// break for the rule to stop firing.
	Sources map[string]RuleSource
	// Size is the file size in bytes. It is read from the scan result when
	// that carries it, and can be set here for a caller that knows better.
	Size int64
}

// Analyze measures the fragility of the detections in a scan result.
//
// It never panics on a partial result: a detector that did not run, or that
// errored, contributes nothing but is named in the notes, because "the file
// was not analysed" is not the same as "the file is clean".
func Analyze(res *scanner.ScanResult, opts Options) *Report {
	r := &Report{Path: res.FilePath, Size: res.Size, Verdict: string(res.Verdict)}
	if opts.Size > 0 {
		r.Size = opts.Size
	}
	if res == nil {
		r.Notes = append(r.Notes, "no scan result: nothing was measured")
		return r
	}

	if res.Detected {
		d := Detector{
			Name:      "hash",
			Class:     res.ThreatName,
			Detail:    fmt.Sprintf("%s hash %s is in the signature database", res.MatchType, shortHash(res.MatchHash)),
			Distance:  1,
			Derivable: true,
			Edit:      "any byte of the file changes the hash, so one changed byte takes this detection out of the database",
		}
		r.Detectors = append(r.Detectors, d)
	}

	for _, m := range res.YaraMatches {
		d, ok := yaraDetector(m, opts.Sources)
		if !ok {
			continue
		}
		r.Detectors = append(r.Detectors, d)
	}

	if res.Static != nil {
		for _, a := range res.Static.Anomalies {
			if a.Score <= 0 {
				continue
			}
			r.Detectors = append(r.Detectors, staticDetector(res.Static, a.Class, a.Detail, a.Technique))
		}
	}

	if res.Stego != nil {
		if d, ok := stegoDetector(res.Stego); ok {
			r.Detectors = append(r.Detectors, d)
		}
	}

	if res.EncChain != nil {
		for _, f := range res.EncChain.Findings {
			r.Detectors = append(r.Detectors, encchainDetector(f))
		}
	}

	// The remaining detectors report what they found, but their distance is
	// not derived: each one keys on a structure (a shortcut's arguments, a
	// macro's entry point, a script's line), and the bytes that would have
	// to change to dismantle a structure are not a number anyone can read off
	// a finding.
	for _, d := range otherDetectors(res) {
		r.Detectors = append(r.Detectors, d)
	}

	r.sortAndBound()
	return r
}

// sortAndBound orders the detectors by how fragile they are and computes the
// bounds on the whole verdict.
func (r *Report) sortAndBound() {
	sort.SliceStable(r.Detectors, func(i, j int) bool {
		a, b := r.Detectors[i], r.Detectors[j]
		if a.Derivable != b.Derivable {
			// The derivable ones first: they are the ones with a number.
			return a.Derivable
		}
		if a.Distance != b.Distance {
			return a.Distance < b.Distance
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Class < b.Class
	})

	var sum, max int
	for _, d := range r.Detectors {
		if !d.Derivable {
			continue
		}
		sum += d.Distance
		if d.Distance > max {
			max = d.Distance
		}
	}
	r.Lower, r.Upper = max, sum
}

// shortHash renders a hash for a message: the first and last bytes are what
// identify it, the middle is noise in a one-line report.
func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "…" + h[len(h)-8:]
}

// WriteText renders the report for a human.
func (r *Report) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "evasion report: %s\n", r.Path)
	fmt.Fprintf(w, "  size    : %d bytes\n", r.Size)
	fmt.Fprintf(w, "  verdict : %s\n", r.Verdict)
	if len(r.Detectors) == 0 {
		fmt.Fprintln(w, "  no detector fired: nothing to measure")
		return nil
	}
	fmt.Fprintf(w, "  bytes that must change for the verdict to move: %d to %d\n", r.Lower, r.Upper)
	fmt.Fprintln(w)
	for _, d := range r.Detectors {
		if d.Derivable {
			fmt.Fprintf(w, "  %-10s %-28s at least %d byte(s) to break\n", d.Name, truncate(d.Class, 28), d.Distance)
		} else {
			fmt.Fprintf(w, "  %-10s %-28s distance not derivable\n", d.Name, truncate(d.Class, 28))
		}
		if d.Detail != "" {
			fmt.Fprintf(w, "             %s\n", d.Detail)
		}
		if d.Edit != "" {
			fmt.Fprintf(w, "             change: %s\n", d.Edit)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
	return nil
}

// String renders the report as text.
func (r *Report) String() string {
	var b strings.Builder
	_ = r.WriteText(&b)
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

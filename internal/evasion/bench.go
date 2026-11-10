package evasion

import (
	"fmt"
	"io"
	"sort"

	"github.com/s-b-repo/cau/internal/eval"
	"github.com/s-b-repo/cau/scanner"
)

// The bench measures the shipped detections against a corpus the operator
// supplies. It ships no attacks and generates none: the corpus is the input,
// the measurement is the output.
//
// What it answers is the question the plan asks — a detector that cannot be
// attacked has not been tested — from the other side. For every detector that
// fired anywhere in the corpus it says how often it fired and how close it
// came to silence: the number of bytes that separate a detection from a file
// that walks past it.

// Scanner scans one file. The engine satisfies it.
type Scanner interface {
	ScanFile(path string) (scanner.ScanResult, *scanner.HeuristicResult)
}

// BenchOptions configures a bench run.
type BenchOptions struct {
	// Sources are the YARA rule sources, used to derive the rule distances.
	Sources map[string]RuleSource
	// MaxSamples caps how many corpus samples are scanned. Zero means no cap.
	MaxSamples int
}

// BenchDetector is one detector's fragility across the corpus.
type BenchDetector struct {
	Name  string `json:"name"`
	Class string `json:"class,omitempty"`
	// Fired is how many samples the detector fired on.
	Fired int `json:"fired"`
	// Derivable is how many of those firings had a distance that could be
	// derived.
	Derivable int `json:"derivable"`
	// OneByte is how many of those firings were a single byte from silence:
	// the detections that are one edit away from being useless.
	OneByte int `json:"one_byte_away"`
	// MinDistance is the smallest distance seen across the corpus, -1 when
	// none of its firings had a derivable distance.
	MinDistance int `json:"min_distance_bytes"`
}

// BenchSample is one corpus sample's measurement.
type BenchSample struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Label   string `json:"label,omitempty"`
	Verdict string `json:"verdict"`
	// MinDistance is the smallest distance any of the sample's detectors
	// reported, -1 when none was derivable.
	MinDistance int `json:"min_distance_bytes"`
	// Detectors is how many detectors fired on the sample.
	Detectors int `json:"detectors"`
}

// Bench is the measurement over a corpus.
type Bench struct {
	Corpus  string `json:"corpus"`
	Scanned int    `json:"scanned"`
	// Detected is how many samples the engine called malicious or
	// suspicious.
	Detected int `json:"detected"`
	// Detectors are the detectors that fired, the most fragile first.
	Detectors []BenchDetector `json:"detectors"`
	// Samples are the per-sample rows, bounded by the caller.
	Samples []BenchSample `json:"samples,omitempty"`
	// Truncated says the per-sample rows were cut.
	Truncated bool `json:"truncated,omitempty"`
}

// RunBench measures a corpus.
//
// The corpus is a manifest in the evaluation harness's format: the same file
// the eval gate reads, so the numbers come from the same corpus the recall
// figures are published from.
func RunBench(s Scanner, manifestPath string, opts BenchOptions) (*Bench, error) {
	m, err := eval.LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	b := &Bench{Corpus: manifestPath, Scanned: len(m.Samples)}
	byKey := map[string]*BenchDetector{}

	for _, sample := range m.Samples {
		if opts.MaxSamples > 0 && len(b.Samples) >= opts.MaxSamples {
			b.Truncated = true
			break
		}
		path := sample.FullPath()
		if path == "" {
			continue
		}
		res, _ := s.ScanFile(path)
		rep := Analyze(&res, Options{Sources: opts.Sources})
		row := BenchSample{
			ID:      sample.Key(),
			Path:    sample.Path,
			Label:   sample.Expected(),
			Verdict: string(res.Verdict),
		}
		row.MinDistance = -1
		for _, d := range rep.Detectors {
			key := d.Name + "|" + d.Class
			bd, ok := byKey[key]
			if !ok {
				bd = &BenchDetector{Name: d.Name, Class: d.Class, MinDistance: -1}
				byKey[key] = bd
			}
			bd.Fired++
			if !d.Derivable {
				continue
			}
			bd.Derivable++
			if d.Distance == 1 {
				bd.OneByte++
			}
			if bd.MinDistance < 0 || d.Distance < bd.MinDistance {
				bd.MinDistance = d.Distance
			}
			if row.MinDistance < 0 || d.Distance < row.MinDistance {
				row.MinDistance = d.Distance
			}
		}
		if len(rep.Detectors) > 0 {
			b.Detected++
		}
		row.Detectors = len(rep.Detectors)
		b.Samples = append(b.Samples, row)
	}

	for _, d := range byKey {
		b.Detectors = append(b.Detectors, *d)
	}
	sort.SliceStable(b.Detectors, func(i, j int) bool {
		a, c := b.Detectors[i], b.Detectors[j]
		if a.OneByte != c.OneByte {
			return a.OneByte > c.OneByte
		}
		if a.MinDistance != c.MinDistance {
			return a.MinDistance < c.MinDistance
		}
		if a.Fired != c.Fired {
			return a.Fired > c.Fired
		}
		if a.Name != c.Name {
			return a.Name < c.Name
		}
		return a.Class < c.Class
	})
	return b, nil
}

// WriteText renders the bench for a human.
func (b *Bench) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "evasion bench: %s\n", b.Corpus)
	fmt.Fprintf(w, "  samples  : %d (%d with a detection)\n", b.Scanned, b.Detected)
	if len(b.Detectors) == 0 {
		fmt.Fprintln(w, "  no detector fired on any sample")
		return nil
	}
	fmt.Fprintln(w, "  detector                          fired  one-byte  min distance")
	for _, d := range b.Detectors {
		min := "n/a"
		if d.MinDistance >= 0 {
			min = fmt.Sprintf("%d byte(s)", d.MinDistance)
		}
		fmt.Fprintf(w, "  %-32s %5d  %8d  %s\n", truncate(d.Name+" "+d.Class, 32), d.Fired, d.OneByte, min)
	}
	if len(b.Samples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  samples:")
		for _, s := range b.Samples {
			min := "n/a"
			if s.MinDistance >= 0 {
				min = fmt.Sprintf("%d byte(s)", s.MinDistance)
			}
			fmt.Fprintf(w, "    %-28s %-10s %-12s %s\n", truncate(s.ID, 28), truncate(s.Label, 10), truncate(s.Verdict, 12), min)
		}
		if b.Truncated {
			fmt.Fprintln(w, "    (the per-sample rows were cut; the counts above cover every sample scanned)")
		}
	}
	return nil
}

package static

import (
	"fmt"
	"os"
	"time"
)

// DefaultMaxSize is the largest file AnalyzeFile reads into memory.
const DefaultMaxSize int64 = 64 << 20

// Options tunes an analysis.
type Options struct {
	// Threshold overrides the package Threshold (0 = package default).
	Threshold int
	// FuzzyDB enables similarity lookups. nil disables them.
	FuzzyDB *FuzzyDB
	// SignerBlocklist flags binaries signed by a known-abused code-signing
	// certificate. nil disables the check.
	SignerBlocklist *SignerBlocklist
	// Now is the reference time for "future timestamp" checks (zero = time.Now).
	Now time.Time
	// NoFuzzy skips TLSH/ssdeep computation. Fuzzy hashing is the most
	// expensive step on large inputs; callers that only want the PE anatomy
	// can turn it off.
	NoFuzzy bool
	// MaxSize overrides DefaultMaxSize for AnalyzeFile (0 = default).
	MaxSize int64
}

// Result is the structural analysis of one file.
type Result struct {
	FilePath string `json:"path,omitempty"`
	Size     int    `json:"size"`

	// Entropy is the whole-file Shannon entropy; Profile is the sliding-window
	// view. Both are computed for every file type.
	Entropy float64        `json:"entropy"`
	Profile EntropyProfile `json:"entropy_profile"`

	// Fuzzy holds the similarity digests; FuzzyMatches the database hits.
	Fuzzy        FuzzyHashes  `json:"fuzzy"`
	FuzzyMatches []FuzzyMatch `json:"fuzzy_matches,omitempty"`

	// IsPE is true when the file parsed as a PE image. PE is then non-nil.
	// ParseError is set for a file that looks like PE but could not be parsed.
	IsPE       bool   `json:"is_pe"`
	PE         *PE    `json:"pe,omitempty"`
	ParseError string `json:"parse_error,omitempty"`

	// IsELF is true when the file parsed as an ELF image. ELF is then non-nil.
	IsELF bool `json:"is_elf"`
	ELF   *ELF `json:"elf,omitempty"`

	Anomalies  []Anomaly       `json:"anomalies,omitempty"`
	Categories []CategoryScore `json:"categories,omitempty"`
	Score      int             `json:"score"`
	// Threshold is the threshold the result was scored against (0 means the
	// package variable applies).
	Threshold int `json:"threshold"`

	// Skipped is a non-empty reason when the file was deliberately not
	// analysed (too large). Error records a read failure. Neither is detected.
	Skipped string `json:"skipped,omitempty"`
	Error   error  `json:"-"`
}

// EffectiveThreshold returns the threshold that applies to this result.
func (r *Result) EffectiveThreshold() int {
	if r.Threshold > 0 {
		return r.Threshold
	}
	return Threshold
}

// Detected reports whether the structural score reached the threshold.
func (r *Result) Detected() bool {
	if r == nil || r.Error != nil || r.Skipped != "" {
		return false
	}
	return r.Score >= r.EffectiveThreshold()
}

// HasObservation reports whether any scored anomaly exists at all, i.e. the
// "below the threshold but not spotless" tier.
func (r *Result) HasObservation() bool {
	if r == nil {
		return false
	}
	for _, a := range r.Anomalies {
		if a.Score > 0 {
			return true
		}
	}
	return false
}

// Imphash returns the import hash, "" for non-PE files.
func (r *Result) Imphash() string {
	if r == nil || r.PE == nil {
		return ""
	}
	return r.PE.Imphash
}

// ImportHash returns the import-set clustering key for the file: the imphash
// of a PE, the CAU import-set hash of an ELF, "" otherwise.
func (r *Result) ImportHash() string {
	switch {
	case r == nil:
		return ""
	case r.PE != nil:
		return r.PE.Imphash
	case r.ELF != nil:
		return r.ELF.ImportHash
	}
	return ""
}

// ImportNames returns the import names used for similarity clustering:
// "dll.function" for a PE, bare symbol names for an ELF.
func (r *Result) ImportNames() []string {
	switch {
	case r == nil:
		return nil
	case r.PE != nil:
		return r.PE.ImportNames()
	case r.ELF != nil:
		return append([]string(nil), r.ELF.Imports...)
	}
	return nil
}

// Analyze runs the structural analysis over an in-memory buffer. It never
// panics on hostile input: parsing failures become ParseError plus warnings.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.Threshold}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	r.Entropy = Entropy(data)
	r.Profile = Profile(data, DefaultEntropyWindow)
	if !opts.NoFuzzy {
		r.Fuzzy = ComputeFuzzy(data)
	}

	var anoms []Anomaly
	switch {
	case IsPE(data):
		p, err := ParsePE(data)
		if err != nil {
			r.ParseError = err.Error()
			anoms = append(anoms, Anomaly{Class: "format.unparseable", Category: CatFormat, Score: 2,
				Detail: "MZ/PE signature present but headers could not be parsed: " + err.Error()})
		} else {
			r.IsPE = true
			r.PE = p
			p.ImportCount = 0
			for _, d := range p.Imports {
				p.ImportCount += len(d.Functions)
			}
			anoms = append(anoms, anomalies(p, now)...)
		}
	case IsELF(data):
		e, err := ParseELF(data)
		if err != nil {
			r.ParseError = err.Error()
			anoms = append(anoms, Anomaly{Class: "format.unparseable", Category: CatFormat, Score: 2,
				Detail: "ELF signature present but headers could not be parsed: " + err.Error()})
		} else {
			r.IsELF = true
			r.ELF = e
			anoms = append(anoms, elfAnomalies(e)...)
		}
	}
	if opts.FuzzyDB != nil {
		r.FuzzyMatches = opts.FuzzyDB.Lookup(r.Fuzzy, r.Imphash())
		anoms = append(anoms, fuzzyAnomalies(r.FuzzyMatches)...)
	}
	if opts.SignerBlocklist != nil && r.PE != nil && r.PE.Authenticode != nil {
		if a, ok := signerBlockAnomaly(opts.SignerBlocklist, r.PE.Authenticode.Certificates); ok {
			anoms = append(anoms, a)
		}
	}
	r.Anomalies = anoms
	r.Categories, r.Score = score(anoms)
	return r
}

// AnalyzeFile reads a file (subject to the size cap) and analyses it.
func AnalyzeFile(path string, opts Options) *Result {
	r := &Result{FilePath: path, Threshold: opts.Threshold}
	max := opts.MaxSize
	if max <= 0 {
		max = DefaultMaxSize
	}
	fi, err := os.Stat(path)
	if err != nil {
		r.Error = fmt.Errorf("could not stat file: %w", err)
		return r
	}
	if fi.IsDir() {
		r.Error = fmt.Errorf("%s is a directory", path)
		return r
	}
	if fi.Size() > max {
		r.Skipped = fmt.Sprintf("file is %d bytes, over the %d byte static-analysis size limit", fi.Size(), max)
		r.Size = int(fi.Size())
		return r
	}
	data, err := os.ReadFile(path)
	if err != nil {
		r.Error = fmt.Errorf("could not read file: %w", err)
		return r
	}
	out := Analyze(data, opts)
	out.FilePath = path
	return out
}

package report

import (
	"fmt"
	"strings"
)

// FailOn selects how strict the exit-code policy is. Each level is a superset
// of the one above it:
//
//	none       never fail on findings (errors still fail, see below)
//	malicious  fail on a hash-signature hit or a YARA match          (default)
//	heuristic  ... or on a heuristic, static (structural) or stego
//	           (invisible-codepoint) score at or above its threshold, or on
//	           a fused verdict that sub-threshold sources corroborated
//	clean      ... or on any heuristic or static observation at all, i.e.
//	           the run must be spotless
//
// The level is a string so that it round-trips through flags and config files
// unchanged; the zero value ("") normalises to FailOnMalicious.
type FailOn string

const (
	FailOnNone      FailOn = "none"
	FailOnMalicious FailOn = "malicious"
	FailOnHeuristic FailOn = "heuristic"
	FailOnClean     FailOn = "clean"
)

// String returns the flag spelling of the level.
func (f FailOn) String() string {
	if f == "" {
		return string(FailOnMalicious)
	}
	return string(f)
}

// Valid reports whether f is one of the known levels.
func (f FailOn) Valid() bool {
	switch f {
	case FailOnNone, FailOnMalicious, FailOnHeuristic, FailOnClean:
		return true
	}
	return false
}

// FailOnLevels lists the accepted levels, loosest first, for usage text.
var FailOnLevels = []FailOn{FailOnNone, FailOnMalicious, FailOnHeuristic, FailOnClean}

// ParseFailOn parses a --fail-on flag value. Matching is case-insensitive and
// ignores surrounding whitespace. An empty string is the default level.
func ParseFailOn(s string) (FailOn, error) {
	v := FailOn(strings.ToLower(strings.TrimSpace(s)))
	if v == "" {
		return FailOnMalicious, nil
	}
	if !v.Valid() {
		names := make([]string, 0, len(FailOnLevels))
		for _, l := range FailOnLevels {
			names = append(names, string(l))
		}
		return FailOnMalicious, fmt.Errorf("invalid --fail-on level %q (want one of %s)", s, strings.Join(names, ", "))
	}
	return v, nil
}

// Process exit codes. They are deliberately small and distinct so a pipeline
// can branch on them: `case 1` is "threat found", `case 2|3` is "the scan is
// not trustworthy", `case 4` is "the invocation was wrong".
const (
	// ExitOK: the run completed and nothing the policy cares about was found.
	ExitOK = 0
	// ExitThreat: at least one finding reached the configured FailOn level.
	ExitThreat = 1
	// ExitScanFailed: the run completed but at least one file could not be
	// scanned (or its heuristics could not run). Only used when fail-on-scan-
	// error is enabled (the default); an unscanned file is a coverage gap.
	ExitScanFailed = 2
	// ExitRunFailed: the scan could not run at all (signature database
	// unreadable, rules would not compile, ...). Always fails.
	ExitRunFailed = 3
	// ExitUsage: the command line was invalid. Never produced by this package;
	// reserved for main.
	ExitUsage = 4
)

// ExitPolicy maps a scan run onto a process exit code. It is a pure value:
// the same Input always yields the same code.
//
// Precedence, highest first:
//
//  1. Input.RunError set                      -> ExitRunFailed
//  2. fail-on-scan-error and any file error   -> ExitScanFailed
//  3. a finding at or above the FailOn level  -> ExitThreat
//  4. otherwise                               -> ExitOK
//
// A run that scanned nothing at all is ExitOK: an empty directory is not a
// threat, and main is responsible for rejecting a bad path before scanning.
type ExitPolicy struct {
	cfg config
}

// NewExitPolicy builds a policy from the shared options. Relevant options are
// WithFailOn, WithFailOnScanError and WithHeuristicThreshold.
func NewExitPolicy(opts ...Option) *ExitPolicy {
	return &ExitPolicy{cfg: buildConfig(opts)}
}

// FailOn returns the configured level.
func (p *ExitPolicy) FailOn() FailOn { return p.cfg.failOn }

// Code returns the exit code for the run.
func (p *ExitPolicy) Code(in Input) int {
	code, _ := p.decide(in)
	return code
}

// Explain returns a one-line, human-readable reason for Code(in).
func (p *ExitPolicy) Explain(in Input) string {
	_, why := p.decide(in)
	return why
}

func (p *ExitPolicy) decide(in Input) (int, string) {
	c := p.cfg

	if in.RunError != nil {
		return ExitRunFailed, fmt.Sprintf("exit %d: scan could not run: %s", ExitRunFailed, c.errorString(in.RunError))
	}

	if c.failOnScanError {
		if n := in.FileErrorCount(); n > 0 {
			return ExitScanFailed, fmt.Sprintf("exit %d: %d file(s) could not be scanned (fail-on-scan-error is on)", ExitScanFailed, n)
		}
	}

	malicious := len(in.Malicious())
	breaches := len(in.HeuristicBreach(c.heuristicThreshold))
	static := len(in.StaticBreach(c.staticThreshold))
	stego := len(in.StegoBreach(c.stegoThreshold))
	encchain := len(in.EncChainBreach(c.encChainThreshold))
	lnkHits := len(in.LNKBreach(c.lnkThreshold))
	oleHits := len(in.OLEBreach(c.oleThreshold))
	pdfHits := len(in.PDFBreach(c.pdfThreshold))
	isoHits := len(in.ISOBreach(c.isoThreshold))
	fused := len(in.FusionCorroborated())

	// suspicious is the shared tail of the heuristic and clean levels: the
	// SUSPICIOUS-tier detectors in a fixed order, so the explanation names the
	// first one that fired.
	suspicious := func() (int, string) {
		switch {
		case breaches > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the heuristic threshold %d", ExitThreat, breaches, c.heuristicThreshold)
		case static > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the static (structural) threshold %d", ExitThreat, static, c.staticThreshold)
		case stego > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the stego (invisible-codepoint) threshold %d", ExitThreat, stego, c.stegoThreshold)
		case encchain > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the encoded-executable threshold %d", ExitThreat, encchain, c.encChainThreshold)
		case lnkHits > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the Shell Link (.lnk) threshold %d", ExitThreat, lnkHits, c.lnkThreshold)
		case oleHits > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the OLE macro threshold %d", ExitThreat, oleHits, c.oleThreshold)
		case pdfHits > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the PDF document threshold %d", ExitThreat, pdfHits, c.pdfThreshold)
		case isoHits > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) reached the ISO container threshold %d", ExitThreat, isoHits, c.isoThreshold)
		case fused > 0:
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) were corroborated suspicious by the fusion of sub-threshold detectors", ExitThreat, fused)
		}
		return ExitOK, ""
	}

	switch c.failOn {
	case FailOnNone:
		return ExitOK, fmt.Sprintf("exit %d: fail-on=none never fails on findings (%d malicious, %d heuristic breach(es), %d static breach(es), %d stego breach(es), %d encoded-executable breach(es), %d shell-link breach(es), %d ole-macro breach(es), %d pdf breach(es), %d iso breach(es), %d fused)", ExitOK, malicious, breaches, static, stego, encchain, lnkHits, oleHits, pdfHits, isoHits, fused)

	case FailOnMalicious:
		if malicious > 0 {
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) matched a hash signature or YARA rule", ExitThreat, malicious)
		}
		return ExitOK, fmt.Sprintf("exit %d: no hash or YARA detections (fail-on=malicious)", ExitOK)

	case FailOnHeuristic:
		if malicious > 0 {
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) matched a hash signature or YARA rule", ExitThreat, malicious)
		}
		if code, why := suspicious(); code != ExitOK {
			return code, why
		}
		return ExitOK, fmt.Sprintf("exit %d: no detections and no heuristic, static, stego, encoded-executable or fused breach (fail-on=heuristic)", ExitOK)

	case FailOnClean:
		if malicious > 0 {
			return ExitThreat, fmt.Sprintf("exit %d: %d file(s) matched a hash signature or YARA rule", ExitThreat, malicious)
		}
		if code, why := suspicious(); code != ExitOK {
			return code, why
		}
		if in.HasHeuristicObservation() {
			return ExitThreat, fmt.Sprintf("exit %d: heuristic evidence below the threshold was observed (fail-on=clean requires a spotless run)", ExitThreat)
		}
		if in.HasStaticObservation() {
			return ExitThreat, fmt.Sprintf("exit %d: structural evidence below the threshold was observed (fail-on=clean requires a spotless run)", ExitThreat)
		}
		return ExitOK, fmt.Sprintf("exit %d: run is spotless (fail-on=clean)", ExitOK)
	}

	// normalize() guarantees one of the cases above; this is unreachable but
	// safe: an unknown level must never silently pass.
	if malicious > 0 {
		return ExitThreat, fmt.Sprintf("exit %d: %d file(s) matched a hash signature or YARA rule", ExitThreat, malicious)
	}
	return ExitOK, fmt.Sprintf("exit %d: no detections", ExitOK)
}

// buildConfig applies the options onto the shipped defaults and normalises
// the result. Every constructor in the package goes through it.
func buildConfig(opts []Option) config {
	c := defaultConfig()
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	c.normalize()
	return c
}

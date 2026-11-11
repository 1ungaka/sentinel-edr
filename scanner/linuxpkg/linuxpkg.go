// Package linuxpkg detects malicious install-time behaviour in Linux software
// packages from their public structure alone — Debian .deb, RPM .rpm, Arch
// .pkg.tar(.zst/.xz/.gz) and PKGBUILD recipes, Flatpak bundles and
// flatpak-builder manifests, AppImage type-2 images, and Docker/OCI image
// tarballs (`docker save` / `podman save`) — plus bare maintainer and install
// shell scripts.
//
// The unifying threat it addresses is the one thing every one of these formats
// has in common: an install-time script that the package manager runs AS ROOT.
// "apt/dnf/pacman install" is a trust decision, and that trust is exactly what a
// software-supply-chain payload (ATT&CK T1195.002) rides in on — a preinst that
// pipes a remote download into a shell, an RPM %post that opens a reverse shell,
// a PKGBUILD package() that drops an SSH key, a Flatpak manifest that escapes the
// sandbox. The detector pulls those scripts out of the container and scores the
// behaviours in them (see vectors.go).
//
// It is DETECTION ONLY and defensive by construction. Nothing here installs,
// extracts to disk, or executes anything: every signal is read from the bytes a
// scanner already holds. Each parser is bounded (member, script, decompression,
// and header-size caps) so a hostile package yields a partial result with a
// warning rather than a panic, a hang, or an unbounded allocation. Because the
// codebase is stdlib-only, members packed with xz or zstd (some modern .deb
// control tarballs, some Arch packages) and the SquashFS inside an AppImage are
// not decompressed; the detector records an honest "present but not inspected"
// note for those instead of guessing.
//
// Findings carry small additive weights (default threshold 8, matching the
// sibling lnk/ole/pdf/iso detectors): a benign postinst that runs ldconfig or
// update-desktop-database scores zero, while a single remote-download-into-shell
// or reverse-shell scriptlet crosses the bar on its own.
package linuxpkg

import (
	"os"

	"github.com/1ungaka/sentinel-edr/internal/intel"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
)

// DefaultThreshold is the shipped score at which a package is reported
// suspicious.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can be
// retuned without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory. Packages can be
// large; the parsers only walk metadata and the (bounded) script regions, so
// memory stays bounded by the caps in containers.go regardless.
const DefaultMaxSize int64 = 512 << 20

// Options configure a scan. The zero value uses the package defaults.
type Options struct {
	Threshold int
	// Intel, when non-nil, is the abuse-intelligence feed. Indicators (IPs,
	// domains, URLs) found in the package's install scripts and manifests are
	// matched against it; a hit is a high-weight finding. nil disables feed
	// matching entirely (the common offline case).
	Intel *intel.Feed
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one detection signal raised against a package.
type Finding struct {
	// Class is a stable identifier ("linuxpkg.script.reverse-shell").
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	// Evidence is a short, single-line, truncated excerpt naming the triggering
	// script and the matched text. It never carries a whole script body.
	Evidence string `json:"evidence,omitempty"`
}

// Parsed is a compact summary of the package, useful to a caller without
// exposing every extracted script.
type Parsed struct {
	Format  string   `json:"format"`
	Name    string   `json:"name,omitempty"`
	Scripts []string `json:"scripts,omitempty"`
	Warning string   `json:"warning,omitempty"`
}

// Result is the outcome for one file.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	Parsed    *Parsed   `json:"parsed,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
}

// EffectiveThreshold returns the threshold applied to this result.
func (r *Result) EffectiveThreshold() int {
	if r == nil {
		return Threshold
	}
	if r.Threshold > 0 {
		return r.Threshold
	}
	return Threshold
}

// Detected reports whether the score reached the threshold.
func (r *Result) Detected() bool {
	return r != nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// recognised Linux package format gets an immediate zero-score result; otherwise
// the container is parsed defensively, its install scripts are scored, and the
// bundle-level and script-level findings are summed into Result.Score.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	format := Detect(data)
	if format == FormatUnknown {
		return r
	}
	c := parse(data, format)
	r.Findings = append(r.Findings, c.findings...)
	r.Findings = append(r.Findings, scanScripts(c.scripts)...)
	r.Findings = append(r.Findings, matchIntel(opts.Intel, c.scripts)...)
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	r.Parsed = &Parsed{
		Format:  string(c.format),
		Name:    c.name,
		Scripts: c.scriptNames,
		Warning: c.warning,
	}
	return r
}

// ScanFile reads a file (subject to the size cap) and analyses it. A file over
// the cap, or one that cannot be read, is reported Skipped, never an error.
func ScanFile(path string, opts Options) *Result {
	fi, err := os.Stat(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "stat: " + err.Error()}
	}
	if fi.Size() > DefaultMaxSize {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "file over the in-memory size limit"}
	}
	data, err := safefs.ReadFile(path, DefaultMaxSize)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

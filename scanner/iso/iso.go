// Package iso detects the malicious-container delivery shape in ISO 9660 disk
// images (.iso / .img) from the public format alone — a mounted image that
// presents a shortcut relaunching an interpreter against a hidden payload is a
// common initial-access vector. ISO/IMG attachments became popular because a
// mounted image historically did NOT propagate the Mark-of-the-Web to the files
// it carried, letting a payload sidestep that warning.
//
// It is DETECTION ONLY. Nothing here creates, mounts or executes an image; the
// signal is derived entirely from the public ISO 9660 structure and from
// published abuse tradecraft (ISO email-smuggling to bypass Mark-of-the-Web),
// read out of the bytes a scanner already has. The detector enumerates the
// contained entries' names, attributes and sizes — it does not scan their
// contents; that is the engine's job elsewhere.
//
// The underlying reader (iso9660.go) is defensive by construction: it walks the
// directory tree through a queue with a depth cap, caps the total records,
// sectors and entries, uses a visited-set of extent LBAs to break cycles, and
// range-checks every access, so a malformed image yields a partial result with
// a warning rather than a panic, a hang, or an out-of-range read. Findings carry
// small additive weights, chosen so that a legitimate software ISO full of
// executables does not cross the default threshold while the lnk-plus-payload
// smuggling shape clearly does.
package iso

import (
	"os"
	"strings"
)

// ── ATT&CK technique ids ───────────────────────────────────────────────────────

const (
	techRemovableMedia = "T1091"     // Replication Through Removable Media (autorun abuse)
	techUserExec       = "T1204.002" // User Execution: Malicious File
	techHideArtifacts  = "T1564.001" // Hide Artifacts: Hidden Files and Directories
)

// ── finding weights ────────────────────────────────────────────────────────────
//
// The scale mirrors the sibling lnk/pdf detectors (DefaultThreshold 8). Weights
// are deliberately small and additive so that no single rule crosses the
// threshold on its own — the container must combine signals the way an ISO lure
// does. Worked examples:
//
//	invoice.lnk + hidden payload.exe (small image):
//	   lnk(2) + executable(2) + hidden-payload(3) + lnk-and-payload(4) + small(1) = 12  -> DETECTED
//	invoice.lnk + payload.exe (not hidden, not small):
//	   lnk(2) + executable(2) + lnk-and-payload(4)                                 = 8   -> DETECTED (just crosses)
//
// while a lone benign tell stays below the threshold of 8:
//
//	a lone .lnk shortcut                           = 2
//	a lone autorun.inf                             = 4
//	a software ISO that merely carries .exe files  = 2
//	an autorun.inf next to a setup.exe             = 6
const (
	weightAutorun       = 4 // autorun.inf in the root (autorun abuse)
	weightLnk           = 2 // a .lnk shortcut present (delivery vector)
	weightExecutable    = 2 // an executable or script file present
	weightHiddenPayload = 3 // a hidden executable/script (hallmark of ISO smuggling)
	weightLure          = 4 // the canonical lnk + payload combination
	weightSmallImage    = 1 // tiny image carrying lnk + payload (email-attachment shape)
)

// DefaultThreshold is the shipped score at which an image is reported
// suspicious. The lnk-plus-payload smuggling shape crosses it; a lone autorun,
// a lone shortcut, or a software ISO of plain executables does not.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can be
// retuned without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory. ISOs can be
// large, so the cap is generous; the reader only walks directory extents (never
// file contents), so memory stays bounded by the enumerator's caps regardless.
const DefaultMaxSize int64 = 256 << 20

// Amplifier thresholds for the "small image" email-attachment shape.
const (
	smallContentBytes int64 = 5 << 20  // total content below this is "small"
	smallImageBytes   int64 = 10 << 20 // whole image below this is "small"
)

// executableExts are the extensions that make a contained file an executable or
// script payload.
var executableExts = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".com": true, ".bat": true,
	".cmd": true, ".ps1": true, ".vbs": true, ".js": true, ".jse": true,
	".wsf": true, ".hta": true, ".pif": true, ".msi": true,
}

// Options configure a scan. The zero value uses the package defaults.
type Options struct {
	Threshold int
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one detection signal raised against an image.
type Finding struct {
	// Class is a stable identifier ("iso.lure.lnk-and-payload").
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	// Evidence is a short excerpt naming the triggering entry; it never carries
	// file content.
	Evidence string `json:"evidence,omitempty"`
}

// Parsed is a compact summary of the image, useful to a caller without exposing
// the full enumeration.
type Parsed struct {
	VolumeID          string `json:"volume_id,omitempty"`
	Files             int    `json:"files"`
	Dirs              int    `json:"dirs"`
	HasJoliet         bool   `json:"has_joliet"`
	TotalContentBytes int64  `json:"total_content_bytes"`
	Warning           string `json:"warning,omitempty"`
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

// Analyze inspects data and returns a non-nil Result. A buffer that is not an
// ISO 9660 image gets an immediate zero-score result; otherwise the image is
// enumerated defensively and the detection rules are summed into Result.Score.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsISO(data) {
		return r
	}
	im := parseISO(data)
	r.Findings = im.detect(len(data))
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	r.Parsed = im.summary()
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
	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── detection ──────────────────────────────────────────────────────────────────

// detect runs every rule over the enumerated entries and returns the findings in
// a stable order. Each signal fires at most once, so Result.Score is the sum of
// the finding weights.
func (im *image) detect(imageSize int) []Finding {
	var out []Finding

	var hasAutorun, hasLnk, hasExec, hasHiddenExec bool
	var autorunName, lnkName, execName, hiddenName string
	var totalContent int64

	for _, e := range im.entries {
		if e.isDir {
			continue
		}
		totalContent += e.size
		if e.depth == 0 && strings.EqualFold(e.name, "autorun.inf") && !hasAutorun {
			hasAutorun = true
			autorunName = e.name
		}
		if e.ext == ".lnk" && !hasLnk {
			hasLnk = true
			lnkName = e.name
		}
		if executableExts[e.ext] {
			if !hasExec {
				hasExec = true
				execName = e.name
			}
			if e.isHidden && !hasHiddenExec {
				hasHiddenExec = true
				hiddenName = e.name
			}
		}
	}

	// Rule 1 — autorun.inf in the root: autorun abuse (T1091). Weighty, but a
	// lone autorun.inf stays below the threshold so legitimate autorun media
	// does not trip on its own.
	if hasAutorun {
		out = append(out, Finding{
			Class: "iso.autorun.inf", Score: weightAutorun, Technique: techRemovableMedia,
			Detail:   "the image carries autorun.inf in its root directory",
			Evidence: autorunName,
		})
	}

	// Rule 2 — a .lnk shortcut is present: the delivery vector (T1204.002).
	if hasLnk {
		out = append(out, Finding{
			Class: "iso.payload.lnk", Score: weightLnk, Technique: techUserExec,
			Detail:   "the image carries a Windows shortcut (.lnk) — a user-execution lure",
			Evidence: lnkName,
		})
	}

	// Rule 3 — an executable or script file is present (T1204.002).
	if hasExec {
		out = append(out, Finding{
			Class: "iso.payload.executable", Score: weightExecutable, Technique: techUserExec,
			Detail:   "the image carries an executable or script file",
			Evidence: execName,
		})
	}

	// Rule 4 — a hidden executable/script (ISO hidden flag, or a payload inside a
	// hidden directory): an evasion hallmark of ISO smuggling (T1564.001).
	if hasHiddenExec {
		out = append(out, Finding{
			Class: "iso.evasion.hidden-payload", Score: weightHiddenPayload, Technique: techHideArtifacts,
			Detail:   "an executable or script is hidden (hidden flag set, or inside a hidden directory)",
			Evidence: hiddenName,
		})
	}

	// Rule 5 — the canonical lure shape: a shortcut together with an executable or
	// script payload (T1204.002). A distinct, higher-weight signal.
	lnkAndPayload := hasLnk && hasExec
	if lnkAndPayload {
		out = append(out, Finding{
			Class: "iso.lure.lnk-and-payload", Score: weightLure, Technique: techUserExec,
			Detail:   "a shortcut (.lnk) delivered alongside an executable/script payload — the canonical ISO lure",
			Evidence: lnkName + " + " + execName,
		})
	}

	// Rule 6 — small-image amplifier: a tiny image (small content or small overall
	// size) carrying the lnk+payload shape is the email-attachment delivery. Only
	// in combination, and tiny, to avoid false positives on legitimate small ISOs.
	if lnkAndPayload && (totalContent < smallContentBytes || int64(imageSize) < smallImageBytes) {
		out = append(out, Finding{
			Class: "iso.lure.small-image", Score: weightSmallImage, Technique: techUserExec,
			Detail:   "a small image carrying a shortcut and a payload — the email-attachment delivery shape",
			Evidence: itoa64(totalContent) + " content bytes",
		})
	}

	return out
}

// summary builds the compact Parsed view returned to callers.
func (im *image) summary() *Parsed {
	s := &Parsed{
		VolumeID:  im.volumeID,
		HasJoliet: im.joliet,
		Warning:   im.warning,
	}
	for _, e := range im.entries {
		if e.isDir {
			s.Dirs++
			continue
		}
		s.Files++
		s.TotalContentBytes += e.size
	}
	return s
}

// itoa64 renders a non-negative-ish int64 without fmt.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

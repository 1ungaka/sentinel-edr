package static

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Anomaly is one labeled structural finding.
type Anomaly struct {
	// Class is a stable dotted identifier ("section.rwx"). Reports, SARIF rule
	// ids and the eval harness key on it; renaming one breaks baselines.
	Class    string `json:"class"`
	Category string `json:"category"`
	// Score is the class weight before the category cap.
	Score  int    `json:"score"`
	Detail string `json:"detail"`
	// Technique is the ATT&CK technique the anomaly is evidence for, when one
	// applies. Structural anomalies map to the obfuscation / masquerading /
	// timestomp families; similarity matches map to none.
	Technique string `json:"technique,omitempty"`
}

// CategoryScore explains how one category contributed to the total.
type CategoryScore struct {
	Category string `json:"category"`
	Raw      int    `json:"raw"`
	Applied  int    `json:"applied"`
	Cap      int    `json:"cap"`
}

// Categories.
const (
	CatSections  = "Sections"
	CatEntry     = "Entry Point"
	CatHeaders   = "Headers"
	CatImports   = "Imports"
	CatPacker    = "Packer"
	CatSignature = "Signature"
	CatOverlay   = "Overlay"
	CatFormat    = "Format"
	CatFuzzy     = "Similarity"
	CatInfo      = "Info"
)

// categoryCaps bounds each category's contribution. Five RWX sections are not
// five times as suspicious as one.
var categoryCaps = map[string]int{
	CatSections:  5,
	CatEntry:     4,
	CatHeaders:   3,
	CatImports:   3,
	CatPacker:    4,
	CatSignature: 8,
	CatOverlay:   2,
	CatFormat:    3,
	CatFuzzy:     8,
	CatInfo:      0,
	CatDynamic:   4,
	CatModule:    3,
	// Every content.* persistence class together stays below the threshold.
	CatPersist: 6,
}

// DefaultThreshold is the shipped score at which a file's structure is
// reported as suspicious. See static_test.go for the real-binary fixtures
// that pin it: ordinary unpacked software (plink, vncviewer, wget, whoami,
// dbghelp.dll) scores 0-4; a UPX-packed binary scores 10+.
const DefaultThreshold = 8

// Threshold is the threshold used when a caller does not pass one. It is a
// variable so operators can retune it without a rebuild.
var Threshold = DefaultThreshold

// ATT&CK technique ids used by the anomaly classes.
const (
	techObfuscated     = "T1027"
	techPacking        = "T1027.002"
	techDynamicAPI     = "T1027.007"
	techEmbeddedPay    = "T1027.009"
	techTimestomp      = "T1070.006"
	techInvalidSig     = "T1036.001"
	techMasquerade     = "T1036"
	techCodeSigning    = "T1553.002"
	techMinEntropyExec = 7.0 // entropy above which an executable section is "packed"
	minOverlayBytes    = 1024
	minHighOverlay     = 4096
)

// ancientTimestamp is 1995-01-01: PE files predate it, but nothing linked for
// a 32-bit Windows that anyone still runs does.
var ancientTimestamp = time.Date(1995, 1, 1, 0, 0, 0, 0, time.UTC)

// standardExecNames are section names compilers give to code.
var standardExecNames = map[string]bool{
	".text": true, "CODE": true, ".code": true, "INIT": true, ".init": true,
	"PAGE": true, ".textbss": true, ".itext": true, ".orpc": true, "PAGELK": true,
	".pdata": false,
}

// anomalies derives the structural findings from a parsed PE. now is the
// reference time for "future" timestamps.
func anomalies(p *PE, now time.Time) []Anomaly {
	var out []Anomaly
	add := func(class, cat string, score int, tech, format string, a ...interface{}) {
		out = append(out, Anomaly{Class: class, Category: cat, Score: score, Technique: tech, Detail: fmt.Sprintf(format, a...)})
	}

	// ── Sections ──
	var rwx, hiEnt, mismatch, vsz, oddExec, truncated []string
	for _, s := range p.Sections {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			name = "<unnamed>"
		}
		if s.Executable() && s.Writable() && !(p.Subsystem == 1 && name == "INIT") {
			// Kernel drivers' INIT section is RWX by convention; it is not evidence.
			rwx = append(rwx, name)
		}
		if s.Executable() && s.RawSize >= 1024 && s.Entropy > techMinEntropyExec {
			hiEnt = append(hiEnt, fmt.Sprintf("%s(%.2f)", name, s.Entropy))
		}
		switch {
		case name == ".text" && !s.Executable():
			mismatch = append(mismatch, ".text is not executable")
		case (name == ".data" || name == ".rdata" || name == ".rsrc" || name == ".reloc" || name == ".idata") && s.Executable():
			mismatch = append(mismatch, name+" is executable")
		}
		if s.Executable() && !standardExecNames[name] && !strings.HasPrefix(name, ".text") && p.Packer == nil {
			oddExec = append(oddExec, name)
		}
		if s.RawSize == 0 && s.Executable() && s.VirtualSize >= 64<<10 && !s.Uninitialized() {
			vsz = append(vsz, fmt.Sprintf("%s(raw 0, virtual %d)", name, s.VirtualSize))
		} else if s.RawSize > 0 && s.VirtualSize > 4*s.RawSize && s.VirtualSize >= 64<<10 && s.Executable() {
			vsz = append(vsz, fmt.Sprintf("%s(raw %d, virtual %d)", name, s.RawSize, s.VirtualSize))
		}
		if s.Truncated {
			truncated = append(truncated, name)
		}
	}
	if len(rwx) > 0 {
		add("section.rwx", CatSections, 3, techEmbeddedPay, "writable+executable section(s): %s", strings.Join(rwx, ", "))
	}
	if len(hiEnt) > 0 {
		add("section.exec-high-entropy", CatSections, 2, techObfuscated, "executable section(s) above %.1f bits/byte: %s", techMinEntropyExec, strings.Join(hiEnt, ", "))
	}
	if len(mismatch) > 0 {
		add("section.name-perm-mismatch", CatSections, 2, techMasquerade, "%s", strings.Join(mismatch, "; "))
	}
	if len(vsz) > 0 {
		add("section.virtual-raw-mismatch", CatSections, 2, techPacking, "executable section(s) far larger in memory than on disk (unpack target): %s", strings.Join(vsz, ", "))
	}
	if len(oddExec) > 0 {
		add("section.exec-unusual-name", CatSections, 1, "", "executable section(s) with non-compiler names: %s", strings.Join(oddExec, ", "))
	}

	// ── Entry point ──
	entryIdx := p.sectionIndexForRVA(p.EntryPoint)
	switch {
	case p.EntryPoint == 0 && !p.IsDLL && !p.IsCLR:
		add("entrypoint.zero", CatEntry, 2, "", "AddressOfEntryPoint is 0 in an executable (only DLLs and CLR images may omit it)")
	case p.EntryPoint != 0 && entryIdx < 0:
		add("entrypoint.outside-sections", CatEntry, 3, techObfuscated, "entry point RVA 0x%x lies outside every section", p.EntryPoint)
	case entryIdx >= 0:
		s := p.Sections[entryIdx]
		if !s.Executable() {
			add("entrypoint.non-exec-section", CatEntry, 2, techObfuscated, "entry point in non-executable section %s (%s)", strings.TrimSpace(s.Name), s.Perms)
		}
		if s.RawSize == 0 {
			add("entrypoint.zero-raw-section", CatEntry, 3, techPacking, "entry point in section %s which has no data on disk", strings.TrimSpace(s.Name))
		}
		if entryIdx == len(p.Sections)-1 && len(p.Sections) > 1 && s.Writable() {
			add("entrypoint.last-writable-section", CatEntry, 1, techPacking, "entry point in the last section (%s), which is writable", strings.TrimSpace(s.Name))
		}
	}
	if p.TLSCallbacks > 0 {
		add("tls.callbacks", CatEntry, 1, "", "%d TLS callback(s) run before the entry point", p.TLSCallbacks)
	}

	// ── Headers ──
	ts := p.TimestampTime()
	switch {
	case p.Debug.Reproducible:
		add("header.timestamp-reproducible", CatInfo, 0, "", "reproducible build: header timestamp is a content hash, consistency checks skipped")
	case p.Timestamp == 0:
		add("header.timestamp-zero", CatHeaders, 1, techTimestomp, "link timestamp is zero")
	case p.Timestamp == delphiTimestamp:
		add("header.timestamp-delphi", CatInfo, 0, "", "Borland/Delphi constant link timestamp (1992-06-19); not an anomaly")
	case !now.IsZero() && ts.After(now.Add(24*time.Hour)):
		add("header.timestamp-future", CatHeaders, 2, techTimestomp, "link timestamp %s is in the future", ts.Format(time.RFC3339))
	case ts.Before(ancientTimestamp):
		add("header.timestamp-ancient", CatHeaders, 1, techTimestomp, "link timestamp %s predates 1995", ts.Format(time.RFC3339))
	default:
		if p.Debug.Present && p.Debug.Timestamp != 0 && absDiff(p.Debug.Timestamp, p.Timestamp) > 86400 {
			add("header.timestamp-mismatch", CatHeaders, 2, techTimestomp, "debug directory timestamp %s disagrees with header %s",
				time.Unix(int64(p.Debug.Timestamp), 0).UTC().Format(time.RFC3339), ts.Format(time.RFC3339))
		} else if p.Exports.Present && p.Exports.Timestamp != 0 && p.Exports.Timestamp != 0xFFFFFFFF && absDiff(p.Exports.Timestamp, p.Timestamp) > 86400 {
			add("header.timestamp-mismatch", CatHeaders, 2, techTimestomp, "export directory timestamp %s disagrees with header %s",
				time.Unix(int64(p.Exports.Timestamp), 0).UTC().Format(time.RFC3339), ts.Format(time.RFC3339))
		}
	}
	if p.Rich != nil && !p.Rich.ChecksumValid {
		add("rich.checksum-invalid", CatHeaders, 2, techMasquerade, "Rich header checksum does not match (key 0x%08x): copied or hand-edited build record", p.Rich.XorKey)
	}
	if p.Rich == nil && importsMSVCRuntime(p) {
		add("rich.missing-msvc", CatHeaders, 1, techMasquerade, "imports the MSVC runtime but carries no Rich header (stripped build record)")
	}
	if p.FileAlignment != 0 && (p.FileAlignment < 0x200 || p.SectionAlignment < p.FileAlignment) {
		add("header.low-alignment", CatHeaders, 1, "", "FileAlignment 0x%x / SectionAlignment 0x%x: hand-built or heavily squeezed image", p.FileAlignment, p.SectionAlignment)
	}

	// ── Imports ──
	switch {
	case p.IsCLR:
		add("clr.present", CatInfo, 0, "", ".NET assembly (CLR header present); import-table analytics do not apply")
	case p.DataDirs[dirImport].VirtualAddress == 0 && !p.IsDLL:
		add("imports.none", CatImports, 2, techDynamicAPI, "no import table in an executable")
	case p.ImportCount == 0 && len(p.Imports) > 0:
		add("imports.empty-descriptors", CatImports, 2, techDynamicAPI, "import descriptors present but no functions resolved")
	case p.ImportCount > 0 && p.ImportCount <= 8 && importsAreLoaderOnly(p):
		add("imports.loader-only", CatImports, 2, techDynamicAPI, "import table is only the loader stub (%s)", strings.Join(p.ImportNames(), ", "))
	case p.ImportCount > 0 && p.ImportCount <= 3:
		w := 1
		if len(hiEnt) > 0 {
			w = 2
		}
		add("imports.minimal", CatImports, w, techDynamicAPI, "only %d imported function(s)", p.ImportCount)
	}

	// ── Packer ──
	if pk := p.Packer; pk != nil {
		switch {
		case installerStubs[pk.Name]:
			add("packer.installer-stub", CatInfo, 0, "", "%s self-extracting stub: compressed payload is expected (%s)", pk.Name, strings.Join(pk.Evidence, "; "))
		case pk.Generic:
			add("packer.generic", CatPacker, 3, techPacking, "packed executable profile: %s", strings.Join(pk.Evidence, "; "))
		default:
			// A recognised packer weighs less than an unrecognised profile:
			// UPX on a benign tool is common, and the report already names it.
			add("packer."+slug(pk.Name), CatPacker, 2, techPacking, "packed with %s (%s)", pk.Name, strings.Join(pk.Evidence, "; "))
		}
	}

	// ── Overlay ──
	if ov := p.Overlay; ov.Size >= minOverlayBytes {
		if ov.Size >= minHighOverlay && ov.Entropy > HighEntropy {
			add("overlay.high-entropy", CatOverlay, 2, techEmbeddedPay, "%d bytes appended after the last section at %.2f bits/byte", ov.Size, ov.Entropy)
		} else {
			add("overlay.present", CatOverlay, 1, techEmbeddedPay, "%d bytes appended after the last section (%.2f bits/byte)", ov.Size, ov.Entropy)
		}
	}

	// ── Signature ──
	if a := p.Authenticode; a != nil {
		add("authenticode.unverified", CatInfo, 0, "", "%s", a.Note)
		if a.ParseErr != "" {
			add("authenticode.parse-error", CatSignature, 1, techInvalidSig, "security directory present but unparseable: %s", a.ParseErr)
		}
		if len(a.Certificates) > 0 {
			leaf := a.Certificates[0]
			if leaf.SelfSigned {
				if v := vendorNameIn(leaf.Subject); v != "" {
					// A self-signed certificate wearing a well-known vendor's name
					// is impersonation by construction; it crosses the threshold
					// on its own (6 + the EKU it will also lack).
					add("authenticode.vendor-name-self-signed", CatSignature, 6, techInvalidSig, "self-signed certificate claims to be %q (%s)", v, leaf.Subject)
				} else {
					add("authenticode.self-signed", CatSignature, 3, techCodeSigning, "signer certificate is self-signed: %s", leaf.Subject)
				}
			}
			if !leaf.CodeSigning {
				add("authenticode.no-codesign-eku", CatSignature, 2, techCodeSigning, "signer certificate lacks the code-signing extended key usage")
			}
			if !leaf.NotAfter.IsZero() && leaf.NotAfter.Sub(leaf.NotBefore) > 10*365*24*time.Hour {
				add("authenticode.long-validity", CatSignature, 1, techCodeSigning, "signer certificate valid for %.0f years", leaf.NotAfter.Sub(leaf.NotBefore).Hours()/8760)
			}
			if p.Timestamp != 0 && p.Timestamp != delphiTimestamp && !p.Debug.Reproducible &&
				(ts.Before(leaf.NotBefore.Add(-24*time.Hour)) || ts.After(leaf.NotAfter.Add(24*time.Hour))) && !a.Countersigned {
				add("authenticode.compiled-outside-validity", CatSignature, 2, techTimestomp, "link time %s is outside the signer certificate's validity (%s to %s) and there is no countersignature",
					ts.Format("2006-01-02"), leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"))
			}
		}
	}

	// ── Format ──
	if len(truncated) > 0 {
		add("format.truncated", CatFormat, 2, "", "section(s) claim data past the end of the file: %s", strings.Join(truncated, ", "))
	}
	if overlap := sectionOverlap(p); overlap != "" {
		add("format.section-overlap", CatFormat, 2, techObfuscated, "%s", overlap)
	}
	if len(p.Sections) == 0 {
		add("format.no-sections", CatFormat, 2, "", "PE image declares no sections")
	}
	return out
}

// fuzzyAnomalies turns database matches into scored evidence.
func fuzzyAnomalies(matches []FuzzyMatch) []Anomaly {
	var out []Anomaly
	for _, m := range matches {
		switch m.Type {
		case FuzzyImphash:
			out = append(out, Anomaly{Class: "fuzzy.imphash", Category: CatFuzzy, Score: 4,
				Detail: fmt.Sprintf("import hash matches %q", m.ThreatName)})
		case FuzzyTLSH:
			out = append(out, Anomaly{Class: "fuzzy.tlsh", Category: CatFuzzy, Score: 8,
				Detail: fmt.Sprintf("TLSH distance %d to %q", m.Distance, m.ThreatName)})
		case FuzzySSDeep:
			w := 5
			if m.Score >= 90 {
				w = 8
			}
			out = append(out, Anomaly{Class: "fuzzy.ssdeep", Category: CatFuzzy, Score: w,
				Detail: fmt.Sprintf("ssdeep score %d to %q", m.Score, m.ThreatName)})
		}
	}
	return out
}

// score applies the per-category caps. Each class contributes once; the
// caller guarantees that by construction (anomalies() emits each class at most
// once and summarises repeats in the detail).
func score(anoms []Anomaly) ([]CategoryScore, int) {
	raw := map[string]int{}
	var order []string
	for _, a := range anoms {
		if _, seen := raw[a.Category]; !seen {
			order = append(order, a.Category)
		}
		raw[a.Category] += a.Score
	}
	var out []CategoryScore
	total := 0
	for _, cat := range order {
		cap, ok := categoryCaps[cat]
		if !ok {
			cap = 3
		}
		applied := raw[cat]
		if applied > cap {
			applied = cap
		}
		total += applied
		out = append(out, CategoryScore{Category: cat, Raw: raw[cat], Applied: applied, Cap: cap})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Applied != out[j].Applied {
			return out[i].Applied > out[j].Applied
		}
		return out[i].Category < out[j].Category
	})
	return out, total
}

func importsMSVCRuntime(p *PE) bool {
	for _, d := range p.Imports {
		n := strings.ToLower(d.Name)
		switch {
		case strings.HasPrefix(n, "vcruntime"), strings.HasPrefix(n, "api-ms-win-crt"):
			return true
		case strings.HasPrefix(n, "msvcr"), strings.HasPrefix(n, "msvcp"):
			// msvcr100.dll / msvcp140.dll are MSVC; msvcrt.dll is the system CRT
			// that MinGW links against and says nothing about the linker.
			if len(n) > 5 && n[5] >= '0' && n[5] <= '9' {
				return true
			}
		}
	}
	return false
}

func sectionOverlap(p *PE) string {
	type span struct {
		name       string
		start, end uint64
	}
	var spans []span
	for _, s := range p.Sections {
		if s.RawSize == 0 {
			continue
		}
		spans = append(spans, span{strings.TrimSpace(s.Name), uint64(s.RawOffset), uint64(s.RawOffset) + uint64(s.RawSize)})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return fmt.Sprintf("raw data of %s overlaps %s on disk", spans[i].name, spans[i-1].name)
		}
	}
	return ""
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

func slug(s string) string {
	var b strings.Builder
	last := '-'
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			last = r
		default:
			if last != '-' {
				b.WriteRune('-')
				last = '-'
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

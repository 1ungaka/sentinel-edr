package ole

import "strings"

// VBA stomping detection (ATT&CK T1564.007, Hide Artifacts: VBA Stomping).
//
// A module stream is two things back to back ([MS-OVBA] 2.3.4.3): the
// PerformanceCache — the compiled p-code — occupying the first TextOffset
// bytes, then the CompressedSourceCode. Office runs the cached p-code when the
// project was compiled by the same VBA build and only falls back to the source
// otherwise, while most tooling (and a human in the VBA editor of a different
// build) reads the source. A stomped document exploits that gap: the source is
// removed, blanked or swapped for something harmless and the p-code is kept.
//
// What is checked here is ONLY the structural consistency between what the dir
// stream declares and what each module stream holds. Nothing is disassembled,
// compiled or executed, and nothing here can produce such a document.
//
//	source missing   TextOffset is at or past the end of the module stream, or
//	                 no CompressedContainer starts there, yet the stream holds
//	                 a substantial p-code region.
//	source blank     the source decompresses to nothing but "Attribute ..."
//	                 lines and whitespace, yet the p-code region is substantial.
//	mismatch         printable string runs in the p-code region name execution
//	                 or auto-run primitives that occur nowhere in the source.
//	                 A heuristic over string runs — not a disassembly.
//
// Two guards keep a damaged file from reading as a stomped one: a module is
// judged only when its stream resolved to exactly the size the directory
// declares (a truncated download breaks the sector chain and would otherwise
// look like "TextOffset beyond the end"), and only when it was found in the
// same storage as the dir stream that names it.

// Stomping caps.
const (
	maxVBAProjects      = 4        // dir streams analysed per file
	maxModulesReported  = 64       // modules listed per project in Parsed
	stompResolveBudget  = 32 << 20 // stream bytes resolved by this pass per file
	stompSourceBudget   = 16 << 20 // source bytes decompressed by this pass per file
	maxPCodeScan        = 1 << 20  // p-code bytes scanned for string runs per stream
	maxPCodeScanTotal   = 8 << 20  // ... and per file
	minPCodeRun         = 4        // shortest printable run kept
	maxStompEvidenceLen = 64
)

// What "a p-code region" and "a substantial p-code region" mean, in bytes
// before TextOffset (clamped to the stream).
//
// Measured 2026-11-06 with TestMeasureVBAProjects over the 39 compound files on
// the build host; 6 carry a VBA project (written by five different VBA builds,
// _VBA_PROJECT Version 0x5E, 0x6D, 0x85, 0x88, 0x97), 18 modules in all:
//
//	12 modules with an Attribute-only source: p-code 767-917 bytes (median 799)
//	 6 modules with code:                     p-code 845, 955, 1084, 2515, 2712, 4343
//	 0 modules with no source container at TextOffset
//
// Six projects is a small sample and all twelve code-less modules are document
// modules (ThisWorkbook / Sheet / ThisDocument): it holds no empty class module
// and no UserForm. The bounds are set with that in mind.
//
// stompMinPCodeBlank is more than twice the largest code-less p-code region
// seen (917). The price is visible in the same sample: three of the six
// code-bearing modules are under it, so a small stomped module with a blanked
// source is left to the string-run check alone.
//
// stompMinPCodeMissing only has to say "this stream begins with a compiled
// module, not with nothing": every Office-written module seen has a source
// container, so a missing one is anomalous at any size, and the bound sits
// below the smallest p-code region seen (767).
const (
	stompMinPCodeBlank   = 2048
	stompMinPCodeMissing = 512
)

// Source states surfaced per module.
const (
	srcPresent    = "present"
	srcBlank      = "blank"
	srcMissing    = "missing"
	srcNoStream   = "stream-not-found"
	srcAmbiguous  = "stream-ambiguous"
	srcUnresolved = "stream-unresolved"
	srcNoOffset   = "no-text-offset"
	srcNotRead    = "not-analysed"
)

// ModuleInfo is one module of a VBA project as the dir stream declares it and
// as its module stream actually reads.
type ModuleInfo struct {
	Name        string `json:"name"`
	Stream      string `json:"stream,omitempty"`
	Type        string `json:"type,omitempty"` // "procedural" or "document"
	TextOffset  uint32 `json:"text_offset"`
	StreamBytes int    `json:"stream_bytes"`
	PCodeBytes  int    `json:"pcode_bytes"`  // bytes before TextOffset
	SourceBytes int    `json:"source_bytes"` // decompressed source length
	SourceState string `json:"source_state"`
}

// VBAProject is the dir-stream view of one VBA project in the compound file.
type VBAProject struct {
	Storage          string       `json:"storage,omitempty"` // storage holding the dir stream
	CodePage         int          `json:"code_page,omitempty"`
	VersionMajor     uint32       `json:"version_major,omitempty"`
	VersionMinor     uint16       `json:"version_minor,omitempty"`
	PCodeVersion     uint16       `json:"pcode_version,omitempty"` // _VBA_PROJECT header Version
	DeclaredModules  int          `json:"declared_modules"`        // PROJECTMODULES Count, -1 if absent
	ModuleCount      int          `json:"module_count"`            // module records parsed
	Modules          []ModuleInfo `json:"modules,omitempty"`
	ModulesTruncated bool         `json:"modules_truncated,omitempty"`
	Warning          string       `json:"warning,omitempty"`
}

// stompNeedles are matched, lowercased, against the p-code string runs. Each is
// a name an auto-running or process-spawning macro cannot avoid spelling out:
// identifiers survive in the project's identifier table and string literals
// inline in the module's p-code. The auto-exec entry points of the source
// rules are included. Read-only after package initialisation.
var stompNeedles = append([]string{
	"shell", "createobject", "wscript", "urldownloadtofile", "powershell",
	"cmd.exe", "xmlhttp", "winhttp", "adodb.stream",
}, autoExecNeedles...)

// stompState accumulates the three finding classes across every project so
// each fires at most once per document, like the other rule groups.
type stompState struct {
	missing, blank, mismatch            int
	missingEv, blankEv, mismatchEv      string
	resolveBudget, sourceBudget, pcodes int
}

// analyzeVBAProjects parses every dir stream (up to maxVBAProjects), checks
// each declared module against its module stream, and returns the project
// summaries plus the stomping findings.
func analyzeVBAProjects(f *cfbFile) ([]VBAProject, []Finding) {
	st := &stompState{
		resolveBudget: stompResolveBudget,
		sourceBudget:  stompSourceBudget,
		pcodes:        maxPCodeScanTotal,
	}
	var projects []VBAProject
	for i, e := range f.entries {
		if e.objType != objStream || !strings.EqualFold(trimCtrl(e.name), "dir") {
			continue
		}
		if len(projects) >= maxVBAProjects {
			break
		}
		projects = append(projects, analyzeProject(f, i, st))
	}

	var findings []Finding
	if st.missing > 0 {
		findings = append(findings, Finding{
			Class: "ole.vba.stomp.source-missing", Score: weightStompMissing, Technique: techStomping,
			Detail:   "VBA module has compiled p-code but no source at its declared TextOffset" + plural(st.missing),
			Evidence: st.missingEv,
		})
	}
	if st.blank > 0 {
		findings = append(findings, Finding{
			Class: "ole.vba.stomp.source-blank", Score: weightStompBlank, Technique: techStomping,
			Detail:   "VBA module has compiled p-code but an Attribute-only source" + plural(st.blank),
			Evidence: st.blankEv,
		})
	}
	if st.mismatch > 0 {
		findings = append(findings, Finding{
			Class: "ole.vba.stomp.mismatch", Score: weightStompMismatch, Technique: techStomping,
			Detail:   "p-code string runs name a primitive absent from the VBA source (string-run heuristic)" + plural(st.mismatch),
			Evidence: st.mismatchEv,
		})
	}
	return projects, findings
}

func plural(n int) string {
	if n <= 1 {
		return ""
	}
	return " (" + itoa(n) + " occurrences)"
}

// analyzeProject handles the dir stream at f.entries[dirIdx].
func analyzeProject(f *cfbFile, dirIdx int, st *stompState) VBAProject {
	dirEntry := f.entries[dirIdx]
	p := VBAProject{DeclaredModules: -1}
	if dirEntry.parent >= 0 {
		p.Storage = f.entries[dirEntry.parent].name
	}

	raw := f.readEntryBudget(dirEntry, &st.resolveBudget)
	dec, ok := decompressContainer(raw, maxDirDecompressed)
	if !ok {
		p.Warning = "dir stream is not a compressed container"
		return p
	}
	d := parseVBADir(dec)
	p.CodePage = int(d.codePage)
	p.VersionMajor, p.VersionMinor = d.versionMajor, d.versionMinor
	p.DeclaredModules = d.declared
	p.ModuleCount = len(d.modules)
	switch {
	case d.truncated:
		p.Warning = "dir stream ended inside a record or exceeded a parse cap"
	case d.declared >= 0 && d.declared != len(d.modules):
		p.Warning = "PROJECTMODULES count does not match the module records"
	}

	// Streams of this project: the dir stream's siblings when the directory
	// tree reaches it, otherwise every stream in the file (and then a name
	// that matches more than one stream is not attributed to either).
	streams := make(map[string][]int)
	for i, e := range f.entries {
		if e.objType != objStream {
			continue
		}
		if dirEntry.parent >= 0 && e.parent != dirEntry.parent {
			continue
		}
		k := strings.ToLower(trimCtrl(e.name))
		streams[k] = append(streams[k], i)
	}

	var projectStream []byte
	if idx := streams["_vba_project"]; len(idx) == 1 {
		projectStream = f.readEntryBudget(f.entries[idx[0]], &st.resolveBudget)
		if v, ok := vbaProjectVersion(projectStream); ok {
			p.PCodeVersion = v
		}
	}

	var sources []string // lowercased sources of every module read, for the project-wide check
	sourcesComplete := true
	flagged := false // a module of this project raised missing / blank
	flaggedName := ""

	for _, m := range d.modules {
		info := ModuleInfo{Name: m.name, Stream: m.streamName, TextOffset: m.textOffset}
		switch m.moduleType {
		case recModuleTypeProc:
			info.Type = "procedural"
		case recModuleTypeDoc:
			info.Type = "document"
		}

		src, pcode, complete := readModule(f, m, streams, &info, st)
		if !complete {
			sourcesComplete = false
		}
		if src != "" {
			sources = append(sources, src)
		}

		label := moduleLabel(info)
		switch info.SourceState {
		case srcMissing:
			if info.PCodeBytes >= stompMinPCodeMissing {
				st.missing++
				flagged = true
				if st.missingEv == "" {
					st.missingEv = label
					flaggedName = info.Name
				}
			}
		case srcBlank:
			// A document module that hosts form controls declares one member
			// per control, so its p-code grows with no code in the source.
			// That growth was not measured here; such a module is not judged.
			if info.PCodeBytes >= stompMinPCodeBlank && !strings.Contains(src, "attribute vb_control") {
				st.blank++
				flagged = true
				if st.blankEv == "" {
					st.blankEv = label
				}
				if flaggedName == "" {
					flaggedName = info.Name
				}
			}
		}

		// Module-level string runs: literals compiled into THIS module's
		// p-code are compared with THIS module's source.
		if complete && len(pcode) > 0 {
			if hit, ok := runsNotInSource(pcode, []string{src}, st); ok {
				st.mismatch++
				if st.mismatchEv == "" {
					st.mismatchEv = clip(info.Name+" p-code: "+hit, maxStompEvidenceLen)
				}
			}
		}

		if len(p.Modules) < maxModulesReported {
			p.Modules = append(p.Modules, info)
		} else {
			p.ModulesTruncated = true
		}
	}

	// Project-level string runs. _VBA_PROJECT holds the identifier table of
	// the WHOLE project, so its names cannot be attributed to one module and
	// are compared with every module's source together. They are used only to
	// corroborate a module already found without source: on their own, in a
	// project whose sources are all present, a leftover name in that table is
	// not evidence of anything.
	if flagged && sourcesComplete && len(projectStream) > vbaProjectHeaderSize {
		if hit, ok := runsNotInSource(projectStream, sources, st); ok {
			st.mismatch++
			if st.mismatchEv == "" {
				st.mismatchEv = clip("_VBA_PROJECT (source-less module "+flaggedName+"): "+hit, maxStompEvidenceLen)
			}
		}
	}
	return p
}

// readModule locates and splits one module stream. It fills info, and returns
// the lowercased decompressed source, the p-code region, and whether the module
// was read completely enough for the string-run comparison to be meaningful.
func readModule(f *cfbFile, m vbaModule, streams map[string][]int, info *ModuleInfo, st *stompState) (src string, pcode []byte, complete bool) {
	if !m.hasOffset {
		info.SourceState = srcNoOffset
		return "", nil, false
	}
	idx := streams[strings.ToLower(m.streamName)]
	switch {
	case m.streamName == "" || len(idx) == 0:
		info.SourceState = srcNoStream
		return "", nil, false
	case len(idx) > 1:
		info.SourceState = srcAmbiguous
		return "", nil, false
	}
	e := f.entries[idx[0]]
	if st.resolveBudget <= 0 || st.sourceBudget <= 0 {
		info.SourceState = srcNotRead
		return "", nil, false
	}
	raw := f.readEntryBudget(e, &st.resolveBudget)
	info.StreamBytes = len(raw)
	if uint64(len(raw)) != e.size {
		// Truncated chain, size cap or budget: the stream is not what the
		// directory declares, so nothing about its layout can be concluded.
		info.SourceState = srcUnresolved
		return "", nil, false
	}

	off := uint64(m.textOffset)
	if off >= uint64(len(raw)) {
		info.PCodeBytes = len(raw)
		info.SourceState = srcMissing
		return "", raw, true
	}
	pcode = raw[:off]
	info.PCodeBytes = len(pcode)
	container := raw[off:]
	if !isContainerStart(container) {
		info.SourceState = srcMissing
		return "", pcode, true
	}
	limit := st.sourceBudget
	dec, _ := decompressContainer(container, limit)
	st.sourceBudget -= len(dec)
	info.SourceBytes = len(dec)
	complete = len(dec) < limit && len(dec) < maxDecompressed
	if sourceIsBlank(dec) {
		info.SourceState = srcBlank
	} else {
		info.SourceState = srcPresent
	}
	lowerASCII(dec) // dec is this function's own buffer
	return string(dec), pcode, complete
}

// isContainerStart reports whether b begins like a CompressedContainer: the
// 0x01 signature byte and a first chunk header with signature bits 0b011.
func isContainerStart(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x01 && (le16(b, 1)>>12)&0x07 == 0b011
}

// sourceIsBlank reports whether a module source is nothing but "Attribute ..."
// lines and whitespace — which is what an empty module looks like, and also
// what a module looks like after its code has been deleted from the source.
func sourceIsBlank(src []byte) bool {
	const attr = "attribute "
	i := 0
	for i < len(src) {
		// One line: [i, j).
		j := i
		for j < len(src) && src[j] != '\n' && src[j] != '\r' {
			j++
		}
		line := src[i:j]
		for len(line) > 0 && (line[0] == ' ' || line[0] == '\t' || line[0] == 0) {
			line = line[1:]
		}
		blank := true
		for _, c := range line {
			if c != ' ' && c != '\t' && c != 0 {
				blank = false
				break
			}
		}
		if !blank && !(len(line) >= len(attr) && strings.EqualFold(string(line[:len(attr)]), attr)) {
			return false
		}
		i = j + 1
	}
	return true
}

func lowerASCII(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
}

// runsNotInSource extracts the printable runs of region and returns the first
// stompNeedle that occurs in them but in none of the (lowercased) sources.
func runsNotInSource(region []byte, sources []string, st *stompState) (string, bool) {
	if st.pcodes <= 0 {
		return "", false
	}
	if len(region) > maxPCodeScan {
		region = region[:maxPCodeScan]
	}
	if len(region) > st.pcodes {
		region = region[:st.pcodes]
	}
	st.pcodes -= len(region)
	runs := printableRuns(region)
	if runs == "" {
		return "", false
	}
needles:
	for _, n := range stompNeedles {
		at := strings.Index(runs, n)
		if at < 0 {
			continue
		}
		for _, s := range sources {
			if strings.Contains(s, n) {
				continue needles
			}
		}
		// Evidence: the run the needle sits in.
		lo := strings.LastIndexByte(runs[:at], '\n') + 1
		hi := strings.IndexByte(runs[at:], '\n')
		if hi < 0 {
			hi = len(runs)
		} else {
			hi += at
		}
		return clip(runs[lo:hi], 48), true
	}
	return "", false
}

// printableRuns returns the printable ASCII runs and the UTF-16LE runs of
// ASCII characters in b, each at least minPCodeRun characters, lowercased and
// newline-separated. It reads b once per encoding and never writes to it; the
// output is at most about 1.5x len(b).
func printableRuns(b []byte) string {
	var out []byte
	printable := func(c byte) bool { return c >= 0x20 && c <= 0x7E }
	lower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + ('a' - 'A')
		}
		return c
	}

	// ASCII runs.
	start := -1
	for i := 0; i <= len(b); i++ {
		if i < len(b) && printable(b[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minPCodeRun {
			for _, c := range b[start:i] {
				out = append(out, lower(c))
			}
			out = append(out, '\n')
		}
		start = -1
	}

	// UTF-16LE runs: a printable byte followed by 0x00, repeated.
	i := 0
	for i+1 < len(b) {
		if !printable(b[i]) || b[i+1] != 0 {
			i++
			continue
		}
		j := i
		for j+1 < len(b) && printable(b[j]) && b[j+1] == 0 {
			j += 2
		}
		if (j-i)/2 >= minPCodeRun {
			for k := i; k < j; k += 2 {
				out = append(out, lower(b[k]))
			}
			out = append(out, '\n')
		}
		i = j
	}
	return string(out)
}

func moduleLabel(info ModuleInfo) string {
	return clip(info.Name+": TextOffset "+itoa(int(info.TextOffset))+
		", stream "+itoa(info.StreamBytes)+" bytes, p-code "+itoa(info.PCodeBytes)+
		" bytes, source "+itoa(info.SourceBytes)+" bytes", 2*maxStompEvidenceLen)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

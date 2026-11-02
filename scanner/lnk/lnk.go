// Package lnk detects malicious Windows Shell Link (.lnk) files from the
// [MS-SHLLINK] binary format alone — a weaponised shortcut is a common initial-
// access and user-execution vector (ISO/ZIP lures that drop a .lnk whose
// arguments relaunch an interpreter).
//
// It is DETECTION ONLY. Nothing here creates, weaponises or executes a
// shortcut; the signal is derived entirely from the public format and from
// published abuse tradecraft, read out of the bytes a scanner already has.
//
// The parser is defensive by construction: it walks the file through a
// bounds-checked cursor, caps every declared size and the total number of
// ExtraData blocks, never recurses, and returns a partial result with a parse
// warning rather than panicking or hanging on truncated or adversarial input.
// Findings are SUSPICIOUS-tier evidence with small additive weights, chosen so
// that a single benign signal cannot cross the default threshold while a clear
// malicious combination (an interpreter plus an encoded flag, a hidden window,
// or environment-variable obfuscation) does.
package lnk

import (
	"encoding/binary"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ── ATT&CK technique ids ───────────────────────────────────────────────────────

const (
	techUserExec    = "T1204.002" // User Execution: Malicious File
	techInterp      = "T1059"     // Command and Scripting Interpreter
	techPowerShell  = "T1059.001" // ... PowerShell
	techCmd         = "T1059.003" // ... Windows Command Shell
	techScriptHost  = "T1059.005" // ... Visual Basic / Windows Script Host
	techObfuscation = "T1027"     // Obfuscated Files or Information
)

// ── finding weights ────────────────────────────────────────────────────────────
//
// The scale mirrors the sibling encchain detector (DefaultThreshold 8). Weights
// are deliberately small and additive so that no single rule crosses the
// threshold on its own — the shortcut must combine signals the way real malware
// does. Worked examples (all reach or pass 8):
//
//	powershell + encoded flag   = 5 + 4 = 9
//	cmd        + hidden window  = 5 + 3 = 8
//	LOLBin     + env-var + .ext = 5 + 3 + 2 = 10
//
// while a lone benign tell stays below:
//
//	a shortcut that merely points at an .exe     = 2
//	a shortcut that merely launches cmd.exe      = 5
const (
	weightInterp   = 5 // an interpreter / LOLBin referenced in the arguments
	weightEncoded  = 4 // encoded / obfuscated command flags
	weightHidden   = 3 // a hidden-window flag
	weightEnvVar   = 3 // environment-variable obfuscation of a path
	weightLongArgs = 2 // unusually long argument string (padding / obfuscation)
	weightTargetEx = 2 // the delivered target is an executable or script
	weightIconLure = 2 // a document-like icon fronting an interpreter (lure)
	weightTrailing = 3 // large data appended past the parsed structures
)

// DefaultThreshold is the shipped score at which a shortcut is reported
// suspicious. A clear interpreter-plus-obfuscation combination crosses it; a
// single benign structural tell does not.
const DefaultThreshold = 8

// Threshold is the score used when a caller passes none. A variable so it can
// be retuned without a rebuild.
var Threshold = DefaultThreshold

// DefaultMaxSize is the largest file ScanFile reads into memory. A real .lnk is
// a few kilobytes; anything far larger is either not a shortcut or carries an
// appended payload the overlay rule already reasons about.
const DefaultMaxSize int64 = 16 << 20

// Format limits that bound the parser's work regardless of the declared sizes.
const (
	headerSize        = 0x0000004C // ShellLinkHeader, fixed by the format
	maxExtraBlocks    = 64         // ExtraData blocks walked before giving up
	maxBenignTrailing = 1024       // bytes of trailing data tolerated after the terminal block
	longArgsChars     = 400        // argument length treated as suspicious padding
	envBlockSize      = 0x00000314 // ENVIRONMENT_VARIABLE_DATA_BLOCK total size
)

// LinkCLSID is the class identifier every Shell Link carries, little-endian:
// {00021401-0000-0000-C000-000000000046}.
var linkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LinkFlags bits (subset used by the detector).
const (
	flagHasLinkTargetIDList = 0x00000001
	flagHasLinkInfo         = 0x00000002
	flagHasName             = 0x00000004
	flagHasRelativePath     = 0x00000008
	flagHasWorkingDir       = 0x00000010
	flagHasArguments        = 0x00000020
	flagHasIconLocation     = 0x00000040
	flagIsUnicode           = 0x00000080
)

// ExtraData block signatures that carry a filesystem path.
const (
	sigEnvironmentVariable = 0xA0000001
	sigIconEnvironment     = 0xA0000007
)

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

// Finding is one detection signal raised against a shortcut.
type Finding struct {
	// Class is a stable identifier ("lnk.command.powershell").
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	// Evidence is a short, truncated excerpt of the triggering bytes; it never
	// carries a large blob.
	Evidence string `json:"evidence,omitempty"`
}

// Parsed is a compact summary of the shortcut's structure, useful to a caller
// without exposing the full parse tree.
type Parsed struct {
	LinkFlags       uint32   `json:"link_flags"`
	FileAttributes  uint32   `json:"file_attributes,omitempty"`
	ShowCommand     uint32   `json:"show_command,omitempty"`
	IsUnicode       bool     `json:"unicode"`
	HasArguments    bool     `json:"has_arguments"`
	HasTargetIDList bool     `json:"has_target_idlist,omitempty"`
	HasLinkInfo     bool     `json:"has_link_info,omitempty"`
	TargetExt       string   `json:"target_ext,omitempty"`
	ArgsLen         int      `json:"args_len,omitempty"`
	ExtraBlocks     []string `json:"extra_blocks,omitempty"`
	TrailingBytes   int      `json:"trailing_bytes,omitempty"`
	Warning         string   `json:"warning,omitempty"`
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

// IsLNK reports whether the buffer begins with a valid ShellLinkHeader: the
// fixed 0x0000004C HeaderSize and the Shell Link class identifier.
func IsLNK(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	if binary.LittleEndian.Uint32(data[0:4]) != headerSize {
		return false
	}
	for i := 0; i < 16; i++ {
		if data[4+i] != linkCLSID[i] {
			return false
		}
	}
	return true
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// Shell Link gets an immediate zero-score result; otherwise the file is parsed
// defensively and the detection rules are summed into Result.Score.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsLNK(data) {
		return r
	}
	p := parse(data)
	r.Findings = p.detect()
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	r.Parsed = p.summary()
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
		return &Result{FilePath: path, Size: int(min64(fi.Size(), 1<<62)), Threshold: opts.threshold(),
			Skipped: "file over the in-memory size limit"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── parser ─────────────────────────────────────────────────────────────────────

// cursor is a bounds-checked reader over the file. Every accessor refuses to
// read past the end, so the parser can never index out of range.
type cursor struct {
	data []byte
	pos  int
}

func (c *cursor) remaining() int { return len(c.data) - c.pos }

func (c *cursor) u16() (uint16, bool) {
	if c.pos < 0 || c.pos+2 > len(c.data) {
		c.pos = len(c.data)
		return 0, false
	}
	v := binary.LittleEndian.Uint16(c.data[c.pos:])
	c.pos += 2
	return v, true
}

func (c *cursor) u32() (uint32, bool) {
	if c.pos < 0 || c.pos+4 > len(c.data) {
		c.pos = len(c.data)
		return 0, false
	}
	v := binary.LittleEndian.Uint32(c.data[c.pos:])
	c.pos += 4
	return v, true
}

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.data) {
		return nil, false
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b, true
}

func (c *cursor) skip(n int) bool {
	if n < 0 || c.pos+n > len(c.data) {
		return false
	}
	c.pos += n
	return true
}

// parsed holds the fields the detector reasons about. Unexported: callers see
// the Parsed summary instead.
type parsed struct {
	fileSize uint32

	linkFlags      uint32
	fileAttributes uint32
	showCommand    uint32
	iconIndex      uint32
	unicode        bool

	hasTargetIDList bool
	hasLinkInfo     bool

	name         string
	relativePath string
	workingDir   string
	arguments    string
	iconLocation string

	hasEnvBlock bool
	envTarget   string
	hasIconEnv  bool
	iconEnvPath string
	extraSigs   []uint32

	structEnd int  // offset just past the last structure the parser accepted
	trailing  int  // bytes after structEnd
	cleanEnd  bool // true when parsing reached a terminal block / clean end
	warning   string
}

func (p *parsed) warn(msg string) {
	if p.warning == "" {
		p.warning = msg
	}
}

// parse walks a Shell Link. The caller has already confirmed IsLNK, so the
// identity bytes are valid; everything beyond is tolerated and, on a problem,
// recorded in the warning with a partial result returned.
func parse(data []byte) *parsed {
	p := &parsed{}
	c := &cursor{data: data}

	// ShellLinkHeader — fixed 76-byte layout. A file can be truncated inside it
	// (IsLNK only vouches for the first 20 bytes).
	if _, ok := c.u32(); !ok { // HeaderSize (already known to be 0x4C)
		p.warn("truncated header")
		return p
	}
	if !c.skip(16) { // LinkCLSID
		p.warn("truncated header")
		return p
	}
	flags, ok := c.u32()
	if !ok {
		p.warn("truncated header: LinkFlags")
		return p
	}
	p.linkFlags = flags
	p.unicode = flags&flagIsUnicode != 0
	p.hasTargetIDList = flags&flagHasLinkTargetIDList != 0
	p.hasLinkInfo = flags&flagHasLinkInfo != 0

	if fa, ok := c.u32(); ok {
		p.fileAttributes = fa
	} else {
		p.warn("truncated header: FileAttributes")
		return p
	}
	if !c.skip(24) { // CreationTime, AccessTime, WriteTime (3 x FILETIME)
		p.warn("truncated header: timestamps")
		return p
	}
	if fs, ok := c.u32(); ok {
		p.fileSize = fs
	} else {
		p.warn("truncated header: FileSize")
		return p
	}
	if ii, ok := c.u32(); ok {
		p.iconIndex = ii
	} else {
		p.warn("truncated header: IconIndex")
		return p
	}
	if sc, ok := c.u32(); ok {
		p.showCommand = sc
	} else {
		p.warn("truncated header: ShowCommand")
		return p
	}
	if !c.skip(12) { // HotKey (2) + Reserved1 (2) + Reserved2 (4) + Reserved3 (4)
		p.warn("truncated header: reserved fields")
		return p
	}

	// LinkTargetIDList — size-prefixed; skipped bounded. The item IDs are not
	// needed by any rule, and walking attacker-controlled item sizes would be
	// pointless work.
	if p.hasTargetIDList {
		idSize, ok := c.u16()
		if !ok {
			p.warn("truncated IDList size")
			return p
		}
		if !c.skip(int(idSize)) {
			p.warn("IDList runs past the end of the file")
			return p
		}
	}

	// LinkInfo — a self-describing block; skip LinkInfoSize bytes from its start.
	if p.hasLinkInfo {
		start := c.pos
		size, ok := c.u32()
		if !ok {
			p.warn("truncated LinkInfo size")
			return p
		}
		if size < 4 {
			p.warn("LinkInfo declares an impossible size")
			return p
		}
		end := start + int(size)
		if end < start || end > len(data) {
			p.warn("LinkInfo runs past the end of the file")
			return p
		}
		c.pos = end
	}

	// StringData — each section is a CountCharacters-prefixed string, in this
	// fixed order, present only when its LinkFlag is set.
	if flags&flagHasName != 0 {
		if p.name, ok = p.readString(c); !ok {
			p.warn("truncated NAME_STRING")
			return p
		}
	}
	if flags&flagHasRelativePath != 0 {
		if p.relativePath, ok = p.readString(c); !ok {
			p.warn("truncated RELATIVE_PATH")
			return p
		}
	}
	if flags&flagHasWorkingDir != 0 {
		if p.workingDir, ok = p.readString(c); !ok {
			p.warn("truncated WORKING_DIR")
			return p
		}
	}
	if flags&flagHasArguments != 0 {
		if p.arguments, ok = p.readString(c); !ok {
			p.warn("truncated COMMAND_LINE_ARGUMENTS")
			return p
		}
	}
	if flags&flagHasIconLocation != 0 {
		if p.iconLocation, ok = p.readString(c); !ok {
			p.warn("truncated ICON_LOCATION")
			return p
		}
	}

	p.parseExtraData(c)
	return p
}

// readString reads one StringData entry. CountCharacters is capped by its
// 16-bit field, so the byte length is bounded; a truncated string returns
// ok=false and leaves the cursor at end.
func (p *parsed) readString(c *cursor) (string, bool) {
	cc, ok := c.u16()
	if !ok {
		return "", false
	}
	if p.unicode {
		b, ok := c.take(int(cc) * 2)
		if !ok {
			return "", false
		}
		return decodeUTF16LE(b), true
	}
	b, ok := c.take(int(cc))
	if !ok {
		return "", false
	}
	return decodeANSI(b), true
}

// parseExtraData walks the trailing ExtraData blocks. The list ends at a block
// whose size is below 4 (the TerminalBlock). The loop is capped so a stream of
// malformed blocks cannot spin, and every block is bounded against the file.
func (p *parsed) parseExtraData(c *cursor) {
	for i := 0; i < maxExtraBlocks; i++ {
		if c.remaining() < 4 {
			// No room for even a block size: a clean end for a shortcut that
			// omits the explicit terminal block.
			p.cleanEnd = true
			p.structEnd = c.pos
			break
		}
		start := c.pos
		size, _ := c.u32()
		if size < 4 {
			// TerminalBlock: structures end here.
			p.cleanEnd = true
			p.structEnd = c.pos
			break
		}
		sig, ok := c.u32()
		if !ok {
			p.warn("truncated ExtraData signature")
			p.structEnd = c.pos
			break
		}
		if len(p.extraSigs) < maxExtraBlocks {
			p.extraSigs = append(p.extraSigs, sig)
		}
		end := start + int(size)
		if end <= start || end > len(c.data) {
			p.warn("ExtraData block runs past the end of the file")
			p.structEnd = c.pos
			break
		}
		// Known path-bearing blocks: TargetAnsi (MAX_PATH, 260) at +8 and
		// TargetUnicode (520) at +268, both within the declared block.
		switch sig {
		case sigEnvironmentVariable:
			if size >= envBlockSize {
				p.hasEnvBlock = true
				p.envTarget = bestPath(
					fixedCString(c.data, start+8, 260),
					fixedWString(c.data, start+268, 520))
			}
		case sigIconEnvironment:
			if size >= envBlockSize {
				p.hasIconEnv = true
				p.iconEnvPath = bestPath(
					fixedCString(c.data, start+8, 260),
					fixedWString(c.data, start+268, 520))
			}
		}
		c.pos = end
		p.structEnd = c.pos
	}
	if p.structEnd == 0 {
		p.structEnd = c.pos
	}
	p.trailing = len(c.data) - p.structEnd
	if p.trailing < 0 {
		p.trailing = 0
	}
}

// ── detection ──────────────────────────────────────────────────────────────────

// detect runs every rule and returns the findings in a stable order.
func (p *parsed) detect() []Finding {
	var out []Finding
	argsLower := lowerASCII(p.arguments)
	interpreterSeen := false

	// Rule 1 — an interpreter or LOLBin named in the arguments (T1059 family).
	for _, g := range interpreterGroups {
		if hit, ok := matchAny(argsLower, g.needles); ok {
			interpreterSeen = true
			out = append(out, Finding{
				Class: g.class, Score: weightInterp, Technique: g.tech,
				Detail:   g.detail,
				Evidence: truncate(hit, 48),
			})
		}
	}

	// Rule 2 — encoded / obfuscated command flags (T1027).
	if hit, ok := matchAny(argsLower, encodedNeedles); ok {
		out = append(out, Finding{
			Class: "lnk.obfuscation.encoded", Score: weightEncoded, Technique: techObfuscation,
			Detail:   "encoded or obfuscated command flag in the arguments",
			Evidence: truncate(hit, 48),
		})
	}

	// Rule 3 — a hidden-window flag (T1027): run with no visible UI.
	if hit, ok := matchAny(argsLower, hiddenNeedles); ok {
		out = append(out, Finding{
			Class: "lnk.evasion.hidden-window", Score: weightHidden, Technique: techObfuscation,
			Detail:   "arguments hide the window of the launched process",
			Evidence: truncate(hit, 48),
		})
	}

	// Rule 4 — environment-variable obfuscation of a path (T1027), either as a
	// %VAR% token in the arguments/target or an ENVIRONMENT_VARIABLE_DATA_BLOCK
	// whose target resolves to an executable or script.
	envScan := lowerASCII(strings.Join([]string{p.arguments, p.relativePath, p.envTarget, p.workingDir}, " "))
	envHit, envOK := matchAny(envScan, envVarNeedles)
	envEvidence := envHit
	if !envOK && p.hasEnvBlock && isExecutableExt(extOf(p.envTarget)) {
		envOK = true
		envEvidence = "ENVIRONMENT_VARIABLE_DATA_BLOCK -> " + truncate(p.envTarget, 40)
	}
	if envOK {
		out = append(out, Finding{
			Class: "lnk.obfuscation.env-var", Score: weightEnvVar, Technique: techObfuscation,
			Detail:   "environment-variable obfuscation of the launched path",
			Evidence: truncate(envEvidence, 60),
		})
	}

	// Rule 5 — unusually long arguments (T1027): padding / inline obfuscation.
	if n := utf8.RuneCountInString(p.arguments); n > longArgsChars {
		out = append(out, Finding{
			Class: "lnk.args.long", Score: weightLongArgs, Technique: techObfuscation,
			Detail:   "command-line arguments are unusually long",
			Evidence: itoa(n) + " characters",
		})
	}

	// Rule 6 — the delivered target is an executable or script (T1204.002).
	targetExt := p.targetExt()
	if isExecutableExt(targetExt) {
		out = append(out, Finding{
			Class: "lnk.target.executable", Score: weightTargetEx, Technique: techUserExec,
			Detail:   "the shortcut target is an executable or script",
			Evidence: targetExt,
		})
	}

	// Rule 7 — icon/target mismatch lure (T1204.002). Conservative: only when an
	// interpreter is already in play does a document-flavoured icon read as a
	// disguise rather than an ordinary shortcut.
	if interpreterSeen {
		if hit, ok := matchAny(lowerASCII(p.iconLocation), documentIconNeedles); ok {
			out = append(out, Finding{
				Class: "lnk.lure.icon-mismatch", Score: weightIconLure, Technique: techUserExec,
				Detail:   "a document-like icon fronts an interpreter invocation",
				Evidence: truncate(hit, 48),
			})
		}
	}

	// Rule 8 — large data appended past the parsed structures (T1027): a
	// shortcut-smuggled payload. Only when the parse reached a clean end, to
	// avoid blaming truncation for the gap.
	if p.cleanEnd && p.trailing > maxBenignTrailing {
		out = append(out, Finding{
			Class: "lnk.overlay.trailing", Score: weightTrailing, Technique: techObfuscation,
			Detail:   "large data appended after the shortcut structures",
			Evidence: itoa(p.trailing) + " trailing bytes",
		})
	}

	return out
}

// summary builds the compact Parsed view returned to callers.
func (p *parsed) summary() *Parsed {
	s := &Parsed{
		LinkFlags:       p.linkFlags,
		FileAttributes:  p.fileAttributes,
		ShowCommand:     p.showCommand,
		IsUnicode:       p.unicode,
		HasArguments:    p.arguments != "",
		HasTargetIDList: p.hasTargetIDList,
		HasLinkInfo:     p.hasLinkInfo,
		TargetExt:       p.targetExt(),
		ArgsLen:         utf8.RuneCountInString(p.arguments),
		Warning:         p.warning,
	}
	if p.cleanEnd && p.trailing > 0 {
		s.TrailingBytes = p.trailing
	}
	for _, sig := range p.extraSigs {
		s.ExtraBlocks = append(s.ExtraBlocks, "0x"+hex32(sig))
	}
	return s
}

// targetExt returns the lowercased extension (with dot) of the shortcut's
// target, preferring the relative path and falling back to the env-block path.
func (p *parsed) targetExt() string {
	if ext := extOf(p.relativePath); ext != "" {
		return ext
	}
	if ext := extOf(p.envTarget); ext != "" {
		return ext
	}
	return ""
}

// ── rule tables ────────────────────────────────────────────────────────────────

type interpreterGroup struct {
	needles []string
	class   string
	tech    string
	detail  string
}

// interpreterGroups maps the scripting interpreters and proxy-execution LOLBins
// to their finding class and the most specific ATT&CK sub-technique. Needles
// are matched case-insensitively against the argument string; each group is
// specific enough (".exe", " /c", distinctive names) to avoid matching ordinary
// path fragments.
var interpreterGroups = []interpreterGroup{
	{[]string{"powershell", "pwsh"}, "lnk.command.powershell", techPowerShell,
		"arguments invoke PowerShell"},
	{[]string{"cmd.exe", "cmd /c", "cmd /k", "cmd /r", "cmd/c"}, "lnk.command.cmd", techCmd,
		"arguments invoke the Windows command shell"},
	{[]string{"wscript", "cscript"}, "lnk.command.wscript", techScriptHost,
		"arguments invoke the Windows Script Host"},
	{[]string{"mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "installutil", "forfiles"},
		"lnk.command.lolbin", techInterp,
		"arguments invoke a living-off-the-land binary"},
}

// encodedNeedles are flags and primitives of encoded / obfuscated command
// execution (chiefly PowerShell).
var encodedNeedles = []string{
	"-enc", "-encodedcommand", "-e ", "-ec ",
	"frombase64string", "iex", "invoke-expression",
	"downloadstring", "downloadfile",
	"-nop", "-noprofile", "-noni", "-noninteractive",
	"-ep bypass", "-executionpolicy bypass", "executionpolicy bypass",
}

// hiddenNeedles are the ways arguments ask for a hidden window.
var hiddenNeedles = []string{
	"-w hidden", "-windowstyle hidden", "windowstyle hidden", "-wstyle hidden", "/min",
}

// envVarNeedles are environment variables commonly used to obfuscate a path.
var envVarNeedles = []string{
	"%comspec%", "%systemroot%", "%appdata%", "%localappdata%",
	"%temp%", "%tmp%", "%windir%", "%programdata%", "%userprofile%", "%public%",
}

// documentIconNeedles mark icon sources that masquerade as a document, used by
// the conservative icon-mismatch lure rule.
var documentIconNeedles = []string{
	"imageres.dll", "shell32.dll", "mshtml.dll", "wordpad", "winword", "acrord", ".ico",
}

// executableExts are target extensions that make a shortcut a delivery vector.
var executableExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".bat": true, ".cmd": true,
	".ps1": true, ".vbs": true, ".js": true, ".jse": true, ".wsf": true,
	".hta": true, ".pif": true,
}

func isExecutableExt(ext string) bool { return executableExts[ext] }

// ── small helpers ──────────────────────────────────────────────────────────────

// decodeUTF16LE decodes little-endian UTF-16 bytes, stopping at a NUL unit and
// ignoring a trailing odd byte.
func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		c := uint16(b[2*i]) | uint16(b[2*i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// decodeANSI treats a byte string as text, stopping at a NUL. High bytes are
// kept verbatim; the detector only needs ASCII tokens out of it.
func decodeANSI(b []byte) string {
	if i := indexZero(b); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// fixedCString reads a NUL-terminated ANSI string from a fixed-width field.
func fixedCString(data []byte, off, max int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off + max
	if end > len(data) {
		end = len(data)
	}
	return decodeANSI(data[off:end])
}

// fixedWString reads a NUL-terminated UTF-16LE string from a fixed-width field.
func fixedWString(data []byte, off, max int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off + max
	if end > len(data) {
		end = len(data)
	}
	return decodeUTF16LE(data[off:end])
}

// bestPath picks the richer of the ANSI and Unicode target paths.
func bestPath(ansi, uni string) string {
	if len(uni) >= len(ansi) {
		return uni
	}
	return ansi
}

func indexZero(b []byte) int {
	for i := range b {
		if b[i] == 0 {
			return i
		}
	}
	return -1
}

func lowerASCII(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// matchAny returns the first needle found in hay (which must already be
// lowercased).
func matchAny(hay string, needles []string) (string, bool) {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return n, true
		}
	}
	return "", false
}

// extOf returns the lowercased extension (with dot) of a path-like string, or
// "" when there is none.
func extOf(path string) string {
	p := strings.TrimSpace(path)
	p = strings.Trim(p, "\"")
	if i := strings.LastIndexAny(p, "\\/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndex(p, "."); i >= 0 {
		ext := lowerASCII(p[i:])
		if !strings.ContainsAny(ext, " \t") {
			return ext
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

func hex32(v uint32) string {
	const digits = "0123456789abcdef"
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[7-i] = digits[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
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

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Package uefi parses a UEFI firmware image — its Firmware Volumes (FV) and the
// FFS files and sections inside them — and reports a module inventory, the FV
// header integrity, and any module whose GUID is on an operator-supplied
// implant blocklist.
//
// This is the Phase-8 firmware wedge, and it is honest about its boundary:
// meaningful malicious-firmware detection needs an implant truth set (known
// bad module GUIDs / signatures), which this package does NOT ship — firmware
// is overwhelmingly legitimate PEI/DXE/SMM drivers, so scoring module shapes
// would be a false-positive machine. What it ships is the structural parse, a
// genuine tamper signal (an FV header whose checksum does not validate), and
// the same operator-loadable blocklist mechanism the signer and fuzzy
// databases use (empty by default). Everything else is inventory.
package uefi

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Parsing and safety limits.
const (
	DefaultMaxSize int64 = 64 << 20
	maxFVs               = 256
	maxFFSFiles          = 1 << 16
	maxSections          = 4096
	maxScan              = 64 << 20
)

// fvSignature is "_FVH" at offset 0x28 of an EFI_FIRMWARE_VOLUME_HEADER.
const fvSignature = 0x4856465F

// intelFlashMagic (0x0FF0A55A) at offset 0x10 marks an Intel flash descriptor,
// the common outer wrapper of a full SPI image.
const intelFlashMagic = 0x0FF0A55A

// FFS file types worth naming.
var ffsTypeNames = map[uint8]string{
	0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE",
	0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER", 0x08: "COMBINED_PEIM_DRIVER",
	0x09: "APPLICATION", 0x0A: "SMM", 0x0B: "FIRMWARE_VOLUME_IMAGE",
	0x0C: "COMBINED_SMM_DXE", 0x0D: "SMM_CORE", 0xF0: "PAD",
}

// Scoring (threshold 8; conservative — only two genuinely defensible signals).
const (
	scoreChecksum = 3
	scoreImplant  = 8
)

const (
	techPreOSBoot = "T1542.001" // System Firmware (pre-OS boot implant)
)

// DefaultThreshold is the shipped score at which an image is reported suspicious.
const DefaultThreshold = 8

// Threshold is used when a caller passes none.
var Threshold = DefaultThreshold

// Options tunes an analysis.
type Options struct {
	Threshold int
	MaxSize   int64
	// ImplantGUIDs is the operator-loaded blocklist of known bad module GUIDs
	// (lower-cased, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"). Empty = none.
	ImplantGUIDs map[string]string
}

func (o Options) threshold() int {
	if o.Threshold > 0 {
		return o.Threshold
	}
	return Threshold
}

// Finding is one labeled firmware observation.
type Finding struct {
	Class     string `json:"class"`
	Score     int    `json:"score"`
	Technique string `json:"technique,omitempty"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// Module is one FFS file in the inventory.
type Module struct {
	GUID  string `json:"guid"`
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"` // UI name section, when present
	Size  int    `json:"size"`
	HasPE bool   `json:"has_pe,omitempty"` // carries a PE32/TE executable section
}

// Summary is the enumerated shape of the image, for the report.
type Summary struct {
	Volumes       int      `json:"volumes"`
	Modules       int      `json:"modules"`
	IntelFlash    bool     `json:"intel_flash,omitempty"`
	ChecksumValid bool     `json:"fv_checksum_valid"`
	Inventory     []Module `json:"inventory,omitempty"`
	NotInspected  string   `json:"not_inspected,omitempty"`
}

// Result is the analysis of one firmware image.
type Result struct {
	FilePath  string    `json:"path,omitempty"`
	Size      int       `json:"size"`
	Findings  []Finding `json:"findings,omitempty"`
	Score     int       `json:"score"`
	Threshold int       `json:"threshold"`
	Parsed    *Summary  `json:"parsed,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
	Error     error     `json:"-"`
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
	return r != nil && r.Error == nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// HasObservation reports whether any finding fired below the threshold.
func (r *Result) HasObservation() bool { return r != nil && len(r.Findings) > 0 }

// IsFirmware reports whether the buffer looks like a UEFI firmware image: an FV
// header (signature "_FVH" at 0x28), or an Intel flash descriptor whose first
// region wraps one.
func IsFirmware(data []byte) bool {
	if len(data) >= 0x2c && le32(data, 0x28) == fvSignature {
		return true
	}
	if len(data) >= 0x14 && le32(data, 0x10) == intelFlashMagic {
		return true
	}
	// A carved image may have padding before the first FV; scan a bounded head.
	return findFV(data, 0) >= 0
}

// findFV returns the offset of the next FV header at or after `from`, or -1.
// It matches the "_FVH" signature at the +0x28 position.
func findFV(data []byte, from int) int {
	limit := len(data)
	if limit > maxScan {
		limit = maxScan
	}
	for off := from; off+0x2c <= limit; off += 8 { // FVs are 8-byte aligned
		if le32(data, off+0x28) == fvSignature {
			return off
		}
	}
	return -1
}

// Analyze inspects data and returns a non-nil Result. A buffer that is not a
// firmware image gets an immediate zero-score result.
func Analyze(data []byte, opts Options) *Result {
	r := &Result{Size: len(data), Threshold: opts.threshold()}
	if !IsFirmware(data) {
		return r
	}
	s := &Summary{ChecksumValid: true}
	if len(data) >= 0x14 && le32(data, 0x10) == intelFlashMagic {
		s.IntelFlash = true
	}
	var checksumBad []string
	off := findFV(data, 0)
	for off >= 0 && s.Volumes < maxFVs {
		fvLen, ok := parseFV(data, off, s, opts, &checksumBad)
		s.Volumes++
		next := off + 8
		if ok && fvLen >= 8 {
			next = off + int(fvLen)
		}
		if next <= off {
			next = off + 8
		}
		off = findFV(data, next)
	}
	s.Modules = len(s.Inventory)
	s.NotInspected = "module bodies (PE/TE drivers) are inventoried, not disassembled; GUIDed/compressed sections are not decompressed"
	r.Parsed = s

	add := func(class string, score int, tech, detail, evidence string) {
		r.Findings = append(r.Findings, Finding{Class: class, Score: score, Technique: tech, Detail: detail, Evidence: evidence})
	}
	if len(checksumBad) > 0 {
		s.ChecksumValid = false
		add("uefi.volume-checksum-invalid", scoreChecksum, techPreOSBoot,
			fmt.Sprintf("%d firmware volume header(s) fail their 16-bit checksum: a hand-built or tampered volume", len(checksumBad)), checksumBad[0])
	}
	// Operator implant blocklist.
	if len(opts.ImplantGUIDs) > 0 {
		var hits []string
		for _, m := range s.Inventory {
			if name, bad := opts.ImplantGUIDs[strings.ToLower(m.GUID)]; bad {
				label := m.GUID
				if name != "" {
					label += " (" + name + ")"
				}
				hits = append(hits, label)
			}
		}
		if len(hits) > 0 {
			add("uefi.known-implant-guid", scoreImplant, techPreOSBoot,
				fmt.Sprintf("%d module GUID(s) match the operator implant blocklist", len(hits)), hits[0])
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Class < r.Findings[j].Class })
	for _, f := range r.Findings {
		r.Score += f.Score
	}
	return r
}

// ScanFile reads a file (subject to the size cap) and analyses it.
func ScanFile(path string, opts Options) *Result {
	max := opts.MaxSize
	if max <= 0 {
		max = DefaultMaxSize
	}
	fi, err := os.Stat(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "stat: " + err.Error()}
	}
	if fi.Size() > max {
		return &Result{FilePath: path, Threshold: opts.threshold(), Size: int(fi.Size()), Skipped: "file over the in-memory size limit"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Result{FilePath: path, Threshold: opts.threshold(), Skipped: "read: " + err.Error()}
	}
	r := Analyze(data, opts)
	r.FilePath = path
	return r
}

// ── FV / FFS walk ──────────────────────────────────────────────────────────

// parseFV parses one firmware volume at off, appends its modules to the
// summary, and records a checksum failure. It returns the volume length and
// whether the header parsed.
func parseFV(data []byte, off int, s *Summary, opts Options, checksumBad *[]string) (uint64, bool) {
	if off+0x38 > len(data) {
		return 0, false
	}
	fvLen := le64(data, off+0x20)
	hdrLen := int(le16(data, off+0x30))
	if hdrLen < 0x38 || off+hdrLen > len(data) {
		return fvLen, false
	}
	// 16-bit checksum: the sum of the header as little-endian u16 words is 0.
	var sum uint16
	for p := off; p+2 <= off+hdrLen; p += 2 {
		sum += le16(data, p)
	}
	if sum != 0 {
		guid := formatGUID(data[off+0x10 : off+0x20])
		*checksumBad = append(*checksumBad, fmt.Sprintf("FV at 0x%x (fs %s)", off, guid))
	}
	// Files begin after the header (ext header, if any, is also after hdrLen in
	// practice we start at the header end), 8-byte aligned.
	fileStart := align8(off + hdrLen)
	fvEnd := off + int(fvLen)
	if fvLen == 0 || fvEnd > len(data) || fvEnd < off {
		fvEnd = len(data)
	}
	p := fileStart
	for p+24 <= fvEnd && len(s.Inventory) < maxFFSFiles {
		size := int(data[p+0x14]) | int(data[p+0x15])<<8 | int(data[p+0x16])<<16
		state := data[p+0x17]
		// An erased/free region: Name and most fields are 0xFF. Stop the walk.
		if size < 24 || allFF(data[p:p+16]) {
			break
		}
		if p+size > fvEnd {
			break
		}
		typ := data[p+0x12]
		m := Module{
			GUID: formatGUID(data[p : p+16]),
			Type: ffsTypeName(typ),
			Size: size,
		}
		_ = state
		m.Name, m.HasPE = walkSections(data, p+24, p+size)
		if typ != 0xF0 { // skip pad files in the inventory
			s.Inventory = append(s.Inventory, m)
		}
		p = align8(p + size)
	}
	return fvLen, true
}

// walkSections scans an FFS file's sections for the UI name and a PE32/TE
// executable section.
func walkSections(data []byte, start, end int) (name string, hasPE bool) {
	p := start
	for n := 0; n < maxSections && p+4 <= end; n++ {
		size := int(data[p]) | int(data[p+1])<<8 | int(data[p+2])<<16
		typ := data[p+3]
		if size < 4 || p+size > end {
			break
		}
		switch typ {
		case 0x10, 0x12: // PE32, TE
			hasPE = true
		case 0x15: // USER_INTERFACE: UCS-2 name
			name = ucs2(data[p+4 : p+size])
		}
		p = align4(p + size)
	}
	return name, hasPE
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ffsTypeName(t uint8) string {
	if n, ok := ffsTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("type-0x%02x", t)
}

// formatGUID renders a 16-byte EFI_GUID in the canonical mixed-endian form.
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		le32(b, 0), le16(b, 4), le16(b, 6),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// ucs2 decodes a NUL-terminated little-endian UCS-2 string to printable ASCII.
func ucs2(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := le16(b, i)
		if c == 0 {
			break
		}
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(byte(c))
		} else {
			sb.WriteByte('?')
		}
		if sb.Len() > 256 {
			break
		}
	}
	return sb.String()
}

func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xFF {
			return false
		}
	}
	return true
}

func align4(n int) int { return (n + 3) &^ 3 }
func align8(n int) int { return (n + 7) &^ 7 }

func le16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func le32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func le64(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

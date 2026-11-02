package static

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Mach-O parsing limits. Each is generous for real software and bounds the
// work a hostile header can direct, exactly as the ELF and PE passes do.
const (
	maxMachOArches    = 32
	maxMachOCmds      = 1 << 12
	maxMachOSegments  = 256
	maxMachOSections  = 1 << 16
	maxMachODylibs    = 512
	maxMachORPaths    = 64
	maxMachOSyms      = 1 << 18
	maxMachONamesKept = 8192
)

// Mach-O magics. The CIGAM forms are the byte-swapped (opposite-endian) magic.
const (
	mhMagic32  = 0xfeedface
	mhCigam32  = 0xcefaedfe
	mhMagic64  = 0xfeedfacf
	mhCigam64  = 0xcffaedfe
	fatMagic   = 0xcafebabe
	fatCigam   = 0xbebafeca
	fatMagic64 = 0xcafebabf
	fatCigam64 = 0xbfbafeca
)

// Load-command ids. LC_REQ_DYLD marks commands the loader must understand.
const (
	lcReqDyld          = 0x80000000
	lcSegment          = 0x1
	lcSymtab           = 0x2
	lcUnixThread       = 0x5
	lcDysymtab         = 0xb
	lcLoadDylib        = 0xc
	lcIDDylib          = 0xd
	lcLoadDylinker     = 0xe
	lcSegment64        = 0x19
	lcCodeSignature    = 0x1d
	lcEncryptionInfo   = 0x21
	lcDyldInfo         = 0x22
	lcDyldInfoOnly     = 0x80000022
	lcLoadWeakDylib    = 0x80000018
	lcRpath            = 0x8000001c
	lcReexportDylib    = 0x8000001f
	lcLoadUpwardDylib  = 0x80000023
	lcMain             = 0x80000028
	lcEncryptionInfo64 = 0x2c
)

// File types.
const (
	mhObject     = 1
	mhExecute    = 2
	mhCore       = 4
	mhPreload    = 5
	mhDylib      = 6
	mhDylinker   = 7
	mhBundle     = 8
	mhDsym       = 10
	mhKextBundle = 11
)

// Header flags worth naming.
const (
	mhPIE                 = 0x200000
	mhAllowStackExecution = 0x20000
	mhNoHeapExecution     = 0x1000000
	mhRootSafe            = 0x40000
	mhTwoLevel            = 0x80
)

// VM protections and the executable section-attribute bits.
const (
	vmProtRead  = 1
	vmProtWrite = 2
	vmProtExec  = 4

	sAttrPureInstructions = 0x80000000
	sAttrSomeInstructions = 0x00000400
	cpuArchABI64          = 0x01000000

	nTypeMask = 0x0e // N_TYPE
	nStab     = 0xe0
	nUndf     = 0x0
	nSect     = 0xe
	nExt      = 0x01
)

// MachODylib is one linked library (the Mach-O analogue of DT_NEEDED).
type MachODylib struct {
	Name     string `json:"name"`
	Weak     bool   `json:"weak,omitempty"`
	ReExport bool   `json:"reexport,omitempty"`
}

// MachOSection is one section inside a segment.
type MachOSection struct {
	Seg     string  `json:"segment"`
	Name    string  `json:"name"`
	Addr    uint64  `json:"addr"`
	Size    uint64  `json:"size"`
	Offset  uint32  `json:"offset"`
	Flags   uint32  `json:"flags"`
	Entropy float64 `json:"entropy,omitempty"`
}

// Instructions reports whether the section is marked as holding code.
func (s MachOSection) Instructions() bool {
	return s.Flags&sAttrPureInstructions != 0 || s.Flags&sAttrSomeInstructions != 0
}

// MachOSegment is one LC_SEGMENT(_64) plus what the parser derived.
type MachOSegment struct {
	Name      string         `json:"name"`
	VMAddr    uint64         `json:"vmaddr"`
	VMSize    uint64         `json:"vmsize"`
	FileOff   uint64         `json:"fileoff"`
	FileSize  uint64         `json:"filesize"`
	MaxProt   uint32         `json:"maxprot"`
	InitProt  uint32         `json:"initprot"`
	Perms     string         `json:"perms"`
	Entropy   float64        `json:"entropy,omitempty"`
	Sections  []MachOSection `json:"sections,omitempty"`
	Truncated bool           `json:"truncated,omitempty"`
}

func (s MachOSegment) Executable() bool {
	return s.InitProt&vmProtExec != 0 || s.MaxProt&vmProtExec != 0
}
func (s MachOSegment) Writable() bool { return s.InitProt&vmProtWrite != 0 }

// MachOImage is one architecture slice: a complete thin Mach-O.
type MachOImage struct {
	CPUType     string   `json:"cpu"`
	CPUSubtype  uint32   `json:"cpu_subtype"`
	FileType    string   `json:"filetype"`
	FileTypeNum uint32   `json:"filetype_num"`
	Flags       uint32   `json:"flags"`
	FlagNames   []string `json:"flag_names,omitempty"`
	NCmds       int      `json:"ncmds"`
	Is64        bool     `json:"is64"`

	Segments []MachOSegment `json:"segments,omitempty"`
	Dylibs   []MachODylib   `json:"dylibs,omitempty"`
	RPaths   []string       `json:"rpaths,omitempty"`

	// Imports are the undefined external symbols; Exports the defined ones.
	// ImportHash is MD5 over the sorted, lower-cased dylib basenames: a CAU
	// clustering key in the spirit of imphash, over libraries rather than
	// functions (Mach-O imports bind by two-level namespace, lib + symbol).
	Imports     []string `json:"imports,omitempty"`
	ImportCount int      `json:"import_count"`
	ExportCount int      `json:"export_count"`
	ImportHash  string   `json:"import_hash,omitempty"`

	// Entry resolution. EntrySegment is the index of the segment mapping the
	// entry point (-1 when none does); EntryExecutable records its protection.
	HasMain         bool   `json:"has_main"`
	HasUnixThread   bool   `json:"has_unixthread"`
	Entry           uint64 `json:"entry,omitempty"`
	EntrySegment    int    `json:"entry_segment"`
	EntryExecutable bool   `json:"entry_executable"`

	// Signed is set when LC_CODE_SIGNATURE is present; nothing is verified (a
	// file scanner cannot reach the trust store, and the report says so).
	Signed        bool `json:"signed"`
	SignatureSize int  `json:"signature_size,omitempty"`
	// Encrypted is set when an LC_ENCRYPTION_INFO command has a non-zero
	// cryptid (FairPlay on App Store binaries, or a protector elsewhere).
	Encrypted bool   `json:"encrypted,omitempty"`
	CryptID   uint32 `json:"crypt_id,omitempty"`

	Offset uint64 `json:"offset,omitempty"` // file offset of this slice (fat)
	Size   uint64 `json:"size,omitempty"`

	order binary.ByteOrder
	base  uint64 // file offset the image starts at
}

// MachO is the parsed structure of a Mach-O file (thin or universal).
type MachO struct {
	Magic     string `json:"magic"` // "mach32","mach64","fat","fat64"
	ByteOrder string `json:"byte_order"`
	Fat       bool   `json:"fat"`
	// Arches holds one image per architecture; a thin file has exactly one.
	Arches   []*MachOImage `json:"arches"`
	Overlay  Overlay       `json:"overlay"`
	Packer   *Packer       `json:"packer,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

func (m *MachO) warn(format string, a ...interface{}) {
	if len(m.Warnings) < 32 {
		m.Warnings = append(m.Warnings, fmt.Sprintf(format, a...))
	}
}

// IsMachO reports whether the buffer begins with a Mach-O or universal magic.
func IsMachO(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	switch be32(data) {
	case mhMagic32, mhCigam32, mhMagic64, mhCigam64, fatMagic, fatCigam, fatMagic64, fatCigam64:
		return true
	}
	return false
}

func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// ParseMachO parses a Mach-O image. It returns an error only when the magic is
// unusable; later inconsistencies are tolerated and recorded in Warnings.
func ParseMachO(data []byte) (*MachO, error) {
	if !IsMachO(data) {
		return nil, fmt.Errorf("not a Mach-O image")
	}
	m := &MachO{}
	switch be32(data) {
	case fatMagic, fatCigam, fatMagic64, fatCigam64:
		m.Fat = true
		m.ByteOrder = "big" // the fat header is always big-endian
		is64 := be32(data) == fatMagic64 || be32(data) == fatCigam64
		if is64 {
			m.Magic = "fat64"
		} else {
			m.Magic = "fat"
		}
		m.parseFat(data, is64)
	default:
		img := parseThin(data, 0, uint64(len(data)), m)
		if img == nil {
			return nil, fmt.Errorf("Mach-O header could not be parsed")
		}
		m.Magic = map[bool]string{true: "mach64", false: "mach32"}[img.Is64]
		m.ByteOrder = orderName(img.order)
		m.Arches = []*MachOImage{img}
	}
	if len(m.Arches) == 0 {
		return nil, fmt.Errorf("no Mach-O architecture could be parsed")
	}
	m.computeOverlay(data)
	m.Packer = identifyMachOPacker(m, data)
	return m, nil
}

func orderName(o binary.ByteOrder) string {
	if o == binary.BigEndian {
		return "big"
	}
	return "little"
}

// parseFat reads the universal-binary table and parses each slice.
func (m *MachO) parseFat(data []byte, is64 bool) {
	if len(data) < 8 {
		return
	}
	n := int(be32(data[4:]))
	if n > maxMachOArches {
		m.warn("fat binary declares %d architectures; reading the first %d", n, maxMachOArches)
		n = maxMachOArches
	}
	entrySize := 20
	if is64 {
		entrySize = 32
	}
	for i := 0; i < n; i++ {
		p := 8 + i*entrySize
		if p+entrySize > len(data) {
			m.warn("fat architecture table runs past the end of the file")
			break
		}
		var off, size uint64
		if is64 {
			off = binary.BigEndian.Uint64(data[p+8:])
			size = binary.BigEndian.Uint64(data[p+16:])
		} else {
			off = uint64(be32(data[p+8:]))
			size = uint64(be32(data[p+12:]))
		}
		if off >= uint64(len(data)) || off+size > uint64(len(data)) || size < 8 {
			m.warn("fat slice %d at 0x%x (+%d) lies outside the file", i, off, size)
			continue
		}
		if img := parseThin(data, off, size, m); img != nil {
			m.Arches = append(m.Arches, img)
		}
	}
}

// parseThin parses one thin Mach-O that starts at base and spans size bytes of
// the underlying buffer.
func parseThin(data []byte, base, size uint64, m *MachO) *MachOImage {
	if base+28 > uint64(len(data)) {
		return nil
	}
	hdr := data[base:]
	// The magic is read in the reader's native order: MH_MAGIC means the file
	// matches it (little-endian here), MH_CIGAM means the opposite (big-endian).
	// Reading big-endian would misclassify every little-endian image.
	magic := binary.LittleEndian.Uint32(hdr)
	img := &MachOImage{EntrySegment: -1, Offset: base, Size: size, base: base}
	switch magic {
	case mhMagic32:
		img.order, img.Is64 = binary.LittleEndian, false
	case mhCigam32:
		img.order, img.Is64 = binary.BigEndian, false
	case mhMagic64:
		img.order, img.Is64 = binary.LittleEndian, true
	case mhCigam64:
		img.order, img.Is64 = binary.BigEndian, true
	default:
		return nil
	}
	r := img.order
	img.CPUType = cpuTypeName(r.Uint32(hdr[4:]))
	img.CPUSubtype = r.Uint32(hdr[8:])
	img.FileTypeNum = r.Uint32(hdr[12:])
	img.FileType = machoFileType(img.FileTypeNum)
	img.NCmds = int(r.Uint32(hdr[16:]))
	img.Flags = r.Uint32(hdr[24:])
	img.FlagNames = machoFlagNames(img.Flags)

	hdrLen := uint64(28)
	if img.Is64 {
		hdrLen = 32
	}
	img.parseLoadCommands(data, base, size, hdrLen)
	img.locateEntry()
	img.ImportHash = dylibSetHash(img.Dylibs)
	return img
}

// parseLoadCommands walks the load-command stream.
func (img *MachOImage) parseLoadCommands(data []byte, base, size, hdrLen uint64) {
	r := img.order
	ncmds := img.NCmds
	if ncmds > maxMachOCmds {
		ncmds = maxMachOCmds
	}
	end := base + size
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	p := base + hdrLen
	seenImp := map[string]bool{}
	for i := 0; i < ncmds; i++ {
		if p+8 > end {
			return
		}
		cmd := r.Uint32(data[p:])
		cmdsize := uint64(r.Uint32(data[p+4:]))
		if cmdsize < 8 || p+cmdsize > end {
			return
		}
		b := data[p : p+cmdsize]
		switch cmd {
		case lcSegment, lcSegment64:
			img.parseSegment(data, base, b, cmd == lcSegment64)
		case lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib:
			if name := lcString(r, b, 8); name != "" && len(img.Dylibs) < maxMachODylibs {
				img.Dylibs = append(img.Dylibs, MachODylib{
					Name:     name,
					Weak:     cmd == lcLoadWeakDylib,
					ReExport: cmd == lcReexportDylib,
				})
			}
		case lcRpath:
			if path := lcString(r, b, 8); path != "" && len(img.RPaths) < maxMachORPaths {
				img.RPaths = append(img.RPaths, path)
			}
		case lcMain:
			if len(b) >= 16 {
				img.HasMain = true
				img.Entry = r.Uint64(b[8:]) // entryoff: a file offset
			}
		case lcUnixThread:
			img.HasUnixThread = true
			img.Entry = img.threadEntry(b)
		case lcCodeSignature:
			if len(b) >= 16 {
				img.Signed = true
				img.SignatureSize = int(r.Uint32(b[12:]))
			}
		case lcEncryptionInfo, lcEncryptionInfo64:
			if len(b) >= 20 {
				img.CryptID = r.Uint32(b[16:])
				img.Encrypted = img.CryptID != 0
			}
		case lcSymtab:
			img.parseSymtab(data, base, b, seenImp)
		}
		p += cmdsize
	}
}

// parseSegment reads one segment command and its sections.
func (img *MachOImage) parseSegment(data []byte, base uint64, b []byte, is64 bool) {
	r := img.order
	var s MachOSegment
	if is64 {
		if len(b) < 72 {
			return
		}
		s.Name = cstringFixed(b[8:24])
		s.VMAddr = r.Uint64(b[24:])
		s.VMSize = r.Uint64(b[32:])
		s.FileOff = r.Uint64(b[40:])
		s.FileSize = r.Uint64(b[48:])
		s.MaxProt = r.Uint32(b[56:])
		s.InitProt = r.Uint32(b[60:])
	} else {
		if len(b) < 56 {
			return
		}
		s.Name = cstringFixed(b[8:24])
		s.VMAddr = uint64(r.Uint32(b[24:]))
		s.VMSize = uint64(r.Uint32(b[28:]))
		s.FileOff = uint64(r.Uint32(b[32:]))
		s.FileSize = uint64(r.Uint32(b[36:]))
		s.MaxProt = r.Uint32(b[40:])
		s.InitProt = r.Uint32(b[44:])
	}
	s.Perms = vmPerms(s.InitProt)
	var nsects uint32
	if is64 {
		nsects = r.Uint32(b[64:])
	} else {
		nsects = r.Uint32(b[48:])
	}
	// Segment data is at base+fileoff; compute entropy for mapped, non-empty
	// segments other than __PAGEZERO.
	if s.FileSize > 0 && s.Name != "__PAGEZERO" {
		off := base + s.FileOff
		if off+s.FileSize <= uint64(len(data)) {
			s.Entropy = Entropy(data[off : off+s.FileSize])
		} else {
			s.Truncated = true
		}
	}
	// Section headers follow the segment command in the same cmdsize block.
	secSize := uint64(68)
	hdr := uint64(56)
	if is64 {
		secSize, hdr = 80, 72
	}
	if nsects > maxMachOSections {
		nsects = maxMachOSections
	}
	for i := uint64(0); i < uint64(nsects); i++ {
		off := hdr + i*secSize
		if off+secSize > uint64(len(b)) {
			break
		}
		sb := b[off:]
		var sec MachOSection
		sec.Name = cstringFixed(sb[0:16])
		sec.Seg = cstringFixed(sb[16:32])
		if is64 {
			sec.Addr = r.Uint64(sb[32:])
			sec.Size = r.Uint64(sb[40:])
			sec.Offset = r.Uint32(sb[48:])
			sec.Flags = r.Uint32(sb[64:])
		} else {
			sec.Addr = uint64(r.Uint32(sb[32:]))
			sec.Size = uint64(r.Uint32(sb[36:]))
			sec.Offset = r.Uint32(sb[40:])
			sec.Flags = r.Uint32(sb[56:])
		}
		s.Sections = append(s.Sections, sec)
	}
	if len(img.Segments) < maxMachOSegments {
		img.Segments = append(img.Segments, s)
	}
}

// parseSymtab reads the symbol table for undefined-external (import) and
// defined-external (export) counts and keeps the import names.
func (img *MachOImage) parseSymtab(data []byte, base uint64, b []byte, seenImp map[string]bool) {
	if len(b) < 24 {
		return
	}
	r := img.order
	symoff := uint64(r.Uint32(b[8:]))
	nsyms := int(r.Uint32(b[12:]))
	stroff := uint64(r.Uint32(b[16:]))
	strsize := uint64(r.Uint32(b[20:]))
	if nsyms > maxMachOSyms {
		img.warnTo(nil)
		nsyms = maxMachOSyms
	}
	nlistSize := 12
	if img.Is64 {
		nlistSize = 16
	}
	symStart := base + symoff
	strStart := base + stroff
	strEnd := strStart + strsize
	if strEnd > uint64(len(data)) {
		strEnd = uint64(len(data))
	}
	readName := func(strx uint32) string {
		o := strStart + uint64(strx)
		if o >= strEnd {
			return ""
		}
		max := int(strEnd - o)
		if max > maxNameLen {
			max = maxNameLen
		}
		return cstring(data, int(o), max)
	}
	for i := 0; i < nsyms; i++ {
		p := symStart + uint64(i*nlistSize)
		if p+uint64(nlistSize) > uint64(len(data)) {
			break
		}
		nb := data[p:]
		strx := r.Uint32(nb[0:])
		ntype := nb[4]
		if ntype&nStab != 0 {
			continue // debug symbol
		}
		name := readName(strx)
		if name == "" {
			continue
		}
		undef := ntype&nTypeMask == nUndf
		ext := ntype&nExt != 0
		switch {
		case undef && ext:
			img.ImportCount++
			if !seenImp[name] && len(img.Imports) < maxMachONamesKept {
				seenImp[name] = true
				img.Imports = append(img.Imports, name)
			}
		case !undef && ext:
			img.ExportCount++
		}
	}
}

func (img *MachOImage) warnTo(_ []string) {}

// threadEntry recovers the entry point from an LC_UNIXTHREAD state for the two
// architectures it is still seen on; other flavors leave the entry at 0.
func (img *MachOImage) threadEntry(b []byte) uint64 {
	r := img.order
	if len(b) < 16 {
		return 0
	}
	flavor := r.Uint32(b[8:])
	state := b[16:]
	switch flavor {
	case 4: // x86_THREAD_STATE64: rip is register index 16
		if len(state) >= 17*8 {
			return r.Uint64(state[16*8:])
		}
	case 1: // i386_THREAD_STATE: eip is register index 10
		if len(state) >= 11*4 {
			return uint64(r.Uint32(state[10*4:]))
		}
	case 6: // ARM_THREAD_STATE64: pc is register index 32
		if len(state) >= 33*8 {
			return r.Uint64(state[32*8:])
		}
	}
	return 0
}

// locateEntry maps the entry point to a segment. LC_MAIN's entryoff is a file
// offset (matched against fileoff ranges); LC_UNIXTHREAD's is a virtual
// address (matched against vmaddr ranges).
func (img *MachOImage) locateEntry() {
	if img.Entry == 0 {
		return
	}
	for i, s := range img.Segments {
		var in bool
		if img.HasMain {
			in = img.Entry >= s.FileOff && img.Entry < s.FileOff+s.FileSize
		} else {
			in = s.VMSize > 0 && img.Entry >= s.VMAddr && img.Entry < s.VMAddr+s.VMSize
		}
		if in {
			img.EntrySegment = i
			img.EntryExecutable = s.Executable()
			return
		}
	}
}

// computeOverlay reports bytes trailing a thin image after the last segment and
// the code signature. Universal binaries are skipped: their slices are laid out
// with alignment padding that is not an overlay.
func (m *MachO) computeOverlay(data []byte) {
	if m.Fat || len(m.Arches) != 1 {
		return
	}
	img := m.Arches[0]
	end := uint64(0)
	for _, s := range img.Segments {
		if !s.Truncated {
			if e := s.FileOff + s.FileSize; e > end {
				end = e
			}
		}
	}
	// The code signature is the legitimate trailer; fold it in like a PE's
	// certificate table so it is not reported as an appended payload.
	sigBytes := uint64(0)
	if img.Signed {
		sigBytes = uint64(img.SignatureSize)
	}
	if end == 0 || end >= uint64(len(data)) {
		return
	}
	ov := Overlay{Offset: int64(end), Size: int64(uint64(len(data)) - end)}
	if sigBytes > 0 && ov.Size >= int64(sigBytes) {
		ov.CertificateBytes = int64(sigBytes)
		ov.Size -= int64(sigBytes)
	}
	if ov.Size > 0 {
		ov.Entropy = Entropy(data[ov.Offset : ov.Offset+ov.Size])
	}
	m.Overlay = ov
}

// identifyMachOPacker reports the generic packed profile: an executable
// segment at compressed-data entropy with nothing linked. UPX on Mach-O keeps
// its "UPX!" marker, matched first.
func identifyMachOPacker(m *MachO, data []byte) *Packer {
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if contains(head, "UPX!") || (len(data) >= 36 && contains(data[len(data)-36:], "UPX!")) {
		return &Packer{Name: "UPX", Evidence: []string{"UPX! marker"}}
	}
	for _, img := range m.Arches {
		if img.FileTypeNum != mhExecute && img.FileTypeNum != mhDylib {
			continue
		}
		hiExec := false
		for _, s := range img.Segments {
			if s.Executable() && s.FileSize >= 1024 && s.Entropy > techMinEntropyExec {
				hiExec = true
			}
		}
		if hiExec && img.ImportCount == 0 && len(img.Dylibs) <= 1 {
			return &Packer{Name: "packed", Generic: true, Evidence: []string{
				"executable segment above 7.0 bits/byte", "nothing imported"}}
		}
	}
	return nil
}

func contains(b []byte, s string) bool { return strings.Contains(string(b), s) }

// ── helpers ──────────────────────────────────────────────────────────────────

// lcString reads a Mach-O lc_str: a 4-byte offset from the command start to a
// NUL-terminated string inside the command.
func lcString(r binary.ByteOrder, cmd []byte, off int) string {
	if off+4 > len(cmd) {
		return ""
	}
	so := int(r.Uint32(cmd[off:]))
	if so < 0 || so >= len(cmd) {
		return ""
	}
	return cstring(cmd, so, maxNameLen)
}

// dylibSetHash is MD5 over the sorted, lower-cased, de-duplicated dylib
// basenames. It is a Mach-O clustering key, not telfhash.
func dylibSetHash(dylibs []MachODylib) string {
	if len(dylibs) == 0 {
		return ""
	}
	set := make([]string, 0, len(dylibs))
	seen := map[string]bool{}
	for _, d := range dylibs {
		base := strings.ToLower(d.Name)
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if base != "" && !seen[base] {
			seen[base] = true
			set = append(set, base)
		}
	}
	sort.Strings(set)
	sum := md5.Sum([]byte(strings.Join(set, ",")))
	return hex.EncodeToString(sum[:])
}

func vmPerms(prot uint32) string {
	b := []byte("---")
	if prot&vmProtRead != 0 {
		b[0] = 'r'
	}
	if prot&vmProtWrite != 0 {
		b[1] = 'w'
	}
	if prot&vmProtExec != 0 {
		b[2] = 'x'
	}
	return string(b)
}

func cpuTypeName(t uint32) string {
	switch t {
	case 7:
		return "i386"
	case 7 | cpuArchABI64:
		return "x86_64"
	case 12:
		return "arm"
	case 12 | cpuArchABI64:
		return "arm64"
	case 12 | 0x02000000:
		return "arm64_32"
	case 18:
		return "ppc"
	case 18 | cpuArchABI64:
		return "ppc64"
	}
	return fmt.Sprintf("cpu-0x%x", t)
}

func machoFileType(t uint32) string {
	switch t {
	case mhObject:
		return "object"
	case mhExecute:
		return "execute"
	case mhCore:
		return "core"
	case mhPreload:
		return "preload"
	case mhDylib:
		return "dylib"
	case mhDylinker:
		return "dylinker"
	case mhBundle:
		return "bundle"
	case mhDsym:
		return "dsym"
	case mhKextBundle:
		return "kext"
	}
	return fmt.Sprintf("type-%d", t)
}

func machoFlagNames(f uint32) []string {
	var out []string
	if f&mhPIE != 0 {
		out = append(out, "PIE")
	}
	if f&mhAllowStackExecution != 0 {
		out = append(out, "ALLOW_STACK_EXECUTION")
	}
	if f&mhNoHeapExecution != 0 {
		out = append(out, "NO_HEAP_EXECUTION")
	}
	if f&mhRootSafe != 0 {
		out = append(out, "ROOT_SAFE")
	}
	if f&mhTwoLevel != 0 {
		out = append(out, "TWOLEVEL")
	}
	return out
}

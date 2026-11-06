package static

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ELF parsing limits. Each is generous for real software and exists so a
// hostile header cannot make the parser walk the whole buffer many times.
const (
	maxELFSegments   = 512
	maxELFSections   = 1 << 16 // -ffunction-sections objects reach tens of thousands
	maxELFDynEntries = 1024
	maxELFDynSyms    = 1 << 18
	maxELFNamesKept  = 8192 // import / export names retained per table
	maxELFNeeded     = 512
	maxELFNotes      = 64
	maxELFInterpLen  = 256
	maxELFNoteName   = 64
	maxELFNoteDesc   = 1 << 12
	maxELFModinfo    = 1 << 16
	maxELFModinfoKey = 256
	maxELFRelocs     = 1 << 20  // relocation entries read when resolving pointers
	maxELFPointers   = 4096     // init/preinit array slots resolved
	maxELFVersions   = 1024     // symbol-version records read
	maxTelfSymbols   = 1 << 16  // function names fed to telfhash
	maxSyscallScan   = 16 << 20 // executable bytes scanned for syscall stubs
)

// ELF header constants.
const (
	elfClass32 = 1
	elfClass64 = 2
	elfData2L  = 1
	elfData2M  = 2

	etRel  = 1
	etExec = 2
	etDyn  = 3
	etCore = 4

	ptNull     = 0
	ptLoad     = 1
	ptDynamic  = 2
	ptInterp   = 3
	ptNote     = 4
	ptPhdr     = 6
	ptTLS      = 7
	ptGNUStack = 0x6474e551
	ptGNURelro = 0x6474e552

	pfX = 1
	pfW = 2
	pfR = 4

	shtNull     = 0
	shtProgbits = 1
	shtSymtab   = 2
	shtStrtab   = 3
	shtNobits   = 8
	shtNote     = 7
	shtDynsym   = 11

	shfWrite     = 0x1
	shfAlloc     = 0x2
	shfExecinstr = 0x4

	dtNull         = 0
	dtNeeded       = 1
	dtPltRelSz     = 2
	dtHash         = 4
	dtStrtab       = 5
	dtSymtab       = 6
	dtRela         = 7
	dtRelaSz       = 8
	dtRelaEnt      = 9
	dtStrsz        = 10
	dtSyment       = 11
	dtInit         = 12
	dtFini         = 13
	dtSoname       = 14
	dtRpath        = 15
	dtSymbolic     = 16
	dtRel          = 17
	dtRelSz        = 18
	dtRelEnt       = 19
	dtPltRel       = 20
	dtDebug        = 21
	dtTextrel      = 22
	dtJmpRel       = 23
	dtBindNow      = 24
	dtInitArray    = 25
	dtInitArraysz  = 27
	dtRunpath      = 29
	dtFlags        = 30
	dtPreinitArr   = 32
	dtPreinitArrsz = 33
	dtGNUHash      = 0x6ffffef5
	dtFlags1       = 0x6ffffffb

	dfTextrel = 0x4
	dfBindNow = 0x8
	df1Now    = 0x1
	df1PIE    = 0x08000000

	stbGlobal  = 1
	stbWeak    = 2
	sttObject  = 1
	sttFunc    = 2
	sttIFunc   = 10
	shnUndef   = 0
	stvDefault = 0

	shtGNUVerdef  = 0x6ffffffd
	shtGNUVerneed = 0x6ffffffe
	shtGNUVersym  = 0x6fffffff

	// Machine-specific R_*_RELATIVE relocation types. A RELATIVE relocation
	// carries its target in the addend (RELA) or in the slot it points at
	// (REL), which is how the init-array resolver recovers a PIE's slots.
	rRelativeX86     = 8    // R_386_RELATIVE and R_X86_64_RELATIVE
	rRelativeAArch64 = 1027 // R_AARCH64_RELATIVE
	rRelativeARM     = 23   // R_ARM_RELATIVE
	rRelativeRISCV   = 3    // R_RISCV_RELATIVE

	ntGNUABITag  = 1
	ntGNUBuildID = 3
	ntGoBuildID  = 4
)

// moduleSignatureMarker terminates a signed Linux kernel module. The 12-byte
// module_signature struct and the signature itself precede it.
const moduleSignatureMarker = "~Module signature appended~\n"

// ELFSegment is one program header plus what the parser derived from it.
type ELFSegment struct {
	Type     string `json:"type"`
	TypeNum  uint32 `json:"type_num"`
	Flags    uint32 `json:"flags"`
	Perms    string `json:"perms"`
	Offset   uint64 `json:"offset"`
	VirtAddr uint64 `json:"virt_addr"`
	FileSize uint64 `json:"file_size"`
	MemSize  uint64 `json:"mem_size"`
	Align    uint64 `json:"align"`
	// Entropy is computed for PT_LOAD segments with data on disk.
	Entropy float64 `json:"entropy"`
	// Entry is true for the segment that maps the entry point.
	Entry bool `json:"entry,omitempty"`
	// Truncated is true when the file range runs past the end of the file.
	Truncated bool `json:"truncated,omitempty"`
}

// Executable reports whether the segment is mapped executable.
func (s ELFSegment) Executable() bool { return s.Flags&pfX != 0 }

// Writable reports whether the segment is mapped writable.
func (s ELFSegment) Writable() bool { return s.Flags&pfW != 0 }

// Load reports whether the segment is a PT_LOAD.
func (s ELFSegment) Load() bool { return s.TypeNum == ptLoad }

// ELFSection is one section header plus what the parser derived from it.
type ELFSection struct {
	Name      string  `json:"name"`
	Type      uint32  `json:"type"`
	TypeName  string  `json:"type_name"`
	Flags     uint64  `json:"flags"`
	Perms     string  `json:"perms"`
	Addr      uint64  `json:"addr"`
	Offset    uint64  `json:"offset"`
	Size      uint64  `json:"size"`
	Link      uint32  `json:"-"`
	Info      uint32  `json:"-"`
	EntSize   uint64  `json:"-"`
	Entropy   float64 `json:"entropy"`
	Entry     bool    `json:"entry,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
}

// Executable reports whether the section holds instructions.
func (s ELFSection) Executable() bool { return s.Flags&shfExecinstr != 0 }

// Writable reports whether the section is writable at run time.
func (s ELFSection) Writable() bool { return s.Flags&shfWrite != 0 }

// Alloc reports whether the section is mapped at run time.
func (s ELFSection) Alloc() bool { return s.Flags&shfAlloc != 0 }

// NoBits reports whether the section occupies no file space (.bss).
func (s ELFSection) NoBits() bool { return s.Type == shtNobits }

// ELFModule is what a Linux kernel module declares about itself.
type ELFModule struct {
	Name       string `json:"name,omitempty"`
	Vermagic   string `json:"vermagic,omitempty"`
	License    string `json:"license,omitempty"`
	SrcVersion string `json:"srcversion,omitempty"`
	Author     string `json:"author,omitempty"`
	// Signed is true when the file ends with the module-signature trailer.
	// Nothing is verified: the kernel's keyring is not available to a file
	// scanner, and the report says so.
	Signed         bool `json:"signed"`
	SignatureBytes int  `json:"signature_bytes,omitempty"`
	// InfoPresent is true when a .modinfo section exists.
	InfoPresent bool `json:"info_present"`
}

// ELFNote is one parsed note.
type ELFNote struct {
	Name string `json:"name"`
	Type uint32 `json:"type"`
	Desc string `json:"desc,omitempty"`
}

// ELFPointer is one resolved function pointer from an init/preinit array: its
// target virtual address, the section that contains it, whether that section
// is executable, and how the address was recovered.
type ELFPointer struct {
	Array      string `json:"array"` // ".init_array" or ".preinit_array"
	VA         uint64 `json:"va"`
	Section    string `json:"section,omitempty"`
	Executable bool   `json:"executable"`
	// Source is "file" (slot held the address), "relative-reloc" (a
	// R_*_RELATIVE relocation supplied it) or "unresolved".
	Source string `json:"source"`
}

// ELFVersionNeed is one dependency's symbol-version requirement, e.g.
// libc.so.6 needing GLIBC_2.34.
type ELFVersionNeed struct {
	File     string   `json:"file"`
	Versions []string `json:"versions"`
}

// ELF is the parsed structure of an Executable and Linkable Format file.
type ELF struct {
	// Class is "elf32" or "elf64"; ByteOrder is "little" or "big".
	Class       string `json:"class"`
	ByteOrder   string `json:"byte_order"`
	Type        uint16 `json:"type"`
	TypeName    string `json:"type_name"`
	Machine     uint16 `json:"machine"`
	MachineName string `json:"machine_name"`
	OSABI       uint8  `json:"osabi"`
	OSABIName   string `json:"osabi_name"`
	Entry       uint64 `json:"entry_point"`
	// EntrySegment is the index of the PT_LOAD mapping the entry point (-1
	// when none does); EntrySection is the section name, "" when unknown.
	EntrySegment int    `json:"entry_segment"`
	EntrySection string `json:"entry_section,omitempty"`

	Segments []ELFSegment `json:"segments"`
	Sections []ELFSection `json:"sections"`
	// NoSectionHeaders is true when the file carries no section table at all
	// (sstrip, UPX). SectionTableInvalid records a table that points outside
	// the file.
	NoSectionHeaders    bool   `json:"no_section_headers,omitempty"`
	SectionTableInvalid string `json:"section_table_invalid,omitempty"`
	ProgramTableInvalid string `json:"program_table_invalid,omitempty"`

	Interp     string   `json:"interp,omitempty"`
	HasDynamic bool     `json:"has_dynamic"`
	Needed     []string `json:"needed,omitempty"`
	SOName     string   `json:"soname,omitempty"`
	RPath      []string `json:"rpath,omitempty"`
	RunPath    []string `json:"runpath,omitempty"`
	// Imports are the undefined dynamic symbols (or, for relocatable
	// objects such as kernel modules, the undefined .symtab entries). Exports
	// are the defined global and weak functions. Both lists are capped; the
	// counts are not.
	Imports     []string `json:"imports,omitempty"`
	ImportCount int      `json:"import_count"`
	Exports     []string `json:"-"`
	ExportCount int      `json:"export_count"`
	// ImportHash is MD5 over the sorted, lower-cased import names. It is a
	// CAU clustering key, not telfhash-compatible.
	ImportHash string `json:"import_hash,omitempty"`
	// Telfhash is the Trend Micro telfhash: TLSH over the filtered, sorted,
	// lower-cased set of global default-visibility function symbols. It is
	// compatible with telfhash for inputs TLSH can digest (the symbol text
	// reaches 50 bytes); a shorter set leaves it empty with TelfhashNote set,
	// since this TLSH library has no forcehash.
	Telfhash     string `json:"telfhash,omitempty"`
	TelfhashNote string `json:"telfhash_note,omitempty"`

	Init           uint64 `json:"init,omitempty"`
	InitArrayCount int    `json:"init_array_count,omitempty"`
	PreinitCount   int    `json:"preinit_array_count,omitempty"`
	// InitArrayTargets are the resolved constructor pointers from .init_array
	// and .preinit_array. A non-PIE image stores the target VA in the slot; a
	// PIE leaves it 0 and a R_*_RELATIVE relocation carries the VA, so
	// resolution needs the relocation tables.
	InitArrayTargets []ELFPointer `json:"init_array_targets,omitempty"`
	// VersionsNeeded lists the symbol-version requirements (dependency ->
	// versions); VersionsDefined the versions this object itself defines.
	VersionsNeeded  []ELFVersionNeed `json:"versions_needed,omitempty"`
	VersionsDefined []string         `json:"versions_defined,omitempty"`
	// SyscallStubs counts raw system-call instructions in executable sections
	// (x86-64 syscall, i386 int 0x80 / sysenter, aarch64 svc #0). It is the
	// tell for a loader or interposer that reaches the kernel without libc.
	SyscallStubs int  `json:"syscall_stubs,omitempty"`
	TextRel      bool `json:"textrel,omitempty"`
	BindNow      bool `json:"bind_now,omitempty"`
	IsPIE        bool `json:"pie"`
	// Static is true for an image that needs no dynamic loader: no PT_INTERP
	// and no PT_DYNAMIC.
	Static          bool `json:"static"`
	StackPresent    bool `json:"gnu_stack_present"`
	StackExecutable bool `json:"stack_executable"`
	RelRO           bool `json:"relro"`

	Notes   []ELFNote `json:"notes,omitempty"`
	BuildID string    `json:"build_id,omitempty"`
	ABITag  string    `json:"abi_tag,omitempty"`

	// Module is non-nil for a Linux kernel module.
	Module *ELFModule `json:"module,omitempty"`
	// AppImage is the AppImage type (1 or 2) when the magic is present.
	AppImage int `json:"appimage,omitempty"`

	Overlay Overlay `json:"overlay"`
	Packer  *Packer `json:"packer,omitempty"`

	Warnings []string `json:"warnings,omitempty"`

	size   int
	is64   bool
	order  binary.ByteOrder
	phoff  uint64
	shoff  uint64
	phnum  int
	shnum  int
	phent  int
	shent  int
	dynOff int
	dynLen int

	// Addresses and sizes captured from the dynamic table for the pointer
	// resolver and relocation walk (all virtual addresses).
	initArrayVA, initArraySz uint64
	preinitVA, preinitSz     uint64
	relaVA, relaSz, relaEnt  uint64
	relVA, relSz, relEnt     uint64
	jmprelVA, pltRelSz       uint64
	pltRel                   uint64

	// telf accumulates telfhash-eligible symbol names (lower-cased) as the
	// symbol tables are walked.
	telf []string
}

func (e *ELF) warn(format string, a ...interface{}) {
	if len(e.Warnings) < 32 {
		e.Warnings = append(e.Warnings, fmt.Sprintf(format, a...))
	}
}

// IsELF reports whether the buffer starts like an ELF file: magic, a known
// class and a known byte order.
func IsELF(data []byte) bool {
	return len(data) >= 52 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' &&
		(data[4] == elfClass32 || data[4] == elfClass64) && (data[5] == elfData2L || data[5] == elfData2M)
}

// ParseELF parses an ELF image. It returns an error only when the identity
// bytes or the header are unusable; every later inconsistency is tolerated
// and recorded in Warnings.
func ParseELF(data []byte) (*ELF, error) {
	if !IsELF(data) {
		return nil, fmt.Errorf("not an ELF image")
	}
	e := &ELF{size: len(data), EntrySegment: -1}
	e.is64 = data[4] == elfClass64
	if e.is64 {
		e.Class = "elf64"
	} else {
		e.Class = "elf32"
	}
	if data[5] == elfData2L {
		e.order, e.ByteOrder = binary.LittleEndian, "little"
	} else {
		e.order, e.ByteOrder = binary.BigEndian, "big"
	}
	e.OSABI = data[7]
	e.OSABIName = osabiName(e.OSABI)

	hdrLen := 52
	if e.is64 {
		hdrLen = 64
	}
	if len(data) < hdrLen {
		return nil, fmt.Errorf("file is %d bytes, shorter than the %d byte ELF header", len(data), hdrLen)
	}
	r := e.order
	e.Type = r.Uint16(data[16:])
	e.TypeName = elfTypeName(e.Type)
	e.Machine = r.Uint16(data[18:])
	e.MachineName = elfMachineName(e.Machine)
	if e.is64 {
		e.Entry = r.Uint64(data[24:])
		e.phoff = r.Uint64(data[32:])
		e.shoff = r.Uint64(data[40:])
		e.phent = int(r.Uint16(data[54:]))
		e.phnum = int(r.Uint16(data[56:]))
		e.shent = int(r.Uint16(data[58:]))
		e.shnum = int(r.Uint16(data[60:]))
	} else {
		e.Entry = uint64(r.Uint32(data[24:]))
		e.phoff = uint64(r.Uint32(data[28:]))
		e.shoff = uint64(r.Uint32(data[32:]))
		e.phent = int(r.Uint16(data[42:]))
		e.phnum = int(r.Uint16(data[44:]))
		e.shent = int(r.Uint16(data[46:]))
		e.shnum = int(r.Uint16(data[48:]))
	}
	shstrndx := int(r.Uint16(data[hdrLen-2:]))

	e.parseSegments(data)
	e.parseSections(data, shstrndx)
	e.Static = e.Interp == "" && !e.HasDynamic && e.Type != etRel
	e.parseDynamic(data)
	e.parseSymbols(data)
	e.parseNotes(data)
	e.locateEntry()
	e.parseModule(data)
	if len(data) >= 11 && data[8] == 'A' && data[9] == 'I' && (data[10] == 1 || data[10] == 2) {
		e.AppImage = int(data[10])
	}
	e.computeOverlay(data)
	e.Packer = identifyELFPacker(e, data)
	e.ImportHash = importSetHash(e.Imports)
	e.Telfhash, e.TelfhashNote = telfhash(e.telf)
	e.resolveInitArray(data)
	e.parseVersions(data)
	e.scanSyscalls(data)
	return e, nil
}

// ── program headers ──────────────────────────────────────────────────────────

func (e *ELF) parseSegments(data []byte) {
	minEnt := 32
	if e.is64 {
		minEnt = 56
	}
	if e.phnum == 0 || e.phoff == 0 {
		if e.Type == etExec || e.Type == etDyn {
			e.ProgramTableInvalid = "no program headers"
		}
		return
	}
	if e.phent < minEnt {
		e.ProgramTableInvalid = fmt.Sprintf("program header entry size %d is below the %d byte minimum", e.phent, minEnt)
		e.warn("%s", e.ProgramTableInvalid)
		return
	}
	n := e.phnum
	if n == 0xffff {
		e.warn("program header count uses the PN_XNUM extension; reading at most %d entries", maxELFSegments)
		n = maxELFSegments
	}
	if n > maxELFSegments {
		e.warn("%d program headers declared; reading the first %d", n, maxELFSegments)
		n = maxELFSegments
	}
	end := e.phoff + uint64(n)*uint64(e.phent)
	if e.phoff >= uint64(len(data)) || end > uint64(len(data)) || end < e.phoff {
		e.ProgramTableInvalid = fmt.Sprintf("program header table at 0x%x (+%d entries) lies outside the %d byte file", e.phoff, n, len(data))
		e.warn("%s", e.ProgramTableInvalid)
		return
	}
	r := e.order
	for i := 0; i < n; i++ {
		b := data[int(e.phoff)+i*e.phent:]
		var s ELFSegment
		if e.is64 {
			s.TypeNum = r.Uint32(b[0:])
			s.Flags = r.Uint32(b[4:])
			s.Offset = r.Uint64(b[8:])
			s.VirtAddr = r.Uint64(b[16:])
			s.FileSize = r.Uint64(b[32:])
			s.MemSize = r.Uint64(b[40:])
			s.Align = r.Uint64(b[48:])
		} else {
			s.TypeNum = r.Uint32(b[0:])
			s.Offset = uint64(r.Uint32(b[4:]))
			s.VirtAddr = uint64(r.Uint32(b[8:]))
			s.FileSize = uint64(r.Uint32(b[16:]))
			s.MemSize = uint64(r.Uint32(b[20:]))
			s.Flags = r.Uint32(b[24:])
			s.Align = uint64(r.Uint32(b[28:]))
		}
		s.Type = segmentTypeName(s.TypeNum)
		s.Perms = elfPerms(uint64(s.Flags&pfR), uint64(s.Flags&pfW), uint64(s.Flags&pfX))
		off, sz, ok := e.fileRange(s.Offset, s.FileSize)
		if !ok && s.FileSize > 0 && s.TypeNum != ptNull {
			s.Truncated = true
		}
		switch s.TypeNum {
		case ptLoad:
			if ok && sz > 0 {
				s.Entropy = Entropy(data[off : off+sz])
			}
		case ptInterp:
			if ok && sz > 0 {
				max := sz
				if max > maxELFInterpLen {
					max = maxELFInterpLen
				}
				e.Interp = cstring(data, off, max)
			}
		case ptDynamic:
			e.HasDynamic = true
			if ok {
				e.dynOff, e.dynLen = off, sz
			}
		case ptGNUStack:
			e.StackPresent = true
			e.StackExecutable = s.Flags&pfX != 0
		case ptGNURelro:
			e.RelRO = true
		}
		e.Segments = append(e.Segments, s)
	}
}

// fileRange bounds (offset, size) against the buffer. ok is false when any
// part of the range lies outside the file.
func (e *ELF) fileRange(off, size uint64) (int, int, bool) {
	if off > uint64(e.size) || size > uint64(e.size) || off+size > uint64(e.size) {
		return 0, 0, false
	}
	return int(off), int(size), true
}

// vaToOffset maps a virtual address through the PT_LOAD segments.
func (e *ELF) vaToOffset(va uint64) (int, bool) {
	for _, s := range e.Segments {
		if !s.Load() || s.FileSize == 0 {
			continue
		}
		// va-VirtAddr (not VirtAddr+FileSize) so a segment whose address range
		// wraps uint64 cannot make a contained VA resolve to "not mapped".
		if va >= s.VirtAddr && va-s.VirtAddr < s.FileSize {
			off := s.Offset + (va - s.VirtAddr)
			if off < uint64(e.size) {
				return int(off), true
			}
		}
	}
	return 0, false
}

// segmentIndexForVA returns the PT_LOAD mapping va (by memory size), or -1.
func (e *ELF) segmentIndexForVA(va uint64) int {
	for i, s := range e.Segments {
		if s.Load() && va >= s.VirtAddr && va-s.VirtAddr < s.MemSize {
			return i
		}
	}
	return -1
}

// ── section headers ──────────────────────────────────────────────────────────

func (e *ELF) parseSections(data []byte, shstrndx int) {
	minEnt := 40
	if e.is64 {
		minEnt = 64
	}
	if e.shoff == 0 {
		if e.shnum != 0 {
			e.SectionTableInvalid = fmt.Sprintf("%d section headers declared at offset 0", e.shnum)
			e.warn("%s", e.SectionTableInvalid)
			return
		}
		e.NoSectionHeaders = true
		return
	}
	if e.shent < minEnt {
		e.SectionTableInvalid = fmt.Sprintf("section header entry size %d is below the %d byte minimum", e.shent, minEnt)
		e.warn("%s", e.SectionTableInvalid)
		return
	}
	n := e.shnum
	r := e.order
	if n == 0 {
		// SHN_UNDEF: the real count is in section 0's sh_size.
		if size := uint64(len(data)); e.shoff <= size && uint64(e.shent) <= size-e.shoff { // subtraction: shoff can wrap
			b := data[e.shoff:]
			var real uint64
			if e.is64 {
				real = r.Uint64(b[32:])
			} else {
				real = uint64(r.Uint32(b[20:]))
			}
			if real > 0 && real <= maxELFSections {
				n = int(real)
			}
		}
		if n == 0 {
			e.SectionTableInvalid = "section header table at a non-zero offset declares zero entries"
			e.warn("%s", e.SectionTableInvalid)
			return
		}
	}
	if n > maxELFSections {
		e.warn("%d section headers declared; reading the first %d", n, maxELFSections)
		n = maxELFSections
	}
	end := e.shoff + uint64(n)*uint64(e.shent)
	if e.shoff >= uint64(len(data)) || end > uint64(len(data)) || end < e.shoff {
		e.SectionTableInvalid = fmt.Sprintf("section header table at 0x%x (+%d entries) lies outside the %d byte file", e.shoff, n, len(data))
		e.warn("%s", e.SectionTableInvalid)
		return
	}
	secs := make([]ELFSection, 0, n)
	nameOffs := make([]uint32, 0, n)
	for i := 0; i < n; i++ {
		b := data[int(e.shoff)+i*e.shent:]
		var s ELFSection
		nameOff := r.Uint32(b[0:])
		s.Type = r.Uint32(b[4:])
		if e.is64 {
			s.Flags = r.Uint64(b[8:])
			s.Addr = r.Uint64(b[16:])
			s.Offset = r.Uint64(b[24:])
			s.Size = r.Uint64(b[32:])
			s.Link = r.Uint32(b[40:])
			s.Info = r.Uint32(b[44:])
			s.EntSize = r.Uint64(b[56:])
		} else {
			s.Flags = uint64(r.Uint32(b[8:]))
			s.Addr = uint64(r.Uint32(b[12:]))
			s.Offset = uint64(r.Uint32(b[16:]))
			s.Size = uint64(r.Uint32(b[20:]))
			s.Link = r.Uint32(b[24:])
			s.Info = r.Uint32(b[28:])
			s.EntSize = uint64(r.Uint32(b[36:]))
		}
		s.TypeName = sectionTypeName(s.Type)
		s.Perms = elfPerms(uint64(s.Flags&shfAlloc), uint64(s.Flags&shfWrite), uint64(s.Flags&shfExecinstr))
		secs = append(secs, s)
		nameOffs = append(nameOffs, nameOff)
	}
	// Resolve names through the section-name string table.
	if shstrndx > 0 && shstrndx < n && secs[shstrndx].Type == shtStrtab {
		st := secs[shstrndx]
		if off, sz, ok := e.fileRange(st.Offset, st.Size); ok {
			tab := data[off : off+sz]
			for i := range secs {
				if int(nameOffs[i]) < len(tab) {
					secs[i].Name = cstring(tab, int(nameOffs[i]), maxNameLen)
				} else {
					secs[i].Name = ""
					e.warn("section %d name offset %d is outside the %d byte string table", i, nameOffs[i], len(tab))
				}
			}
		} else {
			e.warn("section name string table lies outside the file")
			for i := range secs {
				secs[i].Name = ""
			}
		}
	} else {
		if shstrndx != 0 {
			e.warn("section name table index %d is invalid", shstrndx)
		}
		for i := range secs {
			secs[i].Name = ""
		}
	}
	for i := range secs {
		s := &secs[i]
		if s.Type == shtNull {
			continue
		}
		if s.NoBits() || s.Size == 0 {
			continue
		}
		off, sz, ok := e.fileRange(s.Offset, s.Size)
		if !ok {
			s.Truncated = true
			continue
		}
		if s.Executable() && sz >= 1024 {
			s.Entropy = Entropy(data[off : off+sz])
		}
	}
	e.Sections = secs
	e.shnum = n
	if !e.HasDynamic {
		for _, s := range secs {
			if s.Name == ".dynamic" && s.Type == 6 && !s.NoBits() {
				if off, sz, ok := e.fileRange(s.Offset, s.Size); ok {
					e.HasDynamic = true
					e.dynOff, e.dynLen = off, sz
				}
			}
		}
	}
}

// ── dynamic section ──────────────────────────────────────────────────────────

func (e *ELF) parseDynamic(data []byte) {
	if e.dynLen == 0 {
		return
	}
	ent := 8
	if e.is64 {
		ent = 16
	}
	r := e.order
	var strtab, strsz, symtab uint64
	var needed []uint64
	var soname, rpath, runpath uint64
	var hasSoname, hasRpath, hasRunpath bool
	var initArraySz, preinitSz, syment uint64
	var hash, gnuHash uint64
	n := e.dynLen / ent
	if n > maxELFDynEntries {
		e.warn("dynamic section has %d entries; reading the first %d", n, maxELFDynEntries)
		n = maxELFDynEntries
	}
	for i := 0; i < n; i++ {
		b := data[e.dynOff+i*ent:]
		var tag, val uint64
		if e.is64 {
			tag, val = r.Uint64(b[0:]), r.Uint64(b[8:])
		} else {
			tag, val = uint64(r.Uint32(b[0:])), uint64(r.Uint32(b[4:]))
		}
		if tag == dtNull {
			break
		}
		switch tag {
		case dtNeeded:
			if len(needed) < maxELFNeeded {
				needed = append(needed, val)
			}
		case dtStrtab:
			strtab = val
		case dtStrsz:
			strsz = val
		case dtSymtab:
			symtab = val
		case dtSyment:
			syment = val
		case dtSoname:
			soname, hasSoname = val, true
		case dtRpath:
			rpath, hasRpath = val, true
		case dtRunpath:
			runpath, hasRunpath = val, true
		case dtInit:
			e.Init = val
		case dtInitArray:
			e.initArrayVA = val
		case dtInitArraysz:
			initArraySz = val
		case dtPreinitArr:
			e.preinitVA = val
		case dtPreinitArrsz:
			preinitSz = val
		case dtRela:
			e.relaVA = val
		case dtRelaSz:
			e.relaSz = val
		case dtRelaEnt:
			e.relaEnt = val
		case dtRel:
			e.relVA = val
		case dtRelSz:
			e.relSz = val
		case dtRelEnt:
			e.relEnt = val
		case dtJmpRel:
			e.jmprelVA = val
		case dtPltRelSz:
			e.pltRelSz = val
		case dtPltRel:
			e.pltRel = val
		case dtTextrel:
			e.TextRel = true
		case dtBindNow:
			e.BindNow = true
		case dtFlags:
			if val&dfTextrel != 0 {
				e.TextRel = true
			}
			if val&dfBindNow != 0 {
				e.BindNow = true
			}
		case dtFlags1:
			if val&df1PIE != 0 {
				e.IsPIE = true
			}
			if val&df1Now != 0 {
				e.BindNow = true
			}
		case dtHash:
			hash = val
		case dtGNUHash:
			gnuHash = val
		}
	}
	ptr := uint64(4)
	if e.is64 {
		ptr = 8
	}
	if initArraySz > 0 {
		e.InitArrayCount = int(initArraySz / ptr)
		e.initArraySz = initArraySz
	}
	if preinitSz > 0 {
		e.PreinitCount = int(preinitSz / ptr)
		e.preinitSz = preinitSz
	}
	if e.Type == etDyn && !e.IsPIE && e.Interp != "" && !hasSoname {
		// A PIE linked by an older toolchain carries no DF_1_PIE; the loader
		// path without a SONAME is the practical tell.
		e.IsPIE = true
	}

	strOff, strOK := e.vaToOffset(strtab)
	if !strOK || strsz == 0 {
		if len(needed) > 0 || hasSoname {
			e.warn("dynamic string table at 0x%x is not mapped by any segment", strtab)
		}
		strOK = false
	}
	readStr := func(off uint64) string {
		if !strOK || off >= strsz {
			return ""
		}
		end := uint64(strOff) + strsz
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		max := int(end) - (strOff + int(off))
		if max <= 0 {
			return ""
		}
		if max > maxNameLen {
			max = maxNameLen
		}
		return cstring(data, strOff+int(off), max)
	}
	for _, off := range needed {
		if s := readStr(off); s != "" {
			e.Needed = append(e.Needed, s)
		}
	}
	if hasSoname {
		e.SOName = readStr(soname)
	}
	if hasRpath {
		e.RPath = splitPathList(readStr(rpath))
	}
	if hasRunpath {
		e.RunPath = splitPathList(readStr(runpath))
	}

	// Dynamic symbol table: count from the section header when present,
	// otherwise from the hash table.
	if symtab == 0 {
		return
	}
	symOff, ok := e.vaToOffset(symtab)
	if !ok {
		e.warn("dynamic symbol table at 0x%x is not mapped by any segment", symtab)
		return
	}
	symEnt := int(syment)
	wantEnt := 16
	if e.is64 {
		wantEnt = 24
	}
	if symEnt == 0 {
		symEnt = wantEnt
	}
	if symEnt < wantEnt {
		e.warn("dynamic symbol entry size %d is below the %d byte minimum", symEnt, wantEnt)
		return
	}
	count := -1
	for _, s := range e.Sections {
		if s.Type == shtDynsym && s.Size > 0 && s.EntSize > 0 {
			count = int(s.Size / s.EntSize)
			break
		}
	}
	if count < 0 && hash != 0 {
		if off, ok := e.vaToOffset(hash); ok && off+8 <= len(data) {
			count = int(r.Uint32(data[off+4:])) // nchain
		}
	}
	if count < 0 && gnuHash != 0 {
		count = e.gnuHashSymbolCount(data, gnuHash)
	}
	if count < 0 {
		e.warn("dynamic symbol count could not be determined (no .dynsym header, DT_HASH or DT_GNU_HASH)")
		return
	}
	if count > maxELFDynSyms {
		e.warn("%d dynamic symbols declared; reading the first %d", count, maxELFDynSyms)
		count = maxELFDynSyms
	}
	e.readSymbols(data, symOff, symEnt, count, func(nameOff uint32) string { return readStr(uint64(nameOff)) })
}

// gnuHashSymbolCount derives the dynamic symbol count from a DT_GNU_HASH
// table: the highest chain index reached from any bucket, plus one.
func (e *ELF) gnuHashSymbolCount(data []byte, va uint64) int {
	off, ok := e.vaToOffset(va)
	if !ok || off+16 > len(data) {
		return -1
	}
	r := e.order
	nbuckets := int(r.Uint32(data[off:]))
	symoffset := int(r.Uint32(data[off+4:]))
	bloomSize := int(r.Uint32(data[off+8:]))
	if nbuckets <= 0 || nbuckets > 1<<20 || bloomSize < 0 || bloomSize > 1<<20 ||
		symoffset < 0 || symoffset > 1<<24 {
		return -1
	}
	wordSize := 4
	if e.is64 {
		wordSize = 8
	}
	bucketsOff := off + 16 + bloomSize*wordSize
	if bucketsOff+nbuckets*4 > len(data) {
		return -1
	}
	maxIdx := 0
	for i := 0; i < nbuckets; i++ {
		if v := int(r.Uint32(data[bucketsOff+i*4:])); v > maxIdx {
			maxIdx = v
		}
	}
	if maxIdx < symoffset {
		return symoffset
	}
	chainsOff := bucketsOff + nbuckets*4
	for steps := 0; steps < maxELFDynSyms; steps++ {
		if maxIdx-symoffset >= (len(data)-chainsOff)/4 { // division: the product can wrap a 32-bit int
			return -1
		}
		p := chainsOff + (maxIdx-symoffset)*4
		if r.Uint32(data[p:])&1 != 0 {
			break
		}
		maxIdx++
	}
	return maxIdx + 1
}

// readSymbols walks a symbol table and fills Imports / Exports.
func (e *ELF) readSymbols(data []byte, off, ent, count int, name func(uint32) string) {
	r := e.order
	seenImp := map[string]bool{}
	// A stride larger than the file keeps p+ent below from wrapping past the
	// guard; d_val and sh_entsize are both attacker-supplied.
	if ent > len(data) {
		e.warn("symbol entry size %d is larger than the file", ent)
		return
	}
	for i := 0; i < count; i++ {
		p := off + i*ent
		if p+ent > len(data) {
			e.warn("symbol table runs past the end of the file after %d entries", i)
			break
		}
		b := data[p:]
		var nameOff uint32
		var info, other uint8
		var shndx uint16
		if e.is64 {
			nameOff = r.Uint32(b[0:])
			info = b[4]
			other = b[5]
			shndx = r.Uint16(b[6:])
		} else {
			nameOff = r.Uint32(b[0:])
			info = b[12]
			other = b[13]
			shndx = r.Uint16(b[14:])
		}
		typ := info & 0xf
		bind := info >> 4
		if nameOff == 0 {
			continue
		}
		n := name(nameOff)
		if n == "" {
			continue
		}
		// telfhash candidates: global, default-visibility functions, imported
		// or exported alike, minus telfhash's exclusion list. Collected here
		// so the digest uses the same table (.dynsym for images, .symtab for
		// relocatable objects) telfhash would pick.
		if typ == sttFunc && bind == stbGlobal && other&0x3 == stvDefault &&
			len(e.telf) < maxTelfSymbols && !telfhashExcluded(n) {
			e.telf = append(e.telf, strings.ToLower(n))
		}
		switch {
		case shndx == shnUndef:
			if typ == sttFunc || typ == sttObject || typ == 0 || typ == sttIFunc {
				e.ImportCount++
				if !seenImp[n] && len(e.Imports) < maxELFNamesKept {
					seenImp[n] = true
					e.Imports = append(e.Imports, n)
				}
			}
		case (bind == stbGlobal || bind == stbWeak) && (typ == sttFunc || typ == sttIFunc):
			e.ExportCount++
			if len(e.Exports) < maxELFNamesKept {
				e.Exports = append(e.Exports, n)
			}
		}
	}
}

// parseSymbols handles relocatable objects (kernel modules, .o files), whose
// undefined references live in .symtab rather than .dynsym.
func (e *ELF) parseSymbols(data []byte) {
	if e.Type != etRel || e.ImportCount > 0 {
		return
	}
	wantEnt := 16
	if e.is64 {
		wantEnt = 24
	}
	for _, s := range e.Sections {
		if s.Type != shtSymtab || s.EntSize == 0 || s.Size == 0 {
			continue
		}
		// Floor the stride to the struct size, exactly as parseDynamic does:
		// readSymbols reads a fixed-size Elf32/64_Sym, so an attacker-set
		// sh_entsize below the minimum would let the per-entry guard pass
		// while the field read overruns the buffer (out-of-bounds panic).
		ent := int(s.EntSize)
		if ent < wantEnt {
			e.warn(".symtab entry size %d is below the %d byte minimum", ent, wantEnt)
			continue
		}
		off, sz, ok := e.fileRange(s.Offset, s.Size)
		if !ok {
			continue
		}
		if uint64(s.Link) >= uint64(len(e.Sections)) {
			e.warn(".symtab links to string table %d which does not exist", s.Link)
			return
		}
		st := e.Sections[s.Link]
		stOff, stSz, ok := e.fileRange(st.Offset, st.Size)
		if !ok {
			return
		}
		tab := data[stOff : stOff+stSz]
		count := sz / ent
		if count > maxELFDynSyms {
			e.warn("%d symbols declared; reading the first %d", count, maxELFDynSyms)
			count = maxELFDynSyms
		}
		e.readSymbols(data, off, ent, count, func(n uint32) string {
			if uint64(n) >= uint64(len(tab)) {
				return ""
			}
			return cstring(tab, int(n), maxNameLen)
		})
		return
	}
}

// ── notes ────────────────────────────────────────────────────────────────────

func (e *ELF) parseNotes(data []byte) {
	ranges := [][2]int{}
	for _, s := range e.Segments {
		if s.TypeNum == ptNote {
			if off, sz, ok := e.fileRange(s.Offset, s.FileSize); ok {
				ranges = append(ranges, [2]int{off, sz})
			}
		}
	}
	if len(ranges) == 0 {
		for _, s := range e.Sections {
			if s.Type == shtNote {
				if off, sz, ok := e.fileRange(s.Offset, s.Size); ok {
					ranges = append(ranges, [2]int{off, sz})
				}
			}
		}
	}
	r := e.order
	for _, rg := range ranges {
		p, end := rg[0], rg[0]+rg[1]
		for p+12 <= end && len(e.Notes) < maxELFNotes {
			namesz := int(r.Uint32(data[p:]))
			descsz := int(r.Uint32(data[p+4:]))
			typ := r.Uint32(data[p+8:])
			p += 12
			if namesz < 0 || descsz < 0 || namesz > maxELFNoteName || descsz > 1<<20 {
				e.warn("note with implausible sizes (name %d, desc %d) ends the note walk", namesz, descsz)
				break
			}
			nameEnd := p + namesz
			descStart := align4(nameEnd)
			descEnd := descStart + descsz
			if nameEnd > end || descEnd > end || descEnd < descStart {
				e.warn("note runs past its segment")
				break
			}
			name := strings.TrimRight(string(data[p:nameEnd]), "\x00")
			desc := data[descStart:descEnd]
			note := ELFNote{Name: printable([]byte(name)), Type: typ}
			switch {
			case name == "GNU" && typ == ntGNUBuildID:
				note.Desc = hex.EncodeToString(desc[:minInt(len(desc), 64)])
				if e.BuildID == "" {
					e.BuildID = note.Desc
				}
			case name == "GNU" && typ == ntGNUABITag && len(desc) >= 16:
				osn := map[uint32]string{0: "Linux", 1: "GNU", 2: "Solaris", 3: "FreeBSD"}[r.Uint32(desc)]
				if osn == "" {
					osn = fmt.Sprintf("os-%d", r.Uint32(desc))
				}
				note.Desc = fmt.Sprintf("%s %d.%d.%d", osn, r.Uint32(desc[4:]), r.Uint32(desc[8:]), r.Uint32(desc[12:]))
				e.ABITag = note.Desc
			case name == "Go" && typ == ntGoBuildID:
				note.Desc = printable(desc[:minInt(len(desc), 128)])
			default:
				if len(desc) > 0 && len(desc) <= maxELFNoteDesc {
					note.Desc = fmt.Sprintf("%d bytes", len(desc))
				}
			}
			e.Notes = append(e.Notes, note)
			p = align4(descEnd)
		}
	}
}

// ── entry point ──────────────────────────────────────────────────────────────

func (e *ELF) locateEntry() {
	if e.Entry == 0 {
		return
	}
	if idx := e.segmentIndexForVA(e.Entry); idx >= 0 {
		e.EntrySegment = idx
		e.Segments[idx].Entry = true
	}
	for i, s := range e.Sections {
		if !s.Alloc() || s.Size == 0 {
			continue
		}
		if e.Entry >= s.Addr && e.Entry < s.Addr+s.Size {
			e.Sections[i].Entry = true
			e.EntrySection = s.Name
			return
		}
	}
}

// ── kernel module ────────────────────────────────────────────────────────────

func (e *ELF) parseModule(data []byte) {
	if e.Type != etRel {
		return
	}
	var info *ELFSection
	thisModule := false
	for i := range e.Sections {
		switch e.Sections[i].Name {
		case ".modinfo":
			info = &e.Sections[i]
		case ".gnu.linkonce.this_module":
			thisModule = true
		}
	}
	if info == nil && !thisModule {
		return
	}
	m := &ELFModule{InfoPresent: info != nil}
	if info != nil {
		if off, sz, ok := e.fileRange(info.Offset, info.Size); ok {
			if sz > maxELFModinfo {
				sz = maxELFModinfo
			}
			for _, kv := range bytes.Split(data[off:off+sz], []byte{0}) {
				if len(kv) == 0 || len(kv) > maxELFModinfoKey {
					continue
				}
				k, v, found := strings.Cut(printable(kv), "=")
				if !found {
					continue
				}
				switch k {
				case "name":
					m.Name = v
				case "vermagic":
					m.Vermagic = v
				case "license":
					m.License = v
				case "srcversion":
					m.SrcVersion = v
				case "author":
					if m.Author == "" {
						m.Author = v
					}
				}
			}
		}
	}
	if sig := moduleSignatureSize(data); sig > 0 {
		m.Signed = true
		m.SignatureBytes = sig
	}
	e.Module = m
}

// moduleSignatureSize returns the total trailer size (signature struct +
// signature + marker) when the file ends with a kernel module signature, 0
// otherwise.
func moduleSignatureSize(data []byte) int {
	mk := len(moduleSignatureMarker)
	if len(data) < mk+12 || string(data[len(data)-mk:]) != moduleSignatureMarker {
		return 0
	}
	hdr := data[len(data)-mk-12 : len(data)-mk]
	sigLen := int(binary.BigEndian.Uint32(hdr[8:]))
	if sigLen <= 0 || sigLen > len(data)-mk-12 { // subtraction: the sum can wrap a 32-bit int
		return mk + 12
	}
	return mk + 12 + sigLen
}

// ── overlay ──────────────────────────────────────────────────────────────────

func (e *ELF) computeOverlay(data []byte) {
	end := uint64(0)
	bump := func(v uint64) {
		if v > end && v <= uint64(len(data)) {
			end = v
		}
	}
	if e.ProgramTableInvalid == "" && e.phnum > 0 {
		bump(e.phoff + uint64(e.phnum)*uint64(e.phent))
	}
	if e.SectionTableInvalid == "" && e.shnum > 0 && e.shoff != 0 {
		bump(e.shoff + uint64(e.shnum)*uint64(e.shent))
	}
	for _, s := range e.Segments {
		if !s.Truncated && s.TypeNum != ptNull {
			bump(s.Offset + s.FileSize)
		}
	}
	for _, s := range e.Sections {
		if !s.Truncated && !s.NoBits() && s.Type != shtNull {
			bump(s.Offset + s.Size)
		}
	}
	if end == 0 || end >= uint64(len(data)) {
		return
	}
	ov := Overlay{Offset: int64(end), Size: int64(len(data)) - int64(end)}
	if e.Module != nil && e.Module.Signed {
		ov.CertificateBytes = int64(e.Module.SignatureBytes)
		ov.Size -= ov.CertificateBytes
		if ov.Size < 0 {
			ov.Size = 0
		}
	}
	if ov.Size > 0 {
		ov.Entropy = Entropy(data[ov.Offset : ov.Offset+ov.Size])
	}
	e.Overlay = ov
}

// ── packers ──────────────────────────────────────────────────────────────────

// identifyELFPacker recognises UPX by its markers and otherwise reports the
// generic packed profile: no section table, an executable segment at
// compressed-data entropy and nothing for the dynamic loader to resolve.
func identifyELFPacker(e *ELF, data []byte) *Packer {
	var evidence []string
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if bytes.Contains(head, []byte("UPX!")) {
		evidence = append(evidence, "UPX! marker in the loader header")
	}
	if len(data) >= 36 && bytes.Contains(data[len(data)-36:], []byte("UPX!")) {
		evidence = append(evidence, "UPX! trailer")
	}
	if len(evidence) > 0 {
		// The copyright banner alone is not evidence: the upx binary itself
		// carries it as data. It only corroborates a marker.
		if bytes.Contains(data, []byte("$Info: This file is packed with the UPX")) {
			evidence = append(evidence, "UPX copyright string")
		}
		return &Packer{Name: "UPX", Evidence: evidence}
	}
	if e.Type != etExec && e.Type != etDyn {
		return nil
	}
	hiExec := false
	for _, s := range e.Segments {
		if s.Load() && s.Executable() && s.FileSize >= 1024 && s.Entropy > techMinEntropyExec {
			hiExec = true
		}
	}
	if e.NoSectionHeaders && hiExec && e.ImportCount == 0 {
		return &Packer{Name: "packed", Generic: true, Evidence: []string{
			"no section headers", "executable segment above 7.0 bits/byte", "nothing imported through the dynamic loader"}}
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// importSetHash is MD5 over the sorted, lower-cased, de-duplicated import
// names joined by ",". It is a clustering key for ELF files in the same
// spirit as imphash; it is not telfhash.
func importSetHash(names []string) string {
	if len(names) == 0 {
		return ""
	}
	set := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		l := strings.ToLower(n)
		if !seen[l] {
			seen[l] = true
			set = append(set, l)
		}
	}
	sort.Strings(set)
	sum := md5.Sum([]byte(strings.Join(set, ",")))
	return hex.EncodeToString(sum[:])
}

func splitPathList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ":")
	if len(parts) > 64 {
		parts = parts[:64]
	}
	return parts
}

func elfPerms(r, w, x uint64) string {
	b := []byte("---")
	if r != 0 {
		b[0] = 'r'
	}
	if w != 0 {
		b[1] = 'w'
	}
	if x != 0 {
		b[2] = 'x'
	}
	return string(b)
}

func align4(n int) int { return (n + 3) &^ 3 }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func elfTypeName(t uint16) string {
	switch t {
	case 0:
		return "none"
	case etRel:
		return "rel"
	case etExec:
		return "exec"
	case etDyn:
		return "dyn"
	case etCore:
		return "core"
	}
	if t >= 0xff00 {
		return fmt.Sprintf("processor-specific(0x%x)", t)
	}
	if t >= 0xfe00 {
		return fmt.Sprintf("os-specific(0x%x)", t)
	}
	return fmt.Sprintf("unknown(0x%x)", t)
}

func elfMachineName(m uint16) string {
	switch m {
	case 0:
		return "none"
	case 2:
		return "sparc"
	case 3:
		return "i386"
	case 8:
		return "mips"
	case 20:
		return "powerpc"
	case 21:
		return "powerpc64"
	case 22:
		return "s390"
	case 40:
		return "arm"
	case 42:
		return "superh"
	case 50:
		return "ia64"
	case 62:
		return "x86-64"
	case 183:
		return "aarch64"
	case 243:
		return "riscv"
	case 247:
		return "bpf"
	case 258:
		return "loongarch"
	}
	return fmt.Sprintf("machine-%d", m)
}

func osabiName(o uint8) string {
	switch o {
	case 0:
		return "sysv"
	case 1:
		return "hpux"
	case 2:
		return "netbsd"
	case 3:
		return "gnu"
	case 6:
		return "solaris"
	case 9:
		return "freebsd"
	case 12:
		return "openbsd"
	case 64:
		return "arm-aeabi"
	case 97:
		return "arm"
	case 255:
		return "standalone"
	}
	return fmt.Sprintf("osabi-%d", o)
}

func segmentTypeName(t uint32) string {
	switch t {
	case ptNull:
		return "NULL"
	case ptLoad:
		return "LOAD"
	case ptDynamic:
		return "DYNAMIC"
	case ptInterp:
		return "INTERP"
	case ptNote:
		return "NOTE"
	case ptPhdr:
		return "PHDR"
	case ptTLS:
		return "TLS"
	case 0x6474e550:
		return "GNU_EH_FRAME"
	case ptGNUStack:
		return "GNU_STACK"
	case ptGNURelro:
		return "GNU_RELRO"
	case 0x6474e553:
		return "GNU_PROPERTY"
	}
	return fmt.Sprintf("0x%x", t)
}

func sectionTypeName(t uint32) string {
	switch t {
	case shtNull:
		return "NULL"
	case shtProgbits:
		return "PROGBITS"
	case shtSymtab:
		return "SYMTAB"
	case shtStrtab:
		return "STRTAB"
	case 4:
		return "RELA"
	case 5:
		return "HASH"
	case 6:
		return "DYNAMIC"
	case shtNote:
		return "NOTE"
	case shtNobits:
		return "NOBITS"
	case 9:
		return "REL"
	case shtDynsym:
		return "DYNSYM"
	case 14:
		return "INIT_ARRAY"
	case 15:
		return "FINI_ARRAY"
	case 16:
		return "PREINIT_ARRAY"
	case 0x6ffffff6:
		return "GNU_HASH"
	case 0x6ffffffe:
		return "VERNEED"
	case 0x6fffffff:
		return "VERSYM"
	}
	return fmt.Sprintf("0x%x", t)
}

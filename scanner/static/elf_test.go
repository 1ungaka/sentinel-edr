package static

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
)

// ── synthetic ELF builder ────────────────────────────────────────────────────

// elfSecSpec is one content section; each becomes both a PT_LOAD segment and
// (unless the spec suppresses the table) a section header.
type elfSecSpec struct {
	name     string
	shflags  uint64 // SHF_*
	pflags   uint32 // PF_* for the segment
	data     []byte
	memExtra uint64 // extra memsz beyond the data (bss-like)
	vaddr    uint64 // 0 = identity mapping at base+offset
	shtype   uint32 // 0 = PROGBITS
}

// elfSpec describes a synthetic ELF image.
type elfSpec struct {
	class32   bool
	bigEndian bool
	typ       uint16
	machine   uint16
	entry     uint64 // 0 = first executable section/segment
	entryZero bool
	sections  []elfSecSpec
	// rawSegments are PT_LOAD segments without a section header.
	rawSegments []elfSecSpec
	noSections  bool
	shoffBad    bool
	interp      string
	gnuStack    *uint32
	needed      []string
	imports     []string
	exports     []string
	soname      string
	rpath       string
	runpath     string
	init        uint64
	// initArray slots hold their target VA directly (non-PIE style).
	initArray []uint64
	// initArrayRelative leaves slots zero and supplies each target through a
	// RELA R_*_RELATIVE relocation (PIE style).
	initArrayRelative []uint64
	// versionNeed emits one .gnu.version_r record per dependency.
	versionNeed map[string][]string
	textrel     bool
	pie         bool
	forceDyn    bool
	buildID     bool
	overlay     []byte
	appimage    bool
	// module fields apply to ET_REL
	modinfo      map[string]string
	thisModule   bool
	moduleSigned bool
	truncateTo   int // >0: cut the file to this many bytes after building
	upxMarker    bool
}

func pf(flags uint32) *uint32 { return &flags }

type elfSegOut struct {
	typ, flags           uint32
	off, vaddr, fsz, msz uint64
}

type elfSecOut struct {
	name            string
	typ             uint32
	flags           uint64
	addr, off, size uint64
	link, info      uint32
	entsize         uint64
}

func benignELFSpec() elfSpec {
	text := make([]byte, 4096)
	for i := range text {
		text[i] = byte(i*7%97) ^ 0x90 // low entropy, looks like code-ish bytes
	}
	data := bytes.Repeat([]byte("Hello, world\x00"), 64)
	return elfSpec{
		typ:     etDyn,
		machine: 62,
		sections: []elfSecSpec{
			{name: ".text", shflags: shfAlloc | shfExecinstr, pflags: pfR | pfX, data: text},
			{name: ".rodata", shflags: shfAlloc, pflags: pfR, data: data},
			{name: ".data", shflags: shfAlloc | shfWrite, pflags: pfR | pfW, data: data, memExtra: 4096},
		},
		interp:   "/lib64/ld-linux-x86-64.so.2",
		gnuStack: pf(pfR | pfW),
		needed:   []string{"libc.so.6"},
		imports:  []string{"__libc_start_main", "puts", "printf", "malloc", "free", "strlen", "__cxa_finalize"},
		pie:      true,
		buildID:  true,
	}
}

func buildELF(t *testing.T, spec elfSpec) []byte {
	t.Helper()
	is64 := !spec.class32
	var order binary.ByteOrder = binary.LittleEndian
	if spec.bigEndian {
		order = binary.BigEndian
	}
	ehsz, phent, shent := 64, 56, 64
	if !is64 {
		ehsz, phent, shent = 52, 32, 40
	}
	const base = uint64(0x400000)
	dyn := spec.forceDyn || spec.interp != "" || len(spec.imports) > 0 || len(spec.exports) > 0 || len(spec.needed) > 0 ||
		spec.soname != "" || spec.rpath != "" || spec.runpath != "" || spec.textrel || spec.init != 0 || spec.pie
	isRel := spec.typ == etRel

	phnum := 0
	if !isRel {
		phnum = len(spec.sections) + len(spec.rawSegments)
		if spec.interp != "" {
			phnum++
		}
		if dyn {
			phnum += 2 // LOAD for the dynamic blobs + PT_DYNAMIC
		}
		if spec.gnuStack != nil {
			phnum++
		}
		if spec.buildID {
			phnum++
		}
	}
	buf := make([]byte, ehsz+phnum*phent)
	place := func(b []byte) uint64 {
		for len(buf)%16 != 0 {
			buf = append(buf, 0)
		}
		off := uint64(len(buf))
		buf = append(buf, b...)
		return off
	}
	var segs []elfSegOut
	secs := []elfSecOut{{}} // null section
	entry := spec.entry

	addSection := func(s elfSecSpec) {
		off := place(s.data)
		va := base + off
		if s.vaddr != 0 {
			va = s.vaddr
		}
		if !isRel {
			segs = append(segs, elfSegOut{ptLoad, s.pflags, off, va, uint64(len(s.data)), uint64(len(s.data)) + s.memExtra})
		}
		typ := s.shtype
		if typ == 0 {
			typ = shtProgbits
		}
		secs = append(secs, elfSecOut{name: s.name, typ: typ, flags: s.shflags, addr: va, off: off, size: uint64(len(s.data))})
		if entry == 0 && s.pflags&pfX != 0 {
			entry = va
		}
	}
	for _, s := range spec.sections {
		addSection(s)
	}
	for _, s := range spec.rawSegments {
		off := place(s.data)
		va := base + off
		if s.vaddr != 0 {
			va = s.vaddr
		}
		segs = append(segs, elfSegOut{ptLoad, s.pflags, off, va, uint64(len(s.data)), uint64(len(s.data)) + s.memExtra})
		if entry == 0 && s.pflags&pfX != 0 {
			entry = va
		}
	}
	if spec.interp != "" {
		off := place(append([]byte(spec.interp), 0))
		segs = append(segs, elfSegOut{ptInterp, pfR, off, base + off, uint64(len(spec.interp) + 1), uint64(len(spec.interp) + 1)})
		secs = append(secs, elfSecOut{name: ".interp", typ: shtProgbits, flags: shfAlloc, addr: base + off, off: off, size: uint64(len(spec.interp) + 1)})
	}
	if dyn && !isRel {
		// dynstr
		strtab := []byte{0}
		strOff := func(s string) uint64 {
			o := uint64(len(strtab))
			strtab = append(strtab, []byte(s)...)
			strtab = append(strtab, 0)
			return o
		}
		var neededOffs []uint64
		for _, n := range spec.needed {
			neededOffs = append(neededOffs, strOff(n))
		}
		var sonameOff, rpathOff, runpathOff uint64
		if spec.soname != "" {
			sonameOff = strOff(spec.soname)
		}
		if spec.rpath != "" {
			rpathOff = strOff(spec.rpath)
		}
		if spec.runpath != "" {
			runpathOff = strOff(spec.runpath)
		}
		// .gnu.version_r blob. Assembled here, before the string table is
		// frozen by place(strtab) below, because its names index into dynstr.
		var verneedBlob []byte
		var verneedCount uint32
		if len(spec.versionNeed) > 0 {
			var files []string
			for f := range spec.versionNeed {
				files = append(files, f)
			}
			sort.Strings(files)
			for fi, f := range files {
				fileOff := strOff(f)
				vers := spec.versionNeed[f]
				vnRec := make([]byte, 16)
				order.PutUint16(vnRec[0:], 1)                 // vn_version
				order.PutUint16(vnRec[2:], uint16(len(vers))) // vn_cnt
				order.PutUint32(vnRec[4:], uint32(fileOff))   // vn_file
				order.PutUint32(vnRec[8:], 16)                // vn_aux -> first aux
				next := uint32(0)
				if fi < len(files)-1 {
					next = uint32(16 + len(vers)*16) // vn_next
				}
				order.PutUint32(vnRec[12:], next)
				verneedBlob = append(verneedBlob, vnRec...)
				for vi, v := range vers {
					vOff := strOff(v)
					aux := make([]byte, 16)
					order.PutUint32(aux[8:], uint32(vOff)) // vna_name
					auxNext := uint32(0)
					if vi < len(vers)-1 {
						auxNext = 16
					}
					order.PutUint32(aux[12:], auxNext) // vna_next
					verneedBlob = append(verneedBlob, aux...)
				}
			}
			verneedCount = uint32(len(files))
		}
		symEnt := 24
		if !is64 {
			symEnt = 16
		}
		var symtab []byte
		putSym := func(nameOff uint64, info uint8, shndx uint16, value uint64) {
			b := make([]byte, symEnt)
			order.PutUint32(b[0:], uint32(nameOff))
			if is64 {
				b[4] = info
				order.PutUint16(b[6:], shndx)
				order.PutUint64(b[8:], value)
			} else {
				order.PutUint32(b[4:], uint32(value))
				b[12] = info
				order.PutUint16(b[14:], shndx)
			}
			symtab = append(symtab, b...)
		}
		putSym(0, 0, 0, 0)
		for _, n := range spec.imports {
			putSym(strOff(n), stbGlobal<<4|sttFunc, shnUndef, 0)
		}
		for i, n := range spec.exports {
			putSym(strOff(n), stbGlobal<<4|sttFunc, 1, entry+uint64(i)*16)
		}
		nsyms := 1 + len(spec.imports) + len(spec.exports)
		hash := make([]byte, 8+4+4*nsyms)
		order.PutUint32(hash[0:], 1)
		order.PutUint32(hash[4:], uint32(nsyms))

		blobStart := uint64(len(buf))
		for blobStart%16 != 0 {
			blobStart++
		}
		strtabOff := place(strtab)
		symtabOff := place(symtab)
		hashOff := place(hash)

		ptr := 8
		if !is64 {
			ptr = 4
		}
		putPtr := func(b []byte, v uint64) {
			if is64 {
				order.PutUint64(b, v)
			} else {
				order.PutUint32(b, uint32(v))
			}
		}
		// .init_array: direct-value slots, then relative-reloc (zero) slots.
		var initArrayOff, initArrayVA, initArraySz uint64
		var relaOff, relaVA, relaSz uint64
		if len(spec.initArray)+len(spec.initArrayRelative) > 0 {
			slots := make([]byte, (len(spec.initArray)+len(spec.initArrayRelative))*ptr)
			for i, v := range spec.initArray {
				putPtr(slots[i*ptr:], v)
			}
			// relative slots stay zero
			initArrayOff = place(slots)
			initArrayVA = base + initArrayOff
			initArraySz = uint64(len(slots))
			if len(spec.initArrayRelative) > 0 {
				relaEnt := ptr * 3
				rela := make([]byte, len(spec.initArrayRelative)*relaEnt)
				for i, target := range spec.initArrayRelative {
					b := rela[i*relaEnt:]
					slotVA := initArrayVA + uint64(len(spec.initArray)+i)*uint64(ptr)
					putPtr(b[0:], slotVA)         // r_offset
					putPtr(b[ptr:], rRelativeX86) // r_info: type only, sym 0
					putPtr(b[2*ptr:], target)     // r_addend = target VA
				}
				relaOff = place(rela)
				relaVA = base + relaOff
				relaSz = uint64(len(rela))
			}
		}
		// .gnu.version_r blob (assembled above).
		var verneedOff, verneedVA, verneedSz uint64
		if len(verneedBlob) > 0 {
			verneedOff = place(verneedBlob)
			verneedVA = base + verneedOff
			verneedSz = uint64(len(verneedBlob))
		}

		var dynamic []byte
		dynEnt := 16
		if !is64 {
			dynEnt = 8
		}
		putDyn := func(tag, val uint64) {
			b := make([]byte, dynEnt)
			if is64 {
				order.PutUint64(b[0:], tag)
				order.PutUint64(b[8:], val)
			} else {
				order.PutUint32(b[0:], uint32(tag))
				order.PutUint32(b[4:], uint32(val))
			}
			dynamic = append(dynamic, b...)
		}
		for _, o := range neededOffs {
			putDyn(dtNeeded, o)
		}
		if spec.soname != "" {
			putDyn(dtSoname, sonameOff)
		}
		if spec.rpath != "" {
			putDyn(dtRpath, rpathOff)
		}
		if spec.runpath != "" {
			putDyn(dtRunpath, runpathOff)
		}
		putDyn(dtStrtab, base+strtabOff)
		putDyn(dtStrsz, uint64(len(strtab)))
		putDyn(dtSymtab, base+symtabOff)
		putDyn(dtSyment, uint64(symEnt))
		putDyn(dtHash, base+hashOff)
		if initArraySz > 0 {
			putDyn(dtInitArray, initArrayVA)
			putDyn(dtInitArraysz, initArraySz)
		}
		if relaSz > 0 {
			putDyn(dtRela, relaVA)
			putDyn(dtRelaSz, relaSz)
			putDyn(dtRelaEnt, uint64(ptr*3))
		}
		if spec.init != 0 {
			putDyn(dtInit, spec.init)
		}
		if spec.textrel {
			putDyn(dtTextrel, 0)
		}
		if spec.pie {
			putDyn(dtFlags1, df1PIE)
		}
		putDyn(dtNull, 0)
		dynOff := place(dynamic)
		blobEnd := uint64(len(buf))
		segs = append(segs, elfSegOut{ptLoad, pfR | pfW, blobStart, base + blobStart, blobEnd - blobStart, blobEnd - blobStart})
		segs = append(segs, elfSegOut{ptDynamic, pfR | pfW, dynOff, base + dynOff, uint64(len(dynamic)), uint64(len(dynamic))})
		dynstrIdx := uint32(len(secs))
		secs = append(secs, elfSecOut{name: ".dynstr", typ: shtStrtab, flags: shfAlloc, addr: base + strtabOff, off: strtabOff, size: uint64(len(strtab))})
		secs = append(secs, elfSecOut{name: ".dynsym", typ: shtDynsym, flags: shfAlloc, addr: base + symtabOff, off: symtabOff, size: uint64(len(symtab)), link: dynstrIdx, entsize: uint64(symEnt)})
		secs = append(secs, elfSecOut{name: ".hash", typ: 5, flags: shfAlloc, addr: base + hashOff, off: hashOff, size: uint64(len(hash)), link: dynstrIdx - 1})
		secs = append(secs, elfSecOut{name: ".dynamic", typ: 6, flags: shfAlloc | shfWrite, addr: base + dynOff, off: dynOff, size: uint64(len(dynamic)), link: dynstrIdx, entsize: uint64(dynEnt)})
		if initArraySz > 0 {
			secs = append(secs, elfSecOut{name: ".init_array", typ: 14, flags: shfAlloc | shfWrite, addr: initArrayVA, off: initArrayOff, size: initArraySz, entsize: uint64(ptr)})
		}
		if relaSz > 0 {
			secs = append(secs, elfSecOut{name: ".rela.dyn", typ: 4, flags: shfAlloc, addr: relaVA, off: relaOff, size: relaSz, link: dynstrIdx + 1, entsize: uint64(ptr * 3)})
		}
		if verneedSz > 0 {
			secs = append(secs, elfSecOut{name: ".gnu.version_r", typ: shtGNUVerneed, flags: shfAlloc, addr: verneedVA, off: verneedOff, size: verneedSz, link: dynstrIdx, info: verneedCount})
		}
	}
	if spec.gnuStack != nil && !isRel {
		segs = append(segs, elfSegOut{ptGNUStack, *spec.gnuStack, 0, 0, 0, 0})
	}
	if spec.buildID {
		note := make([]byte, 12+4+20)
		order.PutUint32(note[0:], 4)
		order.PutUint32(note[4:], 20)
		order.PutUint32(note[8:], ntGNUBuildID)
		copy(note[12:], "GNU\x00")
		for i := 0; i < 20; i++ {
			note[16+i] = byte(0xa0 + i)
		}
		off := place(note)
		if !isRel {
			segs = append(segs, elfSegOut{ptNote, pfR, off, base + off, uint64(len(note)), uint64(len(note))})
		}
		secs = append(secs, elfSecOut{name: ".note.gnu.build-id", typ: shtNote, flags: shfAlloc, addr: base + off, off: off, size: uint64(len(note))})
	}
	if isRel {
		if spec.modinfo != nil {
			var mi []byte
			for k, v := range spec.modinfo {
				mi = append(mi, []byte(k+"="+v)...)
				mi = append(mi, 0)
			}
			off := place(mi)
			secs = append(secs, elfSecOut{name: ".modinfo", typ: shtProgbits, flags: shfAlloc, off: off, size: uint64(len(mi))})
		}
		if spec.thisModule {
			off := place(make([]byte, 64))
			secs = append(secs, elfSecOut{name: ".gnu.linkonce.this_module", typ: shtProgbits, flags: shfAlloc | shfWrite, off: off, size: 64})
		}
		if len(spec.imports) > 0 {
			strtab := []byte{0}
			symEnt := 24
			if !is64 {
				symEnt = 16
			}
			symtab := make([]byte, symEnt)
			for _, n := range spec.imports {
				o := len(strtab)
				strtab = append(strtab, []byte(n)...)
				strtab = append(strtab, 0)
				b := make([]byte, symEnt)
				order.PutUint32(b[0:], uint32(o))
				if is64 {
					b[4] = stbGlobal<<4 | sttFunc
				} else {
					b[12] = stbGlobal<<4 | sttFunc
				}
				symtab = append(symtab, b...)
			}
			strOff := place(strtab)
			symOff := place(symtab)
			strIdx := uint32(len(secs))
			secs = append(secs, elfSecOut{name: ".strtab", typ: shtStrtab, off: strOff, size: uint64(len(strtab))})
			secs = append(secs, elfSecOut{name: ".symtab", typ: shtSymtab, off: symOff, size: uint64(len(symtab)), link: strIdx, entsize: uint64(symEnt)})
		}
	}

	// Section header table.
	shoff, shnum, shstrndx := uint64(0), 0, 0
	if !spec.noSections {
		shstr := []byte{0}
		nameOffs := make([]uint32, len(secs))
		for i, s := range secs {
			if s.name == "" {
				continue
			}
			nameOffs[i] = uint32(len(shstr))
			shstr = append(shstr, []byte(s.name)...)
			shstr = append(shstr, 0)
		}
		shstrndx = len(secs)
		nameOffs = append(nameOffs, uint32(len(shstr)))
		shstr = append(shstr, []byte(".shstrtab")...)
		shstr = append(shstr, 0)
		shstrOff := place(shstr)
		secs = append(secs, elfSecOut{name: ".shstrtab", typ: shtStrtab, off: shstrOff, size: uint64(len(shstr))})
		shnum = len(secs)
		table := make([]byte, shnum*shent)
		for i, s := range secs {
			b := table[i*shent:]
			order.PutUint32(b[0:], nameOffs[i])
			order.PutUint32(b[4:], s.typ)
			if is64 {
				order.PutUint64(b[8:], s.flags)
				order.PutUint64(b[16:], s.addr)
				order.PutUint64(b[24:], s.off)
				order.PutUint64(b[32:], s.size)
				order.PutUint32(b[40:], s.link)
				order.PutUint32(b[44:], s.info)
				order.PutUint64(b[48:], 1)
				order.PutUint64(b[56:], s.entsize)
			} else {
				order.PutUint32(b[8:], uint32(s.flags))
				order.PutUint32(b[12:], uint32(s.addr))
				order.PutUint32(b[16:], uint32(s.off))
				order.PutUint32(b[20:], uint32(s.size))
				order.PutUint32(b[24:], s.link)
				order.PutUint32(b[28:], s.info)
				order.PutUint32(b[32:], 1)
				order.PutUint32(b[36:], uint32(s.entsize))
			}
		}
		shoff = place(table)
		if spec.shoffBad {
			shoff = 0x7fffff00
		}
	}
	if len(spec.overlay) > 0 {
		buf = append(buf, spec.overlay...)
	}
	if spec.moduleSigned {
		sig := bytes.Repeat([]byte{0x30}, 64)
		hdr := make([]byte, 12)
		binary.BigEndian.PutUint32(hdr[8:], uint32(len(sig)))
		buf = append(buf, sig...)
		buf = append(buf, hdr...)
		buf = append(buf, []byte(moduleSignatureMarker)...)
	}

	// ELF header.
	copy(buf, "\x7fELF")
	if is64 {
		buf[4] = elfClass64
	} else {
		buf[4] = elfClass32
	}
	if spec.bigEndian {
		buf[5] = elfData2M
	} else {
		buf[5] = elfData2L
	}
	buf[6] = 1
	if spec.appimage {
		copy(buf[8:], "AI\x02")
	}
	if spec.entryZero {
		entry = 0
	}
	order.PutUint16(buf[16:], spec.typ)
	order.PutUint16(buf[18:], spec.machine)
	order.PutUint32(buf[20:], 1)
	phoff := uint64(ehsz)
	if phnum == 0 {
		phoff = 0
	}
	if is64 {
		order.PutUint64(buf[24:], entry)
		order.PutUint64(buf[32:], phoff)
		order.PutUint64(buf[40:], shoff)
		order.PutUint16(buf[52:], uint16(ehsz))
		order.PutUint16(buf[54:], uint16(phent))
		order.PutUint16(buf[56:], uint16(phnum))
		order.PutUint16(buf[58:], uint16(shent))
		order.PutUint16(buf[60:], uint16(shnum))
		order.PutUint16(buf[62:], uint16(shstrndx))
	} else {
		order.PutUint32(buf[24:], uint32(entry))
		order.PutUint32(buf[28:], uint32(phoff))
		order.PutUint32(buf[32:], uint32(shoff))
		order.PutUint16(buf[40:], uint16(ehsz))
		order.PutUint16(buf[42:], uint16(phent))
		order.PutUint16(buf[44:], uint16(phnum))
		order.PutUint16(buf[46:], uint16(shent))
		order.PutUint16(buf[48:], uint16(shnum))
		order.PutUint16(buf[50:], uint16(shstrndx))
	}
	for i, s := range segs {
		b := buf[ehsz+i*phent:]
		order.PutUint32(b[0:], s.typ)
		if is64 {
			order.PutUint32(b[4:], s.flags)
			order.PutUint64(b[8:], s.off)
			order.PutUint64(b[16:], s.vaddr)
			order.PutUint64(b[24:], s.vaddr)
			order.PutUint64(b[32:], s.fsz)
			order.PutUint64(b[40:], s.msz)
			order.PutUint64(b[48:], 16)
		} else {
			order.PutUint32(b[4:], uint32(s.off))
			order.PutUint32(b[8:], uint32(s.vaddr))
			order.PutUint32(b[12:], uint32(s.vaddr))
			order.PutUint32(b[16:], uint32(s.fsz))
			order.PutUint32(b[20:], uint32(s.msz))
			order.PutUint32(b[24:], s.flags)
			order.PutUint32(b[28:], 16)
		}
	}
	if spec.upxMarker {
		// l_info sits right after the program headers in a real UPX image.
		copy(buf[ehsz+phnum*phent:], "UPX!")
	}
	if spec.truncateTo > 0 && spec.truncateTo < len(buf) {
		buf = buf[:spec.truncateTo]
	}
	return buf
}

func classesOf(r *Result) map[string]int {
	out := map[string]int{}
	for _, a := range r.Anomalies {
		out[a.Class] = a.Score
	}
	return out
}

// ── parser ───────────────────────────────────────────────────────────────────

func TestParseBenignELF(t *testing.T) {
	data := buildELF(t, benignELFSpec())
	if !IsELF(data) || IsPE(data) {
		t.Fatal("identity bytes not recognised")
	}
	e, err := ParseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	if e.Class != "elf64" || e.ByteOrder != "little" || e.TypeName != "dyn" || e.MachineName != "x86-64" {
		t.Errorf("header = %+v", e)
	}
	if e.Interp != "/lib64/ld-linux-x86-64.so.2" || !e.IsPIE || e.Static || !e.HasDynamic {
		t.Errorf("interp=%q pie=%v static=%v dyn=%v", e.Interp, e.IsPIE, e.Static, e.HasDynamic)
	}
	if len(e.Needed) != 1 || e.Needed[0] != "libc.so.6" {
		t.Errorf("needed = %v", e.Needed)
	}
	if e.ImportCount != 7 || len(e.Imports) != 7 || e.Imports[1] != "puts" {
		t.Errorf("imports = %d %v", e.ImportCount, e.Imports)
	}
	if e.EntrySection != ".text" || e.EntrySegment != 0 || !e.Segments[0].Entry || !e.Sections[1].Entry {
		t.Errorf("entry: section=%q segment=%d", e.EntrySection, e.EntrySegment)
	}
	if e.BuildID != "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3" || len(e.Notes) != 1 {
		t.Errorf("build id = %q notes=%v", e.BuildID, e.Notes)
	}
	if !e.StackPresent || e.StackExecutable {
		t.Errorf("stack = present %v exec %v", e.StackPresent, e.StackExecutable)
	}
	if e.Overlay.Size != 0 || e.Packer != nil || e.Module != nil || e.NoSectionHeaders {
		t.Errorf("unexpected extras: %+v %+v %+v", e.Overlay, e.Packer, e.Module)
	}
	if len(e.Warnings) != 0 {
		t.Errorf("warnings = %v", e.Warnings)
	}
	if e.ImportHash == "" || e.ImportHash != importSetHash(e.Imports) {
		t.Errorf("import hash = %q", e.ImportHash)
	}
	names := map[string]bool{}
	for _, s := range e.Sections {
		names[s.Name] = true
	}
	for _, want := range []string{".text", ".rodata", ".data", ".interp", ".dynstr", ".dynsym", ".dynamic", ".shstrtab", ".note.gnu.build-id"} {
		if !names[want] {
			t.Errorf("section %s missing from %v", want, names)
		}
	}
	r := Analyze(data, Options{NoFuzzy: true})
	if !r.IsELF || r.IsPE || r.ELF == nil || r.Score != 0 || r.Detected() {
		t.Errorf("benign analysis: elf=%v score=%d anomalies=%+v", r.IsELF, r.Score, r.Anomalies)
	}
	if r.ImportHash() != e.ImportHash || len(r.ImportNames()) != 7 {
		t.Errorf("result import accessors: %q %v", r.ImportHash(), r.ImportNames())
	}
}

func TestParseELF32BigEndian(t *testing.T) {
	spec := benignELFSpec()
	spec.class32, spec.bigEndian, spec.machine, spec.interp = true, true, 20, "/lib/ld.so.1"
	data := buildELF(t, spec)
	e, err := ParseELF(data)
	if err != nil {
		t.Fatal(err)
	}
	if e.Class != "elf32" || e.ByteOrder != "big" || e.MachineName != "powerpc" || e.Interp != "/lib/ld.so.1" {
		t.Errorf("header = %+v", e)
	}
	if e.ImportCount != 7 || e.Needed[0] != "libc.so.6" || e.EntrySection != ".text" || e.BuildID == "" {
		t.Errorf("content: imports=%d needed=%v entry=%q buildid=%q", e.ImportCount, e.Needed, e.EntrySection, e.BuildID)
	}
	if r := Analyze(data, Options{NoFuzzy: true}); r.Score != 0 {
		t.Errorf("score = %d: %+v", r.Score, r.Anomalies)
	}
}

func TestELFSymbolCountFromHashWithoutSections(t *testing.T) {
	spec := benignELFSpec()
	spec.noSections = true
	e, err := ParseELF(buildELF(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	if !e.NoSectionHeaders || e.ImportCount != 7 {
		t.Errorf("no-sections parse: headers-missing=%v imports=%d warnings=%v", e.NoSectionHeaders, e.ImportCount, e.Warnings)
	}
}

// ── anomalies ────────────────────────────────────────────────────────────────

func TestELFAnomalies(t *testing.T) {
	rnd := randomBytes(t, 8192)
	lowEntropy := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 13)
		}
		return b
	}
	cases := []struct {
		name   string
		mutate func(s *elfSpec)
		want   []string // classes that must be present with a positive score
		absent []string
		detect bool
	}{
		{"rwx segment", func(s *elfSpec) { s.sections[0].pflags = pfR | pfW | pfX }, []string{"segment.rwx"}, nil, false},
		{"packed exec segment", func(s *elfSpec) { s.sections[0].data = rnd[:4096] }, []string{"segment.exec-high-entropy"}, nil, false},
		{"unpack target", func(s *elfSpec) { s.sections[0].memExtra = 1 << 20 }, []string{"segment.virtual-raw-mismatch"}, nil, false},
		{"no section headers", func(s *elfSpec) { s.noSections = true }, []string{"section.headers-missing"}, nil, false},
		{".text not executable", func(s *elfSpec) { s.sections[0].shflags = shfAlloc }, []string{"section.name-perm-mismatch"}, nil, false},
		{".data executable", func(s *elfSpec) { s.sections[2].shflags |= shfExecinstr }, []string{"section.name-perm-mismatch"}, nil, false},
		{"odd exec section name", func(s *elfSpec) { s.sections[0].name = "code" }, []string{"section.exec-unusual-name"}, nil, false},
		{"entry outside segments", func(s *elfSpec) { s.entry = 0x1 }, []string{"entrypoint.outside-segments"}, nil, false},
		{"entry in data", func(s *elfSpec) { s.entry = 0x400000 + 64 + 56*8 + 4096 + 64 }, []string{"entrypoint.non-exec-segment"}, nil, false},
		{"entry zero exec", func(s *elfSpec) { s.typ = etExec; s.entryZero = true }, []string{"entrypoint.zero"}, nil, false},
		{"exec stack", func(s *elfSpec) { s.gnuStack = pf(pfR | pfW | pfX) }, []string{"segment.exec-stack"}, nil, false},
		{"no gnu stack", func(s *elfSpec) { s.gnuStack = nil }, []string{"segment.no-gnu-stack"}, nil, false},
		{"odd interp", func(s *elfSpec) { s.interp = "/tmp/.x/ld.so" }, []string{"dynamic.interp-unusual"}, nil, false},
		{"insecure runpath", func(s *elfSpec) { s.runpath = "/tmp/lib:/usr/lib" }, []string{"dynamic.rpath-insecure"}, nil, false},
		{"empty rpath component", func(s *elfSpec) { s.rpath = "/usr/lib::/opt/x/lib" }, []string{"dynamic.rpath-insecure"}, nil, false},
		{"origin runpath is fine", func(s *elfSpec) { s.runpath = "$ORIGIN/../lib" }, []string{"dynamic.rpath"}, []string{"dynamic.rpath-insecure"}, false},
		{"needed by path", func(s *elfSpec) { s.needed = append(s.needed, "/tmp/evil.so") }, []string{"dynamic.needed-path"}, nil, false},
		{"textrel", func(s *elfSpec) { s.textrel = true }, []string{"dynamic.textrel"}, nil, false},
		{"init outside code", func(s *elfSpec) { s.init = 0x400000 + 64 + 56*8 + 4096 + 64 }, []string{"dynamic.init-outside-code"}, nil, false},
		{"no imports with loader", func(s *elfSpec) { s.imports = nil }, []string{"imports.none"}, nil, false},
		{"loader-only imports", func(s *elfSpec) { s.imports = []string{"dlopen", "dlsym", "mprotect", "__libc_start_main"} }, []string{"imports.loader-only"}, []string{"imports.minimal"}, false},
		{"minimal imports", func(s *elfSpec) { s.imports = []string{"__libc_start_main", "puts", "__cxa_finalize"} }, []string{"imports.minimal"}, nil, false},
		{"preload interposer", func(s *elfSpec) {
			s.interp, s.pie = "", false
			s.exports = []string{"readdir", "readdir64", "fopen", "open", "accept"}
			s.imports = []string{"dlsym", "strcmp", "strstr", "fopen", "readdir"}
		}, []string{"dynamic.preload-interposer"}, nil, false},
		{"known interposer", func(s *elfSpec) {
			s.interp, s.pie = "", false
			s.soname = "libfakeroot-0.so"
			s.exports = []string{"readdir", "open", "stat", "__xstat"}
			s.imports = []string{"dlsym", "strcmp", "strstr", "fopen", "readdir"}
		}, []string{"dynamic.preload-interposer-known"}, []string{"dynamic.preload-interposer"}, false},
		{"exports without dlsym are not interposition", func(s *elfSpec) {
			s.interp, s.pie = "", false
			s.exports = []string{"readdir", "open", "stat"}
			s.imports = []string{"strcmp", "strstr", "memcpy", "strlen", "malloc"}
		}, nil, []string{"dynamic.preload-interposer"}, false},
		{"high-entropy overlay", func(s *elfSpec) { s.overlay = rnd }, []string{"overlay.high-entropy"}, nil, false},
		{"plain overlay", func(s *elfSpec) { s.overlay = lowEntropy(2048) }, []string{"overlay.present"}, nil, false},
		{"appimage", func(s *elfSpec) { s.overlay = rnd; s.appimage = true }, []string{"overlay.appimage"}, []string{"overlay.high-entropy"}, false},
		{"section table outside file", func(s *elfSpec) { s.shoffBad = true }, []string{"format.section-table-invalid"}, nil, false},
		{"truncated", func(s *elfSpec) { s.truncateTo = 64 + 56*8 + 2000 }, []string{"format.truncated"}, nil, false},
		{"class/machine mismatch", func(s *elfSpec) { s.class32 = true }, []string{"header.class-machine-mismatch"}, nil, false},
		{"upx marker", func(s *elfSpec) { s.upxMarker = true }, []string{"packer.upx"}, nil, false},
		{"generic packed profile", func(s *elfSpec) {
			s.sections = nil
			s.rawSegments = []elfSecSpec{{pflags: pfR | pfW, data: lowEntropy(4096), memExtra: 1 << 20}, {pflags: pfR | pfX, data: rnd[:4096]}}
			s.noSections, s.interp, s.needed, s.imports, s.pie, s.buildID = true, "", nil, nil, false, false
		}, []string{"packer.generic", "section.headers-missing", "segment.exec-high-entropy"}, []string{"imports.none"}, true},
		{"hand-built dropper", func(s *elfSpec) {
			s.sections[0].pflags = pfR | pfW | pfX
			s.sections[0].data = rnd[:4096]
			s.interp = "/tmp/.x/ld.so"
			s.imports = []string{"dlopen", "dlsym"}
		}, []string{"segment.rwx", "segment.exec-high-entropy", "dynamic.interp-unusual", "imports.loader-only"}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := benignELFSpec()
			tc.mutate(&spec)
			data := buildELF(t, spec)
			r := Analyze(data, Options{NoFuzzy: true})
			if !r.IsELF {
				t.Fatalf("not parsed as ELF: %s", r.ParseError)
			}
			got := classesOf(r)
			for _, w := range tc.want {
				if _, ok := got[w]; !ok {
					t.Errorf("missing %s; got %v", w, got)
				}
			}
			for _, a := range tc.absent {
				if _, ok := got[a]; ok {
					t.Errorf("unexpected %s; got %v", a, got)
				}
			}
			if r.Detected() != tc.detect {
				t.Errorf("detected = %v (score %d, threshold %d): %v", r.Detected(), r.Score, r.EffectiveThreshold(), got)
			}
			for _, a := range r.Anomalies {
				if a.Score > 0 && a.Category == CatInfo {
					t.Errorf("scored anomaly in the Info category: %+v", a)
				}
			}
		})
	}
}

func TestELFKernelModule(t *testing.T) {
	spec := elfSpec{typ: etRel, machine: 62,
		sections:   []elfSecSpec{{name: ".text", shflags: shfAlloc | shfExecinstr, data: make([]byte, 512)}},
		modinfo:    map[string]string{"name": "evil", "vermagic": "6.1.0 SMP mod_unload", "license": "Proprietary"},
		thisModule: true, imports: []string{"kallsyms_lookup_name", "register_kprobe", "printk"}}
	r := Analyze(buildELF(t, spec), Options{NoFuzzy: true})
	e := r.ELF
	if e == nil || e.Module == nil || e.Module.Name != "evil" || e.Module.Vermagic != "6.1.0 SMP mod_unload" || e.Module.Signed {
		t.Fatalf("module = %+v", e)
	}
	if e.ImportCount != 3 || e.Imports[0] != "kallsyms_lookup_name" {
		t.Errorf("module imports = %v", e.Imports)
	}
	got := classesOf(r)
	for _, w := range []string{"module.kernel", "module.unsigned", "module.license-proprietary"} {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if _, ok := got["format.program-table-invalid"]; ok {
		t.Errorf("relocatable object reported as missing segments: %v", got)
	}
	if r.Detected() {
		t.Errorf("an unsigned proprietary module alone must not cross the threshold: %d", r.Score)
	}

	spec.moduleSigned = true
	r = Analyze(buildELF(t, spec), Options{NoFuzzy: true})
	if !r.ELF.Module.Signed || r.ELF.Module.SignatureBytes != 64+12+len(moduleSignatureMarker) {
		t.Errorf("signed module = %+v", r.ELF.Module)
	}
	if r.ELF.Overlay.Size != 0 || r.ELF.Overlay.CertificateBytes == 0 {
		t.Errorf("signature must be separated from the overlay: %+v", r.ELF.Overlay)
	}
	if got := classesOf(r); got["module.unsigned"] != 0 {
		t.Errorf("signed module still reported unsigned: %v", got)
	}

	spec.modinfo = nil
	r = Analyze(buildELF(t, spec), Options{NoFuzzy: true})
	if got := classesOf(r); got["module.info-missing"] == 0 {
		t.Errorf("module without .modinfo: %v", got)
	}
}

// ── hostile input ────────────────────────────────────────────────────────────

func TestELFMalformedNeverPanics(t *testing.T) {
	bases := [][]byte{buildELF(t, benignELFSpec())}
	spec := benignELFSpec()
	spec.class32 = true
	spec.machine = 3
	bases = append(bases, buildELF(t, spec))
	if real, err := os.ReadFile("/usr/bin/ls"); err == nil && IsELF(real) {
		bases = append(bases, real)
	}
	rng := rand.New(rand.NewSource(7))
	for _, base := range bases {
		// Truncations at every boundary that matters plus a sweep.
		for _, n := range []int{0, 3, 4, 16, 51, 52, 63, 64, 65, 120, 400, len(base) / 2, len(base) - 1} {
			if n < len(base) {
				Analyze(base[:n], Options{NoFuzzy: true})
			}
		}
		// Bit flips in the headers (where offsets and counts live) and
		// random bytes anywhere.
		for i := 0; i < 1500; i++ {
			m := append([]byte(nil), base...)
			flips := 1 + rng.Intn(6)
			for f := 0; f < flips; f++ {
				var pos int
				if rng.Intn(3) == 0 {
					pos = rng.Intn(len(m))
				} else {
					pos = rng.Intn(minInt(len(m), 1024))
				}
				switch rng.Intn(3) {
				case 0:
					m[pos] ^= 1 << uint(rng.Intn(8))
				case 1:
					m[pos] = 0xff
				default:
					m[pos] = byte(rng.Intn(256))
				}
			}
			r := Analyze(m, Options{NoFuzzy: true})
			if r.Error != nil {
				t.Fatalf("Analyze returned an error on in-memory data: %v", r.Error)
			}
		}
	}
	// Synthetic worst cases: every count and offset at its maximum.
	h := make([]byte, 64)
	copy(h, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(h[16:], etExec)
	binary.LittleEndian.PutUint64(h[32:], 0xffffffffffffff00)
	binary.LittleEndian.PutUint64(h[40:], 0xffffffffffffff00)
	binary.LittleEndian.PutUint16(h[54:], 0xffff)
	binary.LittleEndian.PutUint16(h[56:], 0xffff)
	binary.LittleEndian.PutUint16(h[58:], 0xffff)
	binary.LittleEndian.PutUint16(h[60:], 0xffff)
	binary.LittleEndian.PutUint16(h[62:], 0xffff)
	r := Analyze(h, Options{NoFuzzy: true})
	if !r.IsELF || r.ELF.ProgramTableInvalid == "" {
		t.Errorf("hostile header: elf=%v %+v", r.IsELF, r.ELF)
	}
	if got := classesOf(r); got["format.program-table-invalid"] == 0 {
		t.Errorf("hostile header classes = %v", got)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func TestInterpUnusual(t *testing.T) {
	ok := []string{"/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux.so.2", "/lib/ld-musl-x86_64.so.1", "/lib/ld-linux-aarch64.so.1",
		"/lib/ld-linux-armhf.so.3", "/usr/lib/ld-linux-x86-64.so.2", "/libexec/ld-elf.so.1", "/lib64/ld64.so.2", "/system/bin/linker64",
		"/nix/store/abc123-glibc-2.39/lib/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2", "/libx32/ld-linux-x32.so.2"}
	bad := []string{"/tmp/.x/ld.so", "ld-linux-x86-64.so.2", "/lib64/loader", "/home/u/ld-linux-x86-64.so.2", "/usr/lib/libc.so.6", "/dev/shm/ld-2.31.so", "/opt/ld.so", ""}
	for _, p := range ok {
		if interpUnusual(p) {
			t.Errorf("%q flagged as unusual", p)
		}
	}
	for _, p := range bad {
		if !interpUnusual(p) {
			t.Errorf("%q accepted as a system loader", p)
		}
	}
}

func TestInsecureRPaths(t *testing.T) {
	if got := insecureRPaths([]string{"/usr/lib", "$ORIGIN/../lib", "${ORIGIN}", "$LIB/x", "/opt/app/lib"}); len(got) != 0 {
		t.Errorf("safe paths flagged: %v", got)
	}
	got := insecureRPaths([]string{"", ".", "lib", "/tmp/x", "/var/tmp", "/dev/shm/l", "/home/u/lib", "/tmpfoo"})
	if len(got) != 7 {
		t.Errorf("insecure = %v", got)
	}
	if got := insecureRPaths(make([]string, 20)); len(got) != 7 || !strings.HasPrefix(got[6], "+") {
		t.Errorf("bounding = %v", got)
	}
}

func TestImportSetHash(t *testing.T) {
	a := importSetHash([]string{"puts", "Printf", "malloc"})
	b := importSetHash([]string{"malloc", "printf", "puts", "PUTS"})
	if a == "" || a != b || len(a) != 32 {
		t.Errorf("hash not order/case/duplicate invariant: %q %q", a, b)
	}
	if importSetHash(nil) != "" {
		t.Error("empty import set must hash to empty")
	}
}

func TestModuleSignatureSize(t *testing.T) {
	if moduleSignatureSize([]byte("short")) != 0 {
		t.Error("short input")
	}
	body := append(bytes.Repeat([]byte{1}, 100), make([]byte, 12)...)
	binary.BigEndian.PutUint32(body[100+8:], 50)
	body = append(body, []byte(moduleSignatureMarker)...)
	if got := moduleSignatureSize(body); got != 50+12+len(moduleSignatureMarker) {
		t.Errorf("size = %d", got)
	}
	binary.BigEndian.PutUint32(body[100+8:], 1<<30) // lies about its length
	if got := moduleSignatureSize(body); got != 12+len(moduleSignatureMarker) {
		t.Errorf("oversized claim = %d", got)
	}
}

// ── real binaries (skipped when absent) ──────────────────────────────────────

func TestRealELFSanity(t *testing.T) {
	for _, p := range []string{"/usr/bin/ls", "/bin/ls", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"} {
		data, err := os.ReadFile(p)
		if err != nil || !IsELF(data) {
			continue
		}
		r := Analyze(data, Options{NoFuzzy: true})
		if !r.IsELF || r.ELF == nil {
			t.Fatalf("%s: not parsed: %s", p, r.ParseError)
		}
		e := r.ELF
		if e.ImportCount < 10 || len(e.Warnings) != 0 || e.BuildID == "" || e.NoSectionHeaders {
			t.Errorf("%s: imports=%d warnings=%v buildid=%q", p, e.ImportCount, e.Warnings, e.BuildID)
		}
		if strings.Contains(p, "libc") && e.ExportCount < 1000 {
			t.Errorf("%s: exports=%d", p, e.ExportCount)
		}
		if r.Score != 0 {
			t.Errorf("%s: score %d: %v", p, r.Score, classesOf(r))
		}
	}
}

// ── corpus fixtures ──────────────────────────────────────────────────────────

// TestWriteELFFixtures regenerates the synthetic ELF samples of the smoke
// corpus byte-for-byte when CAU_WRITE_ELF_FIXTURES names an absolute directory. It is
// skipped otherwise; the corpus manifest pins the SHA-256 of what it writes.
//
//	CAU_WRITE_ELF_FIXTURES=$PWD/corpus/smoke go test ./scanner/static/ -run TestWriteELFFixtures
func TestWriteELFFixtures(t *testing.T) {
	dir := os.Getenv("CAU_WRITE_ELF_FIXTURES")
	if dir == "" {
		t.Skip("CAU_WRITE_ELF_FIXTURES not set")
	}
	// Deterministic "packed" bytes: a fixed-seed generator, not crypto/rand,
	// so the fixture is reproducible.
	rng := rand.New(rand.NewSource(0x43415545)) // "CAUE"
	packed := make([]byte, 4096)
	rng.Read(packed)

	benign := benignELFSpec()
	dropper := benignELFSpec()
	dropper.sections[0].pflags = pfR | pfW | pfX
	dropper.sections[0].data = packed
	dropper.interp = "/tmp/.x/ld.so"
	dropper.imports = []string{"dlopen", "dlsym", "mprotect", "__libc_start_main"}
	dropper.buildID = false

	for _, f := range []struct {
		rel    string
		spec   elfSpec
		detect bool
	}{
		{"benign/hello_elf.bin", benign, false},
		{"malicious/elf_dropper_profile.bin", dropper, true},
	} {
		data := buildELF(t, f.spec)
		r := Analyze(data, Options{NoFuzzy: true})
		if r.Detected() != f.detect {
			t.Fatalf("%s: detected=%v score=%d %v", f.rel, r.Detected(), r.Score, classesOf(r))
		}
		path := dir + "/" + f.rel
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes, static score %d)", path, len(data), r.Score)
	}
}

// TestParseELFSymtabTinyEntsize is the regression for the parseSymbols
// out-of-bounds read: a relocatable object whose .symtab declares a 1-byte
// sh_entsize while the parser reads a fixed 24-byte Elf64_Sym. With the
// symbol table placed at end-of-file, the pre-fix per-entry guard
// (p+entsize <= len) passed while the field read (b[0:4], b[6:8]) ran past
// the buffer and panicked. ParseELF must not panic and must skip the
// malformed table.
func TestParseELFSymtabTinyEntsize(t *testing.T) {
	const (
		shentsize = 64
		shnum     = 4 // null, .symtab, .strtab, .shstrtab
	)
	le := binary.LittleEndian

	// Fixed regions first, so the symtab can sit at EOF.
	header := make([]byte, 64)
	shtab := make([]byte, shnum*shentsize)
	shstr := append([]byte{0}, []byte(".symtab\x00.strtab\x00.shstrtab\x00")...)
	strtab := append([]byte{0}, []byte("evil_func\x00")...)

	shoff := uint64(len(header))
	shstrOff := shoff + uint64(len(shtab))
	strOff := shstrOff + uint64(len(shstr))
	symOff := strOff + uint64(len(strtab))
	symSize := uint64(40) // 40 one-byte "entries"; last read starts at EOF-1
	total := symOff + symSize

	// Name offsets into shstr: .symtab=1, .strtab=9, .shstrtab=17.
	putSec := func(idx int, nameOff, typ uint32, off, size uint64, link, entsize uint64) {
		b := shtab[idx*shentsize:]
		le.PutUint32(b[0:], nameOff)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], uint32(link))
		le.PutUint64(b[56:], entsize)
	}
	putSec(1, 1, shtSymtab, symOff, symSize, 2 /*.strtab*/, 1 /*tiny entsize*/)
	putSec(2, 9, shtStrtab, strOff, uint64(len(strtab)), 0, 0)
	putSec(3, 17, shtStrtab, shstrOff, uint64(len(shstr)), 0, 0)

	// ELF64 header.
	copy(header[0:], []byte{0x7f, 'E', 'L', 'F', 2 /*64*/, 1 /*LE*/, 1})
	le.PutUint16(header[16:], etRel)
	le.PutUint16(header[18:], 62) // x86-64
	le.PutUint32(header[20:], 1)
	le.PutUint64(header[40:], shoff)
	le.PutUint16(header[52:], 64) // e_ehsize
	le.PutUint16(header[58:], shentsize)
	le.PutUint16(header[60:], shnum)
	le.PutUint16(header[62:], 3) // e_shstrndx

	buf := make([]byte, 0, total)
	buf = append(buf, header...)
	buf = append(buf, shtab...)
	buf = append(buf, shstr...)
	buf = append(buf, strtab...)
	buf = append(buf, make([]byte, symSize)...)
	if uint64(len(buf)) != total {
		t.Fatalf("layout mismatch: built %d want %d", len(buf), total)
	}

	// Must not panic (a defer-recover makes the failure a clear test error
	// rather than a crashed test binary).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseELF panicked on a tiny-entsize .symtab: %v", r)
		}
	}()
	e, err := ParseELF(buf)
	if err != nil {
		t.Fatalf("ParseELF errored instead of skipping the bad table: %v", err)
	}
	if e.ImportCount != 0 || len(e.Imports) != 0 {
		t.Errorf("malformed .symtab should yield no imports, got count=%d %v", e.ImportCount, e.Imports)
	}
	// Analyze must stay panic-free on the same bytes.
	_ = Analyze(buf, Options{NoFuzzy: true})
}

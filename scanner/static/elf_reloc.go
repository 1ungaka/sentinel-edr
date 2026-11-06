package static

import (
	"sort"
	"strings"

	"github.com/glaslos/tlsh"
)

// This file closes four of the ELF pass's documented gaps: telfhash, pointer
// resolution through relocations (so .init_array / .preinit_array targets are
// recovered, not just counted), symbol-version reading, and the raw-syscall
// tell for a loader or interposer that reaches the kernel without libc.

// ── telfhash ───────────────────────────────────────────────────────────────

// telfhashExcluded applies Trend Micro telfhash's symbol exclusions, before
// lower-casing exactly as the reference does: eight common runtime names, and
// names beginning with "_" or ".", ending in "64", or beginning with "str" or
// "mem" (the families that are too common to carry family signal).
func telfhashExcluded(name string) bool {
	switch name {
	case "__libc_start_main", "main", "abort", "cachectl", "cacheflush", "puts", "atol", "malloc_trim":
		return true
	}
	if name[0] == '_' || name[0] == '.' {
		return true
	}
	if strings.HasSuffix(name, "64") {
		return true
	}
	if strings.HasPrefix(name, "str") || strings.HasPrefix(name, "mem") {
		return true
	}
	return false
}

// telfhash returns the telfhash digest for the collected symbol names. The
// names arrive already lower-cased and past telfhashExcluded; telfhash sorts
// them, keeps duplicates, joins with ",", drops non-ASCII, and TLSH-hashes the
// result. It is compatible with the reference for any input TLSH can digest.
// The reference uses forcehash for shorter inputs; this TLSH library has no
// forcehash, so a symbol set under TLSH's 50-byte floor yields no digest and a
// note instead (telfhash's own empty sentinel is "-").
func telfhash(names []string) (string, string) {
	if len(names) == 0 {
		return "", "no global default-visibility functions after telfhash filtering"
	}
	sort.Strings(names)
	joined := asciiOnly(strings.Join(names, ","))
	t, err := tlsh.HashBytes([]byte(joined))
	if err != nil {
		return "", "symbol set too short or uniform for TLSH (" + err.Error() + "); telfhash's forcehash is unavailable in this library"
	}
	return strings.ToUpper(t.String()), ""
}

// asciiOnly drops bytes outside printable ASCII, mirroring telfhash's
// encode("ascii", "ignore"). Symbol names are ASCII in practice; this only
// guards a hostile table.
func asciiOnly(s string) string {
	if isASCII(s) {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x80 {
			b = append(b, s[i])
		}
	}
	return string(b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ── relocations and init-array resolution ───────────────────────────────────

// relativeRelocType is the R_<arch>_RELATIVE relocation type for the file's
// machine, or 0 when this resolver does not know the architecture. A RELATIVE
// relocation is the loader instruction "store (base + addend) here", which is
// how a PIE's otherwise-zero pointer slots are filled.
func (e *ELF) relativeRelocType() uint32 {
	switch e.Machine {
	case 3, 62: // i386, x86-64
		return rRelativeX86
	case 183: // aarch64
		return rRelativeAArch64
	case 40: // arm
		return rRelativeARM
	case 243: // riscv
		return rRelativeRISCV
	}
	return 0
}

// relativeAddends walks the RELA/REL/JMPREL tables and returns a map from a
// relocation's target virtual address to the virtual address a R_*_RELATIVE
// relocation writes there. Only RELATIVE relocations carry a resolvable value
// in the file; symbol-based relocations depend on load-time symbol lookup and
// are left for the slot's own file value (0) to report as unresolved.
func (e *ELF) relativeAddends(data []byte) map[uint64]uint64 {
	relType := e.relativeRelocType()
	if relType == 0 {
		return nil
	}
	out := map[uint64]uint64{}
	ptr := 4
	if e.is64 {
		ptr = 8
	}
	// RELA: r_offset, r_info, r_addend. The addend is the target VA.
	rela := func(va, sz, ent uint64) {
		if va == 0 || sz == 0 {
			return
		}
		want := uint64(ptr) * 3
		if ent == 0 {
			ent = want
		}
		if ent < want {
			e.warn("RELA entry size %d is below the %d byte minimum", ent, want)
			return
		}
		base, ok := e.vaToOffset(va)
		if !ok {
			return
		}
		n := sz / ent
		if n > maxELFRelocs {
			n = maxELFRelocs
		}
		for i := uint64(0); i < n; i++ {
			// i*ent cannot wrap (i < sz/ent), but base+int(i*ent) can.
			if i*ent > uint64(len(data)) {
				break
			}
			p := base + int(i*ent)
			if p+int(want) > len(data) {
				break
			}
			rOffset := e.word(data[p:])
			rInfo := e.word(data[p+ptr:])
			addend := e.word(data[p+2*ptr:])
			if relocType(rInfo, e.is64) == relType {
				out[rOffset] = addend
			}
		}
	}
	// REL: r_offset, r_info. No addend — the target lives in the slot the
	// relocation points at, which for RELATIVE is the VA itself.
	rel := func(va, sz, ent uint64) {
		if va == 0 || sz == 0 {
			return
		}
		want := uint64(ptr) * 2
		if ent == 0 {
			ent = want
		}
		if ent < want {
			e.warn("REL entry size %d is below the %d byte minimum", ent, want)
			return
		}
		base, ok := e.vaToOffset(va)
		if !ok {
			return
		}
		n := sz / ent
		if n > maxELFRelocs {
			n = maxELFRelocs
		}
		for i := uint64(0); i < n; i++ {
			// i*ent cannot wrap (i < sz/ent), but base+int(i*ent) can.
			if i*ent > uint64(len(data)) {
				break
			}
			p := base + int(i*ent)
			if p+int(want) > len(data) {
				break
			}
			rOffset := e.word(data[p:])
			rInfo := e.word(data[p+ptr:])
			if relocType(rInfo, e.is64) != relType {
				continue
			}
			if slot, ok := e.vaToOffset(rOffset); ok && slot+ptr <= len(data) {
				out[rOffset] = e.word(data[slot:])
			}
		}
	}
	rela(e.relaVA, e.relaSz, e.relaEnt)
	rel(e.relVA, e.relSz, e.relEnt)
	// DT_JMPREL is RELA or REL per DT_PLTREL; it rarely targets .init_array
	// but is cheap to fold in.
	if e.pltRel == dtRela {
		rela(e.jmprelVA, e.pltRelSz, e.relaEnt)
	} else if e.pltRel == dtRel {
		rel(e.jmprelVA, e.pltRelSz, e.relEnt)
	}
	return out
}

// word reads one native-width, native-order pointer from b.
func (e *ELF) word(b []byte) uint64 {
	if e.is64 {
		return e.order.Uint64(b)
	}
	return uint64(e.order.Uint32(b))
}

// relocType extracts the type field from r_info (low byte on 32-bit, low word
// on 64-bit).
func relocType(info uint64, is64 bool) uint32 {
	if is64 {
		return uint32(info & 0xffffffff)
	}
	return uint32(info & 0xff)
}

// resolveInitArray recovers the function pointers in .init_array and
// .preinit_array and records where each one lands. The slot value is the
// target in a non-PIE image; in a PIE the slot is zero and a R_*_RELATIVE
// relocation supplies the address, so the resolver consults the relocation
// map it built from the dynamic tables.
func (e *ELF) resolveInitArray(data []byte) {
	if e.initArrayVA == 0 && e.preinitVA == 0 {
		return
	}
	var addends map[uint64]uint64
	ptr := uint64(4)
	if e.is64 {
		ptr = 8
	}
	resolveSlot := func(slotVA uint64) (uint64, string) {
		off, ok := e.vaToOffset(slotVA)
		if !ok || off+int(ptr) > len(data) {
			return 0, "unresolved"
		}
		if v := e.word(data[off:]); v != 0 {
			return v, "file"
		}
		if addends == nil {
			addends = e.relativeAddends(data)
		}
		if v, ok := addends[slotVA]; ok {
			return v, "relative-reloc"
		}
		return 0, "unresolved"
	}
	walk := func(name string, va, sz uint64) {
		if va == 0 || sz == 0 {
			return
		}
		n := sz / ptr
		for i := uint64(0); i < n && len(e.InitArrayTargets) < maxELFPointers; i++ {
			slotVA := va + i*ptr
			target, src := resolveSlot(slotVA)
			p := ELFPointer{Array: name, VA: target, Source: src}
			if src != "unresolved" {
				p.Section, p.Executable = e.locateVA(target)
			}
			e.InitArrayTargets = append(e.InitArrayTargets, p)
		}
	}
	walk(".preinit_array", e.preinitVA, e.preinitSz)
	walk(".init_array", e.initArrayVA, e.initArraySz)
}

// locateVA names the allocated section containing va and reports whether that
// section (or, when no section table survives, the mapping segment) is
// executable.
func (e *ELF) locateVA(va uint64) (string, bool) {
	for _, s := range e.Sections {
		if s.Alloc() && s.Size > 0 && va >= s.Addr && va-s.Addr < s.Size {
			return s.Name, s.Executable()
		}
	}
	if idx := e.segmentIndexForVA(va); idx >= 0 {
		return "", e.Segments[idx].Executable()
	}
	return "", false
}

// ── symbol versions ──────────────────────────────────────────────────────────

// parseVersions reads the GNU symbol-version sections: .gnu.version_r
// (requirements, e.g. GLIBC_2.34 from libc.so.6) and .gnu.version_d (the
// versions this object itself defines). It needs the section table and the
// dynamic string table; without either it records nothing.
func (e *ELF) parseVersions(data []byte) {
	if len(e.Sections) == 0 {
		return
	}
	r := e.order
	str := func(sec *ELFSection, off uint32) string {
		if sec == nil {
			return ""
		}
		so, ss, ok := e.fileRange(sec.Offset, sec.Size)
		if !ok || uint64(off) >= uint64(ss) {
			return ""
		}
		return cstring(data, so+int(off), maxNameLen)
	}
	strtabOf := func(link uint32) *ELFSection {
		if uint64(link) < uint64(len(e.Sections)) {
			return &e.Sections[link]
		}
		return nil
	}

	for i := range e.Sections {
		s := &e.Sections[i]
		switch s.Type {
		case shtGNUVerneed:
			off, sz, ok := e.fileRange(s.Offset, s.Size)
			if !ok {
				continue
			}
			strs := strtabOf(s.Link)
			p := off
			for recs := 0; recs < maxELFVersions && p >= off && p+16 <= off+sz; recs++ {
				vnCnt := int(r.Uint16(data[p+2:]))
				vnFile := r.Uint32(data[p+4:])
				vnAux := int(r.Uint32(data[p+8:]))
				vnNext := int(r.Uint32(data[p+12:]))
				need := ELFVersionNeed{File: str(strs, vnFile)}
				ap := p + vnAux
				for a := 0; a < vnCnt && a < maxELFVersions && ap >= off && ap+16 <= off+sz; a++ {
					vnaName := r.Uint32(data[ap+8:])
					vnaNext := int(r.Uint32(data[ap+12:]))
					if v := str(strs, vnaName); v != "" {
						need.Versions = append(need.Versions, v)
					}
					if vnaNext <= 0 {
						break
					}
					ap += vnaNext
				}
				if need.File != "" || len(need.Versions) > 0 {
					e.VersionsNeeded = append(e.VersionsNeeded, need)
				}
				if vnNext <= 0 {
					break
				}
				p += vnNext
			}
		case shtGNUVerdef:
			off, sz, ok := e.fileRange(s.Offset, s.Size)
			if !ok {
				continue
			}
			strs := strtabOf(s.Link)
			p := off
			for recs := 0; recs < maxELFVersions && p >= off && p+20 <= off+sz; recs++ {
				vdFlags := r.Uint16(data[p+2:])
				vdCnt := int(r.Uint16(data[p+6:]))
				vdAux := int(r.Uint32(data[p+12:]))
				vdNext := int(r.Uint32(data[p+16:]))
				// vd_flags bit 0x1 is VER_FLG_BASE: the object's own soname, not
				// a defined version. Its first aux name is skipped.
				ap := p + vdAux
				for a := 0; a < vdCnt && a < maxELFVersions && ap >= off && ap+8 <= off+sz; a++ {
					vdaName := r.Uint32(data[ap:])
					vdaNext := int(r.Uint32(data[ap+4:]))
					if v := str(strs, vdaName); v != "" && (a > 0 || vdFlags&0x1 == 0) {
						e.VersionsDefined = append(e.VersionsDefined, v)
					}
					if vdaNext <= 0 {
						break
					}
					ap += vdaNext
				}
				if vdNext <= 0 {
					break
				}
				p += vdNext
			}
		}
	}
	e.VersionsDefined = dedupe(e.VersionsDefined)
}

// ── syscall stubs ─────────────────────────────────────────────────────────────

// scanSyscalls counts raw system-call instructions in the executable regions
// of an image. It is bounded by maxSyscallScan and only recognises the three
// architectures interposer and loader rootkits are written for; other machines
// leave the count at zero (and the rule that reads it simply does not fire).
func (e *ELF) scanSyscalls(data []byte) {
	if e.Type != etExec && e.Type != etDyn {
		return
	}
	scanned := 0
	count := func(buf []byte) {
		e.SyscallStubs += countSyscalls(buf, e.Machine)
	}
	// Prefer executable sections; fall back to executable PT_LOAD segments
	// when the section table is gone (stripped / packed).
	used := false
	for _, s := range e.Sections {
		if !s.Executable() || s.NoBits() || s.Size == 0 {
			continue
		}
		off, sz, ok := e.fileRange(s.Offset, s.Size)
		if !ok {
			continue
		}
		if scanned+sz > maxSyscallScan {
			sz = maxSyscallScan - scanned
		}
		if sz <= 0 {
			break
		}
		count(data[off : off+sz])
		scanned += sz
		used = true
	}
	if used {
		return
	}
	for _, s := range e.Segments {
		if !s.Load() || !s.Executable() {
			continue
		}
		off, sz, ok := e.fileRange(s.Offset, s.FileSize)
		if !ok {
			continue
		}
		if scanned+sz > maxSyscallScan {
			sz = maxSyscallScan - scanned
		}
		if sz <= 0 {
			break
		}
		count(data[off : off+sz])
		scanned += sz
	}
}

// countSyscalls counts the architecture's kernel-entry instruction in buf.
// x86-64 "syscall" (0f 05) and i386 "int 0x80" (cd 80) / "sysenter" (0f 34)
// are byte patterns; aarch64 "svc #0" (d4000001) is read at 4-byte alignment
// to avoid counting the pattern inside unrelated operands.
func countSyscalls(buf []byte, machine uint16) int {
	n := 0
	switch machine {
	case 62: // x86-64
		for i := 0; i+1 < len(buf); i++ {
			if buf[i] == 0x0f && buf[i+1] == 0x05 {
				n++
			}
		}
	case 3: // i386
		for i := 0; i+1 < len(buf); i++ {
			if buf[i] == 0xcd && buf[i+1] == 0x80 {
				n++
			} else if buf[i] == 0x0f && buf[i+1] == 0x34 {
				n++
			}
		}
	case 183: // aarch64, little-endian svc #0 == d4000001
		for i := 0; i+4 <= len(buf); i += 4 {
			if buf[i] == 0x01 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0xd4 {
				n++
			}
		}
	}
	return n
}

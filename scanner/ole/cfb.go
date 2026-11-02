// Package ole detects malicious VBA-macro tradecraft in legacy-Office documents
// stored as OLE Compound File Binary ([MS-CFB]) containers carrying VBA macros
// ([MS-OVBA]) — the macro-dropper vector behind countless phishing lures (a
// .doc/.xls whose auto-executing macro shells out to an interpreter or pulls a
// stage-two payload).
//
// It is DETECTION ONLY. Nothing here creates, weaponises or executes a macro;
// every signal is read out of the public file format and from published abuse
// tradecraft, derived from bytes a scanner already has.
//
// The parser is defensive by construction. It walks the compound file through
// bounds-checked accessors, caps every declared size, caps the number of
// sectors and directory entries it will visit, detects FAT / MiniFAT chain
// cycles with a visited-set, caps the total bytes it will resolve and the total
// decompressed output, and returns a partial result with a warning rather than
// panicking, hanging or allocating unbounded memory on a truncated or
// adversarial file.
//
// This file implements the [MS-CFB] side: the header, the DIFAT, the FAT, the
// directory and the MiniFAT / mini-stream, plus bounded stream resolution. The
// detector enumerates directory entries FLATLY (an array walk over the directory
// stream) rather than walking the red-black tree, skipping unallocated entries.
// A flat walk is sufficient for name / type / stream-content detection and side-
// steps any tree-cycle concerns entirely.
package ole

import "unicode/utf16"

// The OLE/CFB header signature — "D0 CF 11 E0 A1 B1 1A E1".
var oleSignature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Directory entry object types ([MS-CFB] 2.6.1).
const (
	objUnknown byte = 0
	objStorage byte = 1
	objStream  byte = 2
	objRoot    byte = 5
)

// Special FAT sector values ([MS-CFB] 2.2).
const (
	maxRegSect uint32 = 0xFFFFFFFA // highest valid regular sector number
	difSect    uint32 = 0xFFFFFFFC // DIFAT sector
	fatSect    uint32 = 0xFFFFFFFD // FAT sector
	endOfChain uint32 = 0xFFFFFFFE // end of a sector chain
	freeSect   uint32 = 0xFFFFFFFF // unallocated sector
	noStream   uint32 = 0xFFFFFFFF // "no sibling / child" in the directory
)

// Parser caps. Every one bounds the work the parser will do regardless of what
// the (attacker-controlled) header and directory declare.
const (
	oleHeaderSize      = 512      // the fixed header size for both versions
	defaultMiniCutoff  = 4096     // mini-stream cutoff ([MS-CFB] default)
	maxDirEntries      = 8192     // directory entries parsed before giving up
	maxTotalFATEntries = 1 << 22  // FAT / MiniFAT entries accumulated (16M)
	maxDIFATSectors    = 1 << 16  // DIFAT sectors followed
	maxStreamBytes     = 16 << 20 // bytes resolved for a single stream
	maxResolvedBytes   = 64 << 20 // bytes resolved across all streams in a file
)

// cfbEntry is one directory entry the detector reasons about.
type cfbEntry struct {
	name    string
	objType byte
	start   uint32 // starting sector (regular FAT, or mini FAT for small streams)
	size    uint64
}

// cfbFile is a parsed (best-effort) compound file.
type cfbFile struct {
	data         []byte
	sectorSize   int
	miniSectorSz int
	miniCutoff   uint32

	fat        []uint32
	miniFat    []uint32
	miniStream []byte
	entries    []cfbEntry

	resolved int // running total of bytes resolved, against maxResolvedBytes
	warning  string
}

func (f *cfbFile) warn(msg string) {
	if f.warning == "" {
		f.warning = msg
	}
}

// IsOLE reports whether the buffer begins with the compound-file signature.
func IsOLE(data []byte) bool {
	if len(data) < len(oleSignature) {
		return false
	}
	for i := range oleSignature {
		if data[i] != oleSignature[i] {
			return false
		}
	}
	return true
}

// ── bounds-checked little-endian accessors ─────────────────────────────────────
//
// Each returns zero on an out-of-range offset rather than panicking. The parser
// only reads inside sectors it has already range-checked, so these guards are a
// belt-and-suspenders second line of defence.

func le16(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return uint16(b[off]) | uint16(b[off+1])<<8
}

func le32(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// sectorOffset maps a sector number to its byte offset in the file, or ok=false
// when that sector would fall outside the data. Sector N lives at (N+1)*size —
// the first sector follows the header sector for both the 512- and 4096-byte
// layouts.
func (f *cfbFile) sectorOffset(sector uint32) (int, bool) {
	if sector >= maxRegSect {
		return 0, false
	}
	off := (int(sector) + 1) * f.sectorSize
	if off < 0 || off+f.sectorSize > len(f.data) {
		return 0, false
	}
	return off, true
}

// parseCFB parses data defensively and always returns a non-nil *cfbFile. On a
// problem it records a warning and returns whatever parsed.
func parseCFB(data []byte) *cfbFile {
	f := &cfbFile{data: data, sectorSize: 512, miniSectorSz: 64, miniCutoff: defaultMiniCutoff}
	if !IsOLE(data) {
		f.warn("not an OLE compound file")
		return f
	}
	if len(data) < oleHeaderSize {
		f.warn("truncated header")
		return f
	}

	sectorShift := le16(data, 30)
	if sectorShift != 9 && sectorShift != 12 {
		f.warn("unsupported sector shift")
		return f
	}
	f.sectorSize = 1 << sectorShift

	miniShift := le16(data, 32)
	if miniShift < 2 || int(miniShift) >= sectorShiftInt(sectorShift) {
		miniShift = 6 // MS-CFB default (64-byte mini sectors)
	}
	f.miniSectorSz = 1 << miniShift

	// The file must hold at least the header sector plus one data sector.
	if f.sectorSize <= 0 || f.sectorSize*2 > len(data) {
		f.warn("file smaller than one sector")
		return f
	}

	firstDir := le32(data, 48)
	if cutoff := le32(data, 56); cutoff != 0 && cutoff <= (1<<24) {
		f.miniCutoff = cutoff
	}
	firstMiniFat := le32(data, 60)
	firstDifat := le32(data, 68)

	difat := f.readDIFAT(firstDifat)
	f.readFAT(difat)
	if len(f.fat) == 0 {
		f.warn("empty or unreadable FAT")
		return f
	}

	f.parseDirectory(firstDir)

	// The root entry's chain in the regular FAT is the mini stream; small
	// streams are addressed within it via the MiniFAT.
	if len(f.entries) > 0 && f.entries[0].objType == objRoot {
		root := f.entries[0]
		f.miniStream = f.readRegular(root.start, root.size)
	}
	f.miniFat = f.readUint32Chain(firstMiniFat)

	return f
}

func sectorShiftInt(s uint16) int { return int(s) }

// readDIFAT assembles the Double-Indirect FAT: the 109 entries in the header,
// then any that follow in DIFAT sectors. The DIFAT-sector walk is cycle-safe and
// capped.
func (f *cfbFile) readDIFAT(firstDifat uint32) []uint32 {
	difat := make([]uint32, 0, 109)
	for i := 0; i < 109; i++ {
		difat = append(difat, le32(f.data, 76+i*4))
	}
	perSector := f.sectorSize / 4
	if perSector < 1 {
		return difat
	}
	visited := make(map[uint32]struct{})
	cur := firstDifat
	for steps := 0; steps < maxDIFATSectors; steps++ {
		if cur == endOfChain || cur == freeSect || cur >= maxRegSect {
			break
		}
		if _, seen := visited[cur]; seen {
			f.warn("cyclic DIFAT chain")
			break
		}
		visited[cur] = struct{}{}
		off, ok := f.sectorOffset(cur)
		if !ok {
			f.warn("DIFAT sector out of range")
			break
		}
		for i := 0; i < perSector-1; i++ {
			difat = append(difat, le32(f.data, off+i*4))
		}
		cur = le32(f.data, off+(perSector-1)*4)
		if len(difat) > maxTotalFATEntries {
			f.warn("DIFAT too large")
			break
		}
	}
	return difat
}

// readFAT concatenates the FAT sectors named by the DIFAT. Sector locations that
// are free or out of range are skipped; the total is capped.
func (f *cfbFile) readFAT(difat []uint32) {
	perSector := f.sectorSize / 4
	for _, fatSecLoc := range difat {
		if fatSecLoc == freeSect || fatSecLoc >= maxRegSect {
			continue
		}
		off, ok := f.sectorOffset(fatSecLoc)
		if !ok {
			f.warn("FAT sector out of range")
			continue
		}
		for i := 0; i < perSector; i++ {
			f.fat = append(f.fat, le32(f.data, off+i*4))
			if len(f.fat) >= maxTotalFATEntries {
				f.warn("FAT too large")
				return
			}
		}
	}
}

// chain walks a regular-FAT sector chain from start. It is cycle-safe (a
// visited-set plus a hard step cap of the FAT length) and never returns a sector
// outside the FAT.
func (f *cfbFile) chain(start uint32) []uint32 {
	var out []uint32
	visited := make(map[uint32]struct{})
	cur := start
	maxSteps := len(f.fat) + 1
	for steps := 0; steps < maxSteps; steps++ {
		if cur == endOfChain || cur >= maxRegSect {
			break
		}
		if int(cur) >= len(f.fat) {
			f.warn("FAT chain index out of range")
			break
		}
		if _, seen := visited[cur]; seen {
			f.warn("cyclic FAT chain")
			break
		}
		visited[cur] = struct{}{}
		out = append(out, cur)
		cur = f.fat[cur]
	}
	return out
}

// readUint32Chain resolves a regular-FAT chain and reads its sectors as a flat
// array of little-endian uint32 — used for the MiniFAT.
func (f *cfbFile) readUint32Chain(start uint32) []uint32 {
	sectors := f.chain(start)
	perSector := f.sectorSize / 4
	out := make([]uint32, 0, len(sectors)*perSector)
	for _, s := range sectors {
		off, ok := f.sectorOffset(s)
		if !ok {
			break
		}
		for i := 0; i < perSector; i++ {
			out = append(out, le32(f.data, off+i*4))
			if len(out) >= maxTotalFATEntries {
				return out
			}
		}
	}
	return out
}

// parseDirectory walks the directory stream (a regular-FAT chain) and parses its
// fixed 128-byte entries into the flat f.entries slice. Entry count is capped and
// unallocated / unknown entries are skipped.
func (f *cfbFile) parseDirectory(firstDir uint32) {
	const entrySize = 128
	sectors := f.chain(firstDir)
	perSector := f.sectorSize / entrySize
	if perSector < 1 {
		f.warn("sector too small for a directory entry")
		return
	}
	count := 0
	for _, s := range sectors {
		off, ok := f.sectorOffset(s)
		if !ok {
			break
		}
		for i := 0; i < perSector; i++ {
			if count >= maxDirEntries {
				f.warn("directory entry cap reached")
				return
			}
			count++
			base := off + i*entrySize
			objType := f.data[base+66]
			if objType != objStorage && objType != objStream && objType != objRoot {
				continue // unallocated / unknown
			}
			nameLen := le16(f.data, base+64)
			name := decodeDirName(f.data[base:base+64], nameLen)
			start := le32(f.data, base+116)
			size := uint64(le32(f.data, base+120)) | uint64(le32(f.data, base+124))<<32
			f.entries = append(f.entries, cfbEntry{name: name, objType: objType, start: start, size: size})
		}
	}
}

// decodeDirName decodes a directory entry name: UTF-16LE, nameLen bytes
// INCLUDING the terminating null. nameLen is clamped to the 64-byte field.
func decodeDirName(b []byte, nameLen uint16) string {
	n := int(nameLen)
	if n < 2 || n > 64 {
		n = 64 // tolerate a bogus length by scanning the whole field
	}
	u := make([]uint16, 0, n/2)
	for i := 0; i+1 < n && i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// readEntry resolves a directory entry's bytes, choosing the MiniFAT path for a
// small stream and the regular FAT otherwise. Totals are capped globally.
func (f *cfbFile) readEntry(e cfbEntry) []byte {
	if e.size == 0 || f.resolved >= maxResolvedBytes {
		return nil
	}
	var out []byte
	if e.objType == objStream && e.size < uint64(f.miniCutoff) {
		out = f.readMini(e.start, e.size)
	} else {
		out = f.readRegular(e.start, e.size)
	}
	f.resolved += len(out)
	return out
}

// readRegular resolves a regular-FAT chain up to size bytes.
func (f *cfbFile) readRegular(start uint32, size uint64) []byte {
	if size > maxStreamBytes {
		size = maxStreamBytes
		f.warn("stream size capped")
	}
	sectors := f.chain(start)
	capHint := len(sectors) * f.sectorSize
	if int(size) < capHint {
		capHint = int(size)
	}
	buf := make([]byte, 0, capHint)
	for _, s := range sectors {
		off, ok := f.sectorOffset(s)
		if !ok {
			break
		}
		buf = append(buf, f.data[off:off+f.sectorSize]...)
		if uint64(len(buf)) >= size {
			break
		}
	}
	if uint64(len(buf)) > size {
		buf = buf[:size]
	}
	return buf
}

// readMini resolves a MiniFAT chain within the mini stream up to size bytes. It
// is cycle-safe and bounded by the mini stream's length.
func (f *cfbFile) readMini(start uint32, size uint64) []byte {
	if size > maxStreamBytes {
		size = maxStreamBytes
		f.warn("stream size capped")
	}
	msz := f.miniSectorSz
	if msz <= 0 {
		return nil
	}
	var buf []byte
	visited := make(map[uint32]struct{})
	cur := start
	maxSteps := len(f.miniFat) + 1
	for steps := 0; steps < maxSteps; steps++ {
		if cur == endOfChain || cur >= maxRegSect {
			break
		}
		if int(cur) >= len(f.miniFat) {
			f.warn("MiniFAT index out of range")
			break
		}
		if _, seen := visited[cur]; seen {
			f.warn("cyclic MiniFAT chain")
			break
		}
		visited[cur] = struct{}{}
		off := int(cur) * msz
		if off < 0 || off+msz > len(f.miniStream) {
			f.warn("mini sector out of range")
			break
		}
		buf = append(buf, f.miniStream[off:off+msz]...)
		if uint64(len(buf)) >= size {
			break
		}
		cur = f.miniFat[cur]
	}
	if uint64(len(buf)) > size {
		buf = buf[:size]
	}
	return buf
}

package iso

// iso9660.go — a defensive, enumeration-only ISO 9660 reader.
//
// It parses the Volume Descriptor Set and walks the directory tree to list the
// names, attributes and sizes of the contained entries. It NEVER reads file
// content, creates an image, or executes anything; it only enumerates the
// container shape a scanner already has in memory.
//
// The walk is bounded by construction: every sector and record access is
// range-checked, declared sizes are capped, recursion is replaced by an
// explicit queue with a depth cap, and a visited-set of extent LBAs makes a
// self-referential or shared extent terminate instead of looping. On any
// problem it records a warning and returns what it managed to enumerate.

import (
	"strings"
	"unicode/utf16"
)

// On-disk geometry and layout constants from the public ISO 9660 format.
const (
	sectorSize    = 2048                  // logical sector / block size this reader assumes
	vdSetLBA      = 16                    // the Volume Descriptor Set begins at sector 16
	vdSetOffset   = vdSetLBA * sectorSize // 0x8000
	stdIdentifier = "CD001"               // the standard identifier at descriptor offset 1

	vdTypeBoot          = 0
	vdTypePrimary       = 1
	vdTypeSupplementary = 2
	vdTypeTerminator    = 255

	volumeIDOffset  = 40  // Volume Identifier, 32 d-characters (PVD)
	escapeSeqOffset = 88  // Escape Sequences field, 32 bytes (SVD)
	rootRecOffset   = 156 // Directory Record for the root directory
	rootRecLen      = 34  // its fixed length (identifier length 1)

	// Directory Record field offsets.
	recExtentLE  = 2  // Location of Extent, both-endian uint32 (LE half here)
	recDataLenLE = 10 // Data Length, both-endian uint32 (LE half here)
	recFlags     = 25 // File Flags
	recFileIDLen = 32 // Length of File Identifier
	recFileID    = 33 // File Identifier bytes start here

	// File Flags bits used by the enumerator.
	flagHidden = 0x01 // existence (hidden) bit
	flagDir    = 0x02 // directory bit
)

// Work caps. These bound the enumerator's time and memory regardless of how
// adversarial the declared sizes are, so a malformed image can never hang,
// recurse without end, allocate without bound, or read out of range.
const (
	maxVolDescriptors = 32    // volume descriptors scanned at the start of the set
	maxDirRecords     = 50000 // total directory records parsed before giving up
	maxDepth          = 16    // directory-tree recursion depth
	maxSectorsRead    = 65536 // total directory-extent sectors read
	maxExtentSectors  = 8192  // sectors read from any single directory extent
	maxEntries        = 50000 // entries retained in the enumeration
	maxDirsQueued     = 20000 // directory extents queued for the walk
)

// jolietEscapes are the UCS-2 level escape sequences that mark a Joliet
// Supplementary Volume Descriptor: %/@, %/C and %/E.
var jolietEscapes = [][]byte{
	{0x25, 0x2F, 0x40},
	{0x25, 0x2F, 0x43},
	{0x25, 0x2F, 0x45},
}

// entry is one enumerated directory entry. Enumeration only: no content.
type entry struct {
	name     string // cleaned file identifier (version suffix stripped)
	isDir    bool
	isHidden bool // effective: own hidden flag OR inside a hidden directory
	size     int64
	ext      string // lowercased extension with dot, "" when none (files only)
	depth    int    // 0 = a root-level entry
}

// image is the enumerated container, consumed by the detector.
type image struct {
	volumeID string
	joliet   bool
	entries  []entry
	warning  string
}

func (im *image) warn(msg string) {
	if im.warning == "" {
		im.warning = msg
	}
}

// IsISO reports whether the buffer looks like an ISO 9660 image: the standard
// identifier "CD001" at the start of a volume descriptor at sector 16 (its
// type byte is at 0x8000 and "CD001" follows at 0x8001). The leading type byte
// is not required to hold any particular value, and the volume descriptor set
// is scanned for a bounded number of sectors so a descriptor set that does not
// start with the primary is still recognised.
func IsISO(data []byte) bool {
	for i := 0; i < maxVolDescriptors; i++ {
		off := vdSetOffset + i*sectorSize
		if off+6 > len(data) {
			break
		}
		if string(data[off+1:off+6]) == stdIdentifier {
			return true
		}
	}
	return false
}

// parseISO enumerates the container. It always returns a non-nil image; on any
// problem it sets a warning and returns the partial enumeration.
func parseISO(data []byte) *image {
	im := &image{}
	pvd, svd := findDescriptors(data, im)
	if pvd == nil && svd == nil {
		im.warn("no primary or supplementary volume descriptor at sector 16")
		return im
	}
	if len(pvd) >= volumeIDOffset+32 {
		im.volumeID = trimVolID(pvd[volumeIDOffset : volumeIDOffset+32])
	}

	// Prefer the Joliet tree (UCS-2BE names) when a usable one is present.
	desc := pvd
	if svd != nil {
		desc = svd
		im.joliet = true
	}
	if len(desc) < rootRecOffset+rootRecLen {
		im.warn("truncated volume descriptor: root directory record missing")
		return im
	}
	root := desc[rootRecOffset : rootRecOffset+rootRecLen]
	rootLBA := leU32(root, recExtentLE)
	rootLen := leU32(root, recDataLenLE)
	im.walk(data, rootLBA, rootLen)
	return im
}

// findDescriptors scans the volume descriptor set from sector 16 and returns
// the Primary Volume Descriptor and, if present with a Joliet escape, a
// Supplementary Volume Descriptor. Either may be nil; a descriptor whose
// standard identifier is absent, or a terminator, ends the scan.
func findDescriptors(data []byte, im *image) (pvd, svd []byte) {
	for i := 0; i < maxVolDescriptors; i++ {
		off := vdSetOffset + i*sectorSize
		if off+7 > len(data) {
			break
		}
		end := off + sectorSize
		if end > len(data) {
			end = len(data) // tolerate a truncated final descriptor
		}
		vd := data[off:end]
		if string(vd[1:6]) != stdIdentifier {
			break
		}
		switch vd[0] {
		case vdTypeTerminator:
			return pvd, svd
		case vdTypePrimary:
			if pvd == nil {
				pvd = vd
			}
		case vdTypeSupplementary:
			if svd == nil && isJoliet(vd) {
				svd = vd
			}
		case vdTypeBoot:
			// no fields the enumerator needs
		}
	}
	return pvd, svd
}

// isJoliet reports whether a supplementary descriptor carries a Joliet UCS-2
// escape sequence in its escape-sequences field.
func isJoliet(vd []byte) bool {
	if len(vd) < escapeSeqOffset+32 {
		return false
	}
	field := vd[escapeSeqOffset : escapeSeqOffset+32]
	for _, esc := range jolietEscapes {
		if containsBytes(field, esc) {
			return true
		}
	}
	return false
}

// dirJob is one directory extent queued for enumeration.
type dirJob struct {
	lba      uint32
	length   uint32
	depth    int
	inHidden bool // this extent is inside a hidden directory
}

// walk enumerates the directory tree from the root extent with an explicit
// queue (no recursion). Every access is range-checked and every cap is
// honoured; a visited-set of extent LBAs makes a self-referential or shared
// extent terminate rather than loop.
func (im *image) walk(data []byte, rootLBA, rootLen uint32) {
	visited := map[uint32]bool{rootLBA: true}
	queue := []dirJob{{lba: rootLBA, length: rootLen, depth: 0}}
	records := 0
	sectors := 0

	for qi := 0; qi < len(queue); qi++ {
		job := queue[qi]
		numSectors := int((int64(job.length) + sectorSize - 1) / sectorSize)
		if numSectors > maxExtentSectors {
			numSectors = maxExtentSectors
			im.warn("directory extent exceeds the per-extent sector cap")
		}

		for s := 0; s < numSectors; s++ {
			if sectors >= maxSectorsRead {
				im.warn("directory-sector read cap reached")
				return
			}
			sectors++
			off := (int64(job.lba) + int64(s)) * sectorSize
			if off < 0 || off+sectorSize > int64(len(data)) {
				im.warn("directory extent runs past the end of the image")
				break
			}
			sec := data[off : off+sectorSize]

			for pos := 0; pos < sectorSize; {
				recLen := int(sec[pos])
				if recLen == 0 {
					break // no more records in this sector
				}
				if recLen < rootRecLen || pos+recLen > sectorSize {
					im.warn("malformed directory record length")
					break
				}
				rec := sec[pos : pos+recLen]
				pos += recLen

				records++
				if records > maxDirRecords {
					im.warn("directory-record cap reached")
					return
				}

				fidLen := int(rec[recFileIDLen])
				if recFileID+fidLen > recLen {
					im.warn("directory record identifier overruns the record")
					fidLen = recLen - recFileID
				}
				if fidLen <= 0 {
					continue
				}
				id := rec[recFileID : recFileID+fidLen]

				// Skip the "." (0x00) and ".." (0x01) self/parent records.
				if fidLen == 1 && (id[0] == 0x00 || id[0] == 0x01) {
					continue
				}

				flags := rec[recFlags]
				isDir := flags&flagDir != 0
				ownHidden := flags&flagHidden != 0
				extent := leU32(rec, recExtentLE)
				dataLen := leU32(rec, recDataLenLE)
				size := int64(dataLen)

				name := cleanName(decodeName(id, im.joliet))
				if name == "" {
					continue
				}
				effHidden := ownHidden || job.inHidden

				if len(im.entries) < maxEntries {
					im.entries = append(im.entries, entry{
						name:     name,
						isDir:    isDir,
						isHidden: effHidden,
						size:     size,
						ext:      extOf(name),
						depth:    job.depth,
					})
				}

				if isDir && job.depth+1 <= maxDepth && !visited[extent] && len(queue) < maxDirsQueued {
					visited[extent] = true
					queue = append(queue, dirJob{
						lba:      extent,
						length:   dataLen,
						depth:    job.depth + 1,
						inHidden: effHidden,
					})
				}
			}
		}
	}
}

// ── decoding helpers ─────────────────────────────────────────────────────────

// leU32 reads a little-endian uint32 at off from b, returning 0 if out of range.
func leU32(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// decodeName turns a file-identifier field into a string. Joliet identifiers
// are UCS-2BE; otherwise each byte maps to a rune (ISO 8859-1).
func decodeName(id []byte, joliet bool) string {
	if joliet {
		n := len(id) / 2
		if n == 0 {
			return ""
		}
		u := make([]uint16, n)
		for i := 0; i < n; i++ {
			u[i] = uint16(id[2*i])<<8 | uint16(id[2*i+1])
		}
		return string(utf16.Decode(u))
	}
	r := make([]rune, len(id))
	for i, c := range id {
		r[i] = rune(c)
	}
	return string(r)
}

// cleanName strips the ISO 9660 ";version" suffix and any trailing dot.
func cleanName(name string) string {
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimRight(name, ".")
	return name
}

// extOf returns the lowercased extension (with dot) of a filename, or "".
func extOf(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return strings.ToLower(name[i:])
}

// trimVolID decodes the Volume Identifier (ISO 8859-1), trimming trailing
// spaces and NULs.
func trimVolID(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == ' ' || b[end-1] == 0) {
		end--
	}
	r := make([]rune, end)
	for i := 0; i < end; i++ {
		r[i] = rune(b[i])
	}
	return strings.TrimSpace(string(r))
}

// containsBytes reports whether sub appears within b (small, bounded inputs).
func containsBytes(b, sub []byte) bool {
	if len(sub) == 0 {
		return true
	}
	if len(sub) > len(b) {
		return false
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

package ole

import "unicode/utf16"

// The VBA project "dir" stream ([MS-OVBA] 2.3.4.2).
//
// The stream is a CompressedContainer; decompressed, it is a flat sequence of
// records, each an Id (u16), a Size (u32) and Size bytes of data. The records
// this package reads are the project version, the module count, and per module
// its name, its stream name, its TextOffset (MODULEOFFSET) and its type. The
// TextOffset is what the stomping checks in stomp.go stand on: it says where,
// inside the module stream, the compiled PerformanceCache (p-code) ends and the
// CompressedSourceCode begins.
//
// Every field is attacker-controlled. The walk is bounded by the buffer (itself
// capped by the caller's decompression limit), by maxDirRecords, by
// maxDirModules and by maxVBANameBytes; a record that claims more bytes than
// remain ends the parse cleanly with truncated set. It never panics.

// dir-stream record ids.
const (
	recProjectCodePage   uint16 = 0x0003
	recProjectVersion    uint16 = 0x0009
	recProjectModules    uint16 = 0x000F
	recDirTerminator     uint16 = 0x0010
	recModuleName        uint16 = 0x0019
	recModuleStreamName  uint16 = 0x001A
	recModuleTypeProc    uint16 = 0x0021
	recModuleTypeDoc     uint16 = 0x0022
	recModuleTerminator  uint16 = 0x002B
	recModuleOffset      uint16 = 0x0031
	recModuleStreamNameU uint16 = 0x0032
	recModuleNameUnicode uint16 = 0x0047
)

// dir-stream parse caps.
const (
	maxDirDecompressed = 1 << 20 // decompressed dir-stream bytes parsed
	maxDirRecords      = 16384   // records walked before giving up
	maxDirModules      = 1024    // module records kept
	maxVBANameBytes    = 256     // bytes kept of any module / stream name
)

// vbaModule is one MODULE record group of the dir stream.
type vbaModule struct {
	name        string // MODULENAMEUNICODE when present, else MODULENAME
	streamName  string // the unicode stream name when present, else the MBCS one
	nameIsMBCS  bool   // streamName came from the code-page record
	textOffset  uint32 // MODULEOFFSET TextOffset
	hasOffset   bool
	moduleType  uint16 // recModuleTypeProc / recModuleTypeDoc, 0 when absent
	haveUniName bool
}

// vbaDir is the parsed dir stream.
type vbaDir struct {
	codePage     uint16
	versionMajor uint32
	versionMinor uint16
	hasVersion   bool
	declared     int // PROJECTMODULES Count, -1 when the record is absent
	modules      []vbaModule
	records      int
	terminated   bool // the 0x0010 terminator was reached
	truncated    bool // a record overran the buffer, or a cap stopped the walk
}

// parseVBADir walks a DECOMPRESSED dir stream.
func parseVBADir(b []byte) vbaDir {
	d := vbaDir{declared: -1}
	if len(b) > maxDirDecompressed {
		b = b[:maxDirDecompressed]
		d.truncated = true
	}
	var cur *vbaModule
	flush := func() {
		if cur == nil {
			return
		}
		if len(d.modules) < maxDirModules {
			d.modules = append(d.modules, *cur)
		} else {
			d.truncated = true
		}
		cur = nil
	}
	module := func() *vbaModule {
		if cur == nil {
			cur = &vbaModule{}
		}
		return cur
	}

	pos := 0
	for pos+6 <= len(b) {
		if d.records >= maxDirRecords {
			d.truncated = true
			break
		}
		d.records++
		id := le16(b, pos)
		size := le32(b, pos+2)
		pos += 6

		// PROJECTVERSION is the one record whose Size field (always 4) is not
		// its data length: it is followed by VersionMajor (u32) and
		// VersionMinor (u16), six bytes in all.
		if id == recProjectVersion {
			if pos+6 > len(b) {
				d.truncated = true
				break
			}
			d.versionMajor = le32(b, pos)
			d.versionMinor = le16(b, pos+4)
			d.hasVersion = true
			pos += 6
			continue
		}

		if uint64(size) > uint64(len(b)-pos) {
			d.truncated = true // the record claims more than remains
			break
		}
		data := b[pos : pos+int(size)]
		pos += int(size)

		switch id {
		case recProjectCodePage:
			if len(data) >= 2 {
				d.codePage = le16(data, 0)
			}
		case recProjectModules:
			if len(data) >= 2 {
				d.declared = int(le16(data, 0))
			}
		case recModuleName:
			flush() // a MODULENAME opens a new module
			m := module()
			m.name = decodeMBCS(data)
		case recModuleNameUnicode:
			m := module()
			if s := decodeUTF16(data); s != "" {
				m.name = s
				m.haveUniName = true
			}
		case recModuleStreamName:
			m := module()
			m.streamName = decodeMBCS(data)
			m.nameIsMBCS = true
		case recModuleStreamNameU:
			m := module()
			if s := decodeUTF16(data); s != "" {
				m.streamName = s
				m.nameIsMBCS = false
			}
		case recModuleOffset:
			if len(data) >= 4 {
				m := module()
				m.textOffset = le32(data, 0)
				m.hasOffset = true
			}
		case recModuleTypeProc, recModuleTypeDoc:
			module().moduleType = id
		case recModuleTerminator:
			flush()
		case recDirTerminator:
			flush()
			d.terminated = true
			return d
		}
	}
	if pos < len(b) && !d.truncated {
		d.truncated = true // trailing bytes too short to be a record header
	}
	flush()
	return d
}

// decodeMBCS renders a code-page name without a code-page table: ASCII bytes
// are kept and anything else becomes '?'. Stream lookup uses the unicode record
// whenever it is present, so this only has to be exact for ASCII names.
func decodeMBCS(b []byte) string {
	if len(b) > maxVBANameBytes {
		b = b[:maxVBANameBytes]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7E {
			c = '?'
		}
		out = append(out, c)
	}
	return string(out)
}

// decodeUTF16 decodes a UTF-16LE name, stopping at a NUL and at the name cap.
func decodeUTF16(b []byte) string {
	if len(b) > maxVBANameBytes {
		b = b[:maxVBANameBytes]
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// The _VBA_PROJECT stream header ([MS-OVBA] 2.3.4.1): Reserved1 (u16, 0x61CC),
// Version (u16), Reserved2 (u8), Reserved3 (u16), then the PerformanceCache.
// Version identifies the VBA build the project's p-code was compiled by; Office
// only runs the cached p-code when it matches its own build, and recompiles
// from the source otherwise.
const (
	vbaProjectReserved1  = 0x61CC
	vbaProjectHeaderSize = 7
)

// vbaProjectVersion returns the Version field of a _VBA_PROJECT stream.
func vbaProjectVersion(b []byte) (uint16, bool) {
	if len(b) < vbaProjectHeaderSize || le16(b, 0) != vbaProjectReserved1 {
		return 0, false
	}
	return le16(b, 2), true
}

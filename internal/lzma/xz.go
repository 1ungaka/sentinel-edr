package lzma

import (
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"hash/crc64"
)

// The .xz container: one or more streams, each a stream header, blocks, an
// index and a stream footer, with optional zero padding between streams.
//
//	stream header  magic FD 37 7A 58 5A 00, 2 flag bytes (check type), CRC32
//	block          header (size byte, flags, optional sizes, filter flags,
//	               padding, CRC32), compressed data, padding to 4, check
//	index          0x00, record count, (unpadded size, uncompressed size)
//	               per block, padding to 4, CRC32
//	stream footer  CRC32, backward size (index size), flags, magic 59 5A
//
// Exactly one filter is decoded: LZMA2 (id 0x21). A BCJ or delta chain, or
// any other filter, is reported as ErrUnsupported rather than decoded wrong.
// The block check is verified for CRC32, CRC64 and SHA-256, the three types
// the format defines; the reserved types are reported as unverified in the
// Report and do not fail the decode.

var xzMagic = [6]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}

const (
	xzStreamHeaderLen = 12
	xzStreamFooterLen = 12
	xzFilterLZMA2     = 0x21
	// xzMaxBlockHeader is the format's bound on a block header (255+1)*4.
	xzMaxBlockHeader = 1024
	// xzMaxVarint is the longest multibyte integer the format allows.
	xzMaxVarint = 9
)

var crc64Table = crc64.MakeTable(crc64.ECMA)

// IsXZ reports whether b starts with the xz stream magic.
func IsXZ(b []byte) bool {
	return len(b) >= len(xzMagic) && [6]byte(b[:6]) == xzMagic
}

// Report describes what Decode found in an xz file.
type Report struct {
	// Streams and Blocks are the counts decoded.
	Streams, Blocks int
	// Check names the check type of the last stream: "none", "crc32",
	// "crc64", "sha256", or "reserved-N" for a type the format reserves.
	Check string
	// Unverified counts the blocks whose check could not be computed because
	// the stream uses a reserved check type. Zero means every block's check
	// matched (or the stream declared none).
	Unverified int
}

// checkInfo maps a check type id to its name, the size of the check field
// and whether this package can compute it.
func checkInfo(id byte) (name string, size int, verifiable bool) {
	switch id {
	case 0:
		return "none", 0, true
	case 1:
		return "crc32", 4, true
	case 4:
		return "crc64", 8, true
	case 10:
		return "sha256", 32, true
	}
	// Reserved ids still have a defined size, so a stream using one can be
	// walked: 4 bytes for 1-3, 8 for 4-6, 16 for 7-9, 32 for 10-12, 64 for 13-15.
	return "reserved-" + itoa(int(id)), 4 << ((id - 1) / 3), false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// varint reads one xz multibyte integer. It reports the value and the bytes
// used, or ok=false when the integer is malformed, over 63 bits, or missing.
func varint(b []byte) (v uint64, n int, ok bool) {
	for n < len(b) && n < xzMaxVarint {
		c := b[n]
		v |= uint64(c&0x7F) << (7 * uint(n))
		n++
		if c&0x80 == 0 {
			if c == 0 && n > 1 {
				return 0, n, false // a trailing zero byte is not canonical
			}
			return v, n, true
		}
	}
	return 0, n, false
}

// Decode decompresses an xz file (every stream, every block, in order) into
// at most limit bytes. The header CRCs, the index and the block checks are
// verified; any disagreement is ErrCorrupt. See DecodeReport for the check
// coverage.
func Decode(in []byte, limit int) ([]byte, error) {
	out, _, err := DecodeReport(in, limit)
	return out, err
}

// DecodeReport is Decode with a Report of what was verified. The Report is
// meaningful only when err is nil.
func DecodeReport(in []byte, limit int) ([]byte, Report, error) {
	var rep Report
	if !IsXZ(in) {
		return nil, rep, ErrHeader
	}
	if limit <= 0 {
		return nil, rep, ErrTooLarge
	}
	d := &decoder{limit: limit}
	d.out = make([]byte, 0, capHint(-1, limit))
	pos := 0
	for {
		n, err := d.xzStream(in[pos:], &rep)
		if err != nil {
			return nil, rep, err
		}
		pos += n
		// Stream padding: zero bytes, four at a time, then either another
		// stream or the end of the file. Anything else is corruption.
		for pos+4 <= len(in) && in[pos] == 0 && in[pos+1] == 0 && in[pos+2] == 0 && in[pos+3] == 0 {
			pos += 4
		}
		if pos == len(in) {
			return d.out, rep, nil
		}
		if !IsXZ(in[pos:]) {
			return nil, rep, ErrCorrupt
		}
	}
}

// xzStream decodes one stream at the start of in and returns its length.
func (d *decoder) xzStream(in []byte, rep *Report) (int, error) {
	if len(in) < xzStreamHeaderLen+xzStreamFooterLen {
		return 0, ErrTruncated
	}
	flags := in[6:8]
	if binary.LittleEndian.Uint32(in[8:12]) != crc32.ChecksumIEEE(flags) {
		return 0, ErrCorrupt
	}
	if flags[0] != 0 || flags[1]&0xF0 != 0 {
		return 0, ErrUnsupported // reserved stream flags
	}
	checkName, checkSize, verifiable := checkInfo(flags[1] & 0x0F)
	rep.Streams++
	rep.Check = checkName

	type record struct{ unpadded, uncompressed uint64 }
	var records []record
	pos := xzStreamHeaderLen
	for {
		if pos >= len(in) {
			return pos, ErrTruncated
		}
		if in[pos] == 0 {
			break // the index
		}
		n, unpadded, uncompressed, err := d.xzBlock(in[pos:], flags[1]&0x0F, checkSize)
		if err != nil {
			return pos, err
		}
		records = append(records, record{unpadded, uncompressed})
		rep.Blocks++
		if !verifiable {
			rep.Unverified++
		}
		pos += n
	}

	// Index: it must agree with the blocks just decoded, record for record.
	indexStart := pos
	pos++ // the 0x00 indicator
	count, n, ok := varint(in[pos:])
	if !ok || count != uint64(len(records)) {
		return pos, ErrCorrupt
	}
	pos += n
	for _, r := range records {
		unpadded, n, ok := varint(in[pos:])
		if !ok || unpadded != r.unpadded {
			return pos, ErrCorrupt
		}
		pos += n
		uncompressed, n, ok := varint(in[pos:])
		if !ok || uncompressed != r.uncompressed {
			return pos, ErrCorrupt
		}
		pos += n
	}
	for (pos-indexStart)%4 != 0 {
		if pos >= len(in) {
			return pos, ErrTruncated
		}
		if in[pos] != 0 {
			return pos, ErrCorrupt
		}
		pos++
	}
	if pos+4 > len(in) {
		return pos, ErrTruncated
	}
	if binary.LittleEndian.Uint32(in[pos:]) != crc32.ChecksumIEEE(in[indexStart:pos]) {
		return pos, ErrCorrupt
	}
	pos += 4
	indexLen := pos - indexStart

	// Stream footer.
	if pos+xzStreamFooterLen > len(in) {
		return pos, ErrTruncated
	}
	f := in[pos : pos+xzStreamFooterLen]
	if binary.LittleEndian.Uint32(f[0:4]) != crc32.ChecksumIEEE(f[4:10]) {
		return pos, ErrCorrupt
	}
	backward := (uint64(binary.LittleEndian.Uint32(f[4:8])) + 1) * 4
	if backward != uint64(indexLen) || f[8] != flags[0] || f[9] != flags[1] || f[10] != 'Y' || f[11] != 'Z' {
		return pos, ErrCorrupt
	}
	return pos + xzStreamFooterLen, nil
}

// xzBlock decodes one block (header, data, padding, check) at the start of
// in. It returns the bytes the block spans, its unpadded size and its
// uncompressed size, the two figures the index must repeat.
func (d *decoder) xzBlock(in []byte, checkID byte, checkSize int) (n int, unpadded, uncompressed uint64, err error) {
	headerLen := (int(in[0]) + 1) * 4
	if headerLen > len(in) {
		return 0, 0, 0, ErrTruncated
	}
	hdr := in[:headerLen]
	if binary.LittleEndian.Uint32(hdr[headerLen-4:]) != crc32.ChecksumIEEE(hdr[:headerLen-4]) {
		return 0, 0, 0, ErrCorrupt
	}
	bflags := hdr[1]
	if bflags&0x3C != 0 {
		return 0, 0, 0, ErrUnsupported // reserved block flags
	}
	numFilters := int(bflags&0x03) + 1
	p := 2
	var compSize, uncompSize uint64
	hasComp, hasUncomp := bflags&0x40 != 0, bflags&0x80 != 0
	if hasComp {
		v, k, ok := varint(hdr[p : headerLen-4])
		if !ok || v == 0 {
			return 0, 0, 0, ErrCorrupt
		}
		compSize, p = v, p+k
	}
	if hasUncomp {
		v, k, ok := varint(hdr[p : headerLen-4])
		if !ok {
			return 0, 0, 0, ErrCorrupt
		}
		uncompSize, p = v, p+k
	}
	var dictSize uint32
	for i := 0; i < numFilters; i++ {
		id, k, ok := varint(hdr[p : headerLen-4])
		if !ok {
			return 0, 0, 0, ErrCorrupt
		}
		p += k
		propLen, k, ok := varint(hdr[p : headerLen-4])
		if !ok || propLen > uint64(headerLen-4-p) {
			return 0, 0, 0, ErrCorrupt
		}
		p += k
		props := hdr[p : p+int(propLen)]
		p += int(propLen)
		if numFilters != 1 || id != xzFilterLZMA2 {
			// A BCJ chain (0x04..0x0B), delta (0x03), or anything else: the
			// bytes would decode wrong, so they are not decoded at all.
			return 0, 0, 0, ErrUnsupported
		}
		if len(props) != 1 || props[0] > 40 {
			return 0, 0, 0, ErrCorrupt
		}
		if props[0] == 40 {
			dictSize = 0xFFFFFFFF
		} else {
			dictSize = (2 | uint32(props[0])&1) << (props[0]/2 + 11)
		}
	}
	for ; p < headerLen-4; p++ {
		if hdr[p] != 0 {
			return 0, 0, 0, ErrCorrupt // header padding must be zero
		}
	}

	// Sizes, before any work: the header's claims are checked against the
	// limit and the input, then against what the data produced.
	room := uint64(d.limit - len(d.out))
	if hasUncomp && uncompSize > room {
		return 0, 0, 0, ErrTooLarge
	}
	data := in[headerLen:]
	if hasComp {
		if compSize > uint64(len(data)) {
			return 0, 0, 0, ErrTruncated
		}
		data = data[:compSize]
	}
	if dictSize < minDictSize {
		dictSize = minDictSize
	}
	d.dictSize = dictSize
	blockStart := len(d.out)
	consumed, err := d.lzma2(data)
	if err != nil {
		return 0, 0, 0, err
	}
	if hasComp && uint64(consumed) != compSize {
		return 0, 0, 0, ErrCorrupt
	}
	produced := d.out[blockStart:]
	if hasUncomp && uint64(len(produced)) != uncompSize {
		return 0, 0, 0, ErrCorrupt
	}

	// Block padding to a multiple of four, then the check.
	pos := headerLen + consumed
	for pos%4 != 0 {
		if pos >= len(in) {
			return 0, 0, 0, ErrTruncated
		}
		if in[pos] != 0 {
			return 0, 0, 0, ErrCorrupt
		}
		pos++
	}
	if pos+checkSize > len(in) {
		return 0, 0, 0, ErrTruncated
	}
	check := in[pos : pos+checkSize]
	switch checkID {
	case 1:
		if binary.LittleEndian.Uint32(check) != crc32.ChecksumIEEE(produced) {
			return 0, 0, 0, ErrCorrupt
		}
	case 4:
		if binary.LittleEndian.Uint64(check) != crc64.Checksum(produced, crc64Table) {
			return 0, 0, 0, ErrCorrupt
		}
	case 10:
		if sum := sha256.Sum256(produced); [32]byte(check) != sum {
			return 0, 0, 0, ErrCorrupt
		}
	}
	pos += checkSize
	return pos, uint64(headerLen + consumed + checkSize), uint64(len(produced)), nil
}

package lzma

// LZMA2 is a chunked container around LZMA: each chunk is either stored
// bytes or one range-coded LZMA run of a declared packed and unpacked size,
// and the control byte says what to reset before it. The dictionary carries
// across chunks (until a chunk resets it), which is why this decoder keeps
// one output buffer that serves as the dictionary.
//
// Control byte:
//
//	0x00        end of the LZMA2 data
//	0x01        stored chunk, dictionary reset first
//	0x02        stored chunk, no reset
//	0x03..0x7F  invalid
//	0x80..0xFF  LZMA chunk; bits 0-4 are the high bits of the unpacked size;
//	            bits 5-6: 0 nothing reset, 1 state reset, 2 state reset and
//	            new properties, 3 everything reset including the dictionary

// lzma2 is the chunk loop shared by DecodeLZMA2 and the xz block decoder. It
// appends to d.out, which may already hold earlier blocks, and returns how
// many input bytes the chunks spanned, end marker included. On error the
// caller discards d.out.
func (d *decoder) lzma2(in []byte) (consumed int, err error) {
	d.resetDict()
	needDict, needProps := true, true
	pos := 0
	for {
		if pos >= len(in) {
			return pos, ErrTruncated
		}
		c := in[pos]
		pos++
		switch {
		case c == 0x00:
			return pos, nil
		case c == 0x01 || c >= 0xE0:
			d.resetDict()
			needDict, needProps = false, true
		case needDict:
			return pos, ErrCorrupt
		}
		if c < 0x80 {
			if c > 0x02 {
				return pos, ErrCorrupt
			}
			if pos+2 > len(in) {
				return pos, ErrTruncated
			}
			size := int(in[pos])<<8 | int(in[pos+1]) + 1
			pos += 2
			if len(d.out)+size > d.limit {
				return pos, ErrTooLarge
			}
			if pos+size > len(in) {
				return pos, ErrTruncated
			}
			d.out = append(d.out, in[pos:pos+size]...)
			pos += size
			continue
		}
		if pos+4 > len(in) {
			return pos, ErrTruncated
		}
		unpacked := int(c&0x1F)<<16 | int(in[pos])<<8 | int(in[pos+1]) + 1
		packed := int(in[pos+2])<<8 | int(in[pos+3]) + 1
		pos += 4
		switch {
		case c >= 0xC0:
			if pos >= len(in) {
				return pos, ErrTruncated
			}
			p, ok := parseProps(in[pos], 4)
			if !ok {
				return pos, ErrCorrupt
			}
			pos++
			d.setProps(p)
			needProps = false
		case needProps:
			return pos, ErrCorrupt
		case c >= 0xA0:
			d.resetState()
		}
		if len(d.out)+unpacked > d.limit {
			return pos, ErrTooLarge
		}
		if pos+packed > len(in) {
			return pos, ErrTruncated
		}
		chunk := in[pos : pos+packed]
		pos += packed
		if !d.rc.init(chunk) {
			return pos, ErrCorrupt
		}
		target := len(d.out) + unpacked
		ended, err := d.run(target, false)
		switch {
		case err != nil:
			// Overrun and exhaustion are both corruption here: the chunk
			// declared both of its sizes and the data disagreed.
			return pos, ErrCorrupt
		case ended:
			return pos, ErrCorrupt // no marker in LZMA2
		case len(d.out) != target, d.rc.pos != len(chunk), d.rc.code != 0:
			// The chunk must have produced exactly its unpacked size from
			// exactly its packed bytes, with the range coder flushed.
			return pos, ErrCorrupt
		}
	}
}

// DecodeLZMA2 decompresses raw LZMA2 data (the xz block payload without the
// container), producing at most limit bytes. dictSize is the declared
// dictionary size, which bounds match distances; it allocates nothing.
func DecodeLZMA2(in []byte, dictSize uint32, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, ErrTooLarge
	}
	if dictSize < minDictSize {
		dictSize = minDictSize
	}
	d := &decoder{limit: limit, dictSize: dictSize}
	d.out = make([]byte, 0, capHint(-1, limit))
	if _, err := d.lzma2(in); err != nil {
		return nil, err
	}
	return d.out, nil
}

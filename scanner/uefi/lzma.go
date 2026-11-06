package uefi

import (
	"encoding/binary"
	"errors"
)

// A bounded LZMA decoder, for one purpose: opening the LZMA-compressed
// sections firmware images keep their driver volumes in.
//
// Nearly every modern UEFI image stores its main firmware volume inside a
// GUID-defined section compressed with LZMA, so a scanner that cannot
// decompress it inventories a handful of early-boot modules and none of the
// drivers. The standard library has no LZMA decoder and this package takes no
// dependencies, so the decoder is here. It implements the classic LZMA
// stream as the reference specification describes it (the ".lzma" container:
// one properties byte, a 4-byte dictionary size, an 8-byte uncompressed size,
// then the range-coded data).
//
// The input is hostile by assumption. Every bound is explicit:
//
//   - the output never exceeds the caller's limit, whatever the header claims;
//   - a match that reaches back before the start of the output is an error,
//     never a read of unrelated memory;
//   - running out of input is an error, never an endless loop of zeros;
//   - the probability tables are sized from the properties byte, which is
//     validated first, so their size is bounded too (at most 0x300 << 8).

var (
	errLZMAHeader    = errors.New("uefi: not an LZMA stream")
	errLZMACorrupt   = errors.New("uefi: corrupt LZMA data")
	errLZMATooLarge  = errors.New("uefi: LZMA output exceeds the size limit")
	errLZMATruncated = errors.New("uefi: LZMA data ends early")
)

const (
	lzmaHeaderLen     = 13
	lzmaNumStates     = 12
	lzmaNumPosStates  = 16 // 1 << pb, pb <= 4
	lzmaEndPosModel   = 14
	lzmaNumFullDist   = 1 << (lzmaEndPosModel >> 1)
	lzmaMatchMinLen   = 2
	lzmaProbInit      = 1024
	lzmaUnknownSize   = ^uint64(0)
	lzmaTopValue      = 1 << 24
	lzmaBitModelTotal = 1 << 11
)

// lzmaRange is the range decoder.
type lzmaRange struct {
	in        []byte
	pos       int
	rng, code uint32
	// exhausted is set when the decoder needed a byte the input did not have.
	exhausted bool
}

func (r *lzmaRange) next() uint32 {
	if r.pos >= len(r.in) {
		r.exhausted = true
		return 0
	}
	b := r.in[r.pos]
	r.pos++
	return uint32(b)
}

func (r *lzmaRange) init() bool {
	if r.next() != 0 { // the first byte of the range-coded data is always 0
		return false
	}
	r.rng = 0xFFFFFFFF
	for i := 0; i < 4; i++ {
		r.code = r.code<<8 | r.next()
	}
	return !r.exhausted && r.code != r.rng
}

func (r *lzmaRange) normalize() {
	if r.rng < lzmaTopValue {
		r.rng <<= 8
		r.code = r.code<<8 | r.next()
	}
}

func (r *lzmaRange) bit(prob *uint16) uint32 {
	bound := (r.rng >> 11) * uint32(*prob)
	if r.code < bound {
		*prob += (lzmaBitModelTotal - *prob) >> 5
		r.rng = bound
		r.normalize()
		return 0
	}
	*prob -= *prob >> 5
	r.code -= bound
	r.rng -= bound
	r.normalize()
	return 1
}

func (r *lzmaRange) direct(n int) uint32 {
	var res uint32
	for ; n > 0; n-- {
		r.rng >>= 1
		r.code -= r.rng
		t := 0 - (r.code >> 31)
		r.code += r.rng & t
		r.normalize()
		res = res<<1 + t + 1
	}
	return res
}

// tree decodes numBits through a bit tree whose probabilities start at probs[1].
func (r *lzmaRange) tree(probs []uint16, numBits int) uint32 {
	m := uint32(1)
	for i := 0; i < numBits; i++ {
		m = m<<1 + r.bit(&probs[m])
	}
	return m - 1<<numBits
}

func (r *lzmaRange) reverseTree(probs []uint16, numBits int) uint32 {
	m, sym := uint32(1), uint32(0)
	for i := 0; i < numBits; i++ {
		b := r.bit(&probs[m])
		m = m<<1 + b
		sym |= b << i
	}
	return sym
}

type lzmaLen struct {
	choice, choice2 uint16
	low, mid        [lzmaNumPosStates][8]uint16
	high            [256]uint16
}

func (l *lzmaLen) init() {
	l.choice, l.choice2 = lzmaProbInit, lzmaProbInit
	for i := range l.low {
		for j := range l.low[i] {
			l.low[i][j], l.mid[i][j] = lzmaProbInit, lzmaProbInit
		}
	}
	for i := range l.high {
		l.high[i] = lzmaProbInit
	}
}

func (l *lzmaLen) decode(r *lzmaRange, posState uint32) uint32 {
	if r.bit(&l.choice) == 0 {
		return r.tree(l.low[posState][:], 3)
	}
	if r.bit(&l.choice2) == 0 {
		return 8 + r.tree(l.mid[posState][:], 3)
	}
	return 16 + r.tree(l.high[:], 8)
}

func fillProbs(p []uint16) {
	for i := range p {
		p[i] = lzmaProbInit
	}
}

// lzmaDecode decompresses an LZMA ".lzma"-container stream, producing at most
// limit bytes. A stream whose header declares more than limit, or whose data
// would produce more, is refused rather than truncated: a partial firmware
// volume is not something to draw conclusions from.
func lzmaDecode(in []byte, limit int) ([]byte, error) {
	if len(in) < lzmaHeaderLen+5 || limit <= 0 {
		return nil, errLZMAHeader
	}
	d := in[0]
	if d >= 9*5*5 {
		return nil, errLZMAHeader
	}
	lc := uint(d % 9)
	d /= 9
	lp := uint(d % 5)
	pb := uint(d / 5)
	if lc+lp > 8 { // more literal context than a byte position can address
		return nil, errLZMAHeader
	}
	dictSize := binary.LittleEndian.Uint32(in[1:5])
	unpack := binary.LittleEndian.Uint64(in[5:13])
	sizeKnown := unpack != lzmaUnknownSize
	if sizeKnown && unpack > uint64(limit) {
		return nil, errLZMATooLarge
	}
	_ = dictSize // the whole output is kept, so the window never needs the declared size

	r := &lzmaRange{in: in[lzmaHeaderLen:]}
	if !r.init() {
		return nil, errLZMACorrupt
	}

	capHint := limit
	if sizeKnown {
		capHint = int(unpack)
	} else if capHint > 1<<20 {
		capHint = 1 << 20
	}
	out := make([]byte, 0, capHint)

	var (
		isMatch    [lzmaNumStates << 4]uint16
		isRep      [lzmaNumStates]uint16
		isRepG0    [lzmaNumStates]uint16
		isRepG1    [lzmaNumStates]uint16
		isRepG2    [lzmaNumStates]uint16
		isRep0Long [lzmaNumStates << 4]uint16
		posSlot    [4][64]uint16
		posDec     [1 + lzmaNumFullDist - lzmaEndPosModel]uint16
		align      [16]uint16
		lenDec     lzmaLen
		repLenDec  lzmaLen
	)
	lit := make([]uint16, 0x300<<(lc+lp))
	fillProbs(isMatch[:])
	fillProbs(isRep[:])
	fillProbs(isRepG0[:])
	fillProbs(isRepG1[:])
	fillProbs(isRepG2[:])
	fillProbs(isRep0Long[:])
	for i := range posSlot {
		fillProbs(posSlot[i][:])
	}
	fillProbs(posDec[:])
	fillProbs(align[:])
	fillProbs(lit)
	lenDec.init()
	repLenDec.init()

	var rep0, rep1, rep2, rep3 uint32
	state := uint32(0)
	posMask := uint32(1)<<pb - 1
	lpMask := uint32(1)<<lp - 1

	for {
		if r.exhausted {
			return nil, errLZMATruncated
		}
		if sizeKnown && uint64(len(out)) == unpack {
			return out, nil
		}
		if len(out) >= limit {
			return nil, errLZMATooLarge
		}
		pos := uint32(len(out))
		posState := pos & posMask

		if r.bit(&isMatch[state<<4+posState]) == 0 {
			// Literal.
			var prev uint32
			if len(out) > 0 {
				prev = uint32(out[len(out)-1])
			}
			probs := lit[0x300*(((pos&lpMask)<<lc)+(prev>>(8-lc))):]
			sym := uint32(1)
			if state >= 7 {
				if uint64(rep0) >= uint64(len(out)) {
					return nil, errLZMACorrupt
				}
				matchByte := uint32(out[len(out)-int(rep0)-1])
				for sym < 0x100 {
					matchBit := (matchByte >> 7) & 1
					matchByte <<= 1
					b := r.bit(&probs[((1+matchBit)<<8)+sym])
					sym = sym<<1 | b
					if matchBit != b {
						break
					}
				}
			}
			for sym < 0x100 {
				sym = sym<<1 | r.bit(&probs[sym])
			}
			out = append(out, byte(sym))
			switch {
			case state < 4:
				state = 0
			case state < 10:
				state -= 3
			default:
				state -= 6
			}
			continue
		}

		var length uint32
		if r.bit(&isRep[state]) != 0 {
			if len(out) == 0 {
				return nil, errLZMACorrupt
			}
			if r.bit(&isRepG0[state]) == 0 {
				if r.bit(&isRep0Long[state<<4+posState]) == 0 {
					// Short rep: one byte from distance rep0.
					if uint64(rep0) >= uint64(len(out)) {
						return nil, errLZMACorrupt
					}
					out = append(out, out[len(out)-int(rep0)-1])
					if state < 7 {
						state = 9
					} else {
						state = 11
					}
					continue
				}
			} else {
				var dist uint32
				if r.bit(&isRepG1[state]) == 0 {
					dist = rep1
				} else {
					if r.bit(&isRepG2[state]) == 0 {
						dist = rep2
					} else {
						dist = rep3
						rep3 = rep2
					}
					rep2 = rep1
				}
				rep1 = rep0
				rep0 = dist
			}
			length = repLenDec.decode(r, posState)
			if state < 7 {
				state = 8
			} else {
				state = 11
			}
		} else {
			rep3, rep2, rep1 = rep2, rep1, rep0
			length = lenDec.decode(r, posState)
			if state < 7 {
				state = 7
			} else {
				state = 10
			}
			// Distance.
			lenState := length
			if lenState > 3 {
				lenState = 3
			}
			slot := r.tree(posSlot[lenState][:], 6)
			if slot < 4 {
				rep0 = slot
			} else {
				numDirect := int(slot>>1) - 1
				dist := (2 | (slot & 1)) << uint(numDirect)
				if slot < lzmaEndPosModel {
					dist += r.reverseTree(posDec[dist-slot:], numDirect)
				} else {
					dist += r.direct(numDirect-4) << 4
					dist += r.reverseTree(align[:], 4)
				}
				rep0 = dist
			}
			if rep0 == 0xFFFFFFFF {
				// End-of-stream marker.
				if sizeKnown && uint64(len(out)) != unpack {
					return nil, errLZMACorrupt
				}
				if r.exhausted {
					return nil, errLZMATruncated
				}
				return out, nil
			}
		}

		if uint64(rep0) >= uint64(len(out)) {
			return nil, errLZMACorrupt // a match reaching before the start of the output
		}
		length += lzmaMatchMinLen
		if sizeKnown && uint64(len(out))+uint64(length) > unpack {
			return nil, errLZMACorrupt
		}
		if len(out)+int(length) > limit {
			return nil, errLZMATooLarge
		}
		// Byte by byte: the source and destination may overlap, which is how
		// LZ77 encodes a run.
		src := len(out) - int(rep0) - 1
		for i := 0; i < int(length); i++ {
			out = append(out, out[src+i])
		}
	}
}

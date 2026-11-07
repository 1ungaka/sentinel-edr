// Package lzma is a bounded, dependency-free decoder for the LZMA family:
// the classic ".lzma" container (DecodeAlone), raw LZMA2 (DecodeLZMA2) and
// the .xz container (Decode). It exists because the standard library has
// none, and because two parts of the engine need one: the UEFI walker opens
// the LZMA-compressed firmware volumes nearly every modern image keeps its
// drivers in, and the peeler opens xz as a container layer.
//
// Every input is hostile by assumption, and every bound is explicit:
//
//   - the output never exceeds the caller's limit, whatever a header claims;
//   - a match that reaches back before the start of the output (or before
//     the last dictionary reset) is an error, never a read of other memory;
//   - running out of input is an error, never an endless loop of zeros;
//   - the probability tables are sized from the properties byte, which is
//     validated first, so their size is bounded too (at most 0x300 << 8);
//   - a declared dictionary size is a bound on match distances and nothing
//     else: nothing is allocated from it, so a claim of 4 GiB costs nothing.
//
// The decoders are written against the reference specification (the LZMA
// SDK's lzma-specification.txt and the .xz file format specification), and
// each has a fuzz target whose invariant is "never panic, never pass the
// limit, and an error never comes with partial output".
package lzma

import (
	"encoding/binary"
	"errors"
)

// The typed errors. They wrap nothing: a caller compares with errors.Is.
var (
	ErrHeader      = errors.New("lzma: not an LZMA stream")
	ErrCorrupt     = errors.New("lzma: corrupt data")
	ErrTooLarge    = errors.New("lzma: output exceeds the size limit")
	ErrTruncated   = errors.New("lzma: data ends early")
	ErrUnsupported = errors.New("lzma: unsupported feature")
)

const (
	aloneHeaderLen = 13
	numStates      = 12
	numPosStates   = 16 // 1 << pb, pb <= 4
	endPosModel    = 14
	numFullDist    = 1 << (endPosModel >> 1)
	matchMinLen    = 2
	probInit       = 1024
	unknownSize    = ^uint64(0)
	topValue       = 1 << 24
	bitModelTotal  = 1 << 11
	// minDictSize is the smallest dictionary the reference decoder works
	// with; a smaller declared size is rounded up to it, as liblzma does.
	minDictSize = 4096
)

// Internal signals from the decode loop, mapped to the exported errors by the
// container decoders, which know whether an overrun is corruption or a claim
// larger than the limit.
var (
	errExhausted = errors.New("lzma: range coder ran out of input")
	errOverrun   = errors.New("lzma: a match would pass the output target")
)

// rangeDecoder is the range decoder.
type rangeDecoder struct {
	in        []byte
	pos       int
	rng, code uint32
	// exhausted is set when the decoder needed a byte the input did not have.
	exhausted bool
}

func (r *rangeDecoder) next() uint32 {
	if r.pos >= len(r.in) {
		r.exhausted = true
		return 0
	}
	b := r.in[r.pos]
	r.pos++
	return uint32(b)
}

// init starts the decoder on in. It reports false when the five initial bytes
// are missing or malformed (the first is always zero).
func (r *rangeDecoder) init(in []byte) bool {
	*r = rangeDecoder{in: in}
	if r.next() != 0 {
		return false
	}
	r.rng = 0xFFFFFFFF
	for i := 0; i < 4; i++ {
		r.code = r.code<<8 | r.next()
	}
	return !r.exhausted && r.code != r.rng
}

func (r *rangeDecoder) normalize() {
	if r.rng < topValue {
		r.rng <<= 8
		r.code = r.code<<8 | r.next()
	}
}

func (r *rangeDecoder) bit(prob *uint16) uint32 {
	bound := (r.rng >> 11) * uint32(*prob)
	if r.code < bound {
		*prob += (bitModelTotal - *prob) >> 5
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

func (r *rangeDecoder) direct(n int) uint32 {
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
func (r *rangeDecoder) tree(probs []uint16, numBits int) uint32 {
	m := uint32(1)
	for i := 0; i < numBits; i++ {
		m = m<<1 + r.bit(&probs[m])
	}
	return m - 1<<numBits
}

func (r *rangeDecoder) reverseTree(probs []uint16, numBits int) uint32 {
	m, sym := uint32(1), uint32(0)
	for i := 0; i < numBits; i++ {
		b := r.bit(&probs[m])
		m = m<<1 + b
		sym |= b << i
	}
	return sym
}

// lenCoder decodes match lengths.
type lenCoder struct {
	choice, choice2 uint16
	low, mid        [numPosStates][8]uint16
	high            [256]uint16
}

func (l *lenCoder) init() {
	l.choice, l.choice2 = probInit, probInit
	for i := range l.low {
		for j := range l.low[i] {
			l.low[i][j], l.mid[i][j] = probInit, probInit
		}
	}
	for i := range l.high {
		l.high[i] = probInit
	}
}

func (l *lenCoder) decode(r *rangeDecoder, posState uint32) uint32 {
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
		p[i] = probInit
	}
}

// props is a validated lc/lp/pb triple.
type props struct {
	lc, lp, pb uint
}

// parseProps decodes the properties byte. maxLcLp is 8 for LZMA1 (the whole
// byte position) and 4 for LZMA2, which forbids more.
func parseProps(d byte, maxLcLp uint) (props, bool) {
	if d >= 9*5*5 {
		return props{}, false
	}
	p := props{lc: uint(d % 9)}
	d /= 9
	p.lp = uint(d % 5)
	p.pb = uint(d / 5)
	if p.lc+p.lp > maxLcLp {
		return props{}, false
	}
	return p, true
}

// decoder is the LZMA state machine: the probability model, the repeat
// distances and the output so far, which is also the dictionary. The whole
// output is kept, so the window never needs the declared dictionary size.
type decoder struct {
	rc rangeDecoder

	out []byte
	// limit is the most out may ever hold.
	limit int
	// dictStart is where the dictionary begins: a match may not reach before
	// it. It is 0 for a .lzma stream and moves on every LZMA2 dictionary reset.
	dictStart int
	// dictSize bounds match distances when non-zero (LZMA2 and xz declare it).
	dictSize uint32

	props           props
	posMask, lpMask uint32

	isMatch    [numStates << 4]uint16
	isRep      [numStates]uint16
	isRepG0    [numStates]uint16
	isRepG1    [numStates]uint16
	isRepG2    [numStates]uint16
	isRep0Long [numStates << 4]uint16
	posSlot    [4][64]uint16
	posDec     [1 + numFullDist - endPosModel]uint16
	align      [16]uint16
	lenDec     lenCoder
	repLenDec  lenCoder
	lit        []uint16

	rep0, rep1, rep2, rep3 uint32
	state                  uint32
}

// setProps installs a new lc/lp/pb and resets the state (LZMA2 "state reset
// with new properties"; the only way a .lzma stream starts).
func (d *decoder) setProps(p props) {
	d.props = p
	d.posMask = uint32(1)<<p.pb - 1
	d.lpMask = uint32(1)<<p.lp - 1
	if n := 0x300 << (p.lc + p.lp); cap(d.lit) >= n {
		d.lit = d.lit[:n]
	} else {
		d.lit = make([]uint16, n)
	}
	d.resetState()
}

// resetState returns every probability to its initial value and clears the
// state and the repeat distances. The dictionary is untouched.
func (d *decoder) resetState() {
	fillProbs(d.isMatch[:])
	fillProbs(d.isRep[:])
	fillProbs(d.isRepG0[:])
	fillProbs(d.isRepG1[:])
	fillProbs(d.isRepG2[:])
	fillProbs(d.isRep0Long[:])
	for i := range d.posSlot {
		fillProbs(d.posSlot[i][:])
	}
	fillProbs(d.posDec[:])
	fillProbs(d.align[:])
	fillProbs(d.lit)
	d.lenDec.init()
	d.repLenDec.init()
	d.rep0, d.rep1, d.rep2, d.rep3 = 0, 0, 0, 0
	d.state = 0
}

// resetDict forgets the dictionary: nothing decoded so far may be matched.
func (d *decoder) resetDict() {
	d.dictStart = len(d.out)
}

// distanceOK reports whether a match at distance dist (rep value, so the real
// distance is dist+1) stays inside the dictionary.
func (d *decoder) distanceOK(dist uint32) bool {
	if uint64(dist) >= uint64(len(d.out)-d.dictStart) {
		return false
	}
	return d.dictSize == 0 || dist < d.dictSize
}

// run decodes packets until the output holds exactly target bytes (target is
// never past limit), or until an end-of-stream marker when one is allowed.
// It reports whether a marker ended the run. errExhausted means the range
// coder needed input that was not there; errOverrun means a match would
// have passed target.
func (d *decoder) run(target int, allowMarker bool) (bool, error) {
	if target > d.limit {
		target = d.limit
	}
	r := &d.rc
	lc := d.props.lc
	for {
		if r.exhausted {
			return false, errExhausted
		}
		if len(d.out) >= target {
			return false, nil
		}
		// Positions count from the last dictionary reset, as the reference
		// decoders count them (only the low bits matter, so wrap is harmless).
		pos := uint32(len(d.out) - d.dictStart)
		posState := pos & d.posMask
		state := d.state

		if r.bit(&d.isMatch[state<<4+posState]) == 0 {
			// Literal.
			var prev uint32
			if len(d.out) > d.dictStart {
				prev = uint32(d.out[len(d.out)-1])
			}
			probs := d.lit[0x300*(((pos&d.lpMask)<<lc)+(prev>>(8-lc))):]
			sym := uint32(1)
			if state >= 7 {
				if !d.distanceOK(d.rep0) {
					return false, ErrCorrupt
				}
				matchByte := uint32(d.out[len(d.out)-int(d.rep0)-1])
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
			d.out = append(d.out, byte(sym))
			switch {
			case state < 4:
				d.state = 0
			case state < 10:
				d.state = state - 3
			default:
				d.state = state - 6
			}
			continue
		}

		var length uint32
		if r.bit(&d.isRep[state]) != 0 {
			if len(d.out) == d.dictStart {
				return false, ErrCorrupt
			}
			if r.bit(&d.isRepG0[state]) == 0 {
				if r.bit(&d.isRep0Long[state<<4+posState]) == 0 {
					// Short rep: one byte from distance rep0.
					if !d.distanceOK(d.rep0) {
						return false, ErrCorrupt
					}
					d.out = append(d.out, d.out[len(d.out)-int(d.rep0)-1])
					if state < 7 {
						d.state = 9
					} else {
						d.state = 11
					}
					continue
				}
			} else {
				var dist uint32
				if r.bit(&d.isRepG1[state]) == 0 {
					dist = d.rep1
				} else {
					if r.bit(&d.isRepG2[state]) == 0 {
						dist = d.rep2
					} else {
						dist = d.rep3
						d.rep3 = d.rep2
					}
					d.rep2 = d.rep1
				}
				d.rep1 = d.rep0
				d.rep0 = dist
			}
			length = d.repLenDec.decode(r, posState)
			if state < 7 {
				d.state = 8
			} else {
				d.state = 11
			}
		} else {
			d.rep3, d.rep2, d.rep1 = d.rep2, d.rep1, d.rep0
			length = d.lenDec.decode(r, posState)
			if state < 7 {
				d.state = 7
			} else {
				d.state = 10
			}
			// Distance.
			lenState := length
			if lenState > 3 {
				lenState = 3
			}
			slot := r.tree(d.posSlot[lenState][:], 6)
			if slot < 4 {
				d.rep0 = slot
			} else {
				numDirect := int(slot>>1) - 1
				dist := (2 | (slot & 1)) << uint(numDirect)
				if slot < endPosModel {
					dist += r.reverseTree(d.posDec[dist-slot:], numDirect)
				} else {
					dist += r.direct(numDirect-4) << 4
					dist += r.reverseTree(d.align[:], 4)
				}
				d.rep0 = dist
			}
			if d.rep0 == 0xFFFFFFFF {
				// End-of-stream marker.
				if !allowMarker {
					return false, ErrCorrupt
				}
				return true, nil
			}
		}

		if !d.distanceOK(d.rep0) {
			return false, ErrCorrupt // a match reaching before the start of the dictionary
		}
		length += matchMinLen
		if len(d.out)+int(length) > target {
			return false, errOverrun
		}
		// Byte by byte: the source and destination may overlap, which is how
		// LZ77 encodes a run.
		src := len(d.out) - int(d.rep0) - 1
		for i := 0; i < int(length); i++ {
			d.out = append(d.out, d.out[src+i])
		}
	}
}

// capHint sizes the output buffer: the declared size when there is one, else
// a modest start that grows, never the whole limit on a stream's say-so.
func capHint(declared, limit int) int {
	if declared >= 0 && declared <= limit {
		return declared
	}
	return min(limit, 1<<20)
}

// DecodeAlone decompresses a classic ".lzma" container (one properties byte,
// a 4-byte dictionary size, an 8-byte uncompressed size or all-ones for
// unknown, then the range-coded data), producing at most limit bytes. A stream
// whose header declares more than limit, or whose data would produce more, is
// refused rather than truncated: a partial payload is not something to draw
// conclusions from. The declared dictionary size is ignored, as the whole
// output is kept.
func DecodeAlone(in []byte, limit int) ([]byte, error) {
	if len(in) < aloneHeaderLen+5 || limit <= 0 {
		return nil, ErrHeader
	}
	p, ok := parseProps(in[0], 8)
	if !ok {
		return nil, ErrHeader
	}
	unpack := binary.LittleEndian.Uint64(in[5:13])
	sizeKnown := unpack != unknownSize
	if sizeKnown && unpack > uint64(limit) {
		return nil, ErrTooLarge
	}

	d := &decoder{limit: limit}
	if !d.rc.init(in[aloneHeaderLen:]) {
		return nil, ErrCorrupt
	}
	target, declared := limit, -1
	if sizeKnown {
		target, declared = int(unpack), int(unpack)
	}
	d.out = make([]byte, 0, capHint(declared, limit))
	d.setProps(p)

	ended, err := d.run(target, true)
	switch {
	case err == errExhausted:
		return nil, ErrTruncated
	case err == errOverrun:
		if sizeKnown {
			return nil, ErrCorrupt
		}
		return nil, ErrTooLarge
	case err != nil:
		return nil, err
	case ended:
		if sizeKnown && uint64(len(d.out)) != unpack {
			return nil, ErrCorrupt
		}
		if d.rc.exhausted {
			return nil, ErrTruncated
		}
		return d.out, nil
	case !sizeKnown:
		// The limit was reached with no end marker in sight.
		return nil, ErrTooLarge
	}
	return d.out, nil
}

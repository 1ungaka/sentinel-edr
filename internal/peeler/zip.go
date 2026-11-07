package peeler

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
)

// The zip layer turns the members of an archive into branches of the same tree,
// under the same budget. An archive is packaging, so it is read differently from
// an encoding:
//
//   - A member is a file. The archive a sample *is* adds no depth, and neither
//     does one nested in it or one that was only compressed: a jar in a war and
//     a gzipped document are not obfuscation. A zip found under an encoding or a
//     substitution (base64 of a zip) does count, because then it was hidden.
//   - A jar holds thousands of class files, and a node costs thirty trial decodes.
//     Members are therefore screened first, on evidence that is cheap and exact
//     (a compression or container magic, an encoding alphabet, a blob that carves,
//     a substitution that reveals), and only those become nodes. The two guesses
//     that have no evidence to screen on, raw DEFLATE and a substitution over
//     binary, are not tried on members.
//   - Everything decompressed is charged to the output wall, screened out or not.
//   - Nothing is written anywhere and member names are never read as evidence.
//
// The reader is this package's own rather than archive/zip, which builds an entry
// for every central-directory record before a caller can count them.

const zipStep = "zip"

const (
	// maxZipMembers bounds the central-directory records read from one archive.
	// The largest of 1,645 archives on the measurement host holds 19,983.
	maxZipMembers = 32768
	// zipPeek is how much of a member is decompressed to decide whether the rest
	// is worth having: scanner/archive's magic peek.
	zipPeek = 512
	// zipStopEvery is how often the member loop asks whether the peel is over.
	zipStopEvery = 256
)

// The bomb profile is scanner/archive's, on the sizes the directory declares: a
// ratio alone is not a bomb, so it has to come with real size, or the size has to
// be very large on its own. Such an archive is refused before a member is opened.
const (
	zipBombRatio    = 100
	zipBombRatioAbs = 50 << 20
	zipBombAbsolute = 1 << 30
)

// ArchiveStats says what the zip layer did with the archives of one sample.
// Members is every record read; Peeled became branches; Screened had no layer
// evidence and were not walked; Encrypted and Unsupported could not be read.
type ArchiveStats struct {
	Archives    int `json:"archives"`
	Members     int `json:"members"`
	Peeled      int `json:"peeled"`
	Screened    int `json:"screened"`
	Encrypted   int `json:"encrypted,omitempty"`
	Unsupported int `json:"unsupported,omitempty"`
	// Damaged members had a stream that broke before its end. What came out
	// before the break was still read, so they are counted in the three above too.
	Damaged int `json:"damaged,omitempty"`
	// Unscreened members were not read at all: a wall was hit before them.
	Unscreened int `json:"unscreened,omitempty"`
}

func (a *ArchiveStats) add(b ArchiveStats) {
	a.Archives += b.Archives
	a.Members += b.Members
	a.Peeled += b.Peeled
	a.Screened += b.Screened
	a.Encrypted += b.Encrypted
	a.Unsupported += b.Unsupported
	a.Damaged += b.Damaged
	a.Unscreened += b.Unscreened
}

// containerEnv is what a container layer is told about where it sits.
type containerEnv struct {
	// limit is the decoded bytes it may produce, kept or not.
	limit int64
	// hidden reports an encoding somewhere above this blob. Without one the
	// members are files in their own right; with one they end a chain.
	hidden bool
	// stop reports that the peel is over (deadline or cancellation). May be nil.
	stop func() bool
}

// containerReport is what a container layer did besides the branches it opened.
type containerReport struct {
	stats ArchiveStats
	// screenedBytes were decompressed and discarded. They are charged all the same.
	screenedBytes int64
	// wall names a limit this container hit, which makes the peel incomplete.
	// soft marks a wall hit reading a plain archive, where nothing a chain was
	// following was cut short.
	wall string
	soft bool
}

// containerUnwrapper is a layer whose outputs are the members of an archive.
// They are parts of one transform, not rival readings of the blob, so they are
// bounded by the member cap and the node wall rather than the frontier width.
type containerUnwrapper interface {
	UnwrapContainer(blob []byte, env containerEnv) ([]Decoded, containerReport, error)
}

type zipLayer struct{}

func (zipLayer) Name() string { return zipStep }

func (zipLayer) Detect(b []byte) bool { return len(b) >= 22+30 && zipMagic(b) }

func zipMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4
}

func xzMagic(b []byte) bool {
	return len(b) >= 6 && b[0] == 0xfd && b[1] == '7' && b[2] == 'z' && b[3] == 'X' && b[4] == 'Z' && b[5] == 0
}

func (l zipLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	return firstOf(l.UnwrapAll(b, limit))
}

func (l zipLayer) UnwrapAll(b []byte, limit int64) ([]Decoded, error) {
	out, _, err := l.UnwrapContainer(b, containerEnv{limit: limit})
	return out, err
}

// zipMember is one central-directory record, as far as this layer reads it.
type zipMember struct {
	flags, method uint16
	csize, usize  uint64
	offset        uint64
}

func (m zipMember) encrypted() bool {
	// Bit 0 is the classic cipher, bit 6 strong encryption, method 99 AES.
	return m.flags&0x41 != 0 || m.method == 99
}

const (
	zipEndLen    = 22
	zipDirLen    = 46
	zipLocalLen  = 30
	zipEnd64Len  = 56
	zipLocator64 = 20
)

// zipSig reports the record signature PK c d at offset at. Offsets come from the
// sample, so every bound here and below is a subtraction from the length: a sum
// of two hostile 64-bit values can wrap back inside the buffer.
func zipSig(b []byte, at uint64, c, d byte) bool {
	n := uint64(len(b))
	return n >= 4 && at <= n-4 && b[at] == 'P' && b[at+1] == 'K' && b[at+2] == c && b[at+3] == d
}

// zipDirectory finds the central directory and the offset every record in it is
// relative to (non-zero when something was prepended to the archive).
func zipDirectory(b []byte) (dir []byte, base uint64, ok bool) {
	if len(b) < zipEndLen {
		return nil, 0, false
	}
	end := -1
	for i := len(b) - zipEndLen; i >= max(0, len(b)-zipEndLen-0xffff); i-- {
		if zipSig(b, uint64(i), 5, 6) && i+zipEndLen+int(binary.LittleEndian.Uint16(b[i+20:])) <= len(b) {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, 0, false
	}
	records := uint64(binary.LittleEndian.Uint16(b[end+10:]))
	size := uint64(binary.LittleEndian.Uint32(b[end+12:]))
	off := uint64(binary.LittleEndian.Uint32(b[end+16:]))
	dirEnd := uint64(end)
	if records == 0xffff || size == 0xffffffff || off == 0xffffffff {
		if s, o, at, ok := zip64Directory(b, end); ok {
			size, off, dirEnd = s, o, at
		}
	}
	// The directory ends where the end record starts, so both lengths fit under
	// that offset, and with them every sum below.
	if size > dirEnd || off > dirEnd-size {
		return nil, 0, false
	}
	base = dirEnd - size - off
	if size > 0 && !zipSig(b, dirEnd-size, 1, 2) {
		base = 0
	}
	start := base + off
	return b[start : start+size], base, true
}

// zip64Directory reads the zip64 end record the locator before end points at.
func zip64Directory(b []byte, end int) (size, off, at uint64, ok bool) {
	loc := end - zipLocator64
	if loc < 0 || !zipSig(b, uint64(loc), 6, 7) {
		return 0, 0, 0, false
	}
	at = binary.LittleEndian.Uint64(b[loc+8:])
	if n := uint64(len(b)); !zipSig(b, at, 6, 6) || n < zipEnd64Len || at > n-zipEnd64Len {
		// Prepended data shifts the record; it sits right before its locator.
		if loc < zipEnd64Len || !zipSig(b, uint64(loc-zipEnd64Len), 6, 6) {
			return 0, 0, 0, false
		}
		at = uint64(loc - zipEnd64Len)
	}
	return binary.LittleEndian.Uint64(b[at+40:]), binary.LittleEndian.Uint64(b[at+48:]), at, true
}

// zipMembers walks the directory, calling visit for each record until it returns
// false or maxZipMembers have been read. more reports records past that cap.
func zipMembers(dir []byte, visit func(zipMember) bool) (more bool) {
	read := 0
	for p := 0; p+zipDirLen <= len(dir) && zipSig(dir, uint64(p), 1, 2); {
		nameLen := int(binary.LittleEndian.Uint16(dir[p+28:]))
		extraLen := int(binary.LittleEndian.Uint16(dir[p+30:]))
		commentLen := int(binary.LittleEndian.Uint16(dir[p+32:]))
		next := p + zipDirLen + nameLen + extraLen + commentLen
		if next > len(dir) {
			return false
		}
		if read >= maxZipMembers {
			return true
		}
		read++
		m := zipMember{
			flags:  binary.LittleEndian.Uint16(dir[p+8:]),
			method: binary.LittleEndian.Uint16(dir[p+10:]),
			csize:  uint64(binary.LittleEndian.Uint32(dir[p+20:])),
			usize:  uint64(binary.LittleEndian.Uint32(dir[p+24:])),
			offset: uint64(binary.LittleEndian.Uint32(dir[p+42:])),
		}
		m.zip64(dir[p+zipDirLen+nameLen : p+zipDirLen+nameLen+extraLen])
		if !visit(m) {
			return false
		}
		p = next
	}
	return false
}

// zip64 replaces the saturated 32-bit fields from the zip64 extra block, which
// lists only the fields that overflowed, in this order.
func (m *zipMember) zip64(extra []byte) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		n := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+n > len(extra) {
			return
		}
		body := extra[4 : 4+n]
		extra = extra[4+n:]
		if id != 1 {
			continue
		}
		for _, field := range []*uint64{&m.usize, &m.csize, &m.offset} {
			if *field == 0xffffffff && len(body) >= 8 {
				*field = binary.LittleEndian.Uint64(body)
				body = body[8:]
			}
		}
		return
	}
}

// zipData is a member's stored bytes, located through its local header.
func zipData(b []byte, base uint64, m zipMember) ([]byte, bool) {
	n := uint64(len(b))
	if n < zipLocalLen || base > n-zipLocalLen || m.offset > n-zipLocalLen-base {
		return nil, false
	}
	h := base + m.offset
	if !zipSig(b, h, 3, 4) {
		return nil, false
	}
	// Two 16-bit lengths: the header ends at most 131,100 bytes past h.
	skip := zipLocalLen + uint64(binary.LittleEndian.Uint16(b[h+26:])) + uint64(binary.LittleEndian.Uint16(b[h+28:]))
	if skip > n-h {
		return nil, false
	}
	start := h + skip
	// A size that runs past the file is clamped: the stream ends where it ends.
	size := min(m.csize, n-start)
	return b[start : start+size], true
}

// zipInflater reuses one decompressor across the members of an archive.
type zipInflater struct {
	src bytes.Reader
	fr  io.ReadCloser
}

func (z *zipInflater) open(data []byte) io.Reader {
	z.src.Reset(data)
	if z.fr == nil {
		z.fr = flate.NewReader(&z.src)
	} else {
		z.fr.(flate.Resetter).Reset(&z.src, nil)
	}
	return z.fr
}

// Member ranks, best first. The walk spends its nodes in this order, so what is
// most likely to be a layer is reached before the node wall is.
const (
	rankNone = iota
	rankText
	rankEncoding
	rankMagic
)

// headRank reads the first bytes of a member. text reports a member that has to
// be read whole before it can be ranked.
func headRank(peek []byte, hidden bool) (rank int, text bool) {
	if len(peek) < minLayerLen {
		return rankNone, false
	}
	switch {
	case gzipLayer{}.Detect(peek), bzip2Layer{}.Detect(peek), zlibLayer{}.Detect(peek),
		zipMagic(peek), xzMagic(peek), utf16Layer{}.Detect(peek):
		return rankMagic, false
	case hidden && executableMagic(peek):
		return rankMagic, false
	}
	return rankNone, printableFraction(peek) >= 0.85
}

func executableMagic(b []byte) bool {
	t, ok := classify(b[:min(len(b), 4)])
	return ok && t == OutcomeRevealedExecutable
}

// textLayers are the layers that read a whole blob as one encoding. Their Detect
// is an alphabet check, which is exact and stops at the first byte outside it.
var textLayers = sync.OnceValue(func() []Unwrapper {
	return append([]Unwrapper{base64Layer{}, base32Layer{}, hexLayer{}}, baseLayers()...)
})

// bodyRank ranks a text member by what the walk would find in it.
func bodyRank(body []byte, hidden bool, limit int64) int {
	if hidden {
		if _, ok := classify(body); ok {
			return rankMagic
		}
	}
	for _, l := range textLayers() {
		if l.Detect(body) {
			return rankEncoding
		}
	}
	if (carveLayer{}).Detect(body) {
		if _, err := (carveLayer{}).UnwrapAll(body, limit); !errors.Is(err, ErrNotThisLayer) {
			return rankText
		}
	}
	if _, err := (cipherLayer{}).UnwrapAll(body, limit); !errors.Is(err, ErrNotThisLayer) {
		return rankText
	}
	return rankNone
}

// textGuess rates a text member from its first bytes alone, for the order the
// members are read whole in: one unbroken run of an encoding first, then text
// holding a run long enough to carve, then everything else.
func textGuess(peek []byte) int {
	if isToken(textBody(peek)) {
		return 2
	}
	run := 0
	for _, c := range peek {
		if base64Byte(c) || c == '=' {
			if run++; run >= minCarveRun {
				return 1
			}
		} else {
			run = 0
		}
	}
	return 0
}

// UnwrapContainer returns the members worth walking, best first.
func (zipLayer) UnwrapContainer(b []byte, env containerEnv) ([]Decoded, containerReport, error) {
	var rep containerReport
	if !zipMagic(b) {
		return nil, rep, ErrNotThisLayer
	}
	dir, base, ok := zipDirectory(b)
	if !ok {
		return nil, rep, ErrNotThisLayer
	}
	rep.stats.Archives = 1

	// First pass, nothing opened: what the directory declares.
	var declared, packed uint64
	more := zipMembers(dir, func(m zipMember) bool {
		rep.stats.Members++
		// Saturating: a directory can declare sizes whose sum does not fit.
		declared += min(m.usize, ^uint64(0)-declared)
		packed += min(m.csize, ^uint64(0)-packed)
		return true
	})
	if more {
		rep.wall = fmt.Sprintf("zip member cap (first %d members read)", maxZipMembers)
	}
	if declared >= zipBombAbsolute || (declared >= zipBombRatioAbs && declared/max(packed, 1) >= zipBombRatio) {
		rep.wall = fmt.Sprintf("zip decompression-bomb profile (declares %d bytes from %d)", declared, packed)
		rep.stats.Screened = rep.stats.Members
		return nil, rep, nil
	}

	// What a hidden zip holds is the end of a chain, so a payload in it is
	// walked. In a plain archive it is a file like any other.
	hidden := env.hidden
	type candidate struct {
		data  []byte
		rank  int
		index int
	}
	// The members are read in two passes. The first peeks at every one, which
	// is cheap, and settles the ones a peek can settle. The text members it
	// cannot are read whole in the second, most promising first, so the budget
	// reaches a member that looks like an encoding before it reaches the
	// documentation around it.
	type pending struct {
		m     zipMember
		index int
		guess int
	}
	var (
		picked  []candidate
		later   []pending
		spent   int64
		index   int // directory records visited in the first pass
		read    int // members fully settled
		over    bool
		stopped bool
		inf     zipInflater
		head    [zipPeek]byte
	)
	room := func() int64 { return env.limit - spent }
	halt := func(n int) bool {
		if n%zipStopEvery == 0 && env.stop != nil && env.stop() {
			stopped = true
			return true
		}
		return false
	}
	// open yields a member's first bytes and, for a deflated one, the rest of
	// its stream.
	open := func(m zipMember, data []byte) (peek []byte, rest io.Reader) {
		if m.method == 0 {
			return data[:min(len(data), zipPeek)], nil
		}
		rest = inf.open(data)
		n, err := io.ReadFull(rest, head[:])
		peek = head[:n]
		// A member shorter than the peek ends early. Anything else is a
		// stream that broke: what it held is still read, and it is counted.
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			rep.stats.Damaged++
			rest = nil
		}
		return peek, rest
	}
	// whole reads the member behind peek to its end, within the room left.
	whole := func(m zipMember, data, peek []byte, rest io.Reader) ([]byte, bool) {
		if m.method == 0 {
			if int64(len(data)-len(peek)) > room() {
				return nil, false
			}
			spent += int64(len(data) - len(peek))
			return data, true
		}
		var tail []byte
		if rest != nil {
			var err error
			if tail, err = io.ReadAll(io.LimitReader(rest, room()+1)); err != nil {
				rep.stats.Damaged++
			}
		}
		if int64(len(tail)) > room() {
			return nil, false
		}
		spent += int64(len(tail))
		return append(append(make([]byte, 0, len(peek)+len(tail)), peek...), tail...), true
	}

	zipMembers(dir, func(m zipMember) bool {
		if halt(index) {
			return false
		}
		index++
		switch {
		case m.encrypted():
			rep.stats.Encrypted++
			read++
			return true
		case m.method != 0 && m.method != 8:
			rep.stats.Unsupported++
			read++
			return true
		}
		data, ok := zipData(b, base, m)
		if !ok || len(data) == 0 {
			rep.stats.Screened++
			read++
			return true
		}
		peek, rest := open(m, data)
		if int64(len(peek)) > room() {
			over = true
			index--
			return false
		}
		spent += int64(len(peek))
		rank, text := headRank(peek, hidden)
		switch {
		case rank != rankNone:
			// A magic at the head: the member is worth walking whole.
			body, ok := whole(m, data, peek, rest)
			if !ok {
				over = true
				index--
				return false
			}
			picked = append(picked, candidate{data: body, rank: rank, index: index})
		case text:
			later = append(later, pending{m: m, index: index, guess: textGuess(peek)})
			return true
		default:
			rep.stats.Screened++
		}
		read++
		return true
	})

	// Second pass: the text members, in the order the peek rated them.
	sort.SliceStable(later, func(i, j int) bool { return later[i].guess > later[j].guess })
	for i, p := range later {
		if over || halt(i) {
			break
		}
		data, _ := zipData(b, base, p.m)
		peek, rest := open(p.m, data)
		body, ok := whole(p.m, data, peek, rest)
		if !ok {
			over = true
			break
		}
		read++
		if rank := bodyRank(body, hidden, env.limit); rank != rankNone {
			picked = append(picked, candidate{data: body, rank: rank, index: p.index})
		} else {
			rep.stats.Screened++
		}
	}

	// A wall hit reading a hidden archive cut a chain short. In a plain one it
	// only means the archive was not read through, which is said, not scored:
	// the members before it are still returned.
	rep.stats.Unscreened = rep.stats.Members - read
	switch {
	case over && hidden:
		return nil, rep, errBombCap
	case over:
		rep.wall, rep.soft = fmt.Sprintf("archive read past the output wall (%d of %d members read)", read, rep.stats.Members), true
	case stopped && hidden:
		rep.wall = deadlineReason
	case stopped:
		rep.wall, rep.soft = fmt.Sprintf("archive read past the wall clock (%d of %d members read)", read, rep.stats.Members), true
	}

	sort.SliceStable(picked, func(i, j int) bool {
		if picked[i].rank != picked[j].rank {
			return picked[i].rank > picked[j].rank
		}
		return picked[i].index < picked[j].index
	})
	out := make([]Decoded, len(picked))
	for i, c := range picked {
		out[i] = Decoded{Data: c.data, Label: zipStep}
		spent -= int64(len(c.data))
	}
	rep.stats.Peeled = len(out)
	rep.screenedBytes = spent
	return out, rep, nil
}

package lzma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ── raw LZMA2 ──────────────────────────────────────────────────────────────

// lzma2DictSize reads the dictionary size out of a fixture name
// (NAME.d<size>.<props>.lzma2, size in k or m).
func lzma2DictSize(t *testing.T, path string) uint32 {
	t.Helper()
	for _, part := range strings.Split(filepath.Base(path), ".") {
		if len(part) < 3 || part[0] != 'd' {
			continue
		}
		n, err := strconv.Atoi(part[1 : len(part)-1])
		if err != nil {
			continue
		}
		switch part[len(part)-1] {
		case 'k':
			return uint32(n) << 10
		case 'm':
			return uint32(n) << 20
		}
	}
	t.Fatalf("%s: no dictionary size in the name", path)
	return 0
}

func TestLZMA2DecodesReferenceStreams(t *testing.T) {
	for path, stream := range fixtures(t, "lzma2", 20) {
		w := want(t, path)
		got, err := DecodeLZMA2(stream, lzma2DictSize(t, path), 1<<20)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, w) {
			t.Errorf("%s: decoded %d bytes, want %d; first difference at %d", path, len(got), len(w), firstDiff(got, w))
		}
	}
}

// lzma2Stored builds an LZMA2 stream of stored chunks, the first resetting
// the dictionary, so the tests can shape hostile inputs without an encoder.
func lzma2Stored(chunks ...[]byte) []byte {
	var out []byte
	for i, c := range chunks {
		ctl := byte(0x02)
		if i == 0 {
			ctl = 0x01
		}
		out = append(out, ctl, byte((len(c)-1)>>8), byte(len(c)-1))
		out = append(out, c...)
	}
	return append(out, 0x00)
}

func TestLZMA2StoredChunks(t *testing.T) {
	a, b := bytes.Repeat([]byte("a"), 300), bytes.Repeat([]byte("b"), 65536)
	got, err := DecodeLZMA2(lzma2Stored(a, b), 1<<16, 1<<20)
	if err != nil || !bytes.Equal(got, append(a, b...)) {
		t.Fatalf("stored chunks: %v (%d bytes)", err, len(got))
	}
	if _, err := DecodeLZMA2(lzma2Stored(a, b), 1<<16, len(a)+len(b)-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte under the real size: %v", err)
	}
	// Empty: the end marker alone.
	if got, err := DecodeLZMA2([]byte{0}, 4096, 1); err != nil || len(got) != 0 {
		t.Errorf("empty stream: %v (%d bytes)", err, len(got))
	}
	// A long chain of tiny chunks terminates and costs only its bytes.
	many := make([][]byte, 20000)
	for i := range many {
		many[i] = []byte{byte(i)}
	}
	if got, err := DecodeLZMA2(lzma2Stored(many...), 4096, 1<<20); err != nil || len(got) != len(many) {
		t.Errorf("20000 chunks: %v (%d bytes)", err, len(got))
	}
	if _, err := DecodeLZMA2(lzma2Stored(many...), 4096, 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("20000 chunks over a 100-byte limit: %v", err)
	}
}

func TestLZMA2RejectsBadInput(t *testing.T) {
	good := fixture(t, "text.d4k.lc3lp0pb2.lzma2")
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"empty":                 {nil, ErrTruncated},
		"no end marker":         {good[:len(good)-1], ErrTruncated},
		"first chunk no reset":  {append([]byte{good[0] &^ 0x20}, good[1:]...), ErrCorrupt},
		"stored before props":   {append(lzma2Stored([]byte("ab"))[:5], append([]byte{0x80, 0, 0, 0, 5, 0, 0, 0, 0, 0}, 0)...), ErrCorrupt},
		"invalid control":       {[]byte{0x03, 0, 0, 0}, ErrCorrupt},
		"props over 4":          {append([]byte{good[0], good[1], good[2], good[3], good[4], 4 + 9*1}, good[6:]...), ErrCorrupt},
		"props byte 225":        {append([]byte{good[0], good[1], good[2], good[3], good[4], 225}, good[6:]...), ErrCorrupt},
		"stored chunk cut":      {[]byte{0x01, 0, 9, 'a', 'b'}, ErrTruncated},
		"lzma chunk cut":        {good[:len(good)/2], ErrTruncated},
		"nonzero range lead":    {append(append([]byte(nil), good[:6]...), append([]byte{1}, good[7:]...)...), ErrCorrupt},
		"packed size too short": {append(append([]byte(nil), good[:3]...), append([]byte{0, 4}, good[5:]...)...), ErrCorrupt},
	}
	for name, c := range cases {
		out, err := DecodeLZMA2(c.in, 4096, 1<<20)
		if !errors.Is(err, c.want) || out != nil {
			t.Errorf("%s: err=%v (want %v) out=%d", name, err, c.want, len(out))
		}
	}
	// A chunk whose first packet is a match reads before the start of the
	// output; one whose data continues after a dictionary reset must not
	// reach into the bytes before the reset.
	evil := []byte{0xE0, 0, 9, 0, 9, 0x5D, 0, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}
	if out, err := DecodeLZMA2(evil, 4096, 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
		t.Errorf("match before start: %v", err)
	}
	// The same, range-coded exactly: a chunk whose only packet is a short
	// rep (distance rep0 = 1) reads before the start of a fresh dictionary.
	if out, err := DecodeLZMA2(append(shortRepChunk(0xE0), 0), 4096, 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
		t.Errorf("short rep at the start: %v", err)
	}
	// Truncation at every byte is an error with no partial output.
	for n := 0; n < len(good); n++ {
		if out, err := DecodeLZMA2(good[:n], 4096, 1<<16); err == nil || out != nil {
			t.Fatalf("truncated at %d: err=%v out=%d", n, err, len(out))
		}
	}
	// A dictionary size that claims 4 GiB costs nothing and bounds nothing
	// the stream does not use.
	if got, err := DecodeLZMA2(good, 0xFFFFFFFF, 1<<20); err != nil || !bytes.Equal(got, fixture(t, "text.raw")) {
		t.Errorf("4 GiB dictionary claim: %v", err)
	}
	// Declared sizes past the limit are refused before any work.
	if _, err := DecodeLZMA2(good, 4096, 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("limit under the chunk size: %v", err)
	}
	if _, err := DecodeLZMA2(good, 4096, 0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zero limit: %v", err)
	}
}

// rcEncoder is a range encoder, enough to range-code a few bits so the tests
// can build an LZMA chunk by hand: a chunk that only an encoder could make
// is the only way to say "match into what is before the dictionary reset".
type rcEncoder struct {
	low       uint64
	rng       uint32
	cache     byte
	cacheSize int
	out       []byte
}

func newRCEncoder() *rcEncoder { return &rcEncoder{rng: 0xFFFFFFFF, cacheSize: 1} }

func (e *rcEncoder) shiftLow() {
	if uint32(e.low) < 0xFF000000 || e.low>>32 != 0 {
		carry := byte(e.low >> 32)
		temp := e.cache
		for {
			e.out = append(e.out, temp+carry)
			temp = 0xFF
			e.cacheSize--
			if e.cacheSize == 0 {
				break
			}
		}
		e.cache = byte(uint32(e.low) >> 24)
	}
	e.cacheSize++
	e.low = uint64(uint32(e.low) << 8)
}

func (e *rcEncoder) bit(prob *uint16, b uint32) {
	bound := (e.rng >> 11) * uint32(*prob)
	if b == 0 {
		e.rng = bound
		*prob += (bitModelTotal - *prob) >> 5
	} else {
		e.low += uint64(bound)
		e.rng -= bound
		*prob -= *prob >> 5
	}
	for e.rng < topValue {
		e.rng <<= 8
		e.shiftLow()
	}
}

func (e *rcEncoder) flush() []byte {
	for i := 0; i < 5; i++ {
		e.shiftLow()
	}
	return e.out
}

// shortRepChunk is an LZMA2 chunk (props lc3 lp0 pb2) of one packet: a short
// rep, which copies the byte at distance rep0+1 = 1. Over an empty dictionary
// that is a read before the start; after a byte it is a legitimate repeat.
// control carries the reset bits.
func shortRepChunk(control byte) []byte {
	e := newRCEncoder()
	p := [4]uint16{probInit, probInit, probInit, probInit}
	e.bit(&p[0], 1) // isMatch
	e.bit(&p[1], 1) // isRep
	e.bit(&p[2], 0) // isRepG0: distance rep0
	e.bit(&p[3], 0) // isRep0Long: one byte
	rc := e.flush()
	chunk := []byte{control, 0, 0, byte((len(rc) - 1) >> 8), byte(len(rc) - 1), 0x5D}
	return append(chunk, rc...)
}

// The dictionary carries across chunks until a chunk resets it, and a reset
// is a wall: a match may not reach into the bytes before it.
func TestLZMA2DictResetIsAWall(t *testing.T) {
	stored := lzma2Stored([]byte("ab"))[:5] // 0x01 chunk, no end marker
	// 0xC0: state reset with properties, dictionary kept: "ab" + "b".
	got, err := DecodeLZMA2(append(append(append([]byte(nil), stored...), shortRepChunk(0xC0)...), 0), 4096, 1<<20)
	if err != nil || string(got) != "abb" {
		t.Fatalf("continuation: %v %q", err, got)
	}
	// 0xE0: the dictionary is reset first, so the same packet reads before
	// the start of what may be matched.
	got, err = DecodeLZMA2(append(append(append([]byte(nil), stored...), shortRepChunk(0xE0)...), 0), 4096, 1<<20)
	if !errors.Is(err, ErrCorrupt) || got != nil {
		t.Fatalf("after a reset: %v %q", err, got)
	}
	// Through the xz container too, where every block starts with a reset.
	if out, err := Decode(buildXZ(t, 0, append(shortRepChunk(0xE0), 0)), 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
		t.Fatalf("xz block reading before its start: %v", err)
	}
	// A fixture chunk presented after a stored prefix without a reset
	// decodes to the prefix and then the fixture: positions count from the
	// last reset, and the chunk's own matches stay inside its own bytes.
	fix := fixture(t, "text.d4k.lc3lp0pb2.lzma2")
	packed := int(fix[3])<<8 | int(fix[4]) + 1
	first := append([]byte{0xC0 | fix[0]&0x1F}, fix[1:6+packed]...)
	prefix := lzma2Stored(bytes.Repeat([]byte("x"), 100))[:103]
	got, err = DecodeLZMA2(append(append(prefix, first...), 0), 4096, 1<<20)
	if err == nil {
		if !bytes.Equal(got[:100], bytes.Repeat([]byte("x"), 100)) || !bytes.HasPrefix(fixture(t, "text.raw"), got[100:]) {
			t.Fatalf("a chunk after a stored prefix decoded wrong")
		}
	} else if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("chunk after a stored prefix: %v", err)
	}
}

// buildXZ wraps raw LZMA2 block payloads in a single xz stream with the
// given check type (0 none, 1 crc32, 4 crc64, 10 sha256). The index is
// computed from the payloads, so it agrees with them.
func buildXZ(t *testing.T, check byte, blocks ...[]byte) []byte {
	t.Helper()
	flags := []byte{0, check}
	out := append(append([]byte(nil), xzMagic[:]...), flags...)
	out = append(out, crc32Bytes(flags)...)
	_, checkSize, _ := checkInfo(check)
	index := []byte{0x00}
	index = append(index, putVarint(uint64(len(blocks)))...)
	for _, data := range blocks {
		hdr := []byte{0, 0x00, 0x21, 0x01, 0x10} // one filter, LZMA2, 1 MiB dictionary
		for len(hdr)%4 != 0 {
			hdr = append(hdr, 0)
		}
		hdr[0] = byte(len(hdr)/4) - 1
		hdr = append(hdr, crc32Bytes(hdr)...)
		out = append(out, hdr...)
		out = append(out, data...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		plain, err := DecodeLZMA2(data, 1<<20, 1<<20)
		if err != nil {
			plain = nil // a hostile block: the check is over nothing
		}
		switch check {
		case 1:
			out = append(out, crc32Bytes(plain)...)
		default:
			out = append(out, make([]byte, checkSize)...)
		}
		index = append(index, putVarint(uint64(len(hdr)+len(data)+checkSize))...)
		index = append(index, putVarint(uint64(len(plain)))...)
	}
	for len(index)%4 != 0 {
		index = append(index, 0)
	}
	index = append(index, crc32Bytes(index)...)
	out = append(out, index...)
	footer := make([]byte, 12)
	binary.LittleEndian.PutUint32(footer[4:], uint32(len(index)/4-1))
	footer[8], footer[9] = flags[0], flags[1]
	footer[10], footer[11] = 'Y', 'Z'
	copy(footer[0:4], crc32Bytes(footer[4:10]))
	return append(out, footer...)
}

// ── xz ─────────────────────────────────────────────────────────────────────

func TestXZDecodesReferenceStreams(t *testing.T) {
	for path, stream := range fixtures(t, "xz", 20) {
		if strings.Contains(path, ".x86.") {
			continue
		}
		w := want(t, path)
		got, rep, err := DecodeReport(stream, 1<<20)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, w) {
			t.Errorf("%s: decoded %d bytes, want %d; first difference at %d", path, len(got), len(w), firstDiff(got, w))
		}
		if rep.Unverified != 0 || rep.Streams < 1 || rep.Blocks < 1 {
			t.Errorf("%s: report %+v", path, rep)
		}
		if !IsXZ(stream) {
			t.Errorf("%s: IsXZ false", path)
		}
	}
	// The report names what it verified.
	for name, check := range map[string]string{"text.crc32.xz": "crc32", "text.crc64.xz": "crc64", "text.sha256.xz": "sha256", "text.none.xz": "none"} {
		if _, rep, err := DecodeReport(fixture(t, name), 1<<20); err != nil || rep.Check != check {
			t.Errorf("%s: %v %+v", name, err, rep)
		}
	}
	if _, rep, err := DecodeReport(fixture(t, "text.multiblock.xz"), 1<<20); err != nil || rep.Blocks < 2 || rep.Streams != 1 {
		t.Errorf("multiblock: %v %+v", err, rep)
	}
	if _, rep, err := DecodeReport(fixture(t, "text.twostreams.xz"), 1<<20); err != nil || rep.Streams != 2 || rep.Blocks != 2 {
		t.Errorf("two streams: %v %+v", err, rep)
	}
}

func TestXZUnsupportedFilterIsReported(t *testing.T) {
	out, err := Decode(fixture(t, "text.x86.xz"), 1<<20)
	if !errors.Is(err, ErrUnsupported) || out != nil {
		t.Fatalf("BCJ x86 chain: err=%v out=%d", err, len(out))
	}
}

func TestXZLimits(t *testing.T) {
	stream := fixture(t, "runs.crc32.xz")
	w := fixture(t, "runs.raw")
	if got, err := Decode(stream, len(w)); err != nil || len(got) != len(w) {
		t.Errorf("limit at the real size: %v (%d bytes)", err, len(got))
	}
	if out, err := Decode(stream, len(w)-1); !errors.Is(err, ErrTooLarge) || out != nil {
		t.Errorf("limit one under: %v", err)
	}
	if _, err := Decode(stream, 0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("zero limit: %v", err)
	}
	// Two streams share one limit.
	two := fixture(t, "text.twostreams.xz")
	if out, err := Decode(two, 6000); !errors.Is(err, ErrTooLarge) || out != nil {
		t.Errorf("two streams over one limit: %v", err)
	}
	// A 64 MiB dictionary claim allocates nothing: the stream decodes under
	// a limit far smaller than the dictionary.
	if got, err := Decode(fixture(t, "text.d64m.xz"), 1<<15); err != nil || !bytes.Equal(got, fixture(t, "text.raw")) {
		t.Errorf("64 MiB dictionary: %v", err)
	}
}

// patch returns a copy of b with the byte at i replaced.
func patch(b []byte, i int, v byte) []byte {
	out := append([]byte(nil), b...)
	out[i] = v
	return out
}

func TestXZRejectsBadInput(t *testing.T) {
	stream := fixture(t, "text.crc32.xz")
	hdrLen := (int(stream[12]) + 1) * 4
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"empty":                {nil, ErrHeader},
		"bad magic":            {patch(stream, 0, 0xFE), ErrHeader},
		"header only":          {stream[:12], ErrTruncated},
		"bad header crc":       {patch(stream, 8, stream[8]^1), ErrCorrupt},
		"reserved stream flag": {append(append([]byte(nil), stream[:6]...), append(append([]byte{0x80, 0x01}, crc32Bytes([]byte{0x80, 0x01})...), stream[12:]...)...), ErrUnsupported},
		"bad block crc":        {patch(stream, 12+hdrLen-1, stream[12+hdrLen-1]^1), ErrCorrupt},
		"bad check":            {patch(stream, findIndex(stream)-1, stream[findIndex(stream)-1]^1), ErrCorrupt},
		"bad footer crc":       {patch(stream, len(stream)-12, stream[len(stream)-12]^1), ErrCorrupt},
		"bad footer magic":     {patch(stream, len(stream)-1, 'X'), ErrCorrupt},
		"trailing garbage":     {append(append([]byte(nil), stream...), 1, 2, 3, 4), ErrCorrupt},
		"short padding":        {append(append([]byte(nil), stream...), 0, 0), ErrCorrupt},
	}
	for name, c := range cases {
		out, err := Decode(c.in, 1<<20)
		if !errors.Is(err, c.want) || out != nil {
			t.Errorf("%s: err=%v (want %v) out=%d", name, err, c.want, len(out))
		}
	}

	// Truncated at every byte: an error, never partial output, never a hang.
	for n := 0; n < len(stream); n++ {
		if out, err := Decode(stream[:n], 1<<16); err == nil || out != nil {
			t.Fatalf("truncated at %d: err=%v out=%d", n, err, len(out))
		}
	}
	// Index records that disagree with the block (the uncompressed size is
	// the last varint before the index padding and CRC).
	idx := len(stream) - 12 - 4 - 1
	for idx > 12 && stream[idx]&0x80 != 0 {
		idx--
	}
	for v := byte(0); v < 4; v++ {
		if out, err := Decode(patch(stream, idx, stream[idx]^(1<<v)), 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
			t.Errorf("index bit %d: err=%v", v, err)
		}
	}
	// Block header claims: a declared uncompressed size past the limit is
	// refused before any work, a wrong one is corrupt.
	sized := withSizes(t, stream, 3, uint64(len(fixture(t, "text.raw"))))
	if got, err := Decode(sized, 1<<20); err != nil || !bytes.Equal(got, fixture(t, "text.raw")) {
		t.Fatalf("sized block header: %v", err)
	}
	if out, err := Decode(withSizes(t, stream, 3, 1<<40), 1<<20); !errors.Is(err, ErrTooLarge) || out != nil {
		t.Errorf("declared 1 TiB block: %v", err)
	}
	if out, err := Decode(withSizes(t, stream, 3, 7), 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
		t.Errorf("wrong declared size: %v", err)
	}
	// A dictionary-size property of 40 claims 4 GiB; the stream still decodes
	// under a small limit because nothing is allocated from the claim.
	if got, err := Decode(withDictProp(t, stream, 40), 1<<15); err != nil || !bytes.Equal(got, fixture(t, "text.raw")) {
		t.Errorf("4 GiB dictionary property: %v", err)
	}
	if out, err := Decode(withDictProp(t, stream, 41), 1<<20); !errors.Is(err, ErrCorrupt) || out != nil {
		t.Errorf("dictionary property 41: %v", err)
	}
}

func crc32Bytes(b []byte) []byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], crc32.ChecksumIEEE(b))
	return out[:]
}

// rebuildBlockHeader replaces the first block header of a single-block
// stream with one carrying the given flags and body, then repairs the index
// so the file still agrees with itself. The compressed data is untouched.
func rebuildBlockHeader(t *testing.T, stream []byte, flags byte, body []byte) []byte {
	t.Helper()
	oldLen := (int(stream[12]) + 1) * 4
	hdr := append([]byte{0, flags}, body...)
	for len(hdr)%4 != 0 {
		hdr = append(hdr, 0)
	}
	hdr[0] = byte(len(hdr)/4) - 1 // header size counts the CRC too
	hdr = append(hdr, crc32Bytes(hdr)...)
	out := append(append([]byte(nil), stream[:12]...), hdr...)
	// The index's unpadded size counts the header, so the index and the
	// footer's backward size are rebuilt from the original's figures.
	_, rep, err := DecodeReport(stream, 1<<20)
	if err != nil || rep.Blocks != 1 {
		t.Fatalf("rebuildBlockHeader needs a sound single-block stream: %v %+v", err, rep)
	}
	indexStart := findIndex(stream)
	data := stream[12+oldLen : indexStart]
	oldUnpadded, n1, _ := varint(stream[indexStart+2:])
	uncompressed, _, _ := varint(stream[indexStart+2+n1:])
	unpadded := oldUnpadded - uint64(oldLen) + uint64(len(hdr))
	index := []byte{0x00, 0x01}
	index = append(index, putVarint(unpadded)...)
	index = append(index, putVarint(uncompressed)...)
	for len(index)%4 != 0 {
		index = append(index, 0)
	}
	index = append(index, crc32Bytes(index)...)
	footer := make([]byte, 12)
	binary.LittleEndian.PutUint32(footer[4:], uint32(len(index)/4-1))
	footer[8], footer[9] = stream[6], stream[7]
	footer[10], footer[11] = 'Y', 'Z'
	copy(footer[0:4], crc32Bytes(footer[4:10]))
	out = append(out, data...)
	out = append(out, index...)
	return append(out, footer...)
}

// findIndex returns the offset of the index of a single-stream file, read
// back from the footer's backward size.
func findIndex(stream []byte) int {
	f := stream[len(stream)-12:]
	indexLen := (int(binary.LittleEndian.Uint32(f[4:8])) + 1) * 4
	return len(stream) - 12 - indexLen
}

func putVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// withSizes rebuilds the block header with both sizes declared: compressed
// as it really is (read from the index), uncompressed as given.
func withSizes(t *testing.T, stream []byte, _ int, uncompressed uint64) []byte {
	t.Helper()
	indexStart := findIndex(stream)
	hdrLen := (int(stream[12]) + 1) * 4
	unpadded, _, _ := varint(stream[indexStart+2:])
	_, checkSize, _ := checkInfo(stream[7] & 0x0F)
	compressed := unpadded - uint64(hdrLen) - uint64(checkSize)
	body := append(putVarint(compressed), putVarint(uncompressed)...)
	body = append(body, 0x21, 0x01, dictProp(stream))
	return rebuildBlockHeader(t, stream, 0xC0, body)
}

// dictProp reads the LZMA2 dictionary property of the first block.
func dictProp(stream []byte) byte {
	hdrLen := (int(stream[12]) + 1) * 4
	hdr := stream[12 : 12+hdrLen]
	for i := 2; i+2 < len(hdr)-4; i++ {
		if hdr[i] == 0x21 && hdr[i+1] == 0x01 {
			return hdr[i+2]
		}
	}
	return 0
}

func withDictProp(t *testing.T, stream []byte, prop byte) []byte {
	t.Helper()
	return rebuildBlockHeader(t, stream, 0x00, []byte{0x21, 0x01, prop})
}

// A reserved check type is walked and reported unverified, not refused: the
// bytes are still decoded and the index still has to agree.
func TestXZReservedCheckIsUnverified(t *testing.T) {
	stream := fixture(t, "text.crc32.xz") // check id 1 → 4 bytes, like id 2
	flags := []byte{0x00, 0x02}
	alt := append(append([]byte(nil), stream[:6]...), flags...)
	alt = append(alt, crc32Bytes(flags)...)
	alt = append(alt, stream[12:len(stream)-12]...)
	footer := append([]byte(nil), stream[len(stream)-12:]...)
	footer[8], footer[9] = flags[0], flags[1]
	copy(footer[0:4], crc32Bytes(footer[4:10]))
	alt = append(alt, footer...)
	got, rep, err := DecodeReport(alt, 1<<20)
	if err != nil || !bytes.Equal(got, fixture(t, "text.raw")) {
		t.Fatalf("reserved check: %v", err)
	}
	if rep.Unverified != 1 || rep.Check != "reserved-2" {
		t.Fatalf("report %+v", rep)
	}
}

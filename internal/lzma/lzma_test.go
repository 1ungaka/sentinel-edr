package lzma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures under testdata are synthetic: generated text, byte runs and
// seeded random bytes (NAME.raw), compressed by Python's lzma module (liblzma)
// into every container this package decodes. They were made with:
//
//	python3 - internal/lzma/testdata <<'EOF'
//	import lzma, os, random, subprocess, sys
//	out = sys.argv[1]
//	os.makedirs(out, exist_ok=True)
//	rng = random.Random(7)
//	words = ["lorem", "ipsum", "firmware", "volume", "section", "driver", "module", "range", "coder", "stream", "block", "index", "check", "dictionary", "literal", "match", "distance", "length"]
//	text = (" ".join(rng.choice(words) for _ in range(1800)) + "\n").encode()
//	runs = b"".join(bytes([i % 7]) * (50 + i * 3) for i in range(60)) + b"A" * 3000 + bytes(range(256)) * 10
//	mixed = rng.randbytes(6000) + text[:2000]
//	payloads = {"text": text, "runs": runs, "mixed": mixed, "short": b"x", "empty": b""}
//	def put(name, data):
//	    open(os.path.join(out, name), "wb").write(data)
//	for name, raw in payloads.items():
//	    put(name + ".raw", raw)
//	    # .lzma (LZMA1 alone container), four lc/lp/pb property sets
//	    for tag, f in {"default": {}, "lc0lp2pb0": dict(lc=0, lp=2, pb=0), "lc3lp1pb1": dict(lc=3, lp=1, pb=1), "lc4lp0pb4": dict(lc=4, lp=0, pb=4)}.items():
//	        put(f"{name}.{tag}.lzma", lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[dict(id=lzma.FILTER_LZMA1, preset=6, **f)]))
//	    # xz, one check type each
//	    for tag, chk in {"crc32": lzma.CHECK_CRC32, "crc64": lzma.CHECK_CRC64, "sha256": lzma.CHECK_SHA256, "none": lzma.CHECK_NONE}.items():
//	        put(f"{name}.{tag}.xz", lzma.compress(raw, format=lzma.FORMAT_XZ, check=chk))
//	    # raw LZMA2 under several dictionary sizes and property sets; the name carries the dictionary size
//	    for tag, f in {"d4k.lc3lp0pb2": dict(dict_size=4096, lc=3, lp=0, pb=2), "d64k.lc0lp4pb0": dict(dict_size=1 << 16, lc=0, lp=4, pb=0),
//	                   "d1m.lc1lp1pb4": dict(dict_size=1 << 20, lc=1, lp=1, pb=4), "d16m.lc4lp0pb0": dict(dict_size=1 << 24, lc=4, lp=0, pb=0)}.items():
//	        put(f"{name}.{tag}.lzma2", lzma.compress(raw, format=lzma.FORMAT_RAW, filters=[dict(id=lzma.FILTER_LZMA2, preset=6, **f)]))
//	# xz variants over text: non-default properties, a 64 MiB dictionary claim, a BCJ x86 chain (unsupported here), two streams
//	put("text.lc4.xz", lzma.compress(text, format=lzma.FORMAT_XZ, filters=[dict(id=lzma.FILTER_LZMA2, preset=6, lc=4, lp=0, pb=0)]))
//	put("text.d64m.xz", lzma.compress(text, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, filters=[dict(id=lzma.FILTER_LZMA2, preset=6, dict_size=1 << 26)]))
//	put("text.x86.xz", lzma.compress(text, format=lzma.FORMAT_XZ, filters=[dict(id=lzma.FILTER_X86), dict(id=lzma.FILTER_LZMA2, preset=6)]))
//	put("text.twostreams.xz", lzma.compress(text[:5000], format=lzma.FORMAT_XZ) + lzma.compress(text[5000:], format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64))
//	put("text.padded.xz", lzma.compress(text[:5000], format=lzma.FORMAT_XZ) + b"\0" * 8 + lzma.compress(text[5000:], format=lzma.FORMAT_XZ))
//	# a multi-block stream needs the xz CLI: python's encoder never splits blocks
//	put("text.multiblock.xz", subprocess.run(["xz", "--block-size=2048", "-c", "--check=sha256", "-"], input=text, capture_output=True, check=True).stdout)
//	EOF
//
// Each NAME.*.EXT decodes to NAME.raw.

// fixtures returns every testdata file with the extension, keyed by path.
func fixtures(t testing.TB, ext string, atLeast int) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*."+ext))
	if err != nil || len(paths) < atLeast {
		t.Fatalf("%s fixtures missing: %d found (%v)", ext, len(paths), err)
	}
	out := map[string][]byte{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = raw
	}
	return out
}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// want is the raw payload a fixture decodes to.
func want(t testing.TB, path string) []byte {
	t.Helper()
	name := strings.SplitN(filepath.Base(path), ".", 2)[0]
	return fixture(t, name+".raw")
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// ── .lzma ──────────────────────────────────────────────────────────────────

func TestAloneDecodesReferenceStreams(t *testing.T) {
	for path, stream := range fixtures(t, "lzma", 20) {
		w := want(t, path)
		got, err := DecodeAlone(stream, 1<<20)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, w) {
			t.Errorf("%s: decoded %d bytes, want %d; first difference at %d", path, len(got), len(w), firstDiff(got, w))
		}
	}
}

// The reference encoder writes an unknown size and an end marker. Firmware
// tools write the real size and no marker. Both must decode.
func TestAloneKnownSizeHeader(t *testing.T) {
	stream := fixture(t, "text.default.lzma")
	w := fixture(t, "text.raw")
	sized := append([]byte(nil), stream...)
	binary.LittleEndian.PutUint64(sized[5:], uint64(len(w)))
	got, err := DecodeAlone(sized, 1<<20)
	if err != nil || !bytes.Equal(got, w) {
		t.Fatalf("known-size header: %v (%d bytes)", err, len(got))
	}
	// A header that claims less than the stream holds never yields more than
	// the claim: either the exact prefix, or an error when a match straddles
	// the declared end (which the reference decoder also treats as corrupt).
	binary.LittleEndian.PutUint64(sized[5:], 100)
	got, err = DecodeAlone(sized, 1<<20)
	if err == nil && !bytes.Equal(got, w[:100]) {
		t.Errorf("short declared size: decoded %d bytes that are not the 100-byte prefix", len(got))
	}
	// A header that claims more than the stream holds is corrupt, not padded.
	binary.LittleEndian.PutUint64(sized[5:], uint64(len(w)+50))
	if _, err = DecodeAlone(sized, 1<<20); err == nil {
		t.Error("a declared size larger than the data must be an error")
	}
}

func TestAloneLimits(t *testing.T) {
	stream := fixture(t, "runs.default.lzma")
	w := fixture(t, "runs.raw")

	// Unknown size: the output limit is enforced while decoding.
	if _, err := DecodeAlone(stream, len(w)-1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("limit below the real size: %v", err)
	}
	if got, err := DecodeAlone(stream, len(w)+1); err != nil || len(got) != len(w) {
		t.Errorf("limit just above the real size: %v (%d bytes)", err, len(got))
	}
	// Known size: a declared size over the limit is refused before any work.
	big := append([]byte(nil), stream...)
	binary.LittleEndian.PutUint64(big[5:], 1<<40)
	if _, err := DecodeAlone(big, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Errorf("declared 1 TiB: %v", err)
	}
	if _, err := DecodeAlone(stream, 0); err == nil {
		t.Error("a zero limit must refuse")
	}
}

func TestAloneRejectsBadInput(t *testing.T) {
	stream := fixture(t, "mixed.default.lzma")
	cases := map[string][]byte{
		"empty":            nil,
		"header only":      stream[:13],
		"bad props":        append([]byte{225}, stream[1:]...),
		"lc+lp over 8":     append([]byte{8 + 9*4}, stream[1:]...), // lc=8, lp=4
		"nonzero lead":     append(append([]byte(nil), stream[:13]...), append([]byte{1}, stream[14:]...)...),
		"truncated body":   stream[:len(stream)/2],
		"truncated a byte": stream[:len(stream)-6],
	}
	for name, in := range cases {
		if out, err := DecodeAlone(in, 1<<20); err == nil {
			t.Errorf("%s: decoded %d bytes without error", name, len(out))
		}
	}
	// A match before the start of the output: the first packet of a fresh
	// stream cannot be a match, and one that says so must not read memory.
	evil := append(append([]byte(nil), stream[:13]...), 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	if _, err := DecodeAlone(evil, 1<<20); err == nil {
		t.Error("a stream opening with a match must be rejected")
	}
	// Every structural truncation point is an error, never partial output.
	for n := 0; n < len(stream); n += 37 {
		if out, err := DecodeAlone(stream[:n], 1<<16); err == nil || out != nil {
			t.Fatalf("truncated at %d: err=%v out=%d", n, err, len(out))
		}
	}
}

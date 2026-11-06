package uefi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures under testdata/lzma are synthetic: generated text, runs and
// seeded random bytes, compressed with a reference encoder under four
// property sets (lc/lp/pb) so every context-selection path is exercised.
// Each NAME.VARIANT.lzma decodes to NAME.raw.

func lzmaFixtures(t testing.TB) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "lzma", "*.lzma"))
	if err != nil || len(paths) < 20 {
		t.Fatalf("lzma fixtures missing: %d found (%v)", len(paths), err)
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

func lzmaWant(t testing.TB, fixture string) []byte {
	t.Helper()
	name := strings.SplitN(filepath.Base(fixture), ".", 2)[0]
	want, err := os.ReadFile(filepath.Join("testdata", "lzma", name+".raw"))
	if err != nil {
		t.Fatal(err)
	}
	return want
}

func TestLZMADecodesReferenceStreams(t *testing.T) {
	for path, stream := range lzmaFixtures(t) {
		want := lzmaWant(t, path)
		got, err := lzmaDecode(stream, 1<<20)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: decoded %d bytes, want %d; first difference at %d", path, len(got), len(want), firstDiff(got, want))
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// The reference encoder writes an unknown size and an end marker. Firmware
// tools write the real size and no marker. Both must decode.
func TestLZMAKnownSizeHeader(t *testing.T) {
	path := filepath.Join("testdata", "lzma", "text.default.lzma")
	stream, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := lzmaWant(t, path)
	sized := append([]byte(nil), stream...)
	binary.LittleEndian.PutUint64(sized[5:], uint64(len(want)))
	got, err := lzmaDecode(sized, 1<<20)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("known-size header: %v (%d bytes)", err, len(got))
	}
	// A header that claims less than the stream holds never yields more than
	// the claim: either the exact prefix, or an error when a match straddles
	// the declared end (which the reference decoder also treats as corrupt).
	binary.LittleEndian.PutUint64(sized[5:], 100)
	got, err = lzmaDecode(sized, 1<<20)
	if err == nil && !bytes.Equal(got, want[:100]) {
		t.Errorf("short declared size: decoded %d bytes that are not the 100-byte prefix", len(got))
	}
	// A header that claims more than the stream holds is corrupt, not padded.
	binary.LittleEndian.PutUint64(sized[5:], uint64(len(want)+50))
	if _, err = lzmaDecode(sized, 1<<20); err == nil {
		t.Error("a declared size larger than the data must be an error")
	}
}

func TestLZMALimits(t *testing.T) {
	path := filepath.Join("testdata", "lzma", "runs.default.lzma")
	stream, _ := os.ReadFile(path)
	want := lzmaWant(t, path)

	// Unknown size: the output limit is enforced while decoding.
	if _, err := lzmaDecode(stream, len(want)-1); !errors.Is(err, errLZMATooLarge) {
		t.Errorf("limit below the real size: %v", err)
	}
	if got, err := lzmaDecode(stream, len(want)+1); err != nil || len(got) != len(want) {
		t.Errorf("limit just above the real size: %v (%d bytes)", err, len(got))
	}
	// Known size: a declared size over the limit is refused before any work.
	big := append([]byte(nil), stream...)
	binary.LittleEndian.PutUint64(big[5:], 1<<40)
	if _, err := lzmaDecode(big, 1<<20); !errors.Is(err, errLZMATooLarge) {
		t.Errorf("declared 1 TiB: %v", err)
	}
	if _, err := lzmaDecode(stream, 0); err == nil {
		t.Error("a zero limit must refuse")
	}
}

func TestLZMARejectsBadInput(t *testing.T) {
	stream, _ := os.ReadFile(filepath.Join("testdata", "lzma", "mixed.default.lzma"))
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
		if out, err := lzmaDecode(in, 1<<20); err == nil {
			t.Errorf("%s: decoded %d bytes without error", name, len(out))
		}
	}
	// A match before the start of the output: the first packet of a fresh
	// stream cannot be a match, and one that says so must not read memory.
	evil := append(append([]byte(nil), stream[:13]...), 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
	if _, err := lzmaDecode(evil, 1<<20); err == nil {
		t.Error("a stream opening with a match must be rejected")
	}
}

func FuzzLZMADecode(f *testing.F) {
	for _, stream := range lzmaFixtures(f) {
		f.Add(stream)
	}
	f.Add([]byte{0x5d, 0, 0, 0x80, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		const limit = 1 << 16
		out, err := lzmaDecode(data, limit)
		if err == nil && len(out) > limit {
			t.Fatalf("decoded %d bytes past the %d-byte limit", len(out), limit)
		}
		if err != nil && out != nil {
			t.Fatalf("an error must not come with partial output")
		}
	})
}

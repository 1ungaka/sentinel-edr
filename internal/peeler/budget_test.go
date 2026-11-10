package peeler

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The budget has to be consulted before the decoder allocates. Two decoders can
// grow a body: base64 by three quarters, ASCII85 four times over (a 'z' run is
// one character that stands for four bytes). A body that expands past the wall
// must be refused without the buffer ever existing — otherwise the ceiling
// bounds what the peeler *keeps* and not what it *costs*.

func TestBase64RefusesADecodeTheBudgetCannotHold(t *testing.T) {
	body := []byte(strings.Repeat("QUJD", 1024)) // 4 KiB of base64: 3 KiB decoded
	layer := layerNamed(t, "base64")
	if _, err := layer.Unwrap(body, 16); !errors.Is(err, errBombCap) {
		t.Errorf("a 3 KiB decode under a 16-byte budget: want errBombCap, got %v", err)
	}
	// With room for it, the same body decodes.
	out, err := layer.Unwrap(body, 1<<20)
	if err != nil {
		t.Fatalf("base64 with room: %v", err)
	}
	if want := strings.Repeat("ABC", 1024); string(out) != want {
		t.Errorf("decoded %d bytes, want %d", len(out), len(want))
	}
}

func TestAscii85RefusesAnExpansionTheBudgetCannotHold(t *testing.T) {
	// A body of 'z' is the worst case for the decoder: each character stands
	// for four zero bytes, so the output is four times the input.
	body := bytes.Repeat([]byte("z"), 4096)
	layer := layerNamed(t, "ascii85")
	if _, err := layer.Unwrap(body, 1024); !errors.Is(err, errBombCap) {
		t.Errorf("a 16 KiB expansion under a 1 KiB budget: want errBombCap, got %v", err)
	}
	// With room for the expansion the budget is not what stops it: the decoded
	// body is all zeros, which is not plausible content, so it is refused as
	// "not this layer" instead.
	_, err := layer.Unwrap(body, 1<<20)
	if errors.Is(err, errBombCap) {
		t.Errorf("a 16 KiB expansion under a 1 MiB budget was refused by the budget: %v", err)
	}
}

func TestAscii85SizeMatchesWhatTheDecoderWrites(t *testing.T) {
	// The pre-check uses the size, so the size must be the size the decoder
	// actually needs: a bound that is short would refuse a body that fits.
	for _, body := range []string{
		"",
		"z",
		"zzz",
		"87cURD]j7BEbo80",
		strings.Repeat("z", 100) + "87cURD]j7BEbo80",
	} {
		src := []byte(body)
		want := ascii85Size(src)
		out, ok := ascii85Layer().decode(src)
		if !ok {
			continue
		}
		if len(out) > want {
			t.Errorf("ascii85Size(%d bytes) = %d, the decoder wrote %d", len(src), want, len(out))
		}
	}
}

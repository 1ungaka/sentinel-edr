package peeler

import (
	"bytes"
	"errors"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// referenceUnwrap is byteListLayer.UnwrapAll as it was written over strings.FieldsFunc:
// what the walked version has to go on returning.
func referenceUnwrap(b []byte, limit int64) ([]Decoded, error) {
	tokens := strings.FieldsFunc(string(b), listSeparator)
	if len(tokens) < minListTokens {
		return nil, ErrNotThisLayer
	}
	if int64(len(tokens)) > limit {
		return nil, errBombCap
	}
	readings := []struct {
		name  string
		parse func(string) (byte, bool)
	}{
		{"base2", radixToken(2, 8, 8, "")},
		{"base16", prefixedHexToken},
		{"base10", radixToken(10, 1, 3, "")},
		{"base8", radixToken(8, 3, 3, "")},
		{"base16", radixToken(16, 2, 2, "")},
	}
	var text *Decoded
	for _, r := range readings {
		out := make([]byte, len(tokens))
		ok := true
		for i, t := range tokens {
			v, good := r.parse(t)
			if !good {
				ok = false
				break
			}
			out[i] = v
		}
		if !ok {
			continue
		}
		if reveals(out) {
			return []Decoded{{Data: out, Label: r.name}}, nil
		}
		if text == nil && printableFraction(window(out)) >= minPlainFraction {
			text = &Decoded{Data: out, Label: r.name}
		}
	}
	if text == nil {
		return nil, ErrNotThisLayer
	}
	return []Decoded{*text}, nil
}

func sameUnwrap(t *testing.T, in []byte, limit int64) {
	t.Helper()
	got, gotErr := byteListLayer{}.UnwrapAll(in, limit)
	want, wantErr := referenceUnwrap(in, limit)
	if !errors.Is(gotErr, wantErr) && gotErr != wantErr {
		t.Fatalf("%q: error %v, want %v", in, gotErr, wantErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q: got %+v, want %+v", in, got, want)
	}
}

func TestByteListMatchesTheFieldsFuncVersion(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	seps := []string{" ", ",", ", ", ";", ":", "\t", "\r\n", "\\", "%", "  ", "\xc2\xa0", "\xe2\x80\x83", "\xff", "\xc5"}
	gens := []func() string{
		func() string {
			return "0x" + string("0123456789abcdef"[r.Intn(16)]) + string("0123456789abcdef"[r.Intn(16)])
		},
		func() string { return string(rune('0' + r.Intn(10))) },
		func() string { return []string{"65", "104", "255", "256", "300", "7"}[r.Intn(6)] },
		func() string { return []string{"01000001", "01101000", "101", "2"}[r.Intn(4)] },
		func() string { return []string{"141", "150", "777", "400", "008"}[r.Intn(5)] },
		func() string { return []string{"41", "ff", "zz", "4", "411"}[r.Intn(5)] },
		func() string { return []string{"é", "\xff", "x", ""}[r.Intn(4)] },
	}
	for range 20000 {
		gen := gens[r.Intn(len(gens))]
		var b strings.Builder
		for range r.Intn(40) {
			if r.Intn(30) == 0 {
				b.WriteString(gens[r.Intn(len(gens))]())
			} else {
				b.WriteString(gen())
			}
			b.WriteString(seps[r.Intn(len(seps))])
		}
		sameUnwrap(t, []byte(b.String()), int64(4+r.Intn(60)))
	}
}

func TestByteListEdges(t *testing.T) {
	for _, in := range []string{"", " ", ",,,,", "0x41", strings.Repeat("0x41 ", 7), strings.Repeat("0x41 ", 8), strings.Repeat("0x41", 8), strings.Repeat(" 65 ", 9) + "\xff"} {
		sameUnwrap(t, []byte(in), 1000)
	}
	sameUnwrap(t, []byte(strings.Repeat("0x41 ", 20)), 10) // past the bomb cap
}

// The shape that cost more than a gigabyte for a 60 MiB file. An attacker chooses it,
// so what it allocates has to stay in proportion to what it decodes to.
func TestByteListAllocationStaysBounded(t *testing.T) {
	in := bytes.Repeat([]byte("0x41, "), 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := byteListLayer{}.UnwrapAll(in, int64(len(in)))
	runtime.ReadMemStats(&after)
	if err != nil || len(got) != 1 || len(got[0].Data) != 1<<20 {
		t.Fatalf("got %d results, %v", len(got), err)
	}
	if used := after.TotalAlloc - before.TotalAlloc; used > 3<<20 {
		t.Fatalf("decoding %d bytes allocated %d", 1<<20, used)
	}
}

// A reading that fails on its first token must cost nothing, or five of them cost
// five output buffers on every list.
func TestFailedReadingAllocatesNothing(t *testing.T) {
	list := strings.Repeat("zz ", 1000)
	allocs := testing.AllocsPerRun(50, func() {
		if out, ok := parseTokens(list, 1000, radixToken(10, 1, 3, "")); ok || out != nil {
			t.Fatal("zz is not a number")
		}
	})
	if allocs > 2 {
		t.Fatalf("%.0f allocations", allocs)
	}
}

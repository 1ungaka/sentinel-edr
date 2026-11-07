package peeler

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// FuzzPeel drives the whole tree walk with arbitrary bytes. The invariant,
// shared with every other parser in the engine, is "never panic on hostile
// input" — and, because the peeler is a budgeted pipeline, "always terminate
// within the budget". The seeds are real chain shapes so the corpus doubles as
// a fast regression suite under `go test`.
func FuzzPeel(f *testing.F) {
	f.Add(compose(fakeELF, "base64"))
	f.Add(compose(fakeELF, "base64", "gzip", "hex"))
	f.Add(compose([]byte("#!/bin/sh\necho hi; echo hi; echo hi;"), "base64", "zlib"))
	f.Add(encodeLayer("gzip", make([]byte, 1<<20))) // a small bomb seed
	f.Add([]byte("plain text, not a chain at all"))
	f.Add([]byte{})
	f.Add([]byte("QUJD")) // "ABC" in base64, too short to be a layer
	f.Add(composeAny(fakeELF, "base85", "rot47", "base64", "gzip"))
	f.Add(composeAny(fakeELF, "reverse", "base58", "caesar-7", "base91", "gzip"))
	f.Add(composeAny(fakeELF, "base92", "base45", "atbash", "hex", "zlib"))
	f.Add([]byte("72 101 108 108 111 32 119 111 114 108 100 33"))
	f.Add([]byte(`\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03`))
	f.Add([]byte("<~,9\\^LBl5SFBF86lEblk3FEDI_0/#(71G1@60ekI:3A5V\"Hm!KD$3~>"))
	f.Add(append([]byte{0xff, 0xfe}, bytes.Repeat([]byte{'a', 0}, 32)...))
	f.Add([]byte("A=\"" + string(encodeLayer("base64", largeELF())) + "\"\nB=\"" + string(encodeLayer("hex", largeELF())) + "\"\n"))
	f.Add(zipOf(zipEntry{name: "a", body: compose(fakeELF, "base64", "gzip")}, zipEntry{name: "b", body: prose, stored: true}))
	f.Add(compose(zipOf(zipEntry{name: "a", body: harmlessScript}), "base64"))

	// Tight limits keep each fuzz iteration fast while still exercising every
	// wall (nodes, output, depth, wall-clock).
	p := New(WithLimits(BudgetLimits{
		MaxNodes:       128,
		MaxOutputBytes: 1 << 20,
		MaxDepth:       8,
		MaxChildren:    4,
		MaxWallClock:   2 * time.Second,
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		type verdict struct {
			r  Result
			st *peel
		}
		done := make(chan verdict, 1)
		go func() {
			r, st := p.inspect(context.Background(), data, nil)
			done <- verdict{r, st}
		}()
		select {
		case v := <-done:
			// Neither wall may be passed, and the task graph must have stayed
			// inside its bounds: workers, branches per node, bytes held.
			if v.r.OutputBytes > 1<<20 || v.r.NodesVisited > 128 {
				t.Fatalf("%d bytes, %d nodes: over the budget", v.r.OutputBytes, v.r.NodesVisited)
			}
			if broken := v.st.gauges.violation.Load(); broken != nil {
				t.Fatal(*broken)
			}
			if v.r.Exhausted && v.r.Outcome == OutcomeClean {
				t.Fatalf("exhausted (%s) and reported clean", v.r.ExhaustReason)
			}
		case <-time.After(10 * time.Second):
			// A peel that outlives its 2s wall clock by this margin is a
			// termination bug, not slowness.
			t.Fatal("Peel did not terminate within its budget")
		}
	})
}

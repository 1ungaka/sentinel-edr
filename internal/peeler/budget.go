package peeler

import (
	"sync/atomic"
	"time"
)

// Budget is the global, per-sample spend wall. Every branch of the peel tree
// shares one Budget, so an attacker who adds depth adds work against the same
// ceiling rather than multiplying it: depth costs latency, never more total
// spend. Where the budget is spent is the engine's choice (the estimator ranks
// the frontier), never dictated by the sample's shape.
//
// All accounting is atomic because the tree is walked by a bounded worker pool.
// The checks are cooperative: a worker charges before it decodes and asks
// Exhausted at each node, so cancellation is prompt without being preemptive.
type Budget struct {
	// Limits. Zero means "unset" and is treated as the default by DefaultBudget;
	// a caller that builds a Budget directly should set them all.
	maxNodes       int64
	maxOutputBytes int64
	maxDepth       int
	maxChildren    int
	deadline       time.Time

	// Live counters.
	nodes       atomic.Int64
	outputBytes atomic.Int64

	// exhausted latches the first reason the budget was hit so the result can
	// render an honest "peel-exhausted (reason)" instead of a silent clean.
	exhausted atomic.Pointer[string]
}

// BudgetLimits are the knobs DefaultBudget and NewBudget expose.
type BudgetLimits struct {
	MaxNodes       int64         // total nodes the whole tree may visit
	MaxOutputBytes int64         // total decoded bytes across every branch
	MaxDepth       int           // deepest any single path may go
	MaxChildren    int           // transforms attempted per node (frontier width)
	MaxWallClock   time.Duration // time-to-verdict ceiling for the whole peel
}

// DefaultLimits are tuned so a benign sample finishes in well under the wall
// clock while a bomb or a stall-shaped chain hits a wall quickly. They are
// deliberately modest: the peeler is a pre-pass, not a sandbox.
func DefaultLimits() BudgetLimits {
	return BudgetLimits{
		MaxNodes:       512,
		MaxOutputBytes: 64 << 20, // 64 MiB of decoded output, total
		MaxDepth:       32,
		MaxChildren:    6,
		MaxWallClock:   5 * time.Second,
	}
}

// NewBudget builds a Budget from limits, filling any zero field from
// DefaultLimits so a partially-specified limit set is still safe.
func NewBudget(l BudgetLimits) *Budget {
	d := DefaultLimits()
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxOutputBytes <= 0 {
		l.MaxOutputBytes = d.MaxOutputBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxChildren <= 0 {
		l.MaxChildren = d.MaxChildren
	}
	if l.MaxWallClock <= 0 {
		l.MaxWallClock = d.MaxWallClock
	}
	return &Budget{
		maxNodes:       l.MaxNodes,
		maxOutputBytes: l.MaxOutputBytes,
		maxDepth:       l.MaxDepth,
		maxChildren:    l.MaxChildren,
		deadline:       time.Now().Add(l.MaxWallClock),
	}
}

// chargeNode accounts one node visit and returns false if that pushes the tree
// over the node ceiling (the node is then not explored).
func (b *Budget) chargeNode() bool {
	if b.nodes.Add(1) > b.maxNodes {
		b.trip("node ceiling")
		return false
	}
	return true
}

// chargeOutput accounts n decoded bytes and returns false if the total output
// budget is exceeded. A transform whose output would break the wall is
// discarded rather than kept, so the bomb never lands in memory past the cap.
func (b *Budget) chargeOutput(n int) bool {
	if b.outputBytes.Add(int64(n)) > b.maxOutputBytes {
		b.trip("output ceiling (decompression-bomb cap)")
		return false
	}
	return true
}

// remainingOutput is how many decoded bytes may still be produced; used as the
// per-decode LimitReader bound so a single stream cannot overrun the wall.
func (b *Budget) remainingOutput() int64 {
	r := b.maxOutputBytes - b.outputBytes.Load()
	if r < 0 {
		return 0
	}
	return r
}

// timedOut reports whether the wall clock has passed; it also latches the
// reason so the outcome can name it.
func (b *Budget) timedOut() bool {
	if time.Now().After(b.deadline) {
		b.trip("wall-clock deadline")
		return true
	}
	return false
}

// depthExceeded reports whether depth is past the per-path cap.
func (b *Budget) depthExceeded(depth int) bool {
	if depth > b.maxDepth {
		b.trip("depth ceiling")
		return true
	}
	return false
}

// Exhausted reports whether any wall was hit, and the first reason if so.
func (b *Budget) Exhausted() (bool, string) {
	if p := b.exhausted.Load(); p != nil {
		return true, *p
	}
	return false, ""
}

// trip latches the first exhaustion reason. Later reasons do not overwrite it:
// the first wall a sample hit is the honest story.
func (b *Budget) trip(reason string) {
	b.exhausted.CompareAndSwap(nil, &reason)
}

// Nodes returns the number of nodes visited so far (for reporting and tests).
func (b *Budget) Nodes() int64 { return b.nodes.Load() }

// OutputBytes returns the decoded-byte total so far.
func (b *Budget) OutputBytes() int64 { return b.outputBytes.Load() }

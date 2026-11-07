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
	start          time.Time
	deadline       time.Time
	// now is the clock. Tests inject one so a wall-clock outcome is produced
	// by construction instead of by racing a timer.
	now func() time.Time

	// maxHeld bounds the decoded bytes the walk holds at one moment: what it has
	// kept (never more than maxOutputBytes) plus the candidates still waiting for
	// the rank-order rejoin.
	maxHeld int64

	// Live counters.
	nodes       atomic.Int64
	outputBytes atomic.Int64
	held        atomic.Int64
	peakHeld    atomic.Int64

	// exhausted latches the first reason the budget was hit so the result can
	// render an honest "peel-exhausted (reason)" instead of a silent clean.
	exhausted atomic.Pointer[string]
	// hard counts walls a chain ran into; soft counts walls hit reading the
	// members of a plain archive, where nothing obfuscated was being followed.
	// The deadline is counted with whichever came first.
	hard, soft atomic.Int64
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
func NewBudget(l BudgetLimits) *Budget { return newBudget(l, time.Now) }

func newBudget(l BudgetLimits, now func() time.Time) *Budget {
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
		maxHeld:        heldFactor * l.MaxOutputBytes,
		start:          now(),
		deadline:       now().Add(l.MaxWallClock),
		now:            now,
	}
}

// heldFactor sets the held-bytes ceiling as a multiple of the output wall: once
// for what the tree keeps, once for candidates a node is still choosing between.
const heldFactor = 2

// chargeNode accounts one node visit and returns false if that pushes the tree
// over the node ceiling (the node is then not explored).
func (b *Budget) chargeNode() bool {
	for {
		n := b.nodes.Load()
		if n >= b.maxNodes {
			b.trip("node ceiling")
			return false
		}
		if b.nodes.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// hold reserves n decoded bytes against the held-bytes ceiling and reports
// whether they fit. The count can never pass the ceiling: a decode that would
// take it over is refused, and its output is dropped by the caller.
func (b *Budget) hold(n int64) bool {
	for {
		h := b.held.Load()
		if h+n > b.maxHeld {
			b.trip("held-bytes ceiling")
			return false
		}
		if b.held.CompareAndSwap(h, h+n) {
			for {
				p := b.peakHeld.Load()
				if h+n <= p || b.peakHeld.CompareAndSwap(p, h+n) {
					return true
				}
			}
		}
	}
}

// release returns bytes taken with hold, once nothing in the walk refers to them.
func (b *Budget) release(n int64) { b.held.Add(-n) }

// heldRoom is how many more decoded bytes may be held right now.
func (b *Budget) heldRoom() int64 { return max(b.maxHeld-b.held.Load(), 0) }

// floorFraction is the share of each wall kept back for the branches the
// estimator ranks as likely. Once any wall is this close, a speculative branch is
// cancelled instead of opened.
const floorFraction = 8

// belowFloor reports that less than 1/floorFraction of the node, output or time
// budget is left.
func (b *Budget) belowFloor() bool {
	if b.maxNodes-b.nodes.Load() < b.maxNodes/floorFraction {
		return true
	}
	if b.maxOutputBytes-b.outputBytes.Load() < b.maxOutputBytes/floorFraction {
		return true
	}
	return b.deadline.Sub(b.now()) < b.deadline.Sub(b.start)/floorFraction
}

// chargeOutput accounts n decoded bytes and returns false if the total output
// budget is exceeded. A transform whose output would break the wall is
// discarded rather than kept, so the bomb never lands in memory past the cap.
func (b *Budget) chargeOutput(n int) bool {
	for {
		have := b.outputBytes.Load()
		if have+int64(n) > b.maxOutputBytes {
			b.trip("output ceiling (decompression-bomb cap)")
			return false
		}
		if b.outputBytes.CompareAndSwap(have, have+int64(n)) {
			return true
		}
	}
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
	if b.pastDeadline() {
		// The deadline is a consequence of whatever was being done when it
		// struck: it hardens the verdict only if it is the first wall.
		b.exhausted.CompareAndSwap(nil, &deadlineReason)
		return true
	}
	return false
}

var deadlineReason = "wall-clock deadline"

// pastDeadline is timedOut without the latch, for the checks inside a long
// decode.
func (b *Budget) pastDeadline() bool { return b.now().After(b.deadline) }

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
	b.hard.Add(1)
	b.exhausted.CompareAndSwap(nil, &reason)
}

// tripSoft is trip for a wall hit while reading the members of a plain
// archive. The peel is just as incomplete, and says so, but a documentation
// archive that is too big to read through is not evidence of obfuscation.
func (b *Budget) tripSoft(reason string) {
	b.soft.Add(1)
	if !b.exhausted.CompareAndSwap(nil, &reason) {
		// A deadline that struck while the archive was being read is this
		// wall, seen from the decoders beside it.
		b.exhausted.CompareAndSwap(&deadlineReason, &reason)
	}
}

// softOnly reports that every wall hit was a soft one: nothing a chain was
// following was cut short. A deadline that struck first counts as hard.
func (b *Budget) softOnly() bool {
	if b.hard.Load() > 0 || b.soft.Load() == 0 {
		return false
	}
	p := b.exhausted.Load()
	return p != nil && p != &deadlineReason
}

// Nodes returns the number of nodes visited so far (for reporting and tests).
func (b *Budget) Nodes() int64 { return b.nodes.Load() }

// OutputBytes returns the decoded-byte total so far.
func (b *Budget) OutputBytes() int64 { return b.outputBytes.Load() }

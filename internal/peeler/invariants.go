package peeler

import (
	"fmt"
	"sync/atomic"
)

// The task graph is bounded in four ways, and each is counted while the walk
// runs and checked when it ends, so a change that breaks one fails loudly
// instead of quietly costing memory:
//
//   - workers: goroutines running for one peel never exceed its parallelism.
//     There is no queue behind them. A child that finds no free slot runs on the
//     goroutine that found it, so pending work is held on stacks whose depth the
//     depth wall bounds.
//   - children: a node opens at most MaxChildren readings of its blob. The
//     members of an archive share one of those places and are bounded by
//     maxZipMembers and by the node wall.
//   - nodes: no more than MaxNodes are ever explored.
//   - bytes: the decoded bytes the walk holds never exceed heldFactor times the
//     output wall, and all of them are let go by the time it returns.
//
// A broken invariant is a bug in this package, not something a sample did. It is
// still reported through the budget, as peel-exhausted, because a walk that broke
// its own bounds has not earned a clean verdict.
type gauges struct {
	workers      atomic.Int64
	peakWorkers  atomic.Int64
	peakChildren atomic.Int64
	peakMembers  atomic.Int64
	// decodes counts layer decodes started, for the tests that show none starts
	// once the peel is over.
	decodes   atomic.Int64
	violation atomic.Pointer[string]
}

func raise(peak *atomic.Int64, v int64) {
	for {
		p := peak.Load()
		if v <= p || peak.CompareAndSwap(p, v) {
			return
		}
	}
}

func (g *gauges) enter(n int)        { raise(&g.peakWorkers, g.workers.Add(int64(n))) }
func (g *gauges) leave(n int)        { g.workers.Add(-int64(n)) }
func (g *gauges) noteChildren(n int) { raise(&g.peakChildren, int64(n)) }
func (g *gauges) noteMembers(n int)  { raise(&g.peakMembers, int64(n)) }

// checkInvariants runs once the walk has returned. The first breach is kept for
// the tests and latched as the reason the peel is incomplete.
func (st *peel) checkInvariants() {
	g, b := &st.gauges, st.budget
	fail := func(format string, args ...any) {
		reason := "invariant violated: " + fmt.Sprintf(format, args...)
		if g.violation.CompareAndSwap(nil, &reason) {
			b.trip(reason)
		}
	}
	if n := g.peakWorkers.Load(); n > int64(st.p.parallelism) {
		fail("%d workers ran at once under a parallelism of %d", n, st.p.parallelism)
	}
	if n := g.workers.Load(); n != 0 {
		fail("%d workers still running after the walk returned", n)
	}
	if n := len(st.sem); n != 1 {
		fail("%d worker slots held after the walk returned, want the caller's one", n)
	}
	if n := g.peakChildren.Load(); n > int64(b.maxChildren) {
		fail("a node opened %d branches under a frontier width of %d", n, b.maxChildren)
	}
	if n := g.peakMembers.Load(); n > maxZipMembers {
		fail("an archive yielded %d members over a cap of %d", n, maxZipMembers)
	}
	if n := b.nodes.Load(); n > b.maxNodes {
		fail("%d nodes explored over a wall of %d", n, b.maxNodes)
	}
	if n := b.outputBytes.Load(); n > b.maxOutputBytes {
		fail("%d decoded bytes kept over a wall of %d", n, b.maxOutputBytes)
	}
	if n := b.peakHeld.Load(); n > b.maxHeld {
		fail("%d decoded bytes held at once over a ceiling of %d", n, b.maxHeld)
	}
	if n := b.held.Load(); n != 0 {
		fail("%d decoded bytes still held after the walk returned", n)
	}
}

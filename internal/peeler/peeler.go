// Package peeler is the engine-side, bounded unpeeling pre-pass for
// multi-method obfuscation chains (NOVEL-012): encoding → packing → encryption
// stacks where the *depth* of the chain is itself a signal, not just the
// payload at the bottom.
//
// It walks the candidate tree — at each node every applicable layer decoder
// spawns a child — under a single global per-sample budget wall (see Budget),
// so an attacker who adds layers adds latency, never total spend. The decoders at
// a node run together, branches run together, and results rejoin in rank order,
// so a report does not depend on which goroutine finished first. A branch that
// hits the wall yields a first-class `peel-exhausted` outcome, rendered and
// scored, never silently reported clean: an over-budget sample is a finding
// about the budget, not a clean bill of health.
//
// Scope discipline: the peeler only *decodes* reversible layers (the base
// encodings, rot and Caesar substitutions, gzip/zlib/flate/bzip2, the members
// of a zip). It never executes or emulates sample content;
// the emulation-sidecar fallback named in the plan is a separate, later,
// isolated component. What ships here is "what to catch and how to catch it".
//
// This is the first increment: the bounded tree walk, the budget wall, CAS
// dedupe, depth-as-signal scoring, and chain signatures. Scan-path wiring
// (a ScanResult facet + fusion), the entropy/structural estimator that ranks
// the frontier, and the emulation fallback are follow-ons tracked in PLAN.md.
package peeler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/parallel"
)

func itoa(n int) string { return strconv.Itoa(n) }

// Outcome is the terminal classification of a peel. Precedence when several
// occur across branches: RevealedExecutable > RevealedScript > PeelExhausted >
// DeepChain > Clean. "Clean" means the tree was fully explored within budget and
// nothing interesting surfaced — it is only trustworthy *because* the budget was
// not hit, which is why PeelExhausted outranks it. DeepChain is depth with no
// payload identified under it: the wrapper is the observation.
type Outcome string

const (
	OutcomeClean              Outcome = "clean"
	OutcomeRevealedExecutable Outcome = "revealed-executable"
	OutcomeRevealedScript     Outcome = "revealed-script"
	OutcomePeelExhausted      Outcome = "peel-exhausted"
	OutcomeDeepChain          Outcome = "deep-chain"
)

// Chain is one ordered transform path from the input to an interesting
// terminal: the multi-layer equivalent of a hash. Transforms is the ordered
// list of layer names removed (outermost first).
type Chain struct {
	Transforms []string `json:"transforms"`
	// Terminal is what the bottom of this chain was (executable or script).
	Terminal Outcome `json:"terminal"`
	// Depth is the number of layers peeled to reach it. A carve is in Transforms
	// but not in Depth: see layerCount.
	Depth int `json:"depth"`
}

// qualifies reports whether a reveal counts as obfuscation rather than packaging.
// One layer of compression or base64 is normal software, so a chain needs depth,
// but no packager writes a substitution: one of those is deliberate on its own.
func (c Chain) qualifies() bool {
	return c.Depth >= minChainDepth || c.hasCipher()
}

func (c Chain) hasCipher() bool {
	for _, step := range c.Transforms {
		if isCipher(step) {
			return true
		}
	}
	return false
}

// Signature renders the chain as a stable string, e.g. "base64>gzip>base64".
// Ordered chain patterns become family signatures in the detection-content
// lifecycle.
func (c Chain) Signature() string { return strings.Join(c.Transforms, ">") }

// Finding is one peel signal, in the shape the engine's fusion lattice and the
// reporters consume from every detector (Class / Detail / Technique / Novel /
// Score). The peeler emits one per qualifying chain, plus one when the peel was
// exhausted.
type Finding struct {
	// Class is a stable id ("peel.revealed-executable", "peel.exhausted", ...).
	Class string `json:"class"`
	Score int    `json:"score"`
	// Technique and Novel carry the ATT&CK and plan ids for coverage.
	Technique string `json:"technique,omitempty"`
	Novel     string `json:"novel,omitempty"`
	// Detail is human-readable (the chain signature, or the exhaustion reason).
	Detail string `json:"detail"`
}

// Result is the peel verdict for one sample. The first block is the standalone
// `cau peel` view; the second block is the detector contract the engine uses.
type Result struct {
	Outcome Outcome `json:"outcome"`
	// Score is bounded [0,100]. Depth raises it regardless of the payload
	// verdict (a deep chain that outlives the budget still flags); a revealed
	// executable or script adds a payload bonus.
	Score int `json:"score"`
	// MaxDepth is the deepest layer count reached on any branch.
	MaxDepth int `json:"max_depth"`
	// Chains are the ordered transform paths to each interesting terminal,
	// deepest first. Empty when nothing interesting was revealed.
	Chains []Chain `json:"chains,omitempty"`
	// PrimarySignature is the signature of the first (deepest) interesting
	// chain, or "" when there is none.
	PrimarySignature string `json:"primary_signature,omitempty"`
	// Exhausted and ExhaustReason record whether a budget wall was hit and why.
	Exhausted     bool   `json:"exhausted"`
	ExhaustReason string `json:"exhaust_reason,omitempty"`
	// ExhaustSoft reports that the only wall hit was reading the members of a
	// plain archive: the peel is incomplete, and nothing it was following
	// through a chain was cut short. Such a result carries no score floor.
	ExhaustSoft bool `json:"exhaust_soft,omitempty"`
	// NodesVisited and OutputBytes report the spend, for operators and tests.
	NodesVisited int64 `json:"nodes_visited"`
	OutputBytes  int64 `json:"output_bytes"`
	// RootEntropy is the Shannon entropy (bits/byte) of the input, from the
	// estimator pre-pass. High entropy on a blob that does not peel points at a
	// terminal packed/encrypted layer.
	RootEntropy float64 `json:"root_entropy,omitempty"`
	// DeepestSignature is the path to the deepest node, set once MaxDepth reaches
	// deepChainDepth, whether or not anything was identified at the bottom of it.
	DeepestSignature string `json:"deepest_signature,omitempty"`
	// Archive says what the zip layer did: members read, walked, screened out,
	// and the ones it could not read (encrypted, or a method it does not decode).
	Archive *ArchiveStats `json:"archive,omitempty"`
	// Opaque lists the paths that ended in a layer this package recognises and
	// cannot decode (xz). What is under one was not looked at.
	Opaque []string `json:"opaque,omitempty"`
	// Leaves are the decoded blobs at the bottom of the tree, for a caller that
	// rescans them. Empty unless the Peeler was built WithLeaves.
	Leaves []Leaf `json:"-"`

	// ── detector contract (set by the engine; empty for standalone peels) ──
	FilePath  string    `json:"file_path,omitempty"`
	Size      int       `json:"size,omitempty"`
	Threshold int       `json:"threshold,omitempty"`
	Skipped   string    `json:"skipped,omitempty"`
	Findings  []Finding `json:"findings,omitempty"`
}

// Technique is the ATT&CK id this detector is evidence for (partial): the
// T1027 obfuscation family. Depth and chain patterns are the evidence. Novel is
// the plan's detection-first id for chain depth as a signal.
const (
	Technique = "T1027"
	Novel     = "NOVEL-012"
)

// DefaultThreshold is the score at or above which the peeler independently
// reports SUSPICIOUS. A depth-2 revealed chain scores 60 and crosses it; a
// peel-exhausted-only result scores 30 and corroborates through fusion without
// flagging on its own, matching the measured 0-FP envelope.
const DefaultThreshold = 50

// Threshold is the score used when a caller passes none. A variable so a
// deployment can retune without a recompile, like the other detectors.
var Threshold = DefaultThreshold

// EffectiveThreshold returns the threshold applied to this result.
func (r *Result) EffectiveThreshold() int {
	if r == nil || r.Threshold <= 0 {
		return Threshold
	}
	return r.Threshold
}

// Detected reports whether the peeler independently crossed its threshold.
func (r *Result) Detected() bool {
	return r != nil && r.Skipped == "" && r.Score >= r.EffectiveThreshold()
}

// depthScoreThreshold is the layer count above which depth alone is treated as
// suspicious. One encode of a legitimate blob (a single base64 of an asset) is
// ordinary; stacks are not.
const depthScoreThreshold = 2

// deepChainDepth is the layer count at which depth is reported as a finding of
// its own, whatever is at the bottom. Measured first, as the plan requires: of
// 131,253 benign files (/usr/share/doc, /usr/share/man, /usr/lib/python3*,
// /usr/bin, /etc) 106,656 peel to depth 0, 24,557 to depth 1, 40 to depth 2 and
// none deeper, so 4 leaves a whole layer of margin above everything observed.
const deepChainDepth = 4

// maxOpaque bounds the opaque paths a result lists.
const maxOpaque = 16

// minChainDepth is the shortest chain that counts as an obfuscation *chain*
// (NOVEL-012 is about stacks, not single layers). A single ordinary layer —
// a `.gz` of a binary, one base64 of a payload — is normal software packaging
// and is the existing single-layer encoded-executable detector's job
// (`scanner/encchain`), measured at 0.024% FP as single reveals here. The
// peeler only raises a revealed-payload *finding* for depth >= minChainDepth,
// so the two detectors divide the work without double-counting benign
// compression. Shallower reveals are still recorded in Chains for transparency.
const minChainDepth = 2

// Peeler walks obfuscation chains under a budget. Construct it with New; it is
// safe to reuse across samples (each Peel builds its own budget and state).
type Peeler struct {
	unwrappers []Unwrapper
	limits     BudgetLimits
	// parallelism bounds in-flight unwrap goroutines across the whole tree.
	parallelism int
	// leafBytes is the total size of the decoded leaves a result carries.
	leafBytes int
	// clock is what the budget reads the time from; tests replace it.
	clock func() time.Time
}

// Option configures a Peeler.
type Option func(*Peeler)

// WithLimits sets the budget limits (zero fields fall back to DefaultLimits).
func WithLimits(l BudgetLimits) Option { return func(p *Peeler) { p.limits = l } }

// WithUnwrappers replaces the layer-decoder registry.
func WithUnwrappers(u []Unwrapper) Option { return func(p *Peeler) { p.unwrappers = u } }

// WithParallelism sets the max in-flight goroutines across the whole tree, decoders
// and branches alike (default: one per CPU, up to 8). Values below 1 are treated
// as 1 (serial).
func WithParallelism(n int) Option { return func(p *Peeler) { p.parallelism = n } }

// WithLeaves makes each result carry its decoded leaves, up to maxBytes in all,
// so a caller can run its own indicators over what the chain was hiding. Off by
// default: it costs a copy of every leaf kept.
func WithLeaves(maxBytes int) Option { return func(p *Peeler) { p.leafBytes = maxBytes } }

// withClock replaces the budget's clock. It is for the tests, which use it to
// make a deadline strike at a chosen point of the walk.
func withClock(now func() time.Time) Option { return func(p *Peeler) { p.clock = now } }

// New builds a Peeler with the default unwrappers and limits.
func New(opts ...Option) *Peeler {
	p := &Peeler{
		unwrappers:  DefaultUnwrappers(),
		limits:      DefaultLimits(),
		parallelism: min(runtime.GOMAXPROCS(0), maxDefaultParallelism),
		clock:       time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	if p.parallelism < 1 {
		p.parallelism = 1
	}
	return p
}

// maxDefaultParallelism caps the default. A scan already runs one peel per worker,
// so this multiplies, and most nodes have only a few decoders to run.
const maxDefaultParallelism = 8

// peel is the mutable per-sample state shared across the walk.
type peel struct {
	p      *Peeler
	ctx    context.Context
	budget *Budget
	emit   func(Event) // nil unless the peel is being watched

	// sem bounds in-flight goroutines across the tree. A slot that cannot be
	// acquired without blocking means the work runs on the current goroutine —
	// the standard deadlock-free pattern for bounded parallel recursion.
	sem chan struct{}

	mu          sync.Mutex
	seen        map[[32]byte]struct{} // CAS: a blob hash peeled once is never re-peeled
	chains      []Chain
	maxDepth    int
	deepest     string // signature of the deepest path, from deepChainDepth on
	rootEntropy float64
	archive     ArchiveStats
	opaque      []string
	leaves      []leafRef

	gauges gauges
}

func (st *peel) recordRootEntropy(e float64) {
	st.mu.Lock()
	st.rootEntropy = e
	st.mu.Unlock()
}

// Peel walks the obfuscation tree rooted at data and returns the verdict.
// It always terminates within the budget and never executes sample content.
func (p *Peeler) Peel(ctx context.Context, data []byte) Result {
	return p.run(ctx, data, nil)
}

func (p *Peeler) run(ctx context.Context, data []byte, emit func(Event)) Result {
	r, _ := p.inspect(ctx, data, emit)
	return r
}

// inspect is run, with the walk's state handed back for the tests that check
// what it counted.
func (p *Peeler) inspect(ctx context.Context, data []byte, emit func(Event)) (Result, *peel) {
	if ctx == nil {
		ctx = context.Background()
	}
	st := &peel{
		p:      p,
		ctx:    ctx,
		budget: newBudget(p.limits, p.clock),
		emit:   emit,
		sem:    make(chan struct{}, p.parallelism),
		seen:   make(map[[32]byte]struct{}),
	}
	st.sem <- struct{}{} // this goroutine is the first of the N
	st.gauges.enter(1)
	st.guardedWalk(data, nil, 0)
	st.gauges.leave(1)
	st.checkInvariants()

	exhausted, reason := st.budget.Exhausted()
	return st.finish(exhausted, reason), st
}

// guardedWalk is walk with a panic barrier. ScanFile's recover covers only its
// own goroutine, so a decoder panic on one spawned here would end the process
// and every other file's result with it. A contained panic leaves the peel
// incomplete, and it is reported as such rather than as clean.
func (st *peel) guardedWalk(blob []byte, path []string, depth int) {
	defer func() {
		if r := recover(); r != nil {
			st.budget.trip(fmt.Sprintf("decoder panic: %v", r))
		}
	}()
	st.walk(blob, path, depth)
}

// layerCount is how many layers of obfuscation a path peeled, which is what gets
// scored. A carve decodes nothing: it finds a blob in the text around it, and
// one base64 blob in a script is the same ordinary packaging as one base64 file.
// An archive is packaging too, for as long as nothing above it was an encoding:
// the zip a sample is, a jar in a war, a gzipped document. Its members are files,
// and each is scored as it would be on disk. A zip under an encoding or a
// substitution does count, because that archive was hidden. The budget still
// counts every step, through depth, so neither buys any extra walk.
func layerCount(path []string) int {
	n, _ := pathLayers(path)
	return n
}

// pathLayers is layerCount, and whether any step so far was an encoding rather
// than a compression format or an archive.
func pathLayers(path []string) (layers int, encoded bool) {
	for _, step := range path {
		switch step {
		case carveStep:
		case zipStep:
			// Compression over a plain archive packaged the package: the
			// members start from nothing, as they would unpacked.
			if encoded {
				layers++
			} else {
				layers = 0
			}
		case "gzip", "zlib", "bzip2":
			layers++
		default:
			layers++
			encoded = true
		}
	}
	return layers, encoded
}

// walk explores one node: classify, and if not terminal, spawn a child per
// applicable layer. path is the ordered transforms taken to reach this node.
func (st *peel) walk(blob []byte, path []string, depth int) {
	select {
	case <-st.ctx.Done():
		st.budget.trip("context cancelled")
		return
	default:
	}
	if st.budget.timedOut() || st.budget.depthExceeded(depth) || !st.budget.chargeNode() {
		return
	}

	// CAS dedupe: an identical sub-blob (the duplicate-flood vector) costs
	// O(1) after its first visit.
	h := sha256.Sum256(blob)
	layers, encoded := pathLayers(path)
	st.mu.Lock()
	if _, dup := st.seen[h]; dup {
		st.mu.Unlock()
		return
	}
	st.seen[h] = struct{}{}
	st.noteDepth(layers, path)
	st.mu.Unlock()

	// Terminal? A revealed executable or script ends this branch: there is no
	// point peeling a payload we have already identified.
	if term, ok := classify(blob); ok && depth > 0 {
		st.record(Chain{Transforms: append([]string(nil), path...), Terminal: term, Depth: layers})
		st.keepLeaf(blob, h, path, layers, term)
		return
	}
	if xzMagic(blob) {
		// Recognised and not decodable here: said, rather than left as a leaf
		// that looks explored.
		st.noteOpaque(path, "xz")
	}

	// Estimator pre-pass: rank the detecting unwrappers by how likely each is
	// to be the real next layer, so the bounded frontier is spent on the most
	// probable transforms first. Ranking never drops a branch or changes a
	// verdict — it only reorders.
	prof := estimate(blob)
	frontier := rankUnwrappers(blob, st.p.unwrappers, prof)
	if depth == 0 {
		st.recordRootEntropy(prof.entropy)
	}

	// Every applicable layer decodes at once, then the results rejoin in rank
	// order: the width and output walls are spent the same way on every run, so
	// a report does not depend on which decoder happened to finish first.
	// Both are deferred so a panic below still joins the children already
	// running, and only then lets go of the bytes they were reading.
	var held int64
	defer func() { st.budget.release(held) }()
	var wg sync.WaitGroup
	defer wg.Wait()
	decoded := st.decodeFrontier(frontier, blob, encoded)
	outputs := 0
	for _, lo := range decoded {
		outputs += len(lo.outs)
		held += lo.held
	}
	children, spawned := 0, 0
	defer func() { st.gauges.noteChildren(children) }()
	siblings := make(map[[32]byte]bool, outputs)
	for i, lo := range decoded {
		container := lo.report != nil
		if container {
			st.noteContainer(lo.report)
		}
		// A layer is one reading of the blob and takes one place in the frontier
		// width. An archive's members share the place of the archive.
		opened := false
		for _, d := range lo.outs {
			// Two layers can agree on the output (rot13 and rot18 over text with
			// no digits). Settled here, in rank order, the winner is stable.
			if len(d.Data) == 0 || bytes.Equal(d.Data, blob) {
				continue
			}
			if outputs > 1 {
				id := sha256.Sum256(d.Data)
				if siblings[id] {
					continue
				}
				siblings[id] = true
			}
			if !(container && opened) && children >= st.budget.maxChildren {
				st.budget.trip("frontier width")
				return
			}
			// Past the floor, what is left of the budget is for the branches the
			// estimator rates. A guess is cancelled, and the result says where.
			if likelihood(frontier[i].Name(), prof) <= speculative && st.budget.belowFloor() {
				st.budget.trip("budget floor: branch-cancel at layer " + itoa(layers+1) + " (" + frontier[i].Name() + ")")
				break
			}
			if !st.budget.chargeOutput(len(d.Data)) {
				continue
			}
			if !(container && opened) {
				children++
			}
			opened = true
			spawned++
			childPath := append(append([]string(nil), path...), d.Label)
			st.notify(Event{Kind: EventLayer, Path: childPath, Depth: layerCount(childPath)})
			st.spawn(&wg, d.Data, childPath, depth+1)
		}
	}
	if spawned == 0 && depth > 0 {
		st.keepLeaf(blob, h, path, layers, "")
	}
}

// noteDepth records the deepest layer count and, from deepChainDepth on, the
// path that reached it. Ties go to the lower signature, so the path named does
// not depend on which branch got there first. The caller holds mu.
func (st *peel) noteDepth(layers int, path []string) {
	if layers < st.maxDepth {
		return
	}
	if layers >= deepChainDepth {
		if sig := strings.Join(path, ">"); layers > st.maxDepth || sig < st.deepest {
			st.deepest = sig
		}
	}
	st.maxDepth = layers
}

func (st *peel) noteOpaque(path []string, kind string) {
	sig := strings.Join(append(append([]string(nil), path...), kind), ">")
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, have := range st.opaque {
		if have == sig {
			return
		}
	}
	if len(st.opaque) < maxOpaque {
		st.opaque = append(st.opaque, sig)
	}
}

// noteContainer settles what an archive layer did besides opening branches: its
// counts, the bytes it decompressed and threw away, and any wall it hit.
func (st *peel) noteContainer(r *containerReport) {
	st.mu.Lock()
	st.archive.add(r.stats)
	st.mu.Unlock()
	st.gauges.noteMembers(r.stats.Members)
	if r.screenedBytes > 0 {
		st.budget.chargeOutput(int(r.screenedBytes))
	}
	switch {
	case r.wall == "":
	case r.soft:
		st.budget.tripSoft(r.wall)
	default:
		st.budget.trip(r.wall)
	}
}

// halted reports that the whole peel is over: the deadline passed or the caller
// cancelled. A long decode asks it so that it stops with the walk. It does not
// latch a reason: the node that asked it, or the decode that stopped, does.
func (st *peel) halted() bool {
	return st.ctx.Err() != nil || st.budget.pastDeadline()
}

// layerOutput is what one layer made of a blob.
type layerOutput struct {
	outs []Decoded
	// held is the bytes of outs, reserved against the held-bytes ceiling.
	held int64
	// report is set by an archive layer.
	report *containerReport
}

// decodeFrontier runs every layer against blob at once and returns the outputs in
// frontier order. It borrows whatever slots are free rather than waiting for one,
// so a chain many layers deep still cannot deadlock on its own ancestors. The
// caller's own slot covers the first worker, because it blocks until they finish.
func (st *peel) decodeFrontier(frontier []Unwrapper, blob []byte, encoded bool) []layerOutput {
	results := make([]layerOutput, len(frontier))
	extra := 0
borrow:
	for extra < len(frontier)-1 {
		select {
		case st.sem <- struct{}{}:
			extra++
		default:
			break borrow
		}
	}
	st.gauges.enter(extra)
	defer func() {
		st.gauges.leave(extra)
		for range extra {
			<-st.sem
		}
	}()
	// No decode may produce more than the output wall has left, or more than
	// the walk may still hold.
	limit := min(st.budget.remainingOutput(), st.budget.heldRoom())
	parallel.For(len(frontier), extra+1, func(i int) {
		results[i] = st.decode(frontier[i], blob, limit, encoded)
	})
	return results
}

// decode runs one layer. A panic stops at this decoder: its siblings are looking
// at the same blob and may be the ones that recognise it.
func (st *peel) decode(u Unwrapper, blob []byte, limit int64, encoded bool) (out layerOutput) {
	defer func() {
		if r := recover(); r != nil {
			out = layerOutput{}
			st.budget.trip(fmt.Sprintf("decoder panic: %v", r))
		}
	}()
	if st.ctx.Err() != nil || st.budget.timedOut() {
		return out
	}
	st.gauges.decodes.Add(1)
	var err error
	if c, ok := u.(containerUnwrapper); ok {
		var report containerReport
		out.outs, report, err = c.UnwrapContainer(blob, containerEnv{limit: limit, hidden: encoded, stop: st.halted})
		if err == nil || report.stats.Archives > 0 {
			out.report = &report
		}
	} else {
		out.outs, err = unwrapLayer(u, blob, limit)
	}
	if err != nil {
		if errors.Is(err, errBombCap) {
			st.budget.trip("output ceiling (decompression-bomb cap)")
		}
		out.outs = nil
		return out
	}
	var n int64
	for _, d := range out.outs {
		n += int64(len(d.Data))
	}
	// Held from here until the node that asked for it is done with its children.
	if !st.budget.hold(n) {
		out.outs = nil
		return out
	}
	out.held = n
	return out
}

// spawn runs a child either on a new goroutine (if a semaphore slot is free) or
// inline (to avoid the bounded-recursion deadlock).
func (st *peel) spawn(wg *sync.WaitGroup, blob []byte, path []string, depth int) {
	select {
	case st.sem <- struct{}{}:
		wg.Add(1)
		st.gauges.enter(1)
		go func() {
			defer wg.Done()
			defer func() { <-st.sem }()
			defer st.gauges.leave(1)
			st.guardedWalk(blob, path, depth)
		}()
	default:
		st.guardedWalk(blob, path, depth)
	}
}

func (st *peel) record(c Chain) {
	st.mu.Lock()
	st.chains = append(st.chains, c)
	st.mu.Unlock()
	st.notify(Event{Kind: EventChain, Path: c.Transforms, Depth: c.Depth, Terminal: c.Terminal})
}

func (st *peel) notify(e Event) {
	if st.emit != nil {
		st.emit(e)
	}
}

// finish assembles the Result: orders chains deepest-first, picks the outcome
// by precedence, and scores depth-plus-payload.
func (st *peel) finish(exhausted bool, reason string) Result {
	st.mu.Lock()
	chains := append([]Chain(nil), st.chains...)
	maxDepth := st.maxDepth
	rootEntropy := st.rootEntropy
	deepest := st.deepest
	archive := st.archive
	opaque := append([]string(nil), st.opaque...)
	st.mu.Unlock()
	sort.Strings(opaque)

	// Branches finish in any order, so the signature breaks ties: the primary
	// chain of a report has to be the same one on every run.
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Depth != chains[j].Depth {
			return chains[i].Depth > chains[j].Depth
		}
		return chains[i].Signature() < chains[j].Signature()
	})

	r := Result{
		MaxDepth:      maxDepth,
		Chains:        chains,
		Exhausted:     exhausted,
		ExhaustReason: reason,
		ExhaustSoft:   exhausted && st.budget.softOnly(),
		NodesVisited:  st.budget.Nodes(),
		OutputBytes:   st.budget.OutputBytes(),
		RootEntropy:   rootEntropy,
		Opaque:        opaque,
		Leaves:        st.finishLeaves(),
	}
	if maxDepth >= deepChainDepth {
		r.DeepestSignature = deepest
	}
	if archive.Archives > 0 {
		r.Archive = &archive
	}

	// Outcome by precedence. Only a *chain* (depth >= minChainDepth) promotes a
	// revealed payload to a finding; a single ordinary layer is encchain's job.
	switch {
	case hasChainTerminal(chains, OutcomeRevealedExecutable):
		r.Outcome = OutcomeRevealedExecutable
	case hasChainTerminal(chains, OutcomeRevealedScript):
		r.Outcome = OutcomeRevealedScript
	case exhausted:
		r.Outcome = OutcomePeelExhausted
	case maxDepth >= deepChainDepth:
		r.Outcome = OutcomeDeepChain
	default:
		r.Outcome = OutcomeClean
	}

	// PrimarySignature names the qualifying chain when there is a finding, else
	// the deepest recorded chain (which may be a shallow, informational one).
	if sig, ok := primaryChainSignature(chains, r.Outcome); ok {
		r.PrimarySignature = sig
	} else if len(chains) > 0 {
		r.PrimarySignature = chains[0].Signature()
	}
	r.Score = score(r)
	r.Findings = buildFindings(r)
	return r
}

// buildFindings renders the detector-contract findings from a scored result:
// one per qualifying chain (depth >= minChainDepth revealing a payload) and one
// for an exhausted peel. A plain clean result has no findings.
func buildFindings(r Result) []Finding {
	var out []Finding
	for _, c := range r.Chains {
		if !c.qualifies() {
			continue
		}
		switch c.Terminal {
		case OutcomeRevealedExecutable:
			out = append(out, Finding{
				Class: "peel.revealed-executable", Score: r.Score, Technique: Technique, Novel: Novel,
				Detail: "executable revealed through " + c.Signature() + " (depth " + itoa(c.Depth) + ")",
			})
		case OutcomeRevealedScript:
			out = append(out, Finding{
				Class: "peel.revealed-script", Score: r.Score, Technique: Technique, Novel: Novel,
				Detail: "script revealed through " + c.Signature() + " (depth " + itoa(c.Depth) + ")",
			})
		}
	}
	if r.Outcome == OutcomePeelExhausted {
		out = append(out, Finding{
			Class: "peel.exhausted", Score: r.Score, Technique: Technique, Novel: Novel,
			Detail: "peel exhausted at " + itoa(r.MaxDepth) + " layers: " + r.ExhaustReason,
		})
	}
	// Depth is its own observation, whatever was or was not found under it. It
	// carries the depth part of the score only: the payload has its own class.
	if r.MaxDepth >= deepChainDepth {
		out = append(out, Finding{
			Class: "peel.deep-chain", Score: depthScore(r.MaxDepth), Technique: Technique, Novel: Novel,
			Detail: itoa(r.MaxDepth) + " layers peeled through " + r.DeepestSignature,
		})
	}
	return out
}

// depthScore is what depth alone contributes: nothing up to depthScoreThreshold,
// then 15 a layer.
func depthScore(depth int) int {
	if depth <= depthScoreThreshold {
		return 0
	}
	return min((depth-depthScoreThreshold)*15, 100)
}

// primaryChainSignature returns the signature of the deepest chain whose
// terminal matches a finding outcome. chains is already sorted deepest-first.
func primaryChainSignature(chains []Chain, outcome Outcome) (string, bool) {
	for _, c := range chains {
		if c.qualifies() && c.Terminal == outcome {
			return c.Signature(), true
		}
	}
	return "", false
}

// score bounds the verdict to [0,100]. Depth above the threshold raises the
// score on its own (a deep chain that outlived the budget still flags); a
// revealed executable or script adds a payload bonus; an exhausted peel carries
// a floor so it is never rendered as low-signal clean.
func score(r Result) int {
	s := depthScore(r.MaxDepth)
	switch r.Outcome {
	case OutcomeRevealedExecutable:
		s += 60
	case OutcomeRevealedScript:
		s += 40
	case OutcomePeelExhausted:
		// The floor is for a chain the budget cut short. A plain archive the
		// budget could not read through is incomplete, not suspicious.
		if s < 30 && !r.ExhaustSoft {
			s = 30
		}
	}
	// A substitution counts as one more layer: it reads as deliberate at any depth.
	for _, c := range r.Chains {
		if c.Terminal == r.Outcome && c.hasCipher() {
			s += 15
			break
		}
	}
	if s > 100 {
		s = 100
	}
	return s
}

// hasChainTerminal reports whether any recorded chain of at least minChainDepth
// layers ended in terminal t. Depth-1 reveals do not qualify: a single ordinary
// compression/encoding layer is normal packaging, not an obfuscation chain.
func hasChainTerminal(chains []Chain, t Outcome) bool {
	for _, c := range chains {
		if c.qualifies() && c.Terminal == t {
			return true
		}
	}
	return false
}

// classify names what a revealed blob is, for terminal detection. It reads only
// magic bytes — it never runs anything.
func classify(blob []byte) (Outcome, bool) {
	switch {
	case len(blob) >= 2 && blob[0] == 'M' && blob[1] == 'Z':
		return OutcomeRevealedExecutable, true
	case len(blob) >= 4 && blob[0] == 0x7f && blob[1] == 'E' && blob[2] == 'L' && blob[3] == 'F':
		return OutcomeRevealedExecutable, true
	case len(blob) >= 2 && blob[0] == '#' && blob[1] == '!':
		return OutcomeRevealedScript, true
	case scriptLike(window(blob)):
		return OutcomeRevealedScript, true
	}
	return "", false
}

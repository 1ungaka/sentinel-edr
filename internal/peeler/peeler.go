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
// encodings, rot and Caesar substitutions, gzip/zlib/flate/bzip2). It never
// executes or emulates sample content;
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

	"github.com/s-b-repo/cau/internal/parallel"
)

func itoa(n int) string { return strconv.Itoa(n) }

// Outcome is the terminal classification of a peel. Precedence when several
// occur across branches: RevealedExecutable > RevealedScript > PeelExhausted >
// Clean. "Clean" means the tree was fully explored within budget and nothing
// interesting surfaced — it is only trustworthy *because* the budget was not
// hit, which is why PeelExhausted outranks it.
type Outcome string

const (
	OutcomeClean              Outcome = "clean"
	OutcomeRevealedExecutable Outcome = "revealed-executable"
	OutcomeRevealedScript     Outcome = "revealed-script"
	OutcomePeelExhausted      Outcome = "peel-exhausted"
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
	// NodesVisited and OutputBytes report the spend, for operators and tests.
	NodesVisited int64 `json:"nodes_visited"`
	OutputBytes  int64 `json:"output_bytes"`
	// RootEntropy is the Shannon entropy (bits/byte) of the input, from the
	// estimator pre-pass. High entropy on a blob that does not peel points at a
	// terminal packed/encrypted layer.
	RootEntropy float64 `json:"root_entropy,omitempty"`

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

// New builds a Peeler with the default unwrappers and limits.
func New(opts ...Option) *Peeler {
	p := &Peeler{
		unwrappers:  DefaultUnwrappers(),
		limits:      DefaultLimits(),
		parallelism: min(runtime.GOMAXPROCS(0), maxDefaultParallelism),
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
	rootEntropy float64
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
	if ctx == nil {
		ctx = context.Background()
	}
	st := &peel{
		p:      p,
		ctx:    ctx,
		budget: NewBudget(p.limits),
		emit:   emit,
		sem:    make(chan struct{}, p.parallelism),
		seen:   make(map[[32]byte]struct{}),
	}
	st.sem <- struct{}{} // this goroutine is the first of the N
	st.guardedWalk(data, nil, 0)

	exhausted, reason := st.budget.Exhausted()
	return st.finish(exhausted, reason)
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
// The budget still counts it, through depth, so carving buys no extra walk.
func layerCount(path []string) int {
	n := len(path)
	for _, step := range path {
		if step == carveStep {
			n--
		}
	}
	return n
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
	st.mu.Lock()
	if _, dup := st.seen[h]; dup {
		st.mu.Unlock()
		return
	}
	st.seen[h] = struct{}{}
	layers := layerCount(path)
	if layers > st.maxDepth {
		st.maxDepth = layers
	}
	st.mu.Unlock()

	// Terminal? A revealed executable or script ends this branch: there is no
	// point peeling a payload we have already identified.
	if term, ok := classify(blob); ok && depth > 0 {
		st.record(Chain{Transforms: append([]string(nil), path...), Terminal: term, Depth: layers})
		return
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
	// Deferred so a panic below still joins the children already running.
	var wg sync.WaitGroup
	defer wg.Wait()
	children := 0
	decoded := st.decodeFrontier(frontier, blob)
	outputs := 0
	for _, ds := range decoded {
		outputs += len(ds)
	}
	siblings := make(map[[32]byte]bool, outputs)
	for _, ds := range decoded {
		for _, d := range ds {
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
			if children >= st.budget.maxChildren {
				st.budget.trip("frontier width")
				return
			}
			if !st.budget.chargeOutput(len(d.Data)) {
				continue
			}
			children++
			childPath := append(append([]string(nil), path...), d.Label)
			st.notify(Event{Kind: EventLayer, Path: childPath, Depth: layerCount(childPath)})
			st.spawn(&wg, d.Data, childPath, depth+1)
		}
	}
}

// decodeFrontier runs every layer against blob at once and returns the outputs in
// frontier order. It borrows whatever slots are free rather than waiting for one,
// so a chain many layers deep still cannot deadlock on its own ancestors. The
// caller's own slot covers the first worker, because it blocks until they finish.
func (st *peel) decodeFrontier(frontier []Unwrapper, blob []byte) [][]Decoded {
	results := make([][]Decoded, len(frontier))
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
	defer func() {
		for range extra {
			<-st.sem
		}
	}()
	limit := st.budget.remainingOutput()
	parallel.For(len(frontier), extra+1, func(i int) {
		results[i] = st.decode(frontier[i], blob, limit)
	})
	return results
}

// decode runs one layer. A panic stops at this decoder: its siblings are looking
// at the same blob and may be the ones that recognise it.
func (st *peel) decode(u Unwrapper, blob []byte, limit int64) (out []Decoded) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			st.budget.trip(fmt.Sprintf("decoder panic: %v", r))
		}
	}()
	if st.ctx.Err() != nil || st.budget.timedOut() {
		return nil
	}
	out, err := unwrapLayer(u, blob, limit)
	if err != nil {
		if errors.Is(err, errBombCap) {
			st.budget.trip("output ceiling (decompression-bomb cap)")
		}
		return nil
	}
	return out
}

// spawn runs a child either on a new goroutine (if a semaphore slot is free) or
// inline (to avoid the bounded-recursion deadlock).
func (st *peel) spawn(wg *sync.WaitGroup, blob []byte, path []string, depth int) {
	select {
	case st.sem <- struct{}{}:
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-st.sem }()
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
	st.mu.Unlock()

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
		NodesVisited:  st.budget.Nodes(),
		OutputBytes:   st.budget.OutputBytes(),
		RootEntropy:   rootEntropy,
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
	return out
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
	s := 0
	if r.MaxDepth > depthScoreThreshold {
		s += (r.MaxDepth - depthScoreThreshold) * 15
	}
	switch r.Outcome {
	case OutcomeRevealedExecutable:
		s += 60
	case OutcomeRevealedScript:
		s += 40
	case OutcomePeelExhausted:
		if s < 30 {
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

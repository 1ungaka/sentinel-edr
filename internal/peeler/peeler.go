// Package peeler is the engine-side, bounded unpeeling pre-pass for
// multi-method obfuscation chains (NOVEL-012): encoding → packing → encryption
// stacks where the *depth* of the chain is itself a signal, not just the
// payload at the bottom.
//
// It walks the candidate tree — at each node every applicable layer decoder
// spawns a child — under a single global per-sample budget wall (see Budget),
// so an attacker who adds layers adds latency, never total spend. A branch that
// hits the wall yields a first-class `peel-exhausted` outcome, rendered and
// scored, never silently reported clean: an over-budget sample is a finding
// about the budget, not a clean bill of health.
//
// Scope discipline: the peeler only *decodes* reversible layers (base64/base32/
// hex, gzip/zlib/flate/bzip2). It never executes or emulates sample content;
// the emulation-sidecar fallback named in the plan is a separate, later,
// isolated component. What ships here is "what to catch and how to catch it".
//
// This is the first increment: the bounded tree walk, the budget wall, CAS
// dedupe, depth-as-signal scoring, and chain signatures. Scan-path wiring
// (a ScanResult facet + fusion), the entropy/structural estimator that ranks
// the frontier, and the emulation fallback are follow-ons tracked in PLAN.md.
package peeler

import (
	"context"
	"crypto/sha256"
	"sort"
	"strings"
	"sync"
)

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
	// Depth is len(Transforms): the number of layers peeled to reach it.
	Depth int `json:"depth"`
}

// Signature renders the chain as a stable string, e.g. "base64>gzip>base64".
// Ordered chain patterns become family signatures in the detection-content
// lifecycle.
func (c Chain) Signature() string { return strings.Join(c.Transforms, ">") }

// Result is the peel verdict for one sample.
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
}

// Technique is the ATT&CK id this detector is evidence for (partial): the
// T1027 obfuscation family. Depth and chain patterns are the evidence.
const Technique = "T1027"

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

// WithParallelism sets the max in-flight unwrap goroutines (default 4). Values
// below 1 are treated as 1 (serial).
func WithParallelism(n int) Option { return func(p *Peeler) { p.parallelism = n } }

// New builds a Peeler with the default unwrappers and limits.
func New(opts ...Option) *Peeler {
	p := &Peeler{
		unwrappers:  DefaultUnwrappers(),
		limits:      DefaultLimits(),
		parallelism: 4,
	}
	for _, o := range opts {
		o(p)
	}
	if p.parallelism < 1 {
		p.parallelism = 1
	}
	return p
}

// peel is the mutable per-sample state shared across the walk.
type peel struct {
	p      *Peeler
	ctx    context.Context
	budget *Budget

	// sem bounds in-flight child goroutines. A slot that cannot be acquired
	// without blocking means the child runs inline on the current goroutine —
	// the standard deadlock-free pattern for bounded parallel recursion.
	sem chan struct{}

	mu       sync.Mutex
	seen     map[[32]byte]struct{} // CAS: a blob hash peeled once is never re-peeled
	chains   []Chain
	maxDepth int
}

// Peel walks the obfuscation tree rooted at data and returns the verdict.
// It always terminates within the budget and never executes sample content.
func (p *Peeler) Peel(ctx context.Context, data []byte) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	st := &peel{
		p:      p,
		ctx:    ctx,
		budget: NewBudget(p.limits),
		sem:    make(chan struct{}, p.parallelism),
		seen:   make(map[[32]byte]struct{}),
	}
	st.walk(data, nil, 0)

	exhausted, reason := st.budget.Exhausted()
	return st.finish(exhausted, reason)
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
	if depth > st.maxDepth {
		st.maxDepth = depth
	}
	st.mu.Unlock()

	// Terminal? A revealed executable or script ends this branch: there is no
	// point peeling a payload we have already identified.
	if term, ok := classify(blob); ok && depth > 0 {
		st.record(Chain{Transforms: append([]string(nil), path...), Terminal: term, Depth: depth})
		return
	}

	// Spawn a bounded child per applicable layer, up to the frontier width.
	var wg sync.WaitGroup
	children := 0
	for _, u := range st.p.unwrappers {
		if children >= st.budget.maxChildren {
			break
		}
		if !u.Detect(blob) {
			continue
		}
		out, err := u.Unwrap(blob, st.budget.remainingOutput())
		if err != nil {
			if err == errBombCap {
				st.budget.trip("output ceiling (decompression-bomb cap)")
			}
			continue
		}
		if len(out) == 0 || !st.budget.chargeOutput(len(out)) {
			continue
		}
		// Require real progress: a transform that returns its own input (or a
		// no-op) must not spawn an identical child and loop.
		if len(out) == len(blob) && string(out) == string(blob) {
			continue
		}
		children++
		childPath := append(append([]string(nil), path...), u.Name())
		st.spawn(&wg, out, childPath, depth+1)
	}
	wg.Wait()
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
			st.walk(blob, path, depth)
		}()
	default:
		st.walk(blob, path, depth)
	}
}

func (st *peel) record(c Chain) {
	st.mu.Lock()
	st.chains = append(st.chains, c)
	st.mu.Unlock()
}

// finish assembles the Result: orders chains deepest-first, picks the outcome
// by precedence, and scores depth-plus-payload.
func (st *peel) finish(exhausted bool, reason string) Result {
	st.mu.Lock()
	chains := append([]Chain(nil), st.chains...)
	maxDepth := st.maxDepth
	st.mu.Unlock()

	sort.SliceStable(chains, func(i, j int) bool { return chains[i].Depth > chains[j].Depth })

	r := Result{
		MaxDepth:      maxDepth,
		Chains:        chains,
		Exhausted:     exhausted,
		ExhaustReason: reason,
		NodesVisited:  st.budget.Nodes(),
		OutputBytes:   st.budget.OutputBytes(),
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
	return r
}

// primaryChainSignature returns the signature of the deepest chain whose
// terminal matches a finding outcome. chains is already sorted deepest-first.
func primaryChainSignature(chains []Chain, outcome Outcome) (string, bool) {
	for _, c := range chains {
		if c.Depth >= minChainDepth && c.Terminal == outcome {
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
		if c.Depth >= minChainDepth && c.Terminal == t {
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
	}
	return "", false
}

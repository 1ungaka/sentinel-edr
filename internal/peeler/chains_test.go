package peeler

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"
)

// ── depth as its own observation ────────────────────────────────────────────

func findingOf(r Result, class string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.Class == class {
			return f, true
		}
	}
	return Finding{}, false
}

// Four layers over ordinary text: nothing is revealed, and the wrapper is still
// reported. Three layers are not, which is the margin the measurement left.
func TestDepthAloneIsAFinding(t *testing.T) {
	for depth := 1; depth <= 7; depth++ {
		layers := []string{"base64", "gzip", "hex", "base32", "zlib", "base64", "gzip"}[:depth]
		r := peelDefault(compose(prose, layers...))
		f, found := findingOf(r, "peel.deep-chain")
		if found != (depth >= deepChainDepth) {
			t.Fatalf("depth %d: deep-chain finding = %v (%+v)", depth, found, r.Findings)
		}
		if depth < deepChainDepth {
			if r.Outcome != OutcomeClean || r.DeepestSignature != "" {
				t.Errorf("depth %d: outcome %s, deepest %q", depth, r.Outcome, r.DeepestSignature)
			}
			continue
		}
		if r.Outcome != OutcomeDeepChain || r.DeepestSignature != strings.Join(layers, ">") {
			t.Errorf("depth %d: outcome %s, deepest %q", depth, r.Outcome, r.DeepestSignature)
		}
		// The weight is the one depth always had: 15 a layer past the second.
		if want := (depth - 2) * 15; f.Score != want || r.Score != want {
			t.Errorf("depth %d: finding %d, result %d, want %d", depth, f.Score, r.Score, want)
		}
		if got := r.Detected(); got != (depth >= 6) {
			t.Errorf("depth %d: detected = %v", depth, got)
		}
	}
}

// Depth is reported beside a payload, not instead of it, and with its own weight.
func TestDepthIsReportedBesideThePayload(t *testing.T) {
	r := peelDefault(compose(fakeELF, "base64", "gzip", "hex", "zlib", "base32"))
	deep, ok := findingOf(r, "peel.deep-chain")
	exe, ok2 := findingOf(r, "peel.revealed-executable")
	if !ok || !ok2 || r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome %s, findings %+v", r.Outcome, r.Findings)
	}
	if deep.Score != 45 || exe.Score != 100 {
		t.Fatalf("deep %d, executable %d", deep.Score, exe.Score)
	}
}

// Two branches reach the same depth. The one named must not depend on which
// goroutine got there first.
func TestDeepestPathIsStable(t *testing.T) {
	a := compose(prose, "base64", "gzip", "hex", "zlib")
	b := compose(prose[:400], "hex", "gzip", "base64", "zlib")
	blob := zipOf(zipEntry{name: "a", body: a}, zipEntry{name: "b", body: b})
	want := peelDefault(blob).DeepestSignature
	if want != "zip>base64>gzip>hex>zlib" {
		t.Fatalf("deepest = %q", want)
	}
	for i := 0; i < 50; i++ {
		if got := peelDefault(blob).DeepestSignature; got != want {
			t.Fatalf("run %d: %q, want %q", i, got, want)
		}
	}
}

func TestEveryFindingClassIsInTheCatalog(t *testing.T) {
	known := map[string]bool{}
	for _, c := range Classes() {
		known[c.Class] = true
	}
	deepArchive := compose(fakeELF, "base64", "gzip", "hex", "zlib")
	// The two evidence classes are produced by the caller that rescans a
	// decoded layer, so the fixture adds them the way the engine does.
	withEvidence := peelDefault(compose(harmlessScript, "base64", "gzip"))
	withEvidence.AddEvidence(Finding{Class: "peel.rule-match", Score: 40, Detail: "a rule matched the decoded layer"})
	withEvidence.AddEvidence(Finding{Class: "peel.indicator-match", Score: 25, Detail: "an indicator matched the decoded layer"})
	for _, r := range []Result{
		peelDefault(deepArchive),
		withEvidence,
		New(WithLimits(BudgetLimits{MaxDepth: 1})).Peel(context.Background(), deepArchive),
	} {
		for _, f := range r.Findings {
			if !known[f.Class] {
				t.Errorf("finding class %s is not in Classes()", f.Class)
			}
			delete(known, f.Class)
		}
	}
	for class := range known {
		t.Errorf("class %s is in the catalog and no fixture here produced it", class)
	}
}

// ── leaves, for a caller that rescans what the chain hid ────────────────────

func TestLeavesCarryWhatTheChainHid(t *testing.T) {
	blob := compose(harmlessScript, "base64", "gzip")
	if r := peelDefault(blob); r.Leaves != nil {
		t.Fatalf("leaves kept without being asked for: %d", len(r.Leaves))
	}
	r := New(WithLeaves(1<<20)).Peel(context.Background(), blob)
	if len(r.Leaves) != 1 {
		t.Fatalf("leaves = %+v", r.Leaves)
	}
	l := r.Leaves[0]
	if l.Signature != "base64>gzip" || l.Terminal != OutcomeRevealedScript || l.Depth != 2 || l.Truncated || string(l.Data) != string(harmlessScript) {
		t.Fatalf("leaf = %+v", l)
	}

	// A single layer is no finding here, and its leaf is still handed over:
	// that is the case the rescan exists for.
	r = New(WithLeaves(1<<20)).Peel(context.Background(), compose(prose, "base64"))
	if len(r.Leaves) != 1 || r.Leaves[0].Signature != "base64" || r.Leaves[0].Terminal != "" || string(r.Leaves[0].Data) != string(prose) {
		t.Fatalf("leaves = %+v", r.Leaves)
	}
	if r.Outcome != OutcomeClean {
		t.Fatalf("outcome = %s", r.Outcome)
	}
}

func TestLeavesAreBounded(t *testing.T) {
	var entries []zipEntry
	for i := 0; i < 40; i++ {
		entries = append(entries, zipEntry{name: fmt.Sprint(i), body: compose([]byte(fmt.Sprintf("member %d %s", i, prose)), "base64", "gzip")})
	}
	const allowance = 2000
	blob := zipOf(entries...)
	p := New(WithLeaves(allowance))
	want := p.Peel(context.Background(), blob).Leaves
	if len(want) != maxLeaves {
		t.Fatalf("%d leaves kept of 40", len(want))
	}
	total := 0
	for _, l := range want {
		total += len(l.Data)
		if !l.Truncated || len(l.Data) != allowance/maxLeaves {
			t.Fatalf("leaf of %d bytes, truncated %v", len(l.Data), l.Truncated)
		}
	}
	if total > allowance {
		t.Fatalf("%d bytes of leaves over an allowance of %d", total, allowance)
	}
	// Which eight are kept is settled by order, not by arrival.
	for i := 0; i < 20; i++ {
		got := p.Peel(context.Background(), blob).Leaves
		for j := range want {
			if string(got[j].Data) != string(want[j].Data) {
				t.Fatalf("run %d: leaf %d differs", i, j)
			}
		}
	}
	// The copies are the caller's: they do not alias the sample.
	want[0].Data[0] ^= 0xff
	if got := p.Peel(context.Background(), blob).Leaves[0].Data[0]; got == want[0].Data[0] {
		t.Fatal("a leaf aliases the walk's memory")
	}
}

// ── randomized synthetic chains, blue and red ───────────────────────────────

// wrapped is a blob under construction and what the peeler can know about it,
// which decides the layers that may go over it next. The rules mirror the
// decoders' own gates: a base beyond base64/base32/hex has to decode to
// something recognisable, and a substitution is only found over an encoding of
// something that reads as text or as a known format.
type wrapped struct {
	blob   []byte
	layers []string // outermost first
	// reveals: text, or a format a trial decode recognises.
	reveals bool
	// archive: a zip, which a base decoder accepts and a trial decode does not.
	archive bool
	// rotatable: one unbroken run of an encoding over something that reveals.
	rotatable bool
}

var (
	plainBases  = []string{"base64", "base32", "hex"}
	gatedBases  = []string{"base85", "base91", "base92", "base32hex", "base32-lower", "base32-crockford", "zbase32"}
	radixBases  = []string{"base58", "base62", "base36"}
	substitutes = []string{"rot13", "rot47", "atbash", "caesar-3", "caesar-7", "caesar-21", "reverse"}
)

func (w wrapped) wrap(name string) wrapped {
	next := wrapped{blob: encodeAny(name, w.blob), layers: append([]string{name}, w.layers...)}
	switch {
	case isCipher(name), name == "gzip":
		next.reveals = true // rotated text is text; gzip has a header
	case name == zipStep:
		next.archive = true
	case name == "zlib":
		next.reveals = w.reveals // known by what it inflates to
	default:
		next.reveals, next.rotatable = true, w.reveals
	}
	return next
}

// choices is every layer the peeler is built to see through over w.
func (w wrapped) choices() []string {
	out := append([]string{"gzip", "zlib", zipStep}, plainBases...)
	if w.reveals || w.archive {
		out = append(out, gatedBases...)
		if len(w.blob) <= 600 {
			out = append(out, radixBases...)
		}
	}
	if w.rotatable {
		out = append(out, substitutes...)
	}
	return out
}

func randomChain(rng *rand.Rand, leaf wrapped, depth int) wrapped {
	w := leaf
	for len(w.layers) < depth {
		c := w.choices()
		next := w.wrap(c[rng.IntN(len(c))])
		// A substitution that changes nothing (a Caesar shift over digits) is
		// not a layer anyone could find.
		if !bytes.Equal(next.blob, w.blob) {
			w = next
		}
	}
	return w
}

// pathsWalked lists every path a peel opened, for a failure message that shows
// where a chain was lost or grew.
func pathsWalked(blob []byte) []string {
	var out []string
	for e := range New().Start(context.Background(), blob).Events() {
		if e.Kind == EventLayer {
			out = append(out, strings.Join(e.Path, ">"))
		}
	}
	sort.Strings(out)
	return out
}

// Randomized chains over the whole layer library, swept by depth, each red
// fixture beside a blue twin wrapped the same way. FN and FP have to stay at
// zero as depth grows. The leaves are a script that echoes one word, an inert
// header stub, and plain prose.
func TestRandomChainsDepthSweep(t *testing.T) {
	perDepth := 24
	if testing.Short() {
		perDepth = 6
	}
	script := wrapped{blob: harmlessScript, reveals: true}
	stub := wrapped{blob: largeELF()}
	t.Logf("%-6s %-7s %-4s %-4s %-7s %s", "depth", "chains", "FN", "FP", "depth+1", "twins reported deep")
	for depth := 1; depth <= 8; depth++ {
		rng := rand.New(rand.NewPCG(20261106, uint64(depth)))
		fn, fp, deep, grown := 0, 0, 0, 0
		for i := 0; i < perDepth; i++ {
			leaf, terminal := script, OutcomeRevealedScript
			if i%2 == 1 {
				leaf, terminal = stub, OutcomeRevealedExecutable
			}
			red := randomChain(rng, leaf, depth)
			blue := composeAny(prose, red.layers...)
			sig := strings.Join(red.layers, ">")

			c := Chain{Transforms: red.layers, Depth: layerCount(red.layers)}
			r := peelDefault(red.blob)
			switch {
			case !c.qualifies():
				// A single ordinary layer, or packaging alone: not a finding.
				if r.Outcome == OutcomeRevealedExecutable || r.Outcome == OutcomeRevealedScript {
					fp++
					t.Errorf("depth %d: %s is not a chain and was flagged %s", depth, sig, r.Outcome)
				}
			case r.Outcome != terminal || !hasChain(r, sig):
				fn++
				t.Errorf("depth %d: %s not recovered: outcome %s, exhausted %q, walked %v", depth, sig, r.Outcome, r.ExhaustReason, pathsWalked(red.blob))
			}
			// A digit rotation over a reversed encoding can read as a layer of
			// its own (rot5 leaves enough of the head intact to pass for a
			// reveal), which adds one to the depth. Counted, not hidden.
			switch {
			case r.MaxDepth < c.Depth || r.MaxDepth > c.Depth+1:
				t.Errorf("depth %d: %s peeled to %d layers, want %d: walked %v", depth, sig, r.MaxDepth, c.Depth, pathsWalked(red.blob))
			case r.MaxDepth > c.Depth:
				grown++
			}

			b := peelDefault(blue)
			if b.Outcome == OutcomeRevealedExecutable || b.Outcome == OutcomeRevealedScript {
				fp++
				t.Errorf("depth %d: benign twin of %s flagged %s via %s", depth, sig, b.Outcome, b.PrimarySignature)
			}
			if _, ok := findingOf(b, "peel.deep-chain"); ok {
				deep++
				if c.Depth < deepChainDepth {
					t.Errorf("depth %d: benign twin of %s reported deep at %d layers", depth, sig, b.MaxDepth)
				}
			}
		}
		t.Logf("%-6d %-7d %-4d %-4d %-7d %d", depth, perDepth, fn, fp, grown, deep)
	}
}

// ── the wall clock, across chain shapes ─────────────────────────────────────

// Whatever the shape, the peel is over within its wall clock plus the one
// decode that was running when it struck.
func TestWallClockHoldsAcrossChainShapes(t *testing.T) {
	const wall = 1500 * time.Millisecond
	slack := 2500 * time.Millisecond * raceSlow // one in-flight decode, on a busy machine
	shapes := hostileShapes()
	for depth := 4; depth <= 28; depth += 8 {
		layers := make([]string, 0, depth)
		for len(layers) < depth {
			layers = append(layers, []string{"base64", "gzip", "base85", "zlib", "rot13", "hex"}...)
		}
		s := shapes["prose"]
		s.blob = composeAny(fakeELF, layers[:depth]...)
		shapes[fmt.Sprintf("chain of %d", depth)] = s
	}
	for name, s := range shapes {
		t.Run(name, func(t *testing.T) {
			limits := s.limits
			limits.MaxWallClock = wall
			opts := []Option{WithLimits(limits)}
			if s.layers != nil {
				opts = append(opts, WithUnwrappers(s.layers))
			}
			start := time.Now()
			r := New(opts...).Peel(context.Background(), s.blob)
			if d := time.Since(start); d > wall+slack {
				t.Fatalf("took %s under a wall clock of %s (%s, %q)", d, wall, r.Outcome, r.ExhaustReason)
			}
			if r.Exhausted && r.Outcome == OutcomeClean {
				t.Fatalf("an exhausted peel was reported clean: %q", r.ExhaustReason)
			}
		})
	}
}

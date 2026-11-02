package peeler

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// ── synthetic chain composition (blue/red fixtures) ─────────────────────────
//
// compose wraps payload through layers given OUTERMOST-first, so the produced
// blob decodes along exactly that transform order. bzip2 is intentionally
// absent: the stdlib has no bzip2 writer, and the decode side is covered by
// its own unit test. Nothing here builds a weaponized payload — the "payload"
// is an inert magic-prefixed buffer.

func encodeLayer(name string, in []byte) []byte {
	switch name {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(in))
	case "base32":
		return []byte(base32.StdEncoding.EncodeToString(in))
	case "hex":
		return []byte(hex.EncodeToString(in))
	case "gzip":
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write(in)
		w.Close()
		return buf.Bytes()
	case "zlib":
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write(in)
		w.Close()
		return buf.Bytes()
	case "flate":
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		w.Write(in)
		w.Close()
		return buf.Bytes()
	default:
		panic("unknown layer " + name)
	}
}

// compose applies layers innermost-last so the outer blob's decode order equals
// `layers` (outermost first).
func compose(payload []byte, layers ...string) []byte {
	out := payload
	for i := len(layers) - 1; i >= 0; i-- {
		out = encodeLayer(layers[i], out)
	}
	return out
}

// fakeELF is an inert buffer with the ELF magic and enough body that encoders
// have something to work on and layers stay above minLayerLen.
var fakeELF = append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("inert-sample-body."), 8)...)

func TestSingleLayerIsNotAChain(t *testing.T) {
	// A single ordinary layer over a payload is normal packaging (encchain's
	// job), not an obfuscation *chain*: the peeler reports Clean but still
	// records the depth-1 chain for transparency.
	blob := compose(fakeELF, "base64")
	r := New().Peel(context.Background(), blob)
	if r.Outcome != OutcomeClean {
		t.Fatalf("outcome = %s, want clean (single layer is not a chain)", r.Outcome)
	}
	if r.MaxDepth != 1 {
		t.Errorf("max depth = %d, want 1", r.MaxDepth)
	}
	if len(r.Chains) != 1 || r.Chains[0].Signature() != "base64" {
		t.Errorf("expected the depth-1 chain recorded for transparency, got %v", r.Chains)
	}
}

func TestDeepChainRecovered(t *testing.T) {
	layers := []string{"base64", "gzip", "base32", "hex"}
	blob := compose(fakeELF, layers...)
	r := New().Peel(context.Background(), blob)
	if r.Outcome != OutcomeRevealedExecutable {
		t.Fatalf("outcome = %s, want revealed-executable", r.Outcome)
	}
	if r.MaxDepth != len(layers) {
		t.Errorf("max depth = %d, want %d", r.MaxDepth, len(layers))
	}
	want := strings.Join(layers, ">")
	if r.PrimarySignature != want {
		t.Errorf("signature = %q, want %q", r.PrimarySignature, want)
	}
	if r.Exhausted {
		t.Errorf("unexpectedly exhausted: %s", r.ExhaustReason)
	}
}

func TestDepthSweepFlat(t *testing.T) {
	// A depth sweep must recover the payload at every depth up to the cap and
	// must never report a false positive on the benign twin. FP/FN flat as
	// depth grows is the whole point of the budget-bounded tree.
	stack := []string{"base64", "gzip", "zlib", "base64", "hex", "flate"}
	benign := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog\n"), 4)
	for depth := 1; depth <= len(stack); depth++ {
		layers := stack[:depth]
		mal := compose(fakeELF, layers...)
		r := New().Peel(context.Background(), mal)
		// Depth 1 is a single layer (Clean); depth >= 2 is a chain (finding).
		wantOutcome := OutcomeRevealedExecutable
		if depth < minChainDepth {
			wantOutcome = OutcomeClean
		}
		if r.Outcome != wantOutcome {
			t.Errorf("depth %d: outcome = %s, want %s (sig %q)", depth, r.Outcome, wantOutcome, r.PrimarySignature)
		}
		if r.MaxDepth != depth {
			t.Errorf("depth %d: max depth = %d", depth, r.MaxDepth)
		}
		// Benign twin wrapped the same way must not reveal an executable.
		b := compose(benign, layers...)
		rb := New().Peel(context.Background(), b)
		if rb.Outcome == OutcomeRevealedExecutable {
			t.Errorf("depth %d: benign twin flagged as executable", depth)
		}
	}
}

func TestDepthCeilingExhausts(t *testing.T) {
	// A chain deeper than the depth cap never reaches the payload → peel-
	// exhausted, rendered first-class, never silent clean.
	layers := []string{"base64", "gzip", "base64", "gzip", "base64", "hex"}
	blob := compose(fakeELF, layers...)
	r := New(WithLimits(BudgetLimits{MaxDepth: 2})).Peel(context.Background(), blob)
	if r.Outcome != OutcomePeelExhausted {
		t.Fatalf("outcome = %s, want peel-exhausted", r.Outcome)
	}
	if !r.Exhausted || r.ExhaustReason == "" {
		t.Errorf("exhausted=%v reason=%q, want a latched reason", r.Exhausted, r.ExhaustReason)
	}
	if r.Score < 30 {
		t.Errorf("exhausted score = %d, want the >=30 floor", r.Score)
	}
}

func TestDecompressionBombCapped(t *testing.T) {
	// A gzip stream that decompresses far past the output budget must trip the
	// cap and never land in memory; the peel still terminates.
	big := bytes.Repeat([]byte{0}, 4<<20) // 4 MiB of zeros compresses tiny
	blob := encodeLayer("gzip", big)
	r := New(WithLimits(BudgetLimits{MaxOutputBytes: 64 << 10})).Peel(context.Background(), blob)
	if !r.Exhausted {
		t.Errorf("bomb did not trip the budget: %+v", r)
	}
	if r.OutputBytes > 64<<10 {
		t.Errorf("output bytes %d exceeded the cap", r.OutputBytes)
	}
	if r.Outcome == OutcomeRevealedExecutable {
		t.Errorf("bomb of zeros reported an executable")
	}
}

func TestBenignInputsClean(t *testing.T) {
	cases := map[string][]byte{
		"plain text":   []byte("A normal configuration file.\nkey = value\n"),
		"random bytes": bytes.Repeat([]byte{0x13, 0x37, 0xbe, 0xef}, 64),
		"short":        []byte("hi"),
		"png-ish":      append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{1, 2, 3}, 40)...),
	}
	for name, blob := range cases {
		r := New().Peel(context.Background(), blob)
		if r.Outcome == OutcomeRevealedExecutable || r.Outcome == OutcomeRevealedScript {
			t.Errorf("%s: false positive, outcome=%s sig=%q", name, r.Outcome, r.PrimarySignature)
		}
	}
}

func TestScriptTerminal(t *testing.T) {
	payload := append([]byte("#!/bin/sh\n"), bytes.Repeat([]byte("echo hi; "), 8)...)
	blob := compose(payload, "base64", "gzip")
	r := New().Peel(context.Background(), blob)
	if r.Outcome != OutcomeRevealedScript {
		t.Fatalf("outcome = %s, want revealed-script", r.Outcome)
	}
	if r.MaxDepth != 2 {
		t.Errorf("max depth = %d, want 2", r.MaxDepth)
	}
}

func TestPlainExecutableNotWrappedIsClean(t *testing.T) {
	// A bare executable at depth 0 is not the peeler's finding: it reveals no
	// *chain*. classify only records terminals at depth>0.
	r := New().Peel(context.Background(), fakeELF)
	if r.Outcome != OutcomeClean {
		t.Errorf("bare executable: outcome = %s, want clean (no chain)", r.Outcome)
	}
	if len(r.Chains) != 0 {
		t.Errorf("bare executable recorded %d chains", len(r.Chains))
	}
}

// ── CAS dedupe (white box, via fake unwrappers) ─────────────────────────────

type fakeUnwrapper struct {
	name string
	out  []byte
}

func (f fakeUnwrapper) Name() string         { return f.name }
func (f fakeUnwrapper) Detect(b []byte) bool { return bytes.Equal(b, []byte("ROOT")) }
func (f fakeUnwrapper) Unwrap(b []byte, _ int64) ([]byte, error) {
	return append([]byte(nil), f.out...), nil
}

func TestCASDedupeCollapsesIdenticalChildren(t *testing.T) {
	// Two different transforms produce the SAME child blob. CAS dedupe must
	// peel that child once, recording a single chain, not two.
	child := fakeELF
	p := New(WithUnwrappers([]Unwrapper{
		fakeUnwrapper{name: "A", out: child},
		fakeUnwrapper{name: "B", out: child},
	}))
	r := p.Peel(context.Background(), []byte("ROOT"))
	// Both transforms yield the same depth-1 child; CAS must peel it once, so a
	// single chain is recorded (not two). Outcome is Clean because it is only a
	// single layer deep — the point here is the dedupe, not the verdict.
	if len(r.Chains) != 1 {
		t.Errorf("dedupe failed: %d chains recorded, want 1 (%v)", len(r.Chains), r.Chains)
	}
}

func TestContextCancelStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := New().Peel(ctx, compose(fakeELF, "base64", "gzip"))
	// A pre-cancelled context trips the budget on the first node; the peel
	// terminates promptly rather than exploring.
	if !r.Exhausted {
		t.Errorf("cancelled context did not latch exhaustion: %+v", r)
	}
}

func TestNoProgressDoesNotLoop(t *testing.T) {
	// An unwrapper that returns its own input must not spawn an identical child
	// and loop; the walk terminates and the node budget is not blown.
	p := New(WithUnwrappers([]Unwrapper{noopUnwrapper{}}), WithLimits(BudgetLimits{MaxNodes: 50}))
	r := p.Peel(context.Background(), []byte("STAYSAMESTAYSAMESTAY"))
	if r.NodesVisited > 2 {
		t.Errorf("no-progress transform looped: %d nodes", r.NodesVisited)
	}
}

type noopUnwrapper struct{}

func (noopUnwrapper) Name() string                             { return "noop" }
func (noopUnwrapper) Detect(b []byte) bool                     { return true }
func (noopUnwrapper) Unwrap(b []byte, _ int64) ([]byte, error) { return b, nil }

func TestWallClockDeadline(t *testing.T) {
	// A tiny deadline trips before much work; the peel returns exhausted
	// quickly rather than running to the node ceiling.
	blob := compose(fakeELF, "base64", "gzip", "base64", "hex")
	r := New(WithLimits(BudgetLimits{MaxWallClock: time.Nanosecond})).Peel(context.Background(), blob)
	if !r.Exhausted {
		t.Errorf("nanosecond deadline did not trip: %+v", r)
	}
}

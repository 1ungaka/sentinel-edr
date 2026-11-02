package peeler

import "math"

// The estimator is the cheap pre-pass the plan calls for: before paying full
// peel cost at a node, profile the blob (Shannon entropy plus the cheap
// structural hints each unwrapper already exposes through Detect) and use that
// to *rank the frontier* — try the most-probable transform first, so under the
// per-node child cap the budget is spent on the branches most likely to peel.
//
// The estimator never drops a branch Detect accepts and never changes a
// verdict: it only reorders. That keeps the measured 0-FP envelope and the
// depth-sweep detections exactly as they were while making the walk spend its
// bounded frontier wisely. Routing "to specialized peelers" is expressed here
// as this ranking, not as separate pipelines.

// profile is the cheap read of a blob used to rank the frontier.
type profile struct {
	// entropy is Shannon entropy in bits/byte, 0..8. High entropy suggests a
	// compressed or encrypted layer; mid entropy with a constrained alphabet
	// suggests a text encoding; low entropy suggests plain text (unlikely to be
	// a chain layer at all).
	entropy float64
	// printableFraction is the share of bytes in the ASCII printable range. A
	// high fraction points at a text encoding (base64/base32/hex) over a binary
	// compression layer.
	printableFraction float64
}

// estimate profiles a blob. It is O(n) over a single pass and allocation-free.
func estimate(blob []byte) profile {
	if len(blob) == 0 {
		return profile{}
	}
	var counts [256]int
	printable := 0
	for _, b := range blob {
		counts[b]++
		if b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	return profile{
		entropy:           shannonEntropy(counts[:], len(blob)),
		printableFraction: float64(printable) / float64(len(blob)),
	}
}

// shannonEntropy returns the entropy in bits/byte for a precomputed histogram.
func shannonEntropy(counts []int, total int) float64 {
	if total == 0 {
		return 0
	}
	var h float64
	inv := 1.0 / float64(total)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	return h
}

// rankUnwrappers orders the unwrappers that Detect the blob by how likely each
// is to be the real next layer, best first. It returns only the detectors that
// matched, so the caller still honors the per-node child cap but fills it with
// the most-probable transforms. Order is stable for equal scores, so the
// registry order breaks ties deterministically.
func rankUnwrappers(blob []byte, us []Unwrapper, p profile) []Unwrapper {
	type scored struct {
		u     Unwrapper
		score int
		order int
	}
	var matched []scored
	for i, u := range us {
		if !u.Detect(blob) {
			continue
		}
		matched = append(matched, scored{u: u, score: likelihood(u.Name(), p), order: i})
	}
	// Insertion sort by (score desc, order asc): matched is tiny (<= registry
	// size), so this is cheaper than sort.Slice's reflection.
	for i := 1; i < len(matched); i++ {
		for j := i; j > 0; j-- {
			a, b := matched[j-1], matched[j]
			if b.score > a.score || (b.score == a.score && b.order < a.order) {
				matched[j-1], matched[j] = b, a
			} else {
				break
			}
		}
	}
	out := make([]Unwrapper, len(matched))
	for i, m := range matched {
		out[i] = m.u
	}
	return out
}

// likelihood scores how well a layer fits the blob profile. The magic-bearing
// compression layers (gzip/zlib/bzip2) are near-certain when they Detect, so
// they rank highest; a text encoding ranks by how text-like the blob is;
// headerless flate ranks last because its Detect is only a length check.
func likelihood(name string, p profile) int {
	switch name {
	case "gzip", "bzip2", "zlib":
		return 100 // magic matched: almost certainly this layer
	case "base64", "base32", "hex":
		// A text encoding is likely only when the blob really is text-like.
		if p.printableFraction > 0.95 {
			return 80
		}
		return 40
	case "flate":
		// Raw deflate has no header; try it only after everything else.
		return 10
	default:
		return 50
	}
}

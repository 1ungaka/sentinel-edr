package peeler

import (
	"bytes"
	"sort"
	"strings"
)

// Leaf is one decoded blob at the bottom of the tree: a payload the walk
// identified, or the last thing a chain decoded to. It is what the indicators
// that run over the file itself never saw. Data is a copy, cut to the caller's
// byte allowance.
type Leaf struct {
	// Signature is the path that led here, e.g. "base64>gzip".
	Signature string
	// Terminal is what the walk took the leaf for, or "" when it could not say.
	Terminal Outcome
	// Depth is the number of layers peeled to reach it.
	Depth int
	Data  []byte
	// Truncated reports that Data is the head of a longer leaf.
	Truncated bool
}

// maxLeaves bounds how many leaves one result carries, so a rescan costs a
// fixed number of passes whatever the shape of the tree.
const maxLeaves = 8

// leafRef points at a leaf while the walk runs. The copy is made once, at the end.
type leafRef struct {
	blob  []byte
	hash  [32]byte
	sig   string
	depth int
	term  Outcome
}

// before orders leaves: deepest first, an identified payload ahead of an
// unidentified one, then by path and content. It is a total order, so the leaves
// kept do not depend on which branch finished first.
func (a leafRef) before(b leafRef) bool {
	if a.depth != b.depth {
		return a.depth > b.depth
	}
	if (a.term != "") != (b.term != "") {
		return a.term != ""
	}
	if a.sig != b.sig {
		return a.sig < b.sig
	}
	return bytes.Compare(a.hash[:], b.hash[:]) < 0
}

func (st *peel) keepLeaf(blob []byte, hash [32]byte, path []string, depth int, term Outcome) {
	if st.p.leafBytes <= 0 || len(blob) == 0 {
		return
	}
	ref := leafRef{blob: blob, hash: hash, sig: strings.Join(path, ">"), depth: depth, term: term}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.leaves) == maxLeaves && !ref.before(st.leaves[maxLeaves-1]) {
		return
	}
	st.leaves = append(st.leaves, ref)
	sort.Slice(st.leaves, func(i, j int) bool { return st.leaves[i].before(st.leaves[j]) })
	if len(st.leaves) > maxLeaves {
		st.leaves = st.leaves[:maxLeaves]
	}
}

// finishLeaves copies the kept leaves out, sharing the byte allowance evenly.
func (st *peel) finishLeaves() []Leaf {
	st.mu.Lock()
	refs := st.leaves
	st.leaves = nil
	st.mu.Unlock()
	if len(refs) == 0 {
		return nil
	}
	share := st.p.leafBytes / len(refs)
	out := make([]Leaf, 0, len(refs))
	for _, r := range refs {
		n := min(len(r.blob), share)
		if n == 0 {
			continue
		}
		out = append(out, Leaf{
			Signature: r.sig, Terminal: r.term, Depth: r.depth,
			Data: append([]byte(nil), r.blob[:n]...), Truncated: n < len(r.blob),
		})
	}
	return out
}

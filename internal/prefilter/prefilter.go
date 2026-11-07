// Package prefilter skips regular expressions that cannot match, without running
// them.
//
// Go's regexp is linear but slow, and a detector that runs hundreds of expressions
// over a file spends nearly all its time proving that most of them don't match. Yet
// most expressions can only match text containing some literal: `\bsystem\s*\(`
// needs "system". So each expression is reduced to a necessary condition, a set of
// strings of which any match must contain at least one, and one pass of an automaton
// over the text finds which conditions hold. Only those expressions are run.
//
// The contract is that a skip is never wrong: if an expression matches a text, then
// May reports true for it. Reporting true for one that doesn't match costs only the
// run it would have had anyway. Everything here leans that way: any construct not
// understood contributes no condition, and an expression with no condition is always
// run, so what this can get wrong is speed and never a result.
//
// Three things make that contract less obvious than it looks, and each is handled
// deliberately. Case folding: (?i)s also matches U+017F and (?i)k also matches
// U+212A, which lowercasing does not turn into s and k, so the text is folded with
// exactly those two added. Non-ASCII literals: their folding is not tracked, so a
// literal is cut at any such rune and only its ASCII runs are used. Invalid UTF-8:
// the automaton works on bytes, and the ASCII needles it looks for can't be inside
// a multi-byte sequence, so invalid input can't hide one.
package prefilter

import (
	"regexp/syntax"
	"strings"
	"sync"
)

// minNeedle is the shortest string worth looking for. A single byte holds in almost
// every file, which costs automaton hits and saves nothing. Two letters often do
// too, but an alternation is only as selective as its worst branch, and `sh` in one
// branch would otherwise leave a whole expression with no condition at all.
const minNeedle = 2

// Set is the compiled condition of a list of expressions, in order. It is immutable
// once built, and safe for concurrent use.
type Set struct {
	count  int
	always []int // expressions with no condition

	class   [256]uint8
	classes int32
	next    []int32   // premultiplied; negative means the state has outputs
	out     [][]int32 // expressions that may match, by state
	bools   sync.Pool
}

// Hits says which expressions may match one text.
type Hits struct {
	set *Set
	may []bool
}

// May reports whether expression i can match the text. False is a proof that it
// can't. True says nothing.
func (h Hits) May(i int) bool { return h.may == nil || h.may[i] }

// MayAll reports whether every expression in [from, from+n) can match.
func (h Hits) MayAll(from, n int) bool {
	if h.may == nil {
		return true
	}
	for i := from; i < from+n; i++ {
		if !h.may[i] {
			return false
		}
	}
	return true
}

// Release returns the Hits to the Set. It must not be used afterwards.
func (h Hits) Release() {
	if h.may != nil {
		h.set.bools.Put(&h.may)
	}
}

// New builds the condition of each expression, which must be valid. An expression
// that can't be parsed gets no condition rather than a failure, because the caller
// has compiled it already and this is only an optimisation.
func New(exprs []string) *Set {
	s := &Set{count: len(exprs)}
	needles := map[string][]int32{}
	for i, expr := range exprs {
		cond := condition(expr)
		if cond == nil {
			s.always = append(s.always, i)
			continue
		}
		for _, n := range cond {
			needles[n] = append(needles[n], int32(i))
		}
	}
	s.build(needles)
	s.bools.New = func() any {
		b := make([]bool, s.count)
		return &b
	}
	return s
}

func condition(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	return dedupe(required(re.Simplify()))
}

func dedupe(c []string) []string {
	if len(c) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range c {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// required returns strings of which any match of re contains at least one, or nil
// when nothing is known. The default is nil: a construct missing here loses a skip.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if n := longestASCII(re.Rune); len(n) >= minNeedle {
			return []string{n}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
	case syntax.OpConcat:
		// Every part has to match, so any part's condition is the whole's, and the
		// best one to look for is the rarest.
		var best []string
		for _, sub := range re.Sub {
			if c := required(sub); c != nil && (best == nil || better(c, best)) {
				best = c
			}
		}
		return best
	case syntax.OpAlternate:
		// Any branch may be the one that matches, so all of them have to be covered.
		var all []string
		for _, sub := range re.Sub {
			c := required(sub)
			if c == nil {
				return nil
			}
			all = append(all, c...)
		}
		return all
	}
	return nil
}

// better prefers the condition whose shortest string is longest, then the smaller.
func better(a, b []string) bool {
	if la, lb := shortest(a), shortest(b); la != lb {
		return la > lb
	}
	return len(a) < len(b)
}

func shortest(c []string) int {
	n := len(c[0])
	for _, s := range c {
		n = min(n, len(s))
	}
	return n
}

// longestASCII returns the longest ASCII run of a literal, lowercased. Lowercasing
// is right whether or not the literal folds: the text is folded too, and a needle
// that was case sensitive only gets weaker, never wrong.
func longestASCII(lit []rune) string {
	var best, cur strings.Builder
	flush := func() {
		if cur.Len() > best.Len() {
			best.Reset()
			best.WriteString(cur.String())
		}
		cur.Reset()
	}
	for _, r := range lit {
		if r >= 0x80 {
			flush()
			continue
		}
		cur.WriteByte(lowerASCII(byte(r)))
	}
	flush()
	return best.String()
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// build makes an Aho-Corasick DFA over the needles, in one table: its size is states
// times the bytes that appear in a needle, so the rest of the alphabet costs nothing.
func (s *Set) build(needles map[string][]int32) {
	for n := range needles {
		for i := 0; i < len(n); i++ {
			s.class[n[i]] = 1
		}
	}
	s.classes = 1 // class 0 is every byte in no needle
	for b := range 256 {
		if s.class[b] != 0 {
			s.class[b] = uint8(s.classes)
			s.classes++
		}
	}
	for b := byte('A'); b <= 'Z'; b++ {
		s.class[b] = s.class[lowerASCII(b)]
	}

	// The trie.
	trie := [][]int32{make([]int32, s.classes)}
	outs := [][]int32{nil}
	for n, exprs := range needles {
		at := int32(0)
		for i := 0; i < len(n); i++ {
			c := s.class[n[i]]
			if trie[at][c] == 0 {
				trie = append(trie, make([]int32, s.classes))
				outs = append(outs, nil)
				trie[at][c] = int32(len(trie) - 1)
			}
			at = trie[at][c]
		}
		outs[at] = append(outs[at], exprs...)
	}

	// Failure links, breadth first, which turn the trie into a DFA.
	fail := make([]int32, len(trie))
	var queue []int32
	for c := int32(0); c < s.classes; c++ {
		if t := trie[0][c]; t != 0 {
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		outs[st] = append(outs[st], outs[fail[st]]...)
		for c := int32(0); c < s.classes; c++ {
			t := trie[st][c]
			if t == 0 {
				trie[st][c] = trie[fail[st]][c]
				continue
			}
			fail[t] = trie[fail[st]][c]
			queue = append(queue, t)
		}
	}

	// One flat table, with each entry a row offset, negated when that state has
	// outputs. State 0 has none, so an offset of 0 is never negative.
	s.next = make([]int32, int32(len(trie))*s.classes)
	s.out = make([][]int32, len(trie))
	for st, row := range trie {
		s.out[st] = dedupeInts(outs[st])
		for c, t := range row {
			v := t * s.classes
			if len(outs[t]) > 0 {
				v = -v
			}
			s.next[int32(st)*s.classes+int32(c)] = v
		}
	}
}

func dedupeInts(in []int32) []int32 {
	if len(in) < 2 {
		return in
	}
	seen := make(map[int32]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// fold turns the two runes that fold to ASCII but don't lowercase to it into their
// ASCII letters. See the package doc. Almost no text holds either, so this is two
// fast searches and a return.
func fold(text string) string {
	if strings.Contains(text, "ſ") {
		text = strings.ReplaceAll(text, "ſ", "s")
	}
	if strings.Contains(text, "K") {
		text = strings.ReplaceAll(text, "K", "k")
	}
	return text
}

// Scan finds which expressions may match text.
func (s *Set) Scan(text string) Hits {
	if disabled {
		return Hits{}
	}
	p := s.bools.Get().(*[]bool)
	may := *p
	clear(may)
	for _, i := range s.always {
		may[i] = true
	}
	text = fold(text)
	var (
		next  = s.next
		class = &s.class
		state int32
	)
	for i := 0; i < len(text); i++ {
		state = next[state+int32(class[text[i]])]
		if state < 0 {
			state = -state
			for _, e := range s.out[state/s.classes] {
				may[e] = true
			}
		}
	}
	return Hits{set: s, may: may}
}

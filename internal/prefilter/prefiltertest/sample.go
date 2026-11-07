// Package prefiltertest generates text that matches a regular expression, which is
// what it takes to test a filter on its one dangerous case: a real match. Real files
// only exercise the expressions that happen to fire on them.
package prefiltertest

import (
	"math/rand"
	"regexp/syntax"
	"strings"
	"unicode"
)

// Sample returns a string built to match expr. It is a best effort, because a word
// boundary or an anchor depends on what surrounds it, so the caller keeps only the
// samples the expression really matches.
func Sample(expr string, r *rand.Rand) string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return ""
	}
	var b strings.Builder
	walk(re.Simplify(), r, &b)
	return b.String()
}

func walk(re *syntax.Regexp, r *rand.Rand, b *strings.Builder) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				c = anyFold(c, r)
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		if len(re.Rune) >= 2 {
			i := r.Intn(len(re.Rune)/2) * 2
			lo, hi := re.Rune[i], re.Rune[i+1]
			b.WriteRune(lo + rune(r.Int63n(int64(min(hi-lo, 90))+1)))
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte('x')
	case syntax.OpCapture:
		walk(re.Sub[0], r, b)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			walk(s, r, b)
		}
	case syntax.OpAlternate:
		walk(re.Sub[r.Intn(len(re.Sub))], r, b)
	case syntax.OpStar:
		for range r.Intn(3) {
			walk(re.Sub[0], r, b)
		}
	case syntax.OpPlus:
		for range 1 + r.Intn(2) {
			walk(re.Sub[0], r, b)
		}
	case syntax.OpQuest:
		if r.Intn(2) == 0 {
			walk(re.Sub[0], r, b)
		}
	case syntax.OpRepeat:
		for range re.Min {
			walk(re.Sub[0], r, b)
		}
	}
}

// anyFold picks any rune in c's folding orbit, so the unusual ones get exercised:
// (?i)s must find U+017F, and (?i)k must find U+212A.
func anyFold(c rune, r *rand.Rand) rune {
	orbit := []rune{c}
	for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
		orbit = append(orbit, f)
	}
	return orbit[r.Intn(len(orbit))]
}

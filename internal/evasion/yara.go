package evasion

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/1ungaka/sentinel-edr/scanner"
)

// This file reads a YARA rule's condition back and works out how many of the
// rule's matches have to break for the rule to stop firing.
//
// The rule fired, so its condition is true. Breaking the rule means making
// the condition false, and the cheapest way to do that depends on the shape of
// the condition: in `a and b` one side is enough to break, in `a or b` both
// have to go, and in `not a` the string has to appear instead of disappear.
//
// Every number this file produces is a lower bound on the bytes that must
// change. A string that matched may match elsewhere too, so breaking the one
// match that was reported is the cheapest known way out, not a guarantee.

// RuleSource is what the analysis needs to know about one rule: its
// condition, and the shape of the strings it matches on.
type RuleSource struct {
	// Condition is the rule's condition expression.
	Condition string
	// Strings maps a string identifier (without the '$') to its shape.
	Strings map[string]StringSpec
}

// StringSpec describes one string definition well enough to cost an edit.
type StringSpec struct {
	// LiteralLen is the length in bytes of a literal string. It is 0 when the
	// string is a regular expression or a hex blob, where the length of a
	// match is not fixed.
	LiteralLen int
	// Regex marks a regular-expression string: changing one byte of a match
	// may leave the expression matching, so a break costs more than a byte.
	Regex bool
}

// yaraDetector measures one matched rule.
func yaraDetector(m scanner.YaraMatch, sources map[string]RuleSource) (Detector, bool) {
	d := Detector{
		Name:   "yara",
		Class:  m.RuleName,
		Detail: fmt.Sprintf("rule %s matched on %d string(s)", m.RuleName, len(m.Strings)),
	}
	if t, ok := m.Meta("mitre_attack"); ok {
		d.Technique = t.String()
	} else if t, ok := m.Meta("technique"); ok {
		d.Technique = t.String()
	} else if t, ok := m.Meta("attack"); ok {
		d.Technique = t.String()
	}

	src, haveSrc := sources[m.RuleName]
	if !haveSrc || strings.TrimSpace(src.Condition) == "" {
		d.Edit = "the rule's condition is not available, so the cost of breaking it cannot be derived"
		return d, true
	}

	cost, ok := breakCost(src.Condition, src.Strings, m)
	if !ok {
		d.Edit = "the condition reads something this analysis cannot cost, so the distance is not derivable"
		return d, true
	}
	d.Derivable = true
	d.Distance = cost
	d.Edit = fmt.Sprintf("breaking the rule needs at least %d byte(s) changed", cost)
	return d, true
}

// ── the condition model ──────────────────────────────────────────────────────

// truth is what the analysis knows about one sub-expression: whether it is
// true, and what it costs to make it true or false.
type truth struct {
	known bool
	value bool
	// breakCost is the bytes that must change to make it false, -1 when
	// that cannot be derived.
	breakCost int
	// keepCost is the bytes that must change to make it true, -1 when that
	// cannot be derived.
	keepCost int
}

func unknownTruth() truth { return truth{breakCost: -1, keepCost: -1} }

// breakCost works out the bytes that must change for the rule to stop firing.
// It returns false when the condition cannot be costed.
func breakCost(condition string, strings map[string]StringSpec, m scanner.YaraMatch) (int, bool) {
	node, err := parseCondition(condition)
	if err != nil {
		return 0, false
	}
	t := value(node, strings, matchedIDs(m))
	if !t.known {
		return 0, false
	}
	if t.breakCost < 0 {
		return 0, false
	}
	return t.breakCost, true
}

// ofThem costs the "any of them", "all of them" and "N of them" forms.
//
// "them" is every string the rule defines. The analysis knows how many of
// them matched and how many the rule declares, so it knows whether the term
// is true and how many matches have to break for it to go false.
func ofThem(n *node, specs map[string]StringSpec, matched map[string]bool) truth {
	m := len(matched)
	declared := len(specs)
	if n.set != nil {
		// A string set: only the identifiers it names count, and a wildcard
		// stands for every identifier with that prefix.
		m = 0
		for id := range matched {
			if inSet(id, n.set) {
				m++
			}
		}
		declared = 0
		for _, want := range n.set {
			if strings.HasSuffix(want, "*") {
				prefix := strings.TrimSuffix(want, "*")
				for id := range specs {
					if strings.HasPrefix(id, prefix) {
						declared++
					}
				}
				continue
			}
			declared++
		}
	}
	switch n.op {
	case "of_any":
		// True when at least one matched; breaking it means breaking all of
		// them, one byte each.
		if m == 0 {
			return truth{known: true, value: false, breakCost: 0, keepCost: -1}
		}
		return truth{known: true, value: true, breakCost: m, keepCost: 0}
	case "of_all":
		// True only when every declared string matched. When the rule
		// declares strings the analysis does not know about, the term cannot
		// be settled.
		if declared == 0 || m < declared {
			return truth{known: true, value: false, breakCost: 0, keepCost: -1}
		}
		return truth{known: true, value: true, breakCost: m, keepCost: 0}
	case "of_n":
		// "N of them": true when at least N matched. Breaking it means
		// dropping the count to N-1.
		if m < int(n.num) {
			return truth{known: true, value: false, breakCost: 0, keepCost: -1}
		}
		return truth{known: true, value: true, breakCost: m - int(n.num) + 1, keepCost: 0}
	}
	return unknownTruth()
}

// inSet reports whether a string identifier belongs to a string set. A
// trailing '*' makes the entry a wildcard.
func inSet(id string, set []string) bool {
	for _, want := range set {
		if strings.HasSuffix(want, "*") {
			if strings.HasPrefix(id, strings.TrimSuffix(want, "*")) {
				return true
			}
			continue
		}
		if id == want {
			return true
		}
	}
	return false
}

// isNumber reports whether a token is a plain number.
func isNumber(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	return true
}

// parseInt reads a plain number.
func parseInt(t string) (int64, error) {
	return strconv.ParseInt(t, 10, 64)
}

// matchedIDs is the set of string identifiers the rule reported as matched.
func matchedIDs(m scanner.YaraMatch) map[string]bool {
	out := map[string]bool{}
	for _, s := range m.Strings {
		out[strings.TrimPrefix(s.Name, "$")] = true
	}
	return out
}

// value costs one node.
func value(n *node, specs map[string]StringSpec, matched map[string]bool) truth {
	switch n.op {
	case "and":
		l, r := value(n.left, specs, matched), value(n.right, specs, matched)
		if !l.known || !r.known {
			return unknownTruth()
		}
		return truth{
			known:     true,
			value:     l.value && r.value,
			breakCost: min(l.breakCost, r.breakCost),
			keepCost:  sumCosts(l.keepCost, r.keepCost),
		}
	case "or":
		l, r := value(n.left, specs, matched), value(n.right, specs, matched)
		if !l.known || !r.known {
			return unknownTruth()
		}
		return truth{
			known: true,
			value: l.value || r.value,
			// Every side that is true has to be broken for the whole to be
			// false; a side that is already false costs nothing.
			breakCost: sumCosts(l.breakCost, r.breakCost),
			keepCost:  min(l.keepCost, r.keepCost),
		}
	case "not":
		i := value(n.inner, specs, matched)
		if !i.known {
			return unknownTruth()
		}
		return truth{known: true, value: !i.value, breakCost: i.keepCost, keepCost: i.breakCost}
	case "string":
		id := n.term
		spec, haveSpec := specs[id]
		if matched[id] {
			breakCost := 1
			if haveSpec && spec.Regex {
				// A regular expression may still match the edited bytes, so
				// one byte is a lower bound and nothing more can be said.
				breakCost = 1
			}
			return truth{known: true, value: true, breakCost: breakCost, keepCost: 0}
		}
		keep := -1
		if haveSpec && spec.LiteralLen > 0 {
			// The string is absent; making it appear costs writing it.
			keep = spec.LiteralLen
		}
		return truth{known: true, value: false, breakCost: 0, keepCost: keep}
	case "count":
		// "#a > n": the count of matches is at least one when the string is
		// reported, and the rule fired, so the term is true. Breaking it
		// means dropping the count to n or below: with one known match, that
		// is one byte when n is zero, and nothing at all when the term may
		// already be false.
		if !matched[n.term] {
			return truth{known: true, value: false, breakCost: 0, keepCost: -1}
		}
		if n.num <= 0 {
			return truth{known: true, value: true, breakCost: 1, keepCost: 0}
		}
		return truth{known: true, value: true, breakCost: 0, keepCost: 0}
	case "filesize":
		// The size is a property of the file, and the analysis knows it.
		return truth{known: false, value: false, breakCost: -1, keepCost: -1}
	case "of_any", "of_all", "of_n":
		return ofThem(n, specs, matched)
	default:
		// "any of them", "all of them", "N of them" and everything this
		// parser does not model.
		return unknownTruth()
	}
}

func sumCosts(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return a + b
}

func min(a, b int) int {
	if a < 0 {
		return b
	}
	if b < 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// ── the condition parser ─────────────────────────────────────────────────────

// node is one sub-expression of a condition.
type node struct {
	op   string // "and", "or", "not", "string", "count", "filesize", "of_any", "of_all", "of_n", "other"
	term string // the string identifier, for "string" and "count"
	num  int64  // the number, for "count" and "of_n"
	// set is the identifier list of a string set ("2 of ($a, $b*)"), with a
	// trailing '*' marking a wildcard.
	set   []string
	left  *node
	right *node
	inner *node
}

// parseCondition parses the restricted grammar the analysis can cost:
//
//	expr    := or
//	or      := and ( 'or' and )*
//	and     := unary ( 'and' unary )*
//	unary   := 'not' unary | primary
//	primary := '(' expr ')' | term
//	term    := '$' id ['*'] | '#' id '>' n | 'filesize' op n
//	         | 'any'|'all'|n 'of' 'them' | 'them' | 'true' | 'false' | other
//
// Anything else parses as an opaque term, which the analysis reports as not
// derivable rather than guessing at.
func parseCondition(cond string) (*node, error) {
	toks := tokenize(cond)
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("trailing tokens in condition")
	}
	return n, nil
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	if t != "" {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (*node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &node{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (*node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &node{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (*node, error) {
	if p.peek() == "not" {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &node{op: "not", inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (*node, error) {
	t := p.peek()
	switch {
	case t == "(":
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("unbalanced parenthesis")
		}
		return inner, nil
	case strings.HasPrefix(t, "$"):
		p.next()
		id := strings.TrimPrefix(t, "$")
		if p.peek() == "*" {
			p.next()
		}
		return &node{op: "string", term: id}, nil
	case strings.HasPrefix(t, "#"):
		p.next()
		id := strings.TrimPrefix(t, "#")
		op := p.next()
		numTok := p.next()
		num, err := strconv.ParseInt(numTok, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad count term")
		}
		_ = op
		return &node{op: "count", term: id, num: num}, nil
	case t == "filesize":
		p.next()
		p.next() // the comparison operator
		p.next() // the number
		return &node{op: "filesize"}, nil
	case t == "any" || t == "all":
		kind := t
		p.next()
		if p.peek() == "of" {
			p.next()
		}
		set := p.parseSet()
		if p.peek() == "them" {
			p.next()
		}
		return &node{op: "of_" + kind, set: set}, nil
	case t == "them":
		p.next()
		return &node{op: "of_all"}, nil
	case t == "true" || t == "false":
		p.next()
		return &node{op: "other"}, nil
	case isNumber(t):
		p.next()
		num, _ := parseInt(t)
		if p.peek() == "of" {
			p.next()
		}
		set := p.parseSet()
		if p.peek() == "them" {
			p.next()
		}
		return &node{op: "of_n", num: num, set: set}, nil
	default:
		// An opaque term: consume it whole, up to the next boolean operator
		// or the end of the expression.
		for {
			t := p.peek()
			if t == "" || t == "and" || t == "or" || t == ")" {
				break
			}
			p.next()
		}
		if p.pos == 0 {
			return nil, fmt.Errorf("empty condition")
		}
		return &node{op: "other"}, nil
	}
}

// parseSet reads a string set: "($a, $b*)". It returns nil when the next
// token is not an open parenthesis.
func (p *parser) parseSet() []string {
	if p.peek() != "(" {
		return nil
	}
	p.next()
	var set []string
	for {
		t := p.next()
		if t == "" || t == ")" {
			return set
		}
		if strings.HasPrefix(t, "$") {
			set = append(set, strings.TrimPrefix(t, "$"))
		}
	}
}

// tokenize splits a condition into the tokens the parser reads.
func tokenize(cond string) []string {
	var out []string
	for _, f := range strings.Fields(cond) {
		// Keep "(", ")" and comparison operators as their own tokens.
		f = strings.ReplaceAll(f, "(", " ( ")
		f = strings.ReplaceAll(f, ")", " ) ")
		f = strings.ReplaceAll(f, "<=", " <= ")
		f = strings.ReplaceAll(f, ">=", " >= ")
		f = strings.ReplaceAll(f, "==", " == ")
		f = strings.ReplaceAll(f, "!=", " != ")
		out = append(out, strings.Fields(f)...)
	}
	return out
}

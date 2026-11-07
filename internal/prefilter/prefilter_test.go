package prefilter

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/s-b-repo/cau/internal/prefilter/prefiltertest"
)

// The expressions here are chosen to break the extraction, not to look realistic.
var hostile = []string{
	`(?i)system`, `(?i)\bsys\s*tem\b`, `(?i)curl[^\n]{0,40}\|\s*sh`, `SYSVOL`, `(?i)ask`, `(?i)kstack`, `(?i)ſystem`,
	`foo|bar`, `(?:foo|bar)baz`, `(?i)(?:abc|abd)ef`, `abc?def`, `a*bcd`, `(?:abcd)?efgh`, `(?:abcd)*`, `(?:abcd)+`, `(?:abcd){2,3}`, `(?:abcd){0,3}xyz`,
	`\$_(?:GET|POST)`, `/dev/tcp/`, `^#!/bin/sh`, `(?m)^export\s+\w+=`, `(?s)begin.*end`, `(?i)café.?latte`, `日本語abc`, `(?i)Straße`,
	`[Ss]ystem`, `\x00\x01abc`, `(?i)\x{017f}ys`, `(?i)\x{212a}ernel`, `(foo)(bar)?`, `x{3}`, `(?U)aaa+bbb`, `\bword\b`, `(?i)^\s*alias\s+\w+=`, ``, `.*`, `a`,
}

// Every rune folding to ASCII has to be one fold knows about, or the package doc's
// claim about case is wrong.
func TestOnlyTheKnownRunesFoldToASCII(t *testing.T) {
	for c := rune(0x80); c <= unicode.MaxRune; c++ {
		for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
			if f < 0x80 && c != 0x17f && c != 0x212a {
				t.Fatalf("%U folds to ASCII %q", c, f)
			}
		}
	}
}

// The one rule: a text an expression matches must never be skipped.
func checkSound(t *testing.T, exprs []string, text string) {
	t.Helper()
	s := New(exprs)
	h := s.Scan(text)
	defer h.Release()
	for i, e := range exprs {
		if regexp.MustCompile(e).MatchString(text) && !h.May(i) {
			t.Fatalf("skipped a real match: %q on %q", e, text)
		}
	}
}

func TestGeneratedMatchesAreNeverSkipped(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	s := New(hostile)
	matched := 0
	for i, e := range hostile {
		re := regexp.MustCompile(e)
		for range 3000 {
			text := "prefix " + prefiltertest.Sample(e, r) + " suffix"
			if !re.MatchString(text) {
				continue
			}
			matched++
			h := s.Scan(text)
			if !h.May(i) {
				t.Fatalf("skipped a real match: %q on %q", e, text)
			}
			h.Release()
		}
	}
	if matched < 10000 {
		t.Fatalf("only %d real matches: the generator is not testing anything", matched)
	}
}

func TestCaseFoldingEdges(t *testing.T) {
	for _, text := range []string{"ſystem", "SYſTEM", "Kstack", "aſK", "SYSTEM", "SyStEm", "Kstack"} {
		checkSound(t, hostile, text)
	}
}

func TestInvalidUTF8CannotHideAMatch(t *testing.T) {
	for _, text := range []string{"\xff\xfesystem\xff", "\xc5system", "sys\xc5\xbftem", "\xe2\x84system", "/dev/tcp/\xff"} {
		checkSound(t, hostile, text)
	}
}

func TestOverlappingAndNestedNeedles(t *testing.T) {
	exprs := []string{`abcdef`, `bcd`, `cde`, `abc`, `def`, `xabcdefy`}
	s := New(exprs)
	h := s.Scan("__abcdef__")
	defer h.Release()
	for i := range 5 {
		if !h.May(i) {
			t.Fatalf("%q contains %q", "abcdef", exprs[i])
		}
	}
	if h.May(5) {
		t.Fatal("the condition must also be able to say no")
	}
}

// A filter that always says yes passes every test above. This is what it's for.
func TestItActuallySkips(t *testing.T) {
	exprs := []string{`(?i)needle`, `(?:foo|bar)baz`, `/dev/tcp/`}
	s := New(exprs)
	h := s.Scan(strings.Repeat("nothing of interest in this text at all\n", 100))
	defer h.Release()
	for i := range exprs {
		if h.May(i) {
			t.Fatalf("%q can't match this", exprs[i])
		}
	}
}

func TestNoConditionMeansAlwaysRun(t *testing.T) {
	exprs := []string{`.*`, `a`, ``, `[0-9]+`, `(?:abcd)*`, `\ba\b`}
	s := New(exprs)
	h := s.Scan("zzz")
	defer h.Release()
	for i := range exprs {
		if !h.May(i) {
			t.Fatalf("%q has no condition, so it must run", exprs[i])
		}
	}
}

func TestReusedHitsAreClean(t *testing.T) {
	s := New([]string{`alpha`, `bravo`})
	h := s.Scan("alpha")
	h.Release()
	h = s.Scan("bravo")
	defer h.Release()
	if h.May(0) || !h.May(1) {
		t.Fatal("a recycled result must not remember the last text")
	}
}

func TestConcurrentScans(t *testing.T) {
	s := New(hostile)
	done := make(chan bool)
	for range 8 {
		go func() {
			defer func() { done <- true }()
			for range 200 {
				s.Scan("a system of /dev/tcp/ foobaz").Release()
			}
		}()
	}
	for range 8 {
		<-done
	}
}

func FuzzFilterNeverSkipsAMatch(f *testing.F) {
	for _, e := range hostile {
		f.Add(e, "the system of /dev/tcp/ and ſ and K")
	}
	f.Fuzz(func(t *testing.T, expr, text string) {
		re, err := regexp.Compile(expr)
		if err != nil || len(expr) > 200 || len(text) > 4096 {
			return
		}
		h := New([]string{expr}).Scan(text)
		defer h.Release()
		if re.MatchString(text) && !h.May(0) {
			t.Fatalf("skipped a real match: %q on %q", expr, text)
		}
	})
}

func BenchmarkScan(b *testing.B) {
	s := New(hostile)
	text := strings.Repeat("a line of ordinary shell text with nothing in it\n", 20000)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		s.Scan(text).Release()
	}
}

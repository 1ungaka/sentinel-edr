package tradecraft

import (
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/prefilter/prefiltertest"
)

// The rule the filter stands on, over the real detection table: text one of these
// expressions matches must never be skipped. Real files only reach the expressions
// that fire on them, so matches are generated for every one.
func TestEveryVectorSurvivesItsOwnMatches(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	f := scriptFilter()
	exprs, matched, never := 0, 0, 0
	for i, vec := range vectors {
		for j, re := range vec.all {
			exprs++
			got := 0
			for range 300 {
				text := "x " + prefiltertest.Sample(re.String(), r) + " y"
				if !re.MatchString(text) {
					continue
				}
				got++
				h := f.set.Scan(text)
				if !h.May(f.start[i] + j) {
					t.Fatalf("%s skipped a real match of %q on %q", vec.class, re, text)
				}
				h.Release()
			}
			matched += got
			if got == 0 {
				never++
			}
		}
	}
	// A generator that rarely produces a match would make this pass by testing nothing.
	if never*20 > exprs {
		t.Fatalf("no sample matched %d of %d expressions", never, exprs)
	}
	t.Logf("%d expressions, %d real matches, %d with no generated match", exprs, matched, never)
}

// Expressions compile on first use, so a bad one would otherwise only fail on the
// first file that reaches it, on somebody's host.
func TestEveryExpressionCompiles(t *testing.T) {
	for _, vec := range vectors {
		for _, re := range vec.all {
			if _, err := regexp.Compile(re.String()); err != nil {
				t.Errorf("%s: %v", vec.class, err)
			}
		}
		// An exception compiles lazily too, so a typo in one would otherwise
		// surface as a panic on the first file that reached it.
		if vec.except != nil {
			if _, err := regexp.Compile(vec.except.String()); err != nil {
				t.Errorf("%s exception: %v", vec.class, err)
			}
		}
	}
}

// The guards in front of the whole-file regexes make the same promise as the filter:
// text the regex matches must never be ruled out.
func TestCarrierGuardsSurviveTheirOwnMatches(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for name, c := range map[string]struct {
		re    *regexp.Regexp
		guard func(string) bool
	}{
		"hex":     {hexListRe, mayHoldHexList},
		"vb":      {vbHexRe, mayHoldVBHexList},
		"decimal": {decListRe, mayHoldDecimalList},
		"base64":  {base64Re, mayHoldBase64},
	} {
		matched := 0
		for range 2000 {
			text := "before " + prefiltertest.Sample(c.re.String(), r) + " after"
			if !c.re.MatchString(text) {
				continue
			}
			matched++
			if !c.guard(text) {
				t.Fatalf("%s ruled out a real match: %q", name, text)
			}
		}
		if matched < 200 {
			t.Fatalf("%s: only %d real matches, so this tests nothing", name, matched)
		}
	}
}

// The boundary cases, where an off-by-one in a guard would lose a real list.
func TestCarrierGuardsAtTheThreshold(t *testing.T) {
	hex := strings.Repeat("0x41,", 32) + "0x41"
	dec := strings.Repeat("65, ", 32) + "65"
	if !hexListRe.MatchString(hex) || !mayHoldHexList(hex) {
		t.Fatal("the shortest hex list must pass")
	}
	if !decListRe.MatchString(dec) || !mayHoldDecimalList(dec) {
		t.Fatal("the shortest decimal list must pass")
	}
	if b := strings.Repeat("A", 128); !base64Re.MatchString(b) || !mayHoldBase64(b) {
		t.Fatal("the shortest base64 run must pass")
	}
	if mayHoldBase64(strings.Repeat("A", 127)) || mayHoldHexList("0x41, 0x42") || mayHoldDecimalList("1, 2, 3") {
		t.Fatal("a guard that always says yes saves nothing")
	}
}

var numberRe = regexp.MustCompile(`(?i)0x[0-9a-f]+|&h[0-9a-f]+|\d+`)

// eachNumber stands in for numberRe on the one path that can't afford it, so it has
// to find exactly what the expression finds, and parseNumbers what it always did.
func TestEachNumberFindsWhatTheExpressionFinds(t *testing.T) {
	check := func(s string) {
		t.Helper()
		var got []string
		eachNumber(s, func(tok string) bool {
			got = append(got, tok)
			return true
		})
		want := numberRe.FindAllString(s, -1)
		if len(got) != len(want) {
			t.Fatalf("%q: got %q, want %q", s, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q: got %q, want %q", s, got, want)
			}
		}
		if a, b := parseNumbers(s, 1<<30), referenceParse(s); string(a) != string(b) {
			t.Fatalf("%q: decoded %v, want %v", s, a, b)
		}
	}
	for _, s := range []string{"", "0", "0x", "0xg", "0x41", "0X41,0XFF", "&h41", "&H4f", "&h", "&hg", "&", "00x41", "0x0x41", "1,2,3", "12a", "a12", "0x41g", "256", "0x100", "0xFFFFF", "9&h1", "0&h1", "x0x1", "0x", "&", "0"} {
		check(s)
	}
	r := rand.New(rand.NewSource(1))
	const alphabet = "0123456789abcdefxXhH&, \n_g"
	for range 200000 {
		b := make([]byte, r.Intn(14))
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		check(string(b))
	}
}

// referenceParse is parseNumbers as the expression wrote it.
func referenceParse(list string) []byte {
	toks := numberRe.FindAllString(list, -1)
	out := make([]byte, 0, len(toks))
	for _, t := range toks {
		var v uint64
		var err error
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "0x"):
			v, err = strconv.ParseUint(lower[2:], 16, 16)
		case strings.HasPrefix(lower, "&h"):
			v, err = strconv.ParseUint(lower[2:], 16, 16)
		default:
			v, err = strconv.ParseUint(t, 10, 16)
		}
		if err != nil || v > 255 {
			return nil
		}
		out = append(out, byte(v))
	}
	return out
}

// Past the budget take refuses the result, so stopping early changes nothing.
func TestParseNumbersStopsAtItsLimit(t *testing.T) {
	list := strings.Repeat("0x41,", 1000)
	if got := parseNumbers(list, 100); got != nil {
		t.Fatalf("%d bytes past a 100 byte limit", len(got))
	}
	if got := parseNumbers(list, 2000); len(got) != 1000 {
		t.Fatalf("%d bytes", len(got))
	}
}

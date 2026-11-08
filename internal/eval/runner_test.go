package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeCorpus builds a manifest-backed corpus in a temp dir. Files whose name
// contains "mal" are labelled by family "fam", the rest clean.
func writeCorpus(t *testing.T, n int) *Manifest {
	t.Helper()
	dir := t.TempDir()
	var samples []Sample
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("clean_%02d.txt", i)
		label := LabelClean
		if i%3 == 0 {
			name = fmt.Sprintf("mal_%02d.bin", i)
			label = "fam"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat(name, 4)), 0o600); err != nil {
			t.Fatal(err)
		}
		samples = append(samples, Sample{ID: name, Path: name, Label: label})
	}
	m := &Manifest{SchemaVersion: SchemaVersion, Name: "t", Root: dir, Samples: samples, SourcePath: filepath.Join(dir, "manifest.json")}
	if err := m.Resolve(); err != nil {
		t.Fatal(err)
	}
	return m
}

// nameDetector flags files whose base name contains "mal"; it sleeps a random
// time so scheduling order is scrambled.
func nameDetector(name string, jitter bool) Detector {
	return DetectorFunc{DetectorName: name, Fn: func(path string) (Finding, error) {
		if jitter {
			time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
		}
		f := Finding{Path: path}
		if strings.Contains(filepath.Base(path), "mal") {
			f.Signals = []Signal{{Rule: name + "_rule"}}
		}
		return f, nil
	}}
}

func stripDurations(run *Run) {
	for i := range run.Samples {
		run.Samples[i].Duration = 0
	}
}

func TestRunnerDeterministic(t *testing.T) {
	m := writeCorpus(t, 30)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var runs []*Run
	for i := 0; i < 3; i++ {
		r := NewRunner([]Detector{nameDetector("a", true), nameDetector("b", true)},
			RunOptions{Concurrency: 8, Now: func() time.Time { return fixed }, Tool: "test"})
		run, err := r.Run(m)
		if err != nil {
			t.Fatal(err)
		}
		stripDurations(run)
		runs = append(runs, run)
	}
	for i := 1; i < len(runs); i++ {
		if !reflect.DeepEqual(runs[0], runs[i]) {
			a, _ := json.Marshal(runs[0])
			b, _ := json.Marshal(runs[i])
			t.Fatalf("run %d differs:\n%s\n%s", i, a, b)
		}
	}
	run := runs[0]
	if got := run.Info.Detectors; !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("detectors = %v", got)
	}
	for i, s := range run.Samples {
		if s.ID != m.Samples[i].ID {
			t.Fatalf("sample %d out of manifest order: %s", i, s.ID)
		}
		if !s.Scored || s.Size == 0 {
			t.Errorf("sample %s not scored/sized: %+v", s.ID, s)
		}
		want := strings.Contains(s.ID, "mal")
		if s.Detected != want {
			t.Errorf("sample %s detected=%v want %v", s.ID, s.Detected, want)
		}
		if want && !reflect.DeepEqual(s.Detectors, []string{"a", "b"}) {
			t.Errorf("sample %s detectors = %v", s.ID, s.Detectors)
		}
	}
	rep := NewReport(run)
	if rep.Totals != (Counts{TP: 10, TN: 20}) {
		t.Errorf("totals = %s", rep.Totals)
	}
	if rep.Info.Concurrency != 8 || rep.Info.Tool != "test" || rep.Info.OnError != string(OnErrorExclude) {
		t.Errorf("info = %+v", rep.Info)
	}
}

func TestRunnerOnErrorModes(t *testing.T) {
	m := writeCorpus(t, 6)
	// Remove one malicious and one benign file so stat fails.
	os.Remove(m.Samples[0].FullPath()) // mal_00
	os.Remove(m.Samples[1].FullPath()) // clean_01

	for _, tc := range []struct {
		mode    OnErrorMode
		want    Counts
		fails   bool
		errored int
	}{
		{OnErrorExclude, Counts{TP: 1, TN: 3}, false, 2},
		{OnErrorMiss, Counts{TP: 1, TN: 4, FN: 1}, false, 2},
		{OnErrorFail, Counts{}, true, 0},
	} {
		run, err := NewRunner([]Detector{nameDetector("a", false)}, RunOptions{Concurrency: 2, OnError: tc.mode}).Run(m)
		if tc.fails {
			if err == nil || !strings.Contains(err.Error(), "failed to scan") {
				t.Errorf("%s: err = %v, want scan failure", tc.mode, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		rep := NewReport(run)
		if rep.Totals != tc.want {
			t.Errorf("%s: totals = %s, want %s", tc.mode, rep.Totals, tc.want)
		}
		if len(rep.Errors) != tc.errored {
			t.Errorf("%s: errors = %+v", tc.mode, rep.Errors)
		}
		if tc.mode == OnErrorMiss {
			var miss int
			for _, e := range rep.Errors {
				if e.CountedAsMiss {
					miss++
				}
			}
			if miss != 1 {
				t.Errorf("miss mode: %d errors counted as miss, want 1", miss)
			}
		}
	}
}

func TestRunnerMaxFileSizeSkips(t *testing.T) {
	m := writeCorpus(t, 4)
	big := m.Samples[0].FullPath()
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	run, err := NewRunner([]Detector{nameDetector("a", false)}, RunOptions{MaxFileSize: 1000}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	rep := NewReport(run)
	if len(rep.Skipped) != 1 || rep.Skipped[0].Key != m.Samples[0].ID || !strings.Contains(rep.Skipped[0].Reason, "max file size") {
		t.Errorf("skipped = %+v", rep.Skipped)
	}
	if rep.Totals.Total() != 3 {
		t.Errorf("scored %d, want 3", rep.Totals.Total())
	}
}

func TestRunnerNotConfiguredAborts(t *testing.T) {
	m := writeCorpus(t, 3)
	bad := DetectorFunc{DetectorName: "empty", Fn: func(path string) (Finding, error) {
		return Finding{Path: path}, fmt.Errorf("%w: no signatures", ErrNotConfigured)
	}}
	_, err := NewRunner([]Detector{nameDetector("a", false), bad}, RunOptions{}).Run(m)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := NewRunner(nil, RunOptions{}).Run(m); err == nil {
		t.Error("runner with no detectors must fail")
	}
}

func TestRunnerProgress(t *testing.T) {
	m := writeCorpus(t, 5)
	var calls int
	var last int
	_, err := NewRunner([]Detector{nameDetector("a", false)}, RunOptions{Concurrency: 1, Progress: func(done, total int) {
		calls++
		last = done
		if total != 5 {
			t.Errorf("total = %d", total)
		}
	}}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 5 || last != 5 {
		t.Errorf("progress calls=%d last=%d", calls, last)
	}
}

func TestRunnerConcurrentProgressIsSerializedAndOrdered(t *testing.T) {
	m := writeCorpus(t, 40)
	var active atomic.Int32
	var mu sync.Mutex
	var updates []int
	_, err := NewRunner([]Detector{nameDetector("a", false)}, RunOptions{Concurrency: 8, Progress: func(done, total int) {
		if active.Add(1) != 1 {
			t.Error("progress callbacks overlap")
		}
		defer active.Add(-1)
		// Let other workers finish while this callback is still running.
		time.Sleep(time.Millisecond)
		mu.Lock()
		updates = append(updates, done)
		mu.Unlock()
		if total != len(m.Samples) {
			t.Errorf("total = %d, want %d", total, len(m.Samples))
		}
	}}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != len(m.Samples) {
		t.Fatalf("got %d callbacks for %d samples", len(updates), len(m.Samples))
	}
	for i, done := range updates {
		if done != i+1 {
			t.Fatalf("callback %d reported %d completed samples", i+1, done)
		}
	}
}

func TestRunnerDefaultConcurrencyRespectsCPUAllocation(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	run, err := NewRunner([]Detector{nameDetector("a", false)}, RunOptions{}).Run(writeCorpus(t, 3))
	if err != nil {
		t.Fatal(err)
	}
	if run.Info.Concurrency != 1 {
		t.Fatalf("concurrency = %d with GOMAXPROCS=1", run.Info.Concurrency)
	}
}

func TestRunnerDoesNotStartIdleWorkers(t *testing.T) {
	// Hold one sample in its detector while inspecting the worker population.
	// Requested concurrency belongs in the report, but a tiny corpus should
	// never allocate hundreds of goroutines that can only wait for shutdown.
	m := writeCorpus(t, 1)
	before := runtime.NumGoroutine()
	d := DetectorFunc{DetectorName: "bounded", Fn: func(path string) (Finding, error) {
		if added := runtime.NumGoroutine() - before; added > 16 {
			t.Errorf("started %d goroutines for one sample", added)
		}
		return Finding{Path: path}, nil
	}}
	run, err := NewRunner([]Detector{d}, RunOptions{Concurrency: 256}).Run(m)
	if err != nil {
		t.Fatal(err)
	}
	if run.Info.Concurrency != 256 || len(run.Samples) != 1 {
		t.Fatalf("requested concurrency and sample must survive: %+v", run)
	}
}

func TestParseOnErrorMode(t *testing.T) {
	if m, err := ParseOnErrorMode(""); err != nil || m != OnErrorExclude {
		t.Errorf("empty -> %v %v", m, err)
	}
	if _, err := ParseOnErrorMode("explode"); err == nil {
		t.Error("bogus mode accepted")
	}
}

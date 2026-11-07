package parallel

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoRunsEveryTaskAtOnce(t *testing.T) {
	// Each task waits for the others, so this only finishes if they overlap.
	const n = 8
	var arrived atomic.Int32
	all := make(chan struct{})
	task := func() {
		if arrived.Add(1) == n {
			close(all)
		}
		select {
		case <-all:
		case <-time.After(10 * time.Second):
			t.Error("tasks did not run at once")
		}
	}
	tasks := make([]func(), n)
	for i := range tasks {
		tasks[i] = task
	}
	Do(tasks...)
}

func TestForVisitsEveryIndexOnce(t *testing.T) {
	const n = 10000
	hits := make([]atomic.Int32, n)
	For(n, 7, func(i int) { hits[i].Add(1) })
	for i := range hits {
		if hits[i].Load() != 1 {
			t.Fatalf("index %d visited %d times", i, hits[i].Load())
		}
	}
}

func TestForEmpty(t *testing.T) {
	For(0, 0, func(int) { t.Error("nothing to do") })
	Do()
}

func TestForHonoursTheWorkerBound(t *testing.T) {
	var cur, peak atomic.Int32
	For(200, 3, func(int) {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		cur.Add(-1)
	})
	if p := peak.Load(); p > 3 {
		t.Fatalf("%d workers ran, bound was 3", p)
	}
}

// A panic on a worker must reach the caller's recover, or a daemon's panic
// barrier protects nothing, and the rest of the work must still happen.
func TestPanicReachesTheCallerAfterTheRestFinished(t *testing.T) {
	var done atomic.Int32
	defer func() {
		var p *Panic
		if err, ok := recover().(error); !ok || !errors.As(err, &p) || p.Value != "boom" || len(p.Stack) == 0 {
			t.Fatalf("the panic did not arrive intact: %v", p)
		}
		if done.Load() != 99 {
			t.Fatalf("%d of the other 99 ran", done.Load())
		}
	}()
	For(100, 4, func(i int) {
		if i == 50 {
			panic("boom")
		}
		done.Add(1)
	})
}

func TestDoCarriesAPanicToo(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("the panic was lost")
		}
	}()
	Do(func() {}, func() { panic("boom") })
}

func TestShareVisitsEveryIndexOnce(t *testing.T) {
	const n = 10000
	hits := make([]atomic.Int32, n)
	Share(n, func(i int) { hits[i].Add(1) })
	for i := range hits {
		if hits[i].Load() != 1 {
			t.Fatalf("index %d visited %d times", i, hits[i].Load())
		}
	}
}

// Nested Share must finish with no helpers left, which is what stops a For inside a
// For from multiplying: the inner one simply runs on the goroutine it was called on.
func TestShareNestsWithoutDeadlock(t *testing.T) {
	var total atomic.Int64
	Share(64, func(int) {
		Share(64, func(int) {
			Share(16, func(int) { total.Add(1) })
		})
	})
	if total.Load() != 64*64*16 {
		t.Fatalf("got %d", total.Load())
	}
}

func TestShareNeverExceedsTheCPUs(t *testing.T) {
	var cur, peak atomic.Int32
	Share(500, func(int) {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(100 * time.Microsecond)
		cur.Add(-1)
	})
	if p := int(peak.Load()); p > cap(spare)+1 {
		t.Fatalf("%d ran at once, %d helpers plus the caller is the limit", p, cap(spare))
	}
}

func TestSharePanicReachesTheCaller(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("the panic was lost")
		}
	}()
	Share(100, func(i int) {
		if i == 50 {
			panic("boom")
		}
	})
}

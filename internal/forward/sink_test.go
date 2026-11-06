package forward

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSender records what it was handed and can be made to fail or hang, which
// is how the properties that only matter on a bad day get tested at all.
type fakeSender struct {
	mu    sync.Mutex
	got   []map[string]any
	calls int

	fail    atomic.Int64 // number of leading calls that fail
	partial int          // deliver only this many per batch (0 = all)
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeSender) Send(ctx context.Context, events []map[string]any) (int, error) {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()

	if f.fail.Load() > 0 {
		f.fail.Add(-1)
		return 0, errors.New("manager unreachable")
	}
	if f.partial > 0 && f.partial < len(events) {
		f.mu.Lock()
		f.got = append(f.got, events[:f.partial]...)
		f.mu.Unlock()
		return f.partial, errors.New("partial delivery")
	}
	f.mu.Lock()
	f.got = append(f.got, events...)
	f.mu.Unlock()
	return len(events), nil
}

func (f *fakeSender) received() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.got...)
}

func (f *fakeSender) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func ev(i int) map[string]any { return map[string]any{"n": i} }

func fastOpts(queue, batch int) SinkOptions {
	return SinkOptions{
		Queue: queue, Batch: batch,
		Flush:   10 * time.Millisecond,
		Retries: 3,
		Backoff: time.Millisecond,
		Timeout: 2 * time.Second,
	}
}

func TestSinkDeliversWhatItIsGiven(t *testing.T) {
	f := &fakeSender{}
	s := NewSink(f, fastOpts(100, 10))
	s.Start()
	for i := range 25 {
		s.Offer(ev(i))
	}
	st := s.Close(2 * time.Second)

	if got := len(f.received()); got != 25 {
		t.Errorf("delivered %d events, want 25", got)
	}
	if st.Delivered != 25 {
		t.Errorf("Delivered = %d, want 25", st.Delivered)
	}
	if st.Dropped != 0 || st.Failed != 0 {
		t.Errorf("unexpected loss: %+v", st)
	}
	if st.Pending != 0 {
		t.Errorf("Pending = %d after close, want 0", st.Pending)
	}
}

// The property the daemon depends on: no detection path can be slowed by the
// network. With the sender wedged and the queue long overfull, Offer still
// returns promptly.
func TestSinkOfferNeverBlocksWhileSenderHangs(t *testing.T) {
	f := &fakeSender{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	s := NewSink(f, fastOpts(8, 4))
	s.Start()
	s.Offer(ev(-1))
	<-f.entered // the worker is now stuck inside Send

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := range 1000 {
			s.Offer(ev(i))
		}
		done <- time.Since(start)
	}()

	select {
	case d := <-done:
		if d > 2*time.Second {
			t.Errorf("1000 offers took %v with the sender hung; must not block", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Offer blocked while the sender was hung: detection would stall on the SIEM")
	}

	close(f.block)
	s.Close(time.Second)
}

// A full queue costs the oldest events, not memory and not the host.
func TestSinkDropsOldestWhenFull(t *testing.T) {
	f := &fakeSender{}
	// Not started: nothing drains, so the eviction is deterministic.
	s := NewSink(f, fastOpts(4, 4))
	for i := range 10 {
		s.Offer(ev(i))
	}
	st := s.Stats()
	if st.Pending != 4 {
		t.Fatalf("Pending = %d, want the queue bound of 4", st.Pending)
	}
	if st.Dropped != 6 {
		t.Errorf("Dropped = %d, want 6", st.Dropped)
	}
	if st.Offered != 10 {
		t.Errorf("Offered = %d, want 10", st.Offered)
	}

	// The survivors must be the newest, which is what an analyst needs next.
	s.Start()
	s.Close(2 * time.Second)
	got := f.received()
	if len(got) != 4 {
		t.Fatalf("delivered %d, want 4", len(got))
	}
	for i, e := range got {
		if want := 6 + i; e["n"] != want {
			t.Errorf("event %d = %v, want the newest (%d)", i, e["n"], want)
		}
	}
}

func TestSinkRetriesUntilTheManagerRecovers(t *testing.T) {
	f := &fakeSender{}
	f.fail.Store(2) // two failures, then success
	s := NewSink(f, fastOpts(100, 10))
	s.Start()
	s.Offer(ev(1))
	st := s.Close(2 * time.Second)

	if st.Delivered != 1 {
		t.Errorf("Delivered = %d, want the event to land after the retries", st.Delivered)
	}
	if st.Failed != 0 {
		t.Errorf("Failed = %d, want 0", st.Failed)
	}
	if f.callCount() < 1 {
		t.Error("the sender should have been called")
	}
}

// The point of having a queue: an outage longer than the retries must cost the
// queue's depth, not every event after the first few seconds. Nothing offered
// during the outage may be lost while the queue still has room for it.
func TestSinkBuffersThroughOutageAndDeliversOnRecovery(t *testing.T) {
	f := &fakeSender{}
	f.fail.Store(1 << 30) // down, and staying down
	o := fastOpts(100, 2)
	o.Retries = 2
	s := NewSink(f, o)
	s.Start()
	for i := range 6 {
		s.Offer(ev(i))
	}
	// Long enough that the retries are exhausted several times over.
	time.Sleep(300 * time.Millisecond)
	if st := s.Stats(); st.Failed != 0 || st.Dropped != 0 {
		t.Errorf("events were discarded during an outage the queue had room for: %+v", st)
	}

	f.fail.Store(0) // the manager comes back
	st := s.Close(5 * time.Second)

	if st.Delivered != 6 {
		t.Errorf("Delivered = %d, want all 6 buffered events to land", st.Delivered)
	}
	if st.Failed != 0 || st.Dropped != 0 {
		t.Errorf("nothing should be lost across a recovered outage: %+v", st)
	}
	seen := map[any]int{}
	for _, e := range f.received() {
		seen[e["n"]]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Errorf("event %v delivered %d times after the outage", n, c)
		}
	}
	if len(seen) != 6 {
		t.Errorf("got %d distinct events, want 6", len(seen))
	}
}

// A queue that fills during an outage still drops only its oldest, and keeps
// accounting for every event.
func TestSinkOutageOverflowDropsOldestAndCounts(t *testing.T) {
	f := &fakeSender{}
	f.fail.Store(1 << 30)
	o := fastOpts(8, 4)
	o.Retries = 1
	s := NewSink(f, o)
	s.Start()
	for i := range 200 {
		s.Offer(ev(i))
	}
	time.Sleep(200 * time.Millisecond)
	st := s.Stats()
	if st.Offered != 200 {
		t.Errorf("Offered = %d, want 200", st.Offered)
	}
	if st.Pending > 8 {
		t.Errorf("Pending = %d, want the queue bound of 8", st.Pending)
	}
	// Everything offered is either pending, delivered, dropped or failed.
	if total := st.Delivered + st.Dropped + st.Failed + int64(st.Pending); total != st.Offered {
		t.Errorf("accounting lost events: %d accounted for, %d offered (%+v)", total, st.Offered, st)
	}
	f.fail.Store(0)
	s.Close(2 * time.Second)
}

// A partial delivery must resend only the tail, or the SIEM gets duplicates of
// exactly the events it did receive.
func TestSinkPartialDeliveryDoesNotDuplicate(t *testing.T) {
	f := &fakeSender{partial: 2}
	s := NewSink(f, fastOpts(100, 5))
	s.Start()
	for i := range 5 {
		s.Offer(ev(i))
	}
	s.Close(2 * time.Second)

	seen := map[any]int{}
	for _, e := range f.received() {
		seen[e["n"]]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Errorf("event %v delivered %d times; a partial delivery must not be resent", n, c)
		}
	}
}

// Shutdown delivers what is queued rather than discarding the last incidents,
// which are the ones most likely to matter.
func TestSinkCloseFlushesQueue(t *testing.T) {
	f := &fakeSender{}
	s := NewSink(f, SinkOptions{Queue: 100, Batch: 10, Flush: time.Hour, Backoff: time.Millisecond, Timeout: time.Second})
	s.Start()
	for i := range 30 {
		s.Offer(ev(i))
	}
	// Flush is an hour away, so only Close can get these out.
	st := s.Close(2 * time.Second)
	if st.Delivered != 30 {
		t.Errorf("Delivered = %d, want all 30 flushed on close", st.Delivered)
	}
}

// A manager that never answers must not hold the daemon open past its grace.
func TestSinkCloseBoundedByGraceWhenSenderHangs(t *testing.T) {
	f := &fakeSender{block: make(chan struct{}), entered: make(chan struct{}, 1)}
	s := NewSink(f, fastOpts(100, 10))
	s.Start()
	s.Offer(ev(1))
	<-f.entered

	start := time.Now()
	s.Close(150 * time.Millisecond)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Close took %v with the sender hung; the grace period must bound it", d)
	}
	close(f.block)
}

// Offers after Close are counted, not delivered, and must not panic on a closed
// channel: a late incident from a shutting-down layer is normal.
func TestSinkOfferAfterCloseIsSafe(t *testing.T) {
	f := &fakeSender{}
	s := NewSink(f, fastOpts(10, 5))
	s.Start()
	s.Close(time.Second)
	s.Offer(ev(1))
	if st := s.Stats(); st.Dropped != 1 {
		t.Errorf("Dropped = %d, want the post-close offer counted", st.Dropped)
	}
}

func TestSinkCloseTwiceIsSafe(t *testing.T) {
	s := NewSink(&fakeSender{}, fastOpts(10, 5))
	s.Start()
	s.Close(time.Second)
	s.Close(time.Second) // must not panic on an already-closed channel
}

// An outage must not fill the log it is meant to relieve: Warn speaks on the way
// down and on the way back up, not once per failed batch.
func TestSinkWarnsOnStateChangeNotEveryFailure(t *testing.T) {
	var mu sync.Mutex
	var warns []string
	f := &fakeSender{}
	f.fail.Store(6)
	o := fastOpts(100, 1)
	o.Retries = 2
	o.Warn = func(format string, a ...interface{}) {
		mu.Lock()
		warns = append(warns, format)
		mu.Unlock()
	}
	s := NewSink(f, o)
	s.Start()
	for i := range 3 {
		s.Offer(ev(i))
		time.Sleep(30 * time.Millisecond)
	}
	f.fail.Store(0)
	s.Offer(ev(99))
	s.Close(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(warns) == 0 {
		t.Fatal("an outage should be reported at least once")
	}
	if len(warns) > 4 {
		t.Errorf("got %d warnings for one outage (%v); it should speak on state change", len(warns), warns)
	}
}

func TestSinkNilEventIsIgnored(t *testing.T) {
	s := NewSink(&fakeSender{}, fastOpts(10, 5))
	s.Offer(nil)
	if st := s.Stats(); st.Pending != 0 || st.Offered != 0 {
		t.Errorf("a nil event should be ignored, got %+v", st)
	}
}

func TestSinkDefaultsAreSane(t *testing.T) {
	s := NewSink(&fakeSender{}, SinkOptions{})
	if s.opt.Queue != DefaultQueue || s.opt.Batch != DefaultBatch || s.opt.Flush != DefaultFlush {
		t.Errorf("zero options should take the defaults, got %+v", s.opt)
	}
	if s.opt.Warn == nil {
		t.Error("Warn must be non-nil so the sink can report without a guard")
	}
}

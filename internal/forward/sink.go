package forward

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Sender delivers one batch of events and reports how many arrived. A partial
// delivery returns the count that landed together with the error, so the sink
// can account for what was lost without the transport having to be atomic.
type Sender interface {
	Send(ctx context.Context, events []map[string]any) (delivered int, err error)
}

// Defaults for a daemon that is started once and left running. The queue holds
// a few thousand events because that is minutes of a bad day and still bounded
// memory; the batch matches what a manager API accepts in one POST; the flush
// keeps a quiet host's single incident from waiting for a full batch.
const (
	DefaultQueue   = 4096
	DefaultBatch   = 100
	DefaultFlush   = 5 * time.Second
	DefaultRetries = 3
	DefaultBackoff = 2 * time.Second
	DefaultTimeout = 60 * time.Second
	// MaxBackoff caps the wait between retries, so a long outage settles into
	// one attempt a minute rather than drifting into hours.
	MaxBackoff = 60 * time.Second
)

// SinkOptions configures a Sink. A zero value in any field takes the default.
type SinkOptions struct {
	Queue   int
	Batch   int
	Flush   time.Duration
	Retries int
	Backoff time.Duration
	Timeout time.Duration
	// Warn reports delivery trouble. It is called on a state change, not per
	// failure: an unreachable SIEM must not fill the log it is meant to relieve.
	Warn func(string, ...interface{})
}

func (o SinkOptions) withDefaults() SinkOptions {
	if o.Queue <= 0 {
		o.Queue = DefaultQueue
	}
	if o.Batch <= 0 {
		o.Batch = DefaultBatch
	}
	if o.Flush <= 0 {
		o.Flush = DefaultFlush
	}
	if o.Retries <= 0 {
		o.Retries = DefaultRetries
	}
	if o.Backoff <= 0 {
		o.Backoff = DefaultBackoff
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Warn == nil {
		o.Warn = func(string, ...interface{}) {}
	}
	return o
}

// Stats is what the sink has done since it started. It is read while the sink is
// running, so every field is a counter that only grows.
type Stats struct {
	Offered   int64
	Delivered int64
	// Dropped is events evicted from a full queue: the SIEM was behind and a
	// newer incident needed the slot.
	Dropped int64
	// Failed is events the transport would not take after every retry.
	Failed int64
	// Pending is what is still queued right now.
	Pending int
}

// Sink forwards events on its own goroutine. Offer never blocks and never
// fails, so no detection path can be slowed or broken by the network: the cost
// of a SIEM that cannot keep up is paid in this queue, in events dropped and
// counted, never in detection latency.
type Sink struct {
	send Sender
	opt  SinkOptions

	mu     sync.Mutex
	buf    []map[string]any
	closed bool

	// wake is a one-slot signal: a full channel already means "there is work",
	// so a burst of offers costs one wakeup rather than one per event.
	wake chan struct{}
	done chan struct{}
	// hardStop cancels an in-flight send and its backoff on shutdown, so a
	// hung manager cannot hold the daemon open past its grace period.
	hardStop chan struct{}
	wg       sync.WaitGroup

	offered, delivered, dropped, failed atomic.Int64
	// down tracks whether the last batch failed, so Warn speaks on the way
	// down and on the way back up and stays quiet in between.
	down bool

	// cool is how long the next round waits before trying again, grown on each
	// failed round and reset on delivery. It is owned by the delivery
	// goroutine, which is the only thing that reads or writes it.
	cool time.Duration
}

// NewSink builds a sink around a Sender. Start must be called to begin
// delivering.
func NewSink(s Sender, o SinkOptions) *Sink {
	o = o.withDefaults()
	return &Sink{
		send:     s,
		opt:      o,
		buf:      make([]map[string]any, 0, min(o.Batch, o.Queue)),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		hardStop: make(chan struct{}),
	}
}

// Start runs the delivery goroutine.
func (s *Sink) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.loop()
	}()
}

// Offer queues one event. It never blocks. When the queue is full the oldest
// event is evicted to make room: the local report still holds every incident,
// and when a SIEM is behind the newest alerts are the ones worth the slot.
func (s *Sink) Offer(ev map[string]any) {
	if ev == nil {
		return
	}
	s.offered.Add(1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.dropped.Add(1)
		return
	}
	for len(s.buf) >= s.opt.Queue {
		s.buf = s.buf[1:]
		s.dropped.Add(1)
	}
	s.buf = append(s.buf, ev)
	s.mu.Unlock()
	s.signal()
}

func (s *Sink) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// take removes and returns up to Batch events.
func (s *Sink) take() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(len(s.buf), s.opt.Batch)
	if n == 0 {
		return nil
	}
	batch := make([]map[string]any, n)
	copy(batch, s.buf[:n])
	s.buf = s.buf[n:]
	return batch
}

func (s *Sink) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

// loop delivers until Close and then drains what is left.
func (s *Sink) loop() {
	t := time.NewTicker(s.opt.Flush)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			s.drain()
			return
		case <-t.C:
		case <-s.wake:
		}
		s.deliverReady()
	}
}

// deliverReady sends every batch waiting, so a burst is cleared in one wakeup
// instead of one batch per flush tick. It stops at the first round that fails,
// leaving the rest queued for the next one.
func (s *Sink) deliverReady() {
	for s.pending() > 0 {
		if !s.deliverRound() {
			return
		}
		select {
		case <-s.hardStop:
			return
		default:
		}
	}
}

// deliverRound sends one batch and reports whether it landed.
//
// A batch that does not land goes back to the front of the queue rather than
// being thrown away, which is the whole point of having a queue: an outage
// should cost the queue's depth, not every event after the first few seconds.
// The round then extends its cooldown, so a manager that is down is retried on
// a widening interval instead of continuously. Events are only ever lost by the
// bounded queue evicting its oldest, which is the one loss the caller asked for
// by choosing a queue size.
func (s *Sink) deliverRound() bool {
	if s.cool > 0 && !s.sleep(s.cool) {
		return false
	}
	batch := s.take()
	if len(batch) == 0 {
		return true
	}
	left, ok := s.deliver(batch)
	if ok {
		s.cool = 0
		return true
	}
	s.requeue(left)
	s.cool = min(max(s.cool*2, s.opt.Backoff), MaxBackoff)
	return false
}

// requeue puts an undelivered batch back at the front of the queue. If offers
// filled the queue while the batch was in flight, the events that no longer fit
// are the oldest ones, and they are dropped under the same policy Offer uses.
func (s *Sink) requeue(batch []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	room := s.opt.Queue - len(s.buf)
	if room <= 0 {
		s.dropped.Add(int64(len(batch)))
		return
	}
	if len(batch) > room {
		s.dropped.Add(int64(len(batch) - room))
		batch = batch[len(batch)-room:]
	}
	merged := make([]map[string]any, 0, len(batch)+len(s.buf))
	merged = append(merged, batch...)
	merged = append(merged, s.buf...)
	s.buf = merged
}

// drain makes a last effort to deliver what is queued at shutdown, retrying a
// failing manager until the grace period expires rather than giving up on the
// first error: the last incidents before a restart are the ones most likely to
// matter. The grace period is enforced by hardStop, which Close closes when it
// runs out; whatever is still queued then is counted as not delivered.
func (s *Sink) drain() {
	for {
		select {
		case <-s.hardStop:
			if n := s.pending(); n > 0 {
				s.failed.Add(int64(n))
				s.opt.Warn("[WARN] forward: %d events still queued at shutdown were not delivered", n)
			}
			return
		default:
		}
		if s.pending() == 0 {
			return
		}
		s.deliverRound()
	}
}

// deliver sends one batch, retrying a transient failure a few times with a
// short backoff. It reports whether the whole batch landed; what did not is
// left in batch for the caller to requeue.
//
// Retries here handle a blip. A real outage is handled by the caller putting
// the batch back on the queue and waiting out a widening cooldown, so nothing
// is discarded just because the manager was down for longer than a few seconds.
//
// The returned slice is what still has to be delivered. After a partial
// delivery that is the undelivered tail, never the whole batch, or requeueing
// would hand the manager duplicates of the events it did accept.
func (s *Sink) deliver(batch []map[string]any) ([]map[string]any, bool) {
	backoff := s.opt.Backoff
	for attempt := 0; attempt < s.opt.Retries; attempt++ {
		if attempt > 0 && !s.sleep(backoff) {
			return batch, false
		}
		if attempt > 0 {
			backoff = min(backoff*2, MaxBackoff)
		}
		ctx, cancel := s.sendContext()
		n, err := s.send.Send(ctx, batch)
		cancel()
		if n > 0 {
			s.delivered.Add(int64(n))
		}
		if err == nil {
			s.recovered()
			return nil, true
		}
		// A partial delivery must not resend what already landed, or the SIEM
		// gets duplicates of exactly the events it did receive.
		if n > 0 && n < len(batch) {
			batch = batch[n:]
		}
		s.failing(err)
	}
	return batch, false
}

// sendContext bounds one attempt and is cancelled by a hard stop.
func (s *Sink) sendContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opt.Timeout)
	stop := make(chan struct{})
	go func() {
		select {
		case <-s.hardStop:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() { close(stop); cancel() }
}

// sleep waits for d, or returns false if the sink is being torn down.
func (s *Sink) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-s.hardStop:
		return false
	}
}

func (s *Sink) failing(err error) {
	s.mu.Lock()
	first := !s.down
	s.down = true
	s.mu.Unlock()
	if first {
		s.opt.Warn("[WARN] forward: delivery failing, queueing locally (queue %d events, oldest dropped when full): %v", s.opt.Queue, err)
	}
}

func (s *Sink) recovered() {
	s.mu.Lock()
	was := s.down
	s.down = false
	s.mu.Unlock()
	if was {
		st := s.Stats()
		s.opt.Warn("[*] forward: delivery recovered (%d delivered, %d dropped, %d failed so far)", st.Delivered, st.Dropped, st.Failed)
	}
}

// Close stops accepting events and gives the sink grace to deliver what is
// queued before cancelling whatever is still in flight.
func (s *Sink) Close(grace time.Duration) Stats {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return s.Stats()
	}
	s.closed = true
	s.mu.Unlock()

	close(s.done)
	s.signal()

	if grace > 0 {
		timer := time.AfterFunc(grace, func() { close(s.hardStop) })
		drained := make(chan struct{})
		go func() { s.wg.Wait(); close(drained) }()
		<-drained
		// Stop fires the timer's func only if it had not run; either way
		// hardStop must end up closed so a second Close is safe.
		if timer.Stop() {
			close(s.hardStop)
		}
	} else {
		close(s.hardStop)
		s.wg.Wait()
	}
	return s.Stats()
}

// Stats reports what the sink has done.
func (s *Sink) Stats() Stats {
	return Stats{
		Offered:   s.offered.Load(),
		Delivered: s.delivered.Load(),
		Dropped:   s.dropped.Load(),
		Failed:    s.failed.Load(),
		Pending:   s.pending(),
	}
}

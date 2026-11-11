package collector

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/1ungaka/sentinel-edr/internal/report"
)

// Sender delivers OCSF Detection Finding maps to a collector in a sink
// format. Its Send has the method set of forward.Sender, so the defend
// daemon's queue (forward.Sink) can forward correlated incidents to anything
// `cau scan --sink-url` reaches: syslog, CEF, LEEF, GELF, ECS, an OpenSearch
// _bulk endpoint, an OTLP collector.
//
// It owns no format and no transport. The bytes are report.RenderSinkBatch's,
// which are the bytes `--format <fmt>` writes for the same finding, and they
// travel through this package's Client, with its TLS, authorization and
// framing decisions. (This file does not import the forward package, so that
// the collector builds on its own; a test asserts the interface is met.)
//
// What Send returns is shaped for a queue that retries. The count is the
// number of leading events of the batch that must not be offered again, and
// the error, when there is one, says the rest is worth resending. Three kinds
// of event are counted as done although nothing was delivered, because
// resending them could never succeed and would hold the queue's head forever:
//
//   - a map that is not a Detection Finding with a uid (Malformed);
//   - an event too large for one UDP datagram (Oversize);
//   - a document an OpenSearch/Elasticsearch index refused for good (Rejected).
//
// They are reported through Stats and, once per kind, through Warn. A queue
// that counts what Send returned as delivered therefore over-counts by their
// sum; Stats.Sent is the number that reached the transport.
//
// What is still retried as a whole: a request the collector answered with an
// HTTP error, whatever the status. A 401 is fixed by the operator and a 400
// may never be, and the two cannot be told apart safely from here, so both
// stay in the caller's queue, which is bounded.
//
// A Sender is safe for concurrent use, though a queue calls it from one
// goroutine. Each Send opens its own connection: there is no connection state
// to go stale between batches of a daemon that may be quiet for days.
type Sender struct {
	// Warn, when set, is told the first time each kind of undeliverable event
	// is seen. It has the signature of forward.SinkOptions.Warn. Set it before
	// the first Send.
	Warn func(format string, args ...interface{})

	client *Client
	render []report.Option

	sent, malformed, oversize, rejected atomic.Int64
	warned                              [3]atomic.Bool
}

// SenderStats is what a Sender has done since it was built.
type SenderStats struct {
	// Sent is the events handed to the transport: written to the socket, or
	// accepted by the collector with a 2xx.
	Sent int64
	// Malformed is the maps that were not a Detection Finding with a uid.
	Malformed int64
	// Oversize is the events larger than MaxDatagram on a udp:// destination.
	Oversize int64
	// Rejected is the documents a _bulk endpoint refused for good.
	Rejected int64
}

// NewSender builds a Sender from the same Options a one-shot Client takes
// (opts.Format picks the sink format; otlp needs an http(s) URL). The report
// options configure the rendering; the one that matters for a daemon is
// report.WithHostname, the reporting host of an event whose own
// unmapped.agent_host is empty (default: the machine's hostname).
func NewSender(opts Options, render ...report.Option) (*Sender, error) {
	c, err := New(opts)
	if err != nil {
		return nil, err
	}
	// The stream and datagram framings are one event per line; an indented
	// rendering is never what goes on the wire.
	render = append(append([]report.Option(nil), render...), report.WithIndent(false))
	if _, err := report.RenderSinkBatch(c.opts.Format, nil, render...); err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	return &Sender{client: c, render: render}, nil
}

// Client is the transport the Sender delivers through, for its Cleartext and
// Budget.
func (s *Sender) Client() *Client { return s.client }

// Stats reports what the Sender has done.
func (s *Sender) Stats() SenderStats {
	return SenderStats{
		Sent:      s.sent.Load(),
		Malformed: s.malformed.Load(),
		Oversize:  s.oversize.Load(),
		Rejected:  s.rejected.Load(),
	}
}

// The reasons an event of a batch is passed over.
const (
	eventLive = iota
	eventMalformed
	eventOversize
)

// Send renders the batch and delivers it. See Sender for what the returned
// count means. It returns as soon as ctx is done.
func (s *Sender) Send(ctx context.Context, events []map[string]any) (delivered int, err error) {
	if len(events) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c := s.client
	batch, err := report.RenderSinkBatch(c.opts.Format, events, s.render...)
	if err != nil {
		return 0, fmt.Errorf("collector: render %s: %w", c.opts.Format, err)
	}
	state := make([]uint8, len(events))
	for _, i := range batch.Skipped {
		if i >= 0 && i < len(state) {
			state[i] = eventMalformed
		}
	}
	// live[k] is the index in events of the k-th event still to be sent.
	live := make([]int, 0, batch.Rendered)
	for i, st := range state {
		if st == eventLive {
			live = append(live, i)
		}
	}
	wire, count := Events(c.opts.Format, batch.Payload)
	if count != len(live) || (c.opts.Format != "otlp" && len(wire) != len(live)) {
		// One event is one line (or one OTLP log record) by construction; if
		// that ever fails, positions in the payload mean nothing and nothing
		// may be reported as delivered.
		return 0, fmt.Errorf("collector: rendered %d events for %d findings", count, len(live))
	}
	if c.url.Scheme == "udp" {
		keptWire, keptLive := wire[:0], live[:0]
		for k, ev := range wire {
			if len(ev) > MaxDatagram {
				state[live[k]] = eventOversize
				continue
			}
			keptWire, keptLive = append(keptWire, ev), append(keptLive, live[k])
		}
		wire, live = keptWire, keptLive
	}

	// settled is the number of leading live events that need no resend.
	settled, rejected, detail := 0, 0, ""
	switch {
	case len(live) == 0:
		// Nothing deliverable: no connection is opened.
	case c.url.Scheme == "udp":
		settled, err = c.sendUDP(ctx, wire)
	case c.url.Scheme == "tcp" || c.url.Scheme == "tls":
		settled, err = c.sendStream(ctx, wire)
	case c.opts.BulkIndex != "":
		out := c.sendBulk(ctx, wire)
		settled, rejected, detail, err = out.settled, out.rejected, out.detail, out.err
	default:
		settled, err = c.sendHTTP(ctx, wire, len(live))
	}
	settled = max(0, min(settled, len(live)))
	if err == nil && settled < len(live) {
		err = errors.New("collector: the transport reported a short delivery without an error")
	}

	// Everything before the first event still to be sent is done with.
	delivered = len(events)
	if settled < len(live) {
		delivered = live[settled]
	}
	var malformed, oversize int
	for _, st := range state[:delivered] {
		switch st {
		case eventMalformed:
			malformed++
		case eventOversize:
			oversize++
		}
	}
	s.sent.Add(int64(settled - rejected))
	s.note(0, &s.malformed, malformed, "[WARN] collector: %d event(s) were not OCSF Detection Findings with a uid and were not forwarded (counted, not retried)", malformed)
	s.note(1, &s.oversize, oversize, "[WARN] collector: %d event(s) exceed the %d-byte datagram limit and were not forwarded; use tcp:// or tls:// (counted, not retried)", oversize, MaxDatagram)
	s.note(2, &s.rejected, rejected, "[WARN] collector: the bulk endpoint refused %d document(s) for good (%s); they were not indexed (counted, not retried)", rejected, detail)
	return delivered, err
}

// note counts n events of one kind and warns the first time the kind is seen.
func (s *Sender) note(kind int, counter *atomic.Int64, n int, format string, args ...interface{}) {
	if n == 0 {
		return
	}
	counter.Add(int64(n))
	if s.Warn != nil && s.warned[kind].CompareAndSwap(false, true) {
		s.Warn(format, args...)
	}
}

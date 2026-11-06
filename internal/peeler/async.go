package peeler

import "context"

// EventKind says what an Event reports.
type EventKind string

const (
	// EventLayer is one layer peeled. Path ends in it.
	EventLayer EventKind = "layer"
	// EventChain is a chain reaching a payload. Terminal says which kind.
	EventChain EventKind = "chain"
)

// Event is one step of a running peel, in the order branches reached it. Path is
// shared with the walk, so a consumer must not write to it.
type Event struct {
	Kind     EventKind `json:"kind"`
	Path     []string  `json:"path"`
	Depth    int       `json:"depth"`
	Terminal Outcome   `json:"terminal,omitempty"`
}

// Job is a peel running in the background. Events reports it as it happens and
// Wait returns the verdict; a caller can use either or both.
type Job struct {
	events chan Event
	done   chan struct{}
	result Result
}

// Start runs Peel in the background and returns at once. Reading Events is
// optional: the channel holds every event the budget allows, so an unread Job
// still finishes, and a slow reader never slows the peel down.
func (p *Peeler) Start(ctx context.Context, data []byte) *Job {
	nodes := NewBudget(p.limits).maxNodes
	j := &Job{
		// One layer and at most one chain per node visited.
		events: make(chan Event, 2*nodes+1),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(j.done)
		defer close(j.events)
		j.result = p.run(ctx, data, func(e Event) {
			select {
			case j.events <- e:
			default: // a tree past its node budget: the verdict still says so
			}
		})
	}()
	return j
}

// Events delivers the peel's steps and closes when it finishes.
func (j *Job) Events() <-chan Event { return j.events }

// Wait blocks until the peel finishes and returns its verdict. It can be called
// any number of times, from any goroutine.
func (j *Job) Wait() Result {
	<-j.done
	return j.result
}

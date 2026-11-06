package main

import (
	"hash/fnv"
	"sync"
	"time"
)

// wakeup asks a goroutine for one more pass. Any number of fires while it is busy
// collapse into that one, so a burst can neither pile up behind it nor be missed:
// a fire that lands mid-pass still gets a pass that starts after it.
type wakeup chan struct{}

func newWakeup() wakeup { return make(wakeup, 1) }

func (w wakeup) fire() {
	select {
	case w <- struct{}{}:
	default:
	}
}

// stripes locks by key, so unrelated keys rarely wait on each other and a lock
// never has to be created or cleaned up per path an attacker can invent.
type stripes [256]sync.Mutex

func (s *stripes) of(key string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &s[h.Sum32()%uint32(len(s))]
}

// fileQueue hands paths to the scan workers. It has two lanes, because a path
// that just changed and a path a sweep found are not equally urgent: a startup
// sweep of a large tree must not sit in front of the file an attacker dropped a
// second ago. Live paths always go first, and one worker takes nothing else.
//
// A path is in at most one place: queued, busy, or waiting for its recheck.
type fileQueue struct {
	mu   sync.Mutex
	work *sync.Cond // something to pop, or closing
	room *sync.Cond // the backlog has space, or closing

	live, backlog []string
	queued        map[string]bool // true once the path has a live entry
	busy          map[string]bool // being scanned, or cooling down after one
	again         map[string]bool // changed while busy

	limit   int
	recheck time.Duration
	closed  bool
	discard bool // closed for good: what is left is not worth scanning
}

func newFileQueue(limit int, recheck time.Duration) *fileQueue {
	q := &fileQueue{queued: map[string]bool{}, busy: map[string]bool{}, again: map[string]bool{}, limit: limit, recheck: recheck}
	q.work, q.room = sync.NewCond(&q.mu), sync.NewCond(&q.mu)
	return q
}

// push adds a path that just changed. It never blocks, because the watcher's
// reader calls it, and reports false when the lane is full: the event is lost and
// the caller has to sweep. A path already in the backlog is promoted.
func (q *fileQueue) push(p string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return true
	}
	if q.busy[p] {
		q.again[p] = true
		return true
	}
	if q.queued[p] {
		return true
	}
	if len(q.live) >= q.limit {
		return false
	}
	q.addLive(p)
	return true
}

// addLive also promotes: a path still in the backlog gets a live entry as well,
// and pop skips the old one once either has been taken.
func (q *fileQueue) addLive(p string) {
	q.queued[p] = true
	q.live = append(q.live, p)
	q.work.Broadcast()
}

// pushBacklog adds a path a sweep found, waiting for room: only a sweep calls it,
// on its own goroutine, and a sweep that drops paths has to start again. It
// reports false when the queue is closing.
func (q *fileQueue) pushBacklog(p string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.backlog) >= q.limit && !q.closed {
		q.room.Wait()
	}
	if q.closed {
		return false
	}
	if q.busy[p] {
		// A sweep runs because events were lost, so this path may have changed with
		// nothing left to say so.
		q.again[p] = true
		return true
	}
	if _, ok := q.queued[p]; ok {
		return true
	}
	q.queued[p] = false
	q.backlog = append(q.backlog, p)
	q.work.Broadcast()
	return true
}

// pop waits for a path. liveOnly is the reserved worker, which a sweep can never
// occupy with a run of large files. ok is false when the queue is finished.
func (q *fileQueue) pop(liveOnly bool) (path string, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.closed && q.discard {
			return "", false
		}
		for len(q.live) > 0 {
			p := q.live[0]
			q.live = q.live[1:]
			if q.take(p) {
				return p, true
			}
		}
		for !liveOnly && len(q.backlog) > 0 {
			p := q.backlog[0]
			q.backlog = q.backlog[1:]
			q.room.Broadcast()
			if q.take(p) {
				return p, true
			}
		}
		if q.closed {
			return "", false
		}
		q.work.Wait()
	}
}

func (q *fileQueue) take(p string) bool {
	if _, ok := q.queued[p]; !ok {
		return false // the other lane got it first
	}
	delete(q.queued, p)
	q.busy[p] = true
	return true
}

// done releases a path after its scan, once it has cooled down. Every scan is
// followed by a pause, not only one that a change landed during: pausing only then
// let a file rewritten just after each scan finished run back to back, so anyone
// who can write to /tmp could pin a CPU by timing the writes. A change during the
// pause is scanned when it ends, so it is late, never lost, and a file that changes
// once is scanned at once.
func (q *fileQueue) done(p string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		delete(q.busy, p) // again stays, for reopen
		return
	}
	time.AfterFunc(q.recheck, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		changed := q.again[p]
		delete(q.busy, p)
		delete(q.again, p)
		if changed && !q.closed {
			q.addLive(p)
		}
	})
}

// close ends the queue for good, dropping what is left.
func (q *fileQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed, q.discard = true, true
	q.work.Broadcast()
	q.room.Broadcast()
}

// finish lets the workers empty the queue and then stop. reopen undoes it, for
// the next synchronous pass.
func (q *fileQueue) finish() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.work.Broadcast()
	q.room.Broadcast()
}

// reopen runs with no worker alive, so nothing is really being scanned: a pass
// that ended must not leave the next one waiting on a cooldown, and a change that
// arrived during one is due now.
func (q *fileQueue) reopen() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = false
	again := q.again
	q.busy, q.again = map[string]bool{}, map[string]bool{}
	for p := range again {
		q.addLive(p)
	}
}

func (q *fileQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queued)
}

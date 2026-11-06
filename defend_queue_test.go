package main

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func popNow(t *testing.T, q *fileQueue, liveOnly bool) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		p, _ := q.pop(liveOnly)
		got <- p
	}()
	select {
	case p := <-got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("nothing to pop")
		return ""
	}
}

// The reason the queue has two lanes: a file dropped now goes ahead of everything
// a startup sweep found.
func TestLiveGoesAheadOfTheBacklog(t *testing.T) {
	q := newFileQueue(100, time.Millisecond)
	for i := range 10 {
		q.pushBacklog(fmt.Sprintf("/old/%d", i))
	}
	q.push("/tmp/dropped")
	if p := popNow(t, q, false); p != "/tmp/dropped" {
		t.Fatalf("popped %s", p)
	}
}

// A sweep of large files must not be able to occupy the last worker.
func TestReservedWorkerNeverTakesTheBacklog(t *testing.T) {
	q := newFileQueue(100, time.Millisecond)
	q.pushBacklog("/old")
	got := make(chan string, 1)
	go func() {
		p, _ := q.pop(true)
		got <- p
	}()
	select {
	case p := <-got:
		t.Fatalf("the reserved worker took %s", p)
	case <-time.After(50 * time.Millisecond):
	}
	q.push("/tmp/dropped")
	if p := <-got; p != "/tmp/dropped" {
		t.Fatalf("popped %s", p)
	}
}

func TestChangedBacklogPathIsPromotedAndScannedOnce(t *testing.T) {
	q := newFileQueue(100, time.Millisecond)
	q.pushBacklog("/a")
	q.pushBacklog("/b")
	q.push("/b")
	if p := popNow(t, q, false); p != "/b" {
		t.Fatalf("popped %s", p)
	}
	q.done("/b")
	if p := popNow(t, q, false); p != "/a" {
		t.Fatalf("popped %s", p)
	}
	q.done("/a")
	if n := q.size(); n != 0 {
		t.Fatalf("%d left: the promoted path was queued twice", n)
	}
}

// The file an attacker drops must not be refused because a sweep filled up.
func TestFullBacklogDoesNotRefuseALiveFile(t *testing.T) {
	q := newFileQueue(2, time.Millisecond)
	q.pushBacklog("/a")
	q.pushBacklog("/b")
	if !q.push("/tmp/dropped") {
		t.Fatal("a full backlog refused a live path")
	}
}

func TestFullLiveLaneReportsTheLoss(t *testing.T) {
	q := newFileQueue(1, time.Millisecond)
	q.push("/a")
	if q.push("/b") {
		t.Fatal("a dropped event must be reported so the caller can sweep")
	}
}

func TestSweepWaitsForRoomRatherThanDropping(t *testing.T) {
	q := newFileQueue(1, time.Millisecond)
	q.pushBacklog("/a")
	done := make(chan bool, 1)
	go func() { done <- q.pushBacklog("/b") }()
	select {
	case <-done:
		t.Fatal("the sweep did not wait")
	case <-time.After(50 * time.Millisecond):
	}
	if p := popNow(t, q, false); p != "/a" {
		t.Fatalf("popped %s", p)
	}
	if ok := <-done; !ok {
		t.Fatal("the sweep gave up")
	}
}

func TestCloseReleasesEveryoneWaiting(t *testing.T) {
	q := newFileQueue(1, time.Millisecond)
	q.pushBacklog("/a")
	sweep, worker := make(chan bool, 1), make(chan bool, 1)
	go func() { sweep <- q.pushBacklog("/b") }()
	go func() {
		_, ok := q.pop(true)
		worker <- ok
	}()
	time.Sleep(10 * time.Millisecond)
	q.close()
	for _, c := range []chan bool{sweep, worker} {
		select {
		case ok := <-c:
			if ok {
				t.Fatal("a closed queue must say so")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("close left a goroutine waiting")
		}
	}
}

// A file rewritten while it is scanned must end up scanned in its last state, by
// one more scan however many writes there were.
func TestRewriteDuringScanCoalesces(t *testing.T) {
	q := newFileQueue(100, 5*time.Millisecond)
	q.push("/f")
	p := popNow(t, q, false)
	for range 100 {
		q.push("/f")
	}
	if n := q.size(); n != 0 {
		t.Fatalf("%d queued while the scan runs", n)
	}
	q.done(p)
	if again := popNow(t, q, false); again != "/f" {
		t.Fatalf("popped %s", again)
	}
	q.done("/f")
	if n := q.size(); n != 0 {
		t.Fatalf("%d left after the one rescan", n)
	}
}

// A file rewritten in a loop must not be able to pin a worker.
func TestHotFileIsPaced(t *testing.T) {
	const pause = 20 * time.Millisecond
	q := newFileQueue(100, pause)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				q.push("/hot")
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()
	var scans atomic.Int32
	go func() {
		for {
			p, ok := q.pop(false)
			if !ok {
				return
			}
			scans.Add(1)
			time.Sleep(time.Millisecond) // long enough for writes to land mid-scan
			q.done(p)
		}
	}()
	time.Sleep(10*pause + pause/2)
	q.close()
	// Unpaced, a 1 ms scan runs about a hundred times in this window.
	if n := scans.Load(); n > 25 {
		t.Fatalf("%d scans of one file in %s", n, 10*pause)
	}
}

func popWithin(q *fileQueue, d time.Duration) bool {
	got := make(chan bool, 1)
	go func() { _, ok := q.pop(false); got <- ok }()
	select {
	case ok := <-got:
		return ok
	case <-time.After(d):
		return false
	}
}

// Writes timed to land just after each scan finishes never overlap one, which is
// the way to pin a CPU when only an overlapping change is paced.
func TestRewriteBetweenScansIsPaced(t *testing.T) {
	const pause = 60 * time.Millisecond
	q := newFileQueue(10, pause)
	defer q.close()
	q.push("/hot")
	p, _ := q.pop(false)
	q.done(p) // the scan is over
	start := time.Now()
	q.push("/hot") // and the next write lands right after it
	if !popWithin(q, 2*time.Second) {
		t.Fatal("the rewrite was lost")
	}
	if e := time.Since(start); e < pause/2 {
		t.Fatalf("rescanned after %s, want a pause of %s", e, pause)
	}
}

func TestFirstChangeIsNotDelayed(t *testing.T) {
	q := newFileQueue(10, time.Hour)
	defer q.close()
	q.push("/new")
	if !popWithin(q, time.Second) {
		t.Fatal("a file that changed once must be scanned at once")
	}
}

func TestCooledFileIsReleasedWithoutARescan(t *testing.T) {
	q := newFileQueue(10, 10*time.Millisecond)
	defer q.close()
	q.push("/a")
	p, _ := q.pop(false)
	q.done(p)
	time.Sleep(60 * time.Millisecond)
	if q.size() != 0 {
		t.Fatal("no change, no rescan")
	}
	q.push("/a")
	if !popWithin(q, time.Second) {
		t.Fatal("a cooled file must be scannable again")
	}
}

// A synchronous pass must not lose a change to, or wait on, a cooldown.
func TestReopenDeliversPendingChanges(t *testing.T) {
	q := newFileQueue(10, time.Hour)
	defer q.close()
	q.push("/a")
	p, _ := q.pop(false)
	q.done(p)
	q.push("/a") // lands in the cooldown
	q.finish()
	q.reopen()
	if !popWithin(q, time.Second) {
		t.Fatal("the change must be due in the next pass")
	}
}

func TestStripesAreStablePerKey(t *testing.T) {
	var s stripes
	if s.of("/a") != s.of("/a") {
		t.Fatal("one key must always get the same lock")
	}
}

func TestWakeupCollapsesAndIsNeverLost(t *testing.T) {
	w := newWakeup()
	for range 1000 {
		w.fire()
	}
	<-w
	select {
	case <-w:
		t.Fatal("a burst must collapse into one pass")
	default:
	}
	w.fire()
	select {
	case <-w:
	default:
		t.Fatal("a fire after a pass started must get a pass of its own")
	}
}

// A sweep runs because events were lost, so a busy path it reaches may have changed
// with nothing left to say so.
func TestSweepReachingABusyPathRescansIt(t *testing.T) {
	q := newFileQueue(100, time.Millisecond)
	q.push("/f")
	p := popNow(t, q, false)
	q.pushBacklog("/f")
	q.done(p)
	if again := popNow(t, q, false); again != "/f" {
		t.Fatalf("popped %s", again)
	}
}

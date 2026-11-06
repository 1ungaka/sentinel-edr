// Package parallel runs work on as many goroutines as it can use.
//
// Both entry points wait for everything they started, so a caller can treat them
// as one call. A panic on a worker would otherwise take the whole process down
// past any recover the caller holds, which for a daemon means one hostile input
// ends the defence, so it is carried back and raised on the calling goroutine
// once the rest of the work has finished.
package parallel

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// Panic is what the caller receives when a worker panicked. Stack is the
// worker's, which the re-raise would otherwise lose.
type Panic struct {
	Value any
	Stack []byte
}

func (p *Panic) Error() string { return fmt.Sprintf("%v\n%s", p.Value, p.Stack) }

type catcher struct {
	once sync.Once
	p    *Panic
}

func (c *catcher) guard(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			c.once.Do(func() { c.p = &Panic{r, debug.Stack()} })
		}
	}()
	fn()
}

func (c *catcher) raise() {
	if c.p != nil {
		panic(c.p)
	}
}

// Do runs every task at once and returns when all of them have finished.
func Do(tasks ...func()) {
	var c catcher
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, t := range tasks {
		go func() {
			defer wg.Done()
			c.guard(t)
		}()
	}
	wg.Wait()
	c.raise()
}

// For calls fn with every index in [0, n), on at most workers goroutines, and
// returns when all calls have finished. workers <= 0 means one per CPU. fn owns
// its index, so writing to slot i of a preallocated slice needs no lock and keeps
// the input's order.
func For(n, workers int, fn func(i int)) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	workers = min(workers, n)
	if workers <= 0 {
		return
	}
	var c catcher
	var next atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				c.guard(func() { fn(i) })
			}
		}()
	}
	wg.Wait()
	c.raise()
}

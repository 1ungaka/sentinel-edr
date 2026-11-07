//go:build unix

package peeler

import (
	"context"
	"fmt"
	"syscall"
	"testing"
	"time"
)

// processCPU is the user and system time this process has used.
func processCPU(tb testing.TB) time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		tb.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// Parallelism buys latency, not cost, so the wall clock alone does not bound
// what a sample can make the engine spend. The aggregate does have a bound, and
// this measures against it: no shape may use more CPU than every worker running
// flat out for the whole wall clock, plus the one decode each had in flight.
func TestAggregateCPUIsBoundedByTheBudget(t *testing.T) {
	const wall = time.Second
	const workers = 4
	bound := (workers*wall + workers*2*time.Second) * raceSlow
	for name, s := range hostileShapes() {
		t.Run(name, func(t *testing.T) {
			limits := s.limits
			limits.MaxWallClock = wall
			opts := []Option{WithLimits(limits), WithParallelism(workers)}
			if s.layers != nil {
				opts = append(opts, WithUnwrappers(s.layers))
			}
			before := processCPU(t)
			r := New(opts...).Peel(context.Background(), s.blob)
			spent := processCPU(t) - before
			t.Logf("%-22s cpu %-12s nodes %-4d decoded %-9d %s", name, spent.Round(time.Microsecond), r.NodesVisited, r.OutputBytes, r.Outcome)
			if spent > bound {
				t.Fatalf("%s of CPU under a wall clock of %s with %d workers", spent, wall, workers)
			}
		})
	}
}

// BenchmarkPeelDepth is the aggregate-CPU series for benchstat: the same inert
// leaf under more and more layers. cpu-ns/op is process CPU, which is what an
// attacker adding layers would be spending, where ns/op is only latency.
//
//	go test -run '^$' -bench 'PeelDepth|PeelArchive' -count 10 ./internal/peeler/ | benchstat -
func BenchmarkPeelDepth(b *testing.B) {
	cycle := []string{"base64", "gzip", "base85", "zlib", "rot13", "hex"}
	for _, depth := range []int{1, 2, 4, 8, 16, 28} {
		layers := make([]string, 0, depth+len(cycle))
		for len(layers) < depth {
			layers = append(layers, cycle...)
		}
		data := composeAny(fakeELF, layers[:depth]...)
		b.Run(fmt.Sprintf("layers=%d", depth), func(b *testing.B) { benchCPU(b, data) })
	}
}

// BenchmarkPeelArchive is the same series for archives: members that are
// screened out, and members that are walked.
func BenchmarkPeelArchive(b *testing.B) {
	for _, members := range []int{10, 100, 1000} {
		var plain, layered []zipEntry
		for i := 0; i < members; i++ {
			plain = append(plain, zipEntry{name: fmt.Sprint(i), body: []byte(fmt.Sprintf("member %d\n%s", i, prose))})
			layered = append(layered, zipEntry{name: fmt.Sprint(i), body: compose([]byte(fmt.Sprintf("member %d\n%s", i, prose)), "gzip")})
		}
		b.Run(fmt.Sprintf("screened=%d", members), func(b *testing.B) { benchCPU(b, zipOf(plain...)) })
		b.Run(fmt.Sprintf("walked=%d", members), func(b *testing.B) { benchCPU(b, zipOf(layered...)) })
	}
}

func benchCPU(b *testing.B, data []byte) {
	p := New()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	before := processCPU(b)
	for b.Loop() {
		p.Peel(context.Background(), data)
	}
	b.ReportMetric(float64(processCPU(b)-before)/float64(b.N), "cpu-ns/op")
}

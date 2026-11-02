package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cau-edr/cau/internal/peeler"
	"github.com/cau-edr/cau/internal/report"
)

func peelUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau peel [flags] <file>

Walks the obfuscation-chain tree of a file (NOVEL-012): at each node every
applicable reversible layer decoder (base64/base32/hex, gzip/zlib/flate/bzip2)
spawns a child, under a single global per-sample budget wall. Chain *depth* is
itself a signal, and a branch that hits the wall is reported as 'peel-exhausted'
— a first-class outcome, never a silent clean. The peeler only decodes; it
never executes sample content.

Flags:
  --format <fmt>     text or json (default text)
  --max-depth <n>    deepest any path may peel (default 16)
  --max-nodes <n>    total nodes the tree may visit (default 512)
  --max-output <n>   total decoded bytes across every branch (default 67108864)
  --max-children <n> transforms attempted per node (default 4)
  --timeout <dur>    wall-clock ceiling for the whole peel (default 5s)

Exit codes: 0 clean, 1 a chain revealed a payload or the peel was exhausted,
3 the run failed, 4 usage.
`)
}

func cmdPeel(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("peel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	maxDepth := fs.Int("max-depth", 0, "deepest any path may peel (0 = default)")
	maxNodes := fs.Int64("max-nodes", 0, "total nodes the tree may visit (0 = default)")
	maxOutput := fs.Int64("max-output", 0, "total decoded bytes allowed (0 = default)")
	maxChildren := fs.Int("max-children", 0, "transforms attempted per node (0 = default)")
	timeout := fs.Duration("timeout", 0, "wall-clock ceiling (0 = default)")
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() != 1 {
		return fail(stderr, report.ExitUsage, "peel takes exactly one file")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "%v", err)
	}

	p := peeler.New(peeler.WithLimits(peeler.BudgetLimits{
		MaxDepth:       *maxDepth,
		MaxNodes:       *maxNodes,
		MaxOutputBytes: *maxOutput,
		MaxChildren:    *maxChildren,
		MaxWallClock:   *timeout,
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := p.Peel(ctx, data)

	if *format == "json" {
		if err := writeJSON(stdout, r); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		fmt.Fprintf(stdout, "File        : %s\n", fs.Arg(0))
		fmt.Fprintf(stdout, "Outcome     : %s\n", r.Outcome)
		fmt.Fprintf(stdout, "Score       : %d\n", r.Score)
		fmt.Fprintf(stdout, "Max depth   : %d\n", r.MaxDepth)
		fmt.Fprintf(stdout, "Entropy     : %.3f bits/byte\n", r.RootEntropy)
		fmt.Fprintf(stdout, "Nodes       : %d\n", r.NodesVisited)
		fmt.Fprintf(stdout, "Decoded     : %d bytes\n", r.OutputBytes)
		if r.Exhausted {
			fmt.Fprintf(stdout, "Exhausted   : %s\n", r.ExhaustReason)
		}
		for _, c := range r.Chains {
			fmt.Fprintf(stdout, "Chain       : %s  -> %s (depth %d)\n", c.Signature(), c.Terminal, c.Depth)
		}
	}

	// A revealed payload or an exhausted peel is a finding (exit 1); a clean,
	// fully-explored tree is exit 0.
	if r.Outcome == peeler.OutcomeClean {
		return report.ExitOK
	}
	return report.ExitThreat
}

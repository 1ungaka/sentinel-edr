package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/parallel"
	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/report"
)

// maxInputBytes caps how much a command reads from an arbitrary input file or
// stdin, so a huge or endless input (a multi-gigabyte file, /dev/zero, a FIFO)
// cannot exhaust memory. 256 MiB is far larger than any real obfuscation-chain
// sample or intel feed; anything bigger is refused with a clear error.
const maxInputBytes = 256 << 20

// readFileCapped reads at most cap bytes from path and errors if the file is
// larger, instead of letting os.ReadFile allocate an unbounded amount.
func readFileCapped(path string, cap int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr == nil && fi.Mode().IsRegular() && fi.Size() > cap {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte input cap", path, fi.Size(), cap)
	}
	data, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > cap {
		return nil, fmt.Errorf("%s exceeds the %d-byte input cap", path, cap)
	}
	return data, nil
}

// readStdinCapped reads at most cap bytes from stdin.
func readStdinCapped(cap int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > cap {
		return nil, fmt.Errorf("stdin exceeds the %d-byte input cap", cap)
	}
	return data, nil
}

func peelUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cau peel [flags] <file>...

Walks the obfuscation-chain tree of each file (NOVEL-012). At each node every
reversible layer that applies decodes at once, and each result opens a branch:
the base encodings (2, 8, 10, 16, 32, 36, 45, 58, 62, 64, 85, 91, 92), every
rot and Caesar shift, atbash, reversal, UTF-16, gzip, zlib, flate and bzip2, the
members of a zip, and blobs carved out of a surrounding script. Layers chain in
any order, under a single global per-sample budget wall. Chain *depth* is itself
a signal: four or more layers are reported as 'deep-chain' whatever is under
them. A branch that hits the wall is reported as 'peel-exhausted', a first-class
outcome, never a silent clean. The peeler only decodes; it never executes sample
content.

A zip the file is, or one nested straight inside it, is packaging and adds no
depth: each member is peeled as the file it is. A zip found under another layer
counts as one. Members with no sign of a layer are screened out without being
walked, encrypted members are skipped, and both are counted in the output. xz is
recognised and not decoded: a path that ends in it is listed as opaque.

Flags:
  --format <fmt>     text or json (default text)
  --jobs <n>         files peeled at once (default: one per CPU)
  --stream           print each layer and chain as it is found
  --max-depth <n>    deepest any path may peel (default 32)
  --max-nodes <n>    total nodes the tree may visit (default 512)
  --max-output <n>   total decoded bytes across every branch (default 67108864)
  --max-children <n> branches opened per node (default 6)
  --timeout <dur>    wall-clock ceiling for each file's peel (default 5s)

With --stream --format json the output is JSON lines: one object per event, then
one per file with kind "result".

Exit codes: 0 clean, 1 any file revealed a payload, was exhausted or is a deep
chain, 3 the run failed, 4 usage.
`)
}

// peeledFile is one file's outcome, in the slot of its position on the command
// line, so the report keeps that order however the files finished.
type peeledFile struct {
	path   string
	result peeler.Result
	err    error
}

// peelEvents writes --stream output. Files peel at once, so a line is the unit
// that has to stay whole.
type peelEvents struct {
	mu     sync.Mutex
	w      io.Writer
	asJSON bool
}

func (s *peelEvents) event(path string, e peeler.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.asJSON {
		line, err := json.Marshal(struct {
			File string `json:"file"`
			peeler.Event
		}{path, e})
		if err == nil {
			fmt.Fprintf(s.w, "%s\n", line)
		}
		return
	}
	chain := strings.Join(e.Path, ">")
	if e.Kind == peeler.EventChain {
		fmt.Fprintf(s.w, "[chain] %s  %s -> %s\n", report.TermSafe(path), chain, e.Terminal)
		return
	}
	fmt.Fprintf(s.w, "[layer] %s  %s\n", report.TermSafe(path), chain)
}

func (s *peelEvents) result(r peeler.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line, err := json.Marshal(struct {
		Kind string `json:"kind"`
		peeler.Result
	}{"result", r})
	if err == nil {
		fmt.Fprintf(s.w, "%s\n", line)
	}
}

func peelFile(p *peeler.Peeler, path string, events *peelEvents) peeledFile {
	data, err := readFileCapped(path, maxInputBytes)
	if err != nil {
		return peeledFile{path: path, err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	j := p.Start(ctx, data)
	if events != nil {
		for e := range j.Events() {
			events.event(path, e)
		}
	}
	r := j.Wait()
	r.FilePath = path
	return peeledFile{path: path, result: r}
}

func writePeelText(w io.Writer, f peeledFile) {
	r := f.result
	fmt.Fprintf(w, "File        : %s\n", report.TermSafe(f.path))
	fmt.Fprintf(w, "Outcome     : %s\n", r.Outcome)
	fmt.Fprintf(w, "Score       : %d\n", r.Score)
	fmt.Fprintf(w, "Max depth   : %d\n", r.MaxDepth)
	fmt.Fprintf(w, "Entropy     : %.3f bits/byte\n", r.RootEntropy)
	fmt.Fprintf(w, "Nodes       : %d\n", r.NodesVisited)
	fmt.Fprintf(w, "Decoded     : %d bytes\n", r.OutputBytes)
	if r.Exhausted {
		fmt.Fprintf(w, "Exhausted   : %s\n", report.TermSafe(r.ExhaustReason))
	}
	if r.DeepestSignature != "" {
		fmt.Fprintf(w, "Deepest     : %s\n", report.TermSafe(r.DeepestSignature))
	}
	if a := r.Archive; a != nil {
		fmt.Fprintf(w, "Archive     : %d zip, %d members: %d peeled, %d screened out", a.Archives, a.Members, a.Peeled, a.Screened)
		if a.Encrypted > 0 {
			fmt.Fprintf(w, ", %d encrypted (skipped)", a.Encrypted)
		}
		if a.Unsupported > 0 {
			fmt.Fprintf(w, ", %d in a method not decoded (skipped)", a.Unsupported)
		}
		if a.Damaged > 0 {
			fmt.Fprintf(w, ", %d damaged", a.Damaged)
		}
		fmt.Fprintln(w)
	}
	for _, o := range r.Opaque {
		fmt.Fprintf(w, "Opaque      : %s (recognised, not decoded)\n", report.TermSafe(o))
	}
	for _, c := range r.Chains {
		fmt.Fprintf(w, "Chain       : %s  -> %s (depth %d)\n", c.Signature(), c.Terminal, c.Depth)
	}
}

func cmdPeel(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("peel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { peelUsage(stderr) }
	format := fs.String("format", "text", "output format: text or json")
	jobs := fs.Int("jobs", 0, "files peeled at once (0 = one per CPU)")
	stream := fs.Bool("stream", false, "print each layer and chain as it is found")
	maxDepth := fs.Int("max-depth", 0, "deepest any path may peel (0 = default)")
	maxNodes := fs.Int64("max-nodes", 0, "total nodes the tree may visit (0 = default)")
	maxOutput := fs.Int64("max-output", 0, "total decoded bytes allowed (0 = default)")
	maxChildren := fs.Int("max-children", 0, "branches opened per node (0 = default)")
	timeout := fs.Duration("timeout", 0, "wall-clock ceiling for each file (0 = default)")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if *jobs < 0 {
		return fail(stderr, report.ExitUsage, "--jobs must not be negative")
	}
	if fs.NArg() == 0 {
		return fail(stderr, report.ExitUsage, "peel takes at least one file")
	}

	p := peeler.New(peeler.WithLimits(peeler.BudgetLimits{
		MaxDepth:       *maxDepth,
		MaxNodes:       *maxNodes,
		MaxOutputBytes: *maxOutput,
		MaxChildren:    *maxChildren,
		MaxWallClock:   *timeout,
	}))
	var events *peelEvents
	if *stream {
		events = &peelEvents{w: stdout, asJSON: *format == "json"}
	}

	files := fs.Args()
	peeled := make([]peeledFile, len(files))
	parallel.For(len(files), *jobs, func(i int) {
		peeled[i] = peelFile(p, files[i], events)
		if events != nil && events.asJSON && peeled[i].err == nil {
			events.result(peeled[i].result)
		}
	})

	failed, threat := false, false
	var results []peeler.Result
	for _, f := range peeled {
		if f.err != nil {
			failed = true
			fmt.Fprintf(stderr, "[ERROR] %s\n", report.TermSafe(f.err.Error()))
			continue
		}
		// A revealed payload or an exhausted peel is a finding (exit 1); a clean,
		// fully-explored tree is exit 0.
		threat = threat || f.result.Outcome != peeler.OutcomeClean
		results = append(results, f.result)
	}

	switch {
	case *stream && *format == "json": // already written, one line per file
	case *format == "json":
		var doc interface{} = results
		if len(files) == 1 && len(results) == 1 {
			doc = results[0]
		}
		if err := writeJSON(stdout, doc); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	default:
		first := true
		for _, f := range peeled {
			if f.err != nil {
				continue
			}
			if !first {
				fmt.Fprintln(stdout)
			}
			first = false
			writePeelText(stdout, f)
		}
	}

	// A finding outranks a failed read: an unreadable file must not hide one.
	switch {
	case threat:
		return report.ExitThreat
	case failed:
		return report.ExitRunFailed
	}
	return report.ExitOK
}

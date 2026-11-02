package eval

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

// OnErrorMode decides what a scan error does to the confusion matrix.
type OnErrorMode string

const (
	// OnErrorExclude leaves an errored sample out of the matrix (default).
	OnErrorExclude OnErrorMode = "exclude"
	// OnErrorMiss charges an errored malicious sample to the FN column and an
	// errored benign sample to TN. "Could not scan" is a miss in production.
	OnErrorMiss OnErrorMode = "miss"
	// OnErrorFail aborts the run on the first scan error.
	OnErrorFail OnErrorMode = "fail"
)

// ParseOnErrorMode validates a user-supplied mode string.
func ParseOnErrorMode(s string) (OnErrorMode, error) {
	switch OnErrorMode(s) {
	case "", OnErrorExclude:
		return OnErrorExclude, nil
	case OnErrorMiss, OnErrorFail:
		return OnErrorMode(s), nil
	}
	return "", fmt.Errorf("eval: unknown on-error mode %q (want exclude, miss or fail)", s)
}

// RunOptions tunes a Runner. The zero value is usable.
type RunOptions struct {
	// Concurrency is the number of samples scanned in parallel. Defaults to
	// runtime.NumCPU() and is clamped to at least 1.
	Concurrency int
	// OnError defaults to OnErrorExclude.
	OnError OnErrorMode
	// MaxFileSize, when > 0, skips samples larger than this many bytes.
	MaxFileSize int64
	// Tool is recorded in RunInfo.Tool.
	Tool string
	// Now supplies the run timestamp (default time.Now).
	Now func() time.Time
	// Progress, when set, is called after every sample completes.
	Progress func(done, total int)
}

func (o RunOptions) normalized() RunOptions {
	if o.Concurrency < 1 {
		o.Concurrency = runtime.NumCPU()
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.OnError == "" {
		o.OnError = OnErrorExclude
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Runner scans every sample of a manifest with a set of detectors.
type Runner struct {
	detector  Detector
	names     []string
	opts      RunOptions
	stat      func(string) (os.FileInfo, error)
	ensureErr error
}

// NewRunner wires detectors to a runner. Several detectors are wrapped in a
// CompositeDetector so each sample is scanned once by "the engine" while
// signals keep per-detector attribution.
func NewRunner(detectors []Detector, opts RunOptions) *Runner {
	r := &Runner{opts: opts.normalized(), stat: os.Stat}
	var live []Detector
	for _, d := range detectors {
		if d != nil {
			live = append(live, d)
			r.names = append(r.names, d.Name())
		}
	}
	sort.Strings(r.names)
	switch len(live) {
	case 0:
		r.ensureErr = fmt.Errorf("eval: runner has no detectors")
	case 1:
		r.detector = live[0]
	default:
		r.detector = &CompositeDetector{CompositeName: "engine", Detectors: live}
	}
	return r
}

// Run scans the manifest. Results are stored by manifest index, so the output
// is identical regardless of scheduling; the returned Run is ready for
// NewReport.
func (r *Runner) Run(m *Manifest) (*Run, error) {
	if r.ensureErr != nil {
		return nil, r.ensureErr
	}
	if m == nil {
		return nil, fmt.Errorf("eval: nil manifest")
	}
	opts := r.opts
	total := len(m.Samples)
	results := make([]SampleResult, total)

	type job struct {
		idx int
		s   Sample
	}
	jobs := make(chan job)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		done     int
		fatal    error
		firstErr error
	)
	abort := make(chan struct{})
	var abortOnce sync.Once
	setFatal := func(err error) {
		mu.Lock()
		if fatal == nil {
			fatal = err
		}
		mu.Unlock()
		abortOnce.Do(func() { close(abort) })
	}

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			select {
			case <-abort:
				continue
			default:
			}
			res := r.scanOne(j.s)
			if res.Error != "" && opts.OnError == OnErrorFail {
				setFatal(fmt.Errorf("eval: sample %s failed to scan: %s", j.s.Key(), res.Error))
			}
			results[j.idx] = res
			mu.Lock()
			done++
			d := done
			if res.Error != "" && firstErr == nil {
				firstErr = errors.New(res.Error)
			}
			mu.Unlock()
			if opts.Progress != nil {
				opts.Progress(d, total)
			}
		}
	}

	wg.Add(opts.Concurrency)
	for i := 0; i < opts.Concurrency; i++ {
		go worker()
	}
	for i, s := range m.Samples {
		jobs <- job{idx: i, s: s}
	}
	close(jobs)
	wg.Wait()

	if fatal != nil {
		return nil, fatal
	}
	for _, res := range results {
		if res.notConfigured {
			return nil, fmt.Errorf("%w: %s", ErrNotConfigured, res.Error)
		}
	}

	run := &Run{
		SchemaVersion: ReportSchemaVersion,
		Info: RunInfo{
			Tool:        opts.Tool,
			GeneratedAt: opts.Now().UTC(),
			Corpus:      m.SourcePath,
			CorpusName:  m.Name,
			CorpusRoot:  m.Dir,
			Detectors:   append([]string(nil), r.names...),
			Concurrency: opts.Concurrency,
			OnError:     string(opts.OnError),
			MaxFileSize: opts.MaxFileSize,
		},
		Samples: results,
	}
	return run, nil
}

// scanOne scores one sample.
func (r *Runner) scanOne(s Sample) SampleResult {
	res := SampleResult{
		ID:       s.ID,
		Path:     s.Path,
		FullPath: s.FullPath(),
		Expected: s.Expected(),
		Family:   s.ExpectedFamily(),
		Verdict:  VerdictUnknown,
	}
	benign := s.Benign()

	info, err := r.stat(s.FullPath())
	switch {
	case err != nil:
		return r.errored(res, benign, fmt.Sprintf("stat: %v", err))
	case info.IsDir():
		return r.errored(res, benign, "sample is a directory")
	}
	res.Size = info.Size()
	if r.opts.MaxFileSize > 0 && info.Size() > r.opts.MaxFileSize {
		res.SkipReason = fmt.Sprintf("size %d exceeds max file size %d", info.Size(), r.opts.MaxFileSize)
		return res
	}

	start := time.Now()
	f, serr := r.detector.ScanFile(s.FullPath())
	elapsed := time.Since(start)
	if f.Duration > 0 {
		elapsed = f.Duration
	}
	res.Duration = elapsed
	f = f.Normalize(r.detector.Name())

	if serr != nil || (f.Err != nil && !f.Detected()) {
		e := serr
		if e == nil {
			e = f.Err
		}
		out := r.errored(res, benign, e.Error())
		if errors.Is(e, ErrNotConfigured) {
			out.notConfigured = true
		}
		return out
	}

	res.Scored = true
	res.Signals = f.Signals
	res.Scores = f.Scores
	res.Detectors = f.DetectorNames()
	res.Detected = f.Detected()
	res.Verdict = f.Verdict
	if f.Err != nil {
		// Partial failure with detections: the detection stands, the error is
		// recorded for the Errors list without un-scoring the sample.
		res.Error = f.Err.Error()
	}
	return res
}

func (r *Runner) errored(res SampleResult, benign bool, msg string) SampleResult {
	res.Error = msg
	res.Verdict = VerdictError
	if r.opts.OnError == OnErrorMiss {
		res.Scored = true
		res.Detected = false
		if !benign {
			res.CountedAsMiss = true
		}
	}
	return res
}

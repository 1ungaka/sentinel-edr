package scanner

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	yara "github.com/hillu/go-yara/v4"

	"github.com/s-b-repo/cau/internal/safefs"
)

// DefaultScanTimeout is the per-scan wall-clock budget handed to libyara when
// no timeout is configured. An adversarial sample must never be able to pin a
// scanner goroutine forever.
const DefaultScanTimeout = 30 * time.Second

// DefaultMaxScanSize is the largest file that is read into memory for scanning.
// Bigger files are memory-mapped by libyara instead (see ScanFileYara).
const DefaultMaxScanSize int64 = 256 << 20 // 256 MiB

// YaraMatchMeta is one entry of a YARA rule's meta: block (author,
// threat_level, in_the_wild, ...). Value is a string, an int, a bool, or nil.
type YaraMatchMeta struct {
	Identifier string
	Value      interface{}
}

// String renders the meta value as text.
func (m YaraMatchMeta) String() string {
	switch v := m.Value.(type) {
	case nil:
		return ""
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// YaraMatch holds the details of a single YARA rule match.
type YaraMatch struct {
	RuleName string
	// Namespace is the namespace declared by the rule itself ("default" when
	// the rule declares none). It is reported by libyara, not guessed from a
	// file name.
	Namespace string
	Tags      []string
	Strings   []YaraMatchString
	// Metas carries the rule's meta: block, which the CLI-based scanner used
	// to throw away.
	Metas []YaraMatchMeta
}

// Meta returns the meta entry with the given identifier.
func (m YaraMatch) Meta(identifier string) (YaraMatchMeta, bool) {
	for _, meta := range m.Metas {
		if meta.Identifier == identifier {
			return meta, true
		}
	}
	return YaraMatchMeta{}, false
}

// MetaString returns a meta entry rendered as text.
func (m YaraMatch) MetaString(identifier string) string {
	if meta, ok := m.Meta(identifier); ok {
		return meta.String()
	}
	return ""
}

// MetaInt returns an integer meta entry.
func (m YaraMatch) MetaInt(identifier string) (int, bool) {
	meta, ok := m.Meta(identifier)
	if !ok {
		return 0, false
	}
	n, ok := meta.Value.(int)
	return n, ok
}

// YaraMatchString holds a single matched string from a YARA rule.
type YaraMatchString struct {
	Name string
	// Offset is the ABSOLUTE offset of the match inside the scanned data.
	// libyara reports the offset relative to the memory block the match was
	// found in, so this is Base+Offset (see YaraScanner for the details).
	Offset uint64
	Data   []byte
	// Base is the base offset of the memory block that contained the match.
	// It is 0 for the single-block scans performed here, and is kept so that
	// offsets stay correct for multi-block scans.
	Base uint64
	// XorKey is the single byte XOR key that decoded the match (0 = no xor).
	XorKey uint8
}

// YaraScanner owns a compiled ruleset and scans data with it.
//
// The ruleset is compiled once, at load time: the rules directory is walked
// once and every rule file is fed to a single YARA compiler, so scanning a
// sample costs one in-process pass over the ruleset instead of one process
// spawn per rule file.
//
// A *YaraScanner is safe for concurrent use by multiple goroutines: each scan
// creates its own yara.Scanner, because a YARA scanner object must not be
// shared between concurrent scans.
type YaraScanner struct {
	rules *yara.Rules

	source     string
	sources    []RuleSource
	files      []string
	ruleCount  int
	warnings   []RuleCompileWarning
	timeout    time.Duration
	flags      yara.ScanFlags
	maxScanSz  int64
	warn       func(format string, args ...interface{})
	closed     atomic.Bool
	fileWarned atomic.Bool
}

// YaraOption customises a YaraScanner.
type YaraOption func(*yaraConfig)

type yaraConfig struct {
	timeout        time.Duration
	flags          yara.ScanFlags
	maxScanSize    int64
	namespaceOf    func(path string) string
	warn           func(format string, args ...interface{})
	timeoutSet     bool
	maxScanSizeSet bool
}

// WithTimeout sets the per-scan budget. libyara takes whole seconds and treats
// 0 as "no limit", so sub-second values are rounded up to one second and 0 is
// rejected: silently disabling the timeout is never the intent.
func WithTimeout(d time.Duration) YaraOption {
	return func(c *yaraConfig) {
		c.timeout = d
		c.timeoutSet = true
	}
}

// WithScanFlags sets libyara scan flags (e.g. yara.ScanFlagsFastMode).
func WithScanFlags(flags yara.ScanFlags) YaraOption {
	return func(c *yaraConfig) { c.flags = flags }
}

// WithMaxScanSize sets the largest file that is read fully into memory for
// scanning. Larger files are handed to libyara's own file scanner.
func WithMaxScanSize(bytes int64) YaraOption {
	return func(c *yaraConfig) {
		c.maxScanSize = bytes
		c.maxScanSizeSet = true
	}
}

// WithNamespaceFromFileName puts every rule of a file into a namespace derived
// from the file name instead of keeping the namespace declared by the rules.
// Off by default: CAU EDR reports the real YARA namespace.
func WithNamespaceFromFileName() YaraOption {
	return func(c *yaraConfig) { c.namespaceOf = namespaceFromFileName }
}

// WithWarnFunc redirects the warnings emitted while loading and scanning
// (default: stderr, prefixed with "[WARN] ").
func WithWarnFunc(fn func(format string, args ...interface{})) YaraOption {
	return func(c *yaraConfig) { c.warn = fn }
}

func defaultConfig() *yaraConfig {
	return &yaraConfig{
		timeout:     DefaultScanTimeout,
		maxScanSize: DefaultMaxScanSize,
		warn: func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...)
		},
	}
}

// LoadYaraRules compiles the rules found at path (a .yar/.yara file or a
// directory that is walked recursively) into a single compiled ruleset.
//
// It returns the scanner and the number of rule files that made it into the
// ruleset. Rule files that fail to compile are reported as warnings and skipped
// — one broken rule file must not blind the engine — but a ruleset that ends up
// with no usable rule at all is a hard error.
//
// The caller owns the returned scanner and should Close() it when done.
func LoadYaraRules(path string, opts ...YaraOption) (*YaraScanner, int, error) {
	if path == "" {
		return nil, 0, fmt.Errorf("no YARA rules path given")
	}

	files, err := collectRuleFiles(path)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no .yar or .yara files found at: %s", path)
	}

	cfg := applyOptions(opts)

	sources := make([]RuleSource, 0, len(files))
	for _, f := range files {
		src := RuleSource{Path: f}
		if cfg.namespaceOf != nil {
			src.Namespace = cfg.namespaceOf(f)
		}
		sources = append(sources, src)
	}

	ys, err := newYaraScanner(path, sources, cfg)
	if err != nil {
		return nil, 0, err
	}
	return ys, len(ys.files), nil
}

// LoadYaraRuleFiles compiles an explicit list of rule files and/or inline rule
// texts into a single ruleset and returns the number of sources that were
// compiled. It is the same code path used by LoadYaraRules, exposed for callers
// that manage their own rule list (embedded rules, signed rule bundles, ...).
func LoadYaraRuleFiles(sources []RuleSource, opts ...YaraOption) (*YaraScanner, int, error) {
	if len(sources) == 0 {
		return nil, 0, fmt.Errorf("no YARA rule sources given")
	}

	label := sources[0].label()
	if len(sources) > 1 {
		label = fmt.Sprintf("%d rule sources", len(sources))
	}

	ys, err := NewYaraScanner(sources, opts...)
	if err != nil {
		return nil, 0, err
	}
	ys.source = label
	return ys, len(ys.sources), nil
}

// NewYaraScanner compiles the given sources into a single ruleset and returns a
// ready-to-use scanner. The rules are compiled once; every later scan reuses
// the compiled ruleset.
func NewYaraScanner(sources []RuleSource, opts ...YaraOption) (*YaraScanner, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("no YARA rule sources given")
	}
	label := sources[0].label()
	if len(sources) > 1 {
		label = fmt.Sprintf("%d rule sources", len(sources))
	}
	return newYaraScanner(label, sources, applyOptions(opts))
}

func applyOptions(opts []YaraOption) *yaraConfig {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

func newYaraScanner(source string, sources []RuleSource, cfg *yaraConfig) (*YaraScanner, error) {
	timeout, err := normalizeTimeout(cfg.timeout, cfg.timeoutSet)
	if err != nil {
		return nil, err
	}
	if cfg.maxScanSizeSet && cfg.maxScanSize < 0 {
		return nil, fmt.Errorf("yara max scan size must not be negative: %d", cfg.maxScanSize)
	}

	ys := &YaraScanner{
		source:    source,
		timeout:   timeout,
		flags:     cfg.flags,
		maxScanSz: cfg.maxScanSize,
		warn:      cfg.warn,
	}

	rules, sources, warnings, err := compileRuleSources(sources, nil)
	if err != nil {
		return nil, err
	}

	for _, w := range warnings {
		ys.warnf("YARA rule skipped: %s", w.Error())
	}
	ys.warnings = warnings
	ys.rules = rules
	ys.sources = sources
	for _, s := range sources {
		if s.Path != "" {
			ys.files = append(ys.files, s.Path)
		}
	}
	ys.ruleCount = len(rules.GetRules())
	return ys, nil
}

// normalizeTimeout guards against the two ways libyara's timeout API can bite:
// sub-second values truncate to 0, and 0 means "scan forever".
func normalizeTimeout(d time.Duration, set bool) (time.Duration, error) {
	if !set {
		return DefaultScanTimeout, nil
	}
	switch {
	case d <= 0:
		return 0, fmt.Errorf("yara scan timeout must be greater than zero (0 disables the timeout entirely): %s", d)
	case d < time.Second:
		return time.Second, nil
	case d%time.Second != 0:
		return d + (time.Second - d%time.Second), nil
	default:
		return d, nil
	}
}

// Rules exposes the compiled ruleset. Callers that want to drive libyara
// directly (custom callbacks, variables, process scanning) can use it; it must
// not be used after Close.
func (ys *YaraScanner) Rules() *yara.Rules { return ys.rules }

// Warnings returns the diagnostics collected while loading the ruleset: rule
// sources that were skipped plus YARA's non-fatal compiler warnings.
func (ys *YaraScanner) Warnings() []RuleCompileWarning {
	return append([]RuleCompileWarning(nil), ys.warnings...)
}

// RuleCount returns the number of rules in the compiled ruleset.
func (ys *YaraScanner) RuleCount() int { return ys.ruleCount }

// RuleFiles returns the rule files that were compiled into the ruleset.
func (ys *YaraScanner) RuleFiles() []string {
	return append([]string(nil), ys.files...)
}

// Sources returns the rule sources that made it into the ruleset, in compile
// order. It is shorter than the requested source list when some were dropped.
func (ys *YaraScanner) Sources() []RuleSource {
	return append([]RuleSource(nil), ys.sources...)
}

// Source returns the path (or label) the ruleset was loaded from.
func (ys *YaraScanner) Source() string { return ys.source }

// Timeout returns the per-scan budget handed to libyara.
func (ys *YaraScanner) Timeout() time.Duration { return ys.timeout }

// Close releases the compiled ruleset. The scanner must not be used afterwards;
// Close must not run concurrently with a scan.
func (ys *YaraScanner) Close() error {
	if ys.closed.Swap(true) {
		return nil
	}
	if ys.rules != nil {
		ys.rules.Destroy()
		ys.rules = nil
	}
	return nil
}

// Destroy is an alias for Close, mirroring the libyara naming.
func (ys *YaraScanner) Destroy() { _ = ys.Close() }

func (ys *YaraScanner) warnf(format string, args ...interface{}) {
	if ys.warn != nil {
		ys.warn(format, args...)
	}
}

// ScanFileYara scans a file with the compiled ruleset and returns every rule
// that matched.
//
// Matches are never discarded because of a scan-time problem: if the scan is
// aborted (timeout, scan error) after some rules already matched, the matches
// found so far are returned and the failure is reported as a warning, because
// dropping them would silently turn a malicious sample into a clean verdict.
// When nothing matched at all, the error is returned instead. Use
// ScanFileYaraStrict to always get the error alongside the partial results.
func (ys *YaraScanner) ScanFileYara(path string) ([]YaraMatch, error) {
	matches, err := ys.ScanFileYaraStrict(path)
	if err == nil || len(matches) > 0 {
		if err != nil {
			ys.warnf("YARA scan of %s was aborted, results are partial: %v", path, err)
		}
		return matches, nil
	}
	return matches, err
}

// ScanFileYaraStrict scans a file and always returns both the matches collected
// before a failure and that failure, if any.
func (ys *YaraScanner) ScanFileYaraStrict(path string) ([]YaraMatch, error) {
	if err := ys.usable(); err != nil {
		return nil, err
	}

	// Reading the file ourselves keeps libyara behaviour identical for file
	// and buffer scans and makes the reported offsets plain file offsets.
	// Huge files are left to libyara, which memory-maps them in blocks.
	if size, err := fileSize(path); err == nil && size > ys.maxScanSz {
		if !ys.fileWarned.Swap(true) {
			ys.warnf("YARA: %s is %.1f MiB, scanning it in place (max in-memory scan size is %.1f MiB)",
				path, float64(size)/(1<<20), float64(ys.maxScanSz)/(1<<20))
		}
		return ys.scanFileInPlace(path)
	}

	data, err := safefs.ReadFile(path, ys.maxScanSz)
	if errors.Is(err, safefs.ErrTooLarge) {
		return ys.scanFileInPlace(path) // it grew since the size check
	}
	if err != nil {
		return nil, fmt.Errorf("could not read %s for YARA scanning: %w", path, err)
	}
	return ys.scanMem(data, path)
}

// ScanMemYara scans an in-memory buffer with the compiled ruleset. It follows
// the same partial-result policy as ScanFileYara.
func (ys *YaraScanner) ScanMemYara(data []byte) ([]YaraMatch, error) {
	matches, err := ys.ScanMemYaraStrict(data)
	if err == nil || len(matches) > 0 {
		if err != nil {
			ys.warnf("YARA scan aborted, results are partial: %v", err)
		}
		return matches, nil
	}
	return matches, err
}

// ScanMemYaraStrict scans a buffer and always returns both the matches
// collected before a failure and that failure, if any.
func (ys *YaraScanner) ScanMemYaraStrict(data []byte) ([]YaraMatch, error) {
	if err := ys.usable(); err != nil {
		return nil, err
	}
	return ys.scanMem(data, "<memory>")
}

func (ys *YaraScanner) usable() error {
	if ys.rules == nil || ys.closed.Load() {
		return fmt.Errorf("yara scanner is closed")
	}
	return nil
}

// newScanScanner creates a per-scan YARA scanner. A YR_SCANNER must not be
// used by two scans at once, so one is created per call.
func (ys *YaraScanner) newScanScanner(cb yara.ScanCallback) (*yara.Scanner, error) {
	sc, err := yara.NewScanner(ys.rules)
	if err != nil {
		return nil, fmt.Errorf("could not create YARA scanner: %w", err)
	}
	sc.SetTimeout(ys.timeout)
	sc.SetFlags(ys.flags)
	sc.SetCallback(cb)
	return sc, nil
}

// scanMem scans a buffer.
//
// Offsets: libyara's MatchString.Offset is relative to the memory block the
// match occurred in, and MatchString.Base is the base of that block. For the
// single-block scans used here (ScanMem and ScanFile, verified against libyara
// 4.5.8 up to a 34 MB file) Base is always 0 and Offset is already the absolute
// offset, but Base+Offset is computed anyway so multi-block scans (YARA's
// block iterators, e.g. process or split-file scanning) stay correct.
func (ys *YaraScanner) scanMem(data []byte, origin string) ([]YaraMatch, error) {
	var collected yara.MatchRules

	sc, err := ys.newScanScanner(&collected)
	if err != nil {
		return nil, err
	}
	defer sc.Destroy()

	scanErr := sc.ScanMem(data)
	// Matches reported before the failure are kept on purpose.
	matches := convertMatches(collected, data)
	if scanErr != nil {
		return matches, fmt.Errorf("yara scan of %s: %w", origin, describeScanError(scanErr, ys.timeout))
	}
	return matches, nil
}

// scanFileInPlace hands the file to libyara, which memory-maps it. Used for
// files larger than the in-memory scan limit.
func (ys *YaraScanner) scanFileInPlace(path string) ([]YaraMatch, error) {
	// By descriptor: libyara's own open would block on a FIFO swapped in here.
	f, _, err := safefs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open %s for YARA scanning: %w", path, err)
	}
	defer f.Close()

	var collected yara.MatchRules

	sc, err := ys.newScanScanner(&collected)
	if err != nil {
		return nil, err
	}
	defer sc.Destroy()

	scanErr := sc.ScanFileDescriptor(f.Fd())
	matches := convertMatches(collected, nil)
	if scanErr != nil {
		return matches, fmt.Errorf("yara scan of %s: %w", path, describeScanError(scanErr, ys.timeout))
	}
	return matches, nil
}

// convertMatches converts libyara matches into the public representation.
func convertMatches(in yara.MatchRules, data []byte) []YaraMatch {
	if len(in) == 0 {
		return nil
	}
	out := make([]YaraMatch, 0, len(in))
	for _, mr := range in {
		m := YaraMatch{
			RuleName:  mr.Rule,
			Namespace: mr.Namespace,
			Tags:      mr.Tags,
			Metas:     convertMetas(mr.Metas),
			Strings:   make([]YaraMatchString, 0, len(mr.Strings)),
		}
		for _, s := range mr.Strings {
			ms := YaraMatchString{
				Name:   s.Name,
				Offset: s.Base + s.Offset, // absolute offset into the scanned data
				Base:   s.Base,
				Data:   s.Data,
				XorKey: s.XorKey,
			}
			// Defensive: a match can never point outside the scanned data.
			// Report the true absolute offset rather than an out-of-range one.
			if data != nil && ms.Offset+uint64(len(ms.Data)) > uint64(len(data)) {
				continue
			}
			m.Strings = append(m.Strings, ms)
		}
		out = append(out, m)
	}
	return out
}

func convertMetas(in []yara.Meta) []YaraMatchMeta {
	if len(in) == 0 {
		return nil
	}
	out := make([]YaraMatchMeta, 0, len(in))
	for _, m := range in {
		out = append(out, YaraMatchMeta{Identifier: m.Identifier, Value: m.Value})
	}
	return out
}

// describeScanError turns a libyara scan error into an actionable message.
func describeScanError(err error, timeout time.Duration) error {
	var ye yara.Error
	if !errors.As(err, &ye) {
		return err
	}
	if ye.Code == yara.ERROR_SCAN_TIMEOUT {
		return fmt.Errorf("scan timeout after %s, the ruleset was only partially evaluated (%w)",
			timeout, err)
	}
	if ye.RuleIdentifier != "" {
		return fmt.Errorf("%w (while evaluating rule %s)", err, ye.RuleIdentifier)
	}
	return err
}

// IsScanTimeout reports whether err is (or wraps) libyara's scan timeout.
func IsScanTimeout(err error) bool {
	var ye yara.Error
	return errors.As(err, &ye) && ye.Code == yara.ERROR_SCAN_TIMEOUT
}

func fileSize(path string) (int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if fi.IsDir() {
		return 0, fmt.Errorf("%s is a directory", path)
	}
	return fi.Size(), nil
}

// RuleInfo describes one compiled rule: what the coverage matrix and the
// rule linter need without scanning anything.
type RuleInfo struct {
	Name      string
	Namespace string
	Tags      []string
	// Meta holds the rule's meta block with every value rendered as a
	// string (integers in decimal, booleans as "true" / "false"), in
	// declaration order via MetaOrder.
	Meta      map[string]string
	MetaOrder []string
	Private   bool
	Global    bool
	// Strings counts the rule's string definitions.
	Strings int
}

// MetaTechnique returns the ATT&CK technique id(s) a rule declares through
// `mitre_attack`, `attack` or `technique` meta, split on commas and
// whitespace. The same keys the fusion lattice reads.
func (r RuleInfo) MetaTechnique() []string {
	for _, key := range []string{"mitre_attack", "attack", "technique"} {
		if v := strings.TrimSpace(r.Meta[key]); v != "" {
			var out []string
			for _, t := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' || c == ';' }) {
				if t = strings.TrimSpace(t); t != "" {
					out = append(out, t)
				}
			}
			return out
		}
	}
	return nil
}

// RuleInfos enumerates the compiled rules in namespace, then name order.
func (ys *YaraScanner) RuleInfos() []RuleInfo {
	if ys == nil || ys.rules == nil {
		return nil
	}
	var out []RuleInfo
	for _, r := range ys.rules.GetRules() {
		info := RuleInfo{
			Name:      r.Identifier(),
			Namespace: r.Namespace(),
			Tags:      r.Tags(),
			Meta:      map[string]string{},
			Private:   r.IsPrivate(),
			Global:    r.IsGlobal(),
			Strings:   len(r.Strings()),
		}
		for _, m := range r.Metas() {
			var v string
			switch x := m.Value.(type) {
			case string:
				v = x
			case int:
				v = strconv.Itoa(x)
			case bool:
				v = strconv.FormatBool(x)
			default:
				v = fmt.Sprint(x)
			}
			if _, dup := info.Meta[m.Identifier]; !dup {
				info.MetaOrder = append(info.MetaOrder, m.Identifier)
			}
			info.Meta[m.Identifier] = v
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

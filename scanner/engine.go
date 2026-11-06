package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/s-b-repo/cau/internal/intel"
	"github.com/s-b-repo/cau/internal/peeler"
	"github.com/s-b-repo/cau/internal/safefs"
	"github.com/s-b-repo/cau/scanner/archive"
	"github.com/s-b-repo/cau/scanner/chm"
	"github.com/s-b-repo/cau/scanner/encchain"
	"github.com/s-b-repo/cau/scanner/iso"
	"github.com/s-b-repo/cau/scanner/linuxpkg"
	"github.com/s-b-repo/cau/scanner/lnk"
	"github.com/s-b-repo/cau/scanner/ole"
	"github.com/s-b-repo/cau/scanner/pdf"
	"github.com/s-b-repo/cau/scanner/static"
	"github.com/s-b-repo/cau/scanner/stego"
	"github.com/s-b-repo/cau/scanner/tradecraft"
)

// DefaultMaxInMemory is the largest file the engine reads into memory once and
// hands to every detector. Larger files are streamed: hashing streams the file,
// YARA memory-maps it, and heuristics are skipped with an explicit reason, so a
// multi-gigabyte sample can never make the scanner allocate its full size.
const DefaultMaxInMemory int64 = 64 << 20 // 64 MiB

// detectorAttempts is how many times one detector may run on one file. It is
// bounded because the file is hostile: a panic that repeats must cost a known
// amount, not a loop an attacker can hold open.
const detectorAttempts = 2

// DetectorPanic is a detector that panicked on a file. A crash on crafted input is
// worth a human's attention even when the retry completes, so it is reported
// either way. Recovered says the retry finished and the detector's opinion is in
// the result; when false, the file went without that opinion.
type DetectorPanic struct {
	Detector  string
	Value     string
	Attempts  int
	Recovered bool
}

// Engine runs every configured detector over a file with a single read.
//
// Before the engine existed, each file was opened and parsed up to four times
// (hash, YARA, PE imports, strings). Now the bytes are read once, hashed in
// memory, scanned in memory by libyara and handed to the heuristics as a slice.
//
// The zero value scans with hashes only. An Engine is safe for concurrent use.
type Engine struct {
	// DB is the hash signature database. nil disables hash detection.
	DB *SignatureDB
	// Yara is the compiled ruleset. nil disables YARA.
	Yara *YaraScanner
	// Heuristics enables the string/API heuristic detector.
	Heuristics bool
	// HeuristicThreshold overrides the package default (0 = use
	// HeuristicThreshold).
	HeuristicThreshold int
	// MaxInMemory overrides DefaultMaxInMemory (0 = default).
	MaxInMemory int64
	// Jobs is the number of files scanned concurrently by ScanDirectory
	// (0 = runtime.NumCPU()).
	Jobs int
	// FollowSymlinks makes ScanDirectory scan the targets of symbolic links to
	// regular files. Symlinks to directories are never followed (loop risk).
	FollowSymlinks bool

	// Static enables the structural analysis layer (entropy, fuzzy hashes, PE
	// anatomy and anomalies). Its result rides on ScanResult.Static.
	Static bool
	// StaticThreshold overrides static.Threshold (0 = package default).
	StaticThreshold int
	// FuzzyDB enables TLSH / ssdeep / imphash similarity lookups during the
	// static pass. nil disables them; the digests are still computed.
	FuzzyDB *static.FuzzyDB
	// StaticNoFuzzy skips TLSH/ssdeep computation, the most expensive part of
	// the static pass on large inputs.
	StaticNoFuzzy bool
	// SignerBlocklist flags PE files signed by a known-abused code-signing
	// certificate during the static pass. nil disables the check.
	SignerBlocklist *static.SignerBlocklist

	// Stego enables the invisible-codepoint detector for text and code
	// artifacts. Its result rides on ScanResult.Stego.
	Stego bool
	// StegoThreshold overrides stego.Threshold (0 = package default).
	StegoThreshold int

	// EncChain enables the encoded-executable detector (base64/hex layers
	// decoding to a PE/ELF header). Its result rides on ScanResult.EncChain.
	EncChain bool
	// EncChainThreshold overrides encchain.Threshold (0 = package default).
	EncChainThreshold int

	// LNK enables the Windows Shell Link (.lnk) detector. Its result rides on
	// ScanResult.LNK.
	LNK bool
	// LNKThreshold overrides lnk.Threshold (0 = package default).
	LNKThreshold int

	// OLE enables the OLE compound-file (VBA macro) detector. Its result rides
	// on ScanResult.OLE.
	OLE bool
	// OLEThreshold overrides ole.Threshold (0 = package default).
	OLEThreshold int

	// PDF enables the PDF malicious-document detector. Its result rides on
	// ScanResult.PDF.
	PDF bool
	// PDFThreshold overrides pdf.Threshold (0 = package default).
	PDFThreshold int

	// ISO enables the ISO 9660 malicious-container detector. Its result rides
	// on ScanResult.ISO.
	ISO bool
	// ISOThreshold overrides iso.Threshold (0 = package default).
	ISOThreshold int

	// LinuxPkg enables the Linux software-package detector (.deb/.rpm/Arch/
	// Flatpak/AppImage/PKGBUILD install scripts). Its result rides on
	// ScanResult.LinuxPkg.
	LinuxPkg bool
	// LinuxPkgThreshold overrides linuxpkg.Threshold (0 = package default).
	LinuxPkgThreshold int
	// Intel is the abuse-intelligence feed. When non-nil, indicators found in a
	// package's install scripts are matched against it. nil disables feed
	// matching (the offline default).
	Intel *intel.Feed

	// Peel enables the obfuscation-chain peeler (NOVEL-012). Its result rides
	// on ScanResult.Peel.
	Peel bool
	// PeelThreshold overrides peeler.Threshold (0 = package default).
	PeelThreshold int

	// Archive enables the compressed-container detector (ZIP/TAR/gzip and
	// tar.gz: decompression bombs, Zip-Slip, lure and payload members). Its
	// result rides on ScanResult.Archive.
	Archive bool
	// ArchiveThreshold overrides archive.Threshold (0 = package default).
	ArchiveThreshold int

	// CHM enables the Compiled HTML Help (CHM/ITSS) detector (embedded
	// executables, shortcuts and dangerous scripts). Its result rides on
	// ScanResult.CHM.
	CHM bool
	// CHMThreshold overrides chm.Threshold (0 = package default).
	CHMThreshold int

	// Tradecraft enables the behavioural pass over scripts and payload bytes.
	// Its result rides on ScanResult.Tradecraft.
	Tradecraft bool
	// TradecraftThreshold overrides tradecraft.Threshold (0 = package default).
	TradecraftThreshold int

	// beforeDetector, when set, runs at the start of every detector attempt. It
	// is how a test makes one panic.
	beforeDetector func(name string)

	// NoFusion leaves ScanResult.Fusion nil. Fusion is on by default because
	// it costs nothing: it is a view over results already computed.
	NoFusion bool
}

func (e *Engine) maxInMemory() int64 {
	if e.MaxInMemory > 0 {
		return e.MaxInMemory
	}
	return DefaultMaxInMemory
}

func (e *Engine) jobs() int {
	if e.Jobs > 0 {
		return e.Jobs
	}
	if n := runtime.NumCPU(); n > 0 {
		return n
	}
	return 1
}

func (e *Engine) threshold() int {
	if e.HeuristicThreshold > 0 {
		return e.HeuristicThreshold
	}
	return HeuristicThreshold
}

func (e *Engine) staticThreshold() int {
	if e.StaticThreshold > 0 {
		return e.StaticThreshold
	}
	return static.Threshold
}

func (e *Engine) stegoThreshold() int {
	if e.StegoThreshold > 0 {
		return e.StegoThreshold
	}
	return stego.Threshold
}

func (e *Engine) encChainThreshold() int {
	if e.EncChainThreshold > 0 {
		return e.EncChainThreshold
	}
	return encchain.Threshold
}

func (e *Engine) lnkThreshold() int {
	if e.LNKThreshold > 0 {
		return e.LNKThreshold
	}
	return lnk.Threshold
}

func (e *Engine) oleThreshold() int {
	if e.OLEThreshold > 0 {
		return e.OLEThreshold
	}
	return ole.Threshold
}

func (e *Engine) pdfThreshold() int {
	if e.PDFThreshold > 0 {
		return e.PDFThreshold
	}
	return pdf.Threshold
}

func (e *Engine) isoThreshold() int {
	if e.ISOThreshold > 0 {
		return e.ISOThreshold
	}
	return iso.Threshold
}

func (e *Engine) linuxPkgThreshold() int {
	if e.LinuxPkgThreshold > 0 {
		return e.LinuxPkgThreshold
	}
	return linuxpkg.Threshold
}

func (e *Engine) peelThreshold() int {
	if e.PeelThreshold > 0 {
		return e.PeelThreshold
	}
	return peeler.Threshold
}

func (e *Engine) archiveThreshold() int {
	if e.ArchiveThreshold > 0 {
		return e.ArchiveThreshold
	}
	return archive.Threshold
}

func (e *Engine) chmThreshold() int {
	if e.CHMThreshold > 0 {
		return e.CHMThreshold
	}
	return chm.Threshold
}

func (e *Engine) tradecraftThreshold() int {
	if e.TradecraftThreshold > 0 {
		return e.TradecraftThreshold
	}
	return tradecraft.Threshold
}

// ScanFile runs every configured detector over one file. The heuristic result
// is nil when heuristics are disabled or the file could not be read.
func (e *Engine) ScanFile(path string) (res ScanResult, h *HeuristicResult) {
	start := time.Now()
	res = ScanResult{FilePath: path, Verdict: VerdictClean}

	// Defence in depth: a parser bug on a hostile file must degrade to a
	// per-file error, never crash the scan and lose every other file's
	// result. Whatever a detector had already set (a hash or YARA hit, or a
	// pass that completed) is kept; a file that was still clean becomes an
	// error so it is flagged as unscannable rather than silently clean.
	defer func() {
		if r := recover(); r != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("scan aborted by an internal panic (likely a malformed file): %v", r))
			res.Panics = append(res.Panics, DetectorPanic{Detector: "engine", Value: fmt.Sprint(r), Attempts: 1})
			if res.Verdict == VerdictClean {
				res.Verdict = VerdictError
				if res.Error == nil {
					res.Error = fmt.Errorf("internal panic while scanning %s: %v", path, r)
				}
			}
			res.ScanTime = time.Since(start)
		}
	}()

	fail := func(err error) (ScanResult, *HeuristicResult) {
		res.Error = err
		res.Verdict = VerdictError
		res.ScanTime = time.Since(start)
		return res, nil
	}

	fi, err := os.Stat(path)
	if err != nil {
		return fail(fmt.Errorf("could not stat file: %w", err))
	}
	if fi.IsDir() {
		return fail(fmt.Errorf("%s is a directory", path))
	}
	if !fi.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file (%s)", path, fi.Mode().Type()))
	}
	res.Size = fi.Size()

	// ── one read ────────────────────────────────────────
	// The stat above only routes the file. An attacker writing to the scanned
	// directory can swap it for a FIFO or a device afterwards, so the read itself
	// must not be able to block or run away.
	var data []byte
	var d digests
	if fi.Size() <= e.maxInMemory() {
		data, err = safefs.ReadFile(path, e.maxInMemory())
		switch {
		case errors.Is(err, safefs.ErrTooLarge):
			data = nil // it grew past the limit after the stat: a large file now
		case err != nil:
			return fail(fmt.Errorf("could not read file: %w", err))
		}
	}
	if data != nil {
		res.Size = int64(len(data))
		d = hashBytes(data)
	} else {
		if d, err = hashFile(path); err != nil {
			return fail(err)
		}
	}
	res.MD5, res.SHA1, res.SHA256 = d.md5, d.sha1, d.sha256

	// ── hash detection: SHA256 first, stop at first match ──
	if e.DB != nil {
		for _, c := range []struct{ t, v string }{{"SHA256", d.sha256}, {"SHA1", d.sha1}, {"MD5", d.md5}} {
			if sig, found := e.DB.Lookup(c.v); found {
				res.Detected = true
				res.MatchType = c.t
				res.MatchHash = c.v
				res.ThreatName = sig.ThreatName
				res.Verdict = VerdictMalicious
				break
			}
		}
	}

	// ── every detector at once ─────────────────────────
	// Each reads the same bytes, which none of them writes, and fills only its
	// own field of res, last thing, so a panic leaves nothing behind and a retry
	// starts clean. A detector that panics is run again, and the panic is recorded
	// either way: it costs that detector's opinion at worst and never the verdicts
	// of the others. Fusion is the one real dependency, so it runs after the join.
	var mu sync.Mutex
	note := func(w string) {
		mu.Lock()
		defer mu.Unlock()
		res.Warnings = append(res.Warnings, w)
	}
	attempt := func(name string, detector func()) (panicked any) {
		defer func() { panicked = recover() }()
		if e.beforeDetector != nil {
			e.beforeDetector(name)
		}
		detector()
		return nil
	}
	var wg sync.WaitGroup
	run := func(name string, detector func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := DetectorPanic{Detector: name}
			for p.Attempts < detectorAttempts && !p.Recovered {
				p.Attempts++
				if r := attempt(name, detector); r == nil {
					p.Recovered = true
				} else if p.Value == "" {
					p.Value = fmt.Sprint(r)
				}
			}
			if p.Attempts == 1 && p.Recovered {
				return // it simply ran
			}
			mu.Lock()
			defer mu.Unlock()
			res.Panics = append(res.Panics, p)
		}()
	}

	// ── YARA ───────────────────────────────────────────
	if e.Yara != nil {
		run("yara", func() {
			var matches []YaraMatch
			var yerr error
			if data != nil {
				matches, yerr = e.Yara.ScanMemYaraStrict(data)
			} else {
				matches, yerr = e.Yara.ScanFileYaraStrict(path)
			}
			if yerr != nil {
				// Matches collected before the failure are kept: dropping them
				// would turn a malicious sample into a clean one.
				note(fmt.Sprintf("YARA: %v", yerr))
			}
			if len(matches) > 0 {
				res.YaraMatches = matches
				res.Verdict = VerdictMalicious
			}
		})
	}

	// ── heuristics ─────────────────────────────────────
	if e.Heuristics {
		run("heuristics", func() {
			var hr HeuristicResult
			if data != nil {
				hr = ScanHeuristicsData(path, data, HeuristicOptions{Threshold: e.threshold()})
			} else {
				hr = HeuristicResult{
					FilePath:  path,
					Threshold: e.threshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
			h = &hr
		})
	}

	// ── static / structural ────────────────────────────
	if e.Static {
		run("static", func() {
			if data != nil {
				res.Static = static.Analyze(data, static.Options{
					Threshold:       e.staticThreshold(),
					FuzzyDB:         e.FuzzyDB,
					NoFuzzy:         e.StaticNoFuzzy,
					SignerBlocklist: e.SignerBlocklist,
				})
				res.Static.FilePath = path
			} else {
				res.Static = &static.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.staticThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── stego / invisible codepoints ───────────────────
	if e.Stego {
		run("stego", func() {
			if data != nil {
				res.Stego = stego.Scan(data, stego.Options{Threshold: e.stegoThreshold()})
				res.Stego.FilePath = path
			} else {
				res.Stego = &stego.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.stegoThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── encoded-executable chain ───────────────────────
	if e.EncChain {
		run("encchain", func() {
			if data != nil {
				res.EncChain = encchain.Analyze(data, encchain.Options{Threshold: e.encChainThreshold()})
				res.EncChain.FilePath = path
			} else {
				res.EncChain = &encchain.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.encChainThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Windows Shell Link (.lnk) ──────────────────────
	if e.LNK {
		run("lnk", func() {
			if data != nil {
				res.LNK = lnk.Analyze(data, lnk.Options{Threshold: e.lnkThreshold()})
				res.LNK.FilePath = path
			} else {
				res.LNK = &lnk.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.lnkThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── OLE compound-file (VBA macros) ─────────────────
	if e.OLE {
		run("ole", func() {
			if data != nil {
				res.OLE = ole.Analyze(data, ole.Options{Threshold: e.oleThreshold()})
				res.OLE.FilePath = path
			} else {
				res.OLE = &ole.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.oleThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── PDF malicious-document ─────────────────────────
	if e.PDF {
		run("pdf", func() {
			if data != nil {
				res.PDF = pdf.Analyze(data, pdf.Options{Threshold: e.pdfThreshold()})
				res.PDF.FilePath = path
			} else {
				res.PDF = &pdf.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.pdfThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── ISO 9660 malicious-container ───────────────────
	if e.ISO {
		run("iso", func() {
			if data != nil {
				res.ISO = iso.Analyze(data, iso.Options{Threshold: e.isoThreshold()})
				res.ISO.FilePath = path
			} else {
				res.ISO = &iso.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.isoThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Linux software package (.deb/.rpm/Arch/Flatpak/AppImage) ──
	if e.LinuxPkg {
		run("linuxpkg", func() {
			if data != nil {
				res.LinuxPkg = linuxpkg.Analyze(data, linuxpkg.Options{Threshold: e.linuxPkgThreshold(), Intel: e.Intel})
				res.LinuxPkg.FilePath = path
			} else {
				res.LinuxPkg = &linuxpkg.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.linuxPkgThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── obfuscation-chain peeler ───────────────────────
	if e.Peel {
		run("peel", func() {
			if data != nil {
				pr := peeler.New().Peel(context.Background(), data)
				pr.FilePath = path
				pr.Threshold = e.peelThreshold()
				res.Peel = &pr
			} else {
				res.Peel = &peeler.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.peelThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── compressed container (archive) ─────────────────
	if e.Archive {
		run("archive", func() {
			if data != nil {
				res.Archive = archive.Analyze(data, archive.Options{Threshold: e.archiveThreshold()})
				res.Archive.FilePath = path
			} else {
				res.Archive = &archive.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.archiveThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── Compiled HTML Help (CHM) ───────────────────────
	if e.CHM {
		run("chm", func() {
			if data != nil {
				res.CHM = chm.Analyze(data, chm.Options{Threshold: e.chmThreshold()})
				res.CHM.FilePath = path
			} else {
				res.CHM = &chm.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.chmThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	// ── behaviour: scripts and payload bytes ───────────
	if e.Tradecraft {
		run("tradecraft", func() {
			if data != nil {
				res.Tradecraft = tradecraft.Analyze(data, tradecraft.Options{Threshold: e.tradecraftThreshold()})
				res.Tradecraft.FilePath = path
			} else {
				res.Tradecraft = &tradecraft.Result{
					FilePath:  path,
					Size:      int(fi.Size()),
					Threshold: e.tradecraftThreshold(),
					Skipped: fmt.Sprintf("file is %d bytes, over the %d byte in-memory limit",
						fi.Size(), e.maxInMemory()),
				}
			}
		})
	}

	wg.Wait()
	sort.Slice(res.Panics, func(i, j int) bool { return res.Panics[i].Detector < res.Panics[j].Detector })
	for _, p := range res.Panics {
		if p.Recovered {
			res.Warnings = append(res.Warnings, fmt.Sprintf("detector %s panicked (likely a malformed file) and completed on retry: %s", p.Detector, p.Value))
			continue
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("detector %s gave up after %d attempts on an internal panic (likely a malformed file): %s", p.Detector, p.Attempts, p.Value))
		if res.Verdict == VerdictClean {
			res.Verdict = VerdictError
			if res.Error == nil {
				res.Error = fmt.Errorf("internal panic in detector %s while scanning %s: %s", p.Detector, path, p.Value)
			}
		}
	}

	// ── fusion ─────────────────────────────────────────
	if !e.NoFusion {
		res.Fusion = e.fuse(&res, h)
	}

	res.ScanTime = time.Since(start)
	return res, h
}

// ScanDirectory recursively scans every regular file under root with Jobs
// workers. Results are returned in walk order (deterministic, independent of
// scheduling); the heuristic slice is aligned with the files for which
// heuristics ran. Unreadable entries are reported as error results, not
// dropped. progress, if non-nil, is called after each file completes.
func (e *Engine) ScanDirectory(root string, progress func(done, total int, path string)) ([]ScanResult, []HeuristicResult) {
	type entry struct {
		path string
		err  error
	}
	var entries []entry

	walkErr := filepath.Walk(safefs.WalkRoot(root), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			entries = append(entries, entry{path: path, err: err})
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil // keep walking
		}
		if info.IsDir() {
			return nil
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			if !e.FollowSymlinks {
				return nil
			}
			target, serr := os.Stat(path)
			if serr != nil || !target.Mode().IsRegular() {
				return nil // dangling, or a symlink to a directory: never follow
			}
		} else if !mode.IsRegular() {
			return nil // sockets, fifos, devices
		}
		entries = append(entries, entry{path: path})
		return nil
	})
	if walkErr != nil {
		entries = append(entries, entry{path: root, err: fmt.Errorf("directory walk failed: %w", walkErr)})
	}

	results := make([]ScanResult, len(entries))
	heur := make([]*HeuristicResult, len(entries))

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		done int
		next = make(chan int)
	)
	workers := e.jobs()
	if workers > len(entries) {
		workers = len(entries)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				en := entries[i]
				if en.err != nil {
					results[i] = ScanResult{FilePath: en.path, Verdict: VerdictError, Error: en.err}
				} else {
					results[i], heur[i] = e.ScanFile(en.path)
				}
				if progress != nil {
					mu.Lock()
					done++
					progress(done, len(entries), en.path)
					mu.Unlock()
				}
			}
		}()
	}
	for i := range entries {
		next <- i
	}
	close(next)
	wg.Wait()

	hs := make([]HeuristicResult, 0, len(entries))
	for _, h := range heur {
		if h != nil {
			hs = append(hs, *h)
		}
	}
	return results, hs
}

// SortResults orders results by path. ScanDirectory already returns walk
// order, which is lexical per directory; this is for callers that merged
// several roots.
func SortResults(results []ScanResult) {
	sort.SliceStable(results, func(i, j int) bool { return results[i].FilePath < results[j].FilePath })
}

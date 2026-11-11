package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/report"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/scanner/static"
)

// ── hash ─────────────────────────────────────────────────────────────────────

// hashRecord is the per-file output of `cau hash`.
type hashRecord struct {
	Path    string `json:"path"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Imphash string `json:"imphash,omitempty"`
	// ImportHash is the ELF import-set key (not telfhash); PE files use Imphash.
	ImportHash string `json:"import_hash,omitempty"`
	TLSH       string `json:"tlsh,omitempty"`
	SSDeep     string `json:"ssdeep,omitempty"`
	IsPE       bool   `json:"is_pe"`
	IsELF      bool   `json:"is_elf"`
	Note       string `json:"note,omitempty"`
	Error      string `json:"error,omitempty"`
}

func cmdHash(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "[ERROR] give at least one file")
		fs.Usage()
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "[ERROR] --format must be text or json")
		return report.ExitUsage
	}
	var recs []hashRecord
	failed := 0
	for _, p := range fs.Args() {
		rec := hashRecord{Path: p}
		// One read feeds both the digest and the structural analysis, so the
		// SHA-256 and the metadata that ships next to it always describe the
		// same bytes. Reading the path again for the digest would let a file
		// swapped in between report one file's anatomy under another file's
		// hash, and a read that fails must not leave the record looking
		// complete: the digest is the field every consumer keys on.
		data, err := safefs.ReadFile(p, static.DefaultMaxSize)
		if err != nil {
			rec.Error = err.Error()
			failed++
		} else {
			sum := sha256.Sum256(data)
			r := static.Analyze(data, static.Options{})
			rec.Size = int64(len(data))
			rec.SHA256 = hex.EncodeToString(sum[:])
			rec.Imphash = r.Imphash()
			if r.ELF != nil {
				rec.ImportHash = r.ELF.ImportHash
			}
			rec.TLSH = r.Fuzzy.TLSH
			rec.SSDeep = r.Fuzzy.SSDeep
			rec.IsPE = r.IsPE
			rec.IsELF = r.IsELF
			rec.Note = strings.TrimSpace(strings.Join([]string{r.Fuzzy.TLSHNote, r.Fuzzy.SSDeepNote}, " "))
		}
		recs = append(recs, rec)
	}
	if *format == "json" {
		if err := writeJSON(stdout, recs); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
	} else {
		for _, rec := range recs {
			if rec.Error != "" {
				fmt.Fprintf(stdout, "%s\n  error  : %s\n", report.TermSafe(rec.Path), report.TermSafe(rec.Error))
				continue
			}
			fmt.Fprintf(stdout, "%s (%d bytes)\n", report.TermSafe(rec.Path), rec.Size)
			fmt.Fprintf(stdout, "  sha256 : %s\n", rec.SHA256)
			if rec.Imphash != "" {
				fmt.Fprintf(stdout, "  imphash: %s\n", rec.Imphash)
			}
			if rec.ImportHash != "" {
				fmt.Fprintf(stdout, "  imphash: %s (ELF import-set hash)\n", rec.ImportHash)
			}
			if rec.TLSH != "" {
				fmt.Fprintf(stdout, "  tlsh   : %s\n", rec.TLSH)
			}
			if rec.SSDeep != "" {
				fmt.Fprintf(stdout, "  ssdeep : %s\n", rec.SSDeep)
			}
			if rec.Note != "" {
				fmt.Fprintf(stdout, "  note   : %s\n", rec.Note)
			}
		}
	}
	if failed > 0 {
		return report.ExitScanFailed
	}
	return report.ExitOK
}

// ── add-fuzzy ────────────────────────────────────────────────────────────────

func cmdAddFuzzy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add-fuzzy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "compute TLSH, ssdeep and imphash of this file and add every digest it yields")
	typ := fs.String("type", "", "digest type for --hash: TLSH, SSDEEP or IMPHASH")
	hash := fs.String("hash", "", "digest to add (with --type)")
	name := fs.String("name", "", "threat name (e.g. \"Example Family\")")
	db := fs.String("db", "", "fuzzy database (default: auto-discovered "+relFuzzy+")")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if *name == "" || (*file == "" && (*typ == "" || *hash == "")) {
		fmt.Fprintln(stderr, "[ERROR] --name and either --file or --type + --hash are required")
		fs.Usage()
		return report.ExitUsage
	}
	dbPath, searched := findResource(*db, envFuzzy, relFuzzy)
	if dbPath == "" {
		fmt.Fprintf(stderr, "[ERROR] fuzzy database not found; pass --db (searched: %s)\n", strings.Join(searched, ", "))
		return report.ExitUsage
	}
	type entry struct{ typ, hash string }
	var entries []entry
	if *file != "" {
		r := static.AnalyzeFile(*file, static.Options{})
		if r.Error != nil {
			return fail(stderr, report.ExitRunFailed, "%v", r.Error)
		}
		if r.Skipped != "" {
			return fail(stderr, report.ExitRunFailed, "%s", r.Skipped)
		}
		if r.Fuzzy.TLSH != "" {
			entries = append(entries, entry{static.FuzzyTLSH, r.Fuzzy.TLSH})
		}
		if r.Fuzzy.SSDeep != "" {
			entries = append(entries, entry{static.FuzzySSDeep, r.Fuzzy.SSDeep})
		}
		if imp := r.Imphash(); imp != "" {
			entries = append(entries, entry{static.FuzzyImphash, imp})
		}
		if len(entries) == 0 {
			return fail(stderr, report.ExitRunFailed, "%s yields no fuzzy digest (%s %s)", *file, r.Fuzzy.TLSHNote, r.Fuzzy.SSDeepNote)
		}
	} else {
		entries = append(entries, entry{*typ, *hash})
	}
	added := 0
	for _, e := range entries {
		if err := static.AddFuzzySignature(dbPath, e.typ, e.hash, *name); err != nil {
			fmt.Fprintf(stderr, "[ERROR] %v\n", err)
			continue
		}
		t, h, _ := static.ValidateFuzzy(e.typ, e.hash)
		fmt.Fprintf(stdout, "[+] Added to %s: %s|%s|%s\n", filepath.Clean(dbPath), t, h, strings.TrimSpace(*name))
		added++
	}
	if added == 0 {
		return report.ExitRunFailed
	}
	return report.ExitOK
}

// ── cluster ──────────────────────────────────────────────────────────────────

type clusterDoc struct {
	Files         int               `json:"files"`
	PEFiles       int               `json:"pe_files"`
	ELFFiles      int               `json:"elf_files"`
	Skipped       int               `json:"skipped"`
	MinSimilarity float64           `json:"min_similarity"`
	Clusters      []static.Cluster  `json:"clusters"`
	Imphashes     map[string]string `json:"imphashes,omitempty"`
	// WalkErrors lists the paths the directory walk could not read. Anything
	// under them is absent from Files and from the clusters below, so a
	// complete-looking result with a non-empty list here is a partial one.
	WalkErrors []clusterWalkError `json:"walk_errors,omitempty"`
}

// clusterWalkError is one unreadable path of a cluster walk: the path the walk
// was asked to enter and why it could not.
type clusterWalkError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// cmdCluster groups PE and ELF files by import-table similarity: exact
// import-hash groups (imphash for PE, the import-set hash for ELF) and
// MinHash/LSH near groups. It reads every file once and never executes
// anything; files of other formats are counted and skipped.
func cmdCluster(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cluster", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	minSim := fs.Float64("min-similarity", 0.6, "Jaccard floor for near clusters (0 < x <= 1)")
	withHashes := fs.Bool("imphashes", false, "also list every file's import hash (imphash for PE, import-set hash for ELF)")
	maxMiB := fs.Int64("max-in-memory", static.DefaultMaxSize>>20, "largest file (MiB) to read")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "[ERROR] give at least one file or directory")
		fs.Usage()
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "[ERROR] --format must be text or json")
		return report.ExitUsage
	}
	if *minSim <= 0 || *minSim > 1 {
		fmt.Fprintln(stderr, "[ERROR] --min-similarity must be in (0, 1]")
		return report.ExitUsage
	}

	var paths []string
	var walkErrs []clusterWalkError
	for _, target := range fs.Args() {
		info, err := os.Stat(target)
		if err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		if !info.IsDir() {
			paths = append(paths, target)
			continue
		}
		// An unreadable subtree is not evidence that the files under it are
		// absent. The walk carries on through the siblings, and every path it
		// could not read comes back out with it, so a result missing a
		// directory's contents is reported as the partial result it is
		// instead of passing for a complete cluster of everything present.
		walkErr := filepath.Walk(safefs.WalkRoot(target), func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				walkErrs = append(walkErrs, clusterWalkError{Path: p, Error: err.Error()})
				if fi != nil && fi.IsDir() {
					return filepath.SkipDir // nothing under it is readable either
				}
				return nil
			}
			if fi.Mode().IsRegular() {
				paths = append(paths, p)
			}
			return nil
		})
		// The final error is the walk itself giving up on the root. A SkipDir
		// is this callback's own, already recorded above.
		if walkErr != nil && walkErr != filepath.SkipDir {
			walkErrs = append(walkErrs, clusterWalkError{Path: target, Error: walkErr.Error()})
		}
	}
	sort.Strings(paths)

	doc := clusterDoc{Files: len(paths), MinSimilarity: *minSim}
	if *withHashes {
		doc.Imphashes = map[string]string{}
	}
	cl := static.NewClusterer()
	for _, p := range paths {
		r := static.AnalyzeFile(p, static.Options{NoFuzzy: true, MaxSize: *maxMiB << 20})
		if r.Error != nil || r.Skipped != "" || (!r.IsPE && !r.IsELF) {
			doc.Skipped++
			continue
		}
		if r.IsPE {
			doc.PEFiles++
		} else {
			doc.ELFFiles++
		}
		names := r.ImportNames()
		hash := r.ImportHash()
		cl.Add(static.ClusterItem{ID: p, Imphash: hash, Sig: static.ImportMinHash(names), Imports: len(names)})
		if doc.Imphashes != nil {
			doc.Imphashes[p] = hash
		}
	}
	doc.Clusters = cl.Clusters(*minSim)
	if doc.Clusters == nil {
		doc.Clusters = []static.Cluster{}
	}
	doc.WalkErrors = walkErrs

	if *format == "json" {
		if err := writeJSON(stdout, doc); err != nil {
			return fail(stderr, report.ExitRunFailed, "%v", err)
		}
		// The document records each one; stderr names them as well, because a
		// machine-format run has nothing else on stdout to read.
		for _, we := range doc.WalkErrors {
			fmt.Fprintf(stderr, "[ERROR] %s: %s\n", report.TermSafe(we.Path), report.TermSafe(we.Error))
		}
	} else {
		fmt.Fprintf(stdout, "%d file(s), %d PE, %d ELF, %d skipped (neither PE nor ELF, unreadable or over the size cap)\n", doc.Files, doc.PEFiles, doc.ELFFiles, doc.Skipped)
		if len(doc.WalkErrors) > 0 {
			fmt.Fprintf(stdout, "%d path(s) unreadable, so this is a partial result and the files under them are missing:\n", len(doc.WalkErrors))
			for _, we := range doc.WalkErrors {
				fmt.Fprintf(stdout, "    %s: %s\n", report.TermSafe(we.Path), report.TermSafe(we.Error))
			}
		}
		if len(doc.Clusters) == 0 {
			fmt.Fprintf(stdout, "no clusters at similarity >= %.2f\n", *minSim)
		}
		for _, c := range doc.Clusters {
			switch c.Kind {
			case "imphash":
				fmt.Fprintf(stdout, "\n[%s] %d files share import hash %s\n", c.ID, len(c.Members), c.Imphash)
			default:
				fmt.Fprintf(stdout, "\n[%s] %d files with import similarity >= %.2f\n", c.ID, len(c.Members), c.MinSimilarity)
			}
			for _, m := range c.Members {
				fmt.Fprintf(stdout, "    %s\n", report.TermSafe(m))
			}
		}
		if doc.Imphashes != nil {
			fmt.Fprintln(stdout)
			for _, p := range paths {
				if h, ok := doc.Imphashes[p]; ok {
					fmt.Fprintf(stdout, "%s  %s\n", h, report.TermSafe(p))
				}
			}
		}
	}
	// Files the walk could not reach were never clustered, so the result above
	// is whatever the readable part held: say so and exit as an incomplete scan
	// rather than as a clean one.
	if len(doc.WalkErrors) > 0 {
		return fail(stderr, report.ExitScanFailed, "%d path(s) could not be read; the clustering result is incomplete", len(doc.WalkErrors))
	}
	return report.ExitOK
}

package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/1ungaka/sentinel-edr/internal/eval"
	"github.com/1ungaka/sentinel-edr/internal/eval/scannerbridge"
	"github.com/1ungaka/sentinel-edr/scanner"
	"github.com/1ungaka/sentinel-edr/scanner/encchain"
	"github.com/1ungaka/sentinel-edr/scanner/static"
	"github.com/1ungaka/sentinel-edr/scanner/stego"
)

// The detector setup is shared by every harness subcommand that scans a
// corpus, so the flags, the resource discovery and the "every detector is
// disabled" rule live in one place. A gate that measures a different
// detector set from the one the recall numbers came from would be a gate on
// nothing.

// evalScanFlags are the flags that decide which detectors run and how they
// are tuned.
type evalScanFlags struct {
	db      *string
	rules   *string
	fuzzyDB *string

	noHash     *bool
	noYara     *bool
	noHeur     *bool
	noStatic   *bool
	noStego    *bool
	noEncChain *bool
	noFormats  *bool
	noFusion   *bool

	threshold         *int
	staticThreshold   *int
	stegoThreshold    *int
	encChainThreshold *int
}

// evalScanFlagSet registers the detector flags on a flag set.
func evalScanFlagSet(fs *flag.FlagSet) evalScanFlags {
	return evalScanFlags{
		db:      fs.String("db", "", "signature database (default: <manifest dir>/hashes.txt, else auto-discovered)"),
		rules:   fs.String("rules", "", "YARA rules (default: auto-discovered)"),
		fuzzyDB: fs.String("fuzzy-db", "", "fuzzy signature database for the static detector (default: <manifest dir>/fuzzy.txt, else auto-discovered, else none)"),

		noHash:     fs.Bool("no-hash", false, "disable the hash detector"),
		noYara:     fs.Bool("no-yara", false, "disable the YARA detector"),
		noHeur:     fs.Bool("no-heuristics", false, "disable the heuristic detector"),
		noStatic:   fs.Bool("no-static", false, "disable the static structural detector"),
		noStego:    fs.Bool("no-stego", false, "disable the invisible-codepoint (stego) detector"),
		noEncChain: fs.Bool("no-encchain", false, "disable the encoded-executable detector"),
		noFormats:  fs.Bool("no-format-passes", false, "disable the format passes (.lnk, OLE, PDF, ISO, Linux package, peeler, archive, CHM, tradecraft)"),
		noFusion:   fs.Bool("no-fusion", false, "disable the fusion detector (corroboration of sub-threshold detectors)"),

		threshold:         fs.Int("heuristic-threshold", scanner.HeuristicThreshold, "heuristic detection threshold"),
		staticThreshold:   fs.Int("static-threshold", static.Threshold, "static detection threshold"),
		stegoThreshold:    fs.Int("stego-threshold", stego.Threshold, "stego detection threshold"),
		encChainThreshold: fs.Int("encchain-threshold", encchain.Threshold, "encoded-executable detection threshold"),
	}
}

// evalDetectors builds the detectors the harness runs over a corpus.
//
// The closer releases what the detectors hold (the compiled ruleset); the
// caller defers it. The resources are found the same way the CLI finds them,
// with the manifest's own directory taking precedence, so a corpus that
// ships its own signature database measures itself against its own content.
func evalDetectors(f evalScanFlags, m *eval.Manifest, stderr io.Writer, quiet bool) ([]eval.Detector, func(), error) {
	closer := func() {}
	var db *scanner.SignatureDB
	if !*f.noHash {
		dbPath := *f.db
		if dbPath == "" {
			if local := filepath.Join(m.Dir, "hashes.txt"); fileExists(local) {
				dbPath = local
			} else {
				dbPath, _ = findResource("", envSignatures, relSignatures)
			}
		}
		if dbPath == "" {
			return nil, closer, fmt.Errorf("no signature database found; pass --db or --no-hash")
		}
		var err error
		if db, err = scanner.LoadSignatures(dbPath); err != nil {
			return nil, closer, err
		}
		if !quiet {
			fmt.Fprintf(stderr, "[*] hash: %d signatures from %s\n", db.Count(), dbPath)
		}
	}
	var ys *scanner.YaraScanner
	if !*f.noYara {
		rulesPath, searched := findResource(*f.rules, envRules, relRules)
		if rulesPath == "" {
			return nil, closer, fmt.Errorf("no YARA rules found; pass --rules or --no-yara (searched: %s)", strings.Join(searched, ", "))
		}
		warn := func(format string, a ...interface{}) {
			if !quiet {
				fmt.Fprintf(stderr, "[WARN] "+format+"\n", a...)
			}
		}
		var files int
		var err error
		if ys, files, err = scanner.LoadYaraRules(rulesPath, scanner.WithWarnFunc(warn)); err != nil {
			return nil, closer, fmt.Errorf("YARA: %w", err)
		}
		closer = func() { ys.Close() }
		if !quiet {
			fmt.Fprintf(stderr, "[*] yara: %d rules from %d file(s) at %s\n", ys.RuleCount(), files, rulesPath)
		}
	}
	th := *f.threshold
	if *f.noHeur {
		th = -1
	}
	detectors := scannerbridge.Engine(db, ys, th)
	var fuzzy *static.FuzzyDB
	if !*f.noStatic {
		fuzzyPath := *f.fuzzyDB
		if fuzzyPath == "" {
			if local := filepath.Join(m.Dir, "fuzzy.txt"); fileExists(local) {
				fuzzyPath = local
			} else {
				fuzzyPath, _ = findResource("", envFuzzy, relFuzzy)
			}
		}
		if fuzzyPath != "" {
			var err error
			if fuzzy, err = static.LoadFuzzyDB(fuzzyPath); err != nil {
				closer()
				return nil, closer, err
			}
			if !quiet {
				fmt.Fprintf(stderr, "[*] static: %d fuzzy signatures from %s\n", fuzzy.Count(), fuzzyPath)
			}
		} else if !quiet {
			fmt.Fprintln(stderr, "[*] static: no fuzzy database, similarity lookups off")
		}
		detectors = append(detectors, scannerbridge.StaticDetector(*f.staticThreshold, fuzzy))
	}
	if !*f.noStego {
		detectors = append(detectors, scannerbridge.StegoDetector(*f.stegoThreshold))
	}
	if !*f.noEncChain {
		detectors = append(detectors, scannerbridge.EncChainDetector(*f.encChainThreshold))
	}
	if !*f.noFormats {
		detectors = append(detectors, scannerbridge.PassDetectors()...)
	}
	if !*f.noFusion {
		// The fusion detector runs the same engine the CLI runs and reports
		// only what corroboration adds.
		fe := &scanner.Engine{
			DB:                 db,
			Yara:               ys,
			Heuristics:         !*f.noHeur,
			HeuristicThreshold: *f.threshold,
			Static:             !*f.noStatic,
			StaticThreshold:    *f.staticThreshold,
			FuzzyDB:            fuzzy,
			Stego:              !*f.noStego,
			StegoThreshold:     *f.stegoThreshold,
			EncChain:           !*f.noEncChain,
			EncChainThreshold:  *f.encChainThreshold,
		}
		if !*f.noFormats {
			scannerbridge.EnableFormatPasses(fe)
		}
		detectors = append(detectors, scannerbridge.FusionDetector(fe))
	}
	if len(detectors) == 0 {
		closer()
		return nil, closer, fmt.Errorf("every detector is disabled")
	}
	return detectors, closer, nil
}

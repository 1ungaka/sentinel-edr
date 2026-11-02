# Library usage

The module is `github.com/cau-edr/cau`. The public engine lives under
`scanner/`; `internal/report` and `internal/eval` are internal to the module
(Go forbids importing them from elsewhere), so a program that needs the
reporters or the harness either drives the `cau` binary or vendors the
module.

```sh
go get github.com/cau-edr/cau@latest
```

cgo and libyara are required to build anything that imports `scanner`,
because the YARA binding is linked in. See [Installation](installation.md).

## Scanning

```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cau-edr/cau/scanner"
	"github.com/cau-edr/cau/scanner/static"
)

func main() {
	db, err := scanner.LoadSignatures("signatures/hashes.txt")
	if err != nil {
		log.Fatal(err)
	}
	for _, w := range db.Warnings() { // rejected lines, never silent
		log.Println(w)
	}

	ys, files, err := scanner.LoadYaraRules("rules",
		scanner.WithTimeout(30*time.Second),
		scanner.WithWarnFunc(func(format string, a ...interface{}) { log.Printf(format, a...) }),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer ys.Close()
	log.Printf("%d rules from %d files", ys.RuleCount(), files)

	fuzzy, err := static.LoadFuzzyDB("signatures/fuzzy.txt") // optional
	if err != nil {
		log.Fatal(err)
	}

	engine := &scanner.Engine{
		DB:         db,
		Yara:       ys,
		Heuristics: true,
		Static:     true,
		FuzzyDB:    fuzzy,
		Stego:      true,
		// HeuristicThreshold, StaticThreshold, StegoThreshold: 0 = defaults
		// MaxInMemory: 0 = 64 MiB; larger files stream
		// Jobs: 0 = NumCPU for ScanDirectory
	}

	res, heur := engine.ScanFile("sample.exe")
	if res.Error != nil {
		log.Fatal(res.Error)
	}
	fmt.Println(res.Verdict)                 // MALICIOUS, CLEAN or ERROR (hash + YARA)
	if heur != nil && heur.Detected() {      // the SUSPICIOUS tier is a score
		fmt.Println("heuristic", heur.Score, "/", heur.EffectiveThreshold())
	}
	if res.Static != nil && res.Static.Detected() {
		for _, a := range res.Static.Anomalies {
			fmt.Println(a.Class, a.Score, a.Technique, a.Detail)
		}
	}
	if res.Stego != nil && res.Stego.Detected() {
		fmt.Println(res.Stego.Findings)
	}
	if v := res.Fusion; v != nil {           // the lattice over all of the above
		fmt.Println(v.Tier, v.Score, v.Agreed, v.Techniques, v.Explanation)
	}
}
```

`ScanFile` returns the heuristic result as a second value because heuristics
produce a score, not a verdict. `ScanDirectory(root, progress)` walks a tree
with `Jobs` workers and returns results in walk order regardless of
scheduling; unreadable entries come back as error results, never dropped. An
`Engine` is safe for concurrent use.

Package-level `scanner.ScanFile(path, db, ys)` and `scanner.ScanDirectory`
are thin wrappers over an Engine with hashes and YARA only, kept for
compatibility.

## Individual passes

Each pass can be used on its own, on bytes or on a path:

```go
h := scanner.ScanHeuristicsData("name", data, scanner.HeuristicOptions{})   // or ScanHeuristicsFile
s := static.Analyze(data, static.Options{FuzzyDB: fuzzy})                  // or static.AnalyzeFile
t := stego.Scan(data, stego.Options{})                                      // or stego.ScanFile (import scanner/stego)
```

Digests and clustering:

```go
static.Entropy(data)                      // Shannon entropy, bits per byte
static.ComputeFuzzy(data)                 // TLSH + ssdeep
static.TLSHDistance(a, b)                 // published thresholds: <= 30 is a match
static.SSDeepScore(a, b)                  // >= 70 is a match
pe, err := static.ParsePE(data)           // own bounds-checked parser; pe.Imphash
elf, err := static.ParseELF(data)         // same rules; elf.Imports, elf.ImportHash, elf.Module
```

`scanner.CategoryTechnique(category)` and `scanner.Categories()` expose the
heuristic category → ATT&CK map; `static.Classes()` and `stego.Classes()`
the anomaly and finding class catalogs with weights and techniques;
`ys.RuleInfos()` the compiled rules with namespace, tags and meta
(`RuleInfo.MetaTechnique()` splits `mitre_attack`). Inside the module,
`internal/coverage.Build` turns those into the ATT&CK matrix and
`internal/rulelint.Lint` runs the rule checks; `internal/attack` carries
technique names.

## Fusion on your own sources

The lattice is independent of the engine's detectors. Any detector that can
express itself as a score against a threshold, or as a definitive hit, can
join:

```go
import "github.com/cau-edr/cau/scanner/fusion"

v := fusion.Fuse([]fusion.Source{
	{Name: "hash", Definitive: true, Hit: false},
	{Name: "heuristic", Score: 5, Threshold: 7, Evidence: []fusion.Evidence{{Label: "heuristic/process-injection", Technique: "T1055"}}},
	{Name: "my-sandbox", Score: 3, Threshold: 5, Evidence: []fusion.Evidence{{Label: "sandbox/injects-into-explorer", Technique: "T1055"}}},
})
fmt.Println(v.Tier, v.Score, v.Corroborated, v.Explanation)
// suspicious 1.014 true SUSPICIOUS: heuristic 5/7 + my-sandbox 3/5 (fused 1.01 / 1.00, by corroboration: ...)
```

`fusion.FuseWith(sources, fusion.Params{...})` takes explicit constants;
`fusion.Default` holds the shipped ones. `fusion.Fuse` is the flat weighted sum;
`fusion.FuseChained` — what the engine itself uses — adds the bounded, capped
attack-path chains in `fusion.DefaultChains` (each needs two distinct counted
sources) and records any that fired on `v.Chains`, with `v.ChainBonus` and
`v.ChainEscalated`. Chaining only ever raises the score and never past
`fusion.DefaultChainCap`.

## Reports and the harness from Go

`internal/report` and `internal/eval` are importable only inside this
module. From outside, run the binary and parse its JSON (the schema is
documented in [Output formats](output-formats.md) and versioned), or run
`cau eval run --format json` and read the report. Inside the module (for
example when adding a command), the shapes are:

```go
in := report.Input{Results: results, Heuristics: heuristics, Elapsed: elapsed}
rep, _ := report.NewReporter("sarif", report.WithToolVersion(version), report.WithRoot(dir), report.WithFailOn(report.FailOnHeuristic))
rep.Write(os.Stdout, in)
code := report.NewExitPolicy(report.WithFailOn(report.FailOnHeuristic)).Code(in)

m, _ := eval.LoadManifest("corpus/smoke/manifest.json")
detectors := append(scannerbridge.Engine(db, ys, 0), scannerbridge.StaticDetector(0, fuzzy), scannerbridge.StegoDetector(0))
run, _ := eval.NewRunner(detectors, eval.RunOptions{}).Run(m)
r := eval.NewReport(run)
decision := eval.IsRegression(baseline, r, eval.DefaultPolicy())
```

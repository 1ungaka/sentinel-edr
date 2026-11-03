# Architecture

## The pipeline

```
                 ┌─────────────── one read (≤ 64 MiB in memory, else streamed) ───────────────┐
  file ──────►   │ MD5 / SHA-1 / SHA-256 ──► signature DB ──────────────────► hash hit        │
                 │ libyara in-process (timeout) ───────────────────────────► YARA matches     │
                 │ PE/ELF imports + ASCII/UTF-16 strings ► capped scoring ───► heuristic score  │
                 │ entropy, TLSH/ssdeep/imphash, PE/ELF anatomy ► anomalies ──► static score    │
                 │ UTF-8/UTF-16 decode ──► invisible codepoints + context ──► stego score     │
                 └───────────────────────────────┬────────────────────────────────────────────┘
                                                 ▼
                              fusion lattice: ratios, roles, techniques, tier
                                                 ▼
                      internal/report: text | JSON 1.3.0 | SARIF 2.1.0 + exit policy
                      internal/eval:   corpus runner, metrics, diff, regression gate
```

Before the engine existed, every file was opened and parsed up to four times.
Now `scanner.Engine.ScanFile` reads the bytes once, hashes them in memory,
scans them in memory with libyara and hands the same slice to the heuristic,
static and stego passes. Files over the in-memory limit are streamed: hashing
streams, YARA memory-maps, and the other passes record that they were
skipped and why, so a multi-gigabyte sample never makes the scanner allocate
its size and never looks clean by accident.

## Verdict tiers

| Tier | Produced by | Meaning |
|---|---|---|
| MALICIOUS | hash signature, YARA | the content is known |
| SUSPICIOUS | heuristic, static, stego scores at threshold; fusion by corroboration | evidence with a score and an explanation |
| observed / low suspicion | any sub-threshold evidence | recorded, visible with `--fail-on clean` |
| CLEAN | nothing seen | no detector recorded evidence |
| ERROR | a read failure | a coverage gap, never a clean bill of health |

Scores never promote to MALICIOUS. The lattice never demotes a definitive
hit. Both rules are tested.

## Design rules

- **Measure or don't ship.** Every detector change carries before/after
  numbers on the same fixtures; CI gates the smoke corpus against the
  committed baseline. The numbers behind every claim are listed in
  [Evaluation](evaluation.md).
- **Explain, don't just score.** A heuristic breach names the categories and
  indicators; a static breach names the anomaly classes; a stego breach
  names the codepoints, the line and the context rules; a fused verdict
  names the sources, their roles and their techniques.
- **Never trust the input.** Parsers check every offset against the buffer
  and never panic on hostile input; reporters bound every string that came
  from a file; libyara runs under a timeout.
- **No trust store, and say so.** Authenticode chains are parsed and judged
  for implausibility, never verified; `verified` is always `false` and the
  report carries the note.
- **Honest skips.** A pass that did not run on a file says so, in every
  format, and `--fail-on-scan-error` turns unscanned files into a non-zero
  exit.
- **Standard library for the load-bearing parts.** The reporters and the
  harness have no third-party dependencies; the only external module is the
  YARA binding.
- **Detection content never anchors on attacker-controlled surface.** PDB
  paths, file names and similar strings render as metadata, never as a
  verdict (see the analytic-design rule in PLAN.md).

## Repository layout

```
main.go, cmd_eval.go, cmd_static.go, cmd_coverage.go, cmd_rules.go, resources.go
                       CLI commands and resource discovery
scanner/               Engine (single read), signature DB, YARA, heuristics, fuse.go
scanner/static/        PE, ELF and Mach-O parsers, entropy, fuzzy hashes (incl. telfhash), anomalies, packers, Authenticode, clustering
scanner/stego/         invisible-codepoint pass
scanner/encchain/      encoded-executable pass
scanner/lnk/, ole/, pdf/, iso/   document & container detectors (LNK, OLE/VBA, PDF, ISO)
scanner/linuxpkg/      Linux software-package install-script detector (.deb/.rpm/Arch/Flatpak/AppImage/Docker/Snap)
scanner/fusion/        the fusion lattice (weighted sum + attack-path chaining)
internal/procscan/     read-only live process-table scan (cau ps)
internal/peeler/       obfuscation-chain peeler (cau peel)
internal/harden/       in-process self-protection (memory, privileges, process concealment)
internal/report/       text / JSON / SARIF / OCSF reporters and the exit-code policy
internal/coverage/     ATT&CK coverage matrix, expectation gate, Navigator layer
internal/rulelint/     YARA rule linter
internal/attack/       ATT&CK technique names and tactics for the ids the content uses
internal/eval/         corpus manifest, runner, metrics, diff, regression policy
internal/eval/scannerbridge/
                       adapts the scanner to the harness (the only place both meet)
rules/, signatures/    bundled detection content
corpus/smoke/          committed synthetic corpus
baselines/             baseline report, gate policy, ATT&CK coverage expectation
docs/                  these pages
.github/workflows/     ci.yml: lint + vendor check, race tests, detection gates
                       (rule lint, coverage gate, corpus validation, eval gate),
                       SARIF/OCSF self-scan uploaded to code scanning, a fuzz
                       hunt, signed releases on tags
                       package.yml: the Debian/Kali/Arch packaging proof (build,
                       install, smoke test, attach to the release)
                       wiki.yml: wiki/ -> the GitHub wiki
                       actions/cau-env: the shared Go + libyara + pkg-config
                       environment
```

## The engine / console boundary

This repository is the engine: detection content, the scanning library, the
evaluation harness and (planned) an MCP server, under MIT. Fleet state,
policy, response and the resident sensor are inherently stateful and live in
a separate, proprietary control plane. The split is by persona, not by
withholding features: the engine stays genuinely useful standalone. PLAN.md
has the reasoning and the roadmap.

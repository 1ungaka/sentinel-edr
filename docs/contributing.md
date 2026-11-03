# Contributing

## Development environment

```sh
source scripts/dev-env.sh   # only for a user-local Go / libyara layout
make build                  # ./cau
make lint                   # gofmt + go vet
make test                   # unit tests
make test-race              # with the race detector; the CI `test` lane
make bench                  # YARA, heuristics, static and stego benchmarks
make eval                   # validate the smoke corpus, run it, gate against the baseline
make ci                     # lint + build + race tests + eval; the local aggregate
```

`.github/workflows/ci.yml` runs these same targets as six named, time-bounded
lanes (`lint`, `test`, `gates`, `selfscan`, `fuzz`, `release`) instead of one
serial `make ci` job, and the packaging proof
(`.github/workflows/package.yml`) is a separate workflow.

Go 1.24, libyara 4.3 with headers and pkg-config are required; see
[Installation](installation.md).

## The rules

1. **Measure or don't ship.** A change to a detector, a weight, a threshold
   or a content file lands with before/after numbers on the same fixtures.
   The smoke corpus gate (`make eval`) is the floor; the real-binary sets the
   existing numbers were measured on (Kali's `/usr/share/windows-resources`,
   `/usr/share/doc`, `/usr/lib/python3/dist-packages`, and for ELF the
   system's own `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`,
   `/usr/libexec`, `/usr/lib/systemd` plus decompressed kernel modules) are
   the bar. `go test ./scanner/static/ -run TestMeasureReal -v` prints the
   per-file scores for both populations. Record the result where the detector
   is documented and in PLAN.md.
2. **Explain every finding.** New evidence gets a stable, labeled class
   (`section.rwx`, `stego.zero-width`), a weight, a category, and an ATT&CK
   technique where one honestly applies. Reports, SARIF rule ids, the eval
   harness and fused verdicts key on those labels; renaming one breaks
   baselines. New static classes go in `static.Classes()` (a test fails
   otherwise); a new technique id fails `make coverage-gate` until it is
   recorded in `baselines/attack-coverage.txt` with `make coverage-record`,
   and every detector change is reflected in its [ADS](ads/README.md).
3. **Synthetic fixtures only.** Nothing in this repository is built from a
   real sample. PE fixtures are constructed in the tests (`scanner/static/pe_test.go`);
   text fixtures are prose. Real corpora are referenced by hash and URL from
   manifests that live outside git.
4. **Detection only.** This repository implements detection rows, never the
   techniques they detect: no implant code, no weaponisation, no bypass
   engineering in any framing. Technique knowledge enters only as public
   definitions, synthetic fixtures and coverage states. A task that straddles
   the boundary is refused, not split.
5. **Honest output.** A pass that did not run says so. A score never becomes
   a MALICIOUS verdict. A fused verdict never lowers a detector's own.
6. **Never panic on hostile input.** The PE, ELF and Mach-O parsers, the
   document/container and Linux-package passes, and the stego and
   heuristic passes read attacker-controlled bytes; a crash is a denial of
   service. Every such entry point has a `Fuzz*` target (`make fuzz`), and
   `Engine.ScanFile` recovers per file so one bad file cannot drop a whole
   directory scan. A fuzz crasher is committed as a seed under
   `testdata/fuzz/` and fixed before merge.
7. **Standard library** for reporters and the harness; the YARA binding is
   the only third-party module.

## Tests to expect

- `scanner/`: engine single-pass equivalence, streaming over the in-memory
  limit, directory walking, symlink policy, signature DB validation, YARA
  loading and timeouts, heuristic fixtures that pin the measured tool-set
  numbers, fusion wiring.
- `scanner/static/`: synthetic PE builder (headers, imports, Rich header, TLS,
  Authenticode) and synthetic ELF builder (32/64-bit, both byte orders,
  dynamic table, symbols, notes, kernel-module shape, malformed tables)
  covering every anomaly class and the measured non-findings; a mutation test
  that flips header bytes of real and synthetic ELF images and requires no
  panic; `TestWriteELFFixtures`, which regenerates the corpus ELF samples.
- `scanner/stego/`: every class, every context rule, UTF-16, hostile input,
  bounded examples.
- `scanner/fusion/`: roles, definitive handling, cap, floor, stable ordering,
  randomized monotonicity.
- `internal/report/`: a text golden, JSON shape, SARIF structural invariants,
  the exit-code matrix, hostile strings.
- `internal/eval/`: manifest validation, metrics, diff, policy, persistence,
  and a bridge test that requires 100 % recall and 0 false positives on the
  smoke corpus.

## Adding a detector

1. Produce a result type with a score, a threshold, a `Skipped` reason and
   labeled findings; put it under `scanner/<name>/`.
2. Run it from `scanner.Engine.ScanFile` on the already-read buffer and
   attach it to `ScanResult`.
3. Add it as a `fusion.Source` in `scanner/fuse.go` with evidence labels and
   techniques.
4. Render it in `internal/report` (text, JSON with a minor schema bump, SARIF
   rule ids, exit policy) and add it to `Input`'s breach helpers.
5. Add a `scannerbridge` detector and `cau eval run` flag, extend the smoke
   corpus with synthetic positives and benign controls, re-record the
   baseline, and write down the measurement.

## Pull requests

- `make ci` passes locally.
- Documentation under `docs/` and the CHANGELOG are updated with the change.
- Commits describe what was measured, not only what was changed.

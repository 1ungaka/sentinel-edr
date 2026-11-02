# Evaluation harness

Nothing about detection should change without a number. `cau eval` runs a
labelled corpus through the detectors and reports precision, recall,
false-positive rate, per-detector, per-family and per-rule breakdowns, the
exact files on the wrong side of the line, and a performance profile. A
**policy** turns the comparison with a baseline into a CI gate.

```sh
cau eval validate --corpus corpus/smoke/manifest.json --verify-hashes
cau eval run      --corpus corpus/smoke/manifest.json --rules rules --out report.json
cau eval diff     baselines/smoke.json report.json
cau eval gate     --baseline baselines/smoke.json --candidate report.json --policy baselines/policy.json
cau eval policy
```

`make eval` runs validate → run → gate against the committed baseline and CI
runs it on every push. `make baseline` re-records `baselines/smoke.json`;
review the diff before committing it.

## Corpora

A corpus is a directory of samples described by a `manifest.json`. The
harness never infers anything from file names or directory layout: if it is
not in the manifest, it is not in the corpus.

```json
{
  "schema_version": "1",
  "name": "smoke",
  "description": "free text",
  "root": "optional base directory; defaults to the manifest's directory",
  "defaults": { "label": "", "family": "", "source": "synthetic", "license": "MIT" },
  "samples": [
    {
      "id": "mal-wannacry_strings",
      "path": "malicious/wannacry_strings.bin",
      "label": "wannacry",
      "family": "wannacry",
      "sha256": "67752ad7…",
      "tags": ["optional"],
      "notes": "optional",
      "provenance": { "source": "malwarebazaar", "url": "https://…", "license": "CC-BY-SA-4.0", "retrieved": "2026-10-24T00:00:00Z" }
    }
  ]
}
```

- Unknown fields are rejected; paths are relative to the root and must not
  escape it.
- `clean` (aliases benign, good, negative, safe) is the only benign label.
  Every other label is a malware family and counts as a positive; `family`
  defaults to the label.
- A sample without a label and without a default label is an error, never a
  guess.
- Declare `sha256` for every sample; `--verify-hashes` recomputes them and
  fails on drift, because a corpus whose bytes changed under a stable manifest
  produces numbers nobody can reproduce.
- Malware samples should record provenance (source, URL, licence). A missing
  source is a warning by default and an error with `--require-provenance`.
  Benign samples should come from a verifiable build: "clean" must be known,
  not assumed.

### Specificity and recall are measured separately

They are different questions, measured on different corpora, and conflating
them is the most common way a scanner flatters itself:

- **Specificity** — the false-positive side, and now the near-miss margin — is
  measured on a large **clean** population: a real machine's files, none of
  them malware. The published figures (0.020 % encoded-executable hits over
  159,339 files, the stego and static rates) all come from scanning a Kali
  install. `scripts/clean-manifest.sh <root>` labels a directory tree as a
  `clean` corpus so `cau eval` produces those numbers, including the near-miss
  histogram, over the real population. A clean corpus says nothing about what
  the engine *catches*.

- **Recall** — the miss rate — is measured on a **held-out** corpus of real
  malware the detectors were **not** authored from. Measuring recall on the
  samples the rules were written to match (as the `smoke` corpus is, by
  construction) is the corpus-scale version of the failure the per-rule
  mutation harness (`scanner/robustness_test.go`) exists to catch: a rule that
  passes on the sample it was written from. A recall number is only honest
  against bytes the rules have never seen.

### The held-out recall corpus

`corpus/heldout` holds that set. Its sample identities and threat intel live
in an **encrypted** database, `corpus/heldout/hashes.db` (AES-256-GCM, a
PBKDF2-derived key): the hash list is sensitive and a standing temptation to
tune against, so only the ciphertext is committed, never the hashes or the
samples. `cau heldout` manages it:

```sh
export CAU_HELDOUT_KEY=...                 # or --key-file
cau heldout init
cau heldout pull --source full             # full MalwareBazaar DB + intel, resumable
cau heldout list
```

`pull` downloads the MalwareBazaar CSV export (hashes plus intel: signature,
tags, file type, first-seen, reporter) and ingests it incrementally,
checkpointing the encrypted database every `--batch` new records, resuming an
interrupted download with an HTTP Range request, and skipping hashes already
present — so it is fast, and a crashed run self-recovers rather than starting
over. `scripts/fetch-heldout.sh` then downloads the sample bytes by SHA-256,
verifies each hash, keeps the files non-executable, and writes the live scan
manifest. `make eval-recall` runs the corpus when it is present. See
[`corpus/heldout/README.md`](../corpus/heldout/README.md); the one rule that
keeps the number meaningful is never to author or tune a detector against a
sample in it.

Never commit live malware. The harness only reads bytes; it never executes
anything. Keep samples non-executable on disk and scan from an isolated VM.
Add benign samples in the proportion you expect in production if you want a
precision number too: a corpus that is 95 % malware makes every detector look
precise.

### The smoke corpus

`corpus/smoke` is synthetic and committed: plain-text files carrying the
strings the shipped rules look for, one file detected only through
`corpus/smoke/hashes.txt`, one Markdown file with stray zero-width codepoints
between its words (nothing is encoded in them), and benign controls that use
the same invisible codepoints legitimately (emoji sequences, Persian ZWNJ,
Devanagari ZWJ, a byte-order mark, UTF-16 text), and two ELF images that
`scanner/static`'s `TestWriteELFFixtures` regenerates byte-for-byte: a clean
PIE and a file with a dropper's structure (RWX packed code, a program
interpreter under `/tmp`, `dlopen`/`dlsym`-only imports) whose bytes are
pseudo-random and run nothing; it is the structural pass's own true positive.
The engine must reach 100 % recall and 0 false positives on it; a test
enforces that. It proves the plumbing; recall numbers against it are not
detection-quality numbers.

## Reports

A run produces a JSON report (`--out`) with the run metadata (tool, corpus,
detectors, concurrency, error mode), one entry per sample with its verdict
and the signals that fired (detector, rule, family, detail), the confusion
matrix and the derived ratios, per-detector statistics (true and false
positives, recall, FPR, and how many detections were *exclusive* to that
detector), per-family recall, per-rule fires with their false positives, the
lists of false positives, false negatives, errors and skipped samples, and a
performance profile (total and per-sample scan time, p50 / p95 / max,
throughput, the slowest samples). `cau eval report` renders a saved report
as text or JSON.

Signals are the unit of attribution. A detector that returns SUSPICIOUS
without naming a rule contributes to the confusion matrix but nothing to the
triage lists, and the composite "engine" detector reports per-detector
attribution on top of the overall verdict.

### Near misses

The report also carries a `near_miss` section: for each scored detector
(`heuristic`, `static`, `stego`, `encchain`), how close the benign samples
came to firing without crossing the line. A clean corpus can only ever count
the false positives it already has; it cannot, on its own, say how close it
came to more. The near-miss metric answers that — the count of benign files
the detector scored but did not fire on, the width of the "near" band (a
quarter of the threshold), how many fell inside it, the single closest margin,
and the full margin histogram. A detector whose nearest benign file sits one
point under the threshold is one tuning change away from a false-positive
storm; one whose nearest benign file is far below has headroom. Each scored
bridge detector records its sub-threshold score for every file (see
`internal/eval/scannerbridge`), so this is measured, not estimated. Binary
detectors (`hash`, `yara`, `fusion`) have no score and no margin, so they do
not appear.

## Diff and gate

`cau eval diff` reports the change between two reports: recall and precision
in points, false positives and negatives before and after, per-detector and
per-family deltas, and scan-time change. `cau eval gate` applies a policy to
that diff and exits 1 on a violation. The built-in policy
(`cau eval policy`):

```json
{
  "max_recall_drop": 0,
  "max_fpr_increase": 0,
  "max_new_false_positives": 0,
  "max_error_increase": 0,
  "perf": { "max_total_duration_increase_pct": 50 }
}
```

Performance rules are skipped when the baseline run is shorter than one
second (`perf.min_baseline_duration_ms`), because millisecond runs are noise.
Per-detector and per-family rules can be added to a policy file passed with
`--policy`. Example gate output when YARA is disabled by mistake:

```
recall -60.00 pt, precision +0.00 pt, false positives 0 → 0, false negatives 0 → 3
gate: FAIL (1 violation(s))
  ✗ [overall] max_recall_drop: dropped 60.00 pt, at most 0.00 pt allowed (baseline 100.00%, candidate 40.00%)
```

### The content gates beside it

Two more gates run in CI next to the eval gate and fail the build the same
way. `make lint-rules` runs `cau rules lint` over the bundled rules: a rule
that does not compile, lacks its meta, or carries a string that can never
match is an error. `make coverage-gate` runs `cau coverage --expect
baselines/attack-coverage.txt`: the ATT&CK techniques the content maps to
must equal the recorded expectation, so a detector change that drops a
technique is a regression and a rule that adds one has to be recorded with
`make coverage-record`. See [Detection engineering](detection-engineering.md).

## Detectors in the harness

| Name | Fires when | Signals |
|---|---|---|
| `hash` | a signature matches | the threat name, family from its first word |
| `yara` | a rule matches | the rule, its `family` meta, tags and threat level |
| `heuristic` | the score reaches the threshold | `heuristic/score` plus one `heuristic/<category>` per category |
| `static` | the static score reaches the threshold | `static/score`, one `static/<class>` per scored anomaly, `static/fuzzy/<type>` per similarity match |
| `stego` | the stego score reaches the threshold | `stego/score` plus one `stego/<class>` per scored finding |
| `fusion` | the fused verdict is suspicious **by corroboration only** | `fusion/corroborated` plus `fusion/agreed/<source>` |

The fusion detector runs the whole engine but reports nothing a single
detector would have reported itself, so its per-detector row is exactly what
the lattice adds.

## Measurements so far

Numbers quoted in the documentation and where they come from:

| Claim | Set | Result |
|---|---|---|
| heuristic retune | 349 files, `/usr/share/windows-resources` | detections 60 → 28; plink 24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4; credential dumpers and injectors kept |
| static weights | 49 PE files in the same set | 43 score 0; UPX-packed `wget.exe` 7, ASPack-packed `klogger.exe` 6, both below the threshold with the packer named |
| static ELF weights | 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`, `/usr/lib/systemd`; 40 signed kernel modules (`scanner/static` `TestMeasureRealELF`) | 0 reach the threshold; 21 carry one weight-1 class; every module scores 0; UPX-packed `ls` 6 |
| heuristic ELF imports | 4,729 ELF files in the same roots | 1 file gains a heuristic detection through its import table and it is a Kali-shipped offensive tool; `sudo` (ptrace + `process_vm_*`) stays at 6 |
| static throughput | 1.3 MB binary | 44 MB/s with fuzzy hashing, 180 MB/s without |
| stego false positives | 70,102 benign text artifacts under `/usr/share/doc` and `/usr/lib/python3/dist-packages` | 70 detections (0.10 %), 348 legitimate uses excused; 0 of 294 text files in the Windows tool set |
| fusion | 349 files, the Windows tool set | 0 fused-only detections, 0 new false positives |
| bundled YARA rules | the Windows tool set and `/usr/bin` | fire on mimikatz, wce, PowerSploit and `ophcrack`, nothing else |

The honest caveat on all of these: they are fixture-derived numbers from one
machine's package set. Field false-positive rates need the real corpus that
Phase 1 of the plan still lists as open.

# Command-line reference

```
cau scan      [flags] [path ...]     scan files and directories
cau hash      [flags] <path ...>     print SHA-256, imphash, TLSH and ssdeep digests
cau cluster   [flags] <path ...>     group PE and ELF files by import-table similarity
cau add-hash  [flags]                append a hash signature to the database
cau add-fuzzy [flags]                append a TLSH / ssdeep / imphash signature
cau eval      <subcommand> [flags]   corpus evaluation harness
cau version                          print the version
cau help                             this text
```

Every command accepts `--help` and prints its own flags. Flags take one dash
or two (`-quiet`, `--quiet`). The banner and progress lines always go to
stderr; reports go to stdout or `--output`, so machine formats are safe to
pipe.

## cau scan

Scans files and directories with every configured detector and writes one
report.

```sh
cau scan --file suspicious.exe
cau scan --dir ./downloads
cau scan ./build ./dist --format json --output report.json
cau scan --dir . --format sarif --output cau.sarif --fail-on none
cau scan --dir / --jobs 16 --no-heuristics --no-static --quiet
```

Positional arguments, `--file` and `--dir` can be combined; directories are
walked recursively. Sockets, devices and FIFOs are skipped; symbolic links to
files are followed only with `--follow-symlinks`, symbolic links to
directories never.

### Targets and resources

| Flag | Meaning |
|---|---|
| `--file PATH` | a single file (positional paths are accepted too) |
| `--dir PATH` | a directory to scan recursively; also sets the SARIF source root |
| `--db PATH` | signature database (default: auto-discovered) |
| `--rules PATH` | YARA rule file or directory (default: auto-discovered) |
| `--fuzzy-db PATH` | fuzzy signature database (default: auto-discovered, optional) |

### Detectors and thresholds

| Flag | Default | Meaning |
|---|---|---|
| `--no-yara` | off | disable YARA |
| `--no-heuristics` | off | disable the string and API heuristics |
| `--no-static` | off | disable the static structural pass |
| `--no-fuzzy` | off | keep the static pass but skip TLSH / ssdeep (faster on large files; disables similarity lookups) |
| `--no-stego` | off | disable the invisible-codepoint pass |
| `--no-encchain` | off | disable the encoded-executable pass |
| `--no-lnk` | off | disable the Windows Shell Link (.lnk) pass |
| `--no-ole` | off | disable the OLE compound-file (VBA macro) pass |
| `--no-pdf` | off | disable the PDF malicious-document pass |
| `--no-iso` | off | disable the ISO 9660 malicious-container pass |
| `--no-fusion` | off | disable the fusion lattice |
| `--heuristic-threshold N` | 7 | heuristic score at which a file is SUSPICIOUS |
| `--static-threshold N` | 8 | static anomaly score at which a file is SUSPICIOUS |
| `--stego-threshold N` | 4 | stego score at which a text artifact is SUSPICIOUS; 4 is presence-based, 8 requires a modifier |
| `--encchain-threshold N` | 8 | encoded-executable score at which a file is SUSPICIOUS |
| `--lnk-threshold N` | 8 | Shell Link score at which a file is SUSPICIOUS |
| `--ole-threshold N` | 8 | OLE macro score at which a file is SUSPICIOUS |
| `--pdf-threshold N` | 8 | PDF document score at which a file is SUSPICIOUS |
| `--iso-threshold N` | 8 | ISO container score at which a file is SUSPICIOUS |
| `--yara-timeout D` | 30s | per-file YARA budget; a timed-out scan keeps the matches it found and records a warning |
| `--max-in-memory MiB` | 64 | larger files are streamed: hashing streams, YARA memory-maps, the heuristic, static and stego passes are skipped with the reason recorded |
| `--jobs N` | CPUs | files scanned concurrently |
| `--follow-symlinks` | off | scan the targets of symbolic links to files |

Hash signatures cannot be turned off: a signature database is required.

### Output and exit code

| Flag | Default | Meaning |
|---|---|---|
| `--format text\|json\|sarif` | text | report format, see [Output formats](output-formats.md) |
| `--output PATH` | stdout | write the report to a file |
| `--pretty` | off | indent JSON and SARIF |
| `--fail-on none\|malicious\|heuristic\|clean` | malicious | the finding level that produces exit code 1 |
| `--no-fail-on-scan-error` | off | do not exit 2 when some files could not be read |
| `--quiet` | off | no banner or progress on stderr |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing at or above the `--fail-on` level |
| 1 | at least one finding at or above the `--fail-on` level |
| 2 | the run completed but at least one file could not be scanned (unless `--no-fail-on-scan-error`); an unscanned file must never look clean |
| 3 | the run itself failed: unreadable signature database, rules that do not compile, unwritable output. A JSON or SARIF document is still written when possible |
| 4 | usage error |

Precedence, highest first: run failure, scan errors, findings. The `--fail-on`
levels are supersets of each other:

| Level | Exit 1 on |
|---|---|
| `none` | never on findings (errors still fail) |
| `malicious` | a hash-signature hit or a YARA match |
| `heuristic` | ... or a heuristic, static or stego score at its threshold, or a fused verdict reached by corroboration |
| `clean` | ... or any sub-threshold heuristic or static observation; the run must be spotless |

## cau hash

Prints the digests the static pass computes: SHA-256, imphash (PE,
pefile-compatible) or the ELF import-set hash (MD5 over the sorted undefined
symbol names, labeled as such; not telfhash), TLSH and ssdeep.

```sh
cau hash plink.exe
cau hash --format json a.exe b.dll
```

| Flag | Meaning |
|---|---|
| `--format text\|json` | output format |

## cau cluster

Groups PE and ELF files by import-table similarity: exact import-hash groups
first (imphash for PE, the import-set hash for ELF), then MinHash / LSH
clusters over the import sets with a Jaccard floor. Files of other formats
are counted and skipped.

```sh
cau cluster --dir ./samples
cau cluster --min-similarity 0.8 --imphashes a.exe b.exe c.exe
```

| Flag | Default | Meaning |
|---|---|---|
| `--min-similarity X` | 0.6 | Jaccard floor for near clusters (0 < x ≤ 1) |
| `--imphashes` | off | also list every file's import hash |
| `--format text\|json` | text | output format |

## cau add-hash

Appends a validated signature to the hash database. The type is inferred
from the digest length when `--type` is omitted. Duplicates and conflicting
re-labels are refused instead of silently overwriting.

```sh
cau add-hash --hash <sha256> --name "WannaCry Ransomware"
cau add-hash --type md5 --hash 84c82835a5d21bbcf75a61706d8ab549 --name "WannaCry Ransomware"
```

| Flag | Meaning |
|---|---|
| `--hash HEX` | the digest |
| `--type MD5\|SHA1\|SHA256` | digest type (default: from the length) |
| `--name TEXT` | threat name; no `\|` or line breaks |
| `--db PATH` | database (default: auto-discovered) |

## cau add-fuzzy

Appends TLSH, ssdeep or imphash entries to the fuzzy database, either
computed from a file or given explicitly.

```sh
cau add-fuzzy --file sample.bin --name "Example Family"      # every digest the file yields
cau add-fuzzy --type tlsh --hash T1... --name "Example Family"
```

| Flag | Meaning |
|---|---|
| `--file PATH` | compute TLSH, ssdeep and imphash of this file and add each |
| `--type TLSH\|SSDEEP\|IMPHASH` | digest type for `--hash` |
| `--hash DIGEST` | digest to add |
| `--name TEXT` | threat name |
| `--db PATH` | fuzzy database (default: auto-discovered `signatures/fuzzy.txt`) |

## cau eval

The evaluation harness. See [Evaluation](evaluation.md) for the concepts;
this is the flag reference.

```
cau eval validate  check a corpus manifest: paths, labels, hashes, provenance
cau eval run       scan a corpus and write a measured report (optionally gate it)
cau eval report    render a saved report as text or JSON
cau eval diff      compare two reports
cau eval gate      fail (exit 1) when a candidate report regresses against a baseline
cau eval policy    print the default regression policy as JSON
```

Exit codes: 0 ok, 1 validation errors or gate failed, 3 the run failed, 4
usage error.

### cau eval validate

| Flag | Meaning |
|---|---|
| `--corpus PATH` | corpus manifest (required) |
| `--verify-hashes` | recompute SHA-256 of samples that declare one |
| `--require-provenance` | malware samples without a provenance source are errors, not warnings |
| `--max-file-size N` | warn about samples larger than N bytes |
| `--json` | print the validation result as JSON |

### cau eval run

| Flag | Default | Meaning |
|---|---|---|
| `--corpus PATH` | | corpus manifest (required) |
| `--db PATH` | `<manifest dir>/hashes.txt`, else auto-discovered | signature database |
| `--rules PATH` | auto-discovered | YARA rules |
| `--fuzzy-db PATH` | `<manifest dir>/fuzzy.txt`, else auto-discovered, else none | fuzzy database |
| `--no-hash`, `--no-yara`, `--no-heuristics`, `--no-static`, `--no-encchain`, `--no-stego`, `--no-fusion` | | disable a detector |
| `--heuristic-threshold`, `--static-threshold`, `--stego-threshold` | 7, 8, 4 | thresholds |
| `--jobs N` | CPUs | samples scanned concurrently |
| `--on-error exclude\|miss\|fail` | exclude | unscannable samples: leave out, count as false negatives, or abort |
| `--max-file-size N` | | skip samples larger than N bytes |
| `--out PATH` | | write the JSON report (this is what a baseline is) |
| `--format text\|json` | text | stdout rendering |
| `--baseline PATH` | | also gate the run against this report |
| `--policy PATH` | built-in | regression policy for `--baseline` |
| `--verify-hashes` | true | validate the corpus with hash verification before running |
| `--quiet` | | no progress |

The `fusion` detector in an eval run reports only verdicts reached by
corroboration, so its per-detector row is the lattice's own contribution.

### cau eval report, diff, gate

```sh
cau eval report --report report.json [--format json]
cau eval diff   --baseline a.json --candidate b.json [--format json]     # or: cau eval diff a.json b.json
cau eval gate   --candidate b.json [--baseline a.json] [--policy p.json] [--format json]
```

`gate` without `--baseline` applies only the policy's absolute rules.

## cau rules

```sh
cau rules lint [--rules path] [--profile cau|generic] [--format text|json] [--strict]
cau rules list [--rules path] [--format text|json]
```

`lint` compiles the rules and reports, per rule and line: compile errors and
compiler warnings, missing `description` / `author` / `threat_level` (1-5) /
`family` / `mitre_attack` meta, malformed technique ids, text strings that
are hex written as text (`"0x89,0x00"` never matches bytes), strings under
four bytes, text strings without `wide`, and conditions that match every
file. Errors exit 1; `--strict` makes warnings fatal. The `generic` profile
drops the bundled-content conventions (`family`, `wide`, naming) for
third-party rule sets such as signature-base. `list` prints every compiled
rule with namespace, level, family, technique and description.

## cau coverage

```sh
cau coverage [--rules path] [--no-yara] [--db path] [--fuzzy-db path]
             [--format text|json|navigator|sarif] [--pretty] [--output file]
             [--expect file] [--record] [--include-info]
```

Builds the ATT&CK coverage matrix of the shipped content: for every
technique id, the detectors and content entries that are evidence for it;
content with no technique is listed as unmapped. `--format navigator` writes
an ATT&CK Navigator layer (score = number of independent detectors);
`--format sarif` writes a SARIF 2.1.0 log with one rule and result per
technique, so a code-scanning dashboard shows the coverage map and treats a
planned gap as a warning. `--expect` compares the matrix to a committed
expectation file (`baselines/attack-coverage.txt`, one row per technique:
`<id> covered|partial|gap|none [note]`) and exits 1 on any difference;
`--record` rewrites that file from the content, keeping its partial, gap and
none rows. The four states render as detected, partial (covered but
acknowledged incomplete), planned (an expectation `gap`) and none (owned by
the sensor or console). Exit codes: 0 ok, 1 expectation differs, 3 failed, 4
usage.

## CI recipes

GitHub Actions, uploading findings to code scanning:

```yaml
- run: ./cau scan --dir . --format sarif --output cau.sarif --fail-on none --quiet
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cau.sarif
```

Fail a build on anything suspicious, but tolerate unreadable files:

```sh
cau scan --dir ./dist --fail-on heuristic --no-fail-on-scan-error --quiet --format json --output report.json
```

Gate detection changes against the committed baseline (what this repository's
CI does):

```sh
make eval      # validate -> run -> gate
```

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
| `--signers <file>` | off | known-abused code-signing certificate blocklist (lolcerts); flags PE files signed by a listed cert |
| `--no-stego` | off | disable the invisible-codepoint pass |
| `--no-encchain` | off | disable the encoded-executable pass |
| `--no-lnk` | off | disable the Windows Shell Link (.lnk) pass |
| `--no-ole` | off | disable the OLE compound-file (VBA macro) pass |
| `--no-pdf` | off | disable the PDF malicious-document pass |
| `--no-iso` | off | disable the ISO 9660 malicious-container pass |
| `--no-peel` | off | disable the obfuscation-chain peeler (NOVEL-012) |
| `--no-fusion` | off | disable the fusion lattice |
| `--heuristic-threshold N` | 7 | heuristic score at which a file is SUSPICIOUS |
| `--static-threshold N` | 8 | static anomaly score at which a file is SUSPICIOUS |
| `--stego-threshold N` | 4 | stego score at which a text artifact is SUSPICIOUS; 4 is presence-based, 8 requires a modifier |
| `--encchain-threshold N` | 8 | encoded-executable score at which a file is SUSPICIOUS |
| `--lnk-threshold N` | 8 | Shell Link score at which a file is SUSPICIOUS |
| `--ole-threshold N` | 8 | OLE macro score at which a file is SUSPICIOUS |
| `--pdf-threshold N` | 8 | PDF document score at which a file is SUSPICIOUS |
| `--iso-threshold N` | 8 | ISO container score at which a file is SUSPICIOUS |
| `--peel-threshold N` | 50 | obfuscation-chain score at which a file is SUSPICIOUS (a depth-2 revealed chain scores 60) |
| `--yara-timeout D` | 30s | per-file YARA budget; a timed-out scan keeps the matches it found and records a warning |
| `--max-in-memory MiB` | 64 | larger files are streamed: hashing streams, YARA memory-maps, the heuristic, static and stego passes are skipped with the reason recorded |
| `--jobs N` | CPUs | files scanned concurrently |
| `--follow-symlinks` | off | scan the targets of symbolic links to files |
| `--quarantine` | off | **prevention**: after scanning, move files with a MALICIOUS verdict into the vault (hash/YARA tier only; never sub-threshold suspicions) |
| `--quarantine-store <dir>` | default vault | vault directory for `--quarantine` |
| `--interval <dur>` | 0 (one-shot) | **daemon mode**: re-scan every interval (e.g. `15m`, `1h`) until SIGINT/SIGTERM, writing the report each cycle; a finding never stops the daemon. Scheduled, not real-time. See `packaging/systemd/` for service units. |

Hash signatures cannot be turned off: a signature database is required.

The `--signers` blocklist is a JSON array of `{thumbprint, thumbprint_sha256,
serial, issuer, reason}` entries, or a line file of `<thumbprint-or-serial>|<issuer>|<reason>`
(a 40-hex id is read as a SHA-1 thumbprint, 64-hex as SHA-256, anything else as a
serial needing an issuer). `$CAU_SIGNERS` sets it too. It is the lolcerts feed's
consumer; a binary signed by a listed certificate is flagged
`authenticode.known-abused-signer` regardless of whether the signature itself is
otherwise valid.

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

`--frameworks` (text format only) appends the **Unified Kill Chain** sequencing
view: each covered technique is mapped through its ATT&CK tactic onto the
18-phase UKC (Paul Pols / Fox-IT), grouped by stage, with the empty phases named
as honest gaps — the counterfactual to ATT&CK's technique grid, showing which
parts of an intrusion's progression a file scanner can observe.

## cau quarantine

```sh
cau quarantine add     <path> [--store dir] [--threat name] [--keep]
cau quarantine list    [--store dir] [--format text|json]
cau quarantine restore <id>   [--store dir] [--to path] [--force]
cau quarantine verify  [id]   [--store dir]
cau quarantine delete  <id>   [--store dir]
```

A local, directory-backed vault for files a scan flagged, so the OSS engine
has somewhere to put found files short of deleting them. Every entry is
XOR-masked at rest: the vault never holds a runnable PE/ELF on disk, and a
scanner pointed at the vault (including `cau` itself) does not re-flag it. Each
entry is sealed with the SHA-256 of both the original and the masked bytes, so
`restore` and `verify` fail *closed* (`exit 1`) if the vault was corrupted or
tampered with, rather than writing wrong bytes back onto the live path. `add`
moves the file by default (`--keep` copies it); `restore` writes to the
recorded original path, or to `--to`, refusing to clobber an existing file
unless `--force`. The store defaults to `$CAU_QUARANTINE_DIR`, else
`$XDG_DATA_HOME/cau/quarantine`, else `~/.local/share/cau/quarantine`.

The mask is reversible obfuscation for safety, not encryption for secrecy —
the key is stored with the entry. Exit codes: 0 ok, 1 integrity failure, 3
failed, 4 usage.

## cau canary

```sh
cau canary plant --dir dir --manifest path [--count n]
cau canary check --manifest path [--format text|json]
```

Plants decoy files with plausible lure names (credentials, finance, keys) and
records a baseline manifest; `check` diffs the files against the baseline and
classifies each as intact, modified, deleted, or meta-changed. A decoy nobody
advertised has no legitimate reason to be opened, so a tripped canary is
high-signal, near-zero-false-positive ground truth — a rewrite (the ransomware
signal) is reported distinctly from a mere permission change. `check` is a
point-in-time comparison a cron job or task hook runs, not a live watch (that
is the sensor's job). Exit codes: 0 all intact, 1 at least one tripped, 3
failed, 4 usage.

## cau peel

```sh
cau peel [--format text|json] [--max-depth n] [--max-nodes n]
         [--max-output n] [--max-children n] [--timeout dur] <file>
```

Walks the obfuscation-chain tree of a file (NOVEL-012): at each node every
applicable reversible layer decoder — base64, base32, hex, gzip, zlib, flate,
bzip2 — spawns a child, under a single global per-sample budget wall shared
across every branch (nodes, decoded bytes, depth, frontier width, wall clock).
Because the budget is global, adding layers costs latency, never more total
spend. The peeler only *decodes*; it never executes sample content.

Chain *depth* is the signal: a revealed executable or script is a finding only
at depth >= 2 (a real chain), because a single ordinary layer — a `.gz` of a
binary, one base64 blob — is normal packaging and is the single-layer
encoded-executable detector's job. A branch that hits a wall is reported as
`peel-exhausted`, a first-class scored outcome, never a silent clean. Each peel
renders a stable chain signature such as `base64>gzip>base64`. Exit codes: 0
clean, 1 a chain revealed a payload or the peel was exhausted, 3 failed, 4
usage.

## cau intake

```sh
cau intake --format stix|misp|malwarebazaar|loldrivers
           (--input <file> | --url <url>) [--db <path>] [--dry-run] [--output <file>]
```

Parses a threat-intelligence feed into hash signatures and appends the new ones
to the signature database, so the database is fed from machine-readable sources
instead of being hand-typed. Supported feeds: STIX 2.1 bundles (indicator SDOs
with a `file:hashes` pattern), MISP event JSON (md5/sha1/sha256 attributes,
including `filename|hash` composites), MalwareBazaar query/dump JSON, and the
LOLDrivers catalog (known-malicious driver hashes). Each hash is validated and
normalized; a hash already in the database is skipped (intake never re-labels an
existing entry). Read the feed from `--input` (`-` for stdin) or fetch it with an
explicit `--url` (bounded, never automatic — the engine does not phone home on
its own). `--dry-run` prints the new signatures, `--output` writes them to a file
instead of appending to the database. Exit codes: 0 ok (even when nothing is
new), 3 failed, 4 usage.

## cau update

```sh
cau update (--from <dir> | --url <base>) [--pubkey <file>] [--db <path>] [--dry-run]
```

Installs a signed signature-database bundle, fail-closed. The engine never
fetches on its own — this is always an explicit command. A bundle is three
files: `hashes.txt` (the payload), `manifest.json` (`{schema, db_version,
min_engine_version, sha256, created}`), and `manifest.json.sig` (a detached
Ed25519 signature over the manifest). One signature covers everything because
the manifest carries the payload's SHA-256.

Nothing on disk changes unless the signature verifies against the trusted key,
the payload digest matches the signed manifest, and the bundle's
`min_engine_version` is satisfied. On success the live database is replaced
atomically and the previous one is kept as `<db>.bak`. `--from` reads a local
directory (also the air-gap path — the identical payload delivered by media);
`--url` fetches `<base>/hashes.txt`, `<base>/manifest.json` and
`<base>/manifest.json.sig`. `--dry-run` verifies only. The trusted Ed25519
public key (hex) comes from `--pubkey`, else `$CAU_UPDATE_PUBKEY`, else the
key pinned in the build; with none configured, update refuses to install
anything. Exit codes: 0 ok, 1 verification failed, 3 failed, 4 usage.

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

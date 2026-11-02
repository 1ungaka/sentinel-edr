# Changelog

All notable changes to CAU EDR. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project has not
cut a tagged release yet, so everything is under Unreleased.

## Unreleased

### Fixed
- **Unbounded input read in `cau peel` and `cau intake`** (memory-exhaustion
  DoS). Both read the input file with `os.ReadFile`, so a multi-gigabyte file,
  `/dev/zero`, or a FIFO could exhaust memory (reproduced: a 3 GiB file OOM-killed
  the process). Reads are now capped at 256 MiB via a bounded reader
  (`readFileCapped` / `readStdinCapped`) and refused with a clear error above
  that — found in an adversarial audit. New coverage-guided fuzzers
  (`FuzzParse` for the intake and SHA256SUMS parsers, `FuzzVerify` /
  `FuzzVerifySignature` for the fail-closed Ed25519 verifiers) ran millions of
  mutations with no panic and no accepted forgery, and are wired into
  `make fuzz`.
- **Two YARA rules were case-sensitive** where the rest carry `nocase`, so a
  case-folded sample evaded them: the wannacry rule's indicator strings and
  the generic-ransomware rule's extension strings (`.locked`, `.encrypted`,
  `.crypt`; its ransom-note strings were already `nocase`, and the note
  co-requirement keeps false positives down). Both surfaced by the
  detection-robustness harness and closed with `nocase`; the eval gate
  confirms unchanged recall and zero new false positives.
- **ELF parser out-of-bounds read (panic on hostile input).** A relocatable
  object whose `.symtab` declared a sub-minimum `sh_entsize` let the per-entry
  guard pass while the parser read a fixed-size `Elf64_Sym`, panicking on a
  table placed at end-of-file. `parseSymbols` now floors the stride to the
  struct size, exactly as `parseDynamic` already did. Regression test:
  `TestParseELFSymtabTinyEntsize`.
- **Address-range overflow could hide content from the scanner.** PE
  `sectionIndexForRVA` and ELF `vaToOffset` / `segmentIndexForVA` tested
  `addr < base+size`, which wraps when a crafted section/segment range
  overflows; a legitimate RVA/VA in such a range resolved to "not mapped" and
  the imports/strings/entry there were silently skipped. Rewritten as the
  non-wrapping `addr-base < size`.
- **32-bit builds: file-controlled offsets could become negative indices.**
  `rvaToOffset`, `parseDebug` (CodeView) and `gnuHashSymbolCount` now use
  width-safe comparisons and bound the symbol offset, so a high offset is
  rejected rather than indexing a slice negatively on `GOARCH=386`/`arm`.
- Coverage-guided fuzz harness for every untrusted-input entry point
  (`FuzzParseELF`, `FuzzParsePE`, `FuzzAnalyze`, stego `FuzzScan`,
  `FuzzScanHeuristicsData`; `make fuzz`). Each ran millions of mutations with
  no crash after the fixes above; the seed corpora run as unit tests in CI.
- Detection-robustness harness (`scanner/robustness_test.go`): measures the
  benign-transform envelope (case, UTF-16 widening, NUL-infixing, junk
  padding, base64) each string/import detector survives on synthetic
  fixtures, locks in the true positives, and fails if a bundled rule becomes
  brittle. It found the wannacry case-sensitivity gap above. Companion
  harnesses cover the other two content detectors: the structural pass
  (`scanner/static`, a dropper profile stays detected when benign data is
  appended) and the stego pass (`scanner/stego`, an invisible-codepoint dead
  drop stays detected when wrapped in text or re-encoded as UTF-16). The YARA
  harness covers the wannacry, mimikatz, lokibot, generic-ransomware and
  obfuscated-powershell rules (every string-based bundled rule);
  it found both case-sensitivity gaps above.
- Per-file panic isolation in `Engine.ScanFile`: a panic in any detector
  degrades to a per-file error result instead of crashing the whole scan, so
  one hostile file can never drop the rest of a directory batch. Test:
  `TestEngineHostileFileDoesNotBreakBatch`.
- `cau scan --output`, `cau coverage --output` and `cau rules --output` now
  check the file's close error (a `defer fh.Close()` hid a failed flush on a
  written report); `coverage.WriteText` and `FuzzyDB.Add` no longer swallow
  write and TLSH-parse errors.

### Added
- **Signed releases + self-verification** (`internal/release`, `cau verify-self`,
  `cau bundle`, and a signing GitHub Actions release job). Each tagged release is
  signed on GitHub's workers with an Ed25519 CI secret: `cau bundle update`
  produces the signed signature-DB bundle, `cau bundle checksums` a signed
  `SHA256SUMS`, and the job **self-verifies the built binary before publishing**
  — a release that cannot verify itself never ships. `cau verify-self` lets the
  running binary reference itself: it computes its own SHA-256 and checks it
  against the signed `SHA256SUMS` fetched over HTTPS (`--url`) or read offline
  (`--from`), verifying the signature before the hash so a MITM cannot substitute
  a matching digest. (An out-of-band ICMP/QUIC "echo-lane" fetch stays a future
  proprietary transport; the signed-manifest-over-HTTPS path is the secure
  in-engine way today.)
- **GitHub wiki** (`wiki/` + `.github/workflows/wiki.yml`): task-oriented pages
  (install, scanning+prevention, running as a service, updates+self-verification,
  anti-tamper, CLI reference) synced to the project wiki on change.
- **Detection-content self-check / anti-tamper** (`cau selftest`,
  `internal/selftest`): digests the signature database, YARA rules and fuzzy
  database and compares them against a recorded baseline, so an attacker gutting
  signatures or neutering a rule (ATT&CK T1562.001, Impair Defenses) is caught
  rather than silently disabling the scanner. `--record` writes the baseline;
  verification exits 1 and names each drifted resource. A **signed** baseline
  (`--sign-key` / `--pubkey` / `$CAU_SELFTEST_PUBKEY`, Ed25519) is
  tamper-resistant: rewriting the content *and* the manifest still fails because
  the signature can't be forged. The systemd units run it as an `ExecStartPre`
  before each scheduled scan.
- **Automated background scanning** (`cau scan --interval <dur>`, plus systemd
  units in `packaging/systemd/`): a scheduled/resident scan daemon that re-scans
  on a fixed interval until `SIGINT`/`SIGTERM`, writing the report each cycle (a
  finding never stops the daemon; it exits 0 on a clean shutdown). It is portable
  — register it as a systemd service (`cau-daemon.service`), a timer-driven
  one-shot (`cau-scan.service` + `cau-scan.timer`), a container entrypoint, or a
  Windows/`launchd` service. This is a *scheduled* scanner; real-time
  kernel-level file monitoring remains the resident sensor's job.
- **Scan-time prevention** (`cau scan --quarantine`): auto-detect *and* block in
  one pass — after scanning, flagged files are moved into the integrity-sealed
  vault, with the driving evidence recorded as the threat label. Explicit and
  off by default (the move is destructive). `--quarantine-level` chooses the bar:
  `malicious` (the default) blocks only a hard hash/YARA hit, while `suspicious`
  **also** blocks files the fusion lattice places at the SUSPICIOUS tier — the
  fused, multi-indicator score where each indicator contributes at its own
  weighted level and the sum crosses the threshold, with or without any single
  detector crossing on its own (this is the score-based auto-block, and the
  recorded label names the score and the agreeing indicators). `--quarantine-store`
  sets the vault. On-host prevention is free, in line with the licensing model
  (only multi-agent management is paid).
- **Known-abused code-signing certificate blocklist** (`cau scan --signers`,
  `static.SignerBlocklist`): the static pass now extracts each Authenticode
  certificate's SHA-1 and SHA-256 thumbprint and matches it — or its
  serial+issuer — against an operator-supplied blocklist (lolcerts), emitting the
  `authenticode.known-abused-signer` anomaly (weight 9, T1553.002). A valid
  signature from a stolen or abused key is the ground truth behind the "Certs
  Are Useless" thesis, and this flags it. The blocklist is a JSON array or a
  `thumbprint|issuer|reason` line file (stdlib only; `$CAU_SIGNERS` also sets
  it); converting the lolcerts YAML feed into that file is an ops step.
- **Unified Kill Chain binding** (`cau coverage --frameworks`,
  `internal/frameworks`): maps each covered ATT&CK technique through its tactic
  onto the 18-phase Unified Kill Chain (Paul Pols / Fox-IT) and prints the
  sequencing view grouped by stage, with empty phases named as honest gaps — so
  mapping does not hinge on a single registry. The binding type also carries
  MISP-cluster and Malpedia-family fields, left for an intel feed to populate
  because they tag a sample, not a technique. Scan report findings also carry a
  `frameworks` array on the `fusion` object (ATT&CK id + UKC phase/stage per
  technique) — JSON report schema **1.10.0** — so a consumer can pick its scheme.
- **Signed update channel** (`cau update`, `internal/updater`): installs a
  signature-database bundle fail-closed. The bundle is three files —
  `hashes.txt`, `manifest.json`, and a detached `manifest.json.sig` (one Ed25519
  signature over the manifest, which carries the payload's SHA-256). Nothing on
  disk changes unless the signature verifies against the trusted key, the payload
  digest matches the signed manifest, and the bundle's `min_engine_version` is
  satisfied; a success replaces the database atomically and keeps `<db>.bak` for
  rollback. Read from `--from <dir>` or an explicit `--url` fetch (never
  automatic); `--dry-run` verifies only. The trusted key comes from `--pubkey`,
  `$CAU_UPDATE_PUBKEY`, or the source-pinned key — with none configured, update
  refuses to install anything. Release-side keypair/signing and the CI publish
  step are tracked as ops follow-ons in PLAN.md.
- **Threat-intel intake** (`cau intake`, `internal/intake`): parsers that feed
  the hash signature database from machine-readable feeds instead of hand-typed
  entries — STIX 2.1 bundles (indicator `file:hashes` patterns), MISP event JSON
  (md5/sha1/sha256 attributes, including `filename|hash` composites),
  MalwareBazaar query/dump JSON and the abuse.ch CSV, and the LOLDrivers catalog
  (known-malicious driver hashes). Each normalizes to validated signatures,
  dedupes against the live database (an existing hash is never re-labelled), and
  appends in the database's own `TYPE|hash|name` format. Input from a file or
  stdin, or an explicit `--url` fetch (bounded, never automatic); `--dry-run` and
  `--output` for review. Fixture tests per format. The TAXII polling client and
  scheduled sync remain follow-ons in PLAN.md.
- **Obfuscation-chain peeler** (`cau peel`, `internal/peeler`): the first
  increment of NOVEL-012 — a bounded, concurrent tree walk that removes
  reversible layers (base64/base32/hex, gzip/zlib/flate/bzip2; decode only,
  never execute) under a single global per-sample budget wall shared across
  every branch, so adding layers costs latency, not spend. Chain *depth* is the
  signal; `peel-exhausted` is a first-class, scored outcome, never a silent
  clean. A revealed payload is a finding only at chain depth >= 2 (a single
  ordinary layer stays `scanner/encchain`'s job), which is why it measured
  0/116,201 false positives across `/usr/bin`, `/usr/share/doc`,
  `/usr/lib/python3` and `/usr/share/nmap`. Each peel renders a stable chain
  signature (e.g. `base64>gzip>base64`); CAS dedupe, a depth sweep, a
  decompression-bomb cap, and `FuzzPeel` (in `make fuzz`) back it. It is wired
  into `cau scan` as a first-class detector (default on, `--no-peel` /
  `--peel-threshold`): `ScanResult.Peel`, a `peeler` fusion source, the `peel` /
  `peel_*` fields in text / JSON / SARIF / OCSF, and `peeler` content in
  `cau coverage` (T1027). The eval gate is unchanged (recall / precision / FP /
  FN flat) and a repo self-scan flags 0 of 291 files. A cheap entropy estimator
  ranks each node's frontier so the bounded budget is spent on the most-probable
  transform first (reordering only — detections and the 0-FP envelope are
  unchanged); the input's Shannon entropy rides on the result. The PE/ELF
  structural-fingerprint routing and the emulation fallback are tracked as
  follow-ons in PLAN.md.
- **JSON report schema 1.9.0**: added the optional per-file `peel` object and the
  summary fields `peel_detections` / `peel_threshold` (additive, minor bump).
- **Quarantine vault** (`cau quarantine`, `internal/quarantine`): a local,
  directory-backed store for files a scan flagged, giving the OSS engine
  somewhere to put found files short of deletion. Every entry is XOR-masked at
  rest — the vault never holds a runnable PE/ELF on disk and a scanner pointed
  at it (including `cau` itself) does not re-flag it — and sealed with the
  SHA-256 of both the original and the masked bytes, so a corrupted or tampered
  vault fails *closed* (`ErrIntegrity`, exit 1) rather than writing wrong bytes
  back to the live path. Subcommands: `add` (move, or `--keep` to copy), `list`
  (text/JSON), `restore` (to the recorded original or `--to`), `verify` (one
  entry or the whole vault), `delete`. Index writes are atomic. Masking is
  reversible obfuscation for safety, never encryption for secrecy — the key is
  stored alongside the entry and the docs say so.
- **Canary / decoy files** (`cau canary`, `internal/canary`): `plant` writes
  plausible decoy files (credential, finance, key names) and records a baseline
  manifest; `check` diffs them and classifies each as intact, modified,
  deleted, or meta-changed, so a rewrite (the ransomware signal) is never
  conflated with a permission change. Cheap ground truth with near-zero false
  positives; `check` is honest about being a point-in-time comparison a cron
  job or task hook runs, not a live watch.
- **ATT&CK coverage matrix** (`cau coverage`, `internal/coverage`): derived
  from the shipped content (heuristic categories, the new static and stego
  class catalogs, compiled YARA rule meta), never typed in; text, JSON and
  ATT&CK Navigator layer output; each detector labeled with its Pyramid of
  Pain level; unmapped content listed, never padded. `--expect
  baselines/attack-coverage.txt` gates CI: a lost technique is a regression
  and a gained one must be recorded (`--record`). Four per-technique states:
  detected, partial (acknowledged incomplete), planned (a declared gap:
  T1027.013, T1140, T1564.001) and none (owned by the sensor or console);
  the SARIF rendering flags planned gaps as warnings.
- **YARA rule linter** (`cau rules lint`, `internal/rulelint`): compile
  diagnostics, required meta (description, author, threat_level 1-5, family,
  mitre_attack with a valid id), hex-written-as-text strings (the dead-rule
  class Phase 0 found), strings under four bytes, narrow-only text, trivial
  conditions; `cau` and `generic` profiles, text or JSON, `--strict`.
  `cau rules list` prints the compiled inventory. `make lint-rules` runs in CI.
- **OCSF output** (`--format ocsf`): one Detection Finding (class 2004, OCSF
  1.3.0) per suspicious or malicious file with severity, the leading
  analytic, ATT&CK techniques with names, file evidence and digests, malware
  names and the engine-native detail under `unmapped`.
- `mitre_attack` meta on every bundled rule; `static.Classes()`,
  `stego.Classes()` and `YaraScanner.RuleInfos()` expose the content
  catalogs; `internal/attack` carries technique names (ATT&CK v15).
- **ELF structural pass** (`scanner/static`): own bounds-checked ELF parser
  (32- and 64-bit, both byte orders; executables, shared objects, relocatable
  objects and kernel modules) reading segments, sections, the dynamic table,
  dynamic or `.symtab` symbols, notes, `.modinfo` and the appended module
  signature, overlay, UPX markers and the generic packed profile, and an
  import-set hash for clustering. Labeled anomaly classes for RWX and packed
  segments, stripped or invalid section tables, entry-point placement,
  executable stacks, non-system program interpreters, insecure
  `RPATH`/`RUNPATH`, text relocations, `DT_INIT` outside code,
  LD_PRELOAD-style libc interposers (known interposers named at weight 0),
  loader-only imports, unsigned or `modinfo`-less kernel modules and
  malformed tables. Rendered in text, JSON (`is_elf`, `static.elf`,
  `static.import_hash`; schema 1.3.0) and SARIF (`import_hash`, `interp`,
  `packer` properties); `cau hash` and `cau cluster` accept ELF. Measured: 0
  detections on 4,974 ELF files and 40 kernel modules from a Kali install.
- Heuristics read ELF imports (undefined dynamic symbols, or a kernel
  module's undefined `.symtab`) through the same indicator table, with a
  small Linux set (`ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd` as
  injection) and a **Kernel Rootkit** category (T1014: `kallsyms_lookup_name`,
  kprobe and ftrace registration, `set_memory_rw`, `text_poke`,
  `sys_call_table`). `HeuristicResult.IsELF`; `is_elf` in JSON.
- Smoke corpus: two synthetic ELF fixtures (a clean PIE and a dropper
  profile) written byte-for-byte by `TestWriteELFFixtures`; baseline
  re-recorded with the `static` detector's first true positive.
- Documentation set under `docs/` (installation, CLI reference, detectors,
  output formats, detection content, evaluation, library usage, architecture,
  limitations, contributing); the README is now the landing page.
- **Detection fusion lattice** (`scanner/fusion`): every detector's result is a
  source with evidence labels and ATT&CK / NOVEL ids; the strongest counts in
  full, sources at or above 0.4 of their own threshold corroborate at half
  weight, hash and YARA hits are never downgraded. Rendered in text, JSON
  (`fusion`), SARIF (`fusion/corroborated`) and the exit policy; a `fusion`
  eval detector reports only corroborated-only verdicts. Measured: 0 fused-only
  detections and 0 new false positives on the 349-file Kali Windows tool set.
- **Invisible-codepoint detector** (`scanner/stego`, NOVEL-001/002):
  zero-width characters, bidirectional overrides (Trojan Source), TAG
  characters and data-carrying variation selectors in UTF-8 / UTF-16 text and
  code, presence-based with named context exceptions (BOM, emoji sequences,
  joining and spaceless scripts, right-to-left lines, CJK variation sequences,
  flag sequences). `--no-stego`, `--stego-threshold`; SARIF `stego/<class>`
  rules with byte-offset regions. Measured: 0.10 % false positives on 70,102
  benign text artifacts.
- ATT&CK technique on every heuristic category (`scanner.CategoryTechnique`,
  `scanner.Categories`), rendered in text and JSON.
- **Static structural pass** (`scanner/static`): own bounds-checked PE parser,
  Shannon entropy (whole file and sliding window), TLSH / ssdeep / imphash,
  section / entry-point / header / import / packer / overlay / Authenticode
  anomalies as labeled classes with ATT&CK mapping, fuzzy-hash database
  (`signatures/fuzzy.txt`), import clustering. New commands `cau hash`,
  `cau cluster`, `cau add-fuzzy`; `--no-static`, `--static-threshold`,
  `--fuzzy-db`, `--no-fuzzy`.
- Evaluation harness (`cau eval validate|run|report|diff|gate|policy`,
  `internal/eval`), committed smoke corpus, baseline and regression policy;
  `make eval` in CI.
- JSON (schema 1.2.0) and SARIF 2.1.0 output, `--fail-on` exit-code policy,
  `--jobs` concurrency, resource discovery relative to the install prefix.

### Changed
- **Durable atomic writes:** the quarantine vault and the update channel now
  `fsync` the temp file before the rename (and best-effort `fsync` the
  directory after), so a crash can never leave a renamed-in index or database
  with torn or zero contents — the integrity seals only mean something if the
  bytes they cover reached disk.
- **Honest MCP sandbox claim:** the path-confinement comment and `docs/mcp.md`
  no longer overstate the guarantee. Resolve-time symlink containment holds, but
  access is by resolved path (not a retained `O_NOFOLLOW` descriptor), so a
  component swapped after resolution is a residual TOCTOU; this is now stated
  plainly rather than claimed closed.
- The `cau-mcp` server now runs the full CLI detector set: the Shell Link
  (`lnk`), OLE macro (`ole`), PDF (`pdf`), ISO container (`iso`) and
  obfuscation-chain (`peel`) passes are enabled by default (each with a
  `--no-*` flag) and surfaced in the tools' per-detector scores and
  suspicious-tier verdict, so the agent-facing scan matches `cau scan` as the
  docs state.
- Remaining "Astra" naming in the plan, layout and ignore rules renamed to
  CAU, and the GitHub repository is renamed to `s-b-repo/cau` (the old name
  redirects); only the historical origin keeps the Astra name.
- YARA runs in-process through go-yara with a per-scan timeout; rules are
  compiled once; rule meta, namespaces and warnings are kept.
- Heuristics score once per pattern with category caps and a weak-category
  budget; threshold retuned to 7 on the Kali Windows tool set (60 → 28
  detections, credential tools still detected).
- Bundled rules carry `ascii wide`; two rules that could never fire were
  rewritten; the loose ransomware-extension rule requires a ransom-note name.
- Signature database loading validates type, hex and length, rejects
  duplicates and conflicting re-labels; synthetic filler entries removed.

### Removed
- Shelling out to the `yara` binary.

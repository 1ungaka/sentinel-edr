# Changelog

All notable changes to CAU EDR. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added
- **The self-scan SARIF is uploaded to code scanning.** The `selfscan` lane runs
  `cau scan --dir .` in SARIF and OCSF and hands `cau.sarif` to
  `github/codeql-action/upload-sarif@v3` (`security-events: write`), which is
  the CI recipe `docs/cli.md` documents but no workflow ever wired up. A rule or
  heuristic that starts firing on the tree is now a review item rather than an
  artifact nobody opens.
- **A `fuzz` lane and a `vendor/` consistency gate.** Every pull request runs
  `make fuzz FUZZTIME=30s`, a coverage-guided hunt over every `Fuzz*` target
  (the seed corpora already run as unit tests, so the lane buys mutation
  coverage, not re-runs), and the `lint` lane runs `go mod vendor` plus
  `git diff --exit-code -- vendor`, so a stale committed tree fails where it
  costs seconds instead of in the Debian and Arch builds that carry
  `GOPROXY=off`.
- **CI now proves the Debian source package builds.** `dpkg-buildpackage
  -us -uc -S` runs from a copy of the tree, so the "source + binary `.deb`"
  claim in `docs/packaging.md` is measured rather than aspirational. It is
  bounded (10 minutes, `set -eu`, so a broken source package fails the job
  rather than looking like a pass) and scoped to non-PR, non-tag runs: a tag
  build already proves it by building the real source package, and a PR is a
  preview of a merge. The copy carries only what a packager would publish —
  the tree's own build products, the nested `cau-kernel` repository and the
  local WIP paths (`scripts/lintworkflows/`, `docs/p.p`, `cau.sarif`,
  `cau.ocsf.json`) are excluded by the step and now by `.gitignore` too, so
  the proof is not spent on artifacts this repository refuses to publish.
  `.github/dependabot.yml` is new (weekly, grouped updates for the actions the
  workflows pin); the Go module ecosystem is deliberately absent because the
  `vendor/` tree is committed.
- **A security policy, a support policy and a machine-readable price list.**
  `SECURITY.md` states what is in scope (including the anti-tamper claims:
  anything that silently disables detection or makes `cau selftest` pass on
  tampered content), what is not (false positives and missed detections are
  issues, not vulnerabilities — report the sample's SHA-256, never the
  sample), the private reporting channels, the triage clock and 90-day
  coordinated disclosure. `SUPPORT.md` says which artifact is supported how:
  the engine and agents are MIT software supported publicly by issue at every
  scale, the console carries contractual tiers, and the tier tables are
  generated from `pricing.toml` rather than typed twice. `pricing.toml` is the
  checked-in source of truth for the commercial surface — per-managed-agent
  volume bands, tiers, term, the air-gapped renewal path, and a TCO model in
  which every row is labelled FACT or ASSUMPTION so no invented number reads
  as a measurement. `docs/pricing.md` renders it and states in its own header
  that the numbers are a draft under owner review. Both files record the split
  the licensing mechanics already enforce: detection and on-host prevention
  are free and unmetered; only the multi-agent management plane is billed.

### Changed
- **The CI pipeline is six parallel, named, time-bounded lanes** rather than one
  serial job: `lint` (15 min), `test` (45 min, `make test-race` over every
  package), `gates` (20 min: `make build build-mcp`, `make lint-rules`,
  `make coverage`, `make eval`), `selfscan` (20 min), `fuzz` (30 min) and
  `release` (30 min, on a `v*` tag, `needs` the other five). The five
  non-release lanes share the new composite action `.github/actions/cau-env`
  (Go pinned by `go.mod`, libyara 4.3+, pkg-config); the unneeded `yara` CLI is
  no longer installed. A per-ref `concurrency` group cancels a superseded
  pull-request run, a nightly `schedule` is the drift canary for CGO against a
  moving Go/libyara/glibc runner image, `workflow_dispatch` was added, and pull
  requests touching only Markdown, wiki, docs, completions, packaging, scripts
  or `debian/` get no runner time. `make ci` is unchanged and is still the
  local aggregate.
- **A release ships `cau-mcp` and signs everything it publishes.** The release
  job builds `cau` *and* `cau-mcp` (`cau-mcp` was the only artifact the release
  job never built), and the signed `SHA256SUMS` is generated after the integrity
  manifest and the pinned public key are staged, so both are covered by the
  signature instead of shipped unsigned.
- **The module path is `github.com/s-b-repo/cau`.** `go.mod` and all 74
  non-vendor `.go` files carried `github.com/cau-edr/cau`, which is not this
  repository: the published module, every `go get` recipe, every import block
  and the docs that quote them disagreed with the remote in `git remote -v`.
  The default build stamp is `0.1.0-dev`, not `0.4.0-dev` — the first tagged
  release is `v0.1.0` and a default that outranks it is a version lie, so
  `main.go` and `cmd/cau-mcp/main.go` now report the pre-release stamp and let
  the ldflags override supply the real version.
- **The docs match the repository.** `docs/installation.md` no longer says no
  tag has been cut: it names `v0.1.0` (2026-11-02), where its artifacts are
  attached and where the maintainer checklist lives. `docs/README.md` and
  `README.md` cite the JSON schema as 1.10.0, and the README's table links
  `docs/mcp.md` and `docs/packaging.md`, which existed but were unreachable
  from the index. `docs/library.md`, `docs/output-formats.md` and `PLAN.md`
  drop the old module path and the stale `v0.4.0` example version.

### Fixed
- **`package.yml` could never attach anything to a release.** The workflow set
  `permissions: contents: read` workflow-wide, while the `action-gh-release`
  steps that attach the `.deb`, the Kali `.deb` and the `.pkg.tar.zst` to a tag
  need `contents: write`, so each could only fail with a 403 and publish
  nothing; every job now carries `contents: write`.
- **`package.yml`'s `pull_request` allow list silently skipped work.** It omitted
  `main.go`, `scripts/package-smoke.sh` and every new top-level file, so a
  change there ran no packaging gate; the trigger is now a `paths-ignore` list.
  The full-depth checkout (`fetch-depth: 0`) lets `git describe` stamp the tag
  version into a package instead of a commit sha, and `workflow_dispatch` plus a
  bounded runtime per job make the three container legs re-runnable by hand.
- **`package.yml`'s install step smoke-tested nothing on arm64.** Both legs
  installed `./dist/cau_*_amd64.deb` by name, so on an arm64 runner the glob
  matched no file and `apt-get install` installed nothing — the smoke test then
  passed against whatever `cau` was already on the image, which is a green
  packaging gate over an untested package. The architecture is now read from
  `dpkg --print-architecture`, which is the one the builder produced (the cgo
  binding to libyara is built, not cross-compiled), so the file installed is
  the file that was built.

## 0.1.0 - 2026-11-02

First tagged release: the detection engine, the evaluation harness and the
packaging for Debian, Kali Linux and Arch Linux all ship as one version. Every
claim on this page is covered by a test, a measured baseline or a CI gate.

### Notable

- **Packaging that is proven, not claimed.** `dpkg-buildpackage` and `makepkg`
  both build from this repository (the vendored Go module tree is committed, so
  the Debian buildds and the AUR builder need no module-proxy network access).
  `.github/workflows/package.yml` then installs each package into a clean
  Debian trixie, Kali rolling and Arch Linux container and runs
  `scripts/package-smoke.sh`, which asserts the verdicts rather than only the
  exit codes: the malicious smoke sample is caught with zero flags, the benign
  one stays clean, man pages, completions and content are installed, and
  `cau selftest` fails closed. A `.deb`, a Kali `.deb` and a
  `.pkg.tar.zst` are attached to every `v*` release; `scripts/apt-repo.sh`
  builds a signed apt repository from them (see `docs/packaging.md`).
- **The detector list and thresholds are one story.** The engine's detectors,
  thresholds, report formats and content are identical across `cau scan`,
  `cau-mcp` and the packages: all three install through the same Makefile
  target, and the version stamped into a binary is derived from the tag, not
  from the build directory (which is also why the builds are `-trimpath`
  reproducible).
- **`cau selftest` refuses to trust unrecorded content.** With no recorded
  manifest it fails closed (exit 3) instead of reporting success on content
  nobody measured. The release pipeline records a signed manifest.


### Fixed
- **`scripts/clean-manifest.sh` was not executable**, although the Makefile
  invokes it as a command (`make eval-specificity` failed with "Permission
  denied" on a fresh clone). It now carries the executable bit it always had;
  the other scripts are only `source`d and so deliberately do not.
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
- **`cau firmware` — UEFI firmware scan** (`scanner/uefi`): parses a UEFI image's
  Firmware Volumes and FFS files/sections and reports a module inventory (GUID,
  type, UI name, has-PE), FV header checksum integrity, and implant-blocklist
  matches. Deliberately conservative — ships no implant truth set — so only
  `uefi.volume-checksum-invalid` (a tampered/hand-built FV header) and
  `uefi.known-implant-guid` (an operator `--implants` blocklist match) score;
  everything else is inventory. Module bodies are not disassembled and
  compressed/GUIDed sections are not decompressed. `--format text|json`,
  `--threshold`, `--implants`. Adds ATT&CK T1542.001 (System Firmware). A
  standalone command, not part of the per-file `cau scan`.
- **CHM detector** (`scanner/chm`): reads Compiled HTML Help (ITSS) files for
  embedded payloads a help file has no reason to carry — a lone embedded
  executable (`chm.embedded-executable`, crosses on its own), multiple
  executables, an embedded `.lnk`, or a dangerous script (`.hta`/`.vbs`/`.ps1`/
  `.bat`/`.cmd`/`.wsf`, deliberately not plain `.js`). Walks the uncompressed
  ITSF/ITSP/PMGL directory only; the LZX content section is recorded "present but
  not inspected" rather than guessed. New flags `--no-chm` / `--chm-threshold`,
  per-file JSON `chm` object and summary `chm_detections` / `chm_threshold`,
  text/OCSF surfaces and `--fail-on` counting. T1204.002 / T1059 (already-covered
  techniques, so coverage stays at 58).
- **Archive detector** (`scanner/archive`): bounded, write-free ZIP/TAR/gzip
  (and `tar.gz` nesting) container-hygiene analysis — decompression bombs (ratio
  + absolute caps), Zip-Slip/path-traversal members, double-extension lures
  (`invoice.pdf.exe`), disguised single-executable payloads, and encrypted or
  nested members. Never writes to disk or executes a member; every read is
  bounded. New flags `--no-archive` / `--archive-threshold`, per-file JSON
  `archive` object and summary `archive_detections` / `archive_threshold`,
  text/SARIF/OCSF surfaces and `--fail-on` counting. In the coverage matrix as the
  `archive` source (T1036 / T1204.002 / T1027 on existing rows).
- **`cau installed` — installed-package audit** (`internal/linuxpkg` reuse): audits
  the maintainer/install scripts of already-installed packages in place from dpkg
  (`/var/lib/dpkg/info`) and pacman (`/var/lib/pacman/local`) metadata — offline,
  read-only — flagging the same tradecraft as `cau scan` and any abuse-intel
  indicator reference. RPM is reported as a gap. `--format`, `--threshold`,
  `--feed`.
- **`cau feed` — abuse-intel feed** (`internal/intel`): a hybrid offline feed of
  known-bad IPs/CIDRs/domains/URLs/hashes matched by `cau scan` (`--feed`),
  `cau installed` and `cau ps`. Subcommands `list` / `check` / `update`; `update`
  is the only networked action and only with an explicit `--url` (otherwise a
  plain offline file, `--from`/`--replace`).
- **Report-JSON for Mach-O and ELF deep-resolution**: the static object now emits
  `is_macho` and a `macho` object (`magic`, `byte_order`, `fat`, `arches[]` with
  cpu/filetype/flags/signed/encrypted/entry_segment/import_count/import_hash/dylibs),
  and the `elf` object gains `telfhash`, `telfhash_note` and `syscall_stubs`.
- **Linux software-package detector** (`scanner/linuxpkg`): a bounded,
  stdlib-only, detection-only pass that scores the root-run install-time scripts
  in `.deb` (ar → `control.tar` maintainer scripts), `.rpm` (header scriptlets),
  Arch `.pkg.tar` + `PKGBUILD`, Flatpak manifests + bundles, AppImage type-2,
  Docker/OCI `docker save` tarballs, Snap packages, generic `.zip`/`.tar`
  installers, executable configs (`.desktop`/XDG/systemd/shell-rc) and APT/nala
  sources. It scores supply-chain tradecraft (curl-into-shell, reverse/bind
  shell, decode-and-exec, cryptominer, SSH-key backdoor, sudoers NOPASSWD,
  dropper, disable-defenses, persistence, sandbox escape; T1195.002 and family),
  default threshold 8, SUSPICIOUS-tier only, wired into the engine, fusion,
  coverage matrix and every reporter. New flags `--no-pkg` / `--pkg-threshold`
  (also `--no-pkg` on `cau-mcp`); JSON per-file `linuxpkg` object and summary
  `linuxpkg_detections` / `linuxpkg_threshold`. xz/zstd-packed members and
  AppImage/Snap SquashFS are recorded "present but not inspected", never guessed.
- **`cau ps` — live process scan** (`internal/procscan`): a read-only,
  `/proc`-only point-in-time scan of the running process table. It never injects,
  ptraces, or signals a process, and flags what a file scan structurally misses —
  fileless / RAM-only execution (memfd, deleted binary, `/dev/shm`; T1620), name
  masquerading / PID hijacking (T1036.004/005), library-injection hooks
  (world-writable/deleted `.so`, suspicious `LD_PRELOAD`; T1574.006), reverse-shell
  command lines, and ptraced processes (T1055.008). Flags `--format text|json`,
  `--threshold`; exit 0 clean / 1 flagged / 4 usage.
- **Mach-O static support** (`scanner/static/macho.go`): own bounds-checked
  parser for thin and universal/fat images (32/64-bit, both byte orders) —
  segments/sections, dylibs and a dylib-set import hash, `LC_RPATH`,
  `LC_MAIN`/`LC_UNIXTHREAD` entry, `LC_CODE_SIGNATURE` (presence, unverified) and
  `LC_ENCRYPTION_INFO` (cryptid). New `macho.*` anomaly classes (RWX/high-entropy
  segments, writable-executable section, entry outside/non-exec segment,
  executable stack, encrypted/packed region, insecure rpath/dylib path, unsigned
  or unverified signature, overlay), all in the static class catalog.
- **ELF deep-resolution** (`scanner/static/elf_reloc.go`): `.init_array`/
  `.preinit_array` constructor pointers are resolved through the relocations and
  a target outside executable code flags `dynamic.init-array-outside-code`;
  symbol versions are read from `.gnu.version_r`/`_d` (`dynamic.symbol-versions`);
  a raw-syscall libc interposer flags `dynamic.preload-interposer-syscall`; and
  real **telfhash** (TLSH over the Trend Micro filtered symbol set) is computed,
  with an honest note below TLSH's 50-byte floor.
- **Hybrid fusion — attack-path chaining** (`scanner/fusion/chain.go`): on top of
  the independent weighted sum, `FuseChained` (now the engine default) adds
  bounded, capped conditional chains that fire only on a conjunction of two
  distinct counted sources — `packed-and-injects`, `document-dropper`,
  `peel-revealed`. Chaining only ever adds (the lattice stays monotone), is capped
  at 0.75, never resurrects below-floor evidence, and never downgrades a
  definitive hit. The flat `Fuse` is unchanged for library callers.
- **Process concealment & anti-hook self-protection** (`internal/harden`): the
  resident daemon rewrites its own `comm` (always) and command line (best-effort)
  to a neutral random `[a-z0-9]{6,12}` name so malware hunting a defender by name
  (`pgrep`/`pkill`, `/proc/<pid>/comm`) does not find it, strips loader-hijack
  environment variables (`LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`/`GCONV_PATH`),
  and reports an attached tracer. Best-effort and defensive — it does **not**
  resist `SIGKILL` or a kernel-level kill (that is the resident sensor's job); a
  no-op off Linux. The banner logs the real→random name once.
- **`cau heldout` — held-out recall corpus** (`internal/heldout`): an encrypted
  (AES-256-GCM, PBKDF2) hash+intel database for a recall corpus the detectors were
  not authored from. Subcommands `init`/`pull`/`add`/`remove`/`list`/`manifest`;
  `pull` ingests the MalwareBazaar CSV export incrementally (resumable download,
  batched checkpoints, skip-present). Key from `--key-file` / `$CAU_HELDOUT_KEY`.
  Sample bytes are fetched by `scripts/fetch-heldout.sh`, never committed.
- **Near-miss eval metric**: `cau eval report` gains a `near_miss` section per
  scored detector (threshold, benign-scored count, near-threshold band, minimum
  margin, histogram) so a benign corpus that is *almost* crossing a threshold is
  visible before it becomes a false positive.
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
- **Daemon crash & hang auto-recovery** (`cau scan --interval`). A long-lived
  scanner is a target, so the daemon now supervises itself: every scan cycle
  runs behind a panic barrier (`runCycle`) — a panic in a detector, report
  writing, or quarantine is caught, logged with its stack, counted, and the
  daemon continues to the next cycle instead of dying. Under a `Type=notify`
  systemd unit it speaks the sd_notify protocol (new dependency-free
  `internal/sdnotify`): `READY=1` on start, a `STATUS=` line per cycle, and a
  `WATCHDOG=1` keep-alive on its own cadence (half `WatchdogSec`, independent of
  the scan interval) — so a true hang, deadlock, OOM kill, or hard crash stops
  the pings and systemd restarts the process, with `StartLimitBurst` capping a
  crash-loop. All of it is a silent no-op with no `NOTIFY_SOCKET`, so a
  hand-run or plain-container daemon still gets cycle-level recovery.
- **Daemon process self-protection** (new `internal/harden`, Linux). On startup
  the scan daemon makes its process **non-dumpable** (`PR_SET_DUMPABLE=0`) — the
  kernel then refuses `ptrace`/`/proc/<pid>/mem` from a non-owner and emits no
  core dump, closing the cheapest paths to reading its in-memory state (the
  pinned trust anchor, the loaded signatures) — and sets **`no_new_privs`** so a
  coerced `exec` cannot escalate. It also logs the running binary's own SHA-256
  for comparison against the signed release (`cau verify-self`). Best-effort and
  fail-open: a host that denies a step is reported, never fatal, because
  detection must keep running. Stdlib-only (raw `prctl`), so the default build
  stays dependency-free.
- **Hardened systemd units.** `cau-daemon.service` / `cau-scan.service` now run
  as an unprivileged `cau` user holding only `CAP_DAC_READ_SEARCH` (read any
  file, no root), under a full sandbox: `ProtectProc=invisible` + `ProcSubset=pid`
  (other users cannot see or inspect the process), `ProtectSystem=strict`,
  `PrivateDevices`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service`,
  `LockPersonality`, `UMask=0077`, systemd-managed `StateDirectory`/`LogsDirectory`.
  The daemon unit adds `Type=notify` + `WatchdogSec=60s` + `Restart=always` for
  the recovery above.
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
- **Distribution packaging.** Debian/Kali source and binary packages
  (`debian/`: control, rules, postinst creating the unprivileged `cau` user,
  postrm removing it only on purge, docs, watch with a real tagged upstream),
  an Arch `PKGBUILD` + `.SRCINFO` ready for the AUR (`packaging/arch/`), the
  systemd units installed by both, a `make install` that also carries the man
  pages, shell completions and the license (plus `make install-systemd`),
  `scripts/apt-repo.sh` for a signed apt repository, and CI that builds,
  installs and smoke-scans every one of those packages (`package.yml`).
- **Shell completion** (`cau completion bash|zsh|fish`): the scripts are
  embedded in the binary, mirror the real dispatch, accept both `-flag` and
  `--flag` spellings, and are installed for all three shells. A test asserts
  every command in `cau help` appears in every script, so the two cannot drift.
- **Man pages** for `cau` and `cau-mcp` (`docs/cau.1`, `docs/cau-mcp.1`),
  installed under the share directory and by every package.

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

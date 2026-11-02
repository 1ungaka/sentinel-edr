# Limitations

Every detector has a failure mode, and this engine is built so that each one
is stated rather than hidden. The planned evasion suite (PLAN.md, Phase 6)
will demonstrate all of them against this engine; the evaluation harness
exists so the demonstration can be measured.

## By detector

| Detector | Dies to | Survives |
|---|---|---|
| Hash signatures | a single flipped byte | nothing short of an identical file |
| Fuzzy hashes (TLSH, ssdeep, imphash) | a repack, a rebuild, a changed import set | trivial edits and appended data |
| YARA | an author who knows the ruleset: renamed strings, encrypted payloads, split patterns | content the rule author described |
| Heuristics | capability hidden behind dynamic API resolution or encryption; and the inverse: a debugger has an injector's import profile and is reported as one | binaries that still name what they do |
| Static structure | an unpacked, unsigned, plainly linked credential dumper looks ordinary; a packed benign tool looks packed; on ELF, a preload library that reaches libc through raw syscalls instead of `dlsym`, or a loader stub that keeps a system interpreter path and a normal section table | tampered headers, forged signatures, loader-only import tables, appended payloads; on ELF, RWX or packed segments, stripped section tables, non-system interpreters, writable `RPATH`, `dlsym`-resolving libc interposers, unsigned or `modinfo`-less kernel modules |
| Invisible codepoints | a channel that uses visible characters, or lives in a binary format | any invisible codepoint in text or code, regardless of density |
| Fusion | a file silent on every detector | the attacker who beats one detector and leaves evidence on another |

## Documented false-positive classes

| Detector | Class | Measured |
|---|---|---|
| Heuristics | debuggers and injection-capable developer tools (OllyDbg scores 11); on Linux, `sudo` imports `ptrace` and the `process_vm_*` pair for its intercept feature and scores 6 | 28 of 349 files in the Kali Windows tool set score at or above 7, almost all of them offensive tools shipped on purpose; 1 of 4,729 ELF files gains a heuristic detection from its import table and that one is a Kali-shipped offensive tool |
| Static (PE) | none above the threshold on the tool set; packed benign tools render as low suspicion with the packer named | `wget.exe` 7/8, `klogger.exe` 6/8 |
| Static (ELF) | launcher stubs with three or fewer substantive imports (`node`, `gvpr`, `selinuxenabled`); vendor executable sections with non-compiler names (libGL `wtext`, absl `malloc_hook`); one old build with an executable stack; one archiver with an appended data block. Sanitizer runtimes, `libeatmydata` and sudo's noexec shims are named as known libc interposers and not scored | 21 of 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec` and `/usr/lib/systemd` carry one weight-1 observation; 0 reach the threshold; 40 of 40 signed kernel modules score 0; a UPX-packed `ls` scores 6/8 |
| Stego | a stray ZERO WIDTH SPACE pasted into documentation or a translation file; source files that enumerate Unicode categories (regular-expression libraries, identifier tables); a stray byte-order mark mid-file | 70 of 70,102 benign text artifacts (0.10 %) |
| Fusion | none observed | 0 fused-only detections on the tool set |
| Encoded executable | embedded encoded binaries in security tooling and exploit docs (impacket, lsassy, nxc, metasploit) — genuine encoded executables, flagged as designed | 32 of 159,339 benign files (0.020 %) |

## Detection robustness (measured)

`scanner/robustness_test.go` measures how much benign, structure-level
perturbation each string/import detector survives on synthetic fixtures — the
defensive form of "evasion distance". It is a regression gate: a bundled rule
that becomes brittle (a benign transform drops a detection that fired on the
untouched sample) fails the test.

| Transform | YARA / heuristics | Why |
|---|---|---|
| case fold (upper/lower) | **survives** | rules carry `nocase`; the harness surfaced two case-sensitivity gaps that review had missed — the whole wannacry rule, and the ransomware rule's extension strings (`.locked`, `.encrypted`, `.crypt`), both `ascii wide` without `nocase` so a `.LOCKED` note walked past them — and both were fixed by adding `nocase` |
| UTF-16 widening, NUL-infixing | **survives** | the `ascii wide` modifier matches the widened form, so NUL-between-bytes is just UTF-16LE |
| prefix / suffix junk | **survives** | the indicator strings are still present and contiguous |
| base64 of the whole file | **evades** | the contiguous byte sequence is gone; this is the documented encoding gap, not a regression |

The base64/encryption gap is fundamental to byte-pattern matching and is why
the engine fuses several detectors rather than trusting any one; peeling
encoded layers is planned (PLAN.md, NOVEL-012). The harness runs on synthetic
samples only and ships no bypass.

The stego pass is presence-based on purpose: a single pasted codepoint is
reported as exactly one occurrence with no payload run, so an analyst can
tell it from an encoded channel at a glance, and `--stego-threshold 8` makes
the engine require a payload run or an ASCII carrier as well.

## What is not covered yet

- **File formats.** The structural pass parses PE and ELF images (ELF: 32-
  and 64-bit, both byte orders; executables, shared objects, relocatable
  objects and kernel modules). Mach-O, OLE / VBA, PDF, LNK, CHM, ISO,
  archives and firmware images each need their own pass (PLAN.md, Phases 8
  and 9); until then they get hashing, YARA, heuristic strings, entropy,
  fuzzy digests and the stego pass only.
- **ELF, what the pass does not do.** It reads headers, segments, sections,
  the dynamic table, symbols, notes and `.modinfo`; it does not apply
  relocations, so `.init_array` entries are counted but their targets are
  not resolved; symbol versions are not read; a kernel module's appended
  signature is detected, never verified (the kernel keyring is not available
  to a file scanner, and the report says so); the import-set hash is a CAU
  clustering key, not telfhash; and the interposer rule requires the object
  to import `dlsym`, so a preload library that calls libc through raw
  syscalls is caught only by the segment, interpreter and import rules.
- **Unpacking.** Packed samples are identified, not unpacked. The bounded
  peeler and the emulation fallback are planned (NOVEL-012).
- **Behaviour.** The engine is static. Process lineage, network and runtime
  telemetry are the sensor's job, outside this repository.
- **Field false positives.** Every number here is fixture-derived from one
  machine's package set; a real corpus is Phase 1's open item.
- **Trust.** No certificate chain is verified against a trust store, by
  design and by name.

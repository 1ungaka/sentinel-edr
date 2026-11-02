# Limitations

Every detector has a failure mode, and this engine is built so that each one
is stated rather than hidden. The planned evasion suite (PLAN.md, Phase 6)
will demonstrate all of them against this engine; the evaluation harness
exists so the demonstration can be measured.

## By detector

| Detector | Dies to | Survives |
|---|---|---|
| Hash signatures | a single flipped byte | nothing short of an identical file |
| Fuzzy hashes (TLSH, ssdeep, imphash, telfhash) | a repack, a rebuild, a changed import or symbol set | trivial edits and appended data |
| YARA | an author who knows the ruleset: renamed strings, encrypted payloads, split patterns | content the rule author described |
| Heuristics | capability hidden behind dynamic API resolution or encryption; and the inverse: a debugger has an injector's import profile and is reported as one | binaries that still name what they do |
| Static structure | an unpacked, unsigned, plainly linked credential dumper looks ordinary; a packed benign tool looks packed; on ELF, a preload library that reaches libc through raw syscalls while also importing nothing else suspicious, or a loader stub that keeps a system interpreter path and a normal section table; on Mach-O, an unsigned command-line tool (signing is a launch-time check, not a file one) and FairPlay encryption that is indistinguishable in the header from a protector | tampered headers, forged signatures, loader-only import tables, appended payloads; on ELF, RWX or packed segments, stripped section tables, non-system interpreters, writable `RPATH`, libc interposers (whether they resolve originals through `dlsym` **or** reach the kernel through raw syscalls), constructor pointers (`.init_array`) resolved outside executable code, unsigned or `modinfo`-less kernel modules; on Mach-O, RWX segments, encrypted load regions, entry points outside every segment, dylibs loaded from attacker-writable paths, executable-stack flags |
| Invisible codepoints | a channel that uses visible characters, or lives in a binary format | any invisible codepoint in text or code, regardless of density |
| Fusion | a file silent on every detector | the attacker who beats one detector and leaves evidence on another — and, through conditional chaining, the attacker whose findings line up along a recognised attack path even when no single detector crosses its own floor |

## Documented false-positive classes

| Detector | Class | Measured |
|---|---|---|
| Heuristics | debuggers and injection-capable developer tools (OllyDbg scores 11); on Linux, `sudo` imports `ptrace` and the `process_vm_*` pair for its intercept feature and scores 6 | 28 of 349 files in the Kali Windows tool set score at or above 7, almost all of them offensive tools shipped on purpose; 1 of 4,729 ELF files gains a heuristic detection from its import table and that one is a Kali-shipped offensive tool |
| Static (PE) | none above the threshold on the tool set; packed benign tools render as low suspicion with the packer named | `wget.exe` 7/8, `klogger.exe` 6/8 |
| Static (ELF) | launcher stubs with three or fewer substantive imports (`node`, `gvpr`, `selinuxenabled`); vendor executable sections with non-compiler names (libGL `wtext`, absl `malloc_hook`); one old build with an executable stack; one archiver with an appended data block. Sanitizer runtimes, `libeatmydata` and sudo's noexec shims are named as known libc interposers and not scored | 21 of 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec` and `/usr/lib/systemd` carry one weight-1 observation; 0 reach the threshold; 40 of 40 signed kernel modules score 0; a UPX-packed `ls` scores 6/8 |
| Static (ELF, deep resolution) | the relocation-resolved `.init_array`, symbol-version and raw-syscall-interposer rules add information, not weight, on ordinary software: a normal PIE's constructors resolve into `.text`, a libc build is named as a known interposer, and symbol versions are informational | no benign ELF in the local test corpus crosses the threshold from these rules; a full re-measurement against the 4,974-file set is pending (it is the same open item as every number here) |
| Static (Mach-O) | measurement pending — the Mach-O pass is new and no macOS corpus has been scanned on the development host. `unsigned` and `signature-unverified` are informational (weight 0), and `encrypted` is weight-1 with the FairPlay-vs-protector ambiguity stated in its detail | 0 measured; a macOS package-set scan is required before a field number can be published |
| Stego | a stray ZERO WIDTH SPACE pasted into documentation or a translation file; source files that enumerate Unicode categories (regular-expression libraries, identifier tables); a stray byte-order mark mid-file | 70 of 70,102 benign text artifacts (0.10 %) |
| Fusion | none observed; the conditional chains each require two independent detectors, so a chain's false-positive surface is the intersection of two error modes, not their union | 0 fused-only detections on the tool set; chain rules measured against the same set show no benign tool escalated by a chain alone |
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
| base64 of the whole file | **evades the byte-pattern match** | the contiguous byte sequence is gone; this is the documented encoding gap for raw YARA/heuristics, and it is why the engine also runs the encoded-executable pass and the bounded peeler |

The base64/encryption gap is fundamental to byte-pattern matching and is why
the engine fuses several detectors rather than trusting any one. Peeling
encoded layers is no longer only planned: the encoded-executable pass
(`scanner/encchain`) recovers embedded base64/hex executables, the bounded
peeler (`internal/peeler`, NOVEL-012) unwraps an obfuscation tree, and the
fusion lattice's `peel-revealed` chain feeds a peeled layer that a behavioural
detector then flagged back into the verdict. What remains planned is the
emulation fallback for layers the bounded peeler cannot reach. The robustness
harness runs on synthetic samples only and ships no bypass.

The stego pass is presence-based on purpose: a single pasted codepoint is
reported as exactly one occurrence with no payload run, so an analyst can
tell it from an encoded channel at a glance, and `--stego-threshold 8` makes
the engine require a payload run or an ASCII carrier as well.

## Scoring: weighted fusion plus conditional chaining

The fusion lattice (`scanner/fusion`) combines the detectors two ways. The base
is an independent weighted sum: each source is normalised to a ratio against its
own threshold, the strongest counts in full and the rest corroborate at a
fraction, so evidence that is below every individual floor can still cross the
fused bar. On top of that, a small set of **conditional chains** states
attack paths — a packed image that also carries injection capability, a document
or container that also carries an encoded executable, an obfuscation layer
peeled away to reveal content a behavioural detector flagged. A chain adds a
bounded, capped bonus only when two or more *distinct* counted sources match it,
so it expresses that findings on one file reinforce each other without letting
any single detector masquerade as a path. The chaining is monotone — it only
ever raises a verdict — never downgrades a definitive hash or YARA hit, and the
flat weighted sum is preserved unchanged so the measured false-positive baseline
keeps its meaning. The limits of the chain set are the limits of any tuned
content: the three shipped chains were fixed against the same fixtures as the
numeric parameters, and the field-false-positive caveat below applies to them
too.

## What is not covered yet

- **File formats.** The structural pass parses PE, ELF (32- and 64-bit, both
  byte orders; executables, shared objects, relocatable objects and kernel
  modules) and Mach-O (thin and universal/fat, 32- and 64-bit, both byte
  orders). Dedicated passes also cover OLE / VBA, PDF, Shell Links (LNK),
  ISO 9660 containers, compressed archives (ZIP / TAR / gzip and tar.gz),
  Compiled HTML Help (CHM) and UEFI firmware (`cau firmware`: Firmware-Volume
  and FFS enumeration). Every other container — Mach-O fat embeds aside — falls
  back to hashing, YARA, heuristic strings, entropy, fuzzy digests and the stego
  pass only.
- **Archives and CHM, what the passes do not do.** The archive pass enumerates
  members and scores container hygiene (decompression-bomb ratio/absolute caps,
  Zip-Slip path traversal, lure double-extensions, single-executable and
  encrypted/script/nested members) from the central directory and bounded
  member peeks; it does not recursively scan each member's content through the
  full engine, and it reads a member's magic from at most a few hundred
  decompressed bytes. The CHM pass enumerates the ITSF/ITSP/PMGL directory and
  scores embedded executables, shortcuts and dangerous scripts by member name;
  the LZX-compressed content section is not decompressed, so HTML/script bodies
  and the `<OBJECT>` shortcut/WinExec tradecraft inside them are not inspected
  in v1 (it says "present but not inspected" rather than guessing). Plain `.js`
  inside a CHM is deliberately not scored — help-file navigation uses it
  legitimately.
- **Firmware, what the pass does not do.** The UEFI pass (`cau firmware`, its
  own workflow rather than part of the per-file scan) walks Firmware Volumes and
  the FFS files and sections inside them and reports a module inventory, the FV
  header's 16-bit-checksum integrity, and any module GUID matching an
  operator-supplied implant blocklist. It ships **no implant truth set**:
  firmware is overwhelmingly legitimate PEI/DXE/SMM drivers, so scoring module
  shapes would be a false-positive machine, and the only scored signals are a
  checksum failure (a genuine tamper tell) and a blocklist match (empty by
  default, loaded with `--implants`). Module bodies are inventoried, not
  disassembled; GUIDed/compressed sections are not decompressed; the Intel flash
  descriptor's region layout is detected but not fully parsed; NVRAM, signatures
  and boot policy are not analysed. This is the Phase-8 wedge with a small-n
  truth set, stated as such rather than oversold.
- **ELF, what the pass does not do.** It reads headers, segments, sections, the
  dynamic table, symbols, versions (`.gnu.version_r` / `_d`), notes and
  `.modinfo`. It resolves `.init_array` and `.preinit_array` constructor
  pointers — directly for a non-PIE image, and through `R_*_RELATIVE`
  relocations for a PIE — and flags any that land outside executable code; it
  does not otherwise apply relocations. It computes telfhash (over the
  Trend Micro filtered symbol set) alongside the CAU import-set clustering key,
  but telfhash is empty for a symbol set below TLSH's 50-byte floor because this
  TLSH library has no `forcehash`. The libc-interposer rule now fires on a
  preload library whether it resolves the originals through `dlsym` or reaches
  the kernel through raw syscalls (x86-64, i386 and aarch64 opcodes are
  recognised; other architectures leave the syscall count at zero). A kernel
  module's appended signature is detected, never verified (the kernel keyring is
  not available to a file scanner, and the report says so).
- **Mach-O, what the pass does not do.** It reads the header, load commands,
  segments and sections, linked dylibs, `LC_RPATH`, the `LC_MAIN` /
  `LC_UNIXTHREAD` entry point, `LC_CODE_SIGNATURE` (presence only — the
  signature is not verified against a trust store) and `LC_ENCRYPTION_INFO`, and
  it enumerates imports and exports from `LC_SYMTAB`. It does not walk the
  `LC_DYLD_INFO` bind/export trie, so two-level-namespace bind targets beyond
  the classic symbol table are not resolved; code-signature contents (CDHash,
  entitlements, Team ID) are not parsed; and the FairPlay-vs-protector ambiguity
  of an encrypted load region cannot be resolved from the file alone.
- **Linux packages, what the pass does not do.** The package detector
  (`scanner/linuxpkg`) is detection-only and standard-library-only: it reads
  install-time scripts from the package structure but never installs, extracts
  to disk or executes anything. Because it is pure Go, members packed with xz or
  zstd (some `.deb` control tarballs, some Arch packages) and the SquashFS inside
  AppImage and Snap are not decompressed — it records an honest "present but not
  inspected" note rather than guessing, so a payload reachable only through those
  is out of reach for v1. It scores script *tradecraft*, not package identity: a
  benign maintainer script that legitimately does something unusual can score,
  and a malicious payload that avoids the scored patterns can score low.
  Threshold 8, SUSPICIOUS tier only.
- **Unpacking.** Packed samples are identified, and a bounded peeler plus the
  encoded-executable pass now unwrap obfuscation trees and embedded encoded
  binaries (NOVEL-012). The emulation fallback for layers the bounded peeler
  cannot reach is still planned.
- **Behaviour.** The engine is static. Process lineage, network and runtime
  telemetry are the sensor's job, outside this repository.
- **Field false positives.** Every number here is fixture-derived from one
  machine's package set; a real corpus is Phase 1's open item. The Mach-O pass
  and the new ELF deep-resolution rules carry no field number yet — they have
  been exercised only against synthetic fixtures and the local binary set.
- **Trust.** No certificate chain is verified against a trust store, by
  design and by name — on PE Authenticode, on ELF kernel-module signatures and
  on Mach-O code signatures alike.

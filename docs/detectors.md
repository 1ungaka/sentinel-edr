# Detectors

Every file is read once. The same buffer is hashed, scanned by libyara, and
handed to the heuristic, static and stego passes; the fusion lattice then
joins their outcomes. Each detector answers a different question:

| Detector | Question | Tier on a hit |
|---|---|---|
| [Hash signatures](#hash-signatures) | is this exact content known? | MALICIOUS |
| [YARA](#yara) | does it contain patterns a rule author described? | MALICIOUS |
| [Heuristics](#heuristics) | does it name suspicious capabilities? | SUSPICIOUS |
| [Static structure](#static-structure) | is it *built* like something that hides? | SUSPICIOUS |
| [Invisible codepoints](#invisible-codepoints-stego) | does this text or code carry hidden codepoints? | SUSPICIOUS |
| [Encoded executable](#encoded-executable) | is an executable hidden behind text encoding? | SUSPICIOUS |
| [Shell Link (.lnk)](#shell-link-lnk) | is this Windows shortcut a weaponised launcher? | SUSPICIOUS |
| [OLE macro](#ole-macro) | does this Office document carry a malicious VBA macro? | SUSPICIOUS |
| [PDF document](#pdf-document) | does this PDF auto-run code or carry a payload? | SUSPICIOUS |
| [ISO container](#iso-container) | is this disk image a mark-of-the-web-bypass lure? | SUSPICIOUS |
| [Fusion](#fusion) | do several of the above agree, even below their own thresholds? | never lowers; raises CLEAN to SUSPICIOUS |

SUSPICIOUS is evidence with a score and an explanation, never a confirmed
detection; MALICIOUS is reserved for content that is known. The reports keep
the two apart, and `--fail-on` lets a pipeline choose which one it acts on.

## Hash signatures

MD5, SHA-1 and SHA-256 are computed in one streaming pass and looked up in
the signature database, SHA-256 first. Loading validates every entry (known
type, hexadecimal, exact length for the type) and rejects duplicates; a digest
re-listed under a different name is reported as a conflict and the first
entry kept. Rejected lines are warnings, never silent drops, so the reported
signature count is the number of hashes that can actually match.

A hash hit carries the digest type, the digest and the threat name.

## YARA

Rules are compiled once at startup with libyara (through go-yara) and matched
in memory. A rule file that does not compile is reported with file, line and
column and skipped; the rest of the ruleset still loads; a ruleset with no
usable rule is a hard error. Compiler warnings (slow strings, rules that can
never match) are shown, not suppressed.

Each match carries the rule name, the namespace libyara reports (not a file
name), tags, the full `meta:` block and every matched string with its absolute
offset. A per-file timeout (`--yara-timeout`, 30 s) bounds adversarial
inputs; matches found before the timeout are kept and the timeout is recorded
as a warning on the file.

Rule conventions (`ascii wide`, `threat_level`, `family`, `mitre_attack`) are
described in [Detection content](detection-content.md).

## Heuristics

The heuristic pass scores two kinds of evidence: Windows API names in a PE
import table, and substrings of the printable ASCII and UTF-16LE strings of
any file. The scoring model exists because the original implementation scored
every string that contained `http://`, so a binary carrying its certificate
chain scored sixteen points from CRL URLs alone:

1. A pattern scores **once per file**, however many strings contain it.
2. Every category has a cap; five crypto imports are not five times as
   suspicious as one.
3. The weak categories (networking, timers, file deletion, discovery, temp
   paths, memory protection, Unix shell and download-tool references) share a
   budget of 2 points in total, so ordinary program behaviour never adds up to
   a detection.
4. An API credited from the import table is not scored again as a string.

The threshold (7) was chosen on the 349 files of Kali's Windows tool set so
that single-capability binaries stay below it and multi-stage behaviour
(injection plus persistence, credential access plus network, encoded
PowerShell plus download) crosses it. That retune cut detections from 60 to
28; plink went 24 → 5, vncviewer 11 → 4, dbghelp.dll 13 → 4, while mimikatz,
wce, pwdump and PowerSploit stayed detected. OllyDbg still scores 11: a
debugger has exactly the import profile of a process injector, and the report
names the imports responsible.

Every category maps to an ATT&CK technique, rendered in text and JSON and
carried into fused verdicts:

| Category | Cap | Technique |
|---|---|---|
| Process Injection | 8 | T1055 |
| Process Hollowing | 3 | T1055.012 |
| Anti-Debug | 3 | T1622 |
| Timing / Sandbox Evasion (weak) | 4 | T1497.003 |
| Privilege Escalation | 3 | T1134 |
| Registry Persistence | 3 | T1547.001 |
| Service Persistence | 3 | T1543.003 |
| Startup Folder Persistence | 2 | T1547.001 |
| Network Activity (weak) | 4 | T1071 |
| URL Download API | 3 | T1105 |
| Keylogging | 5 | T1056.001 |
| System Discovery (weak) | 4 | T1082 |
| Process Discovery (weak) | 4 | T1057 |
| File Manipulation (weak) | 4 | T1070.004 |
| Encryption / Ransomware | 6 | T1486 |
| Credential Access | 8 | T1003 |
| Memory Protection (weak) | 4 | T1055 |
| Shell Execution | 2 | T1059.003 |
| Encoded PowerShell | 3 | T1027.010 |
| PowerShell Execution | 3 | T1059.001 |
| Script Execution | 2 | T1059.005 |
| LOLBin Execution | 3 | T1218 |
| LOLBin Download | 3 | T1105 |
| Shadow Copy Deletion | 4 | T1490 |
| Suspicious Paths (weak) | 4 | none |
| Account Discovery | 2 | T1087 |
| Ransom Note | 5 | T1486 |
| Ransomware Family | 3 | T1486 |
| VM Detection | 2 | T1497.001 |
| Sandbox Detection | 3 | T1497.001 |
| Unix Shell Reference (weak) | 4 | T1059.004 |
| Download Tool Reference (weak) | 4 | T1105 |
| Kernel Rootkit | 6 | T1014 |

Import names come from the PE import table or, for ELF, the undefined dynamic
symbols (a kernel module's undefined `.symtab` entries). The Linux entries
are few on purpose, because an ELF import table names libc and libc is not
evidence: `ptrace`, `process_vm_readv` / `process_vm_writev` and
`pidfd_getfd` score as injection (`sudo`, `strace` and `gdb` import them
legitimately and stay below the threshold), and Kernel Rootkit holds what a
module needs to find and patch kernel text (`kallsyms_lookup_name`,
`register_kprobe`, `ftrace_set_filter_ip`, `set_memory_rw`, `text_poke`,
`sys_call_table`), which no ordinary driver imports.

The indicator tables are in `scanner/heuristics.go`; `scanner.Categories()`
returns this table programmatically.

## Static structure

`scanner/static` asks whether a file is built like something that is hiding.
It runs on every file type; the PE parts run on PE images and the ELF parts
on ELF images (32- and 64-bit, both byte orders: executables, shared objects,
relocatable objects and kernel modules).

- **Entropy**: whole-file Shannon entropy plus a 256-byte sliding window, so
  a compressed tail inside an otherwise ordinary file shows as a high-entropy
  fraction.
- **Fuzzy digests**: TLSH and ssdeep for every file, imphash for PE files
  (pefile-compatible, including the ws2_32 / wsock32 / oleaut32 ordinal
  tables). With a fuzzy database, matches become evidence: TLSH distance ≤ 30
  or ssdeep score ≥ 70, always reported with the distance and the matched
  entry's name.
- **PE anatomy** from an own parser that checks every offset against the
  buffer (the standard library's `debug/pe` drops ordinal imports, which
  breaks imphash, and trusts header sizes): sections with permissions and
  entropy, entry-point placement, import profile, delay and bound imports,
  exports, debug directory and PDB path (metadata only, never scored), TLS
  callbacks, overlay with the certificate table separated out, the Rich header
  with its checksum, and the Authenticode certificate chain.
- **ELF anatomy** from an own parser under the same rule (`debug/elf` trusts
  header counts and allocates what they declare): program headers with
  permissions and entropy, section headers with the stripped and
  pointing-outside-the-file cases named, `PT_INTERP`, the dynamic table
  (`DT_NEEDED`, `SONAME`, `RPATH` / `RUNPATH`, `DT_INIT`, text relocations,
  PIE and bind-now flags), undefined and defined dynamic symbols (a
  relocatable object's `.symtab` instead), GNU build-id and ABI notes,
  `.modinfo` and the appended kernel-module signature, overlay with the
  signature separated out, AppImage magic, UPX markers, and an import-set
  hash for clustering (MD5 over the sorted undefined symbol names; a CAU key,
  not telfhash).

Findings are labeled **anomaly classes**, each with a weight, a category and
an ATT&CK technique where one applies. Categories are capped (Sections 5,
Entry Point 4, Headers 3, Imports 3, Packer 4, Signature 8, Overlay 2,
Format 3, Similarity 8; for ELF also Dynamic Linking 4 and Kernel Module 3)
and the threshold is 8, so several independent things must be wrong at once.

| Class | Weight | Meaning |
|---|---|---|
| `section.rwx` | 3 | writable and executable section (T1027.009); a kernel driver's `INIT` is exempt |
| `section.exec-high-entropy` | 2 | executable section above 7.0 bits/byte (T1027) |
| `section.name-perm-mismatch` | 2 | `.text` not executable, data section executable (T1036) |
| `section.virtual-raw-mismatch` | 2 | executable section far larger in memory than on disk: an unpack target (T1027.002) |
| `section.exec-unusual-name` | 1 | executable section with a non-compiler name |
| `entrypoint.zero`, `.outside-sections`, `.non-exec-section`, `.zero-raw-section`, `.last-writable-section` | 2, 3, 2, 3, 1 | where the entry point lands |
| `tls.callbacks` | 1 | code that runs before the entry point |
| `header.timestamp-zero`, `-future`, `-ancient`, `-mismatch` | 1, 2, 1, 2 | link-time inconsistencies (T1070.006); Delphi's constant 1992 stamp and reproducible builds are explicit non-findings |
| `rich.checksum-invalid`, `rich.missing-msvc` | 2, 1 | copied or stripped build record (T1036) |
| `header.low-alignment` | 1 | hand-built or squeezed image |
| `imports.none`, `.empty-descriptors`, `.loader-only`, `.minimal` | 2, 2, 2, 1–2 | import table that says nothing (T1027.007) |
| `packer.generic` / `packer.<name>` | 3 / 2 | packed profile; a recognised packer (UPX, ASPack, Themida, VMProtect, ...) weighs *less* because the report names it; installer stubs are informational |
| `overlay.high-entropy`, `overlay.present` | 2, 1 | data appended past the last section (T1027.009) |
| `authenticode.vendor-name-self-signed` | 6 | a self-signed certificate wearing a well-known vendor's name crosses the threshold on its own (T1036.001) |
| `authenticode.self-signed`, `.no-codesign-eku`, `.long-validity`, `.compiled-outside-validity`, `.parse-error` | 3, 2, 1, 2, 1 | signer implausibility (T1553.002, T1070.006, T1036.001) |
| `format.truncated`, `.section-overlap`, `.no-sections`, `.unparseable` | 2 each | malformed images |
| `fuzzy.tlsh`, `fuzzy.ssdeep`, `fuzzy.imphash` | 8, 5–8, 4 | similarity to a database entry |

ELF classes (the shared names above keep their weights; `segment.*` is the
`PT_LOAD` view):

| Class | Weight | Meaning |
|---|---|---|
| `segment.rwx` | 3 | writable and executable `PT_LOAD` (T1027.009) |
| `segment.exec-high-entropy`, `segment.virtual-raw-mismatch` | 2, 2 | executable segment above 7.0 bits/byte; executable segment far larger in memory than on disk (T1027, T1027.002) |
| `section.headers-missing` | 2 | no section table at all: sstrip, a packer or a hand-built loader (T1027.002) |
| `section.name-perm-mismatch`, `section.exec-unusual-name` | 2, 1 | as for PE; the kernel's own executable section names and `.text.*` are exempt |
| `entrypoint.zero`, `.outside-segments`, `.non-exec-segment`, `.outside-sections`, `.non-exec-section` | 2, 3, 2, 2, 2 | where the entry point lands |
| `segment.exec-stack`, `segment.no-gnu-stack` | 2, 1 | `PT_GNU_STACK` requests an executable stack, or is absent from a dynamically linked image |
| `dynamic.interp-unusual` | 2 | program interpreter outside the system loader directories or not named like a loader (T1574) |
| `dynamic.rpath-insecure` | 2 | `RPATH` / `RUNPATH` with a relative or empty component, or under `/tmp`, `/dev/shm`, `/home` and the like (T1574); `$ORIGIN` idioms are informational |
| `dynamic.needed-path`, `dynamic.textrel`, `dynamic.init-outside-code` | 1, 1, 2 | dependency named by path; text relocations; `DT_INIT` outside executable memory (T1574, T1027) |
| `dynamic.preload-interposer` | 3 | a shared object that defines two or more of the libc entry points preload rootkits replace (`readdir`, `open`, `stat`, `accept`, `execve`, `ptrace`, ...) and imports `dlsym` to reach the originals (T1574.006); sanitizer runtimes, fakeroot, `libeatmydata`, sudo's noexec shims and other known interposers are reported at weight 0 under `-known` |
| `imports.none`, `.loader-only`, `.minimal` | 2, 2, 1–2 | a dynamically linked image that imports nothing, only `dlopen` / `dlsym` and memory calls, or three or fewer substantive symbols (T1027.007); statically linked images are informational |
| `packer.upx` / `packer.generic` | 2 / 3 | UPX by its `UPX!` markers (the copyright banner alone is not evidence: the `upx` binary carries it); otherwise no section table plus a packed executable segment plus nothing imported |
| `overlay.present`, `overlay.high-entropy` | 1, 2 | data past the end of every header, segment and section (T1027.009); an AppImage's appended filesystem is informational |
| `module.unsigned`, `module.info-missing` | 1, 2 | a kernel module without an appended signature (presence only: the keyring is not here), or without `.modinfo` vermagic (T1014) |
| `header.class-machine-mismatch`, `format.program-table-invalid`, `format.section-table-invalid`, `format.truncated`, `format.interp-without-dynamic`, `format.type-unknown` | 1, 2, 2, 2, 2, 2 | malformed images; a section table pointing outside the file is the classic trick that breaks analysis tools while the loader does not care |

Honesty rules baked into the output: packed is not malicious (a Debian-shipped
UPX binary is packed, correctly, by provenance); signature presence is not
validity (nothing is verified against a trust store, `verified` is always
`false` and the report says so); similarity is evidence, not identity.
Measured on the 49 PE files in `/usr/share/windows-resources`, 43 score 0,
the UPX-packed `wget.exe` scores 7 and renders as low suspicion with the
packer named, nothing crosses the threshold, and credential tools score 0 here
by design because capability is the heuristic pass's job.
Measured on 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`,
`/usr/lib/x86_64-linux-gnu`, `/usr/libexec` and `/usr/lib/systemd` plus 40
signed kernel modules, nothing crosses the threshold and 21 files carry a
single weight-1 observation (launcher stubs with three or fewer imports,
vendor executable sections such as libGL's `wtext`); a UPX-packed `ls`
scores 6 and renders as low suspicion with the packer named; `libasan`,
`libeatmydata` and sudo's noexec shims are named as known interposers at
weight 0.

`static.Classes()` returns this catalog programmatically, with a test that
pins it to the emitting code; `cau coverage` reads it.
`cau hash` prints the digests, `cau cluster` groups PE and ELF files by
import similarity (exact imphash or ELF import-set hash, then MinHash / LSH
over import sets).

## Invisible codepoints (stego)

`scanner/stego` examines text artifacts (valid UTF-8, or UTF-16 with a
byte-order mark; binary content is skipped and the reason recorded) for
codepoints that have no glyph:

| Class | Codepoints | Weight | What it carries |
|---|---|---|---|
| `zero-width` | ZERO WIDTH SPACE / NON-JOINER / JOINER, WORD JOINER, the invisible operators, COMBINING GRAPHEME JOINER, MONGOLIAN VOWEL SEPARATOR, ZERO WIDTH NO-BREAK SPACE | 6 | the alphabet of zero-width steganography: README dead-drop channels, payloads between the words of a comment |
| `bidi-control` | directional embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069) | 6 | Trojan Source (CVE-2021-42574): source that compiles differently from how it is displayed |
| `tag` | U+E0000–U+E007F | 6 | invisible copies of ASCII used to smuggle text past filters and into language models |
| `variation-selector` | U+FE00–U+FE0F, U+E0100–U+E01EF where no base character wants them | 4 | 256 invisible values make a byte alphabet |
| informational | LEFT-TO-RIGHT / RIGHT-TO-LEFT MARK, ARABIC LETTER MARK, SOFT HYPHEN | 0 | recorded, never scored |

Detection is **presence-based**: density thresholds are the first thing an
encoder drops below. What keeps it usable is a closed list of context rules,
each named in the report when it applies:

- U+FEFF at offset 0 is a byte-order mark.
- ZERO WIDTH JOINER next to a pictographic codepoint, a skin-tone modifier or
  a presentation selector is an emoji sequence.
- ZERO WIDTH JOINER / NON-JOINER next to a script that uses joiners (Arabic,
  Persian, Hebrew, the Indic scripts, Myanmar, Khmer, Mongolian, ...) is
  typography.
- ZERO WIDTH SPACE next to a script written without inter-word spaces (Khmer,
  Thai, Lao, Myanmar, Tibetan) is that script's word separator.
- A directional control on a line that holds right-to-left text is
  bidirectional typesetting; on a line of ASCII it stays scored.
- VARIATION SELECTOR-15/16 directly after an emoji is presentation; a CJK
  variation selector directly after a CJK ideograph is an ideographic variant;
  a selector after anything else, or a second selector in a row, carries data.
- TAG characters inside a subdivision-flag sequence (after U+1F3F4) are a
  flag.

Two modifiers raise the score without being findings: a run of eight or more
consecutive invisible codepoints (`stego.payload-run`, payloads have length)
and codepoints whose visible neighbours on both sides are ASCII
(`stego.ascii-carrier`, the dead-drop pattern). The default threshold (4) is
reached by any scored class; `--stego-threshold 8` requires a modifier too.

The report lists every codepoint with its count, how many occurrences a
context rule excused and which rule, the first line and byte offset, and up
to two bounded examples with the invisibles rendered as `<U+200B>`.

Measured on 70,102 benign text artifacts (every text file under Kali's
`/usr/share/doc` and `/usr/lib/python3/dist-packages`) the pass fires on 70,
a 0.10 % false-positive rate, and on none of the 294 text files in
`/usr/share/windows-resources`; the context rules excused 348 legitimate
uses. The remaining false positives are the two documented classes: a stray
ZERO WIDTH SPACE pasted into documentation or a translation file, and source
files that enumerate Unicode categories. See [Limitations](limitations.md).

This is the engine half of the plan's NOVEL-001 / NOVEL-002 rows; findings
carry `technique: T1027` and `novel: NOVEL-001`.

## Encoded executable

`scanner/encchain` answers a question the byte-pattern detectors cannot: is a
PE or ELF image hidden behind one or more layers of base64 or hex encoding? An
encoded executable has no contiguous `MZ`/`\x7fELF` sequence for a hash, YARA
rule or heuristic to match, so a dropper that carries its payload base64-encoded
in a script, document or `.bs64` blob slips past them.

The detector scans for base64 and hex runs (MIME line-wrapping tolerated),
decodes each — bounded by a layer cap, a byte budget and a candidate cap so a
decode bomb cannot exhaust it — and reports a finding when a decoded layer is a
**valid** PE header (the `MZ` magic plus a `PE\0\0` signature at the
`e_lfanew` offset) or ELF header (the magic plus a valid class, data encoding
and version). Peeling more than one layer is reported with its depth. The
signal is content-anchored: the decoded bytes are an executable, which an
attacker cannot shed without losing the payload. It is the engine half of the
plan's NOVEL-012; findings carry `technique` T1027.013 (a straight decode) or
T1140 (through layers) and `novel` NOVEL-012.

It is SUSPICIOUS-tier, never MALICIOUS: an embedded encoded binary is strong
evidence, not proof of malice (installers and security tools carry them too).
Measured over 159,339 benign files from a Kali install, it fired on 32
(0.020 %), every one a genuine embedded encoded executable in offensive
tooling or exploit documentation. `--no-encchain` disables it and
`--encchain-threshold` tunes the score.

## Shell Link (.lnk)

`scanner/lnk` reads the Windows Shell Link ([MS-SHLLINK]) binary format and
asks whether a shortcut is a weaponised launcher — the classic ISO/ZIP lure
that drops a `.lnk` whose arguments relaunch an interpreter. It parses the
ShellLinkHeader, the optional LinkTargetIDList and LinkInfo, the StringData
sections (name, relative path, working directory, **command-line arguments**,
icon location) and the ExtraData blocks, through a bounds-checked cursor that
caps every declared size and never recurses, so a truncated or adversarial
shortcut yields a partial result with a warning rather than a panic.

The findings are small additive signals, each mapped to ATT&CK: an interpreter
or LOLBin in the arguments (`powershell`→T1059.001, `cmd`→T1059.003,
`wscript`/`cscript`→T1059.005, `mshta`/`rundll32`/`regsvr32`/… →T1059), encoded
or obfuscated command flags (`-enc`, `FromBase64String`, `IEX`, …→T1027), a
hidden-window flag (T1027), environment-variable path obfuscation (T1027), an
executable or script target (T1204.002), a document-icon lure fronting an
interpreter (T1204.002), unusually long arguments, and data appended past the
shortcut structures (T1027). The default threshold (8) is chosen so no single
benign tell crosses it while a real combination does — an interpreter plus an
encoded flag, or an interpreter plus a hidden window.

It is SUSPICIOUS-tier, never MALICIOUS: the structure is strong evidence of a
launcher, not proof of malice (legitimate installers ship shortcuts too).
`--no-lnk` disables it and `--lnk-threshold` tunes the score.

## OLE macro

`scanner/ole` reads the OLE Compound File Binary ([MS-CFB]) container behind
legacy-Office documents (`.doc`/`.xls`/`.ppt`) and asks whether it carries a
malicious VBA macro — the phishing-lure dropper that auto-runs on open and
shells out to an interpreter or pulls a stage-two payload. It parses the CFB
(header, DIFAT, FAT, directory, MiniFAT/mini-stream) through bounds-checked
accessors that cap every declared size, detect FAT/MiniFAT chain cycles with a
visited-set, and bound the total bytes resolved, so a malformed or adversarial
document yields a partial result with a warning rather than a panic, a hang or
unbounded memory. It then locates the VBA module streams, decompresses their
[MS-OVBA] `CompressedContainer` source (a bounded, cycle-free implementation of
the container/chunk/token algorithm), and reads the macro source.

The findings are ATT&CK-mapped signals: a VBA project at all (T1059.005, low
weight — legit docs have macros), an **auto-executing entry point**
(`AutoOpen`, `Document_Open`, `Workbook_Open`, … → T1137), a shell or
interpreter call (`Shell`, `powershell`, `cmd` → T1059.001/.003/.005), a
downloader (`URLDownloadToFile`, `MSXML2.XMLHTTP` → T1105), late-binding
(`CreateObject`/`GetObject`), heavy character-code obfuscation (T1027), and
embedded-object / Equation-Editor lures (`\x01Ole10Native`, `Equation Native` →
T1204.002 / T1203). The default threshold (8) is chosen so a plain
macro-bearing document stays below it while an auto-exec entry point plus a
suspicious call crosses it.

It is SUSPICIOUS-tier, never MALICIOUS: a macro is strong evidence, not proof
(business documents legitimately automate). `--no-ole` disables it and
`--ole-threshold` tunes the score.

## PDF document

`scanner/pdf` detects malicious PDFs — the phishing lure whose document
auto-runs JavaScript, launches an external program, or carries an embedded
payload. A full PDF parse is unnecessary and, on adversarial files, dangerous,
so the detector is a **bounded lexical + shallow-structural scan** (the tool
most PDF-malware detectors actually use): it never recurses, caps the bytes it
reads and the number of name tokens it processes, and returns a partial result
with a warning rather than hanging. It first resolves PDF name obfuscation —
names may hex-escape characters as `#xx` (`/J#61vaScript` is `/JavaScript`), so
matching is done against the decoded canonical name.

The ATT&CK-mapped signals: an auto-run action (`/OpenAction`, `/AA` → T1204.002),
embedded JavaScript (`/JavaScript`, `/JS` → T1059.007), a `/Launch` action
(T1059), an embedded-file payload (`/EmbeddedFile` → T1204.002), a remote fetch
(`/SubmitForm`, `/GoToR` → T1105), a `/URI` link (T1204.001, low weight),
JavaScript exploitation primitives (`unescape`, `eval`, `%u` heap-spray,
`getAnnots` → T1027), and — the strongest intent signal — a sensitive name
spelled with `#xx` hex escapes (T1027), which benign PDFs essentially never do.
Encryption is noted but never scored alone (many benign PDFs are encrypted); it
adds a tiny amplifier only when combined with an auto-run action and JavaScript.
The default threshold (8) is chosen so a plain PDF with a benign link stays well
below while the canonical `OpenAction`→`JavaScript` dropper crosses.

It is SUSPICIOUS-tier, never MALICIOUS. `--no-pdf` disables it and
`--pdf-threshold` tunes the score.

## ISO container

`scanner/iso` recognises the ISO/IMG email-smuggling delivery shape: attackers
mail a small `.iso` that, when mounted, shows a `.lnk` relaunching an
interpreter against a hidden payload — a route that became popular because
mounted-image contents historically did not inherit Mark-of-the-Web. The
detector reads the ISO 9660 directory tree (with Joliet UCS-2 names when
present) through a parser that is enumeration-only — it never reads file
contents — and bounded by construction: an explicit queue instead of recursion,
caps on records/sectors/entries/depth, a visited-set of extent LBAs that breaks
self-referential extents, and a range check on every sector and record, so a
malformed image yields a partial enumeration with a warning rather than a hang.

The ATT&CK-mapped signals: `autorun.inf` in the root (T1091), a `.lnk` shortcut
(T1204.002), an executable or script file (T1204.002), a hidden-flagged
executable or a payload inside a hidden directory (T1564.001), and — the
canonical lure — a `.lnk` present together with an executable payload
(`iso.lure.lnk-and-payload`, T1204.002), with a tiny extra weight when the image
is also small (the attachment shape). The default threshold (8) is tuned so a
legitimate software ISO full of executables does not cross on executables alone,
while the lnk-plus-payload smuggling shape does. The detector enumerates the
container shape; the files it names are scanned on their own by the other
detectors.

It is SUSPICIOUS-tier, never MALICIOUS. `--no-iso` disables it and
`--iso-threshold` tunes the score.

## Fusion

Each detector's threshold is tuned so that it alone stays quiet on ordinary
software. The cost is that a file scoring 5/7 on the heuristics and 6/8 on
the structural pass used to be CLEAN although two detectors with uncorrelated
error modes both saw something. `scanner/fusion` makes that corroboration
count:

1. Every scored source becomes a **ratio** score/threshold, capped at 1.5 so
   one loud detector is still one detector.
2. The strongest source is **primary** and counts in full. Every other source
   at or above **0.4** of its own threshold is **corroborating** and counts at
   **0.5** × ratio. Weaker evidence (one `Sleep` import) is listed as
   below-floor and does not count.
3. The fused score reaches **1.0** when a detector crosses alone, exactly as
   before, or when corroboration adds up to the same thing. Two sources at
   0.7 of their thresholds fuse to 1.05 and alert; one at 0.9 and one at 0.2
   fuse to 0.9 and do not.
4. A hash or YARA hit is **definitive**: it is never downgraded, and next to
   it a scored source either corroborates (at or above the floor) or does
   not.

The verdict carries a tier (`clean`, `observed`, `suspicious`, `malicious`),
the fused score, a confidence (`low`, `medium`, `high`), the sources that
agreed strongest first, the union of their ATT&CK and NOVEL ids, every source
with its role (`definitive`, `primary`, `corroborating`, `below-floor`,
`silent`, `skipped`) and evidence, a one-line explanation, and a
`corroborated` flag that is set when the suspicious tier was reached only
through the lattice. Those are the detections fusion adds; they are what the
`fusion` eval detector, the `fusion/corroborated` SARIF rule and the
"Fused-only detections" summary line count. Fuzzy-hash matches are their own
`similarity` source, separate from the structural score.

The lattice never creates evidence: a file silent on every detector stays
clean, and raising any input never lowers the fused score or tier (a
randomized test pins this). Measured on the 349 files of the Kali Windows tool
set: zero fused-only detections and zero new false positives; the nearest
benign file (the UPX-packed `wget.exe`, static 7/8) has no second source
above the floor.

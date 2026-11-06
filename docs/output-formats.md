# Output formats

`cau scan` writes one report per run in one of three formats. The text format
is for people; JSON and SARIF are for machines. Both machine formats are
written even when the run fails (with `run_error` set and exit code 3), so a
pipeline always gets a document, and the stderr banner never enters them.

Rules that apply to every format:

- **Never trust the input.** Every string that came from a scanned file or a
  signature database is length-bounded before it reaches the output (matched
  blobs to 256 bytes, hashes to 128 characters, messages to 1024 runes, with
  an explicit truncation marker and the original length), invalid UTF-8 is
  replaced, and JSON HTML escaping stays on so a hostile file name cannot
  inject markup into a web UI.
- **Text output escapes control and bidi characters** (`report.TermSafe`). A
  file name carrying `\x1b[2K\r [CLEAN] harmless.txt\x1b[8m` would otherwise
  erase its own line, print a forged verdict and conceal the rest of the
  scan; a newline would forge a whole line. The text report and every other
  human CLI surface escape ANSI CSI/OSC sequences, BEL, backspace, bidi
  overrides and stray newlines inside a quoted path. JSON, SARIF and OCSF
  keep the exact bytes, because machines parse them.
- **Reporters never fail on suspicious content.** They fail only if the
  output cannot be encoded or written.
- **Thresholds are recorded.** Each result carries the threshold it was
  scored against, so a report produced with `--heuristic-threshold 5` says
  `score 6 / threshold 5`, not the default.

## Text

One block per finding, a one-line `[CLEAN]` or `[~] LOW SUSPICION` for
everything else, then a summary. Markers:

| Marker | Meaning |
|---|---|
| `[!] DETECTED (Hash)` / `(YARA)` | MALICIOUS, with the signature or the rule, its meta and the matched strings at their offsets |
| `[!] DETECTED (Heuristics)` / `(Static)` / `(Stego)` | SUSPICIOUS, with the score, the threshold and the categories, anomaly classes or codepoints responsible, each with its technique |
| `[!] DETECTED (Fusion)` | SUSPICIOUS by corroboration: no single detector crossed, the agreeing sources are listed with their ratios and evidence |
| `[+] Fusion` | the fused view of a file some detector already flagged, printed only when at least two sources agreed |
| `[~] LOW SUSPICION` | sub-threshold evidence, with the score and the classes seen |
| `[~] SKIPPED` | a pass that did not run on this file (too large, not text), with the reason |
| `[ERR]` | the file could not be scanned |

The summary lists files scanned, detections per detector, errors and the exit
code with its reason.

## JSON

`--format json` writes a single self-describing document.
`schema_version` is `1.11.0` and follows a strict contract: a patch bump
changes nothing a consumer sees; a minor bump adds optional fields or enum
values; only a major bump removes, renames or retypes anything. Consumers
should ignore unknown fields.

```jsonc
{
  "schema_version": "1.11.0",
  "tool": { "name": "CAU EDR", "version": "0.1.0-dev", "tagline": "..." },
  "generated_at": "2026-10-25T09:47:00Z",
  "root": "./dist",                      // present when --dir was the only target
  "summary": {
    "files_scanned": 3, "hash_detections": 0, "yara_detections": 1,
    "heuristic_detections": 1, "static_detections": 0, "stego_detections": 1,
    "encchain_detections": 0, "lnk_detections": 0, "ole_detections": 0,
    "pdf_detections": 0, "iso_detections": 0, "linuxpkg_detections": 0,
    "archive_detections": 0, "chm_detections": 0, "peel_detections": 0, "tradecraft_detections": 0,
    "fusion_detections": 0,              // suspicious by corroboration only
    "errors": 0, "elapsed_ms": 12,
    "heuristic_threshold": 7, "static_threshold": 8, "stego_threshold": 4,
    "encchain_threshold": 8, "lnk_threshold": 8, "ole_threshold": 8,
    "pdf_threshold": 8, "iso_threshold": 8, "linuxpkg_threshold": 8,
    "archive_threshold": 8, "chm_threshold": 8, "peel_threshold": 50, "tradecraft_threshold": 8,
    "verdict": "malicious", "fail_on": "malicious",
    "exit_code": 1, "exit_reason": "exit 1: 1 file(s) matched a hash signature or YARA rule"
  },
  "run_error": "...",                    // only when the run itself failed
  "files": [ { ... } ]
}
```

Per file:

| Field | Content |
|---|---|
| `path`, `size`, `scan_time_ms`, `warnings[]`, `error` | identity and bookkeeping; `verdict` is `clean`, `suspicious`, `malicious` or `error` |
| `hashes` | `md5`, `sha1`, `sha256` |
| `hash_match` | `type`, `hash`, `threat` when a signature matched |
| `yara[]` | `rule`, `namespace`, `tags[]`, `meta[]` as key/value pairs in rule order, `strings[]` with `name`, `offset`, `data_hex`, `preview`, `truncated`, `length`, `xor_key` |
| `heuristics` | `score`, `threshold`, `detected`, `is_pe`, `is_elf`, `skipped`, `categories[]` (`category`, `raw`, `applied`, `cap`, `weak`, `technique`), `matches[]` (`indicator`, `category`, `source`, `pattern`, `score`, `hits`, `examples[]`, `technique`) |
| `static` | `score`, `threshold`, `detected`, `is_pe`, `is_elf`, `entropy`, `high_entropy_fraction`, `tlsh`, `ssdeep`, `imphash` (PE), `import_hash` (ELF import-set key, not telfhash), `pe` (format, machine, subsystem, timestamp, entry point and section, imports, DLLs, sections with permissions and entropy, overlay, packer with evidence, Rich header, signature with the certificate chain and `verified: false` plus a note, debug directory), `elf` (class, byte order, type, machine, OS ABI, entry point and section, interpreter, `pie` / `static` / `stack_executable` / `relro` / `textrel`, build-id, ABI tag, SONAME, `needed[]`, `rpath[]`, `runpath[]`, import and export counts, `segments[]` and `sections[]` with permissions and entropy, overlay, packer, `module` with `signed` as presence only and a note saying so, plus `telfhash` / `telfhash_note` (the note is set when the symbol set is below TLSH's floor) and `syscall_stubs`), `is_macho`, `macho` (`magic`, `byte_order`, `fat`, `arches[]` with `cpu`, `filetype`, `flags[]`, `signed`, `encrypted`, `entry_segment`, `import_count`, `import_hash`, `dylibs[]`), `anomalies[]` (`class`, `category`, `score`, `detail`, `technique`), `categories[]`, `fuzzy_matches[]` (`type`, `hash`, `threat`, `distance`, `score`) |
| `stego` | `score`, `threshold`, `detected`, `is_text`, `encoding`, `skipped`, counts `suspicious` / `benign` / `info`, `longest_run`, `ascii_carrier`, `codepoints[]` (`codepoint`, `name`, `class`, `count`, `benign_context`, `first_offset`, `first_line`, `excuses{}`, `examples[]`), `findings[]` (`class`, `score`, `detail`, `technique`, `novel`) |
| `encchain` | `score`, `threshold`, `detected`, `skipped`, `candidates`, `layers_peeled`, `budget_exhausted`, `findings[]` (the decoded PE/ELF, the encoding and the layer depth) |
| `lnk` | `score`, `threshold`, `detected`, `skipped`, `target_ext`, `args_len`, `findings[]` (`class`, `score`, `technique`, `detail`) — [MS-SHLLINK] |
| `ole` | `score`, `threshold`, `detected`, `skipped`, `has_vba`, `modules`, `findings[]` (`class`, `score`, `technique`, `detail`) — [MS-CFB] + [MS-OVBA] |
| `pdf` | `score`, `threshold`, `detected`, `skipped`, `version`, `has_javascript`, `has_openaction`, `encrypted`, `findings[]` (`class`, `score`, `technique`, `detail`) |
| `iso` | `score`, `threshold`, `detected`, `skipped`, `volume_id`, `files`, `has_joliet`, `findings[]` (`class`, `score`, `technique`, `detail`) |
| `linuxpkg` | `score`, `threshold`, `detected`, `skipped`, `format` (deb/rpm/arch/flatpak/appimage/docker/snap/…), `name`, `scripts[]` (names only), `findings[]` (`class`, `score`, `technique`, `detail`, `evidence` — a truncated single-line excerpt, never a whole script) |
| `archive` | `score`, `threshold`, `detected`, `skipped`, `format` (zip/tar/gzip/…), `members`, `uncompressed_bytes`, `encrypted_members`, `executable_members`, `not_inspected`, `findings[]` (`class`, `score`, `technique`, `detail`, `evidence`) — decompression-bomb caps, Zip-Slip and lure/payload members |
| `chm` | `score`, `threshold`, `detected`, `skipped`, `entries`, `content_files`, `not_inspected` (the LZX content section is not decompressed in v1), `findings[]` (`class`, `score`, `technique`, `detail`) — embedded executable/LNK/dangerous-script payloads |
| `peel` | `score`, `threshold`, `detected`, `skipped`, `outcome`, `max_depth`, `primary_signature` (the ordered chain, e.g. `base64>gzip>base64`), `exhausted`, `exhaust_reason`, `findings[]` (NOVEL-012) |
| `tradecraft` | `score`, `threshold`, `detected`, `skipped`, `decoded` (carrier layers analysed), `findings[]` (`class`, `score`, `technique`, `detail`, `evidence`) — behaviour in scripts and payload bytes. Classes span web shells (`tradecraft.webshell.*`), network shells (`tradecraft.netshell.*`), in-memory loaders (`tradecraft.memory.*`), shellcode primitives (`tradecraft.shellcode.*`), living-off-the-land abuse (`tradecraft.lolbin.*`, `tradecraft.gtfobins.*`), script tradecraft (`tradecraft.script.*`), trusted-SaaS C2 channels (`tradecraft.c2service.*`) and EDR-bypass primitives (`tradecraft.bypass.*`) |
| `fusion` | `tier`, `score`, `threshold`, `confidence`, `agreed[]`, `techniques[]`, `novel[]`, `frameworks[]` (per-technique ATT&CK + Unified Kill Chain phase/stage), `corroborated`, `explanation`, `sources[]` (`name`, `role`, `hit`, `score`, `threshold`, `ratio`, `weight`, `counted`, `skipped`, `evidence[]` with `label`, `detail`, `technique`, `novel`, `weight`). The engine verdict applies the attack-path chaining layer (`FuseChained`); the chaining bonus is folded into `score`/`tier`. |

Verdict precedence per file: `error` when the file could not be read or a
pass failed on it, `malicious` on a hash or YARA hit, `suspicious` on a
heuristic, static or stego breach or a corroborated fused verdict, else
`clean`. The summary verdict is the strongest per-file verdict, with `error`
reserved for a run that could not execute.

## SARIF

`--format sarif` writes SARIF 2.1.0 for GitHub code scanning, GitLab, Azure
DevOps, DefectDojo and similar. One run, one driver, a sorted rule table and
one result per finding.

| Rule id | Level | Produced by |
|---|---|---|
| `hash/<threat>` | error | a hash-signature hit |
| `yara/<namespace>/<rule>` | error | a YARA match; the rule carries the description, tags, threat level and author |
| `heuristic/score` | note | a heuristic breach, with every indicator in `properties.indicators` |
| `static/score` | note | a static breach, with the anomalies, imphash (PE) or import hash and interpreter (ELF), packer and TLSH in properties |
| `stego/zero-width`, `stego/bidi-control`, `stego/tag`, `stego/variation-selector` | note | one result per scored stego class, with a byte-offset region (`byteOffset`, `byteLength`, `startLine`) at the first hidden codepoint and the modifiers in properties |
| `fusion/corroborated` | note | a fused verdict reached by corroboration, with the agreeing sources, techniques and the one-line explanation |
| `scan/error` | warning | a file that could not be scanned: a coverage gap, not a clean bill of health |

Every result carries a `sha256/v1` partial fingerprint so a code-scanning UI
recognises the same file when it moves. With `--dir`, artifact URIs are
relative to the scan root through `%SRCROOT%`. Library users can change the
levels (`WithSARIFLevels`) or drop the SUSPICIOUS-tier and error results
(`WithSARIFHeuristics(false)`, `WithSARIFScanErrors(false)`).

## Coverage SARIF

`cau coverage --format sarif` writes a separate SARIF 2.1.0 log describing
the detection program rather than a scan: one rule and one result per ATT&CK
technique, each with a `state` property (detected, partial, planned, none), a
logical location of `attack/<id>` and a help URI into attack.mitre.org.
Planned gaps are warnings; everything else is a note. It is not the
scan-findings SARIF above; `make coverage` writes it to
`eval-out/attack-coverage.sarif`.

## OCSF

`--format ocsf` writes a JSON array of OCSF 1.3.0 Detection Finding objects
(`class_uid` 2004), one per file reported suspicious or malicious, for
security lakes that speak OCSF (Matano, Amazon Security Lake). Malicious
maps to severity High and `is_alert`, suspicious to Medium; the leading
detector is `finding_info.analytic` (YARA rule or hash threat as its uid,
the fusion lattice when only corroboration reached the tier); every ATT&CK
technique any detector attached is in `finding_info.attacks` with its name;
the file with its digests is `evidences[0].file`; hash threats, rule
families and fuzzy matches are `malware`; the engine-native scores, classes
and rule names sit under `unmapped`. Clean and unscannable files are not
findings and are omitted. `jq -c '.[]'` turns the array into NDJSON.

## SIEM sink formats

Nine further `--format` values write the same findings as OCSF in the wire
formats SIEMs ingest. They are profiles of one event, not separate mappings:
each is derived from the OCSF Detection Finding, so a file that is a finding
in `ocsf` is exactly one event in every profile, with the same uid, severity,
techniques and digests. Clean and unscannable files are omitted, as in OCSF.

| `--format` | Shape | Typical consumer |
|---|---|---|
| `ecs` | Elastic Common Schema 8.11 documents, one per line | OpenSearch Security Analytics, Security Onion |
| `cef` | `CEF:0\|CAU\|cau\|…` one event per line | OSSIM, ArcSight |
| `leef` | LEEF 2.0, tab-delimited attributes, one event per line | OSSIM, QRadar |
| `gelf` | GELF 1.1 messages, one per line | Graylog |
| `syslog` | RFC 5424 frames, the finding as structured data | any syslog collector |
| `syslog-ecs`, `syslog-cef`, `syslog-leef` | RFC 5424 frames whose MSG is that payload | Security Onion, OSSIM |
| `otlp` | one OTLP/JSON `ExportLogsServiceRequest` | OpenTelemetry collectors |

Severity is the two engine tiers on each standard's own scale. Critical is
never claimed.

| Verdict | OCSF | CEF / LEEF / ECS `event.severity` | syslog / GELF level | OTLP |
|---|---|---|---|---|
| malicious | High (4) | 8 | 3 (error) | ERROR (17) |
| suspicious | Medium (3) | 5 | 4 (warning) | WARN (13) |

Field notes:

- **ECS**: `event.kind` is `alert`, `event.category` `["malware"]`; the file is
  `file.path` / `file.hash.*`, the leading detector `rule.*`, techniques
  `threat.technique.id[]` with index-aligned names, tactics
  `threat.tactic.name[]`. Engine-native detail (verdict, detectors, malware
  names, confidence) is under the `cau` object.
- **CEF**: the signature id is the analytic uid (`yara/<ns>/<rule>`,
  `hash/<threat>`); extensions use the CEF dictionary (`rt`, `dvchost`,
  `filePath`, `fname`, `fsize`, `fileHash`, `msg`, `externalId`) and the six
  custom strings carry techniques, detectors, malware, confidence, SHA-1 and
  MD5, each with its label.
- **RFC 5424**: facility `authpriv` (10), APP-NAME `cau`, MSGID `finding`. The
  structured-data id is `cau@32473`; 32473 is the enterprise number RFC 5612
  reserves for documentation, used because the project holds no registered
  number. No transport framing is added to a file or pipe.
- **OTLP**: 64-bit integers are strings, as the OTLP JSON mapping requires;
  attribute names follow the ECS dotted names; `service.name` is `cau`.
- Identifiers that a pipeline keys on (`cau` as module, dataset, service name,
  device product, APP-NAME) are constants and do not follow the display name.

Fidelity: `ecs`, `gelf` and `otlp` are JSON and carry file paths byte-exact;
bidi and other display-altering characters are written as `\uXXXX` escapes,
which decode to the same value. `cef`, `leef` and `syslog` are line formats,
where a control character in an attacker-chosen path could forge a second
event, so they apply the standard's own escapes and render the remaining
control and bidi characters visibly. LEEF defines no escape for its delimiter,
so a tab inside a value becomes the visible `\t`. A consumer that needs exact
bytes reads a JSON profile.

Each standard has a committed conformance fixture under
`internal/report/testdata/conformance/` (one RFC 5424 frame, one CEF event,
one LEEF event, one GELF message, one ECS document, one OCSF object, one OTLP
batch). The test suite regenerates each, compares it byte for byte and parses
it back with a reader written against the standard, so a change to a profile
is a visible fixture diff. `--sink-url` delivers these formats to a collector;
see [cli.md](cli.md#siem-sink-formats-and-forwarding-free).

## Exit-code policy

The policy is pure: the same input always yields the same code.

| Code | Condition |
|---|---|
| 3 | the run could not execute |
| 2 | at least one file could not be scanned (unless `--no-fail-on-scan-error`) |
| 1 | a finding at or above the `--fail-on` level |
| 0 | otherwise, including an empty directory |

`--fail-on` levels: `none` (findings never fail), `malicious` (hash or YARA;
the default), `heuristic` (also heuristic, static or stego breaches and
corroborated fused verdicts), `clean` (also any sub-threshold observation).
An unknown level falls back to `malicious`: a typo must never silently
disable failure. The reason is printed on stderr and recorded in both machine
formats (`exit_reason`, `exitCodeDescription`).

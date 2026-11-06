# Detection content

The engine ships with three content files, all plain text, all validated on
load. Nothing in them is trusted: malformed lines are warnings, duplicates
are refused, and every string they contain is bounded before it reaches a
report.

## Hash signatures (`signatures/hashes.txt`)

Pipe-delimited, one entry per line, `#` comments:

```
HASH_TYPE|HASH|THREAT_NAME
SHA256|0e05a72c8edfeb9ed20174dee7160b3dd4c91d3c27dc70ff14a951ce31dd8d48|Example Family
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
```

Rules enforced by `scanner.LoadSignatures` and the tests:

- type is MD5, SHA1 or SHA256 (spellings such as `sha-256` are normalised);
- the digest is hexadecimal and exactly the length for its type, and the
  error names the type the length *does* fit when it is wrong;
- a duplicate digest is skipped with a warning; a digest re-listed under a
  different name is a conflict and the first entry is kept;
- the threat name contains no `|` or line breaks.

`cau add-hash` appends after the same validation. The shipped file contains
real hashes only; the synthetic filler the original project carried was
removed, and a test fails on invalid or synthetic entries.

The planned intake (PLAN.md, Phase 4) replaces hand-typed hashes with
MalwareBazaar / MISP / LOLDrivers feeds and signed release-channel updates.

## YARA rules (`rules/`)

Put `.yar` or `.yara` files in the rules directory; it is walked recursively
and compiled in sorted order into one ruleset. Conventions the bundled
`rules/rule_list.yar` follows and that the reports rely on:

| Convention | Why |
|---|---|
| text strings carry `ascii wide` | they match both the narrow strings in scripts and the UTF-16LE strings in Windows binaries; the original rules were ASCII-only and never fired on mimikatz.exe |
| byte patterns are hex strings | a rule matching the *text* `"0x89,0x00"` can never fire on bytes; two such rules were rewritten |
| `meta.threat_level` 1–5 | shown in reports and SARIF properties |
| `meta.family` | the family the rule claims, used for per-family recall in the evaluation harness |
| `meta.mitre_attack` | the ATT&CK technique id (comma-separated for several); the fusion lattice carries it into fused verdicts, `cau coverage` builds the matrix from it, OCSF output names it |
| `meta.description`, `meta.author`, `meta.in_the_wild` | rendered in the text report and the SARIF rule |

The bundled rules cover WannaCry, Mimikatz, LokiBot, shellcode (a PEB module walk
beside an export-name hash), PowerShell download cradles, ransomware notes, the
Windows netcat lineage with its shell relay compiled in, and PEASS scripts wrapped
into an ELF. Behaviour that names no family belongs to the
[tradecraft pass](detectors.md#tradecraft), not to a YARA rule: a YARA hit is
MALICIOUS, which `--quarantine` acts on. `ophcrack`, which embeds mimikatz command
strings, is a known false positive.

Hash feeds stay an operator's choice. `cau intake --format loldrivers --input
drivers.json` turns the [LOLDrivers](https://www.loldrivers.io/api/drivers.json)
catalogue into signatures, 6,682 on 2026-11-06, but most of its entries are
legitimate vendor drivers that are vulnerable, and a hash hit is MALICIOUS, so the
database does not ship them.

`cau rules lint` checks all of the above plus compile diagnostics, technique
id shape, strings under four bytes, hex written as text and trivially true
conditions; `make lint-rules` runs it in CI and errors fail the build. `cau
rules list` prints the compiled inventory with level, family and technique.

`--rules` replaces the bundled set rather than adding to it, so to extend it copy
both into one directory: a directory is walked recursively into one ruleset.
Measured, [signature-base](https://github.com/Neo23x0/signature-base) beside the
bundled rules took heldout from about 60 % to 70.4 %; see
[Evaluation](evaluation.md#the-lab-corpus).

For production coverage, point `--rules` at
[Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
[Yara-Rules/rules](https://github.com/Yara-Rules/rules) or the
[MalwareBazaar YARA export](https://bazaar.abuse.ch/export/yara/). Compile
warnings from large rule sets are printed, not suppressed; a file that does
not compile is skipped with its position and the rest still loads.

## Fuzzy-hash database (`signatures/fuzzy.txt`)

```
TYPE|DIGEST|THREAT_NAME
TLSH|T1...70 hex characters...|Example Family
SSDEEP|blocksize:hash1:hash2|Example Family
IMPHASH|32 hex characters|Example Family
```

Each digest is validated for its type; duplicates and conflicting re-labels
are refused with the existing entry named. Matching thresholds are published
constants: TLSH distance ≤ 30, ssdeep score ≥ 70; an imphash matches exactly.
A match is SUSPICIOUS-tier evidence carrying the distance and the entry's
name, never a MALICIOUS verdict. `IMPHASH` entries are PE import hashes
(pefile-compatible); the ELF import-set hash that `cau hash` prints is a
clustering key for `cau cluster` and is not looked up here. TLSH and ssdeep
entries apply to every file type.

The shipped database is empty on purpose: fuzzy content arrives through the
same measured intake as hashes, never hand-typed. `cau add-fuzzy --file`
computes every digest a sample yields and appends them.

## Tradecraft catalogues (`scanner/tradecraft/`)

The behavioural pass does not ship a file the operator edits; its catalogue
is Go source, compiled into the binary, so a change is a review and a build.
The source projects it draws on are stable public datasets:

| Catalogue | File | Shape of what comes out |
|---|---|---|
| [GTFOBins](https://gtfobins.github.io) | `extra_vectors.go` | abuse-shaped shell/`sudo`/setuid breakouts (editor bang-escape, `pty.spawn`, `-exec /bin/sh`, `sh -p`, `chmod +s` on a shell) |
| [LOLBAS](https://lolbas-project.github.io) | `extra_vectors.go` + `script.go` | Windows system-binary download, proxy-execution, credential-dump and recovery-destroy shapes; a binary's name alone proves nothing, so each vector carries the abusive switches |
| [LOLC2](https://lolc2.github.io) | `c2_cloud_vectors.go` | 56 abused SaaS services, each with the URL paths the catalogued C2 agents hit (per-agent paths on Firebase, Graph mail / drive / Teams writes, Lambda invoke, Google Apps Script `/macros/s/*/exec`, blockchain RPC endpoints) |
| [LOLFSaaS](https://lolfsaas.github.io) | `c2_cloud_vectors.go` | 127 trusted cloud fronts (`workers.dev`, `pages.dev`, `azurewebsites.net`, `cloudfront.net`, `s3.amazonaws.com`, `appspot.com`, `herokuapp.com`, `firebaseapp.com`) |
| [LOTWebhooks](https://lotwebhooks.github.io) | `c2_cloud_vectors.go` + `script.go` | 41 webhook destinations (chat, incident, push, messaging) |
| [LOTTunnels](https://lottunnels.github.io) | `c2_cloud_vectors.go` + `script.go` | 92 reverse-tunnel and ingress-broker domains |
| [ArcticFox bypasses](https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md) | `bypass_vectors.go` | the twelve detection-bypass primitives catalogued there, each detected on a pairing: `memfd_create` + `execveat`, `prctl(PR_SET_NAME)` + a socket/exec, `/etc/ld.so.preload` written, `pam_exec.so` added to a PAM stack, `systemctl edit --full` on a real unit, `/proc/self/exe` unlink, raw `IPPROTO_ICMP` socket + payload decode, `dns.resolver.resolve(..., 'TXT')` + base64 |

Finding classes and their scores are in `scanner/tradecraft/catalog.go`; the
ATT&CK technique each one maps to is validated against `internal/attack`'s
table and gated by `baselines/attack-coverage.txt` (run `cau coverage
--expect <file> --record` to record an intentional change).

## Content changes are measured

Every change to these files runs through the evaluation harness in CI
(`make eval`): the smoke corpus must keep 100 % recall and 0 false positives
against the committed baseline. See [Evaluation](evaluation.md).

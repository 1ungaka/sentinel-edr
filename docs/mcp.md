# MCP server (`cau-mcp`)

`cau-mcp` exposes the CAU detection engine over the
[Model Context Protocol](https://modelcontextprotocol.io): an LLM agent or an
IDE drives the scanner through a set of tools, resources and prompts. It is the
same engine as the `cau` CLI — the same detectors, the same signature database,
the same YARA ruleset and the same ATT&CK coverage matrix — presented as an MCP
server rather than a command line.

The MCP server's detector set matches `cau scan`: hashes, YARA, heuristics, the
static-structure pass, invisible codepoints, the encoded-executable pass, the
Shell Link (`lnk`), OLE macro (`ole`), PDF (`pdf`) and ISO container (`iso`)
detectors, the obfuscation-chain peeler, the Linux software-package pass, the
**archive** and **CHM** detectors, and the **tradecraft** pass (web shells,
network shells, in-memory loaders, LOLBAS and GTFOBins abuse, the lolol.farm
trusted-SaaS catalogue and the ArcticFox detection-bypass primitives). Each
can be turned off with the corresponding `--no-*` flag, exactly as `cau scan`
takes them.

Two transports are supported, both JSON-RPC 2.0:

- **stdio** (default): one JSON message per line on stdin/stdout.
- **streamable HTTP** (`--http <addr>`): a single endpoint at `/mcp` that takes
  a JSON-RPC message by POST and returns the response as `application/json`.

The protocol layer is transport-agnostic, so the tools, resources and prompts
behave identically on either.

## Running

```
cau-mcp --root /path/to/scan [--db ...] [--rules ...] [--fuzzy-db ...]
```

`cau-mcp` reads requests on stdin and writes responses on stdout; all logging
goes to stderr, so the stdout stream stays a clean JSON-RPC channel.

To serve the HTTP transport instead, bind an address (loopback is strongly
recommended — anyone who can reach the socket can drive the scanner within the
`--root` sandbox). Requests carrying a browser `Origin` other than loopback are
refused with 403, so a web page cannot reach the server through the analyst's
browser; clients that send no `Origin`, as agents and SDKs do, are unaffected:

```
cau-mcp --root /path/to/scan --http 127.0.0.1:8923
```

```
curl -s -X POST localhost:8923/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mitre_coverage","arguments":{}}}'
```

Resources
(signature database, YARA rules, fuzzy database) are auto-discovered exactly as
the CLI discovers them (see [Installation](installation.md)); override them with
the same flags or the `CAU_SIGNATURES` / `CAU_RULES` / `CAU_FUZZY` environment
variables.

### Registering with an MCP client

A typical client configuration launches the server as a stdio subprocess:

```json
{
  "mcpServers": {
    "cau": {
      "command": "cau-mcp",
      "args": ["--root", "/srv/samples"]
    }
  }
}
```

## The sandbox — path confinement

An MCP client is, sooner or later, an autonomous agent that will point a scanner
at `/`. The file-touching tools are therefore confined to a **scan-root
allowlist** given with one or more `--root` flags:

- Every path a tool touches must resolve — with all symlinks followed — to a
  location inside a root. A symlink *inside* a root that points *outside* it is
  rejected, not followed. (Honest limit: access is by resolved path, not a
  retained `O_NOFOLLOW` descriptor, so a component swapped for an out-of-root
  symlink in the window between resolution and open is a residual TOCTOU; the
  confinement holds against static layouts and resolve-time symlinks, not an
  attacker racing component swaps inside a granted root.)
- Rule text given to `yara_test_rule` cannot use `include`: compiling it would
  otherwise read any file the server can, past these roots. Rule files in the
  operator's own rules directory keep theirs.
- Files larger than `--max-bytes` (default 256 MiB) are refused before being
  read.
- A directory with more than `--max-files` (default 10000) regular files is
  refused rather than walked, so one call cannot fan out across a filesystem.

With **no** `--root`, the file tools (`scan_file`, `scan_dir`,
`explain_verdict`, `peel_file`, `firmware_image`, `boot_scan`,
`hardware_identity`, `eval_report`) are disabled; the hash, rule, coverage and
honesty tools still work, because they touch no client-supplied file.

Two of the boot-surface inputs deserve a word. `boot_scan` and
`hardware_identity` take an efivarfs or sysfs directory, and they take it
**only under a root**: there is no auto-discovery, and a client cannot point
the server at the live `/sys/firmware/efi/efivars` or `/sys` unless the
operator placed `/sys` (or the efivars mount) in `--root`. That is a
deliberate operator decision, made on the command line, never by the agent.
The sandbox checks these directories for containment without the file-count
walk (a sysfs tree is large and the scanners read a fixed set of entries under
their own bounds); disk images given to `boot_scan` are confined and must be
regular files, but are exempt from `--max-bytes` because only their boot
sectors and partition tables are read by offset — they are never loaded.

Results are always **bounded summaries** — scores, verdicts, matched rule names
and top categories — never raw YARA offset dumps, which would blow out an
agent's context. Truncation of any list is reported, never silent.

## Tools

| Tool | What it does |
|---|---|
| `scan_file` | Scan one file; return the verdict and per-detector scores. |
| `scan_dir` | Scan a tree; return aggregate counts and a bounded list of flagged files. |
| `scan_hash` | Look up an MD5/SHA1/SHA256 in the signature database (no file access). |
| `explain_verdict` | Why a file scored as it did: detectors that fired, matched rules with meta, top heuristic categories, fusion corroboration. |
| `yara_test_rule` | Compile a YARA rule from source, report diagnostics, optionally test it against sandboxed paths. |
| `generate_yara_rule` | Draft a well-formed rule skeleton that satisfies the linter's required meta. |
| `list_signatures` | List hash signatures (bounded) with per-type counts. |
| `add_signature` | Validate and persist a hash signature to the local database. |
| `mitre_coverage` | ATT&CK coverage of the shipped content: covered techniques, per-source summary, declared gaps. With `frameworks: true`, also the Unified Kill Chain phase view (`cau coverage --frameworks`): every phase with the covered techniques that land in it, empty phases listed as gaps. |
| `honesty_index` | The honesty index (`cau honesty`): coverage against the committed expectation, what a recorded evaluation report measured (with the synthetic-corpus caveat), and whether the content matches its integrity baseline. Each section carries a state and its caveats; there is no overall score. Reads only the operator's `--expect`, `--eval`, `--manifest` and `--pubkey`, never a client path. |
| `eval_report` | Summarise an evaluation report (`cau eval run --out`) at a sandboxed path: totals, precision/recall/FPR, per-detector rows, corpus class, error and skip counts, and whether the headline totals follow from the sample records. Per-sample rows only with `include_samples`, and then capped. |
| `peel_file` | Peel a file's obfuscation chain under the peeler's budget: outcome, score, max depth, primary and deepest chain signatures, findings, archive statistics. Decoded bytes are never returned. |
| `firmware_image` | Inventory a UEFI firmware image within the firmware size cap: volumes, modules (first 50), checksum validity, LZMA sections opened and failed, findings, and rule matches over the executable module bodies when the server holds a ruleset. |
| `boot_scan` | Scan explicitly named boot surfaces, each confined to a root: disk images, an ESP directory, an efivarfs directory, a sysfs root, an optional dbx reference. No auto-discovery; signatures reported present or absent, never verified. |
| `hardware_identity` | The `cau hwid` snapshot from a sysfs root under a root: DMI, physical interfaces, TPM and PCR 0–7, hardware RNG, unverifiable anchors. `redact` defaults to **true** (serials, UUID and MACs replaced by digests). |

The new analysis tools follow `scan_file`'s discipline exactly: the sandbox
resolves every path, the size cap applies before a read, every list is capped
at 50 with the cut reported in a `truncated` flag and `*_omitted` counts, and
every file-derived string (a module name, a DMI value, a boot-entry
description) is made valid UTF-8, shown with visible escapes for control and
bidi characters, and cut at 256 runes.

### Argument schemas of the analysis tools

| Tool | Arguments |
|---|---|
| `honesty_index` | none |
| `eval_report` | `path` (string, required); `include_samples` (boolean); `limit` (integer, capped at 50) |
| `peel_file` | `path` (string, required) |
| `firmware_image` | `path` (string, required) |
| `boot_scan` | `disks` (array of string); `esp` (string); `efivars` (string); `sysfs` (string); `dbx_reference` (string); at least one of the first four |
| `hardware_identity` | `sysfs` (string, required); `redact` (boolean, default true) |
| `mitre_coverage` | `technique` (string); `frameworks` (boolean) |

## Resources

| URI | Contents |
|---|---|
| `cau://signatures` | Signature-database counts and a bounded sample. |
| `cau://coverage` | The ATT&CK coverage matrix summary. |
| `cau://honesty` | The honesty index, the same document the `honesty_index` tool returns. |
| `cau://rules/{name}` | Namespace, tags, meta and string count for one compiled rule. |

## Prompts

| Prompt | Purpose |
|---|---|
| `triage_sample` | Triage a file with the detection tools and write an analyst summary. |
| `rule_review` | Assess a proposed YARA rule's false-positive risk and quality before promotion. |
| `boot_chain_review` | Triage a boot chain: run `boot_scan` (and `hardware_identity`, `firmware_image` where inputs allow) over explicitly named, sandboxed surfaces and summarise posture, chain, disks, findings and what was not inspected. |

## The honesty index's inputs

`honesty_index` and `cau://honesty` read three operator-configured paths, the
same ones `cau honesty` reads: `--expect` (the coverage expectation; defaults
to `baselines/attack-coverage.txt` when present in the working directory),
`--eval` (an evaluation report; defaults to `baselines/smoke.json` when
present) and `--manifest` (the integrity baseline; defaults to
`integrity.json` next to the signature database). `--pubkey` (or
`$CAU_SELFTEST_PUBKEY`) verifies the baseline's signature; a key that was
supplied and cannot be read is reported in the index as "not checked, and
why", never downgraded to a silent digest check. The build-time pinned key the
`cau` binary carries is not available to `cau-mcp`.

## Scope

`cau-mcp` is a **detection and analysis** surface. Every tool is read-only:
nothing here executes, writes outside the signature file `add_signature`
maintains, quarantines, blocks or kills. `cau defend`, `cau net`, the
quarantine store and the response actions are deliberately not exposed over
MCP: an autonomous agent gets to look, not to act on the host. The server
never samples or executes content either: `peel_file` returns layer
signatures, never decoded bytes, and `firmware_image` inventories module
bodies without disassembling or running them.

It also deliberately omits the evasion-report tool and evasion-assessment
prompt from the original Phase 3 sketch: those belong to the evasion suite,
which the project's [scope note](../PLAN.md) keeps out of the engine.
`generate_yara_rule` is a detection-authoring aid — it drafts a rule to catch
a described artifact; it is not a payload or obfuscation generator.
`cau://corpus/{sample}/report` and `cau://model/{name}/card` from the Phase 3
sketch are still not advertised: the first waits on evaluation-corpus
addressing, the second on the ML ladder (there is no model).

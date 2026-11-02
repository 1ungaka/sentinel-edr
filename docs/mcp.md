# MCP server (`cau-mcp`)

`cau-mcp` exposes the CAU detection engine over the
[Model Context Protocol](https://modelcontextprotocol.io): an LLM agent or an
IDE drives the scanner through a set of tools, resources and prompts. It is the
same engine as the `cau` CLI — the same detectors, the same signature database,
the same YARA ruleset and the same ATT&CK coverage matrix — presented as an MCP
server rather than a command line.

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
`--root` sandbox):

```
cau-mcp --root /path/to/scan --http 127.0.0.1:8923
```

```
curl -s -X POST localhost:8923/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mitre_coverage","arguments":{}}}'
``` Resources
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
  rejected, not followed.
- Files larger than `--max-bytes` (default 256 MiB) are refused before being
  read.
- A directory with more than `--max-files` (default 10000) regular files is
  refused rather than walked, so one call cannot fan out across a filesystem.

With **no** `--root`, the file tools (`scan_file`, `scan_dir`,
`explain_verdict`) are disabled; the hash, rule and coverage tools still work,
because they touch no arbitrary file.

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
| `mitre_coverage` | ATT&CK coverage of the shipped content: covered techniques, per-source summary, declared gaps. |

## Resources

| URI | Contents |
|---|---|
| `cau://signatures` | Signature-database counts and a bounded sample. |
| `cau://coverage` | The ATT&CK coverage matrix summary. |
| `cau://rules/{name}` | Namespace, tags, meta and string count for one compiled rule. |

## Prompts

| Prompt | Purpose |
|---|---|
| `triage_sample` | Triage a file with the detection tools and write an analyst summary. |
| `rule_review` | Assess a proposed YARA rule's false-positive risk and quality before promotion. |

## Scope

`cau-mcp` is a **detection** surface. It deliberately omits the evasion-report
tool and evasion-assessment prompt from the original Phase 3 sketch: those
belong to the evasion suite, which the project's
[scope note](../PLAN.md) keeps out of the engine. `generate_yara_rule` is a
detection-authoring aid — it drafts a rule to catch a described artifact; it is
not a payload or obfuscation generator.

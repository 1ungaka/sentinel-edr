# CLI Reference

Full detail: [`docs/cli.md`](https://github.com/s-b-repo/cau/blob/main/docs/cli.md).
`cau <command> --help` prints usage for any command.

| Command | What it does |
|---|---|
| `cau scan` | scan files/dirs; detectors, thresholds, formats, `--quarantine`, `--interval` (daemon) |
| `cau hash` | print SHA-256, imphash, TLSH, ssdeep digests |
| `cau cluster` | group PE files by import-table similarity |
| `cau add-hash` / `cau add-fuzzy` | append a signature to the database |
| `cau eval` | corpus evaluation harness (validate/run/report/diff/gate) |
| `cau rules` | `lint` / `list` the YARA rules |
| `cau coverage` | ATT&CK coverage matrix derived from content; `--frameworks` for the Unified Kill Chain view |
| `cau quarantine` | vault flagged files: `add` / `list` / `restore` / `verify` / `delete` |
| `cau canary` | plant decoy files and detect tampering |
| `cau peel` | walk an obfuscation chain; depth as signal (NOVEL-012) |
| `cau intake` | ingest a threat-intel feed (STIX / MISP / MalwareBazaar / LOLDrivers) into the DB |
| `cau update` | install a signed signature-DB bundle, fail-closed |
| `cau selftest` | verify detection content has not been tampered with |
| `cau verify-self` | verify this binary against the signed release manifest |
| `cau bundle` | `update` / `checksums` — produce signed release artifacts (CI) |
| `cau version` | print the version |

## Prevention and self-protection flags on `cau scan`

| Flag | Meaning |
|---|---|
| `--quarantine` | move MALICIOUS-verdict files into the vault (free prevention) |
| `--quarantine-store <dir>` | vault directory |
| `--interval <dur>` | daemon mode: re-scan every interval until SIGINT/SIGTERM |
| `--signers <file>` | flag binaries signed by a known-abused certificate (lolcerts) |

## Exit codes

`0` ok/clean · `1` finding (or verification failure) · `2` some files unscannable
· `3` the run failed · `4` usage error.

# CLI Reference

Full detail: [`docs/cli.md`](https://github.com/1ungaka/sentinel-edr/blob/main/docs/cli.md).
`cau <command> --help` prints usage for any command. Flags can go before or after
the paths, and everything after `--` is a path.

| Command | What it does |
|---|---|
| `cau scan` | scan files/dirs; detectors (PE/ELF/Mach-O, document, Linux-package), thresholds, formats, `--quarantine`, `--interval` (daemon) |
| `cau ps` | read-only scan of the live process table over `/proc` (fileless, masquerade, injection, ptrace) |
| `cau net` | read-only scan of the network plane, per namespace and attributed to processes; `block` / `unblock` / `blocks` / `clear` for reversible, expiring drop rules |
| `cau persist` | read-only persistence audit, of a live host or a mounted disk |
| `cau defend` | the resident agent: every layer, correlated incidents, real-time file scanning, automatic response. `--report-only` watches without acting |
| `cau boot-scan` | read-only boot-chain scan: MBR, GPT, the ESP, Secure Boot and dbx, WPBT, option ROMs |
| `cau firmware` | parse a UEFI image: module inventory through LZMA and nested volumes, integrity, rules, implant blocklist |
| `cau hwid` | snapshot the hardware identity; `--record` / `--check` against a baseline, `--redact` for sharing |
| `cau installed` | audit already-installed packages' maintainer scripts in place (dpkg/pacman; RPM is a gap) |
| `cau feed` | abuse-intel feed (IPs/domains/URLs/hashes): `list` / `check` / `update` (offline cache, opt-in fetch) |
| `cau hash` | print SHA-256, imphash, TLSH, ssdeep digests |
| `cau cluster` | group PE files by import-table similarity |
| `cau add-hash` / `cau add-fuzzy` | append a signature to the database |
| `cau eval` | corpus evaluation harness (validate/run/report/diff/gate) |
| `cau heldout` | manage the encrypted held-out recall corpus (init/pull/add/remove/list/manifest) |
| `cau rules` | `lint` / `list` the YARA rules |
| `cau coverage` | ATT&CK coverage matrix derived from content; `--frameworks` for the Unified Kill Chain view |
| `cau quarantine` | vault flagged files: `add` / `list` / `restore` / `verify` / `delete` |
| `cau canary` | plant decoy files and detect tampering |
| `cau peel` | walk obfuscation chains through every common base, rot and Caesar, in parallel; `--jobs` for several files, `--stream` for live output (NOVEL-012) |
| `cau intake` | ingest a threat-intel feed (STIX / MISP / MalwareBazaar / LOLDrivers, or TAXII 2.1 with `--taxii`) into the DB, recording `--provenance` |
| `cau update` | install a signed signature-DB bundle, fail-closed; refuses an older bundle unless `--allow-downgrade` |
| `cau selftest` | verify detection content, the feed, the config and the binary against a baseline |
| `cau honesty` | what is covered, what was measured and whether the content is intact, with no overall score |
| `cau verify-self` | verify this binary against the signed release manifest |
| `cau bundle` | `update` / `checksums` / `sbom` — produce signed release artifacts and a CycloneDX SBOM (CI) |
| `cau completion` | print a shell completion script (bash, zsh or fish) |
| `cau version` | print the version |

## Prevention and self-protection flags on `cau scan`

| Flag | Meaning |
|---|---|
| `--quarantine` | move MALICIOUS-verdict files into the vault (free prevention) |
| `--quarantine-store <dir>` | vault directory |
| `--interval <dur>` | daemon mode: re-scan every interval until SIGINT/SIGTERM |
| `--signers <file>` | flag binaries signed by a known-abused certificate (lolcerts) |
| `--format <fmt>` | text, json, sarif, ocsf, or a SIEM sink: ecs, cef, leef, gelf, syslog, syslog-ecs, syslog-cef, syslog-leef, otlp |
| `--sink-url <url>` | deliver a sink format over `udp://`, `tcp://`, `tls://` or `https://` |
| `--wazuh-url <url>` | post findings to a Wazuh manager (free) |

## Exit codes

`0` ok/clean · `1` finding (or verification failure) · `2` some files unscannable
· `3` the run failed · `4` usage error.

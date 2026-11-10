# Command-line reference

```
cau scan      [flags] [path ...]     scan files and directories
cau ps        [flags]                scan the live process table over /proc; --respond stops confirmed processes
cau net       [flags]                scan the network plane; block|unblock|blocks|clear for reversible drop rules
cau persist   [flags]                audit the host for persistence (read-only)
cau defend    [flags]                chain every layer: incidents, real-time file scanning, automatic response
cau installed [flags]                audit already-installed packages' maintainer scripts
cau firmware  [flags] <image>        parse a UEFI firmware image: inventory, FV integrity, rules
cau boot-scan [flags]                read the boot chain, read-only: MBR/GPT, the ESP, Secure Boot, firmware tables
cau hwid      [flags]                snapshot the hardware identity, and compare it with a baseline
cau peel      [flags] <file>...      walk obfuscation chains: every common base, rot and Caesar, in parallel
cau evasion  report|bench [flags]    measure how fragile the shipped detections are, per detector
cau model    list|verify|promote|rollback [flags]
                                        the signed registry of the model artifacts the engine may run
cau feed      <subcommand> [flags]   abuse-intel feed: list / check / update
cau intake    --format <fmt> [flags] ingest STIX, MISP, MalwareBazaar, LOLDrivers or TAXII 2.1 intel
cau update    (--from|--url) [flags] install a signed signature-DB bundle, refusing an older one
cau selftest  [--record] [flags]     verify detection content, feed, config and binary against a baseline
cau verify-self (--from|--url)       verify this binary against the signed release manifest
cau bundle    update|checksums|sbom  produce signed release artifacts and a CycloneDX SBOM
cau quarantine <subcommand>          vault flagged files: add / list / restore / verify / delete
cau canary    plant|check [flags]    plant decoy files and detect tampering
cau hash      [flags] <path ...>     print SHA-256, imphash, TLSH and ssdeep digests
cau cluster   [flags] <path ...>     group PE and ELF files by import-table similarity
cau add-hash  [flags]                append a hash signature to the database
cau add-fuzzy [flags]                append a TLSH / ssdeep / imphash signature
cau rules     lint|list [flags]      lint the YARA rules, or list them with their meta
cau coverage  [flags]                ATT&CK coverage matrix of the shipped content
cau honesty   [flags]                what is covered, what was measured, and whether the content is intact
cau eval      <subcommand> [flags]   corpus evaluation harness
cau heldout   <subcommand> [flags]   encrypted held-out recall-corpus hash database
cau completion <shell>               print a shell completion script (bash, zsh or fish)
cau version                          print the version
cau help                             this text
```

Every command accepts `--help` and prints its own flags. Flags take one dash
or two (`-quiet`, `--quiet`) and can go before or after the paths, so
`cau scan /bin --no-yara` and `cau scan --no-yara /bin` are the same. After `--`
everything is a path, which is how to name a file that starts with a dash. The banner and progress lines always go to
stderr; reports go to stdout or `--output`, so machine formats are safe to
pipe.

## cau scan

Scans files and directories with every configured detector and writes one
report.

```sh
cau scan --file suspicious.exe
cau scan --dir ./downloads
cau scan ./build ./dist --format json --output report.json
cau scan --dir . --format sarif --output cau.sarif --fail-on none
cau scan --dir / --jobs 16 --no-heuristics --no-static --quiet
```

Positional arguments, `--file` and `--dir` can be combined; directories are
walked recursively. Sockets, devices and FIFOs are skipped; symbolic links to
files are followed only with `--follow-symlinks`, symbolic links to
directories never. A directory you name yourself is scanned even when it is a
symbolic link, so `cau scan /bin` works on a merged-`/usr` host; the rule above
is for links found during the walk.

### Targets and resources

| Flag | Meaning |
|---|---|
| `--file PATH` | a single file (positional paths are accepted too) |
| `--dir PATH` | a directory to scan recursively; also sets the SARIF source root |
| `--db PATH` | signature database (default: auto-discovered) |
| `--rules PATH` | YARA rule file or directory (default: auto-discovered) |
| `--fuzzy-db PATH` | fuzzy signature database (default: auto-discovered, optional) |

### Detectors and thresholds

| Flag | Default | Meaning |
|---|---|---|
| `--no-yara` | off | disable YARA |
| `--no-heuristics` | off | disable the string and API heuristics |
| `--no-static` | off | disable the static structural pass |
| `--no-fuzzy` | off | keep the static pass but skip TLSH / ssdeep (faster on large files; disables similarity lookups) |
| `--signers <file>` | off | known-abused code-signing certificate blocklist (lolcerts); flags PE files signed by a listed cert |
| `--no-stego` | off | disable the invisible-codepoint pass |
| `--no-encchain` | off | disable the encoded-executable pass |
| `--no-lnk` | off | disable the Windows Shell Link (.lnk) pass |
| `--no-ole` | off | disable the OLE compound-file (VBA macro) pass |
| `--no-pdf` | off | disable the PDF malicious-document pass |
| `--no-iso` | off | disable the ISO 9660 malicious-container pass |
| `--no-pkg` | off | disable the Linux software-package pass (.deb/.rpm/Arch/Flatpak/AppImage/Docker/Snap install scripts) |
| `--no-archive` | off | disable the compressed-container pass (ZIP/TAR/gzip: bombs, Zip-Slip, lure/payload members) |
| `--no-chm` | off | disable the Compiled HTML Help (CHM) pass (embedded executables, shortcuts, dangerous scripts) |
| `--no-tradecraft` | off | disable the behavioural pass over scripts and payload bytes (web shells, network shells, in-memory loaders, shellcode) |
| `--no-peel` | off | disable the obfuscation-chain peeler (NOVEL-012) |
| `--no-fusion` | off | disable the fusion lattice |
| `--heuristic-threshold N` | 7 | heuristic score at which a file is SUSPICIOUS |
| `--static-threshold N` | 8 | static anomaly score at which a file is SUSPICIOUS |
| `--stego-threshold N` | 4 | stego score at which a text artifact is SUSPICIOUS; 4 is presence-based, 8 requires a modifier |
| `--encchain-threshold N` | 8 | encoded-executable score at which a file is SUSPICIOUS |
| `--lnk-threshold N` | 8 | Shell Link score at which a file is SUSPICIOUS |
| `--ole-threshold N` | 8 | OLE macro score at which a file is SUSPICIOUS |
| `--pdf-threshold N` | 8 | PDF document score at which a file is SUSPICIOUS |
| `--iso-threshold N` | 8 | ISO container score at which a file is SUSPICIOUS |
| `--pkg-threshold N` | 8 | Linux-package install-script score at which a file is SUSPICIOUS |
| `--archive-threshold N` | 8 | compressed-container score at which a file is SUSPICIOUS |
| `--chm-threshold N` | 8 | CHM help-file score at which a file is SUSPICIOUS |
| `--tradecraft-threshold N` | 8 | tradecraft score at which a file is SUSPICIOUS |
| `--feed <path>` | search path | abuse-intel feed to match indicators against (empty = none; see `cau feed`) |
| `--peel-threshold N` | 50 | obfuscation-chain score at which a file is SUSPICIOUS (a depth-2 revealed chain scores 60) |
| `--yara-timeout D` | 30s | per-file YARA budget; a timed-out scan keeps the matches it found and records a warning |
| `--max-in-memory MiB` | 64 | larger files are streamed: hashing streams, YARA memory-maps, the heuristic, static and stego passes are skipped with the reason recorded |
| `--jobs N` | CPUs | files scanned concurrently |
| `--follow-symlinks` | off | scan the targets of symbolic links to files |
| `--quarantine` | off | **prevention**: after scanning, auto-block flagged files by moving them into the vault |
| `--quarantine-level <bar>` | `malicious` | what `--quarantine` blocks: `malicious` (a hard hash/YARA hit only) or `suspicious` (**also** files the fusion lattice places at the SUSPICIOUS tier — the fused multi-indicator score, each indicator at its own weighted level, crossed the threshold with or without any single detector crossing alone). The recorded label names the score and the indicators that drove it. |
| `--quarantine-store <dir>` | default vault | vault directory for `--quarantine` |
| `--interval <dur>` | 0 (one-shot) | **daemon mode**: re-scan every interval (e.g. `15m`, `1h`) until SIGINT/SIGTERM, writing the report each cycle; a finding never stops the daemon. Scheduled, not real-time. See `packaging/systemd/` for service units. |
| `--wazuh-url <url>` | — | Wazuh Manager API base (e.g. `https://wazuh.example.com:55000`). When set, the scan's OCSF findings are posted to the manager after the local report is written. Free — the agent speaks directly, no console required. |
| `--wazuh-user <name>` | — | Wazuh API user |
| `--wazuh-password-env <VAR>` | `WAZUH_PASSWORD` | environment variable holding the Wazuh API password. Argv is never used — argv is world-readable in `/proc/<pid>/cmdline`. |
| `--wazuh-ca <file>` | — | PEM CA bundle trusted for the Wazuh manager's TLS certificate |
| `--wazuh-insecure` | off | skip Wazuh TLS verification (also allows `http://`). Explicit opt-in; prints a warning |
| `--wazuh-timeout <dur>` | 10s | per-request timeout for the forwarder |

Hash signatures cannot be turned off: a signature database is required.

### Wazuh SIEM forwarding (free)

The agent posts the scan's OCSF findings to a Wazuh Manager over its REST
API: `POST /security/user/authenticate` with HTTP Basic, then `POST /events`
with the returned JWT and a body of `{"events":[<json-finding>, ...]}`. Each
finding is byte-identical to what `cau scan --format ocsf` writes locally,
so a Wazuh custom decoder keyed on OCSF `class_uid` 2004 catches the
delivery with no translation. The password comes from the env var named by
`--wazuh-password-env` (default `WAZUH_PASSWORD`), never from argv.

The forwarder is **best-effort**: a transport error is logged and dropped,
so a Wazuh outage never breaks the scan's exit code, a CI gate or the local
report. Batches cap at 100 events per request. Scan-time is reported on
stderr as `[*] wazuh forward: N/M findings delivered`.

```sh
export WAZUH_PASSWORD='…'    # or point --wazuh-password-env elsewhere
cau scan --dir /var/www \
         --format ocsf \
         --wazuh-url https://wazuh.example.com:55000 \
         --wazuh-user cau-agent \
         --wazuh-ca /etc/pki/wazuh/manager-ca.pem
```

Shipping `cau scan --wazuh-url …` directly to the Manager stays free
because it is a single-host action (see `docs/pricing.md`). syslog, Splunk
HEC, Elastic / OpenSearch `_bulk` and the OCSF Lake sink follow the same
rule and will ship free when added.

### Package provenance (`--provenance`)

`--provenance` resolves every scanned file against the host's package
database (dpkg or pacman; rpm is reported as `unsupported`, because its
database is not loose files and the engine never shells out) and records
whether a package owns the file and whether its content still matches the
digest the package shipped. Every report format carries it: a `provenance`
object per file in JSON (`manager`, `package`, `version`, `state`,
`shipped_digest`, `digest_algo`), a line in the text report, a property in
SARIF, `unmapped.provenance` in OCSF, `cau.provenance` in ECS. States:
`owned-intact`, `owned-modified`, `owned-conffile` (configuration files are
expected to differ), `owned-unverifiable` (no digest recorded), `unowned`,
`unsupported`, `unknown` (no database). usr-merge spellings and dpkg
diversions are resolved. The database is loaded once per scan; on a
4,400-package Debian install that is about one to three seconds of CPU and
roughly 70 MB of memory, which is why it is off by default.

A package-owned executable or script whose content no longer matches the
package is reported as the observation `provenance.modified-system-binary`
(T1554). It is reported beside the verdict and never scored, because it has
no measured weight yet; it never changes the exit code. Measured on this
host's `/usr/bin` and `/usr/sbin` (4,157 files): 4,154 intact, 2 unowned and 1
modified, the latter a locally rebuilt daemon. The note the output carries is
the honest one: provenance says a file is what the package shipped, per a
database that root can rewrite; it says nothing about whether the package is
trustworthy. `--provenance-root <dir>` points at another root (tests, a
mounted image).

### SIEM sink formats and forwarding (free)

Beside the four report formats, `--format` takes nine SIEM sink formats:
`ecs`, `cef`, `leef`, `gelf`, `syslog`, `syslog-ecs`, `syslog-cef`,
`syslog-leef` and `otlp` (shapes and field mappings in
[output-formats.md](output-formats.md#siem-sink-formats)). They all carry the
same findings as `--format ocsf`, one event per finding, so they can be
written to a file or a pipe like any report. `--format stix` writes the same
findings as one STIX 2.1 bundle (a document, not sent by `--sink-url`).

`--sink-url` also delivers them to a collector after the scan. `--format`
still picks the local report; `--sink-format` picks what is sent (it defaults
to `--format` when that is a sink format).

| Flag | Default | Meaning |
|---|---|---|
| `--sink-url <url>` | none | `udp://host:port`, `tcp://host:port`, `tls://host:port` or `https://host/path` |
| `--sink-format <fmt>` | `--format` if a sink format | which sink format to send |
| `--sink-index <name>` | none | with `https://` and `ecs`: send an OpenSearch / Elasticsearch `_bulk` body creating into this index or data stream |
| `--sink-auth-env <VAR>` | `CAU_SINK_AUTH` | environment variable holding the HTTP `Authorization` header value. Never on argv |
| `--sink-ca <file>` | system roots | PEM CA bundle trusted for the collector's certificate |
| `--sink-insecure` | off | skip TLS verification; also the only way `http://` is accepted |
| `--sink-timeout <dur>` | 10s | per-connection and per-request timeout |

| Destination | Framing |
|---|---|
| `udp://` | one event per datagram; an event over 8,192 bytes is reported undelivered, never truncated |
| `tcp://`, `tls://` with `syslog*` | RFC 6587 octet counting (the framing RFC 5425 requires over TLS) |
| `tcp://`, `tls://` with `gelf` | NUL-terminated messages (the GELF TCP input) |
| `tcp://`, `tls://` with `ecs`, `cef`, `leef` | newline-delimited |
| `https://` with `otlp` | one `ExportLogsServiceRequest`; point it at the collector's `/v1/logs` |
| `https://` with `ecs` and `--sink-index` | `_bulk` body, a `create` action before each document; a 200 whose body says `"errors": true` is reported as a failure |
| `https://` with `gelf` | one POST per message (the GELF HTTP input) |

```sh
# Security Onion / any syslog collector: ECS documents in RFC 5424 frames over TLS
cau scan --dir /srv --sink-url tls://so-manager.example:6514 --sink-format syslog-ecs \
         --sink-ca /etc/pki/so-ca.pem

# OpenSearch Security Analytics: ECS over the bulk API
export CAU_SINK_AUTH='Basic …'
cau scan --dir /srv --sink-url https://opensearch.example:9200/_bulk \
         --sink-format ecs --sink-index logs-cau.finding-default

# OpenTelemetry collector
cau scan --dir /srv --sink-url https://otel.example:4318/v1/logs --sink-format otlp

# OSSIM / QRadar: CEF or LEEF over syslog
cau scan --dir /srv --sink-url udp://ossim.example:514 --sink-format syslog-cef
```

The flags are checked before the scan starts, so a mistyped collector is a
usage error (exit 4). Delivery itself is **best-effort**, like the Wazuh
forwarder: a collector that is down is one `[WARN]` line and never changes the
exit code. A clean scan opens no connection. `udp://` and `tcp://` are
cleartext and the status line says so; redirects are not followed. For the
resident agent (`cau defend`) the queued, retrying forwarder is separate; this
one sends once, at the end of a scan.

### Daemon mode: crash recovery and self-protection

When `--interval` is set, `cau scan` runs as a resident, self-supervising
daemon rather than a one-shot:

- **Crash recovery.** Every scan cycle runs behind a panic barrier — a panic in
  any detector, in report writing, or in quarantine is caught, logged with its
  stack, counted, and the daemon continues to the next cycle. One bad file or
  bug never takes the service down.
- **Hang/death recovery (systemd).** Under a `Type=notify` unit with
  `WatchdogSec=`, the daemon signals readiness and pings the watchdog on its own
  cadence (half the watchdog window), independent of the scan interval. A true
  hang, deadlock, or hard crash stops the pings and systemd restarts the
  process; a crash-loop is capped by `StartLimitBurst`. With no `NOTIFY_SOCKET`
  (run by hand or in a plain container) these calls are silent no-ops and
  cycle-level recovery still applies.
- **Self-protection.** At startup the daemon makes its process **non-dumpable**
  and sets **no-new-privs** (Linux) so its in-memory state (the pinned trust
  anchor, the loaded signatures) cannot be read out via `ptrace`/`/proc/<pid>/mem`
  or a core dump, and a coerced `exec` cannot escalate. It logs the running
  binary's own SHA-256 so you can compare it to the signed release
  (`cau verify-self`). The shipped unit wraps this in an unprivileged,
  `ProtectProc=invisible`, syscall-filtered sandbox and runs `cau selftest`
  before each start. See the [Anti-Tamper](../wiki/Anti-Tamper.md) guide.

The `--signers` blocklist is a JSON array of `{thumbprint, thumbprint_sha256,
serial, issuer, reason}` entries, or a line file of `<thumbprint-or-serial>|<issuer>|<reason>`
(a 40-hex id is read as a SHA-1 thumbprint, 64-hex as SHA-256, anything else as a
serial needing an issuer). `$CAU_SIGNERS` sets it too. It is the lolcerts feed's
consumer; a binary signed by a listed certificate is flagged
`authenticode.known-abused-signer` regardless of whether the signature itself is
otherwise valid.

### Output and exit code

| Flag | Default | Meaning |
|---|---|---|
| `--format text\|json\|sarif` | text | report format, see [Output formats](output-formats.md) |
| `--output PATH` | stdout | write the report to a file |
| `--pretty` | off | indent JSON and SARIF |
| `--fail-on none\|malicious\|heuristic\|clean` | malicious | the finding level that produces exit code 1 |
| `--no-fail-on-scan-error` | off | do not exit 2 when some files could not be read |
| `--quiet` | off | no banner or progress on stderr |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing at or above the `--fail-on` level |
| 1 | at least one finding at or above the `--fail-on` level |
| 2 | the run completed but at least one file could not be fully scanned (unless `--no-fail-on-scan-error`); a YARA pass that errored or timed out is an incomplete scan, so such a file is not reported clean, and a file that was not fully scanned must never look clean |
| 3 | the run itself failed: unreadable signature database, rules that do not compile, unwritable output. A JSON or SARIF document is still written when possible |
| 4 | usage error |

Precedence, highest first: run failure, scan errors, findings. The `--fail-on`
levels are supersets of each other:

| Level | Exit 1 on |
|---|---|
| `none` | never on findings (errors still fail) |
| `malicious` | a hash-signature hit or a YARA match |
| `heuristic` | ... or a heuristic, static or stego score at its threshold, or a fused verdict reached by corroboration |
| `clean` | ... or any sub-threshold heuristic or static observation; the run must be spotless |

## cau defend

Every layer works alone: `cau ps` finds a shell and never reads its file, `cau
persist` finds a cron line and never scans what it runs, and each decides on its
own. `cau defend` runs them all at once, each on its own schedule, and joins what
they see into **incidents**, so a process, its file and the entry that restarts it
are one finding.

```
sudo cau defend --report-only                    # change nothing: alerts on stdout
sudo cau defend                                  # acts: freezes, quarantines and blocks confirmed incidents
sudo cau defend --once --report-only --watch /var/www   # one pass, exit 1 on any incident
sudo cau defend --respond stop --quarantine      # act on confirmed incidents
sudo cau defend --respond stop --quarantine --block-exe \
     --kernel-events /run/cau/kernel-events.jsonl --canary-manifest canary.json
```

| Layer | Source | Pace |
|---|---|---|
| process | the live process table; a flagged process's executable is read through `/proc/<pid>/exe`, so a deleted or memfd binary still gets scanned | `--interval`, on a change to a watched persistence directory, and on a newly flagged file |
| file | all fifteen detectors, weighed by the fusion lattice, over new files, flagged executables and whatever a persistence entry points at | as files land |
| persistence | `cau persist` | as for process |
| network | the network plane (`cau net`): every socket the kernel holds, attributed to its process and executable, plus the resolver configuration and the neighbour table. Beaconing and gateway-MAC churn compare samples, so they exist only here and in `cau net --interval` | as for process |
| external | telemetry from elsewhere (`--ingest`): another cau host's incidents, an OCSF event from a firewall or an IDS, or a plain JSON line. It joins on the **peer address**, the one identifier two machines agree on, so one C2 address seen from two places is one incident. Remote evidence corroborates and never directs | as for process |
| kernel | the `cau-kernel enforce netshell` event log, including refused attempts whose process is gone; `--kernel-events` or auto-discovered from `/var/log/cau-kernel/events.jsonl` | with process |
| canary | decoys from `cau canary plant`; a rewritten or deleted decoy is live evidence; `--canary-manifest` or auto-discovered from `/var/lib/cau/canary.json` | as for process |
| package | installed maintainer scripts (`cau installed`) | hourly |
| selftest | the engine's own detection content, verified against the baseline recorded by `cau selftest --record` (ATT&CK T1562.001). A drift is live evidence of tampering and confirms on its own. Auto-discovered from `integrity.json` next to the signature DB | `--selftest-interval` (default 15m) |
| feed | re-reads the abuse-intel feed from disk, so a `cau feed update` run on the host lands without a restart | `--feed-reload` (default 10m) |

**Proactive.** A dropped script is flagged a few milliseconds after it lands, and a
persistence entry that runs it confirms the incident tens of milliseconds later. A
real binary takes as long as its scan, about 0.3 s for 1.4 MB on a quiet host: see
[the measurements](../README.md#measured-not-asserted). Files are watched with inotify under the places attacks land
(`/tmp`, `/var/tmp`, `/dev/shm`, `/var/www`, `/srv`) and persist (cron, systemd
units, profile, udev, MOTD, APT, sudoers, PAM and root's SSH directories), with
`--watch` to replace that list. A file is scanned as soon as it lands and correlated
against what the other layers last reported; a change to a persistence directory
runs the audit immediately, and so does a newly flagged file, because the entry that
restarts it may sit somewhere no watch covers. A file that gets `chmod +x` later is
scanned again. What is already there is swept at startup, and after the kernel
reports lost events. Symlinks are not followed. Reaching the 8,192-directory limit is
reported.

Flagged files are remembered, because otherwise an attacker could beat correlation
by waiting: a file dropped now joins the process that runs it an hour later, and the
incident is raised again with its new evidence.

**Nothing waits.** Every layer, every scan worker, the startup sweep and each
incident's response is its own goroutine, so a slow part delays only itself: the
package audit takes seconds and no alert waits for it. Within a part the work fans
out too: the process table per process, the persistence audit per check, the package
audit per package, the engine per detector and a response per action. Two things
stay single-file on purpose. The correlator is one goroutine, because a join has to
see one view of the evidence; it does no I/O, and a join takes about 50 µs over ten
signals and 1.4 ms over a thousand, with requests made while one runs collapsed into
the next. Writes to one file are collapsed into one rescan.

New files go ahead of anything a sweep found, and half the workers never take sweep
work, so a sweep can't use every core and a drop lands fast while a large tree is
being swept. A file is scanned at most ten times a second however often it changes.
Reading the events still costs something: a file rewritten in a tight loop used
50 % to 83 % of one core at 15,000 to 150,000 rewrites a second. Scans are bounded by
the CPUs this process may use, up to 32, which respects a CPU quota. Each scan reads
at most 64 MiB into memory, and files over 1 MiB share a budget of 128 MiB across all
scans, so large files take turns: a burst of them is slower, and nothing is skipped.
One 60 MiB file still costs real memory: about 310 MB of heap for text or a list of
hex numbers, and 567 MB for a single run of base64 — 642 MB before the text decoders
were right-sized, measured by peeling a 58 MiB file of wrapped base64 through
`cau peel`. What is left of that peak is not a decoder's buffer: each layer that
detects a wrapped blob re-joins its lines, so that repetition dominates now, and a
decode is still not cut short before the output budget is checked, because an early
refusal turns a "not this layer" into a bomb verdict and loses the finding. The daemon
also sets a soft 768 MiB heap limit unless `GOMEMLIMIT` is set. A stop waits 5 seconds
for a scan in progress, which can't be interrupted, and then exits without it. A
response is always finished first. A file over 1 GiB is not read at all,
because hashing streams to the end and a sparse file is any size for free. It raises
a `file.too-large` alert instead, and is never quarantined for that alone. The
watched trees are also swept every five minutes, which is what finds a file nothing
reported: no inotify, or a directory past the watch limit.

**A crash is news.** A detector that panics on a file runs once more, and the other
detectors are not affected. The panic is reported whether or not the retry worked,
as a warning in every report and, under `cau defend`, as a `file.detector-panic`
alert. If the retry also fails the file went without that detector's opinion, and a
file that was otherwise clean is reported as an error rather than as clean. A parser
bug can be tripped by a harmless file, so this is an alert for a human and never
confirms anything on its own, though it joins other evidence like any file signal.

A daemon task that panics is retried at once, and raises one `defend.crash.<task>`
alert on the incident stream, with the stack in the service log. A retry that keeps
failing waits for that task's next trigger, so a repeating panic can't spin. A
response that panics is the exception: it is not run again, because part of it may
have happened, and the incident is reported with what the other actions did.

A response that fails cleanly is unfinished, because the file is still there or the
peer still reachable. A failed quarantine or block raises the incident again after
5, 10 and 20 seconds, on the evidence as it stands by then and through the same
gate, and each attempt reports its own outcome.

**Output never holds anything up.** The daemon writes reports on their own goroutine,
so a consumer that stops reading can't stop detection, a response, the SIEM forward
or a shutdown. It keeps the last 4,096 reports, drops the oldest past that, says so
on stderr, and gives a stalled consumer 2 seconds at exit. The memory of raised
incidents and flagged files is bounded at 65,536 each, and neither is wiped when
full, since that would raise every live incident again at once.

**Blocking.** It defends by default: a confirmed incident gets its process
frozen (`--respond stop`), its file moved to the vault (`--quarantine`), and the
kernel and firewall blocks (`--block-exe`, `--netblock`) arm themselves where the
host can do them, skipping with a clear log line where it cannot.
`--report-only` turns the whole response surface off and leaves it detecting,
alerting and forwarding — the mode to run in for a while on a host you do not
know yet. `report-only = true` in `/etc/cau/cau.conf` does the same without
editing a unit file.

What makes that safe to leave on is not the default but what counts as
confirmed, and that every default action is reversible: `stop` freezes a process
with its memory intact for you to examine rather than killing it, and the vault
restores. `--respond kill` is still opt-in, because it is the one that is not
reversible. Response acts only on a **confirmed** incident, which needs one of:

| Evidence | Examples |
|---|---|
| live state of the host | a shell on a real socket or pipe relay, a set-uid shell, memfd execution, a process with no file on disk holding a socket, a kernel guard event, a rewritten canary |
| two independent layers on one artefact | a flagged file that a cron line runs; this host's quiet connection to a peer a firewall already identified |
| known-bad content, for a file | a hash or YARA hit |
| known-bad peer, for a connection | a remote address the abuse-intel feed lists |

One layer's opinion alone is an alert for a human. Text in argv never confirms
anything, because `grep "/dev/tcp" notes.txt` reads exactly like the attack. Only a
file the content scanner flagged is quarantined, never a cron table or a PAM stack
that merely names it, and never a system path. System paths also never link
signals: every shell's executable is `/usr/bin/bash`, and joining on it would merge
every unrelated incident on the host. `--once` exits 0 clean, 1 incidents, 3 failed,
4 usage. Alerts are text, or one JSON object per line with `--format json`.

**Forwarding to a SIEM.** Each incident is posted as one OCSF 1.3.0 Detection
Finding in the same envelope `cau scan --format ocsf` writes, so one correlation
rule matches events from either surface. Free and unmetered, like the rest of
detection and prevention: see [pricing](pricing.md).

```
sudo cau defend --wazuh-url https://wazuh.example.com:55000 \
     --wazuh-user cau-agent --wazuh-password-env WAZUH_PASSWORD
```

| Flag | Default | |
|---|---|---|
| `--wazuh-url <base>` | | Wazuh Manager API base; enables forwarding |
| `--wazuh-user <user>` | | API user |
| `--wazuh-password-env <var>` | `WAZUH_PASSWORD` | variable holding the password. It is never put on argv, which is world-readable in `/proc/<pid>/cmdline` |
| `--wazuh-ca <file>` | | PEM CA bundle to trust for the manager's certificate |
| `--wazuh-insecure` | off | skip TLS verification; also allows `http://` |
| `--wazuh-timeout <dur>` | 10s | per-request timeout |
| `--forward-queue <n>` | 4096 | incidents buffered while the manager is unreachable |

Delivery runs on its own goroutine and is designed for a daemon nobody restarts:

- **Detection never waits on the network.** Raising an incident hands it to a
  bounded queue and returns, so a manager that is slow or wedged costs queued
  events and not one millisecond of detection latency.
- **An outage is buffered, not discarded.** A batch the manager refuses goes
  back on the queue and is retried on a widening interval that settles at one
  attempt a minute, rather than hammering a service that is already struggling.
  When the manager returns, what was buffered is delivered.
- **The buffer is bounded, so the cost is memory you chose and not the host.**
  Past `--forward-queue` events the queue drops its *oldest* to admit a newer
  one, because the local report is still the complete record and the freshest
  incidents are the ones an analyst needs next. That eviction is the only way an
  event is lost while the daemon is up, and it is counted.
- **It says so when delivery breaks**, once on the way down and once on the way
  back up, rather than once per failed batch: an unreachable SIEM must not fill
  the log it is meant to relieve. The counts are reported at shutdown.
- **A forwarder that cannot work fails at startup.** A `--wazuh-url` with no
  password in the environment is a usage error, not a daemon that looks healthy
  and delivers nothing.

A partial delivery resends only the undelivered tail, so the manager does not
get duplicates of exactly the events it did receive. `finding_info.uid` is the
incident fingerprint the daemon itself dedupes on, so an incident raised again
carries the same uid and is collapsible rather than a second page.

**Network response and cross-domain intake.** `--netblock` is on by default, so a
confirmed incident's peers are dropped in cau's own nftables table or iptables
chains — and skipped with one clear line at startup on a host with neither, so a
defence that cannot act never looks armed. `--netblock=false` leaves the network
plane read-only while every other layer keeps responding, and `--report-only`
turns the whole response surface off; `--block-ttl` (default 1h) is how long that lasts, `--sever` also
destroys the sockets already open, and `--netblock-dry-run` logs the firewall
commands without running them. Loopback, this host's own addresses, its gateways
and its resolvers are never blocked. `--ingest <path>` (repeatable, a file or a
directory) reads telemetry from other hosts and sensors; `--ingest-max-age`
(default 24h) keeps a file left behind by a stopped sensor from raising its last
incident forever. Only this host's own artefacts are ever acted on: a remote
signal confirms an incident, it does not direct the response. Strong remote
evidence does put its peers on the network sensor's watchlist, which is how a
sub-threshold local connection to an already-identified address stops being
quiet. Full policy in [network.md](network.md).

| Flag | Default | |
|---|---|---|
| `--report-only` | off | change nothing: detect, alert and forward, never act |
| `--config <file>` | `/etc/cau/cau.conf` | agent configuration; the only place a setting can be signed |
| `--siem <addr>` | | where to forward: IP, host, host:port or full URL. `10.0.0.5` means `https://10.0.0.5:55000` |
| `--respond <action>` | `stop` | stop, kill or none for confirmed processes. `stop` is reversible and keeps the memory |
| `--quarantine` | **on** | move confirmed files into the vault |
| `--block-exe` | **on** | ask the kernel to refuse confirmed files; skipped if cau-kernel is absent |
| `--netblock` | **on** | drop traffic to and from a confirmed incident's peers; skipped with no firewall |
| `--block-ttl <dur>` | 1h | how long a block lasts; 0 means until it is removed |
| `--sever` | off | with `--netblock`: destroy established connections to a blocked peer |
| `--netblock-dry-run` | off | log the firewall commands and run none of them |
| `--ingest <path>` | | read telemetry from this file or directory; repeatable |
| `--ingest-max-age <dur>` | 24h | ignore ingested events older than this; 0 keeps everything |
| `--no-network` | | disable the network layer |

`packaging/systemd/cau-defend.service` runs it as a service, defending, with
`--report-only` documented in the unit for operators who want to watch first.
Its sandbox differs from the scan daemon's on purpose: that one hides other
processes, `/tmp` and `/dev/shm`, which would leave this one healthy and blind.

**Configuration and tamper resistance.** Settings come from the built-in
defaults, then `/etc/cau/cau.conf`, then the command line — a flag you type
always wins. The file is where the SIEM address belongs, because it is the only
one of the three whose contents can be *signed*:

```
# /etc/cau/cau.conf
siem      = 10.0.0.5          # https://10.0.0.5:55000; host:port and full URLs also work
siem-user = cau-agent
respond   = stop

# Who may answer at that address. Without this, a certificate from any CA in
# the host's trust store is enough. Start the agent without it and it logs the
# pin the manager presented, which is the value to paste here.
siem-cert-pin = sha256/K7tbT0d3kEHgKqkTSL4L0xNfz7pQBHJ+Zq0Xq8kVn1A=
```

```sh
sudo cau selftest --record --sign-key priv.hex   # pin it; keep the key off the host
sudo cau defend --siem 10.0.0.5                  # or set it for one run
CAU_SIEM=10.0.0.5 sudo -E cau defend             # or from the environment
```

`cau selftest --record` baselines the signature DB, the YARA rules, the fuzzy
DB, the threat feed, this configuration file and the agent binary, and pins the
SIEM address into the manifest. Every file the agent reads is then checked twice:

| Check | What it closes |
|---|---|
| how it sits on disk | a symlink can be repointed after the check; a world-writable file, or (running as root) a group-writable one, or one owned by another user, can be rewritten after it |
| against the signed baseline | the contents changed since someone trusted them |

The feed is verified on **every reload**, not only on the selftest interval,
because the reload is what an emptied feed would ride in on — a feed that fails
is refused and the last good one stays live. The digest is taken over the file
the agent is *about* to read, not the path the baseline records, so pointing
`feed =` or `--feed` at another file is reported rather than quietly verified
against the untouched original. A feed that parses to zero indicators never
replaces a populated one, baseline or no baseline.

Because the feed is the one baselined resource an operator updates routinely,
`cau feed update` re-records its digest as it writes, so an ordinary update
lands without being mistaken for an attack — and the daemon re-reads the
baseline on each reload, so a re-record takes effect without a restart. A
*signed* baseline is never rewritten without its key: pass `--sign-key` to
`cau feed update`, or re-record afterwards with `cau selftest --record
--sign-key`. The command says which, rather than leaving a stale digest that
would later read as tampering. The SIEM address is pinned, so
editing `cau.conf` to point elsewhere neither silences the stream nor redirects
it: the baselined address is used and the edit is raised as
`defend.tamper.siem-redirected`. Any other drift raises a confirmed incident of
its own (T1562.001).

A failed check never disables the agent. Refusing to run because one file
changed would hand an attacker a one-file off switch for the defence, so the
agent keeps the last trustworthy value and says so loudly instead.

The same holds at startup: nothing on disk stops `cau defend`, and only a mistake
on its own command line can. A corrupted, missing or planted public key, baseline,
`cau.conf`, signature database, fuzzy database or rule file leaves the daemon
running without what it lost, and raises a top-score incident
(`defend.tamper.integrity-unverifiable`, `defend.tamper.config-unusable`,
`defend.tamper.content-unusable.*`). So do a canary manifest it cannot read
(`defend.tamper.canary-unusable`) and a forwarder from `cau.conf` that cannot run
(`defend.tamper.siem-unusable`). A key or baseline that cannot be checked vouches
for nothing: no signature is reported as verified and no pin is honoured, a feed
already loaded stays frozen, and digest drift is still reported. Both are retried
on every selftest cycle, so a repair needs no restart. `--selftest-pubkey` has to
be a regular file that nobody but root or the agent's own user can replace, which
rules out a pipe; `$CAU_SELFTEST_PUBKEY` supplies a key with no file. `cau selftest`
stays strict and exits 3.

**Guarantees that are not in force are reported too.** The way integrity
checking fails in practice is not that somebody defeats it; it is that it was
quietly worth nothing all along. Three of those are now alerts rather than
silence — scored to corroborate, never to confirm, because a misconfiguration
must not arm a response:

| Class | What it means |
|---|---|
| `defend.weak.signing-key-on-host` | a file that looks like an Ed25519 signing key is in `/etc/cau` or beside the manifest. Whoever can rewrite the content can sign their own baseline over it, so the signature is worth no more than a digest |
| `defend.weak.siem-pin-overridden` | `--siem` or `$CAU_SIEM` set the pinned address aside. The override still wins — an operator moving their SIEM should not need a re-recorded baseline first — but it is the one way left to redirect the stream without the config digest changing, so it is never silent |
| `defend.weak.siem-tls-unverified` | `--wazuh-insecure` is on, so the pinned address no longer says who receives these incidents |

**Who receives the incidents, not just where they go.** `siem-cert-pin`
requires the manager's public key to match, in addition to the certificate
chain verifying — never instead of it. The address pin alone is only half the
control: TLS verification is what identifies the server, and that holds only
while every one of the hundred-odd CAs in the host's trust store does. The pin
is a SHA-256 over the DER `SubjectPublicKeyInfo`, so it survives certificate
renewal; several may be listed comma-separated to rotate a key without an
outage; any certificate in the presented chain may match, so you can pin an
issuing CA of your own; hex and base64 both work, and `sha256/` is optional. On
a mismatch the agent logs the pin the manager actually presented — which is
either the value to paste into the config, or the evidence that something else
is answering. The pin is signed into the baseline, since an attacker who could
edit it on disk would simply substitute their own collector's. Pinning together
with `--wazuh-insecure` is refused rather than silently resolved.

A release build also carries a **pinned baseline-signing key**, the same way
`cau update` carries a pinned release key, and a build you compile yourself can
carry one too with `make build SELFTEST_PUBKEY=$(cat pub.hex)`. That closes a
downgrade: without one,
"no key configured" and "this baseline is unsigned" are the same state, so an
attacker who rewrites the content can replace the signed baseline with an
unsigned one and the agent has nothing to object to. With a key in the binary a
signature is *expected*, and deleting the operator's key file no longer helps.
The CA bundle is baselined alongside the SIEM address, since swapping it for one
you control redirects the stream with TLS verification still nominally on.

The remaining limits are in [limitations](limitations.md), and they are real:
an attacker with root can replace the binary along with the key pinned into it,
a build you compiled yourself pins no key at all, and drift records *when* but
not *who*.

**Leaving it running.** The unit appends to `/var/log/cau/defend.jsonl`, so
`packaging/logrotate/cau` (installed to `/etc/logrotate.d/cau` by the Debian and
Arch packages, or by `make install-logrotate`) rotates it daily, at 100 MB, over
14 generations. Without it the one thing an always-on agent is guaranteed to do
is fill the disk of the host it protects. The newest rotation is left
uncompressed for `grep` and `jq`. Rotation restarts the unit to reopen the
append target rather than using `copytruncate`, which races with a writing
process and can tear a line.

## cau persist

Audits a Linux host for persistence (`internal/persist`): what will run after
the next reboot or login, and the accounts and privileges that let an attacker
back in. Read-only: it never edits a file, because the line it would remove may
be the only evidence, and a machine-edited PAM or sudoers file can lock the
operator out.

```
sudo cau persist                 # audit this host
cau persist --all                # include sub-threshold observations
cau persist --root /mnt/suspect  # audit a mounted disk from a clean host
cau persist --format json
```

| Class | Looks at | Technique |
|---|---|---|
| `persist.ld-preload` | `/etc/ld.so.preload` | T1574.006 |
| `persist.symlink.writable-target` | an audited path that links into a world-writable or hidden location | T1037 |
| `persist.symlink.critical-file` | `ld.so.preload`, `sudoers`, `passwd`, `shadow` or `crontab` being a link at all | per file |
| `persist.symlink.unaudited` | an audited path linking outside the system trees (an observation, shown with `--all`) | T1037 |
| `persist.cron.*` | crontabs, `cron.d`, the periodic directories, spools | T1053.003 |
| `persist.systemd.*` | `Exec*=` lines of system, user and transient units and their drop-ins | T1543.002 |
| `persist.shellrc.*` | profile and rc files, `~/.ssh/rc`; aliases shadowing `sudo`, `su`, `ssh`, `passwd`; exported `LD_PRELOAD` | T1546.004 |
| `persist.rc-local.*` | `rc.local` | T1037.004 |
| `persist.autostart.*` | XDG autostart `Exec=` lines | T1547.013 |
| `persist.ssh-key.*` | forced commands; direct root keys (observation) | T1098.004 |
| `persist.account.*` | extra UID 0 accounts, empty passwords | T1136.001, T1078.003 |
| `persist.sudoers.*` | `ALL ALL=NOPASSWD: ALL`; `env_keep` of a loader variable; single-user NOPASSWD (observation) | T1548.003 |
| `persist.udev.*` | `RUN` keys of local udev rules | T1546 |
| `persist.init-script.*` | MOTD, `init.d` and `if-up` scripts | T1037 |
| `persist.apt-hook.*` | `Pre-Invoke` and `Post-Invoke` package hooks | T1546.004 |
| `persist.ld-conf.*` | library search path entries in writable locations | T1574.006 |
| `persist.modprobe.*` | `install` directives that run a command | T1547.006 |
| `persist.perms.*` | account files writable or `shadow` readable by everyone; autostart files anyone can write | T1222.002 |
| `persist.caps.*` | root-equivalent file capabilities on interpreters | T1548.001 |
| `persist.pam.*` | `auth sufficient pam_permit.so`; `pam_exec` from writable paths | T1556.003 |
| `persist.suid.writable-dir` | set-uid programs in `/tmp`, `/var/tmp`, `/dev/shm` | T1548.001 |

Autostart entries score on the same hostile-command recognisers as the package
scanner, or on running from a world-writable or hidden location. Symlinks are
not followed, so a root audit cannot be steered into quoting `/etc/shadow`. A link
is judged by where it points instead, without opening the target, and one into a
system tree is taken at face value: packages create them by the hundred.
Run as root: without it `/etc/shadow`, other users' homes and their crontabs are
skipped. Exit codes: 0 clean, 1 detections, 4 usage.

## cau ps

A point-in-time threat scan of the **live process table**, read entirely from
`/proc` (`internal/procscan`). The scan itself is **read-only**; only `--respond`
ever touches a process. It complements the file scanner: a dropper that already decoded and executed in memory leaves nothing on disk for
`cau scan`, but its process is still running.

```
cau ps                       # scan every process, text report
cau ps --format json         # machine-readable
sudo cau ps                  # full visibility into other users' processes
sudo cau ps --respond stop   # freeze confirmed processes, keep their memory for forensics
sudo cau ps --interval 10s --respond stop   # keep watching
```

It flags processes a benign system would not be running:

- **Fileless / RAM-only execution** — a `memfd:` backing, a deleted executable,
  or an exe under `/dev/shm` (T1620).
- **Name masquerading / PID hijacking** — a fake `btop`, a `/tmp/sshd`, a
  `[kworker]` bracket-name with a real userspace exe (T1036.004 / T1036.005).
- **Library-injection hooks** — a `.so` mapped from a world-writable, hidden, or
  deleted path, or a suspicious `LD_PRELOAD` / `LD_LIBRARY_PATH` (T1574.006).
- **Malicious command lines** — reverse shells, `curl|bash`, droppers, and the
  whole `tradecraft` vocabulary: socat (`EXEC:` and `SYSTEM:`), gawk `/inet`,
  `openssl s_client` and `curl telnet://` relays, BusyBox `telnetd -l /bin/sh`,
  inline PHP, Python, Perl, Ruby and Lua shells, encoded loaders, [GTFOBins](https://gtfobins.github.io)
  breakouts under `sudo` or setuid, [LOLBAS](https://lolbas-project.github.io)
  download and proxy-execution shapes, [lolol.farm](https://lolol.farm) trusted-SaaS
  channels (Microsoft Graph mail, Firebase realtime DB, Cloudflare Workers,
  Google Apps Script, Dropbox content upload, Discord CDN, Slack API, Lambda invoke,
  blockchain RPC) and the [ArcticFox detection-bypass](https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md)
  primitives (`memfd_create` + `execveat`, `prctl(PR_SET_NAME)`, `LD_PRELOAD`
  shims, PAM backdoors, systemd unit hijacks, `/proc/self/exe` unlink, ICMP/DNS
  covert channels, domain fronting). The recognisers overlap on purpose, so
  together they count as one piece of evidence: the strongest keeps its score
  and the rest report at zero.
- **Network shells** — an interpreter whose stdin and stdout are both a live TCP
  connection, the wiring of a reverse or bind shell, whatever its command line
  claims (T1059.004). The socket inode is resolved against the process's own
  network namespace, because harnesses run shells over `AF_UNIX` socketpairs
  that look the same in `/proc/<pid>/fd`.
- **Pipe relays** — `mkfifo | sh | nc` puts no socket on the shell, so this looks
  for an interpreter whose stdout is the stdin of a network tool holding a live
  connection, with its own stdin also piped. Both halves matter: `curl x | sh`
  keeps a terminal on stdout, and `./report.sh | nc host` has no fed stdin.
- **Set-uid shells** — an interpreter whose effective uid differs from its real
  uid, what a SUID GTFOBin leaves behind (T1548.001). `sudo` sets both, so an
  ordinary root shell does not match.
- **Kernel guard events** — with `--kernel-events`, what `cau-kernel enforce
  netshell` recorded about a live process. A PID alone is not identity, because
  the log outlives processes, so the name must agree as well.
- **Processes under ptrace** (T1055.008), and **anonymous executable memory**
  (T1055) as context only: JIT runtimes carry it on a clean host, so it can
  corroborate but never flag a process alone.

### Responding

`--respond stop` sends SIGSTOP, which freezes the process with its memory and
sockets intact and is undone with `kill -CONT <pid>`. `--respond kill` sends
SIGKILL and cannot be undone. Response is opt-in and acts only on a **confirmed**
process: one with a conclusive finding (a network shell or pipe relay, a set-uid
shell, memfd or `/dev/shm` execution, a masquerade, a kernel guard event, or a
network-shell command line held by the interpreter or relay tool running it), or
a combined score of at least `--respond-score` (default 16). Everything else
is reported and left for a human, and the report says so for each process.

`procscan.fileless.deleted` is deliberately not conclusive: a program upgraded
while it runs looks exactly the same, and freezing a service for that is an
outage the defender caused. Reverse-shell text in argv counts only on an
interpreter, so `grep` over a note about one is never touched. PID 1, the
responder and its ancestors are never signalled, and the process identity is
re-read immediately before the signal so a recycled PID is not hit.

`--block-exe` adds a kernel response: before the signal it asks `cau-kernel enforce
block` to refuse the process's file, so it cannot be run or read again. It needs a
running file guard (`cau-kernel enforce run --core bpf/lsm_fileopen.bpf.o`), and
it refuses system paths and interpreters outright, because the executable of a
reverse shell is usually `/bin/bash`.

Without root, other users' processes are only partly readable; those fields are
skipped and counted as *unreadable* rather than failing the scan.

| Flag | Default | Meaning |
|---|---|---|
| `--format <fmt>` | `text` | `text` or `json` |
| `--threshold N` | 8 | per-process score at which a process is flagged |
| `--feed <path>` | search path | abuse-intel feed to match process command lines against (empty = none) |
| `--proc-root <dir>` | `/proc` | override the procfs root (testing) |

Exit codes: `0` nothing flagged, `1` one or more processes flagged, `4` usage.
(The procscan techniques are a **runtime** surface and are not yet part of the
`cau coverage` ATT&CK matrix, which today ingests the file-scanner detectors.)

## cau net

A point-in-time threat scan of the **network plane**, read entirely from `/proc`
and `/etc` (`internal/netscan`), plus the blocker that acts on it
(`internal/netblock`). The scan is **read-only**: it opens no socket, sends no
probe and captures no packets. See [network.md](network.md) for the design, the
full class list and the response policy.

```
cau net                                       # one read of the network plane
cau net --interval 30s                        # beaconing and MAC churn need samples
cau net --feed /var/lib/cau/feed.txt          # match peers against the abuse-intel feed
cau net --format json                         # machine-readable
sudo cau net                                  # full attribution of other users' sockets
sudo cau net --respond block --dry-run        # what it would block, and nothing else
sudo cau net --respond block --block-ttl 30m  # act on live and known-bad findings only
sudo cau net block 203.0.113.9 --reason "phishing kit C2"
cau net blocks                                # what is blocked, why, and when it expires
sudo cau net unblock 203.0.113.9
sudo cau net clear                            # remove every rule cau created
```

Every socket the kernel holds is attributed to the process and the executable
behind it, which is what makes a network finding something you can act on — and
what lets the correlator join a connection to the file scanner's verdict on the
same binary. Sockets are read **per network namespace**, so a container's
backdoor is found and attributed rather than missed.

It flags:

- **Fileless network presence** — a socket held by a process whose executable is
  a `memfd:`, a deleted inode or a tmpfs path (T1620 with T1071/T1571). This is
  the one network class that counts as **live state**: a payload that never
  touched disk is holding a connection now.
- **Bind shells and relays** — a listener owned by nc, ncat, socat, telnet or
  rcat, or by a shell or language runtime, whatever the command line says
  (T1059.004).
- **Known-bad peers** — a remote address, a `resolv.conf` nameserver or an
  `/etc/hosts` target that the abuse-intel feed lists. An exact identification,
  like a hash hit (T1071).
- **Handler ports and unexpected listeners** — the default ports of the common
  handlers (4444, 1337, 31337, …), and a binary no package installed listening
  on every address (T1571). Context only: a developer can bind any of them.
- **DNS-plane escape** — a program querying a nameserver this host is *not*
  configured to use (T1071.004), DoT/DoQ from a program whose job is not DNS
  (T1572), a `resolv.conf` naming a nameserver that is neither local nor a
  documented public resolver, and an `/etc/hosts` entry that points a security
  or update domain at a dead address so the host cannot heal itself (T1562.001).
  A program sending to port 53 is *not* a signal: glibc's resolver runs inside
  every process that looks up a name.
- **Connect sweeps** — one process with connections in flight to twelve or more
  distinct peers, the shape of service discovery (T1046).
- **Beaconing** — repeated connections to one peer on a schedule, measured
  across samples: four or more with 25 % jitter or less (T1071.001). Needs
  `--interval` or `cau defend`.
- **Neighbour-table tampering** — the default gateway's MAC moving under the
  host, or one MAC answering for the gateway and another address (T1557.002).
  Reported, never live: a router failover does this too.

The reporting threshold (`--threshold`, default 5) is per **subject** — one
process, or one peer when the holder could not be read — so a developer's
`python3 -m http.server` (4) stays silent while the same interpreter on 4444 (8)
does not. Without root most holders are unreadable; those sockets stay in the
report as unattributed and are counted, never guessed at.

### Blocking

`--respond block` acts only on a finding that confirms itself: **live state** (a
fileless process holding a socket) or an **exact identification** (a feed
match). A score, however high, is an alert for a human.

A block is a drop rule in cau's own nftables table (or its own iptables
chains), at the output, input **and forward** hooks so a container host blocks
its containers too. It **expires** — `--block-ttl`, one hour by default — with
nftables holding the timeout in the kernel, so a block survives a crash of the
agent and is still released on time; the iptables fallback carries the expiry in
each rule's comment. `--block-ttl 0` makes it permanent, which you have to ask
for. `--sever` also destroys the sockets already open, because a dropped TCP
session otherwise keeps retransmitting inside the host for minutes.

These are **never** blocked, however confirmed the incident: loopback, the
unspecified address, multicast, link-local, every address configured on this
host, every default gateway and every configured nameserver. Blocking the
gateway is what an attacker would want a confirmed-looking incident to achieve.

`cau net clear` removes exactly what cau created and leaves the host's own
firewall as it was. Every block is appended to `/var/lib/cau/netblock.log` with
its reason, which `cau net blocks` reads back.

A drop rule is visible to the peer, and a peer with a second address is back at
once. It buys an operator minutes; it is not containment, and this engine does
not call it protection.

| Flag | Meaning |
|---|---|
| `--format text\|json` | report format |
| `--threshold <n>` | per-subject score to report (default 5) |
| `--feed <path>` | abuse-intel feed to match remote addresses against |
| `--interval <d>` | re-scan until a termination signal; what gives the time-based analytics their samples |
| `--respond block` | block the peers of confirmed findings |
| `--block-ttl <d>` | how long a block lasts (default 1h; 0 means until removed) |
| `--sever` | also destroy established connections to a blocked peer |
| `--dry-run` | print the firewall commands and run none of them |
| `--backend nftables\|iptables` | force a backend instead of discovering one |
| `--ledger <path>` | where blocks are recorded (default `/var/lib/cau/netblock.log`) |
| `--reason <text>` | with `block`: why, for the ledger |
| `--proc-root`, `--etc-root` | override `/proc` and `/etc` (testing) |

Exit codes: 0 nothing flagged, 1 one or more findings, 3 the run failed, 4 usage.

## cau installed

Audits the maintainer/install scripts of **already-installed** packages, in
place, from the package managers' on-disk metadata — offline and read-only. It
flags any package whose scripts carry the same tradecraft `cau scan` looks for
(curl-into-shell, reverse shells, SSH-key backdoors, persistence) or that
reference an abuse-intel indicator. This catches a supply-chain compromise that
already landed, without re-downloading anything.

```
cau installed                 # audit every installed package
cau installed --format json
```

It covers **dpkg** (`/var/lib/dpkg/info`) and **pacman**
(`/var/lib/pacman/local`). RPM keeps its scriptlets inside the rpmdb rather than
as loose files, so it is reported as a **gap**, not silently skipped.

| Flag | Default | Meaning |
|---|---|---|
| `--format <fmt>` | `text` | `text` or `json` |
| `--threshold N` | 8 | per-package score at which a package is flagged |
| `--feed <path>` | search path | abuse-intel feed to match against |
| `--dpkg-info <dir>` | `/var/lib/dpkg/info` | override the dpkg metadata dir (testing) |
| `--pacman-local <dir>` | `/var/lib/pacman/local` | override the pacman metadata dir (testing) |

Exit codes: `0` nothing flagged, `1` one or more packages flagged, `3` failed,
`4` usage.

## cau firmware

Parses a **UEFI firmware image** — its Firmware Volumes and the FFS files and
sections inside them, including volumes nested inside LZMA-compressed sections —
and reports a module inventory (GUID, type, UI name, nesting depth, whether it
carries a PE), the FV header's checksum integrity, any module GUID on an
operator-supplied implant blocklist, and any module whose executable body
matches a YARA rule. This is the Phase-8 firmware
wedge: firmware persistence survives disk wipes, and no mainstream EDR publishes
its firmware layer.

```
cau firmware ./bios.rom
cau firmware ./capsule.bin --implants known-implants.txt --format json
```

It is **honest about its boundary**: the engine ships **no implant truth set**,
because firmware is overwhelmingly legitimate PEI/DXE/SMM drivers and scoring
module shapes would be a false-positive machine. So only three things score —
`uefi.volume-checksum-invalid` (an FV header whose 16-bit checksum does not
validate, a genuine tamper/hand-built tell), `uefi.known-implant-guid` (a
module matching your `--implants` blocklist) and `uefi.module-rule-match` (a
module's PE32/TE body matching a YARA rule, weight 8). Everything else is
inventory. ATT&CK T1542.001 (System Firmware).

**Compressed volumes.** Nearly every modern image keeps its driver volume in an
LZMA-compressed section, so the parser carries its own bounded LZMA decoder
and walks what is inside (at most 64 MiB per section, 256 MiB per image, four
levels of nesting). On the stock OVMF images this takes the inventory from 0-1
modules to 91-156. Sections in the EFI/Tiano compression or another
GUID-defined encoding are not opened; the report counts every section that
could not be opened and says its contents are not in the inventory.

**Rules over module bodies.** Each module's executable section is run through
the YARA rules (`--rules`, default the bundled set; `--no-yara` to skip). The
bundled rules were written for operating-system malware, so a hit on a firmware
module is strong evidence and no hit says little. Measured on the 11 OVMF
images shipped by Debian (1,079 module bodies): no rule fired. That is one
firmware family and a small sample, not a false-positive rate for vendor
firmware. When rules are not run, the report says so instead of showing an
empty result. Module bodies are not disassembled, and NVRAM, signatures and
boot policy are not analysed.

The `--implants` file is one `guid` or `guid|name` per line, `#` comments.

| Flag | Default | Meaning |
|---|---|---|
| `--format <fmt>` | `text` | `text` or `json` |
| `--threshold N` | 8 | score at which the image is reported suspicious |
| `--implants <file>` | none | implant-GUID blocklist (empty/omitted = structural inventory only) |

Exit codes: `0` clean, `1` suspicious, `3` the run failed, `4` usage. (This is a
standalone command; UEFI is not part of the per-file `cau scan`.)

### cau firmware scan

```sh
cau firmware scan [--format text|json] [--rules <dir>] [--db <path>]
                  [--no-static] [--max-members <n>] [--fail-on none|heuristic|malicious]
                  <image>...
```

Looks inside a firmware image and runs the ordinary detectors over what it
finds there. A router, NAS or IoT image is a container: a filesystem, an
archive or a compressed stream with the real content somewhere inside it, and
scanning the image as one blob finds the container's bytes and nothing else.

The container formats this build identifies are squashfs, cramfs, jffs2,
ext2/3/4, FAT, gzip, zip, tar, xz, zstd, LZMA, uImage and ISO. The members of
gzip, zip and tar are extracted and scanned like any other file. A container
this build cannot open is reported with its offset and the reason it was not
opened — never as an empty result, because an image whose filesystem was not
unpacked is an image nothing was measured in.

The extraction is bounded: at most `--max-members` members per image, each
member and the whole extraction under fixed byte budgets.

## cau boot-scan

Reads the **boot chain**, the part of a host that a file scan never reaches,
and reports what it finds. It is strictly read-only: disks are opened
read-only, no firmware variable is set, no option ROM is enabled and no flash
chip is touched. A test over the package source fails the build if that ever
stops being true.

```sh
sudo cau boot-scan                                  # this host: ESP, firmware variables, sysfs
sudo cau boot-scan --disk /dev/nvme0n1              # plus the disk's MBR, GPT and boot sectors
cau boot-scan --offline --disk ./evidence.img       # an image from another machine, nothing else
cau boot-scan --dbx-reference ./x64_DBXUpdate.bin --format json
```

| Surface | What is read | What is scored |
|---|---|---|
| Disks (`--disk`, repeatable) | MBR, GPT primary and backup headers with both CRC32s, each partition's first sector | a ransom note in the boot area (`boot.ransom-text`, the only class that crosses the threshold alone); a destroyed primary GPT with an intact backup; header or entry CRC failures; primary and backup that disagree; overlapping or out-of-range partitions; an ESP that is not FAT; unrecognised MBR boot code |
| EFI System Partition (`--esp`) | every `.efi` file: SHA-256, PE subsystem, machine, whether a signature is present; queued firmware capsules | unsigned EFI binaries **when Secure Boot is enabled**; a `.efi` that is an OS-subsystem PE or not a PE at all; a `system32` directory at the ESP root |
| Firmware variables (`--efivars`) | Secure Boot and setup mode, boot entries and order, dbx / db / shim MOK sizes, SBAT level | setup mode; an empty dbx with Secure Boot on; a dbx missing entries from `--dbx-reference` |
| Firmware inventory (`--sysfs`) | ACPI table names, the WPBT table, PCI option ROMs, the firmware update resource table | the WPBT table (weight 1) |

On Linux the ESP (the FAT mount at `/boot/efi`, `/efi` or `/boot`),
`/sys/firmware/efi/efivars` and `/sys` are found automatically; `--offline`
turns that off. Reading a live disk, and usually the ESP, needs root. Whatever
could not be read is listed under "Not inspected / limits" and is never
reported clean: an unreadable ESP is not an empty one, and an absent
`SecureBoot` variable is "unknown", not "disabled".

Boundaries: a signature is reported present or absent and never verified (the
engine holds no trust store); option ROM contents are not read, because sysfs
only maps a ROM after a write; Secure Boot being off is reported as posture
and not scored; the scan is one point in time. Recognising the MBR boot code
as GRUB, Windows or syslinux only withholds the low-weight "unrecognised"
finding and is never evidence that the code is benign.

| Flag | Default | Meaning |
|---|---|---|
| `--disk <path>` | none | disk image or block device (repeatable) |
| `--esp <dir>` | auto | mounted EFI System Partition |
| `--efivars <dir>` | auto | efivarfs mount |
| `--sysfs <dir>` | auto | sysfs root for the firmware inventory |
| `--offline` | off | scan only what is named |
| `--dbx-reference <file>` | none | revocation list to compare the host dbx against (the UEFI Forum dbx update, bare or in its signed wrapper) |
| `--record <file>` | none | write a baseline of what was scanned (mode 0600; refuses an existing file without `--force`) |
| `--check <file>` | none | compare this scan with a baseline |
| `--sign-key <file>` | none | with `--record`: sign the baseline (hex Ed25519 seed or key) |
| `--pubkey <file>` | none | with `--check`: require the baseline's signature to verify against this hex Ed25519 public key |
| `--force` | off | with `--record`: replace an existing baseline |
| `--format <fmt>` | `text` | `text` or `json` |
| `--threshold N` | 8 | score at which the scan is reported suspicious |

**Baselines: has the boot chain changed?** `--record` saves the comparable
facts of a scan (boot entries and order, Secure Boot state, digests of
PK/KEK/db/dbx/MOK, SBAT levels, every EFI binary's digest, the disk's boot code
and partition table, ACPI table names, option ROMs, firmware versions), and
`--check` compares a later scan with it.

```sh
sudo cau boot-scan --disk /dev/nvme0n1 --record /var/lib/cau/boot.json --sign-key boot-key.hex
sudo cau boot-scan --disk /dev/nvme0n1 --check  /var/lib/cau/boot.json --pubkey boot-pub.hex
```

Each difference has a kind (`added`, `removed`, `changed`, `not-reverified`,
`not-in-baseline`) and a severity. Only **security** differences set exit
code 1:

- a boot entry added, or its target, device path or arguments changed; a
  different entry booting first;
- Secure Boot turned off, setup mode turned on, PK/KEK/db/MOK changed;
- the dbx shrank or was replaced, or an SBAT level fell;
- an EFI binary added or changed (never downgraded because it is signed: the
  signature is not verified);
- the MBR boot code or the partition table changed;
- an ACPI table or an option ROM appeared, or a ROM changed size;
- a firmware version went down.

A dbx that only grew, an SBAT level that only rose and a firmware version that
went up are **expected with updates** and do not fail the check. Removals that
introduce no code are informational. Something the baseline covers that this
run could not read (the ESP without root, a disk not named with `--disk`) is
`not-reverified`, never "removed" and never a failure, and something readable
now that the baseline did not cover is `not-in-baseline`. The output states
what the baseline covers and what it does not.

An unsigned baseline is compared and the output says "UNSIGNED COMPARISON":
whoever can write the file can hide a change. With `--pubkey`, an unsigned
baseline, a bad signature or an unreadable key is a failed run (exit 3), never
a quiet unsigned comparison. Limits: dbx growth is judged by counts and a
digest, not the hash set; `BootNext` is not recorded; disks are matched by the
path given; ROM and WPBT contents are not read, so a same-size replacement is
invisible; and stability across reboots has not been measured (ten checks
within one boot on one host gave no differences).

Exit codes: `0` nothing at or above the threshold and, with `--check`, no
security-relevant difference; `1` suspicious or a security-relevant
difference; `3` nothing could be scanned, or the baseline or a key is
unusable; `4` usage. ATT&CK: T1542.003, T1542.001, T1542.002, T1561.002,
T1486, T1553.006. These are a host surface and are not yet rows in the
`cau coverage` file-scanner matrix.

## cau hwid

```sh
cau hwid                                   # snapshot, text
sudo cau hwid --record /var/lib/cau/hwid.json
sudo cau hwid --check  /var/lib/cau/hwid.json
cau hwid --redact --format json            # shareable: serials, UUID and MACs as digests
```

A read-only snapshot of the host's **hardware identity**, taken from sysfs, and
a comparison with a recorded baseline: is this still the same machine.

| Anchor | Read from | Notes |
|---|---|---|
| DMI / SMBIOS | `/sys/class/dmi/id` | vendor, product, UUID, serials, BIOS. The UUID and serials need root; vendor filler such as `To Be Filled By O.E.M.` is a `placeholder`, never compared as an identity |
| Network interfaces | `/sys/class/net` | address and `addr_assign_type`. Type 3 on a physical NIC means the address was set by userspace. sysfs does not expose the burned-in address, so this shows that the MAC was changed, not from what; virtual interfaces are listed and never flagged |
| TPM | `/sys/class/tpm/tpm0` | presence, version, PCRs 0-7 (SHA-256). No quote is captured: the PCR values are the kernel's unsigned report |
| Entropy source | `/sys/class/misc/hw_random` | the active hardware RNG, or none |

Every field has a state: `ok`, `absent`, `unreadable` or `placeholder`. The
`unverifiable` list names every anchor the host could not prove in this run,
and is never empty (the TPM quote is always on it). Nothing is padded to
"verified".

`--check` reports differences by kind. Only `changed` (a value that was `ok`
in the baseline and is `ok` and different now, or a NIC that went from a
permanent to a userspace-set address) sets exit code 1. `not-reverified` (it
was readable when recorded and is not now, typically because the check ran
without root) is printed and does not change the exit code. A firmware update
legitimately changes the BIOS fields and PCRs, and the output says so.

`--redact` replaces the UUID, serials and MAC addresses with a truncated
SHA-256 so a snapshot can be shared and still compared. It is a pseudonym, not
anonymity: a short serial can be enumerated. A redacted snapshot cannot be
compared with an unredacted baseline.

| Flag | Default | Meaning |
|---|---|---|
| `--sysfs <dir>` | `/sys` | sysfs root |
| `--format <fmt>` | `text` | `text` or `json` |
| `--redact` | off | digest the UUID, serials and MAC addresses |
| `--record <file>` | none | write the snapshot as a baseline (mode 0600; refuses to overwrite without `--force`) |
| `--check <file>` | none | compare with a baseline |

Exit codes: `0` ok, `1` identity changed (`--check` only), `3` the run failed,
`4` usage. The package itself never writes; only `--record` does, in the
command layer. Serials and UUIDs stay on the host unless you move the file.

## cau feed

The abuse-intelligence feed: known-bad IPs, CIDRs, domains, URLs and file hashes
that `cau scan`, `cau installed` and `cau ps` match references against. It is
**hybrid** — a plain offline file that works with no network, refreshed on
demand. `update` is the only subcommand that ever touches the network, and only
with an explicit `--url`.

```
cau feed list                         # how many indicators of each kind are loaded
cau feed check 203.0.113.5 evil.test  # test indicators against the feed (exit 1 on a match)
cau feed update --from local.txt      # merge a local file, no network
cau feed update --url https://…       # opt-in fetch and merge
```

`update` flags: `--from <file>` (merge a local file), `--url <url>` (opt-in
network fetch), `--replace` (replace the cache instead of merging), `--feed
<path>` (cache file to write; default `$CAU_ABUSE_FEED`, then
`./signatures/abuse-feed.txt`, then the system share dirs).

Feed file format (one indicator per line, `#` comments): `value` (auto-classified
by shape), `value|label`, or `type|value|label` where type is
`ip|cidr|domain|url|hash`.

Exit codes: `0` ok, `1` `check` found a match, `3` failed, `4` usage.

## cau hash

Prints the digests the static pass computes: SHA-256, imphash (PE,
pefile-compatible) or the ELF import-set hash (MD5 over the sorted undefined
symbol names, labeled as such; not telfhash), TLSH and ssdeep.

```sh
cau hash plink.exe
cau hash --format json a.exe b.dll
```

| Flag | Meaning |
|---|---|
| `--format text\|json` | output format |

## cau cluster

Groups PE and ELF files by import-table similarity: exact import-hash groups
first (imphash for PE, the import-set hash for ELF), then MinHash / LSH
clusters over the import sets with a Jaccard floor. Files of other formats
are counted and skipped.

```sh
cau cluster ./samples
cau cluster --min-similarity 0.8 --imphashes a.exe b.exe c.exe
```

| Flag | Default | Meaning |
|---|---|---|
| `--min-similarity X` | 0.6 | Jaccard floor for near clusters (0 < x ≤ 1) |
| `--imphashes` | off | also list every file's import hash |
| `--format text\|json` | text | output format |

## cau add-hash

Appends a validated signature to the hash database. The type is inferred
from the digest length when `--type` is omitted. Duplicates and conflicting
re-labels are refused instead of silently overwriting.

```sh
cau add-hash --hash <sha256> --name "WannaCry Ransomware"
cau add-hash --type md5 --hash 84c82835a5d21bbcf75a61706d8ab549 --name "WannaCry Ransomware"
```

| Flag | Meaning |
|---|---|
| `--hash HEX` | the digest |
| `--type MD5\|SHA1\|SHA256` | digest type (default: from the length) |
| `--name TEXT` | threat name; no `\|` or line breaks |
| `--db PATH` | database (default: auto-discovered) |

## cau add-fuzzy

Appends TLSH, ssdeep or imphash entries to the fuzzy database, either
computed from a file or given explicitly.

```sh
cau add-fuzzy --file sample.bin --name "Example Family"      # every digest the file yields
cau add-fuzzy --type tlsh --hash T1... --name "Example Family"
```

| Flag | Meaning |
|---|---|
| `--file PATH` | compute TLSH, ssdeep and imphash of this file and add each |
| `--type TLSH\|SSDEEP\|IMPHASH` | digest type for `--hash` |
| `--hash DIGEST` | digest to add |
| `--name TEXT` | threat name |
| `--db PATH` | fuzzy database (default: auto-discovered `signatures/fuzzy.txt`) |

## cau eval

The evaluation harness. See [Evaluation](evaluation.md) for the concepts;
this is the flag reference.

```
cau eval validate  check a corpus manifest: paths, labels, hashes, provenance
cau eval run       scan a corpus and write a measured report (optionally gate it)
cau eval report    render a saved report as text or JSON
cau eval diff      compare two reports
cau eval gate      fail (exit 1) when a candidate report regresses against a baseline
cau eval temporal  score the content across a time boundary in the corpus: the recall
                   drop across the boundary fails the gate
cau eval policy    print the default regression policy as JSON
```

Exit codes: 0 ok, 1 validation errors or gate failed, 3 the run failed, 4
usage error.

### cau eval validate

| Flag | Meaning |
|---|---|
| `--corpus PATH` | corpus manifest (required) |
| `--verify-hashes` | recompute SHA-256 of samples that declare one |
| `--require-provenance` | malware samples without a provenance source are errors, not warnings |
| `--max-file-size N` | warn about samples larger than N bytes |
| `--json` | print the validation result as JSON |

### cau eval run

| Flag | Default | Meaning |
|---|---|---|
| `--corpus PATH` | | corpus manifest (required) |
| `--db PATH` | `<manifest dir>/hashes.txt`, else auto-discovered | signature database |
| `--rules PATH` | auto-discovered | YARA rules |
| `--fuzzy-db PATH` | `<manifest dir>/fuzzy.txt`, else auto-discovered, else none | fuzzy database |
| `--no-hash`, `--no-yara`, `--no-heuristics`, `--no-static`, `--no-encchain`, `--no-stego`, `--no-fusion` | | disable a detector |
| `--heuristic-threshold`, `--static-threshold`, `--stego-threshold` | 7, 8, 4 | thresholds |
| `--jobs N` | CPUs | samples scanned concurrently |
| `--on-error exclude\|miss\|fail` | exclude | unscannable samples: leave out, count as false negatives, or abort |
| `--max-file-size N` | | skip samples larger than N bytes |
| `--out PATH` | | write the JSON report (this is what a baseline is) |
| `--format text\|json` | text | stdout rendering |
| `--baseline PATH` | | also gate the run against this report |
| `--policy PATH` | built-in | regression policy for `--baseline` |
| `--verify-hashes` | true | validate the corpus with hash verification before running |
| `--quiet` | | no progress |

The `fusion` detector in an eval run reports only verdicts reached by
corroboration, so its per-detector row is the lattice's own contribution.

### cau eval report, diff, gate

```sh
cau eval report --report report.json [--format json]
cau eval diff   --baseline a.json --candidate b.json [--format json]     # or: cau eval diff a.json b.json
cau eval gate   --candidate b.json [--baseline a.json] [--policy p.json] [--format json]
```

`gate` without `--baseline` applies only the policy's absolute rules.

### cau eval temporal

| Flag | Default | Meaning |
|---|---|---|
| `--corpus PATH` | | corpus manifest (required) |
| `--split PERIOD` | the median period | the period that opens the later half |
| `--policy PATH` | built-in | the policy whose `max_recall_drop` applies |
| `--max-drop POINTS` | the policy's | the recall drop across the boundary that fails the gate |
| `--db PATH`, `--rules PATH`, `--fuzzy-db PATH` | | as in `cau eval run` |
| `--format text\|json` | text | stdout rendering |
| `--out PATH` | | write the JSON measurement here |
| `--quiet` | | no progress |

The corpus is cut at the period boundary and both sides are scored by the same
scan. The gate fails when the content loses more recall across the boundary
than the policy allows. See [Evaluation](evaluation.md#the-temporal-gate).

## cau rules

```sh
cau rules lint [--rules path] [--profile cau|generic] [--format text|json] [--strict]
cau rules list [--rules path] [--format text|json]
```

`lint` compiles the rules and reports, per rule and line: compile errors and
compiler warnings, missing `description` / `author` / `threat_level` (1-5) /
`family` / `mitre_attack` meta, malformed technique ids, text strings that
are hex written as text (`"0x89,0x00"` never matches bytes), strings under
four bytes, text strings without `wide`, and conditions that match every
file. Errors exit 1; `--strict` makes warnings fatal. The `generic` profile
drops the bundled-content conventions (`family`, `wide`, naming) for
third-party rule sets such as signature-base. `list` prints every compiled
rule with namespace, level, family, technique and description.

## cau coverage

```sh
cau coverage [--rules path] [--no-yara] [--db path] [--fuzzy-db path]
             [--format text|json|navigator|sarif] [--pretty] [--output file]
             [--expect file] [--record] [--include-info]
```

Builds the ATT&CK coverage matrix of the shipped content: for every
technique id, the detectors and content entries that are evidence for it;
content with no technique is listed as unmapped. `--format navigator` writes
an ATT&CK Navigator layer (score = number of independent detectors);
`--format sarif` writes a SARIF 2.1.0 log with one rule and result per
technique, so a code-scanning dashboard shows the coverage map and treats a
planned gap as a warning. `--expect` compares the matrix to a committed
expectation file (`baselines/attack-coverage.txt`, one row per technique:
`<id> covered|partial|gap|none [note]`) and exits 1 on any difference;
`--record` rewrites that file from the content, keeping its partial, gap and
none rows. The four states render as detected, partial (covered but
acknowledged incomplete), planned (an expectation `gap`) and none (owned by
the sensor or console). Exit codes: 0 ok, 1 expectation differs, 3 failed, 4
usage.

`--frameworks` (text format only) appends the **Unified Kill Chain** sequencing
view: each covered technique is mapped through its ATT&CK tactic onto the
18-phase UKC (Paul Pols / Fox-IT), grouped by stage, with the empty phases named
as honest gaps — the counterfactual to ATT&CK's technique grid, showing which
parts of an intrusion's progression a file scanner can observe.

## cau honesty

```sh
cau honesty                                   # text, from the working tree
cau honesty --format json --no-timestamp --output honesty.json
cau honesty --eval eval-out/report.json --strict
```

One document that says what the engine covers, what was measured and whether
its detection content is intact, built from three things the engine already
computes. It is meant to be run by someone other than the vendor.

| Section | Source | States |
|---|---|---|
| ATT&CK coverage | the same matrix as `cau coverage`, compared with `baselines/attack-coverage.txt` | `measured`, `mismatch`, `error` |
| Evaluation | a report written by `cau eval run --out` (`--eval`, default `baselines/smoke.json`) | `measured`, `not-measured`, `error` |
| Selftest | the signed integrity baseline `cau selftest` checks | `measured`, `no-baseline`, `tampered`, `error` |

There is no overall score or grade: a gap in one section is not offset by a
result in another. Anything unknown is `null`, never zero. A missing integrity
baseline is `no-baseline`, which is not a pass. The evaluation section carries
a corpus class; the committed smoke corpus is labelled synthetic, and its
recall is described as a plumbing check and not a detection rate. A report
whose totals do not follow from its own sample records is an `error`. The
`not_claimed` list states what the index does not measure (no third-party
columns, no real-malware recall unless a real corpus report is supplied, no
runtime coverage, no signature on the index itself).

| Flag | Default | Meaning |
|---|---|---|
| `--format <fmt>` | `text` | `text`, `markdown` or `json` |
| `--output <file>` | stdout | write the document to a file |
| `--eval <file>` | `baselines/smoke.json` if present | evaluation report to read |
| `--expect <file>` | the committed baseline if present | coverage expectation to compare with |
| `--manifest <file>`, `--pubkey <file>` | auto | selftest baseline and its public key |
| `--db`, `--rules`, `--fuzzy-db` | auto | detection content to describe |
| `--no-timestamp` | off | omit `generated`, for byte-identical output (`SOURCE_DATE_EPOCH` is also honoured) |
| `--strict` | off | exit 1 when a section is `mismatch`, `tampered` or `error` |

Exit codes: `0` the document was produced, whatever it says; `1` only with
`--strict`; `3` it could not be written; `4` usage.

## cau quarantine

```sh
cau quarantine add     <path> [--store dir] [--threat name] [--keep]
cau quarantine list    [--store dir] [--format text|json]
cau quarantine restore <id>   [--store dir] [--to path] [--force]
cau quarantine verify  [id]   [--store dir]
cau quarantine delete  <id>   [--store dir]
```

A local, directory-backed vault for files a scan flagged, so the OSS engine
has somewhere to put found files short of deleting them. Every entry is
XOR-masked at rest: the vault never holds a runnable PE/ELF on disk, and a
scanner pointed at the vault (including `cau` itself) does not re-flag it. Each
entry is sealed with the SHA-256 of both the original and the masked bytes, so
`restore` and `verify` fail *closed* (`exit 1`) if the vault was corrupted or
tampered with, rather than writing wrong bytes back onto the live path. `add`
moves the file by default (`--keep` copies it); `restore` writes to the
recorded original path, or to `--to`, refusing to clobber an existing file
unless `--force`. The store defaults to `$CAU_QUARANTINE_DIR`, else
`$XDG_DATA_HOME/cau/quarantine`, else `~/.local/share/cau/quarantine`.

The mask is reversible obfuscation for safety, not encryption for secrecy —
the key is stored with the entry. Exit codes: 0 ok, 1 integrity failure, 3
failed, 4 usage.

## cau canary

```sh
cau canary plant --dir dir --manifest path [--count n]
cau canary check --manifest path [--format text|json]
```

Plants decoy files with plausible lure names (credentials, finance, keys) and
records a baseline manifest; `check` diffs the files against the baseline and
classifies each as intact, modified, deleted, or meta-changed. A decoy nobody
advertised has no legitimate reason to be opened, so a tripped canary is
high-signal, near-zero-false-positive ground truth — a rewrite (the ransomware
signal) is reported distinctly from a mere permission change. `check` is a
point-in-time comparison a cron job or task hook runs, not a live watch (that
is the sensor's job). Exit codes: 0 all intact, 1 at least one tripped, 3
failed, 4 usage.

## cau peel

```sh
cau peel [--format text|json] [--jobs n] [--stream] [--max-depth n]
         [--max-nodes n] [--max-output n] [--max-children n] [--timeout dur]
         <file>...
```

Walks the obfuscation-chain tree of each file (NOVEL-012). At each node every
reversible layer that applies decodes at once, and each result opens a branch,
under a single global per-sample budget wall shared across every branch (nodes,
decoded bytes, depth, frontier width, wall clock). Because the budget is global,
adding layers costs latency, never more total spend. The peeler only *decodes*;
it never executes sample content.

| Layers | |
|---|---|
| Bases | 2, 8, 10 and 16 (bare, or as lists: `72 101`, `0x48,0x65`, `\x48\x65`, `%48%65`); 32 (RFC 4648, lower case, hex, Crockford, z-base-32); 36; 45; 58 (Bitcoin, Flickr, Ripple); 62; 64 (standard and URL-safe, with or without wrapping); 85 (RFC 1924, Ascii85, Z85); 91; 92 |
| Substitutions | every Caesar shift (rot1 to rot25), rot5, rot18, rot47, atbash, reversal |
| Other | gzip, zlib, raw deflate, bzip2, UTF-16, blobs carved out of a surrounding script |

Layers chain in any order, and one blob can open several branches: a script with
three embedded payloads is three chains. A chain is named by its layers, such as
`carve>base64>rot13>flate`, and a Caesar layer by its shift, such as `caesar-7`.
A wrong guess at a base gives noise and is dropped. A substitution has to reveal
something, because rotating text only gives more text; rotations are tried on
the first 4 KiB, and a whole-number base (36, 58, 62) reads at most 64 KiB.

`--jobs` peels that many files at once, one per CPU by default, and reports them
in command-line order. `--stream` prints each layer and chain as it is found; with
`--format json` that output is JSON lines, ending in a `"kind":"result"` object
per file. Several files with `--format json` and no `--stream` give an array. A
file that cannot be read is reported and the others still run.

Chain *depth* is the signal: a revealed executable or script is a finding at
depth >= 2 (a real chain), because a single ordinary layer — a `.gz` of a
binary, one base64 blob — is normal packaging and is the single-layer
encoded-executable detector's job. A substitution counts at any depth, because
no packaging tool writes one, and a carve does not count as a layer, because it
decodes nothing. A branch that hits a wall is reported as
`peel-exhausted`, a first-class scored outcome, never a silent clean. Each peel
renders a stable chain signature such as `base64>gzip>base64`.

Zip archives are opened through the peeler's own bounded reader (stored and
deflate members; encrypted ones are skipped and counted; nothing is written to
disk; member names are never evidence). A zip that *is* the sample, or sits
under compression only, is packaging and its members score as they would on
disk; a zip under an encoding or a substitution counts as a layer
(`base64>zip>ELF` is depth 2). A plain archive that outruns a wall is
`peel-exhausted` with no score floor, so a large documentation archive does not
become suspicious for being large. xz is recognised and reported as opaque, not
opened. A chain four or more layers deep is the `deep-chain` outcome
(`peel.deep-chain`), scored by depth beside whatever the leaf is; on 131,253
benign local files no chain reached depth 3. Exit codes: 0 clean, 1 a chain
revealed a payload, was four or more layers deep, or the peel was exhausted, 3
failed, 4 usage.

## cau evasion

```sh
cau evasion report --file <path> [--rules <dir>] [--db <path>] [--format text|json]
cau evasion bench --corpus <manifest> [--rules <dir>] [--db <path>]
                   [--format text|json] [--limit n]
```

Measures how fragile the shipped detections are. For every detector that fired
it answers one question: how many bytes have to change for that detector to
stop firing on this file? The number comes from the detection's own evidence —
the matched hash, the rule's condition, the invisible codepoints — and never
from a guess. A detector whose distance cannot be derived (a finding that keys
on a structure rather than on bytes) is reported as *not derivable*, with the
reason, instead of being given a number nobody checked.

What the report deliberately does not do is produce a patched file. It describes
the change ("breaking the rule needs at least two bytes changed") and never
the bytes to write: no offsets, no matched values, no mutated sample. This is
a measurement of how much work the detection content still needs, in the same
spirit as the recall and false-positive numbers the evaluation harness
publishes — not a kit for making a sample quiet.

The bounds are bounds. One edit can break several detectors at once — a byte
inside a string two rules share — so the bytes that must change for the whole
verdict to move are given as a range: the largest single detector's distance is
the lower bound, and the sum of the distances is the upper bound.

`report` measures one file. `bench` measures a corpus — the same manifest
format `cau eval` reads, so the numbers come from the corpus the recall
figures are published from — and reports, per detector, how often it fired and
how many of its firings were a single byte from silence. The corpus is the
operator's: the bench ships no attacks and generates none.

```
$ cau evasion bench --corpus corpus/smoke/manifest.json --db corpus/smoke/hashes.txt
evasion bench: corpus/smoke/manifest.json
  samples  : 18 (8 with a detection)
  detector                          fired  one-byte  min distance
  encchain encchain.elf                1         1  1 byte(s)
  hash Smoke_Hash Synthetic Sample     1         1  1 byte(s)
  yara generic_ransomware_extensi…     1         1  1 byte(s)
  static segment.rwx                   1         0  n/a
  yara wannacry_ransomware             1         0  2 byte(s)
  stego stego.codepoints               1         0  48 byte(s)
```

Exit codes: 0 the measurement was taken, 3 the measurement failed, 4 usage.

## cau model

```sh
cau model list
cau model verify --sig models/registry.sig --pubkey pub.hex
cau model promote --model embedder@1.2.0
cau model rollback
cau model card --model embedder@1.2.0
```

The registry of the model artifacts the engine may run. A model is a file an
attacker would love to replace — a classifier that says "clean" is worse than
no classifier at all — so the registry is signed with the same trust anchor as
the release manifest and the update bundle, over its own canonical bytes and in
its own signature domain. Every artifact is named by its digest, and every
artifact carries an SBOM and a model card; both are checked against their
digests, and a model without either is refused at parse time.

The registry records which version is in force. `promote` makes a version
active and remembers the one it replaced; `rollback` returns to it. Both
rewrite the document, so a promotion is an act that has to be signed again —
`cau model promote` says so.

The registry does not run anything: inference belongs to a sidecar process.
What it answers is "which artifact may run, is it the one that was signed, and
how do I go back to the previous one".

`cau model score` is the engine's half of the sidecar conversation: the bytes
go to the sidecar, which holds the runtime and the artifacts, and the scores
come back. The engine never loads a model into its own process — a runtime
linked into the core would put a model inside the process that reads hostile
files — and the source gate `TestNoInferenceInTheEngine` keeps it that way.

```sh
cau model score --model embedder@1.2.0 --file sample.bin \
    --sidecar /run/cau-model.sock [--fail-at 0.8]
```

The protocol is a length-prefixed JSON frame over a unix socket: one request
(`{"model": "name@version", "bytes": "<base64>"}`) and one response (the
scores, the labels, the sidecar's version, or the reason the model did not
run). A model that is not in the registry is not asked for, and a sidecar that
says "the model did not run" is an error, never a clean result.

| Flag | Default | Meaning |
|---|---|---|
| `--registry PATH` | `models/registry.json` | the registry document |
| `--sig PATH` | | the detached signature over the registry |
| `--pubkey FILE` | `$CAU_MODEL_PUBKEY` | the trusted public key (hex) |
| `--model ID` | | the artifact to act on, as `name@version` |
| `--format text\|json` | text | stdout rendering |
| `--out PATH` | the registry | write the result here instead of stdout |

Exit codes: 0 ok, 1 the verification failed, 3 the operation failed, 4 usage.

## cau intake

```sh
cau intake --format stix|misp|malwarebazaar|loldrivers
           (--input <file> | --url <url>) [--db <path>] [--dry-run] [--output <file>]
cau intake --taxii <collection-url> [--taxii-state <file> | --added-after <ts>]
           [--auth-env <VAR>] [--provenance <file>] [--db <path>] [--dry-run]
```

Parses a threat-intelligence feed into hash signatures and appends the new ones
to the signature database, so the database is fed from machine-readable sources
instead of being hand-typed. Supported feeds: STIX 2.1 bundles (indicator SDOs
with a `file:hashes` pattern), MISP event JSON (md5/sha1/sha256 attributes,
including `filename|hash` composites), MalwareBazaar query/dump JSON, and the
LOLDrivers catalog (known-malicious driver hashes). Each hash is validated and
normalized; a hash already in the database is skipped (intake never re-labels an
existing entry). Read the feed from `--input` (`-` for stdin) or fetch it with an
explicit `--url` (bounded, never automatic — the engine does not phone home on
its own). `--dry-run` prints the new signatures, `--output` writes them to a file
instead of appending to the database. Exit codes: 0 ok (even when nothing is
new), 3 failed, 4 usage.

`--taxii` polls a **TAXII 2.1 collection** (`…/collections/<id>/`) for STIX
objects, following the server's pagination, and feeds them to the STIX parser.
`--taxii-state <file>` keeps the polling cursor (the server's
`X-TAXII-Date-Added-Last`), so each run asks only for what was added since the
last run that wrote; `--added-after` sets the cursor by hand. The
`Authorization` header value comes from the environment variable named by
`--auth-env` (default `CAU_INTAKE_AUTH`). The collection must be `https://`
unless `--allow-http` is given, a redirect to another host is refused, and the
poll is bounded in pages, objects and bytes. A dry run neither advances the
cursor nor writes provenance.

What is not ingested: a STIX indicator its producer marked `revoked` or whose
`valid_until` has passed; a STIX indicator whose `indicator_types` say `benign`
or do not include `malicious-activity` or `compromised` (an untyped indicator
is taken); and a MISP attribute exported with `to_ids: false` (context, not a
detection). MISP galaxy-cluster tags on an event, an attribute or in a STIX
indicator's labels are recorded in the provenance line as `misp_clusters`, and
a `misp-galaxy:malpedia` cluster as `malpedia_family`. `--provenance <file>` appends one JSON line per
new signature with its `source`, `origin`, `retrieved_at` and `confidence`.
Confidence is what the source states (STIX `confidence` on the None / Low /
Med / High scale) and `unstated` otherwise; the engine does not invent one.
The weekly `intake` workflow runs this against the public feeds, gates the
candidates on the evaluation corpus and publishes them as an artifact. It
never commits: promotion is a pull request.

## cau update

```sh
cau update (--from <dir> | --url <base>) [--pubkey <file>] [--db <path>] [--dry-run]
           [--allow-downgrade]
```

Installs a signed signature-database bundle, fail-closed. The engine never
fetches on its own — this is always an explicit command. A bundle is three
files: `hashes.txt` (the payload), `manifest.json` (`{schema, db_version,
min_engine_version, sha256, created}`), and `manifest.json.sig` (a detached
Ed25519 signature over the manifest). One signature covers everything because
the manifest carries the payload's SHA-256.

Nothing on disk changes unless the signature verifies against the trusted key,
the payload digest matches the signed manifest, the bundle's
`min_engine_version` is satisfied, and the bundle is not older than the one
installed. On success the live database is replaced atomically, the previous
one is kept as `<db>.bak`, and the manifest is recorded as `<db>.manifest`.
That record is what stops a mirror replaying an old signed bundle; the first
install has nothing to compare against, and `--allow-downgrade` installs an
older bundle on purpose, to back out a bad release. `--from` reads a local
directory (also the air-gap path — the identical payload delivered by media);
`--url` fetches `<base>/hashes.txt`, `<base>/manifest.json` and
`<base>/manifest.json.sig`. `--dry-run` verifies only. The trusted Ed25519
public key (hex) comes from `--pubkey`, else `$CAU_UPDATE_PUBKEY`, else the
key pinned in the build; with none configured, update refuses to install
anything. Exit codes: 0 ok, 1 verification failed, 3 failed, 4 usage.

## cau selftest

```sh
cau selftest --record [--sign-key priv.hex] [--manifest file]
cau selftest [--pubkey pub.hex] [--manifest file]
```

Verifies that nothing the agent relies on has been tampered with — the signature
database, the YARA rules, the fuzzy database, the threat feed, `/etc/cau/cau.conf`
and the agent binary — so an attacker who guts signatures or neuters a rule
(ATT&CK T1562.001, Impair Defenses) is caught instead of silently disabling the
scanner. Detection content is the obvious target but not the cheapest one:
emptying the feed, or repointing the SIEM address at a collector of their own,
needs no change to a single rule, which is why both are baselined and why the
SIEM address is pinned into the manifest. `--record` digests each resource and
writes a baseline (`integrity.json` next to the signature database by default);
without `--record` it recomputes and compares, exiting 1 and naming each drifted
resource on any change. Directory resources (the rules) reduce to one canonical
digest, so adding, removing, editing or renaming any rule file is detected.

For tamper-*resistance* (not just drift detection), record a **signed** baseline
with `--sign-key` and verify it with `--pubkey` (or `$CAU_SELFTEST_PUBKEY`):
an attacker who rewrites both the content and the manifest still cannot forge
the Ed25519 signature, so the check fails closed. Keep the signing key off the
host; run `cau selftest --pubkey …` from a timer or before each scan. A `--pubkey`
that cannot be read or parsed is an **error**, never a quiet fall back to a
digest-only check — that downgrade is exactly what deleting the key would be
worth doing for, and it would leave every later log line looking healthy. Exit
codes: 0 intact, 1 drift or a bad/missing required signature, 3 failed, 4 usage.

`--sign-key` and `--pubkey` also accept a pipe, so a key can stay off the disk:
`--sign-key <(pass show cau/key)`. A pipe has the same 64 KiB limit as a file, and
a FIFO with no writer is an error. A private key gets two minutes to arrive, since
the command behind the pipe may stop to ask for a passphrase. A public key gets
five seconds, because `cau defend` reads one at startup with nobody watching.
Devices are refused.

## cau verify-self

```sh
cau verify-self (--from <dir> | --url <base>) [--pubkey file] [--name name]
```

Verifies the running binary against a signed release manifest — the secure way
to answer "is this the authoritative, unmodified build". It computes its own
SHA-256, fetches the release's `SHA256SUMS` and `SHA256SUMS.sig` (`--url` over
HTTPS, or `--from` a local/air-gapped copy), verifies the Ed25519 signature
against the trusted key (`--pubkey`, else `$CAU_UPDATE_PUBKEY`, else the pinned
key), and only then compares its own digest to the signed entry. A MITM of the
download cannot forge the signature, so a tampered binary or manifest fails
closed. `--name` overrides the filename looked up in `SHA256SUMS` (default: the
running executable's own name). Exit 0 verified, 1 failed, 3 run error, 4 usage.

## cau bundle

```sh
cau bundle update    --db hashes.txt --sign-key priv.hex --out dist [--db-version V] [--min-engine V]
cau bundle checksums --sign-key priv.hex --out dist <file>...
cau bundle keygen    --out <dir> [--hybrid] [--ed25519-key <file>]
cau bundle sbom      [--binary <path>] [--output <file>]
```

Producer-side signing, run in CI with the signing key from a secret.
`update` writes the signed signature-DB bundle (`hashes.txt` + `manifest.json` +
`manifest.json.sig`) that `cau update` installs. `checksums` writes a signed
`SHA256SUMS` (+ `.sig`) over the release files that `cau verify-self` and users
check downloads against. Both use Ed25519; keep the key off developer machines.

**Hybrid post-quantum signatures.** `--sign-key` takes either an Ed25519 key
(hex, as before) or a hybrid key, and the kind of key decides the signature
written. `keygen --hybrid` makes an Ed25519 + ML-DSA-65 pair (FIPS 204, from
the Go standard library) as `cau-release.key` (mode 0600) and
`cau-release.pub`, refusing to overwrite; `--ed25519-key` keeps an existing
Ed25519 half so hosts that pin it keep verifying. A verifier holding a hybrid
public key requires **both** signatures to be valid over the same bytes and
refuses an artifact signed with Ed25519 alone, so the post-quantum half cannot
be stripped. A verifier holding only the Ed25519 key still verifies a
hybrid-signed release on that half and warns that the ML-DSA-65 signature was
not checked. `cau update` and `cau verify-self` print which signatures were
checked, and a key that is named and cannot be read or parsed is an error
(exit 3), never "no key". Sizes: public key file 4,015 bytes, signature file
6,792 bytes. The hybrid file format (`cau-hybrid-v1`) is this project's own,
not the IETF composite encoding. Limits: hybrid keys need a binary built with
Go 1.27 or later (an older build refuses them), and `go.mod` and CI are still
on Go 1.24, so released binaries are Ed25519-only until that changes; the
`cau selftest` baseline signature is Ed25519-only; the code is new and has had
no outside review.

`sbom` writes a CycloneDX 1.5 software bill of materials for a Go binary (this
one by default), read from the build information the linker embedded in it: the
modules that were actually linked, each with its go.sum hash. The document has
no timestamp and no serial number, so the same binary always yields the same
bytes. Libraries linked through cgo (libyara, the C library) are not Go modules;
the document says so in a property rather than omitting them silently.

## CI recipes

GitHub Actions, uploading findings to code scanning:

```yaml
- run: ./cau scan --dir . --format sarif --output cau.sarif --fail-on none --quiet
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cau.sarif
```

Fail a build on anything suspicious, but tolerate unreadable files:

```sh
cau scan --dir ./dist --fail-on heuristic --no-fail-on-scan-error --quiet --format json --output report.json
```

Gate detection changes against the committed baseline (what this repository's
CI does):

```sh
make eval      # validate -> run -> gate
```

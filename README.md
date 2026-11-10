# CAU EDR == Certs Are Useless

[![ci](https://github.com/s-b-repo/cau/actions/workflows/ci.yml/badge.svg)](https://github.com/s-b-repo/cau/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A transparent, open-source malware detection engine in Go. Fifteen detectors read
every file once, every finding is explained with a labeled class and an
ATT&CK technique, every report is machine-readable with CI exit codes, and an
evaluation harness gates every detection change against a measured baseline.

```sh
cau scan --dir ./downloads
cau ps                                                              # scan the live process table (fileless, masquerade, injection, network shells)
sudo cau ps --respond stop                                          # freeze confirmed processes, memory intact for forensics
sudo cau persist                                                    # audit cron, systemd, keys, accounts, PAM, preload and SUID footholds
sudo cau net                                                        # the network plane: every socket attributed to its process and file, resolver and neighbour state
sudo cau net --respond block --block-ttl 30m                        # drop a confirmed peer in cau's own nftables table; the block expires on its own
sudo cau defend                                                     # every layer at once, defending by default: process, file, network, persistence, kernel, canary, package
sudo cau defend --report-only                                       # the same, changing nothing: watch here first on a host you do not know
sudo cau defend --siem 10.0.0.5                                     # free: stream every incident to a SIEM as OCSF, start it once and leave it
sudo cau selftest --record --sign-key priv.hex                      # sign what the agent reads: content, feed, config, binary, and pin the SIEM address
cau firmware ./bios.rom --implants known.txt                        # UEFI firmware: module inventory, FV integrity, implant blocklist
cau scan ./dist --format sarif --output cau.sarif --fail-on none    # code scanning
cau scan ./build --format json --fail-on heuristic                   # fail CI on suspicion
cau scan ./dist --format ocsf --output findings.json                 # OCSF for a security lake
cau scan ./dist --wazuh-url https://wazuh.example.com:55000 \
                --wazuh-user cau-agent --wazuh-password-env WAZUH_PASSWORD # free: post findings to Wazuh
cau coverage --format navigator --output layer.json                  # ATT&CK Navigator heat map
cau rules lint --rules ./signature-base --profile generic            # lint a third-party rule set
cau quarantine add ./suspicious.exe --threat Win.Trojan.Agent        # integrity-sealed vault
cau canary plant --dir /srv/share/.decoys --manifest canary.json     # decoys as cheap ground truth
cau peel ./dropper.b64                                               # walk an obfuscation chain, depth as signal
cau peel --stream --jobs 8 ./samples/*                               # many files at once, each layer as it is found
sudo cau boot-scan                                                   # the boot chain, read-only: ESP, Secure Boot, firmware tables
sudo cau hwid --record /var/lib/cau/hwid.json                        # baseline the hardware identity; --check compares
cau honesty                                                          # what is covered, what was measured, what is intact
cau bundle sbom --output cau.cdx.json                                # CycloneDX bill of materials for this binary
```

## What it does

| Detector | Question it answers | Result |
|---|---|---|
| **Hash signatures** | is this exact content known? | MALICIOUS with the threat name |
| **YARA** (in-process libyara, per-file timeout) | does it contain patterns a rule describes? | MALICIOUS with rule, namespace, meta and matched strings at their offsets |
| **Heuristics** | does it name suspicious capabilities? | SUSPICIOUS with a capped score, the categories responsible and their ATT&CK techniques |
| **Static structure** (own PE, ELF and Mach-O parsers, entropy, TLSH / ssdeep / imphash / telfhash) | is it *built* like something that hides? | SUSPICIOUS with labeled anomaly classes: packer, RWX sections or segments, forged build record, implausible signer, appended payload, stripped section table, non-system program interpreter, writable `RPATH`, libc interposer, unsigned kernel module, constructor outside code, encrypted Mach-O, similarity to a known sample |
| **Invisible codepoints** | does this text or code carry hidden codepoints? | SUSPICIOUS with every zero-width, bidi-override, TAG or variation-selector codepoint, its line, and the context rules that excused the rest |
| **Encoded executable** (base64/hex, multi-layer) | is an executable hidden behind text encoding? | SUSPICIOUS with the decoded PE/ELF, the encoding and the layer depth |
| **Obfuscation-chain peeler** (parallel tree unwrap through every common base, rot and Caesar, budget-walled) | is a payload stacked behind *several* encoding/compression layers? | SUSPICIOUS at chain depth ≥ 2 with the ordered chain signature (e.g. `base64>gzip>base64`); `peel-exhausted` when the budget wall is hit |
| **Shell Link (.lnk)** ([MS-SHLLINK] parser) | is this Windows shortcut a weaponised launcher? | SUSPICIOUS with interpreter arguments, encoded/hidden-window flags, env-var path obfuscation, executable target and icon lure |
| **OLE macro** ([MS-CFB] + [MS-OVBA]) | does this Office document carry a malicious VBA macro? | SUSPICIOUS with auto-exec entry points, shell/interpreter and download calls, obfuscation and embedded-object lures |
| **PDF document** (bounded lexical scan) | does this PDF auto-run code or carry a payload? | SUSPICIOUS with auto-run actions, embedded JavaScript, Launch, embedded files and JS exploit primitives |
| **ISO container** (ISO 9660 + Joliet) | is this disk image a mark-of-the-web-bypass lure? | SUSPICIOUS on the `.lnk`-plus-payload smuggling shape, hidden payloads and `autorun.inf` |
| **Linux software package** (.deb/.rpm/Arch/Flatpak/AppImage/Docker/Snap) | does an install-time script run root-level tradecraft? | SUSPICIOUS with the maintainer/scriptlet behaviours scored: curl-into-shell, reverse shell, dropper, persistence, sandbox escape |
| **Archive** (ZIP/TAR/gzip, recursive) | is this container a bomb, a Zip-Slip, or a lure wrapping a payload? | SUSPICIOUS with decompression-bomb caps, path-traversal members, double-extension lures and executable payloads |
| **CHM help file** (ITSS directory) | does this help file smuggle an executable, shortcut or script? | SUSPICIOUS with embedded PE/LNK/HTA/VBS/PS1 payloads a help file has no reason to carry |
| **Tradecraft** (behaviour in scripts and payload bytes, through decoded carriers) | what does this file *do*, when it names no family and has no odd structure? | SUSPICIOUS with the behaviour: web shells, network shells, in-memory loaders, living-off-the-land abuse ([LOLBAS](https://lolbas-project.github.io) and [GTFOBins](https://gtfobins.github.io) breakouts, `sudo` and setuid privilege escalation), trusted-SaaS command channels (the full [lolol.farm](https://lolol.farm) catalogue — [LOLC2](https://lolc2.github.io), [LOLFSaaS](https://lolfsaas.github.io), [LOTTunnels](https://lottunnels.github.io), [LOTWebhooks](https://lotwebhooks.github.io)), EDR-bypass primitives ([ArcticFox detection-bypass catalogue](https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md): anonymous in-memory exec via `memfd_create` + `execveat`, kernel process-name camouflage via `prctl(PR_SET_NAME)`, `LD_PRELOAD`/`RTLD_NEXT` shims, PAM-stack backdoors, systemd unit hijacks, `/proc/self/exe` self-delete, GitHub README dead-drops, ICMP and DNS-TXT covert channels, open-redirect heartbeats with zero-width codepoints, TLS domain fronting), shellcode in the clear or in a byte array or encoded blob |
| **Fusion** | do several detectors agree, even below their own thresholds? | one fused verdict naming the sources that agreed, their roles and techniques, plus attack-path chaining |

## The runtime planes

The detectors above read files. Three more layers read the host as it runs, and
`cau defend` joins all of them into one incident:

| Plane | Command | Question it answers |
|---|---|---|
| **Process** | `cau ps` | is anything running that a benign system would not run? Fileless execution, masquerades, injection hooks, network shells and pipe relays, set-uid shells |
| **Network** | `cau net` | what is this host talking to, and who on this host is doing the talking? Every socket the kernel holds — per network namespace, so containers are covered — attributed to its process and executable: fileless egress and bind shells, known-bad peers, handler ports, DNS-plane escape, connect sweeps, beaconing cadence, and neighbour-table tampering. See [docs/network.md](docs/network.md) |
| **Persistence** | `cau persist` | what will run again after a reboot or a login? |

Response is tiered the same way everywhere: `--respond stop` freezes a confirmed
process with its memory intact, `--quarantine` seals a confirmed file in the
vault, `--block-exe` asks the kernel guard to refuse it, and `--netblock` drops
its peers — in cau's own firewall table, with an expiry the kernel holds, and
never an address the host itself needs.

**What gates it is the evidence, not a flag.** Under `cau defend` these are on
by default, each degrading to a warning where the host cannot carry it out (no
kernel guard, no firewall); `--report-only` turns the whole surface off to watch
first, and `cau ps` and `cau net` on their own stay read-only until asked.
Nothing acts on a single layer's opinion: only live state, a known-bad
identification or two independent layers agreeing license a machine to act, and
a network block additionally refuses every address the host needs to stay
reachable.

`cau defend --ingest <path>` takes in telemetry from other hosts and sensors —
another cau host's incidents, an OCSF event from a firewall or an IDS, a plain
JSON line — and joins it on the peer address, the one identifier two machines
agree on. Remote evidence corroborates an incident; it never directs the
response, because a PID and a path mean nothing off the host that produced them.

Hash and YARA hits are MALICIOUS; scores are SUSPICIOUS and never promoted;
the lattice raises CLEAN to SUSPICIOUS only when independent sources
corroborate each other, and never lowers anything.

## Beyond the file and the host

| Area | Command | What it gives you |
|---|---|---|
| **Boot chain** | `cau boot-scan` | MBR and both GPT copies, every EFI binary on the ESP, Secure Boot state and dbx, WPBT and option ROMs. Read-only, and a test fails the build if it ever gains a write |
| **Firmware** | `cau firmware` | a UEFI image's module inventory, through LZMA and nested volumes, with every module body run through the YARA rules |
| **Hardware identity** | `cau hwid` | DMI, NIC addresses, TPM PCRs and the entropy source, with `--record` and `--check` against a baseline, and `--redact` for sharing |
| **Threat intel** | `cau intake` | STIX, MISP, MalwareBazaar, LOLDrivers and TAXII 2.1 with a persisted cursor, recording the provenance of every signature |
| **SIEM delivery** | `cau scan --format`, `--sink-url`, `--wazuh-url` | thirteen formats, including ECS, CEF, LEEF, GELF, RFC 5424 syslog and OTLP, delivered over UDP, TCP, TLS or HTTPS. Free, and `cau defend` streams to Wazuh by itself |
| **Honesty** | `cau honesty` | one document of what is covered, what was measured and whether the content is intact, with no overall score |
| **Supply chain** | `cau bundle sbom`, `cau verify-self` | a reproducible CycloneDX SBOM per binary, and signed release manifests. `cau update` refuses an older signed bundle |

## Quick start

```sh
sudo apt install golang-go libyara-dev pkg-config build-essential   # or: pacman -S go yara pkgconf, or: brew install go yara pkg-config
git clone https://github.com/s-b-repo/cau.git cau && cd cau
make build
./cau scan --file corpus/smoke/malicious/mimikatz_strings.bin --db corpus/smoke/hashes.txt
```

```
 [!] DETECTED (YARA) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : MALICIOUS
     [YARA] default::mimikatz_strings
            author=CAU threat_level=5 in_the_wild=true desc="Mimikatz module and command strings (binary or script carrier)"
            $m1 @ 0x48 : "sekurlsa::logonpasswords"
            $m3 @ 0x61 : "lsadump::sam"
            $m5 @ 0x37 : "privilege::debug"

 [!] DETECTED (Heuristics) — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : SUSPICIOUS
     Score     : 8 / 7 threshold

     [Credential Access]  (T1003)
       [String]       sekurlsa::logonpasswords
       [String]       lsadump::sam

 [+] Fusion — corpus/smoke/malicious/mimikatz_strings.bin
     Verdict   : MALICIOUS (fused 1.14 / 1.00, high confidence)
     Agreed    : yara, heuristic
     Techniques: T1003
```

`sudo make install` puts the binary in `/usr/local/bin` and the rules and
signatures in `/usr/local/share/cau`, where the binary finds them. Exit codes:
0 clean, 1 findings at the `--fail-on` level, 2 unscannable files, 3 the run
failed, 4 usage.

## Documentation

| | |
|---|---|
| [Installation](docs/installation.md) | requirements, build, install, release tarballs, resource discovery |
| [Command-line reference](docs/cli.md) | every command and flag, exit codes, CI recipes |
| [MCP server](docs/mcp.md) | `cau-mcp`: the engine over the Model Context Protocol, its tools/resources/prompts and the scan-root sandbox |
| [Detectors](docs/detectors.md) | how each detector scores, its classes and techniques, and the numbers it was tuned on |
| [Network plane](docs/network.md) | the network sensor's classes, the blocker's policy and backends, and how telemetry from other hosts is joined |
| [Output formats](docs/output-formats.md) | the text report, JSON schema 1.13.0, SARIF 2.1.0 rule ids, OCSF Detection Findings, the exit policy |
| [Detection content](docs/detection-content.md) | signature databases, YARA conventions and the rule linter, the fuzzy-hash database |
| [Detection engineering](docs/detection-engineering.md) | ADS documents, the ATT&CK coverage matrix and its gate, Pyramid of Pain, OCSF |
| [Evaluation harness](docs/evaluation.md) | corpora, baselines, regression gates, every measurement behind the docs |
| [Evasion report](docs/evasion.md) | how fragile the shipped detections are: the bytes that must change for each detector to stop firing, per file and per corpus |
| [Library usage](docs/library.md) | using the engine and the fusion lattice from Go |
| [Architecture](docs/architecture.md) | the single-read pipeline, verdict tiers, design rules, layout |
| [Packaging](docs/packaging.md) | the maintainer guide: what CI builds on push and tag, the release checklist, the signed apt repository |
| [Limitations](docs/limitations.md) | what each detector cannot do, documented false-positive classes |
| [Contributing](docs/contributing.md) | development, tests, the measure-or-don't-ship rule, the regex audit |
| [PLAN.md](PLAN.md) · [CHANGELOG.md](CHANGELOG.md) | roadmap and design reasoning · release notes |

## Measured, not asserted

| Claim | Where it was measured | Result |
|---|---|---|
| heuristics stay quiet on real tools | 349 files, Kali's Windows tool set | detections 60 → 28 after the rescoring; credential dumpers and injectors still detected |
| static structure does not flag packed benign tools | 49 PE files in the same set | 43 score 0, nothing crosses the threshold, UPX and ASPack named below it |
| static structure stays quiet on a Linux system | 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`, `/usr/lib/systemd`; 40 kernel modules | 0 cross the threshold, 21 carry one weight-1 observation, every module scores 0, a UPX-packed `ls` scores 6 with the packer named |
| invisible-codepoint pass is usable on real text | 70,102 benign text artifacts | 0.10 % false positives, 348 legitimate uses excused by named rules |
| fusion adds no false positives | 349 files | 0 fused-only detections, 0 new false positives |
| the network sensor stays quiet on an ordinary host | a synthetic eight-daemon host (sshd, systemd-resolved, nginx, firefox, curl, postgres and a developer's `python3 -m http.server`), and a stock Kali desktop read **as root**: 48 sockets, 40 of them attributed to a process | 0 findings at the shipped threshold in both. At `--threshold 1` the live host lists 4 sockets as inventory — NetworkManager's raw ICMPv6 socket and ARP packet socket, and wpa_supplicant's two 802.1X ones — and nothing sums to the threshold. One host and one run, not a fleet |
| the root-level read is what found the one real false positive | the same stock host, before the fix | NetworkManager scored 5 — exactly the threshold — because a raw socket (3) and an ARP packet socket (2) shared one subject. Unprivileged runs had hidden it: a socket whose holder cannot be read has no executable to group by. The capture classes now weigh **who holds the socket** over what it is (packaged: 2 and 1; unpackaged: 6 and 3), and `TestNetworkManagerShapeStaysQuiet` pins it |
| the time-based analytics stay quiet on real traffic | the same host, `--interval 20s --threshold 1` for 10 samples over 3.3 minutes, during ordinary desktop use | 0 beaconing, gateway-MAC-churn and sweep findings; the only classes that fired across all 10 samples were the same 4 inventory sockets each time. The window was capable of producing a beacon — a 20-second poller would have made 10 connections in it, well past the 4 the analytic needs — so the zero is meaningful rather than vacuous. It does **not** cover a slow beacon: a 60-second cadence makes only 3 connections in 3.3 minutes and could not have been detected either way |
| blocking is reversible and leaves the host's firewall as it was | a real kernel: block two addresses, list them back, unblock one, `cau net clear` | the `inet cau` table carried both elements with kernel-side expiry (`timeout 1h expires 59m47s`), `cau net blocks` read them back through real `nft -j` output, and after `clear` the `nft list ruleset` digest was byte-identical to the one taken before the first block, with 0 tables left. Re-applying the ruleset left 8 rules, not 16, and did not drop the live element |
| the response policy refuses what the host needs | every address class a machine could be asked to block | loopback, unspecified, multicast, link-local, this host's own addresses, its default gateways and its configured resolvers are refused with a reason; `netblock.Check` is a pure function and tested as one |
| encoded-executable detection is low-noise | 159,339 benign files (Kali doc/python/nmap/metasploit trees) | 0.020 % detections, every one a genuine embedded encoded executable |
| **detection rate on tools the rules were not written from** | 280 real offensive samples held out by tool (`make eval-lab`) | **61.1 %, up from 25.4 %**, 6/2,431 false positives; public tooling, not a malware detection rate, see [the caveats](docs/evaluation.md#the-lab-corpus) |
| false positives across a wide benign sweep | 25,000 files, held-out excluded | 0.15 %; all 4 hits from the behavioural pass are genuine offensive material |
| a dropped script is flagged as it lands | `cau defend` on a 12-core host, the real binary through the real watcher, a one-line PHP file | median under 1 ms on a quiet host, 7 ms during a 20,000-file sweep; worst seen 141 ms, in the first instant after start. At load 15 to 25: median 3 to 85 ms, worst 158 ms. The quiet-host figures predate the scanning changes; on the final build, measured only at load 31 to 35: median 23 to 177 ms |
| a dropped script and the cron entry that runs it become one confirmed incident | same, through the real persistence audit | median 3.4 ms on a quiet host, 13 ms during a sweep; worst seen 244 ms. At load 15 to 25: median 21 to 176 ms, worst 337 ms |
| scanning takes longer the larger the file | all detectors over `/usr/bin/bash` (1.4 MB), which is what an alert on a real binary waits for | about 0.3 s on a quiet host, 1.3 s at load 22, down from 3.7 s; most of it is regexes over the whole binary |
| running detectors at once costs no throughput | the smoke corpus, serial and parallel engines built from one tree, 10 runs each in random order | 10 % faster at the median |
| skipping regexes that cannot match changes no result | 10,410 files, mostly offensive tooling, against a build without the filter: every finding of every detector compared | 0 differences in 1,513 files with findings across 112 classes; about 100 s rather than 529 s, at a higher load |
| kernel guards load and behave | the running kernel in QEMU, real verifier and real `execve` (`cau-kernel`: `make vm-test`) | 38/38 scenarios through the real CLI, including `ssh host cmd` shells, inetd listeners, blocking a running file and fail-open |
| the response really happens, and only where it should | the running kernel in QEMU, the real binary with its defaults as real root (`make vm-respond`) | 19/19: a shell on a TCP socket and a deleted binary stopped, one killed, a file moved to the vault and caught again when re-dropped; argv text, `/etc` and PID 1 left alone |
| nothing regresses silently | `corpus/smoke` on every push | 100 % recall, 0 false positives, gated in CI against the committed baseline |
| coverage claims are derived, not typed | `cau coverage` on every push | 59 techniques with content and no declared gaps (3 held honestly as `partial`), gated against `baselines/attack-coverage.txt`; every bundled rule passes `cau rules lint` |

Details and caveats in [docs/evaluation.md](docs/evaluation.md).

## Project

This repository is the **engine and agent**: detection content, scanning
library, MCP server, evaluation harness, and all on-host prevention/response
(quarantine, restore, block, kill, canaries), under MIT. The kernel guards live in
the sibling `cau-kernel` project. **Detection and
prevention are free and unmetered, forever.** The only paid artifact is a
separate control plane whose job is *managing a fleet of these free agents* from
one pane — central policy, cross-host timelines, multi-tenancy — inherently
stateful server-side work that adds no detect-or-prevent capability a single
free agent lacks. The paywall is multi-agent management, not withheld features.
The roadmap, the reasoning and the measurements behind each phase are in
[PLAN.md](PLAN.md).

It started as a fork of the Astra AV Engine educational series; the
implementation has since been reworked for correctness and measurability,
and the episode structure survives in the detectors' names.

## Disclaimer

For educational and research use. Only analyze files and systems you own or
are authorised to analyze. Handle real malware samples in isolated
environments and never commit them to this repository.

## License

MIT, see [LICENSE](LICENSE).

## Support

If this work has helped you, you can support more independent security research
with Monero:

```
478Lb78LDscQ8ukEDTZqXgEtjoBX1jMuVGvgfy2RagxZZk89YuyVYsganfLUKnwggz8YiBxhG25yWWiHUppG9uarSiseseY
```

XMR · Optional support, always appreciated.

# CAU EDR — Certs Are Useless

[![ci](https://github.com/s-b-repo/cau/actions/workflows/ci.yml/badge.svg)](https://github.com/s-b-repo/cau/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A transparent, open-source malware detection engine in Go. Six detectors read
every file once, every finding is explained with a labeled class and an
ATT&CK technique, every report is machine-readable with CI exit codes, and an
evaluation harness gates every detection change against a measured baseline.

```sh
cau scan --dir ./downloads
cau scan ./dist --format sarif --output cau.sarif --fail-on none    # code scanning
cau scan ./build --format json --fail-on heuristic                   # fail CI on suspicion
cau scan ./dist --format ocsf --output findings.json                 # OCSF for a security lake
cau coverage --format navigator --output layer.json                  # ATT&CK Navigator heat map
cau rules lint --rules ./signature-base --profile generic            # lint a third-party rule set
cau quarantine add ./suspicious.exe --threat Win.Trojan.Agent        # integrity-sealed vault
cau canary plant --dir /srv/share/.decoys --manifest canary.json     # decoys as cheap ground truth
cau peel ./dropper.b64                                               # walk an obfuscation chain, depth as signal
```

## What it does

| Detector | Question it answers | Result |
|---|---|---|
| **Hash signatures** | is this exact content known? | MALICIOUS with the threat name |
| **YARA** (in-process libyara, per-file timeout) | does it contain patterns a rule describes? | MALICIOUS with rule, namespace, meta and matched strings at their offsets |
| **Heuristics** | does it name suspicious capabilities? | SUSPICIOUS with a capped score, the categories responsible and their ATT&CK techniques |
| **Static structure** (own PE and ELF parsers, entropy, TLSH / ssdeep / imphash) | is it *built* like something that hides? | SUSPICIOUS with labeled anomaly classes: packer, RWX sections or segments, forged build record, implausible signer, appended payload, stripped section table, non-system program interpreter, writable `RPATH`, libc interposer, unsigned kernel module, similarity to a known sample |
| **Invisible codepoints** | does this text or code carry hidden codepoints? | SUSPICIOUS with every zero-width, bidi-override, TAG or variation-selector codepoint, its line, and the context rules that excused the rest |
| **Encoded executable** (base64/hex, multi-layer) | is an executable hidden behind text encoding? | SUSPICIOUS with the decoded PE/ELF, the encoding and the layer depth |
| **Obfuscation-chain peeler** (bounded tree unwrap, budget-walled) | is a payload stacked behind *several* encoding/compression layers? | SUSPICIOUS at chain depth ≥ 2 with the ordered chain signature (e.g. `base64>gzip>base64`); `peel-exhausted` when the budget wall is hit |
| **Fusion** | do several detectors agree, even below their own thresholds? | one fused verdict naming the sources that agreed, their roles and techniques |

Hash and YARA hits are MALICIOUS; scores are SUSPICIOUS and never promoted;
the lattice raises CLEAN to SUSPICIOUS only when independent sources
corroborate each other, and never lowers anything.

## Quick start

```sh
sudo apt install golang-go libyara-dev pkg-config build-essential   # or: brew install go yara pkg-config
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
| [Detectors](docs/detectors.md) | how each detector scores, its classes and techniques, and the numbers it was tuned on |
| [Output formats](docs/output-formats.md) | the text report, JSON schema 1.3.0, SARIF 2.1.0 rule ids, OCSF Detection Findings, the exit policy |
| [Detection content](docs/detection-content.md) | signature databases, YARA conventions and the rule linter, the fuzzy-hash database |
| [Detection engineering](docs/detection-engineering.md) | ADS documents, the ATT&CK coverage matrix and its gate, Pyramid of Pain, OCSF |
| [Evaluation harness](docs/evaluation.md) | corpora, baselines, regression gates, every measurement behind the docs |
| [Library usage](docs/library.md) | using the engine and the fusion lattice from Go |
| [Architecture](docs/architecture.md) | the single-read pipeline, verdict tiers, design rules, layout |
| [Limitations](docs/limitations.md) | what each detector cannot do, documented false-positive classes |
| [Contributing](docs/contributing.md) | development, tests, the measure-or-don't-ship rule |
| [PLAN.md](PLAN.md) · [CHANGELOG.md](CHANGELOG.md) | roadmap and design reasoning · release notes |

## Measured, not asserted

| Claim | Where it was measured | Result |
|---|---|---|
| heuristics stay quiet on real tools | 349 files, Kali's Windows tool set | detections 60 → 28 after the rescoring; credential dumpers and injectors still detected |
| static structure does not flag packed benign tools | 49 PE files in the same set | 43 score 0, nothing crosses the threshold, UPX and ASPack named below it |
| static structure stays quiet on a Linux system | 4,974 ELF files under Kali's `/usr/bin`, `/usr/sbin`, `/usr/lib/x86_64-linux-gnu`, `/usr/libexec`, `/usr/lib/systemd`; 40 kernel modules | 0 cross the threshold, 21 carry one weight-1 observation, every module scores 0, a UPX-packed `ls` scores 6 with the packer named |
| invisible-codepoint pass is usable on real text | 70,102 benign text artifacts | 0.10 % false positives, 348 legitimate uses excused by named rules |
| fusion adds no false positives | 349 files | 0 fused-only detections, 0 new false positives |
| encoded-executable detection is low-noise | 159,339 benign files (Kali doc/python/nmap/metasploit trees) | 0.020 % detections, every one a genuine embedded encoded executable |
| nothing regresses silently | `corpus/smoke` on every push | 100 % recall, 0 false positives, gated in CI against the committed baseline |
| coverage claims are derived, not typed | `cau coverage` on every push | 37 techniques with content and 3 declared gaps, gated against `baselines/attack-coverage.txt`; every bundled rule passes `cau rules lint` |

Details and caveats in [docs/evaluation.md](docs/evaluation.md).

## Project

This repository is the **engine**: detection content, scanning library,
evaluation harness and, next, an MCP server, under MIT. Fleet state,
response and the resident sensor are inherently stateful and belong to a
separate control plane; the split is by persona, not by withholding features.
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

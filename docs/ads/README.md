# Alerting and Detection Strategies

One document per detector in the
[Palantir ADS](https://github.com/palantir/alerting-detection-strategy-framework)
format. Each answers the same nine questions so an analyst reading a hit
knows what the detector is for, what it cannot see, why it fires on benign
files, and how to prove it still works.

| ADS | Detector | Tier |
|---|---|---|
| [Hash signatures](hash-signatures.md) | exact-content match against the signature database | MALICIOUS |
| [YARA](yara.md) | compiled rules over the file's bytes | MALICIOUS |
| [Heuristics](heuristics.md) | capability named by imports and strings | SUSPICIOUS |
| [Static structure](static-structure.md) | PE and ELF anatomy that hides something | SUSPICIOUS |
| [Invisible codepoints](invisible-codepoints.md) | zero-width, bidi, TAG and variation-selector steganography | SUSPICIOUS |
| [Obfuscation chain](obfuscation-chain.md) | a payload stacked behind layers of encoding, compression or simple ciphers | SUSPICIOUS |
| [Tradecraft](tradecraft.md) | behaviour in scripts and payload bytes, through decoded carriers — web/net/in-memory shells, LOLBAS and GTFOBins abuse, the lolol.farm trusted-SaaS catalogue (LOLC2, LOLFSaaS, LOTTunnels, LOTWebhooks) and the ArcticFox EDR-bypass primitives | SUSPICIOUS |
| [Fusion](fusion.md) | corroboration between sub-threshold detectors | raises CLEAN to SUSPICIOUS |

Sections, in order: Goal, Categorization, Strategy Abstract, Technical
Context, Blind Spots and Assumptions, False Positives, Validation, Priority,
Response. Numbers in the blind-spot and false-positive sections come from
[Limitations](../limitations.md) and [Evaluation](../evaluation.md); when a
number there changes, the ADS changes with it.

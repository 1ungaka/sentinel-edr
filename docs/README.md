# CAU EDR documentation

CAU EDR ("Certs Are Useless") is an open-source malware detection engine
written in Go. These pages are the reference; the repository
[README](../README.md) is the overview.

| Page | What it covers |
|---|---|
| [Installation](installation.md) | requirements, building, installing, release tarballs, where resources are found |
| [Command-line reference](cli.md) | every command and flag (`scan`, `coverage`, `rules`, `eval`, ...), exit codes, CI recipes |
| [MCP server](mcp.md) | `cau-mcp`: the engine over the Model Context Protocol, its tools/resources/prompts and the scan-root sandbox |
| [Detectors](detectors.md) | hash signatures, YARA, heuristics, static structure, invisible codepoints, encoded executables, the fusion lattice |
| [Output formats](output-formats.md) | the text report, the JSON document (schema 1.4.0), SARIF 2.1.0, OCSF Detection Findings, the `--fail-on` policy |
| [Detection content](detection-content.md) | signature databases, YARA rule conventions and the linter, the fuzzy-hash database, external rule sets |
| [Detection engineering](detection-engineering.md) | ADS documents per detector, the ATT&CK coverage matrix and its gate, Pyramid of Pain levels, OCSF |
| [ADS](ads/README.md) | one Alerting and Detection Strategy per detector |
| [Evaluation harness](evaluation.md) | corpora, manifests, baselines, regression policies, the measurements behind every number |
| [Library usage](library.md) | using the engine from Go |
| [Architecture](architecture.md) | the single-read pipeline, verdict tiers, design rules, repository layout |
| [Limitations](limitations.md) | what each detector cannot do, the documented false-positive classes |
| [Contributing](contributing.md) | development environment, tests, the measure-or-don't-ship rule, corpus policy |

Roadmap and design reasoning live in [PLAN.md](../PLAN.md); release notes in
[CHANGELOG.md](../CHANGELOG.md).

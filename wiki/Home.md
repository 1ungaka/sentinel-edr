# CAU EDR

**Certs Are Useless** — a transparent, open-source malware detection *and
prevention* engine. Detection and prevention are free and unmetered on every
host; only the multi-agent management console is paid.

This wiki is generated from the repository (`wiki/`), so it tracks the code.
The canonical, in-depth docs live in [`docs/`](https://github.com/s-b-repo/cau/tree/main/docs)
and the roadmap in [`PLAN.md`](https://github.com/s-b-repo/cau/blob/main/PLAN.md).

## Start here

- **[Installation](Installation)** — build it, or install from a signed release.
- **[Scanning and Prevention](Scanning-and-Prevention)** — `cau scan`, detect and
  quarantine in one pass.
- **[Running as a Service](Running-as-a-Service)** — automated background scanning
  (daemon + systemd).
- **[Updates and Self-Verification](Updates-and-Self-Verification)** — signed
  signature updates, and how the binary verifies *itself*.
- **[Anti-Tamper](Anti-Tamper)** — detecting attempts to disable the scanner.
- **[CLI Reference](CLI-Reference)** — every command.

## What it finds

Hash signatures, YARA (in-process libyara), string/API heuristics, a bounds-checked
PE/ELF/Mach-O static-structure pass, invisible-codepoint (stego) analysis, an
encoded-executable pass, document/archive detectors (LNK, OLE, PDF, ISO), a Linux
software-package pass (.deb/.rpm/Arch/Flatpak/AppImage/Docker/Snap install
scripts), a compressed-archive pass (ZIP/TAR/gzip: bombs, Zip-Slip,
lure/payload members), a Compiled HTML Help (CHM) pass (embedded executables,
shortcuts, dangerous scripts), an obfuscation-chain peeler (NOVEL-012), a
behavioural **tradecraft** pass over scripts and payload bytes (web shells,
network shells, in-memory loaders, LOLBAS and GTFOBins abuse, the full
[lolol.farm](https://lolol.farm) catalogue of trusted-SaaS command channels, and
the EDR-bypass primitives from the
[ArcticFox detection-bypass catalogue](https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md)),
and a known-abused code-signing certificate blocklist — joined by a fusion
lattice with attack-path chaining. Beyond files: a read-only live process scan
(`cau ps`) for what is already running (fileless, masquerade, injection), an
installed-package audit (`cau installed`), and an abuse-intel feed
(`cau feed`). Every verdict is machine-readable (text,
JSON, SARIF, OCSF) with CI exit codes, and ATT&CK coverage is **derived from the
shipped content, never hand-typed** (`cau coverage`).

## Licensing in one line

Everything that finds and stops threats on a host is MIT and free. The paid
artifact is only the web console that manages a *fleet* of these free agents from
one pane. See [`PLAN.md` → Product shape](https://github.com/s-b-repo/cau/blob/main/PLAN.md).

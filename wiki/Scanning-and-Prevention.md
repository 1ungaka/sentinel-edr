# Scanning and Prevention

## Detect

```sh
cau scan --dir ./downloads
cau scan --file suspicious.exe
cau scan ./app.deb ./pkg.rpm ./image.tar                            # Linux packages & docker-save images
cau scan ./dist --format sarif --output cau.sarif --fail-on none   # code scanning
cau scan ./build --format json  --fail-on heuristic                 # fail CI on suspicion
cau scan ./dist --format ocsf   --output findings.json              # OCSF for a lake
```

A single file is read once and offered to every detector: hash, YARA, string/API
heuristics, the PE/ELF/Mach-O static structural pass, invisible codepoints,
encoded-executable and obfuscation-chain peeling, the document/container passes
(.lnk, OLE, PDF, ISO), the Linux software-package pass (.deb/.rpm/Arch/
Flatpak/AppImage/Docker-OCI/Snap install scripts), the compressed-archive
pass (ZIP/TAR/gzip: decompression bombs, Zip-Slip, lure/payload members), and
the Compiled HTML Help (CHM) pass (embedded executables, shortcuts, dangerous
scripts). Hash
and YARA hits are
**MALICIOUS**; heuristic / static / stego / document / package / chain breaches
are **SUSPICIOUS** and never promoted. The fusion lattice reports sub-threshold
detectors that corroborate each other, with attack-path chaining for recognised
combinations. Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` some
files unscannable, `3` the run failed, `4` usage.

Each detector can be disabled (`--no-yara`, `--no-static`, `--no-peel`,
`--no-pkg`, `--no-archive`, …) and has a `--*-threshold`. An abuse-intel feed
(`--feed`, managed with `cau feed`) adds known-bad IP/domain/URL/hash matching.
See [CLI Reference](CLI-Reference).

`cau installed` audits the maintainer scripts of already-installed packages in
place (dpkg/pacman, offline, read-only) — catching a supply-chain compromise
that landed before you deployed the scanner. See [CLI Reference](CLI-Reference).

## Scan the live process table

`cau scan` looks at files; `cau ps` looks at what is **already running**, read
entirely from `/proc` and strictly read-only:

```sh
cau ps                       # flag fileless, masqueraded, injected or ptraced processes
sudo cau ps --format json    # full visibility, machine-readable
```

It catches what a file scan structurally cannot — a dropper that decoded and
executed in memory (memfd, deleted binary, `/dev/shm`), a process masquerading as
`btop`/`sshd`/`[kworker]`, a `.so` injected from a world-writable or deleted path,
and reverse-shell command lines. Exit `0` clean, `1` flagged, `4` usage.

## Prevent (free)

Detect **and** stop in one pass — move confirmed-malicious files into the
integrity-sealed vault as they are found:

```sh
cau scan --dir /mnt/usb --quarantine
cau scan --dir / --quarantine --quarantine-store /var/lib/cau/quarantine
```

`--quarantine` is explicit and off by default (the move is destructive). It acts
only on the MALICIOUS tier (hash/YARA), never on sub-threshold suspicions.

The vault is a neutralized, integrity-sealed store:

```sh
cau quarantine list
cau quarantine verify                 # fail-closed: tamper → exit 1
cau quarantine restore <id> --to ./recovered.bin
cau quarantine delete <id>
```

Entries are XOR-masked at rest (never a runnable PE/ELF on disk, never re-flagged
by a scanner pointed at the vault) and sealed with the SHA-256 of both the
original and the stored bytes, so a corrupted or tampered vault fails closed
instead of restoring wrong bytes.

## Decoys as cheap ground truth

```sh
cau canary plant --dir /srv/share/.decoys --manifest canary.json --count 8
cau canary check --manifest canary.json      # modified/deleted/meta-changed → exit 1
```

A decoy nobody advertised has no legitimate reason to be touched, so a tripped
canary is high-signal, near-zero-false-positive ground truth.

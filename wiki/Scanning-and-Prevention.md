# Scanning and Prevention

## Detect

```sh
cau scan --dir ./downloads
cau scan --file suspicious.exe
cau scan ./dist --format sarif --output cau.sarif --fail-on none   # code scanning
cau scan ./build --format json  --fail-on heuristic                 # fail CI on suspicion
cau scan ./dist --format ocsf   --output findings.json              # OCSF for a lake
```

Hash and YARA hits are **MALICIOUS**; heuristic / static / stego / document /
chain breaches are **SUSPICIOUS** and never promoted. The fusion lattice reports
sub-threshold detectors that corroborate each other. Exit codes: `0` clean, `1`
findings at/above `--fail-on`, `2` some files unscannable, `3` the run failed, `4`
usage.

Each detector can be disabled (`--no-yara`, `--no-static`, `--no-peel`, …) and has
a `--*-threshold`. See [CLI Reference](CLI-Reference).

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

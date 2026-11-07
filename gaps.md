# Audit findings

Static source audit of the current worktree. Findings are ordered by severity. No implementation files were changed and no tests were run.

## P1 — High

### Quarantine can unlink a different file after a path race

`Store.Quarantine` reads through `safefs.ReadFileNoFollow`, then writes the vault entry and later calls `os.Remove(abs)` by pathname without verifying that the pathname still identifies the file it read. The descriptor is already closed by the helper. In the shipped `cau-defend.service`, response runs with `CAP_DAC_OVERRIDE`/`CAP_FOWNER` and can write under `/tmp`, `/var/tmp`, `/var/lib/cau`, `/var/log/cau`, `/var/www`, and `/srv`. An attacker controlling a scanned parent directory can swap it for a symlink between the scan/read and unlink steps, redirecting quarantine to a different same-named file in those writable locations. This can remove logs or other service data instead of the flagged file. [quarantine.go](/home/kali/cau/internal/quarantine/quarantine.go:174), [quarantine.go](/home/kali/cau/internal/quarantine/quarantine.go:218), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1727), [cau-defend.service](/home/kali/cau/packaging/systemd/cau-defend.service:118), [cau-defend.service](/home/kali/cau/packaging/systemd/cau-defend.service:124)

## P2 — Material

### ASCII85 peeling allocates well beyond the configured output budget

`ascii85Layer` allocates `4*len(src)+4` bytes before decoding or checking the per-decode limit. The scanner accepts files up to 64 MiB by default, so an ASCII85-looking sample can make this decoder allocate about 256 MiB by itself. Multiple matching decoders and concurrent file scans can multiply the peak. The peeler’s 64 MiB output budget is charged only after a decoder returns, so it does not constrain this allocation. [bases.go](/home/kali/cau/internal/peeler/bases.go:259), [bases.go](/home/kali/cau/internal/peeler/bases.go:261), [budget.go](/home/kali/cau/internal/peeler/budget.go:63), [peeler.go](/home/kali/cau/internal/peeler/peeler.go:631)

### The packaged update unit always fails its self-verification preflight

`cau-update.service` invokes `verify-self` without `--name`, so the command checks the running executable as `cau`. Release checksums contain versioned names such as `cau-v<tag>-linux-amd64`; CI’s own verification supplies that exact name explicitly. The installed unit therefore gets “file is not listed” and never reaches `cau update`. [cau-update.service](/home/kali/cau/packaging/systemd/cau-update.service:40), [cmd_verifyself.go](/home/kali/cau/cmd_verifyself.go:94), [ci.yml](/home/kali/cau/.github/workflows/ci.yml:265), [ci.yml](/home/kali/cau/.github/workflows/ci.yml:363)

### Debian, Kali, and Arch release packages are outside the signed checksum manifest

The release workflow signs files in its own `dist/` directory, while a separate packaging workflow attaches `.deb` and `.pkg.tar.zst` files to the release afterward. The installation guide directs users to download those package assets directly, but the project-signed `SHA256SUMS` does not authenticate their digests. [ci.yml](/home/kali/cau/.github/workflows/ci.yml:348), [package.yml](/home/kali/cau/.github/workflows/package.yml:167), [package.yml](/home/kali/cau/.github/workflows/package.yml:246), [package.yml](/home/kali/cau/.github/workflows/package.yml:308), [installation.md](/home/kali/cau/docs/installation.md:111)

### `bundle checksums` can silently omit an input file

The command stores digests by `filepath.Base(f)`. If two input paths share a basename, the later digest overwrites the earlier one, so the signed manifest covers fewer unique files than the success message’s `fs.NArg()` count claims. [cmd_bundle.go](/home/kali/cau/cmd_bundle.go:182), [cmd_bundle.go](/home/kali/cau/cmd_bundle.go:188), [cmd_bundle.go](/home/kali/cau/cmd_bundle.go:204)

### Auto-quarantine does not quarantine a file reached through a symlink

`Engine.ScanFile` follows symlinks, and `--follow-symlinks` makes directory scans inspect their targets. Auto-quarantine then passes the symlink path to `Store.Quarantine`, which uses `ReadFileNoFollow` and refuses it. The scan warns and continues while the detected target remains in place, so the requested prevention action did not occur. [engine.go](/home/kali/cau/scanner/engine.go:369), [engine.go](/home/kali/cau/scanner/engine.go:391), [cmd_quarantine.go](/home/kali/cau/cmd_quarantine.go:302), [quarantine.go](/home/kali/cau/internal/quarantine/quarantine.go:174)

### Canary manifest edits can clear the canary tamper alert

`ReadManifest` validates JSON and the version only; it does not authenticate the baseline or validate its entries. A valid version-1 manifest with an empty `canaries` list is accepted, and `canarySignals` then clears the canary tamper state. The general selftest baseline does not include the canary manifest. Where that manifest is writable by the same UID as the defender, its baseline can be replaced to silence all canary checks without an alert. [canary.go](/home/kali/cau/internal/canary/canary.go:242), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1059), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1068), [cmd_selftest.go](/home/kali/cau/cmd_selftest.go:207)

### Canary checks ignore modification-time changes

Planting records `Canary.ModTime`, and package documentation says the checker detects timestamp-only changes. `checkOne` compares the digest and mode but never compares `info.ModTime()` with the recorded value, so a timestamp-only change is reported as intact. [canary.go](/home/kali/cau/internal/canary/canary.go:15), [canary.go](/home/kali/cau/internal/canary/canary.go:149), [canary.go](/home/kali/cau/internal/canary/canary.go:210)

### Canary manifest writes follow symlinks and do not enforce mode 0600 on existing files

`WriteManifest` uses `os.WriteFile` directly. An existing destination symlink is followed and its target is truncated; this is unsafe when a privileged `cau canary plant` writes into an attacker-writable directory. Also, the permission argument only applies when creating a file, so an existing manifest with broader permissions stays broader despite the function’s 0600 contract. [canary.go](/home/kali/cau/internal/canary/canary.go:216), [canary.go](/home/kali/cau/internal/canary/canary.go:227), [cmd_canary.go](/home/kali/cau/cmd_canary.go:76)

### Malformed CHM directory entries silently stop enumeration without marking it incomplete

When a PMGL entry has an invalid name length, overruns the chunk, or has malformed trailing integers, enumeration breaks or skips the rest of that entry without setting `truncated`. Later names in that chunk are not inspected, and the result omits the “directory walk hit a parse bound” note. A crafted directory can therefore hide later executable or script names while appearing fully enumerated. [chm.go](/home/kali/cau/scanner/chm/chm.go:283), [chm.go](/home/kali/cau/scanner/chm/chm.go:285), [chm.go](/home/kali/cau/scanner/chm/chm.go:289), [chm.go](/home/kali/cau/scanner/chm/chm.go:313)

### Network socket limits are enforced after all namespace tables are allocated

`readSockets` reads and retains all seven per-namespace tables for as many as 256 namespaces before applying `maxSockets`. Each table read can be up to 16 MiB, so a host with many large namespace tables can force multi-gigabyte transient allocations before the advertised 131,072-socket cap takes effect. [proc.go](/home/kali/cau/internal/netscan/proc.go:21), [proc.go](/home/kali/cau/internal/netscan/proc.go:178), [proc.go](/home/kali/cau/internal/netscan/proc.go:183), [proc.go](/home/kali/cau/internal/netscan/proc.go:193), [proc.go](/home/kali/cau/internal/netscan/proc.go:314)

### The per-process FD cap is applied after the full `/proc/<pid>/fd` listing is read

`socketInodes` calls `os.ReadDir` before checking `maxFDs`. A process with a very large descriptor table can therefore force a large directory allocation/read on every network scan despite the 1,024-entry cap. [proc.go](/home/kali/cau/internal/netscan/proc.go:20), [proc.go](/home/kali/cau/internal/netscan/proc.go:284), [proc.go](/home/kali/cau/internal/netscan/proc.go:289)

### Eval’s encoded-executable selection and fusion results are inconsistent

The CLI reference documents `--no-encchain`, but `eval run` does not define it. The encoded-executable detector is instead gated by `--no-stego`, so disabling stego also disables encchain. Conversely, with `--no-format-passes`, the standalone encchain detector remains enabled but the fusion engine never enables it; with default format passes, fusion enables encchain even when `--no-stego` removed the standalone detector. Per-detector and fusion measurements can therefore disagree about which evidence was enabled. [cmd_eval.go](/home/kali/cau/cmd_eval.go:132), [cmd_eval.go](/home/kali/cau/cmd_eval.go:244), [cmd_eval.go](/home/kali/cau/cmd_eval.go:254), [bridge.go](/home/kali/cau/internal/eval/scannerbridge/bridge.go:464), [cli.md](/home/kali/cau/docs/cli.md:1263)

### `cluster` reports success after incomplete directory walks

The `filepath.Walk` callback discards callback errors and the function ignores the final walk error. An unreadable directory or subtree is skipped while the command can still report apparently complete clustering results and exit successfully. [cmd_static.go](/home/kali/cau/cmd_static.go:233), [cmd_static.go](/home/kali/cau/cmd_static.go:238)

### `hash` can exit successfully with a missing or inconsistent SHA-256

The command computes structural digests with `static.AnalyzeFile`, then rereads the path for SHA-256. `sha256File` discards the second read’s error, and a file changed between reads can produce metadata from one byte sequence and SHA-256 from another. The missing digest does not increment the failure count. [cmd_static.go](/home/kali/cau/cmd_static.go:57), [cmd_static.go](/home/kali/cau/cmd_static.go:66), [cmd_static.go](/home/kali/cau/cmd_static.go:114)

### Installed-package script audits silently truncate at 1 MiB

`readScript` reads only the first MiB and discards read errors. It does not report truncation or unreadability, so tradecraft after the boundary can be missed while the package remains counted as audited. [cmd_installed.go](/home/kali/cau/cmd_installed.go:268), [cmd_installed.go](/home/kali/cau/cmd_installed.go:270), [cmd_installed.go](/home/kali/cau/cmd_installed.go:276)

### `selftest` resource override flags do not affect verification

`cmdSelftest` resolves `--db`, `--rules`, `--fuzzy-db`, `--feed`, and `--config` and passes the resulting resources to `selftestVerify`, but the verifier ignores that argument and calls `selftest.Verify(baseline)`, which checks the paths stored in the manifest. If an active resource moved or was replaced at a new path, specifying that path does not make verification cover it, despite the usage text promising overrides. [cmd_selftest.go](/home/kali/cau/cmd_selftest.go:207), [cmd_selftest.go](/home/kali/cau/cmd_selftest.go:233), [cmd_selftest.go](/home/kali/cau/cmd_selftest.go:270), [cmd_selftest.go](/home/kali/cau/cmd_selftest.go:287)

### A clean Arch package install lacks the `cau` account required by its units

The Arch `PKGBUILD` installs the systemd units but has no install hook or sysusers file to create `cau`. The scan, daemon, and update units specify `User=cau`/`Group=cau`; Debian postinst and RPM `%pre` create that account, while a clean Arch install does not. Enabling the packaged units fails until the operator creates it manually, and the Arch install guide does not mention the prerequisite. [PKGBUILD](/home/kali/cau/packaging/arch/PKGBUILD:49), [cau-scan.service](/home/kali/cau/packaging/systemd/cau-scan.service:32), [cau.postinst](/home/kali/cau/debian/cau.postinst:8), [cau.spec](/home/kali/cau/packaging/rpm/cau.spec:71), [installation.md](/home/kali/cau/docs/installation.md:139)

### The `/etc` quarantine exclusion checks an unnormalised path string

`Quarantinable` rejects only strings beginning `/etc/`. A path such as `/tmp/../etc/cron.d/job` passes that check, while `Store.Quarantine` later calls `filepath.Abs`, which cleans the traversal and operates on `/etc/cron.d/job`. If a local file signal preserves such a path, the intended “never quarantine system configuration” policy is bypassed. [correlate.go](/home/kali/cau/internal/correlate/correlate.go:330), [quarantine.go](/home/kali/cau/internal/quarantine/quarantine.go:168)

### An incomplete YARA scan can still produce a clean verdict and exit status

When YARA returns an error or times out, `ScanFile` adds a warning but leaves `Error` and `Verdict` unchanged if YARA found no partial matches. The JSON report retains the warning while labelling the file `clean`; scan-error exit handling only sees actual file errors. Consumers that key on verdict or exit status can therefore treat an artifact as fully scanned when YARA stopped early. [engine.go](/home/kali/cau/scanner/engine.go:468), [engine.go](/home/kali/cau/scanner/engine.go:476), [json.go](/home/kali/cau/internal/report/json.go:1036), [cli.md](/home/kali/cau/docs/cli.md:291)

### Large-file hashes and YARA results can describe different file contents

Above the in-memory threshold, `ScanFile` hashes by opening the path, then the YARA detector separately opens it later. If a writable scanned path is replaced or modified between those reads, the result can combine hashes from one version with YARA matches from another, misattributing evidence to the path and digest shown in the report. [engine.go](/home/kali/cau/scanner/engine.go:402), [engine.go](/home/kali/cau/scanner/engine.go:471), [scanner.go](/home/kali/cau/scanner/scanner.go:456), [yara.go](/home/kali/cau/scanner/yara.go:410), [yara.go](/home/kali/cau/scanner/yara.go:506)

### The signed selftest baseline does not authenticate resource paths

`Manifest.SigningBytes` signs each entry’s name, digest, and directory flag but omits `Path`. `selftest.Verify` then trusts the path from the manifest when recomputing that digest. Someone able to edit the manifest but without the signing key can redirect an entry to a clean copy of a resource while keeping the signature valid; the defender’s selftest layer can then miss drift in the active resource. [selftest.go](/home/kali/cau/internal/selftest/selftest.go:257), [selftest.go](/home/kali/cau/internal/selftest/selftest.go:267), [selftest.go](/home/kali/cau/internal/selftest/selftest.go:316), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1158), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1171)

### A truncated TAXII page can advance the saved cursor past objects not ingested

`FetchTAXII` records `X-TAXII-Date-Added-Last` for the whole response before enforcing `maxObjects`. If the object cap is reached partway through a page, `cmd intake` still saves that response-level timestamp as the next `added_after` cursor. Remaining objects in the page can then be skipped on the next poll. The TAXII specification defines this header as the date of the response’s last object and `added_after` as selecting objects later than the given timestamp. [taxii.go](/home/kali/cau/internal/intake/taxii.go:227), [taxii.go](/home/kali/cau/internal/intake/taxii.go:234), [cmd_intake.go](/home/kali/cau/cmd_intake.go:135), [cmd_intake.go](/home/kali/cau/cmd_intake.go:138), [TAXII 2.1 specification](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)

### Feed text matching silently ignores indicators after fixed candidate limits

`MatchText` examines only the first 256 URLs, 256 IP literals, and 512 domains. A script or command line can place more ordinary candidates before a listed bad indicator, which is then skipped without any truncation warning. This creates an order-dependent false negative in package and process intelligence matching. [intel.go](/home/kali/cau/internal/intel/intel.go:277), [intel.go](/home/kali/cau/internal/intel/intel.go:288), [intel.go](/home/kali/cau/internal/intel/intel.go:293), [vectors.go](/home/kali/cau/scanner/linuxpkg/vectors.go:154), [procscan.go](/home/kali/cau/internal/procscan/procscan.go:231)

### Abuse feeds larger than 128 MiB are accepted as complete after truncation

`intel.Parse` reads through a `LimitReader` capped at 128 MiB but never checks whether more input remains. Local and remote feed loaders pass another reader with the same cap, so an oversized feed can be saved as a successful partial feed with indicators after the cutoff silently omitted. [intel.go](/home/kali/cau/internal/intel/intel.go:89), [intel.go](/home/kali/cau/internal/intel/intel.go:97), [cmd_feed.go](/home/kali/cau/cmd_feed.go:344), [cmd_feed.go](/home/kali/cau/cmd_feed.go:353)

### A provenance write failure can permanently lose intake provenance

Intake commits new signatures before appending their provenance records. If the provenance append fails, a retry sees those hashes as already present, and `Apply` only returns newly accepted indicators, so it cannot regenerate the missing records. The command reports the first failure but leaves the database and provenance log inconsistent. [cmd_intake.go](/home/kali/cau/cmd_intake.go:168), [cmd_intake.go](/home/kali/cau/cmd_intake.go:174), [cmd_intake.go](/home/kali/cau/cmd_intake.go:217), [intake.go](/home/kali/cau/internal/intake/intake.go:596), [intake.go](/home/kali/cau/internal/intake/intake.go:605)

### Persistence scans can report “no detections” after paths fail to read

`persist.read` and `persist.list` turn open, scan, and directory-read failures into empty results without recording an incomplete-coverage status. The CLI can still print “No persistence detections” and exit successfully, so inaccessible paths are indistinguishable from clean or absent locations. [persist.go](/home/kali/cau/internal/persist/persist.go:169), [persist.go](/home/kali/cau/internal/persist/persist.go:175), [persist.go](/home/kali/cau/internal/persist/persist.go:193), [persist.go](/home/kali/cau/internal/persist/persist.go:203), [cmd_persist.go](/home/kali/cau/cmd_persist.go:86), [cmd_persist.go](/home/kali/cau/cmd_persist.go:90)

### ZIP member limits are applied after the central directory is materialized

`zip.NewReader` builds the full `zr.File` entry list before `analyzeZip` checks `maxMembers`. A ZIP with a very large central directory can therefore allocate substantial per-entry memory before the 100,000-member cap is reached; concurrent scans can multiply that memory use. [archive.go](/home/kali/cau/scanner/archive/archive.go:473), [archive.go](/home/kali/cau/scanner/archive/archive.go:476), [archive.go](/home/kali/cau/scanner/archive/archive.go:483), [archive.go](/home/kali/cau/scanner/archive/archive.go:38)

### Import clustering can do quadratic work for identical signatures

Files with the same non-empty import signature are already united in the exact-imphash pass, but the LSH pass still enumerates their shared buckets, computes pairwise similarities, and stores every pair in `checked`. A large set of identical or near-identical binaries can therefore cause O(n²) comparisons and pair-map memory despite already being in the same exact group. [cluster.go](/home/kali/cau/scanner/static/cluster.go:157), [cluster.go](/home/kali/cau/scanner/static/cluster.go:189), [cluster.go](/home/kali/cau/scanner/static/cluster.go:197)

### LNK ExtraData blocks after the 64th are silently ignored

The parser stops after `maxExtraBlocks` without marking the parse incomplete. A shortcut can place path-bearing environment or icon blocks after 64 valid blocks; those targets are then omitted from detection while the result carries no truncation warning. [lnk.go](/home/kali/cau/scanner/lnk/lnk.go:481), [lnk.go](/home/kali/cau/scanner/lnk/lnk.go:512), [lnk.go](/home/kali/cau/scanner/lnk/lnk.go:533)

### ISO directory subtrees beyond the queue cap disappear without an incomplete result

When the queued-directory count reaches 20,000, later directory records are retained as entries but their extents are not queued for traversal. The image result has no warning or partial marker, so malicious files inside those subtrees can be missed while the inventory looks complete. [iso9660.go](/home/kali/cau/scanner/iso/iso9660.go:60), [iso9660.go](/home/kali/cau/scanner/iso/iso9660.go:291)

### Ingest drops events after reaching `MaxEvents` but advances past them

`readFile` parses the full newly appended region and advances the path offset before `Collect` truncates the combined results to `MaxEvents`. When one file contains more events than the remaining pass budget, the discarded signals are already consumed and will not appear on the next pass, despite the warning saying they will be read then. [ingest.go](/home/kali/cau/internal/ingest/ingest.go:384), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:391), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:486), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:505)

### Replaced ingest files can skip their new prefix

Offsets are keyed only by pathname. A replacement or rotation is detected only when the new file is smaller than the saved offset; if the replacement is at least as large, the reader seeks to the old offset and permanently misses the beginning of the new file. [ingest.go](/home/kali/cau/internal/ingest/ingest.go:368), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:460), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:463), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:470)

### An overlong JSONL record blocks all later records in that file

The scanner has a 1 MiB maximum line size. On an oversized line, it reports the scanner error but saves the offset only through preceding complete lines. Every later pass retries from the same oversized line and stops there again, so valid records after it are never ingested. [ingest.go](/home/kali/cau/internal/ingest/ingest.go:475), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:476), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:501), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:505)

### Informational external telemetry can corroborate a local response

The OCSF parser reads `is_alert` but does not use it, and accepts any non-empty message or finding text; unknown and informational severity score 1. Correlation joins external events and local signals by peer across hosts, then treats any two layers as confirmation. `PlanFor` has no minimum-score check when an external peer corroborates a local process or network signal, so a low-confidence event can help stop a local PID or block its peer. [ingest.go](/home/kali/cau/internal/ingest/ingest.go:225), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:265), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:297), [correlate.go](/home/kali/cau/internal/correlate/correlate.go:189), [correlate.go](/home/kali/cau/internal/correlate/correlate.go:273), [correlate.go](/home/kali/cau/internal/correlate/correlate.go:379), [correlate.go](/home/kali/cau/internal/correlate/correlate.go:411), [correlate.go](/home/kali/cau/internal/correlate/correlate.go:421)

### Inotify watch failures leave silent real-time coverage gaps

The recursive watch setup discards directory-walk errors and ignores `InotifyAddWatch` failures without setting `truncated`. Startup reports only the explicit directory-count cap, so watch-limit exhaustion or inaccessible subtrees can go unnoticed and rely on later periodic sweeps. [watch_linux.go](/home/kali/cau/internal/watch/watch_linux.go:91), [watch_linux.go](/home/kali/cau/internal/watch/watch_linux.go:110), [cmd_defend.go](/home/kali/cau/cmd_defend.go:2317), [cmd_defend.go](/home/kali/cau/cmd_defend.go:2318)

### MCP stdio accepts unbounded request lines

The stdio server calls `ReadBytes('\n')` without a line-size limit. A newline-free request can grow the buffer in proportion to the input before JSON decoding, while the HTTP transport enforces a 4 MiB body cap. [server.go](/home/kali/cau/internal/mcp/server.go:142), [server.go](/home/kali/cau/internal/mcp/server.go:271), [http.go](/home/kali/cau/internal/mcp/http.go:24), [http.go](/home/kali/cau/internal/mcp/http.go:82)

### UEFI firmware inventory caps silently omit later structures

The FFS walk, section walk, and volume search stop at their structural caps without setting a partial or truncation field. Malicious modules or executable sections after those limits are omitted, while `NotInspected` describes compression and disassembly limits only. [uefi.go](/home/kali/cau/scanner/uefi/uefi.go:29), [uefi.go](/home/kali/cau/scanner/uefi/uefi.go:296), [uefi.go](/home/kali/cau/scanner/uefi/uefi.go:358), [uefi.go](/home/kali/cau/scanner/uefi/uefi.go:427), [uefi.go](/home/kali/cau/scanner/uefi/uefi.go:204)

### MBR logical-partition boot sectors are not scanned

The MBR parser returns only the four primary entries and does not walk extended boot records. `AnalyzeDisk` scans the first sector of each returned partition, which checks the extended container entry but omits VBRs belonging to logical partitions. [disk.go](/home/kali/cau/internal/bootscan/disk.go:219), [disk.go](/home/kali/cau/internal/bootscan/disk.go:248), [disk.go](/home/kali/cau/internal/bootscan/disk.go:269)

### Backup-only GPT recovery does not report invalid partition-entry integrity

When the primary GPT header is missing, the recovery path reads the backup entry array and records whether its CRC is valid, but never emits the `gpt.entries-crc-invalid` finding used in the primary-header path. A bad or unreadable backup array can therefore yield a recovery report with incomplete partitions and only the primary-header finding. [disk.go](/home/kali/cau/internal/bootscan/disk.go:450), [disk.go](/home/kali/cau/internal/bootscan/disk.go:467), [disk.go](/home/kali/cau/internal/bootscan/disk.go:471), [disk.go](/home/kali/cau/internal/bootscan/disk.go:484), [disk.go](/home/kali/cau/internal/bootscan/disk.go:493)

### Invalid PE certificate-table offsets can make an EFI binary look signed

The PE inspector sets `Signed` when the certificate-directory offset and size fields are merely nonzero. It does not check that the file-offset range is in bounds or contains a certificate entry, so forged directory values can suppress the unsigned-EFI finding even when no certificate table is present. [esp.go](/home/kali/cau/internal/bootscan/esp.go:133), [esp.go](/home/kali/cau/internal/bootscan/esp.go:148), [esp.go](/home/kali/cau/internal/bootscan/esp.go:281), [esp.go](/home/kali/cau/internal/bootscan/esp.go:284)

### Old kernel-guard events can be attached to a reused PID and trigger a response

The kernel-event log retains recent historical records, but the event schema has no timestamp or process-start identity. Matching uses TGID plus a matching comm or executable basename; a later process that reuses the PID and name can inherit the old conclusive finding, which can then stop the new process. [kernel.go](/home/kali/cau/internal/procscan/kernel.go:17), [kernel.go](/home/kali/cau/internal/procscan/kernel.go:42), [kernel.go](/home/kali/cau/internal/procscan/kernel.go:60), [kernel.go](/home/kali/cau/internal/procscan/kernel.go:76), [respond.go](/home/kali/cau/internal/procscan/respond.go:32), [cmd_defend.go](/home/kali/cau/cmd_defend.go:1586)

### A process can be stopped when its shell input and output use different peers

`stdioPeer` checks that both descriptors map to established TCP connections, but it does not verify they map to the same peer. It reports the stdin peer as if both streams used it; this conclusive shell finding can stop an interpreter that has separate legitimate input and output connections. [netshell.go](/home/kali/cau/internal/procscan/netshell.go:96), [netshell.go](/home/kali/cau/internal/procscan/netshell.go:102), [netshell.go](/home/kali/cau/internal/procscan/netshell.go:104), [procscan.go](/home/kali/cau/internal/procscan/procscan.go:331), [respond.go](/home/kali/cau/internal/procscan/respond.go:32)

## P3 — Lower impact

### Eval report, diff, and gate accept unknown output formats as text

These subcommands document `text` or `json` but treat every value other than exactly `json` as text and exit successfully. A typo such as `--format=jsno` is not rejected. [cmd_eval.go](/home/kali/cau/cmd_eval.go:354), [cmd_eval.go](/home/kali/cau/cmd_eval.go:390), [cmd_eval.go](/home/kali/cau/cmd_eval.go:419)

### Arch `.SRCINFO` omits the `logrotate` optional dependency

`PKGBUILD` advertises `logrotate`, but the committed `.SRCINFO` omits it. AUR helpers consuming `.SRCINFO` will not prompt for the rotator even though the package installs its config and the resident defend service can grow `/var/log/cau`. [PKGBUILD](/home/kali/cau/packaging/arch/PKGBUILD:11), [.SRCINFO](/home/kali/cau/packaging/arch/.SRCINFO:16), [packaging.md](/home/kali/cau/docs/packaging.md:126)

### Network scan undercounts unreadable processes

`readProc` sets `p.partial` when the executable or network-namespace link cannot be read, then overwrites it with the result from `socketInodes`. If the FD directory is readable, those earlier failures disappear from the `unreadable` count, understating missing attribution. [proc.go](/home/kali/cau/internal/netscan/proc.go:265), [proc.go](/home/kali/cau/internal/netscan/proc.go:272), [proc.go](/home/kali/cau/internal/netscan/proc.go:277)

### Repeated feed updates grow duplicate CIDRs and slow IP matching

Unlike the map-backed indicator kinds, CIDRs are appended without deduplication during both parse and merge. Reapplying an overlapping feed grows the saved cache with duplicates, while every IP candidate scans the full CIDR slice linearly. Large feeds and repeated refreshes therefore increase both storage and per-match work. [intel.go](/home/kali/cau/internal/intel/intel.go:94), [intel.go](/home/kali/cau/internal/intel/intel.go:138), [intel.go](/home/kali/cau/internal/intel/intel.go:224), [intel.go](/home/kali/cau/internal/intel/intel.go:316)

### Directory scans retain all per-file results until the walk finishes

`ScanDirectory` keeps every entry and full `ScanResult`, then allocates another result slice after workers finish. Peak memory grows with the total number of files and findings rather than only with active workers; large tree scans could benefit from a streaming result/report path. [engine.go](/home/kali/cau/scanner/engine.go:761), [engine.go](/home/kali/cau/scanner/engine.go:769), [engine.go](/home/kali/cau/scanner/engine.go:834)

### Fuzzy matching performs a full database pass for every file

`FuzzyDB.Lookup` compares each TLSH or ssdeep digest with every entry. For F scanned files and D fuzzy indicators, the work is O(F×D), which can dominate as the database grows; the source comments already identify indexing as a future need. [fuzzy.go](/home/kali/cau/scanner/static/fuzzy.go:338), [fuzzy.go](/home/kali/cau/scanner/static/fuzzy.go:353), [fuzzy.go](/home/kali/cau/scanner/static/fuzzy.go:366)

### Streaming hashes launch and join three goroutines for every 1 MiB chunk

`hashReader` calls `parallel.Do` for each chunk, and `Do` creates three goroutines and waits for them each time. Multi-gigabyte inputs cause thousands of short-lived goroutine batches; persistent workers or a measured sequential path may improve throughput. [scanner.go](/home/kali/cau/scanner/scanner.go:465), [scanner.go](/home/kali/cau/scanner/scanner.go:469), [scanner.go](/home/kali/cau/scanner/scanner.go:475), [parallel.go](/home/kali/cau/internal/parallel/parallel.go:95)

### PDF name detection counts tokens inside strings, comments, and stream data

`scanNames` searches raw bytes for `/Name` tokens without tracking PDF lexical context. Text such as `(/OpenAction /JavaScript)` or matching bytes in comments/streams can therefore produce automatic-action or JavaScript findings even though those names are not active PDF objects. [pdf.go](/home/kali/cau/scanner/pdf/pdf.go:272), [pdf.go](/home/kali/cau/scanner/pdf/pdf.go:279), [pdf.go](/home/kali/cau/scanner/pdf/pdf.go:404), [pdf.go](/home/kali/cau/scanner/pdf/pdf.go:424)

### Concurrent ingest collections can emit the same records more than once

`Reader` is documented as safe for concurrent use, but each call reads the saved offset and releases the lock before seeking and parsing. Two concurrent `Collect` calls can both read the same range before either updates the offset, duplicating signals. [ingest.go](/home/kali/cau/internal/ingest/ingest.go:366), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:460), [ingest.go](/home/kali/cau/internal/ingest/ingest.go:504)

### Process-scan command lines, environments, and maps are silently truncated

`readSmall` does not report when it reaches its byte limit, while procscan caps cmdline and environ at 64 KiB and maps at 4 MiB; mapped paths also stop after 4,096 entries. Relevant argv, `LD_PRELOAD`/`LD_LIBRARY_PATH`, or injected mappings beyond those caps are omitted without a partial-scan warning. [procscan.go](/home/kali/cau/internal/procscan/procscan.go:61), [read.go](/home/kali/cau/internal/procscan/read.go:31), [read.go](/home/kali/cau/internal/procscan/read.go:51), [read.go](/home/kali/cau/internal/procscan/read.go:84), [read.go](/home/kali/cau/internal/procscan/read.go:107), [read.go](/home/kali/cau/internal/procscan/read.go:139)

### EFI `BootOrder` truncation is not marked partial

The parser stops collecting the `BootOrder` variable after 256 IDs but does not add a note or set `BootEntriesPartial`. The later cap on enumerated `Boot####` variables does set both, so a longer order list is silently incomplete in reports and baselines. [efi.go](/home/kali/cau/internal/bootscan/efi.go:283), [efi.go](/home/kali/cau/internal/bootscan/efi.go:285), [efi.go](/home/kali/cau/internal/bootscan/efi.go:297), [efi.go](/home/kali/cau/internal/bootscan/efi.go:300)

### EFI signature lists accept a partial trailing signature entry

The parser floors `len(body)/sigSize` and advances past the whole declared list without checking for a remainder. A DBX list with a partial trailing entry is returned as parsed, with the incomplete bytes omitted from its counts and no unparsed indicator. [efi.go](/home/kali/cau/internal/bootscan/efi.go:433), [efi.go](/home/kali/cau/internal/bootscan/efi.go:445), [efi.go](/home/kali/cau/internal/bootscan/efi.go:448), [efi.go](/home/kali/cau/internal/bootscan/efi.go:464)

### MCP stdio discards response-write errors

`Server.write` ignores `json.Encoder.Encode` errors, so a broken output pipe does not stop request dispatch or reach `Serve` as the documented I/O error. A state-changing tool can complete while its caller receives no acknowledgment. [server.go](/home/kali/cau/internal/mcp/server.go:222), [server.go](/home/kali/cau/internal/mcp/server.go:228)

### Shared sockets are attributed to only one process

When multiple processes hold the same socket inode, `readSockets` keeps only the lowest PID and reports the socket against that process. A forked child or other co-owner can therefore lose its process-level network finding, or the socket can be attributed to the wrong executable. [proc.go](/home/kali/cau/internal/netscan/proc.go:144), [proc.go](/home/kali/cau/internal/netscan/proc.go:153), [proc.go](/home/kali/cau/internal/netscan/proc.go:160), [proc.go](/home/kali/cau/internal/netscan/proc.go:197)

### Beacon cadence can merge different processes using the same executable and peer

Beacon tracks are keyed by executable and remote endpoint without PID or network namespace. Observations from separate processes can combine into one cadence and the final finding is assigned to whichever PID was processed last, creating false timing patterns or incorrect attribution. [beacon.go](/home/kali/cau/internal/netscan/beacon.go:115), [beacon.go](/home/kali/cau/internal/netscan/beacon.go:158), [beacon.go](/home/kali/cau/internal/netscan/beacon.go:194)

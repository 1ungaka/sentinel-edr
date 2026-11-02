# ADS: Static structure

## Goal
Flag files that are built like something that hides: packed, tampered,
implausibly signed, loader-hijacking or malformed PE, ELF and Mach-O images,
and files similar to known samples.

## Categorization
Anomaly classes map to T1027 (.002, .007, .009), T1036 (.001), T1070.006,
T1553.002, T1574 (.006) and T1014; similarity matches carry a sample name,
not a technique. The full class catalog is `static.Classes()` and the table
in [Detectors](../detectors.md). Pyramid of Pain: TTPs (structure),
hash values (similarity). Tier: SUSPICIOUS.

## Strategy Abstract
Own bounds-checked PE, ELF and Mach-O parsers read sections or segments, entry
point, imports, build record, Authenticode/code-signature presence, overlay,
packer markers, dynamic table and kernel-module info. ELF deep-resolution
resolves `.init_array` constructor targets through the relocations, reads symbol
versions, and flags a raw-syscall libc interposer. Each observation is a labeled
class with a weight and a capped category; the threshold (8) needs several
independent things to be wrong. TLSH, ssdeep, imphash and telfhash are matched
against the fuzzy database as a separate `similarity` source.

## Technical Context
Packed is not malicious: a recognised packer weighs less because the report
names it. Signature presence is not validity: nothing is verified against a
trust store and `verified` is always false. Delphi's constant timestamp,
kernel drivers' RWX `INIT`, MinGW's `msvcrt.dll`, reproducible builds,
sanitizer runtimes and other known interposers are explicit non-findings
because each one was a false positive on the first measurement pass.

## Blind Spots and Assumptions
An unpacked, unsigned, plainly linked credential dumper looks ordinary (that
is the heuristic pass's job). Packed samples are identified, not unpacked (the
NOVEL-012 peeler walks encoding/compression layers separately). PE, ELF and
Mach-O are parsed here; OLE, PDF, LNK and ISO have their own detectors and
Linux packages the `linuxpkg` pass; CHM, UEFI/firmware and recursive archive
members are not parsed yet.

## False Positives
PE: none above the threshold on 49 tool-set binaries; UPX-packed `wget.exe`
scores 7 and ASPack-packed `klogger.exe` 6, both rendered as low suspicion
with the packer named. ELF: 0 of 4,974 system files and 40 kernel modules
reach the threshold; 21 carry one weight-1 observation (launcher stubs,
vendor section names); a UPX-packed `ls` scores 6.

## Validation
Synthetic PE and ELF fixtures in `scanner/static/*_test.go` pin every class;
`TestClassCatalogMatchesSource` pins the published catalog to the emitting
code; the smoke corpus has a dropper-profile ELF as the detector's true
positive (`make eval`).

## Priority
Medium; a self-signed certificate wearing a vendor name crosses alone and is
the one class worth treating as high.

## Response
Read the classes: a packer name plus nothing else is provenance work
(is this package supposed to be packed?); a forged build record, a loader
hijack or an appended high-entropy payload is triage.

# ADS: YARA

## Goal
Detect files containing patterns a rule author described: strings, byte
sequences and their combinations, with the rule's meta carried into the
report.

## Categorization
Per rule, from `meta.mitre_attack` (bundled rules: T1003, T1027.007,
T1059.001, T1486, T1555). Pyramid of Pain: tools. Tier: MALICIOUS.

## Strategy Abstract
Rules are compiled once at startup with libyara and matched in memory, with
a per-file timeout. Every match carries the rule, namespace, tags, full meta
and the matched strings at their offsets. A hit is definitive for the fusion
lattice.

## Technical Context
A rule file that does not compile is reported with position and skipped;
compiler warnings are shown, not suppressed. Bundled rules carry `ascii
wide` (the originals were ASCII-only and never fired on mimikatz.exe), hex
patterns as hex (two originals matched the text `"0x89,0x00"` and could never
fire), `threat_level`, `family` and `mitre_attack`. `cau rules lint` enforces
all of that; `cau rules list` prints the inventory. `highly_sus_shellcode`
was rewritten after it fired on `msdia140.dll` and missed every Metasploit
stub; new rules cover the Windows netcat lineage and wrapped PEASS. The
loose `.locked` / `.encrypted` / `.crypt` ransomware rule now requires a
ransom-note name beside the extensions to stop the 18 Go-binary false
positives it had.

## Blind Spots and Assumptions
An author who knows the ruleset: renamed strings, encrypted payloads, split
patterns. Nothing inside an unpacked layer the file does not expose. The
bundled set is small; production coverage comes from signature-base,
Yara-Rules or the MalwareBazaar export via `--rules`.

## False Positives
Measured over Kali's Windows tool set and `/usr/bin`: hits on mimikatz, wce,
PowerSploit, one dual-use tool (ophcrack embeds mimikatz command strings) and
nothing else. The loose ransomware-extension rule hit 18 Go binaries until it
required a ransom-note name beside the extensions.

## Validation
`corpus/smoke/malicious/wannacry_strings.bin` and `mimikatz_strings.bin` must
hit (`make eval`); `make lint-rules` must pass; the coverage gate must list
each rule's technique.

## Priority
High for `threat_level` 4-5, medium below; SARIF and OCSF carry the level.

## Response
Read the matched strings in the report before acting: they say which part of
the rule fired. Quarantine on family rules; triage on generic ones.

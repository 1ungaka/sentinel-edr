# ADS: Tradecraft

## Goal
Surface files by what they do, when they name no known family and have no
structure to be odd about: web shells, network shells, in-memory loaders,
shellcode, GTFOBins / LOLBAS abuse, trusted-SaaS command channels and the
specific EDR-bypass primitives red teams use. Raw bytes, bytes inside an
executable, and bytes carried as an array or encoded blob in text are all read
through the same checks.

## Categorization
Technique per class in [Detectors](../detectors.md#tradecraft): T1505.003, T1059
and its children, T1620, T1027 and its children, T1562.001, T1003, T1134, T1021,
plus the newer rows T1548.001 (setuid), T1548.003 (sudo), T1102 / T1102.002 (web
service / dead-drop), T1556.003 (PAM backdoor), T1543.002 (systemd hijack),
T1574.006 (`LD_PRELOAD` shim), T1036.005 (process-name camouflage), T1070.004
(self-delete), T1095 (ICMP C2), T1071.004 (DNS TXT C2), T1090.004 (domain
fronting) and T1001.003 (open-redirect channel). Pyramid of Pain: TTPs. Tier:
SUSPICIOUS.

## Strategy Abstract
Script vectors match behaviour in text and require a source and a sink where the
behaviour has both, so a request parameter and an exec call must both be
present. Byte checks follow what position-independent code must do: find APIs
with no import table, learn its own address, decode itself in place, or issue
socket syscalls by hand. Carriers are decoded and analysed again, so every
encoding of a payload meets the same checks. The GTFOBins pass names
abuse-shaped breakouts (`sudo <bin> -exec /bin/sh`, `sh -p` from a setuid
binary, `pty.spawn`, `:!sh` in an editor) — the escape syntax, not the tool
name. The SaaS-C2 pass draws on the lolol.farm family
([LOLC2](https://lolc2.github.io), [LOLFSaaS](https://lolfsaas.github.io),
[LOTTunnels](https://lottunnels.github.io), [LOTWebhooks](https://lotwebhooks.github.io)):
naming a host corroborates (score 3), hitting an abusable API path like
`graph.microsoft.com/v1.0/me/sendMail` or a firebaseio realtime-DB write
convicts harder (score 5). The bypass pass reads the ArcticFox detection-bypass
catalogue and fires only on pairings (`memfd_create` + `execveat`,
`prctl(PR_SET_NAME)` + a socket, `/etc/ld.so.preload` written, `pam_exec.so`
added to a PAM stack, `systemctl edit --full` on a real unit, `/proc/self/exe`
unlink, raw `IPPROTO_ICMP` socket + payload decode, `dns.resolver` TXT +
base64). Classes at 8 or above are a verdict alone; below that, two must agree.

## Technical Context
`scanner/tradecraft`: `script.go` (vectors and the PHP taint walk),
`extra_vectors.go` (GTFOBins breakouts and LOLBAS gap-fills, registered via
`init`), `c2_cloud_vectors.go` (the lolol.farm catalogues as abuse-shaped
vectors with a per-service hint for the walker's substring short-circuit),
`bypass_vectors.go` (the ArcticFox detection-bypass primitives), `shellcode.go`
(byte checks), `carrier.go` (decoders and their bounds), `catalog.go` (the
single table of class, score, technique and meaning). Classes flow into the
coverage matrix through `tradecraft.Classes()`, so every row is gated by
`baselines/attack-coverage.txt` and the `cau coverage` check.

## Blind Spots and Assumptions
Tailored encryption: a payload under a key the file does not carry in a
recognised form presents no bytes to check, and an encoder that avoids GetPC
idioms presents no stub. Runtime-assembled code, API hashing with a non-rotate
function, and language constructs outside the vectors. UPX-packed binaries are
not unpacked. The taint walk is textual and ignores scope. Files that only do
something dangerous when combined with others (a module loader, a tool's
helper) carry no behaviour of their own and are not detected. The SaaS-C2
vectors see hostnames and API paths; they cannot see real network traffic, so a
binary that only speaks to `graph.microsoft.com` through an opaque buffer and
builds no literal URL strings presents nothing. The bypass pass is deliberate
about pairing — a `memfd_create` call alone, a `prctl(PR_SET_NAME)` alone or a
plain `dns.resolver.resolve(..., 'A')` stay quiet; only a bypass-shaped
combination fires. Text is read to 4 MiB; payload checks run to 64 MiB.

## False Positives
Example scripts that really are reverse shells (netcat and WireGuard
documentation under `/usr/share/doc`). Security tooling and its documentation.
A legitimate Microsoft 365 integration that calls Graph mail endpoints, a
monitoring tool that polls Firebase, a development script that calls OpenAI or
Anthropic — all name real abused hosts from the lolol.farm catalogue, so the
channel class fires at score 3 (corroborating) and crosses threshold only with
a second finding. GTFOBins shapes stay quiet on plain `sudo sh -c`, `ssh -p
22`, `chmod 4755 /usr/bin/ping` and `find -exec sh -c`, because the vectors
look for the GTFOBins-specific escape syntax, not the tool. The bypass pass
pairs two sub-signals: `memfd_create` for Go temp files, `prctl(PR_SET_NAME)`
in the runtime, `dns.resolver` TXT for SPF, or an `/etc/ld.so.preload` *read*
by an integrity checker all stay quiet because no exec, socket or decode
accompanies them. Figures are in [Limitations](../limitations.md).

## Validation
`go test ./scanner/tradecraft/`, which pins each vector on inert text, benign
near-neighbours of each vector, each carrier, and the decoding bounds, and
which has dedicated positive and quiet cases for every GTFOBins breakout,
SaaS-C2 host, SaaS-API-abuse path and ArcticFox bypass primitive; `FuzzAnalyze`
for robustness; `make eval-lab` for recall against real tooling; `make eval`
for the regression gate (FPs 0→0, recall unchanged across the shipped corpora).

## Priority
High when a `webshell`, `netshell` or `shellcode` class fires on a file in a
web root, a temporary directory or a user-writable path. Medium for
`tradecraft.script.*` combinations in a location where administrators keep scripts.

## Response
Read the evidence and the decoded chain in the report. Check where the file is
and who wrote it. For a web shell, review web-server logs for requests to that
path; for a network shell or loader, run `cau ps` to see whether it is live and
`cau persist` to see what would bring it back. Quarantine with
`cau quarantine add`, which keeps the bytes for analysis.

# ADS: Obfuscation chain

## Goal
Find a payload stacked behind several layers of encoding, compression or simple
ciphers, and treat the stack itself as evidence. Software rarely hides anything
behind three layers, and the shape of a chain outlives any one payload.

## Categorization
T1027 (Obfuscated Files or Information), NOVEL-012. The classes are
`peel.revealed-executable`, `peel.revealed-script` and `peel.exhausted`.

## Strategy Abstract
`internal/peeler` walks a tree. At each node every layer that applies decodes at
once, and each result opens a branch, so a blob read as base64 and as hex is
explored both ways, and a script holding three payloads is three chains. A branch
ends at a recognised executable or script. One budget covers the whole tree:
512 nodes, 64 MiB of decoded output, depth 32, 6 branches per node and 5 seconds.
Nothing is ever executed.

| Layers | |
|---|---|
| Bases | 2, 8, 10, 16, 32 and its variants, 36, 45, 58, 62, 64, 85 and its variants, 91, 92, and byte lists such as `0x48,0x65` |
| Substitutions | every Caesar shift, rot5, rot18, rot47, atbash, reversal |
| Other | gzip, zlib, raw deflate, bzip2, UTF-16, blobs carved out of a script |

A chain is a stable signature such as `carve>base64>rot13>flate`, which is the
family key. See [Detectors](../detectors.md#obfuscation-chain-peeler).

## Technical Context
The gates are what make the detector usable, because each layer adds to a score
and most decoders can be made to succeed on ordinary input.

- A base decoder's output must be a known format or clean text. The wrong base
  gives noise, so a wrong guess is dropped.
- A substitution must reveal something. Rotating text only gives more text, so
  plain rotated text is never a layer, whatever the shift.
- A carve must find a payload inside the run, through any encodings. Text is not
  enough, or a file of test vectors would open a branch per line. A carve is also
  not counted as a layer, because it decodes nothing.

## Blind Spots and Assumptions
- Encryption with a key. The peeler reverses encodings and fixed substitutions,
  and it does not guess keys, including single-byte XOR.
- A rotation is judged on its first 4 KiB, so a payload behind 4 KiB of padding
  that reveals nothing is not found by rotation.
- A whole-number base (36, 58, 62) is read up to 64 KiB, because its decode is
  quadratic.
- A script split into short fragments and joined at run time is not carved: a run
  must be at least 64 characters, and fragments are not reassembled.
- A chain is bounded by the budget. Hitting it is reported as `peel.exhausted`
  rather than clean, but what lay past the wall stays unseen.
- A payload that is neither an executable nor recognisably a script ends its
  branch without a finding.

## False Positives
Measured over 116,885 benign files from `/usr/bin`, `/usr/share/doc`, Python
packages and nmap's data: 10 revealed payloads and 0 budget exhaustions. All 10 are
real encoded payloads inside offensive tooling on a Kali host: 8 Metasploit exploit
documents and 2 `lsassy` embedded dumpers. A hit in that kind of file is correct and
expected. There is no measurement on an ordinary host yet.

## Validation
`go test ./internal/peeler -run TestMeasureRealPeel -v` repeats the measurement and
names every offender. `TestEveryBaseCarriesAChain` and
`TestEveryCipherCarriesAChain` prove each layer end to end, and
`TestBenignTwinsStayClean` holds the traps: prose, source code, minified JavaScript,
JSON, hash lists, tokens, wrapped text and data URIs. To see a chain:

```sh
cau peel --stream ./dropper.b64
```

## Priority
Medium alone. A depth-2 revealed executable scores 60 and crosses the threshold of
50, and a script needs depth 3 or a substitution. A chain raises the verdict through
the fusion lattice's `peel-revealed` path when a behavioural detector also flags
what was revealed.

## Response
Read the chain signature first: it says how the payload was hidden. Peel the sample
in isolation, then scan what it reveals. A cipher layer on its own is a strong
signal, because no packaging tool writes one. A hit in security documentation or a
pentest toolkit is usually correct and not an incident.

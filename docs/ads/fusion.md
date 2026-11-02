# ADS: Fusion

## Goal
Make corroboration count: a file that two detectors with uncorrelated error
modes both saw, each below its own threshold, is reported SUSPICIOUS with the
sources that agreed named.

## Categorization
The union of the agreeing evidence's ATT&CK and NOVEL ids. Tier: raises
CLEAN to SUSPICIOUS, never lowers anything; hash and YARA hits are definitive.

## Strategy Abstract
Each scored source becomes a ratio score/threshold capped at 1.5. The
strongest source counts in full; every other source at or above 0.4 of its
threshold corroborates at half weight. The fused score reaches 1.0 when a
detector crosses alone, as before, or when corroboration adds up.

On top of that independent weighted sum is a **conditional chaining** layer (the
dependent half of the hybrid). A chain is a set of predicates that must each bind
to a distinct *counted* source; when they all match, it adds a small bounded
bonus and records the attack path it saw. The shipped chains are
`packed-and-injects` (static packer + heuristic T1055), `document-dropper`
(OLE/PDF/LNK/ISO vector + encoded executable, T1027.009), and `peel-revealed`
(peeler/encchain + a behavioural detector on the revealed content, T1027).
Chaining only adds, so the lattice stays monotone, and the total bonus is capped
(`DefaultChainCap` = 0.75) so it can never lift a verdict more than one
corroborating source would, and never resurrects evidence discarded below the
floor. The engine verdict uses `fusion.FuseChained`; the flat `fusion.Fuse` is
kept for library callers who want the weighted sum alone.

## Technical Context
`scanner/fusion` is independent of the engine's detectors: anything that
expresses itself as a score against a threshold or as a definitive hit can
join. The verdict carries tier, score, confidence, the agreed sources, every
source's role and evidence, an explanation and a `corroborated` flag that
marks the detections fusion added.

## Blind Spots and Assumptions
A file silent on every detector. The lattice never creates evidence, and
raising any input never lowers the fused score (a randomized test pins
this).

## False Positives
None observed: 0 fused-only detections and 0 new false positives on the 349
files of the Kali Windows tool set; the nearest benign file (UPX-packed
`wget.exe`, static 7/8) has no second source above the floor.

## Validation
`scanner/fusion/fusion_test.go` (monotonicity, floor and cap cases);
`scanner/fusion/chain_test.go` (chain matching, the distinct-source bipartite
assignment, the bonus cap); `scanner/engine_fusion_test.go`; the `fusion` eval
detector and the "Fused-only detections" summary line.

## Priority
Medium, with the confidence field as the tie-breaker: high confidence is two
strong sources, low is a primary barely over its floor.

## Response
The explanation line names the sources and their ratios; treat it as a
prompt to read both detectors' evidence, which is already in the same report.

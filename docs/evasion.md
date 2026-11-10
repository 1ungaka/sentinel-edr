# The evasion report

How fragile are the shipped detections? The evasion report answers that
question, per detector, with a number: **how many bytes have to change for
this detector to stop firing on this file?**

It is the credibility instrument the plan asks for, and it is deliberately
small. It measures the detection content's strength. It does not ship attacks,
it does not mutate samples, and it does not tell anyone where to put the
patch.

```sh
cau evasion report --file suspicious.bin
cau evasion bench --corpus corpus/smoke/manifest.json --db corpus/smoke/hashes.txt
```

## What the number means

Every distance is a **lower bound** on the bytes that must change, derived
from the detection's own evidence:

| Detector | The distance | Why it is exact |
|---|---|---|
| `hash` | 1 byte | any change to the file changes its digest, and the changed digest is not in the database |
| `yara` | 1 byte per match that has to break | the rule's condition decides how many of its strings have to go: in `a and b` one is enough, in `a or b` both are, in `3 of them` the count has to drop below three |
| `static` (overlay) | the overlay's size | removing the appended data removes the finding |
| `stego` | the bytes of the invisible codepoints | deleting them deletes the finding |
| `encchain` | 1 byte | one byte inside the encoded run changes what it decodes to |
| everything else | not derivable | the detection keys on a structure — a shortcut's arguments, a macro's entry point, a script's line — and "how many bytes is that" is not a number a finding carries |

A detector whose distance cannot be derived is reported as **not derivable**,
with the reason. It is never given a number nobody checked: a report that
guesses is worse than a report that says "I could not measure this".

## The bounds are bounds

One edit can break several detectors at once — a byte inside a string two
rules share. So the number of bytes that must change for the whole verdict to
move is a range:

- the **lower bound** is the largest single detector's distance: one edit
  could break them all;
- the **upper bound** is the sum of the distances: breaking them one at a time
  always works.

Both are honest. A single number would be a claim nobody could check.

## What it deliberately does not do

The plan's sketch of this feature asks for "the minimum patch set that flips
the verdict". This implementation does not produce it, and the reason is the
project's scope note: the rule is that the repository implements detection
rows and never the techniques that defeat them, and "the part that crosses
the boundary is refused, not split off and shipped".

So the report names the change — "breaking the rule needs at least two bytes
changed", "the matched string `$ext1`" — and carries **no offsets, no matched
byte values and no mutated file**. A detection engineer gets the number they
need to know which of their rules are one edit from being useless. Someone
looking for a bypass does not get a patch out of it.

The same line runs through the rest of the phase. The plan also lists an
adversarial harness that *generates* attacks — integrated-gradient function
replacement, active-opcode insertion, control-flow-graph dummy injection.
Those are attack generators, and they are out of scope here for the same
reason. What ships is the **measurement** side: `cau evasion bench` runs the
shipped detectors over a corpus the operator supplies and reports, per
detector, how often it fired and how many of its firings were a single byte
from silence. The corpus is the operator's; this repository ships no attacks
and generates none.

The measurement is the part that matters for the claim the plan makes —
*a detector that cannot be attacked has not been tested*. The bench is how an
operator checks that claim against their own suite.

## The bench

`cau evasion bench` reads a corpus in the evaluation harness's manifest format
(`cau eval`), so the numbers come from the same corpus the recall and
false-positive figures are published from. It reports, per detector:

- how many samples it fired on,
- how many of those firings were **one byte** from silence,
- the **smallest distance** it ever came to.

and then the per-sample rows: the sample, its label, the verdict and the
distance that was measured for it.

The rows are bounded (`--limit`, 50 by default) and the report says when they
were cut. The counts always cover every sample that was scanned.

## Reading the output

```
$ cau evasion bench --corpus corpus/smoke/manifest.json --db corpus/smoke/hashes.txt
evasion bench: corpus/smoke/manifest.json
  samples  : 18 (8 with a detection)
  detector                          fired  one-byte  min distance
  encchain encchain.elf                1         1  1 byte(s)
  hash Smoke_Hash Synthetic Sample     1         1  1 byte(s)
  yara generic_ransomware_extensi…     1         1  1 byte(s)
  static segment.rwx                   1         0  n/a
  yara wannacry_ransomware             1         0  2 byte(s)
  stego stego.codepoints               1         0  48 byte(s)
```

The one-byte column is the one to read first: those are the detections that a
single edit would silence. A hash detection is always one byte — that is what
a hash is — so the interesting rows are the rule and structure ones. A rule
that fires on `3 of them` with four matches needs two bytes; a rule that fires
on one string needs one, and that string is probably too common.

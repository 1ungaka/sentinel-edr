# Held-out recall corpus

This corpus measures **recall** — the miss rate — and it is deliberately kept
apart from everything the rules were written from.

## Why it is separate

The clean population (a Kali install, `cau eval` run over the filesystem)
measures **specificity**: false positives and, now, near misses. It contains
no malware, so it says nothing about what the engine *catches*.

The `smoke` corpus proves the plumbing. Its malicious samples are synthetic
text files authored to carry the exact strings the shipped rules look for, so
100 % recall against it is guaranteed by construction. Measuring detection on
the samples the rules were authored from is the same failure the per-rule
mutation harness (`scanner/robustness_test.go`) exists to catch — a rule that
passes on the sample it was written from and misses a variant — only at corpus
scale. A recall number from `smoke` is not a detection number, and
[`docs/evaluation.md`](../../docs/evaluation.md) says so.

Honest recall therefore needs a set the rules were **not** authored against:
real, provenance-tracked family samples, held out from rule development. That
is this corpus.

## The hashes live in an encrypted database

The sample identities and their threat intel are kept in
`corpus/heldout/hashes.db`, encrypted at rest with AES-256-GCM under a
passphrase (PBKDF2). The hash list reveals which families and samples are
tracked and is a standing temptation to tune rules against, so it is never
stored in plaintext. The **ciphertext** database is safe to commit; the
hashes, the intel and the samples are not. `cau heldout` manages it:

```sh
export CAU_HELDOUT_KEY=...          # or pass --key-file

cau heldout init                    # create the empty encrypted database
cau heldout pull --source full      # download the full MalwareBazaar DB + intel
cau heldout list                    # inspect (decrypts in memory only)
```

`pull` is incremental and self-recovering: it checkpoints the encrypted
database every `--batch` new records, resumes an interrupted download with an
HTTP Range request, and skips hashes already present — so a crashed pull
continues where it left off instead of starting over. `--source recent` is a
fast daily top-up; `--family <name>` narrows to one family.

## What is tracked, and what is not

Tracked:

- `README.md` — this file.
- `hashes.db` — the **encrypted** identity + intel database (ciphertext).

Not tracked (see `../../.gitignore`):

- `samples/` — the fetched malware bytes.
- `manifest.json` — the live scan manifest `fetch-heldout.sh` generates.
- `.heldout-download.zip` — the resumable download cache.

Anyone with the passphrase rebuilds the corpus byte-for-byte from the hashes,
so the measurement is reproducible without the samples ever entering the repo.

## Fetching the sample bytes

The database holds identities; scanning needs the bytes. `fetch-heldout.sh`
asks `cau heldout manifest` for a manifest (decrypted in memory), downloads
each sample **by SHA-256** into `samples/`, verifies the hash, leaves the file
non-executable, and writes a live `manifest.json` for the samples it got:

```sh
# Needs the DB passphrase and a MalwareBazaar auth key (abuse.ch, free).
CAU_HELDOUT_KEY=... MB_API_KEY=... scripts/fetch-heldout.sh --family lokibot --limit 200
```

Scan from an isolated VM; the engine only ever reads bytes, but the samples
are real. Then measure:

```sh
make eval-recall      # runs this corpus when manifest.json is present
```

`eval-recall` is **opt-in**. CI does not fetch malware, so it skips this gate
when `corpus/heldout/manifest.json` is absent, and the committed `smoke` gate
is unaffected.

## Keeping it held out

The one rule that makes this corpus worth anything: **do not author or tune a
detector against a sample in here.** When a new sample drives a rule change,
move it to a development corpus and add a fresh, unseen sample in its place.
The moment the rules learn these bytes, the recall number becomes the smoke
number again.

## Sourcing

Pull a spread of families, not a pile of one. Record provenance for every
sample (`source`, `url`, `license`, `retrieved`). Good free sources:

- [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch) — by SHA-256, tagged by
  family; the fetch script targets its API.
- [MalShare](https://malshare.com), [VirusShare](https://virusshare.com) — by
  hash, with an account.

Mix in benign samples in the proportion you expect in production if you want a
precision number from this corpus too; for a pure miss-rate measurement, a
malware-only set is fine — recall does not depend on the benign count.

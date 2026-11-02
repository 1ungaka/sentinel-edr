# Anti-Tamper

Disabling the scanner is a standard attacker move (ATT&CK **T1562.001**, Impair
Defenses): gut the signature database, neuter a rule, or swap the binary. CAU
makes each of those detectable.

## Detection content — `cau selftest`

Record a baseline on a known-good install, then verify it (e.g. from a timer, or
as the `ExecStartPre` the shipped systemd units already use):

```sh
cau selftest --record                      # baseline: signatures, rules, fuzzy DB
cau selftest                               # verify; drift → exit 1, names the resource
```

A plain baseline catches drift by a process that cannot also rewrite the
manifest. For tamper-*resistance*, sign the baseline and verify against a pinned
key — an attacker who rewrites the content **and** the manifest still cannot
forge the signature:

```sh
cau selftest --record --sign-key priv.hex
cau selftest --pubkey pub.hex              # fail-closed on a bad/missing signature
```

## The binary itself — `cau verify-self`

Verify the running binary against the signed release `SHA256SUMS`. See
[Updates and Self-Verification](Updates-and-Self-Verification).

## The vault and updates fail closed

- The quarantine vault is sealed with the SHA-256 of both the original and the
  stored bytes; `cau quarantine verify` exits 1 on any tampering, and restore
  refuses to write wrong bytes back to the live path.
- `cau update` installs nothing whose Ed25519 signature does not verify.
- Both write atomically and `fsync` before rename, so a crash cannot leave a
  half-written index or database that would silently pass or fail later checks.

## Honest limits

- The MCP file sandbox enforces symlink containment at resolve time, but access
  is by resolved path, not a retained `O_NOFOLLOW` descriptor — a component
  swapped in the window between resolution and open is a residual TOCTOU. Stated
  plainly rather than claimed closed.
- Real-time kernel-level self-protection (independent supervisor, eBPF watchdog,
  boot-measured identity) is the resident sensor's job, not this engine's.

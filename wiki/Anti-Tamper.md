# Anti-Tamper

Disabling the scanner is a standard attacker move (ATT&CK **T1562.001**, Impair
Defenses): gut the signature database, neuter a rule, or swap the binary. CAU
makes each of those detectable.

## Detection content — `cau selftest`

Record a baseline on a known-good install, then verify it (e.g. from a timer, or
as the `ExecStartPre` the shipped systemd units already use):

```sh
cau selftest --record                      # baseline: signatures, rules, fuzzy DB, feed, config, binary
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

`cau selftest --record` also pins the SIEM address and its CA bundle in the baseline,
so editing `cau.conf` can no longer redirect or silence the incident stream.
`cau defend` checks everything it reads twice: how the file sits on disk, and against
the signed baseline. The feed is checked on every reload, a resource that fails is
refused while the last trustworthy value stays live, and drift raises a confirmed
incident. A failed check never stops the agent, because that would be a one-file off
switch. A signing key left on the host is reported, since it reduces a signed baseline
to an unsigned one.

## The binary itself — `cau verify-self`

Verify the running binary against the signed release `SHA256SUMS`. See
[Updates and Self-Verification](Updates-and-Self-Verification).

## The running daemon — process self-protection & recovery

A resident scanner (`cau scan --interval …`) is a standing target, so the
daemon protects itself and recovers from attempts to crash it:

- **Memory cannot be read out.** On startup the daemon clears its *dumpable*
  flag (`prctl(PR_SET_DUMPABLE, 0)`): the kernel then refuses `ptrace`-attach
  and `/proc/<pid>/mem` reads from any non-owner, and the process produces no
  core dump. That closes the two cheapest ways to lift its in-memory state — the
  pinned Ed25519 trust anchor, the loaded signatures — off a running host.
- **No privilege escalation from a coerced exec.** It sets `no_new_privs`, so
  nothing it (or any child) executes can gain privileges via setuid/setgid or
  file capabilities.
- **Tamper-evidence at startup.** It logs the running binary's own SHA-256;
  compare it to the signed release (`cau verify-self`) to confirm the on-disk
  binary was not swapped.
- **Process concealment & anti-hook.** On startup the daemon rewrites its own
  process name so malware that hunts for a defender by name (`pgrep cau`,
  `pkill`, scanning `/proc/<pid>/comm` and `cmdline`) does not find it: `comm`
  is always set to a neutral random `[a-z0-9]{6,12}` string (via
  `prctl(PR_SET_NAME)`) and the command line is overwritten best-effort (ps,
  `/proc/self/cmdline`). The name is random, never an impersonation of a real
  process. It also strips the loader-hijack environment variables
  (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `GCONV_PATH`, …) so a function
  hook cannot be injected through the daemon's own environment, and it reports
  an attached `ptrace` tracer. The daemon banner logs the real→random name once
  so an operator can still correlate it. This is **best-effort and defensive**:
  `comm` always takes, the command-line overwrite is best-effort, and
  concealment does **not** make the process unkillable — it does not resist
  `SIGKILL` or a kernel-level kill (that is the resident sensor's / `cau-kernel`'s
  job). Off Linux the whole step is an honest no-op.
- **Crash auto-recovery.** Every scan cycle runs behind a panic barrier — a
  panic in a detector, in report writing, or in quarantine is caught, logged,
  counted, and the daemon continues. One hostile file can never take the
  service down. (Per-file panics are *also* isolated inside the engine, so a
  bad file degrades to a per-file error without even reaching the cycle
  barrier.)
- **Hang/death auto-recovery.** Under a `Type=notify` systemd unit with
  `WatchdogSec=`, the daemon pings a watchdog on its own cadence; a hang,
  deadlock, OOM kill, or hard crash stops the pings and systemd restarts it.
  `StartLimitBurst` caps a crash-loop in `cau-daemon.service`;
  `cau-defend.service` never gives up, because a unit left failed is a host with
  no EDR until someone notices.
- **No file can stop `cau defend`.** A corrupted or planted key, baseline,
  `cau.conf`, signature database or rule file used to be a one-file off switch.
  The daemon now runs without what it lost and raises a top-score
  `defend.tamper.*` incident, and only a mistake on its command line stops it. A
  key or baseline it cannot check vouches for nothing and is never reported as
  verified, and both are retried on every selftest cycle, so a repair needs no
  restart. The cost of staying up is listed in
  [limitations](https://github.com/1ungaka/sentinel-edr/blob/main/docs/limitations.md).

The shipped systemd units add the sandbox around all of this: an unprivileged
user holding only `CAP_DAC_READ_SEARCH` (not root), `ProtectProc=invisible` (no
other user can even see or inspect the process), a read-only system view, a
`@system-service` syscall filter, private `/tmp` and devices, and `cau selftest`
as `ExecStartPre` to report tampered detection content before the service starts.
The leading `-` on that line is deliberate: tampering is reported, and never stops
the defence. See [Running as a Service](Running-as-a-Service).

## The vault and updates fail closed

- The quarantine vault is sealed with the SHA-256 of both the original and the
  stored bytes; `cau quarantine verify` exits 1 on any tampering, and restore
  refuses to write wrong bytes back to the live path.
- `cau update` installs nothing whose Ed25519 signature does not verify, and refuses a
  bundle older than the one installed.
- Index updates hold a file lock, because the daemon and the CLI share the vault, and
  an entry is the only key to its blob.
- Both write atomically and `fsync` before rename, so a crash cannot leave a
  half-written index or database that would silently pass or fail later checks.

## Honest limits

- The MCP file sandbox enforces symlink containment at resolve time, but access
  is by resolved path, not a retained `O_NOFOLLOW` descriptor — a component
  swapped in the window between resolution and open is a residual TOCTOU. Stated
  plainly rather than claimed closed.
- Real-time kernel-level self-protection (independent supervisor, eBPF watchdog,
  boot-measured identity) is the resident sensor's job, not this engine's.

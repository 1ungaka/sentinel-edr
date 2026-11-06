# Running CAU as an automated background service

CAU's engine is a one-shot scanner by design. There are two supported ways to
run it automatically in the background; pick one.

Both of these are **scheduled** scanners, rescanning on an interval or a timer. For
real-time protection use `cau-defend.service` instead: it runs every detection
layer at once, scans new files as they land, correlates what the layers see
into incidents, and can respond. See [Command-line reference](../../docs/cli.md#cau-defend).

`cau scan --interval` could not scan anything before 0.1.0-dev+2026-11-06: process
concealment overwrote its own arguments, so `--dir` became NUL bytes. Check the
report rather than the service state on an older build.

## 1. Timer-driven scheduled scan (recommended)

`systemd` runs a single `cau scan` on a schedule; nothing resident stays in
memory between runs.

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cau  # unprivileged runner
sudo install -D -m0644 cau-scan.service /etc/systemd/system/cau-scan.service
sudo install -D -m0644 cau-scan.timer   /etc/systemd/system/cau-scan.timer
sudoedit /etc/systemd/system/cau-scan.service   # set the scan path, options
sudo systemctl daemon-reload
sudo systemctl enable --now cau-scan.timer
systemctl list-timers cau-scan.timer            # confirm the schedule
```

The unit runs as the unprivileged `cau` user, not root: scanning the whole
filesystem needs only `CAP_DAC_READ_SEARCH` (read any file), granted narrowly
instead of full root. systemd creates `/var/lib/cau` and `/var/log/cau` for it
(`StateDirectory`/`LogsDirectory`). If you must run as root instead, delete the
`User=`/`Group=`/`*Capabilities=` lines.

## 2. Resident daemon

One long-lived process that re-scans every `--interval` and stops cleanly on
`SIGTERM`. Useful in containers or where you want an always-on unit.

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cau
sudo install -D -m0644 cau-daemon.service /etc/systemd/system/cau-daemon.service
sudoedit /etc/systemd/system/cau-daemon.service  # set the path and --interval
sudo systemctl daemon-reload
sudo systemctl enable --now cau-daemon.service
journalctl -u cau-daemon -f                      # watch it run
```

Under the hood the daemon is just `cau scan --interval <dur> …`; you can run
that directly in a container entrypoint without systemd.

### Crash & hang auto-recovery

The daemon unit is `Type=notify` with `WatchdogSec=60s` and `Restart=always`,
so it recovers from failure at two levels:

- **A panic inside one scan cycle** is caught by the daemon itself, logged with
  its stack, and the daemon continues to the next cycle — one bad file or bug
  never takes the service down.
- **A true hang, deadlock, or hard crash** (e.g. an OOM kill, a wedged CGo
  call) stops the watchdog pings; systemd then kills and restarts the service.
  `StartLimitBurst=5` / `StartLimitIntervalSec=300` stop a crash-loop from
  spinning forever — after 5 failures in 5 minutes it stays failed for an
  operator. Tune `WatchdogSec` above your host's scheduler-stall tolerance; the
  daemon pings every `WatchdogSec/2` on a timer independent of the scan
  interval, so a long gap between scans is never mistaken for a hang.

When not run under systemd (no `NOTIFY_SOCKET`), the watchdog calls are silent
no-ops and the in-process panic recovery still applies, so a container
entrypoint gets cycle-level recovery for free and can add `--restart`/`restart:
always` at the orchestrator for process-level recovery.

### Self-protection

At startup the daemon makes its own process **non-dumpable** and sets
**no-new-privs** (Linux), so its in-memory state — the pinned trust anchor, the
loaded signatures — cannot be read out via `ptrace`/`/proc/<pid>/mem` or a core
dump, and a coerced `exec` cannot escalate. It also logs the running binary's
SHA-256 so you can compare it against the signed release (`cau verify-self`).
The unit adds the sandbox around that: unprivileged user, `ProtectProc=invisible`
(other users cannot even see the process), read-only system, a locked-down
syscall filter, and `cau selftest` as `ExecStartPre` to refuse a start on
tampered detection content. See [Anti-Tamper](../../wiki/Anti-Tamper.md).

## Prevention

Add `--quarantine` to either `ExecStart` to move confirmed-malicious files into
the vault as they are found, and grant the vault directory in `ReadWritePaths`
(e.g. `ReadWritePaths=/var/log/cau /var/lib/cau/quarantine`).

## Windows / macOS

There is no first-party service wrapper yet. The same `cau scan --interval <dur>`
daemon runs anywhere, so register it as a service with the platform's own tools:

- **Windows:** wrap it with [NSSM](https://nssm.cc/) or `sc.exe create`, or run
  one-shot `cau scan` from Task Scheduler on a trigger.
- **macOS:** a `launchd` plist running `cau scan` with `StartInterval`, or the
  `--interval` daemon with `KeepAlive`.

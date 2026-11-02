# Running as a Service (automated background scanning)

CAU's engine is a one-shot scanner. Run it automatically in the background two
ways. Either way it is a **scheduled** scanner — real-time, kernel-level file
monitoring (fanotify/eBPF) is the resident sensor's job, a separate component.

## Built-in daemon

```sh
cau scan --dir / --interval 1h --quiet
```

Scans immediately, re-scans every interval, writes the report each cycle, and
exits cleanly (`0`) on `SIGINT`/`SIGTERM`. A finding never stops the daemon. This
runs anywhere — a container entrypoint, or wrapped as a service.

### Self-supervising: crash & hang recovery

The daemon is built to survive, because a long-lived security process is a
target:

- **A panic in one cycle is caught**, logged with its stack, counted, and the
  daemon continues — one hostile file or bug never kills the service.
- **A true hang or hard crash is recovered by the supervisor.** Under a
  `Type=notify` systemd unit with `WatchdogSec=`, the daemon pings a watchdog on
  its own cadence (independent of the scan interval); if the process hangs,
  deadlocks, is OOM-killed, or crashes, the pings stop and systemd restarts it.
  A crash-loop is capped by `StartLimitBurst`. Run by hand or in a plain
  container (no `NOTIFY_SOCKET`), these are silent no-ops and cycle-level
  recovery still applies — add `restart: always` at your orchestrator for the
  process level.

### Self-protection at startup

On Linux the daemon makes its own process **non-dumpable** and sets
**no-new-privs**, so its in-memory state (the pinned trust anchor, the loaded
signatures) cannot be read out via `ptrace`/`/proc/<pid>/mem` or a core dump,
and a coerced `exec` cannot escalate. It logs the running binary's SHA-256 at
startup so you can compare it against the signed release with `cau verify-self`.
See [Anti-Tamper](Anti-Tamper).

## systemd (Linux)

Units ship in [`packaging/systemd/`](https://github.com/s-b-repo/cau/tree/main/packaging/systemd).
Prefer the timer-driven one-shot:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cau
sudo install -D -m0644 packaging/systemd/cau-scan.service /etc/systemd/system/cau-scan.service
sudo install -D -m0644 packaging/systemd/cau-scan.timer   /etc/systemd/system/cau-scan.timer
sudoedit /etc/systemd/system/cau-scan.service     # set the path, options, --quarantine
sudo systemctl daemon-reload
sudo systemctl enable --now cau-scan.timer
```

The units run as the unprivileged `cau` user (not root): full-filesystem
scanning needs only `CAP_DAC_READ_SEARCH`, granted narrowly, and systemd creates
`/var/lib/cau` + `/var/log/cau` for it. They run `cau selftest` as an
`ExecStartPre` so a tampered-with detection set is caught before each scan, and
apply a locked-down sandbox (`ProtectProc=invisible`, read-only system, a
`@system-service` syscall filter) — see [Anti-Tamper](Anti-Tamper). For an
always-on process with crash/hang auto-recovery instead of a timer, use
`cau-daemon.service` (`Type=notify`, `WatchdogSec`, `Restart=always`).

## Windows / macOS

The same `cau scan --interval <dur>` runs everywhere:

- **Windows:** wrap it with [NSSM](https://nssm.cc/) or `sc.exe create`, or run a
  one-shot `cau scan` from Task Scheduler.
- **macOS:** a `launchd` plist with `StartInterval`, or the `--interval` daemon
  with `KeepAlive`.

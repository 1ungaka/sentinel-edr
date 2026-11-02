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

## systemd (Linux)

Units ship in [`packaging/systemd/`](https://github.com/s-b-repo/cau/tree/main/packaging/systemd).
Prefer the timer-driven one-shot:

```sh
sudo install -D -m0644 packaging/systemd/cau-scan.service /etc/systemd/system/cau-scan.service
sudo install -D -m0644 packaging/systemd/cau-scan.timer   /etc/systemd/system/cau-scan.timer
sudoedit /etc/systemd/system/cau-scan.service     # set the path, options, --quarantine
sudo mkdir -p /var/log/cau
sudo systemctl daemon-reload
sudo systemctl enable --now cau-scan.timer
```

The unit runs `cau selftest` as an `ExecStartPre` so a tampered-with detection
set is caught before each scan (see [Anti-Tamper](Anti-Tamper)). For an always-on
process instead of a timer, use `cau-daemon.service`.

## Windows / macOS

The same `cau scan --interval <dur>` runs everywhere:

- **Windows:** wrap it with [NSSM](https://nssm.cc/) or `sc.exe create`, or run a
  one-shot `cau scan` from Task Scheduler.
- **macOS:** a `launchd` plist with `StartInterval`, or the `--interval` daemon
  with `KeepAlive`.

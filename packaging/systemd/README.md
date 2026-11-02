# Running CAU as an automated background service

CAU's engine is a one-shot scanner by design. There are two supported ways to
run it automatically in the background; pick one.

Either way, this is a **scheduled** scanner — it rescans on an interval or a
timer. Real-time, kernel-level monitoring (fanotify/eBPF file events, memory) is
the job of the resident sensor, a separate component, not this engine binary.

## 1. Timer-driven scheduled scan (recommended)

`systemd` runs a single `cau scan` on a schedule; nothing resident stays in
memory between runs.

```sh
sudo install -D -m0644 cau-scan.service /etc/systemd/system/cau-scan.service
sudo install -D -m0644 cau-scan.timer   /etc/systemd/system/cau-scan.timer
sudoedit /etc/systemd/system/cau-scan.service   # set the scan path, options
sudo mkdir -p /var/log/cau
sudo systemctl daemon-reload
sudo systemctl enable --now cau-scan.timer
systemctl list-timers cau-scan.timer            # confirm the schedule
```

## 2. Resident daemon

One long-lived process that re-scans every `--interval` and stops cleanly on
`SIGTERM`. Useful in containers or where you want an always-on unit.

```sh
sudo install -D -m0644 cau-daemon.service /etc/systemd/system/cau-daemon.service
sudoedit /etc/systemd/system/cau-daemon.service  # set the path and --interval
sudo mkdir -p /var/log/cau
sudo systemctl daemon-reload
sudo systemctl enable --now cau-daemon.service
journalctl -u cau-daemon -f                      # watch it run
```

Under the hood the daemon is just `cau scan --interval <dur> …`; you can run
that directly in a container entrypoint without systemd.

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

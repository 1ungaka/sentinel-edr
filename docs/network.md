# The network plane — NDR, cross-domain correlation and blocking

The file detectors answer "is this file malicious?" and `cau ps` answers "is
anything running that shouldn't be?". This document covers the third question:
**what is this host talking to, who on this host is doing the talking, and what
may be done about it.**

Three pieces, each usable on its own:

| Piece | Package | What it is |
|---|---|---|
| Sensor | `internal/netscan` | a read-only scan of the host's network plane, attributed to processes and files |
| Response | `internal/netblock` | reversible, expiring kernel drop rules in cau's own table |
| Cross-domain intake | `internal/ingest` | telemetry from other hosts and sensors, joined on the peer address |

`cau net` is the sensor and the response on the command line. `cau defend` runs
the sensor as one more layer beside the process, file, persistence, kernel,
canary and package layers, where the correlator joins all of them.

## The sensor

### Why /proc and not a packet tap

A packet tap sees bytes with no owner. The question that decides a response is
not "what crossed the wire" but **which process is talking to this peer, and
what file does that process run from** — and the kernel already holds that join:
the socket tables carry an inode, and `/proc/<pid>/fd` says which process holds
it. The sensor reads the join rather than inferring it, so every network finding
arrives with a PID and an executable path that the file scanner, the persistence
audit and the correlator can all act on.

The honest cost of that choice is in [limitations](limitations.md): no payload,
no TLS fingerprint, no per-connection byte counts, and a connection that opens
and closes between two samples is never seen.

### What it reads

Per network namespace, not once per host: a process in a container has its own
socket table, and reading only the host's would report a container's backdoor as
unattributed or miss it. Namespaces are identified by the inode behind
`/proc/<pid>/ns/net`, so one read covers every process that shares one.

- `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` — every socket, its state and both ends
- `/proc/<pid>/fd/*` — socket inodes, which attribute each row to its holder
- `/proc/<pid>/{comm,exe}` — the holder's name and the file behind it
- `/proc/net/arp`, `/proc/net/route`, `/proc/net/ipv6_route` — neighbours and gateways
- `/etc/resolv.conf`, `/etc/hosts` — where names are answered

Without root most other users' processes are unreadable. Those rows stay in the
report as unattributed sockets and are counted in `unreadable`, never guessed
at. The difference is larger than it looks: an unattributed socket has no
executable to group findings by, so several weak signals about one daemon never
meet and an unprivileged run comes out **quieter than it should be**. Measured
on a stock desktop, 40 of 48 sockets were attributed as root against 13 of 33
as an ordinary user, and the one real false positive this sensor has had was
invisible until it was read as root.

Reading every process's file descriptors sounds expensive and is not: a full
scan of a 336-process host took **79–111 ms** as root, which is a 0.3 % duty
cycle against the daemon's 30-second interval.

### Classes

| Class | Score | ATT&CK | What it is |
|---|---|---|---|
| `netscan.egress.fileless` | 9 **live** | T1620, T1071 | a process whose executable is a memfd, a deleted inode or a tmpfs path holds an outbound connection |
| `netscan.listen.fileless` | 9 **live** | T1620, T1571 | the same process, listening |
| `netscan.egress.intel` | 9 **known-bad** | T1071 | the peer is an address or CIDR in the abuse-intel feed |
| `netscan.resolver.intel` | 9 **known-bad** | T1071.004 | `resolv.conf` names a nameserver the feed knows |
| `netscan.hosts.intel` | 9 **known-bad** | T1071.004 | `/etc/hosts` sends a name to an address the feed knows |
| `netscan.capture.fileless` | 9 **live** | T1620, T1040 | a process with no file on disk holds a raw or packet socket |
| `netscan.capture.packet-socket` | 8 (4 for a packaged binary) | T1040 | an `AF_PACKET` socket bound to `ETH_P_ALL`: every frame the interface sees, credentials included |
| `netscan.listen.relay-tool` | 7 | T1059.004 | nc, ncat, socat, telnet or rcat is listening: the bind-shell shape |
| `netscan.sweep.pending` | 6–7 | T1046 | one process with connections in flight to 12+ distinct peers |
| `netscan.arp.gateway-churn` | 7 | T1557.002 | the default gateway's MAC changed between samples |
| `netscan.egress.watchlist` | 6 | T1071 | a connection to a peer another source already identified (see below) |
| `netscan.beacon.periodic` | 6 (3 for a packaged binary) | T1071.001 | repeated connections to one peer on a schedule |
| `netscan.hosts.sinkholed-defence` | 6 | T1562.001 | `/etc/hosts` points an update or security domain at a dead address |
| `netscan.resolver.unexpected` | 5 | *unmapped* | a nameserver that is neither local nor a documented public resolver |
| `netscan.arp.gateway-shared` | 5 | T1557.002 | one MAC answers for the gateway and for another address |
| `netscan.listen.handler-port` | 4 | T1571 | a listener on a known handler port (4444, 1337, 31337, …) |
| `netscan.egress.relay-tool` | 4 | T1059.004 | nc, ncat, socat or telnet connected out |
| `netscan.listen.interpreter` | 4 | T1059.004 | a shell or language runtime listening on a wildcard address |
| `netscan.sweep.fanout` | 4 | T1046 | a binary no package installed talking to 64+ peers |
| `netscan.egress.handler-port` | 3 | T1571 | connected to a known handler port |
| `netscan.listen.nonsystem` | 3 | T1571 | a binary no package installed listening on every address |
| `netscan.dns.off-resolver` | 3 | T1071.004 | a program querying a nameserver this host is not configured to use |
| `netscan.dns.encrypted-escape` | 3 | T1572 | DoT/DoQ from a program whose job is not DNS |
| `netscan.capture.raw-socket` | 6 (3 for a packaged binary) | T1095 | a raw IP socket: packets the kernel's own protocols do not account for, which is what an ICMP channel needs |
| `netscan.capture.packet-socket-filtered` | 2 | T1040 | an `AF_PACKET` socket bound to one ethertype, which is how a DHCP client and an ARP tool work |

`netscan.resolver.unexpected` is deliberately left unmapped: no ATT&CK
sub-technique covers tampering with a host's resolver configuration, and
mapping it to something adjacent would pad the coverage matrix.

`/proc/net/{raw,raw6,packet}` are read alongside the four IP tables, because a
socket that reads or writes the wire directly is not a conversation and the
conversation analytics would say nothing useful about it. `tcpdump` scores 4 for
a full-capture socket and a binary no package installed scores 8 — the program
is not the finding, where it came from is.

### Scoring discipline

The reporting threshold (default 5) is applied **per subject** — one process, or
one peer when the holder could not be read — and a subject that reaches it keeps
all of its signals. Two deliberate consequences:

- A developer's `python3 -m http.server` on `0.0.0.0:8000` scores 4 and is never
  reported. The same interpreter listening on 4444 scores 8 and is.
- A connection to a handler port scores 3 alone and is silent. From a binary no
  package installed it adds up and is reported.

The threshold adds up **per subject**, and what the subject is matters: the
process when it could be read, the peer when it could not, and otherwise the
socket itself. The last case is not a detail — without it, six harmless
single-ethertype packet sockets scoring 2 each share a class, add up to 12, and
all six are reported. That happened on the development host and is now
`netscan_test.go`'s business.

Only two classes assert **live state** — a process with no file on disk holding
a socket, listening or connected — and three assert an **exact
identification** (a feed match). Everything else needs a second layer before
`cau defend` will let a machine act on it. That is the same rule the rest of the
engine follows: a MAC that moved, a cadence, a netcat listener and a sweep all
have innocent explanations, so they are alerts for a human.

### The analytics that need time

`netscan.beacon.periodic` and `netscan.arp.gateway-churn` compare samples, so
they say nothing on a single `cau net` run. Give the sensor a `History` — which
`cau net --interval` and `cau defend` both do — and:

- **Beaconing**: each new local port for the same executable-and-peer pair is a
  new connection. Four or more of them whose intervals have a relative standard
  deviation of 25 % or less, with a mean between 5 s and 1 h, is a schedule. A
  binary a package installed scores 3 for this (update agents and time sync
  really do check in on a schedule); anything else scores 6.
- **Gateway churn**: the default gateway's hardware address changing under the
  host. Reported, never live: a router failover or a VRRP pair does this too.

Measured on a stock desktop, 10 samples at 20-second intervals over 3.3 minutes
of ordinary use produced **0** beaconing, gateway-churn and sweep findings. That
window could have produced a beacon — a 20-second poller makes 10 connections in
it, well past the 4 the analytic needs — so the result is not vacuous. It says
nothing about a slow beacon: a 60-second cadence makes only 3 connections in
3.3 minutes, below the minimum, so neither a true nor a false positive was
reachable for one. A longer run is the measurement that would cover that.

The record is in memory only, bounded (4096 peer pairs, a 2 h window), and lost
on restart — the analytics go quiet and rebuild rather than persisting state
that could be tampered with.

## Response: what blocking is and is not

`internal/netblock` asks the kernel to drop traffic to and from an address.

- **nftables** is the primary backend: cau's own `inet cau` table, with
  `blocked4`/`blocked6` sets carrying a per-element timeout the *kernel* holds,
  so a block survives a crash of the agent and is still released on time. The
  ruleset is written to be applied repeatedly — `add` is a no-op on an object
  that exists, and only the chains are flushed before their rules go back in, so
  a restart can never stack duplicate rules or release a live block. It is
  applied when the blocker opens, not when the first block is made, so arming
  the blocker creates an empty `inet cau` table up front and a block is then a
  set element rather than a rule change made under pressure. An operator who
  expects the firewall untouched until something happens should know that;
  `cau net blocks` shows what is in it and `cau net clear` removes it.
- **iptables** is the fallback: cau's own `CAU-OUT`/`CAU-IN` chains, jumped into
  from `OUTPUT` and `INPUT`. There are no element timeouts, so the expiry is
  written into each rule's own comment and `Expire()` reads it back — the
  kernel is still the record.
- Chains at the `output`, `input` **and `forward`** hooks, because a host that
  routes (a container host, a gateway) would otherwise block only its own
  traffic and let a container keep talking.
- `cau net clear` removes exactly what cau created. This package never reads or
  edits a chain it did not make.

### Never blocked

However confirmed an incident is:

- loopback, the unspecified address, multicast and link-local
- every address configured on an interface of this host
- every default gateway
- every nameserver in `resolv.conf`

`netblock.Check` is a pure function, so the policy is reviewable and tested
without a firewall. The reason it exists: blocking the gateway is precisely what
an attacker would want a confirmed-looking incident to achieve.

### Blocks expire

A machine-made block lasts one hour by default. `--block-ttl 0` makes it
permanent, which an operator has to ask for. A wrong block on a production host
heals itself.

### What it is not

A drop rule is visible to the peer, and a peer with a second address is back at
once. `--sever` (`ss -K`) destroys the sockets already open, because a dropped
TCP session otherwise keeps retransmitting inside the host for minutes. Together
they buy an operator time; neither is containment, and the engine does not call
it protection.

Every block is appended to `/var/lib/cau/netblock.log` with its reason, and
`cau net blocks` reads the reason back.

## Cross-domain: joining somebody else's evidence

`internal/ingest` reads JSON lines from files or directories and turns them into
signals the correlator can join. Three shapes:

1. **A cau incident**, bare (`cau defend --format json`) or inside the OCSF
   Detection Finding envelope the forwarder emits. Both carry the incident
   verbatim, so another cau host's evidence arrives with its classes, scores and
   techniques intact rather than flattened into a message string.
2. **An OCSF event from anything else.** Severity becomes a score (High → 7,
   Critical → 9), the ATT&CK objects become techniques, and the endpoint
   addresses become peers.
3. **A plain event**: `{"host","class","score","technique","detail","files",
   "pid","peers"}`, for a sensor or a script with no format of its own.

### The join

The correlator links signals that share an artefact. A file path and a PID mean
nothing off the host that produced them, so **link keys are host-scoped**: two
machines each with a `/tmp/payload` and a PID 900 are two incidents, not one.

The **peer address is the one key that joins across hosts on purpose**. The same
command-and-control address seen from two machines is one incident, which is the
whole reason to take in telemetry from elsewhere.

### Two rules that keep it honest

- **Nothing from outside is ever local.** Every ingested signal carries the host
  it came from; an event that names none is attributed to the file it was read
  from, and failing that to `unknown-sensor`. An empty host means "this machine"
  to the correlator, so the package can never produce one.
- **Remote evidence corroborates, it does not direct.** `correlate.PlanFor`
  skips every signal with a host, so a peer saying "stop PID 42" cannot stop
  this host's PID 42, and a path on another machine is never quarantined here.
  What a remote signal *can* do is confirm an incident whose other half is
  local — and that is what makes the response correct rather than remote-
  controlled.

### The watchlist

A sub-threshold local observation is dropped by the sensor, which would make it
unavailable to the correlator — the quiet connection to a peer a firewall has
already identified is exactly the one worth having. So strong remote evidence
(definitive, live, or scoring 7+) puts its peers on the sensor's **watchlist**,
and a connection to a watchlisted address is reported whatever it would
otherwise have scored (`netscan.egress.watchlist`, 6).

In `cau defend` the ingest layer therefore runs before the local sensors in a
one-shot cycle, and wakes the network layer whenever it learns something new.

Two properties keep that from becoming a liability. A remote claim **expires**
at `--ingest-max-age` (24 hours by default), pruned both on ingest and whenever
the watchlist is read, because an identification is a statement about an address
at a moment and addresses are reassigned. And telemetry is opened through
`internal/safefs`, so a FIFO left in an ingest directory cannot hold the layer —
and with it shutdown, and `--once` — open for ever.

## Response policy, end to end

`correlate.PlanFor` decides what a confirmed incident permits:

| Action | Comes from | Guard |
|---|---|---|
| `Stop` | the process, kernel and network layers | the layers that read the kernel's own view of a process. A process the process scan never flagged — a memfd binary holding a connection, scored below that scanner's threshold — is looked up in `/proc` so it can actually be stopped, and every guard still applies: the start time read at that moment is what refuses a recycled PID, and PID 1, the responder and its ancestors are never signalled |
| `Quarantine` | the file layer only | never a cron table or a PAM stack, never a system path |
| `Block` | the network layer only | `netblock.Check`; a peer named in a file's *text* is a string, not a connection |

An unconfirmed incident permits nothing at all.

## Running it

```sh
cau net                                         # one read of the network plane
cau net --interval 30s                          # keep reading: beaconing and MAC churn need samples
cau net --feed /var/lib/cau/feed.txt            # match peers against the abuse-intel feed
cau net --format json                           # for a pipeline
sudo cau net --respond block --dry-run          # what it would block, and nothing else
sudo cau net --respond block --block-ttl 30m    # act on live and known-bad findings only
sudo cau net block 203.0.113.9 --reason "phishing kit C2"
cau net blocks                                  # what is blocked, why, and when it expires
sudo cau net unblock 203.0.113.9
sudo cau net clear                              # remove everything cau created

# every layer at once, with the network plane and another sensor's telemetry
sudo cau defend --respond stop --quarantine --netblock \
                --ingest /var/lib/cau/telemetry \
                --block-ttl 1h --sever
```

Exit codes follow the rest of the CLI: 0 nothing found, 1 findings, 3 the run
failed, 4 usage.

## Where the ATT&CK coverage matrix fits

`cau coverage` maps the **file-content** detectors, because that is the content a
rule change can regress. The runtime layers — the process table, persistence,
and now the network plane — are documented here and in
[detectors.md](detectors.md) instead, which is the same treatment `cau ps` and
`cau persist` get. Their techniques are in every report and in the OCSF and
SARIF output; they are not in the coverage baseline, so the gate measures what
it can actually gate.

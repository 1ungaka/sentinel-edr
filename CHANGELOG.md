# Changelog

All notable changes to CAU EDR. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-11-08

### Pipeline, Arch packaging and worker reliability

- Build Arch packages from the checkout being tested, with native x86_64 and
  ARM container images, synchronized AUR metadata and offline Go builds.
- Preserve Debian and Kali packages separately in signed release assets and
  require all six distribution/architecture outputs before signing.
- Keep pending file changes across defend worker passes and prevent old
  cooldown timers from releasing files under a new scan.
- Serialize evaluation progress callbacks, respect the process CPU allocation,
  and stop evaluation recipes immediately when validation or scanning fails.
- Install the systemd service account definition with the shared unit target.

### Network plane: NDR, cross-domain correlation and blocking

- **New `cau net`** and a new `network` layer in `cau defend`
  (`internal/netscan`): a read-only scan of the host's network plane. Every
  socket the kernel holds is read **per network namespace** — so a container's
  backdoor is found and attributed rather than missed — and joined to the
  process and the executable behind it through `/proc/<pid>/fd`, which is what
  makes a network finding something a response can act on. It opens no socket,
  sends no probe and captures no packets.
  - Live state: a process whose executable is a `memfd:`, a deleted inode or a
    tmpfs path, holding a connection or listening (`netscan.egress.fileless`,
    `netscan.listen.fileless`, T1620 with T1071/T1571).
  - Exact identification: a peer, a `resolv.conf` nameserver or an `/etc/hosts`
    target the abuse-intel feed lists. `intel.Feed.MatchHost` is new, because the
    kernel hands over an address, not a line of script to search.
  - Bind shells and relays (T1059.004), handler ports and unexpected listeners
    (T1571), connect sweeps (T1046).
  - Sockets that read the wire rather than talk to a peer: `AF_PACKET` bound to
    `ETH_P_ALL` is every frame the interface sees, credentials included
    (T1040 — 8 from a binary no package installed, 4 from tcpdump, because the
    program is not the finding), one bound to a single ethertype is how a DHCP
    client works and scores 2, and a raw IP socket is what an ICMP channel needs
    (T1095).
  - DNS plane: queries to a nameserver this host is not configured to use
    (T1071.004), DoT/DoQ past the host's own resolver (T1572), an unexpected
    nameserver, and an `/etc/hosts` entry that blackholes a security or update
    domain so the host cannot heal itself (T1562.001). A program sending to port
    53 is explicitly *not* a signal: glibc's resolver runs inside every process
    that looks up a name.
  - Over samples: beaconing cadence (T1071.001 — four or more connections to one
    peer with 25 % jitter or less; a packaged binary scores 3, not 6, because
    update agents really do check in on a schedule) and default-gateway MAC churn
    (T1557.002, reported and never live, because a router failover looks the same
    from one host).
  - The reporting threshold is per subject — the process when it could be read,
    the peer when it could not, otherwise the socket itself — so
    `python3 -m http.server` on a wildcard address scores 4 and stays silent
    while the same interpreter on 4444 scores 8 and does not. Measured: an
    eight-daemon ordinary host produces 0 findings
    (`TestOrdinaryHostIsQuiet`), and so does this development host at
    `--threshold 1` for the sockets an unprivileged user can attribute.
  - Two bugs the development host found before release, both now regression
    tests: a process whose `ns/net` link could not be read was treated as a
    namespace of its own, so the host's tables were read twice and every socket
    reported twice; and unattributed findings of one class pooled their scores,
    so six harmless single-ethertype packet sockets at 2 each added up to 12 and
    all six were reported.
- **Network response** (`internal/netblock`, `cau net block|unblock|blocks|clear`,
  `cau defend --netblock`, on by default under the daemon and opt-in from
  `cau net`): reversible, **expiring** drop rules in cau's own
  nftables table — or its own iptables chains — at the output, input *and
  forward* hooks, so a container host blocks its containers too. nftables holds
  the timeout in the kernel, so a block survives a crash of the agent and is
  still released on time; the iptables fallback carries the expiry in each rule's
  comment. Default lifetime 1h; `--block-ttl 0` makes it permanent, which an
  operator has to ask for. `--sever` (`ss -K`) also destroys the sockets already
  open. `cau net clear` removes exactly what cau created. Loopback, this host's
  own addresses, its default gateways and its configured resolvers are **never**
  blocked, however confirmed the incident: `netblock.Check` is a pure function and
  tested as the policy it is. `--dry-run` renders every command and runs none.
  Blocks are appended to `/var/lib/cau/netblock.log` with their reason, which
  `cau net blocks` reads back.
- **Measured as root on a stock host, which found a false positive at the
  shipped threshold.** NetworkManager holds a raw socket for ICMPv6 and a packet
  socket for ARP; both are its job, and the two scored 3 and 2, sharing one
  subject — the process — for a total of exactly the reporting threshold. So a
  packaged system daemon was a reported finding on an untouched machine. No
  unprivileged run could have shown it, because a socket whose holder cannot be
  read has no executable to group by. The capture classes now weigh who holds
  the socket over what the socket is (a packaged binary scores 2 for a raw
  socket and 1 for a filtered packet socket; an unpackaged one still scores 6
  and 3), which is the discriminator the rest of the sensor already used.
  `TestNetworkManagerShapeStaysQuiet` pins the shape. After the fix: 48 sockets
  read, 40 attributed, 0 findings at the shipped threshold, and the four
  plumbing sockets still listed at `--threshold 1` for inventory.
- The time-based analytics measured against real traffic for the first time: 10
  samples at 20-second intervals over 3.3 minutes of ordinary desktop use, 0
  beaconing, gateway-churn and sweep findings. The window was capable of
  producing a beacon (a 20-second poller makes 10 connections in it, against the
  4 the analytic needs) and says nothing about a 60-second cadence, which makes
  only 3 and so was not reachable either way.
- The blocker verified against a real kernel rather than a fake runner: the
  `inet cau` table carried both test elements with kernel-side expiry, `cau net
  blocks` read them back through real `nft -j` output (the parser had only been
  tested against a hand-written fixture), re-applying the ruleset left 8 rules
  rather than 16 and did not release the live element, and after `cau net clear`
  the `nft list ruleset` digest was byte-identical to the one taken before the
  first block.
- Three findings from review, fixed and tested: a FIFO in an ingest directory
  hung the ingest layer, shutdown and `--once` on a blocking open, so telemetry
  is now read through `internal/safefs`, whose package doc describes that exact
  attack; remote evidence was bounded by size and never by age, so an
  identification taken in while fresh stayed on the watchlist for the daemon's
  whole uptime and could confirm an incident about a reassigned address, and it
  now expires at `--ingest-max-age`; and a stop planned for a process only the
  network layer found could not be carried out, because `procscan.Respond`
  matches entries it was given and `Process` carries an unexported start time —
  new `procscan.Lookup` reads that identity from /proc so the response happens,
  with every existing guard intact.
- **Cross-domain intake** (`internal/ingest`, `cau defend --ingest`): JSON lines
  from other hosts and sensors become signals the correlator joins — a cau
  incident (bare or in the OCSF envelope the forwarder emits, so a fleet
  round-trips with no lossy mapping), an OCSF event from any other product, or a
  plain `{host,class,score,technique,detail,files,pid,peers}` line. Strong remote
  evidence puts its peers on the sensor's watchlist, which is how this host's
  quiet, sub-threshold connection to an already-identified address stops being
  quiet (`netscan.egress.watchlist`).
- **Correlation across hosts, response only at home** (`internal/correlate`):
  signals gained `Peers` and `Host`. Link keys are now **host-scoped**, so two
  machines each with a `/tmp/payload` and a PID 900 are two incidents rather than
  one; the peer address is the single key that joins across hosts on purpose.
  `PlanFor` gained `Block` (network-layer peers only — an address in a file's
  text is a string, not a connection) and now discards every signal carrying a
  host name, so a remote sensor can confirm an incident but can never direct a
  local stop, quarantine or block.
- `docs/network.md` is the new page for all of it: classes with scores and
  techniques, the blocker's policy and backends, and the trust boundary that
  `--ingest` draws. The limits are in `docs/limitations.md`: no payload, a sample
  rather than a stream, no byte counts, attribution needs privilege, and blocking
  is not containment.

### Detection, measured

- **First real detection rate.** `corpus/smoke`'s 100 % is synthetic and
  `corpus/heldout` was never populated, so a local lab corpus now measures real
  offensive tooling split by tool: held-out detection went from **25.4 % to 61.1 %**
  with 6/2,431 false positives, 0.15 % over a 25,000-file benign sweep. This is
  public tooling, not a malware detection rate; see `docs/evaluation.md`.
- `cau eval` ran 7 of the engine's detectors, so its numbers described something
  that does not ship. It now runs all of them, and fusion runs on the CLI's engine.
- New `tradecraft` pass: web shells, network shells, in-memory loaders, living off
  the land abuse and shellcode, raw or in a byte array or encoded blob. Everything
  it finds is SUSPICIOUS tier. JSON schema 1.11.0.
- `tradecraft` extended from the living-off-the-land projects it already drew on:
  GTFOBins Unix breakouts (`tradecraft.gtfobins.*` — shell escape, `sudo` and
  setuid privilege escalation, new technique T1548.001), the LOLBAS shapes missing
  from the Windows lolbin vectors (`certreq`, `GfxDownloadWrapper`, `ms-appinstaller`,
  `Microsoft.Workflow.Compiler`, `AgentExecutor`, `Register-CimProvider`, and more),
  a few further reverse/bind shells (`socat SYSTEM:`, BusyBox `telnetd`), and a much
  wider third-party command-channel host list (webhooks, reverse tunnels, paste/file
  drops, out-of-band interaction).
- `tradecraft` grew the full lolol.farm catalogue of trusted-SaaS C2 covers: every
  one of the 56 abused services from [LOLC2](https://lolc2.github.io), the 127
  cloud fronts from [LOLFSaaS](https://lolfsaas.github.io), the 92 tunnel domains
  from [LOTTunnels](https://lottunnels.github.io) and the 41 webhook sinks from
  [LOTWebhooks](https://lotwebhooks.github.io). A new class
  `tradecraft.c2service.saas-api-call` (score 5) fires on specific abusable paths
  — Microsoft Graph mail/drive write, Firebase realtime-DB write, Dropbox content
  upload, Google Apps Script `/macros/s/*/exec`, Cloudflare Workers/Pages, Lambda
  invoke — while the existing third-party-channel class grew to match every
  tunnel/webhook/paste/SaaS host in the catalogues.
- **Free Wazuh SIEM forwarder** (`internal/forward/wazuh`, `cau scan --wazuh-url`).
  The agent now speaks the Wazuh Manager REST API directly:
  `POST /security/user/authenticate` with HTTP Basic, then `POST /events` with
  the returned JWT and a body of the scan's OCSF findings (byte-identical to
  `cau scan --format ocsf`). Password is sourced from an environment variable
  (`--wazuh-password-env`, default `WAZUH_PASSWORD`) — never from argv.
  TLS verifies against a `--wazuh-ca` bundle; `--wazuh-insecure` is the explicit
  opt-out and is required to use plain `http://`. The forward is best-effort:
  a Wazuh outage logs a warning and drops the delivery, never breaking the
  scan's exit code. Batches cap at 100 events per request. The feature is
  **free**: SIEM delivery the agent handles directly is a single-host action
  and sits in the free surface by the licensing rule
  (`docs/pricing.md`, `pricing.toml`).
- **The resident daemon forwards too, so the agent can be left running.** The
  Wazuh forwarder only existed for one-off `cau scan` runs, which meant the
  always-on surface — the one that actually watches a host — had no way to reach
  a SIEM. `cau defend` now takes the same `--wazuh-*` flags and posts every
  correlated incident as it is raised, as an OCSF 1.3.0 Detection Finding in the
  same envelope `cau scan --format ocsf` writes, so one SIEM rule matches both
  (the envelope constants are now shared rather than duplicated).
  `finding_info.uid` is the fingerprint the daemon dedupes on, so a re-raised
  incident is collapsible instead of a second page; a CONFIRMED incident is a
  High `is_alert`, an unconfirmed one a Medium finding that is not, which keeps
  the daemon's own alert/confirm distinction intact instead of paging on one
  layer's opinion. The full incident travels in `unmapped`, so the SIEM is not a
  worse record than the host's log.
- Delivery is built for a process nobody restarts (`internal/forward.Sink`):
  raising an incident hands it to a bounded queue and returns, so **detection
  never waits on the network**; a batch the manager refuses goes back on the
  queue and is retried on a widening interval capped at a minute, so an outage
  is *buffered and then delivered* rather than discarded; past
  `--forward-queue` (default 4096) the oldest is evicted and counted, which is
  the only way an event is lost while the daemon is up; a partial delivery
  resends only the undelivered tail, so the manager gets no duplicates of what
  it accepted; delivery trouble is reported once on the way down and once on the
  way back up rather than once per failed batch; and shutdown flushes within a
  grace period and prints the final counts. A `--wazuh-url` with no password in
  the environment is a startup error, not a daemon that looks healthy and
  delivers nothing. Measured end to end against a manager killed mid-run: 5
  incidents raised, 5 delivered, 0 dropped, 0 duplicated, RSS flat across the
  outage.
- **Log rotation, because `cau-defend.service` is meant to be left running.**
  The unit appends to `/var/log/cau/defend.jsonl` forever, so without rotation
  the one thing an always-on agent was guaranteed to do was fill the disk of the
  host it protects. New `packaging/logrotate/cau` (daily, 100 MB, 14
  generations, newest left uncompressed for `grep`/`jq`) installed to
  `/etc/logrotate.d/cau` by `make install-logrotate` and by both the Debian and
  Arch packages, where it is a conffile/`backup` entry so an operator's
  retention edits survive an upgrade. It restarts the unit to reopen the append
  target rather than using `copytruncate`, which races with a writing process
  and can tear a line.
- **`cau defend` defends by default.** Response was opt-in, which meant the
  common case — somebody installs the agent and leaves it running — was a host
  that watched an intrusion and did nothing. A confirmed incident now has its
  process frozen, its file moved to the vault, and the kernel and firewall
  blocks armed where the host can do them. `--report-only` turns the whole
  response surface off in one switch, and `report-only = true` does it without
  editing a unit file. What makes this safe to leave on is not the default but
  what counts as confirmed — live state of the host, two independent layers
  agreeing, or known-bad content, never one layer's opinion — and that every
  default action is reversible: the default is `stop`, which freezes a process
  with its memory intact to examine, not `kill`, which stays opt-in because it
  is the one that cannot be undone. `--block-exe` and `--netblock` downgrade
  with one clear log line on a host with no kernel guard or no firewall, rather
  than failing the start or producing a failed block per incident.
- **The agent has a configuration file**: `/etc/cau/cau.conf`, installed by
  `make install-config` and both packages as a conffile. Precedence is built-in
  default, then the file, then the command line, so a flag that was typed always
  wins. `--siem <addr>` and `$CAU_SIEM` take an IP, host, `host:port` or a full
  URL — `10.0.0.5` means `https://10.0.0.5:55000` — so configuring where
  incidents go no longer means knowing the Wazuh API's URL shape.
- **The threat feed is tamper-proofed, and so is everything else the agent
  reads.** The feed was the cheapest way to blind this agent: a plain text file,
  hot-reloaded every ten minutes, with no verification at all, so replacing it
  with an empty one silenced every intel verdict within the reload interval
  without touching a rule or restarting anything. `cau selftest --record` now
  baselines the feed, `cau.conf` and the agent binary alongside the signature
  DB, rules and fuzzy DB, and every file the agent reads is checked twice: how
  it sits on disk (a symlink can be repointed after the check; a world-writable
  file, or a group-writable one when running as root, or one owned by another
  user, can be rewritten after it) and against the signed baseline. The feed is
  verified on **every reload**, not just on the selftest interval, because the
  reload is what a replaced feed rides in on — and on the initial load too,
  which was the one path that was never checked and the one an attacker is most
  likely to catch, on the restart after they rewrite the file. A resource that
  fails is refused and the last trustworthy value stays live; drift raises a
  confirmed incident of its own (T1562.001). A failed check never disables the
  agent, because refusing to run on a bad digest would hand an attacker a
  one-file off switch for the defence.
- **The SIEM address is signed.** Manifest schema 2 adds `pins`: signed settings
  that are not file digests. `cau selftest --record` pins the configured SIEM
  address, so editing `cau.conf` can no longer do the two things that edit was
  worth doing for — stop the real SIEM hearing about an intrusion, and deliver
  the agent's own findings to whoever wrote the line. The daemon uses the
  baselined address and raises `defend.tamper.siem-redirected` (or
  `-siem-removed`). Pins are emitted into the signing bytes only when present,
  so a signature made over a schema-1 manifest still verifies byte for byte and
  no existing baseline breaks on upgrade. Measured end to end: with the address
  rewritten under a signed baseline, forwarding went to the pinned address and
  two confirmed incidents were raised; restoring the file and re-recording
  produced no alerts at all.
- **Two defects in the forwarded OCSF envelope**, found by the agent cau-00 had
  build a wire-format Sender over it — the value of someone consuming your
  output being that they notice what you encoded rather than what you meant:
  - `finding_info.analytic.uid` carried the *incident* id. An analytic uid names
    what detected something, not which thing was detected, and CEF and LEEF use
    that field as their event id — so every incident looked like a different
    kind of event and an ArcSight or QRadar class map had a value it could never
    group on. It is now the lead signal's class, which is stable across
    incidents of the same kind. The incident's own identity remains
    `finding_info.uid` (its fingerprint) and its id remains in
    `unmapped.incident.id`. Two tests pin both halves: like detections share an
    analytic uid while staying individually identifiable, and unlike ones do not
    share it.
  - `unmapped.verdict` was missing, so formats derived from this envelope
    carried the tier in `severity` alone and lost the distinction the daemon
    acts on. It now holds CONFIRMED or ALERT, in the same field `cau scan` uses
    for a file's verdict.
- **A hardening check could hang the daemon at startup.** The scan for a signing
  key left on the host read candidate files with `os.ReadFile` after a
  stat-based size check. That check was not protection: it is a stat before an
  open, so the file can change in between, and a FIFO reports a size of zero and
  passed it outright — after which an unbounded read blocks forever on a writer
  that never comes. Measured rather than reasoned about: a FIFO reports 0 bytes
  and `os.ReadFile` on it was still blocked after 3 seconds. So a named pipe
  called `priv.hex` in `/etc/cau` would have hung `cau defend` before its
  watchers were even armed — a denial of service dressed as a hardening check,
  in code added the same day to make the agent harder to tamper with. It now
  reads through `safefs.ReadFileNoFollow` with a bound and skips anything that
  is not a regular file, with a regression test on a real FIFO. Found by the
  `make regex-audit` gate (`memory/go-readfile`), relayed by cau-47.
  The policy on pipes deliberately differs by who named the path. A walked
  directory refuses them, because the agent is reading whatever it finds and a
  pipe is something nobody asked it to read. A path the operator named allows
  them, with a bound and a deadline, so that `--sign-key <(pass show cau/key)`
  can keep a signing key off disk entirely — which is the one practice that
  makes a signed baseline worth more than a digest in the first place. That
  split, and the bounded reads behind it, are cau-c9's.
- **Two more integrity limitations closed, both previously listed as
  unfixable-here.**
  - *A self-built binary can now pin a key.* `pinnedSelftestKey` became a `var`
    so `-ldflags -X` can write it, and the Makefile takes
    `make build SELFTEST_PUBKEY=$(cat pub.hex)`. Before this the anti-downgrade
    protection only existed in official releases, which left it absent on
    exactly the installs whose owner cared enough to compile from source.
    Demonstrated: a binary built with a key exits 1 on an unsigned baseline
    ("manifest is not signed") where the same binary without one exits 0.
  - *Pinning where incidents go now also says who may receive them*
    (`siem-cert-pin`, `internal/forward/wazuh/pin.go`). The address pin was only
    half the control: TLS verification is what identifies the server, and that
    holds only while every CA in the host's trust store does, so anyone able to
    obtain a certificate for the manager's name — or add a CA — received this
    agent's incidents with verification nominally passing. The manager's public
    key is now pinned as a SHA-256 over the DER SubjectPublicKeyInfo, in
    addition to chain verification and never instead of it. It pins the key
    rather than the certificate so the manager can renew without an outage;
    several pins may be listed to rotate one; any certificate in the chain may
    match, so an operator can pin their own issuing CA; hex and base64 are both
    accepted because operators arrive with both; and on a mismatch the agent
    logs the pin the manager actually presented, which is the one string needed
    to either fix the config or evidence the interception. The pin value is
    itself signed into the baseline (`PinSIEMCert`), since an attacker who could
    edit it on disk would just substitute their own collector's. A pin together
    with `--wazuh-insecure` is refused as a contradiction rather than silently
    resolved. With no pins configured the forwarder behaves exactly as before,
    so `cau scan --wazuh-url` is unaffected.
- **Four of the documented integrity limitations are now closed.** The way this
  kind of checking fails in practice is not that somebody defeats it, but that
  it was quietly worth nothing all along, so each of these turns a silent hollow
  guarantee into something an operator is told about:
  - *An unsigned baseline no longer satisfies a build that expects a signature.*
    New `pinnedSelftestKey`, empty in source and set by a release exactly as
    `pinnedUpdateKey` already is for the update channel. Without it, "no key
    configured" and "this baseline is unsigned" were the same state, so an
    attacker who rewrote the content could replace the signed baseline with an
    unsigned one of their own and the agent had nothing to object to — the
    strongest check turned itself off quietly. Deleting the operator's key file
    no longer helps either, because the build still carries one.
  - *A signing key left on the host is detected* (`internal/trust.SigningKeysNearby`,
    class `defend.weak.signing-key-on-host`). A key in `/etc/cau` beside the
    manifest it signed reduces the signed case to the unsigned one exactly, and
    it was invisible. It reports rather than refuses, since the file may be a
    decoy or a fixture and a security tool that will not start over a file it
    found is its own kind of outage.
  - *Overriding the pinned SIEM address is reported* (`defend.weak.siem-pin-overridden`).
    `--siem` and `$CAU_SIEM` still take precedence, deliberately — an operator
    moving their SIEM must not need a re-recorded baseline first — but that was
    the one remaining way to redirect the incident stream without the config
    digest changing, and it was silent.
  - *The other half of that redirect is covered too.* The CA bundle is baselined
    alongside the address, since swapping it for one you control sends the
    stream elsewhere with TLS verification still nominally on, and
    `--wazuh-insecure` now raises `defend.weak.siem-tls-unverified`.
  Weaknesses score 5 and are not live, so they corroborate and never confirm: a
  misconfiguration must not arm a response. They are reported once per state,
  like a tamper, so a long-running daemon does not repeat them every cycle.
  `docs/limitations.md` has been rewritten to say what is actually left, which
  is root being able to replace the binary and the key in it, a source build
  pinning no key, and drift recording *when* but not *who*.
- **Five fixes to the integrity path, from an independent review (cau-47,
  cau-b0).** Each was reproduced in the code before being changed:
  - *A redirected path defeated the feed check entirely.* `Guard.VerifyFile`
    validated the caller's path on disk but digested the path recorded in the
    baseline, so editing `feed =` or passing `--feed` left the baselined file
    untouched, its digest still matching, while the daemon loaded somebody
    else's. It now digests the file it is about to read and reports a path the
    baseline does not cover. A regression test fails on the old behaviour.
  - *A routine feed update left the host with no feed at all.* `cau feed update`
    never touched the baseline, so on a baselined host the new feed was refused
    as tampering — and because the refusal happens on the load path, after a
    restart there was no previous feed to fall back to. The update now
    re-records the feed's digest (`--manifest`, `--sign-key`,
    `--no-rebaseline`), and `Guard.Refresh` re-reads the baseline on each reload
    so a re-record lands without a restart, which the usage text already
    claimed. A signed baseline is never rewritten without its key, because
    saving a stale signature would turn a stale digest into a refusal to start;
    the command prints the exact re-record instead.
  - *A persistent tamper went silent after one alert.* An incident's id hashes
    its hosts, files, PIDs and peers, and a tamper signal has none of those, so
    the fingerprint was identical every time and the join's once-only memory
    swallowed every later raise for the life of the daemon. Tamper now raises on
    a change of reason and forgets a resource that verifies clean again, so a
    re-tamper is news.
  - *An emptied feed replaced a good one* on a host with no baseline to catch it
    by digest. `cau scan` had always refused a zero-indicator feed; the daemon
    now agrees with it.
  - *An unreadable feed was only a stderr line.* A digest that fails with EACCES
    now raises evidence, since not being able to verify something is not a clean
    bill of health.
- **The shipped unit can now actually do what the defaults say.** With
  `--netblock` on by default, `cau-defend.service` shipped without
  `CAP_NET_ADMIN` and with `RestrictAddressFamilies=AF_UNIX`, so nft and
  iptables could not reach the kernel over netlink and the blocker failed to arm
  on every start of the packaged service — a warning on every boot and a unit
  header that was untrue. It now grants exactly those two, and documents
  dropping both plus `netblock = false` for anyone who would rather the agent
  could not touch the firewall at all.
- **A pinned public key that cannot be used is now an error.**
  `resolveSelftestPubkey` returned "no key" for a `--pubkey`/`--selftest-pubkey`
  it could not read or parse, so `cau selftest --pubkey <corrupt file>` quietly
  downgraded to a digest-only check and `cau defend` started in the unsigned
  state while every log line still looked healthy. Deleting or corrupting one
  file was therefore enough to turn off the only check that resists an attacker
  who rewrites the content *and* rebaselines the manifest — and with schema-2
  pins, the signature is also what vouches for the SIEM address. Both commands
  now refuse to start (exit 3) and say which key and why. A key that was never
  asked for is still not a failure. `cau honesty` keeps reporting rather than
  failing, since describing the host's real state is that command's job. Found
  by cau-00's honesty subagent.
- New `internal/trust`: the configuration loader and the integrity guard, usable
  in all three states a host can be in — no baseline (nothing can be verified,
  and it says so once rather than silently answering "fine"), baseline only
  (catches a change nobody covered their tracks for), and baseline plus pinned
  key (resists a rewrite of the baseline itself). The honest limits of all of
  this, including what root can still do and why the signing key belongs off the
  host, are in `docs/limitations.md`.
- `cau-defend.service` shipped `RestrictAddressFamilies=AF_UNIX`, which would
  have made every forwarded delivery fail with `EPERM` with no hint why. The
  unit now documents the one-line widening the forwarder needs, next to the
  directive and in its header, along with how to supply the password through
  `EnvironmentFile` rather than argv.
- **Paid-feature shape is now final.** `docs/pricing.md` names the complete
  `cau-console` paid surface — fleet inventory and health, central policy
  distribution, cross-host incident timelines, multi-tenancy / RBAC / SSO /
  audit, the content lifecycle, the Threat Graph at Scale, and service
  levels — and spells out exactly what stays free (every detector, every
  on-host response, every direct-from-agent SIEM sink, `cau-mcp`, the
  evaluation harness, coverage matrix, rule linter and the signed update
  channel). Monetary values stay DRAFT until owner review.
- `tradecraft.bypass.*` — a new class family for the evasion primitives catalogued
  in [ArcticFox's detection-bypass doc](https://github.com/s-b-repo/arcticfox-c3/blob/main/docs/Detection-Bypasses.md):
  anonymous in-memory execution (`memfd_create` + `execveat`/`fexecve`), kernel
  `prctl(PR_SET_NAME)` process-name camouflage, `LD_PRELOAD`/`RTLD_NEXT` library
  shims, PAM-stack backdoors (`pam_exec.so`, `pam_unix.so` replacement), systemd
  unit hijacks (`systemctl edit --full`, `.service.d/override.conf`), self-delete
  of `/proc/self/exe`, GitHub README dead-drops with cache-busting, ICMP and DNS
  TXT covert channels, open-redirect heartbeat URLs with zero-width codepoints,
  and TLS domain fronting (SNI ≠ Host). New ATT&CK rows: T1001.003, T1071.004,
  T1090.004, T1095, T1102.002, T1556.003.
- `highly_sus_shellcode` rewritten: it fired on `msdia140.dll` and missed every
  Metasploit stub. New rules for the Windows netcat lineage and wrapped PEASS.
- `.onion` now weighs 1, since every Go binary with a network stack carries it.
- Static: `elf.tiny-loader` for hand-built ELF stubs.
- `cau-mcp` now runs the archive, CHM and tradecraft passes.

### Windows false positives

- Measured on 5,701 public Windows admin scripts: 1.03 % false positives, 15 of
  them MALICIOUS. `obfuscated_powershell` now needs execution and download on one
  line, and Chocolatey and Scoop bootstrap URLs are excused line by line: 0.63 %,
  4 MALICIOUS, for one heldout detection.

### Kernel guards

- The kill guard is self-contained and proven in QEMU: root cannot kill, stop or
  ptrace a protected process, an unprotected one still dies, and detaching lifts
  protection. `make vm-test` runs 54 scenarios.
- **Fixed:** with the file guard loaded, `enforce on` refused every file open, so
  logs, reads and the `enforce off` binary itself were locked out. The freeze now
  refuses only opens that load a program.

### Layered defence

- New `cau defend` chains every layer in one loop. `internal/correlate` joins
  process, file, persistence, kernel, canary and package findings into one incident
  per artefact, keeping flagged files across cycles so waiting does not beat it.
- `internal/watch` scans files as they land, through inotify on the places attacks
  arrive and persist, with `packaging/systemd/cau-defend.service` to run it.
- Automatic response needs live host state, two independent layers, or known-bad
  content. Argv text alone never acts.

### Fixed

- **`cau scan --interval` scanned nothing.** Process concealment overwrote argv,
  which Go's flag values alias, so `--dir` became NUL bytes on every cycle while
  the daemon reported success. Concealment still applies; arguments now survive it.

### Live defence

- **`cau defend` is self-contained.** Two extra layers close the "left running"
  gap: a **selftest** layer verifies the detection content on disk against the
  signed `integrity.json` baseline every `--selftest-interval` (default 15m), so
  someone gutting the signature DB or neutering a YARA rule while the daemon
  runs is caught as the T1562.001 move it is and raises a confirmed self-layer
  incident on its own; and a **feed** layer re-reads the abuse-intel feed from
  disk every `--feed-reload` (default 10m), so a `cau feed update` on the host
  lands without a restart. The canary manifest and the `cau-kernel` event log
  are now auto-discovered from standard paths (`/var/lib/cau/canary.json`,
  `/var/log/cau-kernel/events.jsonl`), so a plain `cau defend` wires every layer
  up by itself.
- **`cau defend` runs everything at once.** A file dropped while the package audit
  ran used to wait for it: 9.9 s to alert, 17.6 s from drop to a confirmed incident
  right after start. Each layer, scan worker and response is now its own goroutine,
  so a slow part delays only itself, and the 500 ms debounce is gone. Measured
  through the real binary at load 15 to 25, drop to confirmed is a median 34 ms
  idle and 176 ms during a 20,000-file sweep, 337 ms at worst, for a small script. A
  real binary is limited by scan time: 1.4 MB takes 0.3 s on a quiet host and 1.3 s
  at load 22, down from 3.7 s. The
  process table, the persistence audit, the package audit, canary checks, detectors
  within a file, script vectors and hashes all fan out as well. New files go ahead
  of a sweep, and one worker is reserved for them. `cau installed` went from 10.6 s
  to 1.9 s.
- A newly flagged file now wakes the process and persistence layers, so an entry no
  watch covers joins it at once rather than at the next `--interval`.
- **A panic is retried and raised.** A detector that panics runs once more, and is
  reported either way: a warning in every report, and a `file.detector-panic` alert
  under `cau defend`, which never confirms on its own. Other detectors are no longer
  lost to one panic: they run independently, and fusion weighs what they found. A
  daemon task that panics is retried at once and raises `defend.crash.<task>`.
- `cau defend` output is written one incident at a time, so concurrent incidents
  never interleave, and two incidents naming one file quarantine it once.
- `cau defend` no longer keeps a clean verdict on a file rewritten with the same
  size and a restored mtime: a file version now includes its inode and ctime, which
  its writer cannot set, and a file that changed within 20 ms of its scan is rescanned
  on the next event. This also makes `chmod +x` a new version, as documented.
- The file at a path and the bytes a process runs from it are now two verdicts. A
  process running a deleted binary kept losing its verdict to the persistence audit,
  which only has the path and found it missing.
- An incident is reported even if its response panics, with what the other actions
  did, and a hung `cau-kernel`, `nft` or `iptables` gives up after 30 s rather than
  holding the alert.
- A response that failed is tried again: a quarantine or block that failed raises its
  incident again after 5, 10 and 20 seconds, through the same gate. It used to be
  reported once and never tried again.
- A consumer that stops reading `cau defend`'s output no longer stops anything else.
  Reports are written on their own goroutine, the oldest are dropped past 4,096, and
  shutdown waits 2 seconds for it. Before, one stalled pipe held up every response,
  the SIEM forward and the exit.
- The memory of raised incidents rotates in two generations rather than being wiped
  when full, which raised every live incident again at once, and flagged files are
  capped at 65,536.
- `make vm-respond` proves the response on a real kernel as real root, in QEMU, with
  no root on the host: real stops, kills and quarantines, and what must be left alone.
- **Scanning is several times faster and uses far less memory, with identical
  findings.** `tradecraft` was 77 % of scan CPU, nearly all of it regexes proving they
  didn't match, so `internal/prefilter` reduces each expression to literals any match
  must contain and finds which are present in one pass of an automaton, and the rest
  never run. A mixed 10,410-file set took about 100 s rather than 529 s at higher load,
  and its full results were compared against a build without these changes: no
  difference in any result, finding class or verdict. The same filter covers `linuxpkg`
  script vectors and `heuristics` string patterns.
- A 60 MiB text file peaks at about 310 MB of heap rather than 855 MB, allocating 68 MB
  rather than 952 MB, and a 60 MiB list of hex numbers at 306 MB rather than about
  1.2 GB, allocating 129 MB rather than 2.3 GB: `stego` had reallocated a 16-rune
  window for every rune, `encchain` a buffer for every word, `heuristics` a string for
  every line, and `tradecraft` and `peeler` a string header for every number in a
  list. A 60 MiB run of base64 still peaks around 840 MB.
- A 60 MiB run of base64 peaks at 567 MB of heap rather than 642 MB, and a 60 MiB-scale
  run of hex numbers at 461 MB rather than 778 MB: every text decoder now sizes its
  output to its encoding's own expansion ratio and decodes in place instead of copying
  the text first. The worst of them was `ascii85`, which reserved four times the length
  of its input for a body that decodes to four fifths of it — 324 MB of buffer for the
  65 MB it decodes out of 81 MB of Adobe text, now 65 MB. No decode is refused earlier
  than it was, so no verdict moved: `make eval` still holds at 100 % recall and no
  false positives.
- Tradecraft expressions compile on first use, which takes start-up from 54 ms of CPU
  and 26 MB to 17 ms and 19 MB for every command. `cau defend` builds them before
  taking work, so the first file to land does not pay for it.
- `ScanDirectory` scans as it walks, so a large tree has results at once. Nested
  parallel work borrows idle CPUs rather than stacking goroutines, large files are
  hashed in parallel, and worker counts respect a CPU quota.
- `cau defend` gives a sweep half the workers, stops within 5 seconds of a scan that
  can't be interrupted, and passes the threat feed to the engine as `cau scan` does.
- `correlate.PlanFor` acts on less. Nothing under `/etc` is quarantined, however it
  was flagged, since a PAM stack or a cron table going missing locks an operator out.
  A process is stopped only on its own live or exact evidence, or when another layer
  points at it: sharing an interpreter outside the system paths used to let a live
  shell's confirmation stop an unrelated process with only argv text against it.
- `cau defend` quarantines a file only on that file's own verdict. A clean file moved
  to a running implant's path used to be taken for it, and the implant kept running.
- An old guard refusal no longer names a process unless its name still matches, so a
  reused PID isn't stopped for last week's log line. Refusals also kept being lost once
  the log passed 4 MiB, because the count of lines read stopped growing.
- A file written back to a quarantined path is raised and acted on again. Its
  fingerprint used to silence it.
- A sparse file can no longer hold a scan slot: past 1 GiB a file raises
  `file.too-large` instead of being read. A few such files used to stop the file layer
  and shutdown, and the watchdog kept reporting a healthy daemon.
- Files that arrive with no write and no close are seen: hard links, `O_TMPFILE`, and
  a writer that keeps its descriptor. Deletions are reported too, so a verdict on a
  file that has gone does not stay for ever. Reaching the directory limit at run time
  starts a sweep, and sweeps also run every five minutes, which is the only way the
  file layer works at all without inotify. Walks of new trees are bounded.
- `cau ps` finds network shells by resolving stdin and stdout to a real TCP
  connection, pipe relays, set-uid shells and the tradecraft vocabulary on argv.
- `cau ps --respond stop|kill` acts on confirmed processes only, and never on PID
  1, the responder or its ancestors. A deleted executable alone is not confirmed,
  because any program upgraded while running looks the same.
- `cau ps --kernel-events` correlates the `cau-kernel` guard's log with live
  processes, and `--block-exe` asks the kernel to refuse a confirmed implant's file,
  refusing system paths and interpreters.
- New `cau persist`: a read-only audit of Linux persistence, for a live host or a
  mounted disk.


### Added
- **`scripts/regex-audit.py`, a regex sweep for known bug shapes** (`make
  regex-audit`). 87 rules across Go, C and BPF, Python, shell and workflow files
  cover swallowed errors, memory handling, broken logic, bad code, filesystem races
  and injection. Rules run per line, across lines, per function ("opens a file and
  never closes it") and per loop ("a `break` that only leaves the `select`"). Each
  carries a sample of what it catches and what it must not, and `--self-test`
  checks them. Hits are candidates; `audit:ok` on a line marks it as read, and
  `scripts/regex-audit.baseline` records the rest, so the sweep reports only new
  code and exits 1 on a hit nobody has looked at.
- **The peeler reads every common base, rot and Caesar, and layers chain in any
  order.** New: bases 2, 8, 10, 36, 45, 58, 62, 85, 91 and 92, the base32 and base64
  variants, byte lists (`0x48,0x65`, `\x48\x65`, `%48%65`), every Caesar shift,
  rot5, rot18, rot47, atbash, reversal, UTF-16, and line-wrapped encodings, which
  is what `base64` writes by default and which used to be no layer at all. A
  substitution has to reveal something before it counts, because rotating text
  gives more text and depth is scored. One substitution is a finding by itself,
  since no packaging tool writes one, and scripts are recognised without a shebang.
  A blob carved out of a script is peeled too, but carving is not a layer: one
  base64 blob in a script is the same packaging as one base64 file.
  The default depth goes from 16 to 32 and the width from 4 to 6.
- **Peeling is parallel and layers work together.** All the decoders at a node run
  at once and rejoin in rank order, so a report does not depend on scheduling. One
  layer can open several branches, so a script holding three payloads is three
  chains, each through its own stack. A panic stops at the decoder that raised it.
  `WithParallelism(1)` is now actually serial. `Peeler.Start` runs a peel in the
  background and streams each layer as it is found. `cau peel` takes several files,
  with `--jobs` and `--stream`.
- **The self-scan SARIF is uploaded to code scanning.** The `selfscan` lane runs
  `cau scan --dir .` in SARIF and OCSF and hands `cau.sarif` to
  `github/codeql-action/upload-sarif@v3` (`security-events: write`), which is
  the CI recipe `docs/cli.md` documents but no workflow ever wired up. A rule or
  heuristic that starts firing on the tree is now a review item rather than an
  artifact nobody opens.
- **A `fuzz` lane and a `vendor/` consistency gate.** Every pull request runs
  `make fuzz FUZZTIME=30s`, a coverage-guided hunt over every `Fuzz*` target
  (the seed corpora already run as unit tests, so the lane buys mutation
  coverage, not re-runs), and the `lint` lane runs `go mod vendor` plus
  `git diff --exit-code -- vendor`, so a stale committed tree fails where it
  costs seconds instead of in the Debian and Arch builds that carry
  `GOPROXY=off`.
- **CI now proves the Debian source package builds.** `dpkg-buildpackage
  -us -uc -S` runs from a copy of the tree, so the "source + binary `.deb`"
  claim in `docs/packaging.md` is measured rather than aspirational. It is
  bounded (10 minutes, `set -eu`, so a broken source package fails the job
  rather than looking like a pass) and scoped to non-PR, non-tag runs: a tag
  build already proves it by building the real source package, and a PR is a
  preview of a merge. The copy carries only what a packager would publish —
  the tree's own build products, the nested `cau-kernel` repository and the
  local WIP paths (`scripts/lintworkflows/`, `docs/p.p`, `cau.sarif`,
  `cau.ocsf.json`) are excluded by the step and now by `.gitignore` too, so
  the proof is not spent on artifacts this repository refuses to publish.
  `.github/dependabot.yml` is new (weekly, grouped updates for the actions the
  workflows pin); the Go module ecosystem is deliberately absent because the
  `vendor/` tree is committed.
- **A security policy, a support policy and a machine-readable price list.**
  `SECURITY.md` states what is in scope (including the anti-tamper claims:
  anything that silently disables detection or makes `cau selftest` pass on
  tampered content), what is not (false positives and missed detections are
  issues, not vulnerabilities — report the sample's SHA-256, never the
  sample), the private reporting channels, the triage clock and 90-day
  coordinated disclosure. `SUPPORT.md` says which artifact is supported how:
  the engine and agents are MIT software supported publicly by issue at every
  scale, the console carries contractual tiers, and the tier tables are
  generated from `pricing.toml` rather than typed twice. `pricing.toml` is the
  checked-in source of truth for the commercial surface — per-managed-agent
  volume bands, tiers, term, the air-gapped renewal path, and a TCO model in
  which every row is labelled FACT or ASSUMPTION so no invented number reads
  as a measurement. `docs/pricing.md` renders it and states in its own header
  that the numbers are a draft under owner review. Both files record the split
  the licensing mechanics already enforce: detection and on-host prevention
  are free and unmetered; only the multi-agent management plane is billed.

### Changed
- **The CI pipeline is six parallel, named, time-bounded lanes** rather than one
  serial job: `lint` (15 min), `test` (45 min, `make test-race` over every
  package), `gates` (20 min: `make build build-mcp`, `make lint-rules`,
  `make coverage`, `make eval`), `selfscan` (20 min), `fuzz` (30 min) and
  `release` (30 min, on a `v*` tag, `needs` the other five). The five
  non-release lanes share the new composite action `.github/actions/cau-env`
  (Go pinned by `go.mod`, libyara 4.3+, pkg-config); the unneeded `yara` CLI is
  no longer installed. A per-ref `concurrency` group cancels a superseded
  pull-request run, a nightly `schedule` is the drift canary for CGO against a
  moving Go/libyara/glibc runner image, `workflow_dispatch` was added, and pull
  requests touching only Markdown, wiki, docs, completions, packaging, scripts
  or `debian/` get no runner time. `make ci` is unchanged and is still the
  local aggregate.
- **A release ships `cau-mcp` and signs everything it publishes.** The release
  job builds `cau` *and* `cau-mcp` (`cau-mcp` was the only artifact the release
  job never built), and the signed `SHA256SUMS` is generated after the integrity
  manifest and the pinned public key are staged, so both are covered by the
  signature instead of shipped unsigned.
- **The module path is `github.com/s-b-repo/cau`.** `go.mod` and all 74
  non-vendor `.go` files carried `github.com/cau-edr/cau`, which is not this
  repository: the published module, every `go get` recipe, every import block
  and the docs that quote them disagreed with the remote in `git remote -v`.
  The default build stamp is `0.1.0-dev`, not `0.4.0-dev` — the first tagged
  release is `v0.1.0` and a default that outranks it is a version lie, so
  `main.go` and `cmd/cau-mcp/main.go` now report the pre-release stamp and let
  the ldflags override supply the real version.
- **No file can stop `cau defend`.** A corrupted or planted public key, baseline,
  `cau.conf`, signature database, fuzzy database or rule file used to make it
  refuse to start or hang, and `StartLimitBurst=5` then made systemd give up, so
  one file left the host with no EDR. It now always starts, keeps detecting with
  what it still has, and raises a score-10 `defend.tamper.*` signal. A key or
  baseline it cannot check vouches for nothing, is never reported as verified, and
  is retried every selftest cycle, so a repair needs no restart. The key must now
  pass `CheckFile`, so a key other users can replace is not believed. These reads
  no longer block on a FIFO, including `cau selftest`, which runs as
  `ExecStartPre`, and an unreadable canary manifest now raises tamper. A mistake on
  the command line still stops it. `cau selftest` stays strict. If `cau.conf` is
  broken the daemon runs on built-in defaults, which act, so set `--report-only` on
  the command line rather than only in that file.
- **A key file can no longer hang or exhaust a run.** `--sign-key` on `selftest`,
  `bundle` and `feed update`, `--pubkey` on `selftest` and `update`, and
  `heldout --key-file` now share `safefs.ReadOperatorFile`. Each takes a regular
  file or a pipe, up to 64 KiB. A pipe gets two minutes for a private key or
  passphrase and five seconds for a public key, which `cau defend` reads at
  startup. A FIFO with no writer is an immediate error and a device is refused,
  where these could block
  forever or read `/dev/zero` until the host ran out of memory.
  `--sign-key <(pass show cau/key)` keeps working; `boot-scan` still takes regular
  files only.
- **The docs caught up with the changelog.** The README, man pages, wiki and
  `docs/` now cover every new command, the architecture page no longer calls
  `cau-mcp` planned or `cau defend` a separate product, `docs/detectors.md` and an
  ADS document the peeler, and the firmware page no longer says compressed sections
  are skipped. `cau --help` lists `cau peel <file>...` and `bundle sbom`.
- **The docs match the repository.** `docs/installation.md` no longer says no
  tag has been cut: it names `v0.1.0` (2026-11-02), where its artifacts are
  attached and where the maintainer checklist lives. `docs/README.md` and
  `README.md` cite the JSON schema as 1.10.0, and the README's table links
  `docs/mcp.md` and `docs/packaging.md`, which existed but were unreachable
  from the index. `docs/library.md`, `docs/output-formats.md` and `PLAN.md`
  drop the old module path and the stale `v0.4.0` example version.

### Fixed
- **`cau scan /bin` scanned nothing and reported clean.** `filepath.Walk` lstats
  its root, so a root that is a symlink comes back as a non-directory and the
  walk ends: `Files scanned: 0`, exit 0, on `/bin`, `/sbin` and `/lib` of every
  merged-`/usr` host. A directory the caller names is now resolved; links found
  during the walk still are not. The rules loader, `cau static` and the
  `selftest` digest had the same hole, and the digest's version meant a
  symlinked rules directory hashed as an empty tree and passed whatever it held.
  `selftest` now also binds symlinks inside the tree, which it used to skip
  while the rule loader followed them.
- **`cau ps` could not see past the first page of a socket table.**
  `/proc/<pid>/net/tcp` and `maps` are seq_files, which return about a page per
  read, and they were read once: 27 of 40 sockets on the development host. A
  reverse shell further down had no peer and did not count as one.
- **A crafted header could end a file's scan early, or the whole process.** Eight
  bounds checks in the Mach-O, CHM, UEFI and ELF parsers wrapped (`off+size`
  landing back inside the file, `base+stride` going negative), so the check
  passed and the slice panicked, abandoning every detector still to run on that
  file. They now subtract. The peeler's worker goroutines had no recover, and
  `ScanFile`'s only covers its own goroutine, so a decoder panic there would
  have ended the process and the daemon with it; it now marks the peel
  exhausted.
- **A file swapped mid-scan could hang or exhaust the scanner.** A stat followed
  by a read checks one file and reads another: a FIFO swapped in blocked a worker
  forever, a link to `/dev/zero` read until the host ran out of memory. Every
  read of an attacker-reachable path now goes through `internal/safefs`, which
  opens first, asks the descriptor, cannot block, and never returns a prefix.
  `cau quarantine`, which runs privileged, refuses a link at the open rather than
  after an lstat, so one swapped in can no longer pull `/etc/shadow` into the
  vault.
- **Quarantining concurrently lost files for good.** The daemon and the CLI share
  a vault, and index updates were an unlocked read-modify-write: 24 concurrent
  quarantines kept 4 entries. An entry is the only key to its blob and the
  original is deleted once stored, so the other 20 were unrecoverable. Index
  updates now hold a file lock.
- **File names could rewrite the text report.** A name carrying `\x1b[2K\r
  [CLEAN] harmless.txt\x1b[8m` erased its own line, printed a forged verdict and
  concealed the rest of the output; a newline forged a whole line. The text
  report and the CLI's other human output now escape control and bidi characters
  (`report.TermSafe`). JSON, SARIF and OCSF keep the exact bytes. An existing test
  named this attack but asserted only the invalid UTF-8 half of it.
- **Any web page could drive `cau-mcp --http`.** The server ignored `Origin`,
  which the MCP transport requires it to validate, so a page open in an analyst's
  browser could call `add_signature` on loopback, directly or through DNS
  rebinding. Browser origins other than loopback now get 403. The non-loopback
  warning also missed `[::]:port` and every concrete LAN address.
- **`yara_test_rule` could read past the sandbox.** Rule text from an MCP client
  reached a compiler with `include` enabled; it is disabled for inline text.
  `--root /` also contained nothing, because the prefix check became `//`.
- **`make fuzz` skipped five parsers.** `chm`, `uefi`, `archive` and `tradecraft`
  had targets it never ran and `linuxpkg` had none, which is how the wrapping
  checks above survived. Mach-O and the ELF dynamic section gain targets of their
  own.
- **A symlink could hide persistence from `cau persist`.** Links were skipped so a
  user's dotfile could not get `/etc/shadow` quoted into a root audit, but the
  loader follows them: making `/etc/ld.so.preload` a link took the audit from one
  detection to none. A link at an audited path is now judged by where it points,
  and its target is still never opened. Pointing into a world-writable or hidden
  location is a detection, and so is `ld.so.preload`, `sudoers`, `passwd`, `shadow`
  or `crontab` being a link at all. Pointing outside the system trees is an
  observation, since `/opt` installs and dotfile managers do that. All 100 links
  at audited paths on the development host stay quiet.
- **`cau update` accepted an older signed bundle.** A signature proves a bundle
  was released, not that it is current, so a compromised mirror could replay a
  year-old database and drop every detection added since. The installed manifest
  is now recorded as `<db>.manifest` and an older bundle is refused, as is an
  undated one replacing a dated one. `--allow-downgrade` backs out a bad release.
  The first install has nothing to compare against.
- **`cau defend` watched nothing through a symlinked root.** The `/bin` bug again,
  in newer code: the file watcher and the startup sweep skipped a root that was a
  symlink, with no error, so the watch was silently empty. `cau persist` and the
  ESP walk had the same call. Signature appends also reported success when the
  final flush failed, and `internal/ingest` cut the error chain.
- **`cau update --from` read an unverified bundle with no limit.** That directory is
  the air-gap path, so it can hold whatever was on the media, and it is read before
  the signature is checked: a FIFO hung the update and a huge file filled memory.
- **Workflow actions are pinned to commit hashes.** A tag can be moved, and these
  steps run with release credentials. Dependabot keeps the hashes current.
- **`scripts/lintworkflows` flagged every workflow.** It never recognised an indented
  list item, so two steps with a `run` key read as a duplicate: 35 false alarms.
- **`cau ps --respond` could signal a recycled PID.** Identity was comm and exe,
  and a reverse shell is usually `/usr/bin/bash`, so another bash that inherited
  the PID passed the check. The kernel's start time is now compared too.
- **Flags after a path were treated as files.** `cau scan /bin --no-yara` scanned
  a file called `--no-yara` and left YARA on. Every command now takes flags on
  either side of its arguments; `--` still ends them.
- **32-bit builds could panic on crafted files.** `debian/control` says
  `Architecture: any`, and on a 32-bit build a ten-digit `ar` size, an RPM string
  offset, an OLE FAT index, or an ELF version, hash-chain or module-signature field
  could go negative as an `int` and pass its bounds check. `scanner/static` tests
  also did not compile for 386. All of it now runs as real 386 binaries.
- The encoded-executable report line carried a double-encoded em dash, putting
  raw C1 control bytes in every such detection. `cau-kernel` no longer reads an
  unparseable taint value as a clean kernel, and `cau_guard` holds enough
  kretprobe instances that a burst of execs cannot pass the freeze unprobed.
  `heldout.Save` syncs before its rename, which its crash-safety comment already
  claimed. `canary plant` creates decoys with `O_EXCL`.
- **`package.yml` could never attach anything to a release.** The workflow set
  `permissions: contents: read` workflow-wide, while the `action-gh-release`
  steps that attach the `.deb`, the Kali `.deb` and the `.pkg.tar.zst` to a tag
  need `contents: write`, so each could only fail with a 403 and publish
  nothing; every job now carries `contents: write`.
- **`package.yml`'s `pull_request` allow list silently skipped work.** It omitted
  `main.go`, `scripts/package-smoke.sh` and every new top-level file, so a
  change there ran no packaging gate; the trigger is now a `paths-ignore` list.
  The full-depth checkout (`fetch-depth: 0`) lets `git describe` stamp the tag
  version into a package instead of a commit sha, and `workflow_dispatch` plus a
  bounded runtime per job make the three container legs re-runnable by hand.
- **`package.yml`'s install step smoke-tested nothing on arm64.** Both legs
  installed `./dist/cau_*_amd64.deb` by name, so on an arm64 runner the glob
  matched no file and `apt-get install` installed nothing — the smoke test then
  passed against whatever `cau` was already on the image, which is a green
  packaging gate over an untested package. The architecture is now read from
  `dpkg --print-architecture`, which is the one the builder produced (the cgo
  binding to libyara is built, not cross-compiled), so the file installed is
  the file that was built.

### SIEM sinks, intel intake and the boot chain

- **SIEM sink formats.** `cau scan --format` gained `ecs`, `cef`, `leef`, `gelf`,
  `syslog` (RFC 5424), `syslog-ecs`, `syslog-cef`, `syslog-leef` and `otlp`. All
  nine are profiles of the OCSF finding, so every format reports the same
  findings with the same uid. A hostile file name cannot forge a second event
  in the line formats, and the JSON formats carry it byte-exact.
- **Conformance fixtures.** One committed fixture per standard (RFC 5424, CEF,
  LEEF, GELF, ECS, OCSF, OTLP) is regenerated, compared and parsed back by an
  independent reader on every test run.
- **Collector forwarding.** `cau scan --sink-url` delivers a sink format over
  `udp://`, `tcp://`, `tls://` (RFC 6587 octet counting for syslog) or
  `https://` (OTLP `/v1/logs`, OpenSearch `_bulk` with `--sink-index`, GELF
  HTTP). Flags are validated before the scan; delivery is best-effort and never
  changes the exit code. `http://` needs `--sink-insecure`; redirects are not
  followed; the `Authorization` value comes from an environment variable.
- **TAXII 2.1 intake.** `cau intake --taxii <collection>` polls a collection
  with pagination, a persisted cursor (`--taxii-state`) and bounds on pages,
  objects and bytes. HTTPS only unless `--allow-http`; cross-host redirects
  are refused.
- **Intake provenance.** `--provenance <file>` records source, origin,
  retrieved-at and the source-stated confidence for every new signature.
- **Intake now skips withdrawn intel.** STIX indicators that are `revoked` or
  past `valid_until`, and MISP attributes with `to_ids: false`, are no longer
  turned into signatures. This changes what an existing feed yields.
- **Weekly intake workflow** (`.github/workflows/intake.yml`): reads the public
  feeds, gates the candidates on the evaluation corpus, publishes them as an
  artifact and fails when a feed parses to nothing. It never commits.
- **`cau boot-scan`** (new command, `internal/bootscan`): a read-only scan of
  the boot chain. Disks: MBR, GPT primary and backup with both CRC32s,
  partition boot sectors, a ransom note in the boot area. EFI System
  Partition: every EFI binary with digest, subsystem and signature presence.
  Firmware variables: Secure Boot and setup mode, boot entries, dbx size and a
  comparison against a reference dbx. Inventory: WPBT, PCI option ROMs, ESRT.
  A test fails the build if the package ever gains a write.
- **SBOM.** `cau bundle sbom [--binary <path>]` writes a reproducible CycloneDX
  1.5 bill of materials from the build information embedded in the binary; the
  release job publishes one per binary under the signed `SHA256SUMS`.
- **Source gates.** `source_gates_test.go` fails the build if the engine gains
  an injection primitive (ptrace, `process_vm_writev`, module loading,
  `memfd_create`, raw `bpf`), if anything under `scanner/` or `internal/peeler/`
  starts a process, opens a socket or writes outside two allowlisted
  signature-database appends, or if a new file imports `os/exec` without being
  listed with its reason.
- **Hostile file names, every format.** One test renders a file name built to
  break each format through all thirteen `--format` values.
- **Docs checked against the CLI.** `cmd_docs_test.go` fails when a `cau`
  example in the README, `docs/` or the wiki names a command or a flag the CLI
  does not define. Its first run found and fixed one stale example
  (`cau cluster --dir`).
- **`cau honesty`** (new command): one document of what is covered, what was
  measured and whether the detection content is intact, with a state per
  section, a list of what it does not claim, and no overall score.
- **`cau firmware` now sees real images.** The firmware-volume walk treated a
  pad file (all-0xFF name, placed first by edk2 in every volume with an
  extended header) as free space and stopped, so the inventory was empty on
  stock OVMF images. It now steps over the pad file.
- **`cau firmware` opens compressed volumes and runs rules.** An in-tree,
  bounded LZMA decoder opens the compressed sections modern images keep their
  driver volumes in, nested volumes are walked, and every module's executable
  body goes through the YARA rules (`uefi.module-rule-match`; `--rules`,
  `--no-yara`). On the OVMF images Debian ships, the eight code images went
  from 0-1 to 91-156 inventoried modules, and no rule fired on 1,079 module
  bodies across all eleven.
- **`cau hwid`** (new command, `internal/hwanchor`): a read-only snapshot of the
  hardware identity (DMI, NIC addresses, TPM PCRs, entropy source) with a
  state per field, a list of what could not be verified, `--record` / `--check`
  against a baseline and `--redact` for sharing.
- **Opt-in periodic update.** `packaging/systemd/cau-update.service` and
  `cau-update.timer` run `cau verify-self` then `cau update` weekly, sandboxed
  and unprivileged. Nothing enables them; the unit refuses to run until the
  release URL and public key are configured.
- **RPM packaging** (`packaging/rpm/cau.spec`): offline build from the release
  tarball, same install targets as the Debian and Arch packages. Built locally
  with `rpmbuild --nodeps`; not yet built on an RPM distribution.
- **Reproducible-build lane.** CI builds the same checkout in two directories
  and fails if `cau` or `cau-mcp` differ; releases depend on it.
- **Intake keeps galaxy tags.** MISP galaxy-cluster tags and the Malpedia
  family a feed attaches are recorded in the intake provenance file.
- **Docs test widened.** Man pages, inline code spans, completion scripts and
  every `--help` text are now checked against the flags the code defines. It
  found and fixed 38 mismatches (bash and fish completions offering flags that
  `hash`, `cluster`, `rules`, `coverage`, `peel`, `firmware`, `add-hash` and
  `add-fuzzy` reject; `-no-heur` in the man page).
- **Strict rule lint.** `make lint-rules` fails on warnings as well as errors.
- **`--format stix`.** `cau scan` can write its findings as one STIX 2.1
  bundle; `cau intake --format stix` reads it back.
- **Intake takes only malicious STIX indicators.** An indicator whose
  `indicator_types` say `benign`, or do not include `malicious-activity` or
  `compromised`, is no longer turned into a signature. Untyped indicators are
  taken as before.
- **Daemon forwarding seam.** `collector.NewSender` lets the resident agent's
  queue deliver any SIEM sink format; no `cau defend` flag uses it yet.
- **OpenSearch `_bulk` results are read per document.** `--sink-url` now
  reports how many documents were indexed instead of treating a chunk as all
  or nothing.
- **`cau boot-scan --record / --check`.** A baseline of the boot chain, with
  optional Ed25519 signing, and typed differences: only security-relevant
  changes fail the check. All of boot-scan's file reads now go through the
  bounded, non-blocking reader, so a named pipe can no longer hang it.
- **Hybrid post-quantum signatures.** Update bundles and `SHA256SUMS` can be
  signed with Ed25519 + ML-DSA-65 (`cau bundle keygen --hybrid`); a hybrid
  verifier requires both. Ed25519-only keys and releases behave as before.
  Needs a binary built with Go 1.27 or later; CI is still on 1.24, so releases
  remain Ed25519-only for now.
- `cau update` and `cau verify-self` now print which signatures were checked.
- **VBA stomping** (T1564.007): the OLE pass parses the VBA `dir` stream and
  reports modules whose compiled p-code and source disagree
  (`ole.vba.stomp.source-missing`, `source-blank`, `mismatch`). Weighted so
  that structure alone does not cross the threshold: only six VBA-bearing
  documents were available to measure on.
- **Peeler: zip as a layer, depth as a signal.** The obfuscation-chain peeler
  opens zip archives through its own bounded reader (nothing written to disk,
  encrypted members skipped and counted, bomb caps shared with the rest of
  the walk), scores chains four or more layers deep (`peel.deep-chain`,
  measured at 0 hits on 131,253 benign files), cancels speculative branches
  when a budget is nearly spent, and enforces its task-graph bounds as
  checked invariants. xz is recognised and reported as opaque, not opened.
  `cau peel` exits 1 on the new `deep-chain` outcome.
- **ELF content classes.** The static pass now reads what a Linux binary
  carries: raw syscall stubs in a dynamically linked image for calls it does
  not import (`content.direct-syscalls`), an embedded SSH key next to an
  `authorized_keys` path, an `sshd_config` directive set to yes, a crontab
  line, a systemd unit body, several autostart mechanisms at once. A location
  string alone is never enough, and a new `Persistence` category is capped so
  content alone cannot cross the threshold. Measured on 11,519 system ELF
  files: no new detection.
- **MCP surface.** `cau-mcp` exposes six more read-only analyses as tools
  (`honesty_index`, `eval_report`, `peel_file`, `firmware_image`, `boot_scan`,
  `hardware_identity`), a `frameworks` view on `mitre_coverage`, the
  `cau://honesty` resource and a `boot_chain_review` prompt, all behind the
  same path sandbox and bounding. New `cau-mcp` flags `--expect`, `--eval`,
  `--manifest`, `--pubkey`. Nothing that acts on the host is exposed.
- **Macro-enabled Office documents.** The archive pass recognises
  `.docm`/`.xlsm`/`.pptm`, opens the embedded `vbaProject.bin` and runs the
  full OLE/VBA analysis over it (classes prefixed `archive.ooxml.`, with the
  member in `via`), and reports remote-template injection
  (`archive.ooxml.remote-template`, T1221). JSON schema 1.13.0 adds
  `archive.vba_member`, `archive.embedded_vba` and `via` on archive findings.
- **`cau scan --provenance`.** Every scanned file can carry its package owner
  and whether its content matches what the package shipped (dpkg and pacman;
  usr-merge, diversions and conffiles handled). A package-owned executable
  that no longer matches is reported as the unscored observation
  `provenance.modified-system-binary` (T1554). Carried in every output
  format. Off by default: the database load costs a few seconds and ~70 MB.
- **Nightly fuzzing budget.** The scheduled CI run now fuzzes each target for
  4 minutes instead of 30 seconds; pushes and pull requests keep the 30-second
  smoke hunt. `make fuzz` gained the two boot-scan targets.

## 0.1.0 - 2026-11-02

First tagged release: the detection engine, the evaluation harness and the
packaging for Debian, Kali Linux and Arch Linux all ship as one version. Every
claim on this page is covered by a test, a measured baseline or a CI gate.

### Notable

- **Packaging that is proven, not claimed.** `dpkg-buildpackage` and `makepkg`
  both build from this repository (the vendored Go module tree is committed, so
  the Debian buildds and the AUR builder need no module-proxy network access).
  `.github/workflows/package.yml` then installs each package into a clean
  Debian trixie, Kali rolling and Arch Linux container and runs
  `scripts/package-smoke.sh`, which asserts the verdicts rather than only the
  exit codes: the malicious smoke sample is caught with zero flags, the benign
  one stays clean, man pages, completions and content are installed, and
  `cau selftest` fails closed. A `.deb`, a Kali `.deb` and a
  `.pkg.tar.zst` are attached to every `v*` release; `scripts/apt-repo.sh`
  builds a signed apt repository from them (see `docs/packaging.md`).
- **The detector list and thresholds are one story.** The engine's detectors,
  thresholds, report formats and content are identical across `cau scan`,
  `cau-mcp` and the packages: all three install through the same Makefile
  target, and the version stamped into a binary is derived from the tag, not
  from the build directory (which is also why the builds are `-trimpath`
  reproducible).
- **`cau selftest` refuses to trust unrecorded content.** With no recorded
  manifest it fails closed (exit 3) instead of reporting success on content
  nobody measured. The release pipeline records a signed manifest.


### Fixed
- **`scripts/clean-manifest.sh` was not executable**, although the Makefile
  invokes it as a command (`make eval-specificity` failed with "Permission
  denied" on a fresh clone). It now carries the executable bit it always had;
  the other scripts are only `source`d and so deliberately do not.
- **Unbounded input read in `cau peel` and `cau intake`** (memory-exhaustion
  DoS). Both read the input file with `os.ReadFile`, so a multi-gigabyte file,
  `/dev/zero`, or a FIFO could exhaust memory (reproduced: a 3 GiB file OOM-killed
  the process). Reads are now capped at 256 MiB via a bounded reader
  (`readFileCapped` / `readStdinCapped`) and refused with a clear error above
  that — found in an adversarial audit. New coverage-guided fuzzers
  (`FuzzParse` for the intake and SHA256SUMS parsers, `FuzzVerify` /
  `FuzzVerifySignature` for the fail-closed Ed25519 verifiers) ran millions of
  mutations with no panic and no accepted forgery, and are wired into
  `make fuzz`.
- **Two YARA rules were case-sensitive** where the rest carry `nocase`, so a
  case-folded sample evaded them: the wannacry rule's indicator strings and
  the generic-ransomware rule's extension strings (`.locked`, `.encrypted`,
  `.crypt`; its ransom-note strings were already `nocase`, and the note
  co-requirement keeps false positives down). Both surfaced by the
  detection-robustness harness and closed with `nocase`; the eval gate
  confirms unchanged recall and zero new false positives.
- **ELF parser out-of-bounds read (panic on hostile input).** A relocatable
  object whose `.symtab` declared a sub-minimum `sh_entsize` let the per-entry
  guard pass while the parser read a fixed-size `Elf64_Sym`, panicking on a
  table placed at end-of-file. `parseSymbols` now floors the stride to the
  struct size, exactly as `parseDynamic` already did. Regression test:
  `TestParseELFSymtabTinyEntsize`.
- **Address-range overflow could hide content from the scanner.** PE
  `sectionIndexForRVA` and ELF `vaToOffset` / `segmentIndexForVA` tested
  `addr < base+size`, which wraps when a crafted section/segment range
  overflows; a legitimate RVA/VA in such a range resolved to "not mapped" and
  the imports/strings/entry there were silently skipped. Rewritten as the
  non-wrapping `addr-base < size`.
- **32-bit builds: file-controlled offsets could become negative indices.**
  `rvaToOffset`, `parseDebug` (CodeView) and `gnuHashSymbolCount` now use
  width-safe comparisons and bound the symbol offset, so a high offset is
  rejected rather than indexing a slice negatively on `GOARCH=386`/`arm`.
- Coverage-guided fuzz harness for every untrusted-input entry point
  (`FuzzParseELF`, `FuzzParsePE`, `FuzzAnalyze`, stego `FuzzScan`,
  `FuzzScanHeuristicsData`; `make fuzz`). Each ran millions of mutations with
  no crash after the fixes above; the seed corpora run as unit tests in CI.
- Detection-robustness harness (`scanner/robustness_test.go`): measures the
  benign-transform envelope (case, UTF-16 widening, NUL-infixing, junk
  padding, base64) each string/import detector survives on synthetic
  fixtures, locks in the true positives, and fails if a bundled rule becomes
  brittle. It found the wannacry case-sensitivity gap above. Companion
  harnesses cover the other two content detectors: the structural pass
  (`scanner/static`, a dropper profile stays detected when benign data is
  appended) and the stego pass (`scanner/stego`, an invisible-codepoint dead
  drop stays detected when wrapped in text or re-encoded as UTF-16). The YARA
  harness covers the wannacry, mimikatz, lokibot, generic-ransomware and
  obfuscated-powershell rules (every string-based bundled rule);
  it found both case-sensitivity gaps above.
- Per-file panic isolation in `Engine.ScanFile`: a panic in any detector
  degrades to a per-file error result instead of crashing the whole scan, so
  one hostile file can never drop the rest of a directory batch. Test:
  `TestEngineHostileFileDoesNotBreakBatch`.
- `cau scan --output`, `cau coverage --output` and `cau rules --output` now
  check the file's close error (a `defer fh.Close()` hid a failed flush on a
  written report); `coverage.WriteText` and `FuzzyDB.Add` no longer swallow
  write and TLSH-parse errors.

### Added
- **`cau firmware` — UEFI firmware scan** (`scanner/uefi`): parses a UEFI image's
  Firmware Volumes and FFS files/sections and reports a module inventory (GUID,
  type, UI name, has-PE), FV header checksum integrity, and implant-blocklist
  matches. Deliberately conservative — ships no implant truth set — so only
  `uefi.volume-checksum-invalid` (a tampered/hand-built FV header) and
  `uefi.known-implant-guid` (an operator `--implants` blocklist match) score;
  everything else is inventory. Module bodies are not disassembled and
  compressed/GUIDed sections are not decompressed. `--format text|json`,
  `--threshold`, `--implants`. Adds ATT&CK T1542.001 (System Firmware). A
  standalone command, not part of the per-file `cau scan`.
- **CHM detector** (`scanner/chm`): reads Compiled HTML Help (ITSS) files for
  embedded payloads a help file has no reason to carry — a lone embedded
  executable (`chm.embedded-executable`, crosses on its own), multiple
  executables, an embedded `.lnk`, or a dangerous script (`.hta`/`.vbs`/`.ps1`/
  `.bat`/`.cmd`/`.wsf`, deliberately not plain `.js`). Walks the uncompressed
  ITSF/ITSP/PMGL directory only; the LZX content section is recorded "present but
  not inspected" rather than guessed. New flags `--no-chm` / `--chm-threshold`,
  per-file JSON `chm` object and summary `chm_detections` / `chm_threshold`,
  text/OCSF surfaces and `--fail-on` counting. T1204.002 / T1059 (already-covered
  techniques, so coverage stays at 58).
- **Archive detector** (`scanner/archive`): bounded, write-free ZIP/TAR/gzip
  (and `tar.gz` nesting) container-hygiene analysis — decompression bombs (ratio
  + absolute caps), Zip-Slip/path-traversal members, double-extension lures
  (`invoice.pdf.exe`), disguised single-executable payloads, and encrypted or
  nested members. Never writes to disk or executes a member; every read is
  bounded. New flags `--no-archive` / `--archive-threshold`, per-file JSON
  `archive` object and summary `archive_detections` / `archive_threshold`,
  text/SARIF/OCSF surfaces and `--fail-on` counting. In the coverage matrix as the
  `archive` source (T1036 / T1204.002 / T1027 on existing rows).
- **`cau installed` — installed-package audit** (`internal/linuxpkg` reuse): audits
  the maintainer/install scripts of already-installed packages in place from dpkg
  (`/var/lib/dpkg/info`) and pacman (`/var/lib/pacman/local`) metadata — offline,
  read-only — flagging the same tradecraft as `cau scan` and any abuse-intel
  indicator reference. RPM is reported as a gap. `--format`, `--threshold`,
  `--feed`.
- **`cau feed` — abuse-intel feed** (`internal/intel`): a hybrid offline feed of
  known-bad IPs/CIDRs/domains/URLs/hashes matched by `cau scan` (`--feed`),
  `cau installed` and `cau ps`. Subcommands `list` / `check` / `update`; `update`
  is the only networked action and only with an explicit `--url` (otherwise a
  plain offline file, `--from`/`--replace`).
- **Report-JSON for Mach-O and ELF deep-resolution**: the static object now emits
  `is_macho` and a `macho` object (`magic`, `byte_order`, `fat`, `arches[]` with
  cpu/filetype/flags/signed/encrypted/entry_segment/import_count/import_hash/dylibs),
  and the `elf` object gains `telfhash`, `telfhash_note` and `syscall_stubs`.
- **Linux software-package detector** (`scanner/linuxpkg`): a bounded,
  stdlib-only, detection-only pass that scores the root-run install-time scripts
  in `.deb` (ar → `control.tar` maintainer scripts), `.rpm` (header scriptlets),
  Arch `.pkg.tar` + `PKGBUILD`, Flatpak manifests + bundles, AppImage type-2,
  Docker/OCI `docker save` tarballs, Snap packages, generic `.zip`/`.tar`
  installers, executable configs (`.desktop`/XDG/systemd/shell-rc) and APT/nala
  sources. It scores supply-chain tradecraft (curl-into-shell, reverse/bind
  shell, decode-and-exec, cryptominer, SSH-key backdoor, sudoers NOPASSWD,
  dropper, disable-defenses, persistence, sandbox escape; T1195.002 and family),
  default threshold 8, SUSPICIOUS-tier only, wired into the engine, fusion,
  coverage matrix and every reporter. New flags `--no-pkg` / `--pkg-threshold`
  (also `--no-pkg` on `cau-mcp`); JSON per-file `linuxpkg` object and summary
  `linuxpkg_detections` / `linuxpkg_threshold`. xz/zstd-packed members and
  AppImage/Snap SquashFS are recorded "present but not inspected", never guessed.
- **`cau ps` — live process scan** (`internal/procscan`): a read-only,
  `/proc`-only point-in-time scan of the running process table. It never injects,
  ptraces, or signals a process, and flags what a file scan structurally misses —
  fileless / RAM-only execution (memfd, deleted binary, `/dev/shm`; T1620), name
  masquerading / PID hijacking (T1036.004/005), library-injection hooks
  (world-writable/deleted `.so`, suspicious `LD_PRELOAD`; T1574.006), reverse-shell
  command lines, and ptraced processes (T1055.008). Flags `--format text|json`,
  `--threshold`; exit 0 clean / 1 flagged / 4 usage.
- **Mach-O static support** (`scanner/static/macho.go`): own bounds-checked
  parser for thin and universal/fat images (32/64-bit, both byte orders) —
  segments/sections, dylibs and a dylib-set import hash, `LC_RPATH`,
  `LC_MAIN`/`LC_UNIXTHREAD` entry, `LC_CODE_SIGNATURE` (presence, unverified) and
  `LC_ENCRYPTION_INFO` (cryptid). New `macho.*` anomaly classes (RWX/high-entropy
  segments, writable-executable section, entry outside/non-exec segment,
  executable stack, encrypted/packed region, insecure rpath/dylib path, unsigned
  or unverified signature, overlay), all in the static class catalog.
- **ELF deep-resolution** (`scanner/static/elf_reloc.go`): `.init_array`/
  `.preinit_array` constructor pointers are resolved through the relocations and
  a target outside executable code flags `dynamic.init-array-outside-code`;
  symbol versions are read from `.gnu.version_r`/`_d` (`dynamic.symbol-versions`);
  a raw-syscall libc interposer flags `dynamic.preload-interposer-syscall`; and
  real **telfhash** (TLSH over the Trend Micro filtered symbol set) is computed,
  with an honest note below TLSH's 50-byte floor.
- **Hybrid fusion — attack-path chaining** (`scanner/fusion/chain.go`): on top of
  the independent weighted sum, `FuseChained` (now the engine default) adds
  bounded, capped conditional chains that fire only on a conjunction of two
  distinct counted sources — `packed-and-injects`, `document-dropper`,
  `peel-revealed`. Chaining only ever adds (the lattice stays monotone), is capped
  at 0.75, never resurrects below-floor evidence, and never downgrades a
  definitive hit. The flat `Fuse` is unchanged for library callers.
- **Process concealment & anti-hook self-protection** (`internal/harden`): the
  resident daemon rewrites its own `comm` (always) and command line (best-effort)
  to a neutral random `[a-z0-9]{6,12}` name so malware hunting a defender by name
  (`pgrep`/`pkill`, `/proc/<pid>/comm`) does not find it, strips loader-hijack
  environment variables (`LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`/`GCONV_PATH`),
  and reports an attached tracer. Best-effort and defensive — it does **not**
  resist `SIGKILL` or a kernel-level kill (that is the resident sensor's job); a
  no-op off Linux. The banner logs the real→random name once.
- **`cau heldout` — held-out recall corpus** (`internal/heldout`): an encrypted
  (AES-256-GCM, PBKDF2) hash+intel database for a recall corpus the detectors were
  not authored from. Subcommands `init`/`pull`/`add`/`remove`/`list`/`manifest`;
  `pull` ingests the MalwareBazaar CSV export incrementally (resumable download,
  batched checkpoints, skip-present). Key from `--key-file` / `$CAU_HELDOUT_KEY`.
  Sample bytes are fetched by `scripts/fetch-heldout.sh`, never committed.
- **Near-miss eval metric**: `cau eval report` gains a `near_miss` section per
  scored detector (threshold, benign-scored count, near-threshold band, minimum
  margin, histogram) so a benign corpus that is *almost* crossing a threshold is
  visible before it becomes a false positive.
- **Signed releases + self-verification** (`internal/release`, `cau verify-self`,
  `cau bundle`, and a signing GitHub Actions release job). Each tagged release is
  signed on GitHub's workers with an Ed25519 CI secret: `cau bundle update`
  produces the signed signature-DB bundle, `cau bundle checksums` a signed
  `SHA256SUMS`, and the job **self-verifies the built binary before publishing**
  — a release that cannot verify itself never ships. `cau verify-self` lets the
  running binary reference itself: it computes its own SHA-256 and checks it
  against the signed `SHA256SUMS` fetched over HTTPS (`--url`) or read offline
  (`--from`), verifying the signature before the hash so a MITM cannot substitute
  a matching digest. (An out-of-band ICMP/QUIC "echo-lane" fetch stays a future
  proprietary transport; the signed-manifest-over-HTTPS path is the secure
  in-engine way today.)
- **GitHub wiki** (`wiki/` + `.github/workflows/wiki.yml`): task-oriented pages
  (install, scanning+prevention, running as a service, updates+self-verification,
  anti-tamper, CLI reference) synced to the project wiki on change.
- **Detection-content self-check / anti-tamper** (`cau selftest`,
  `internal/selftest`): digests the signature database, YARA rules and fuzzy
  database and compares them against a recorded baseline, so an attacker gutting
  signatures or neutering a rule (ATT&CK T1562.001, Impair Defenses) is caught
  rather than silently disabling the scanner. `--record` writes the baseline;
  verification exits 1 and names each drifted resource. A **signed** baseline
  (`--sign-key` / `--pubkey` / `$CAU_SELFTEST_PUBKEY`, Ed25519) is
  tamper-resistant: rewriting the content *and* the manifest still fails because
  the signature can't be forged. The systemd units run it as an `ExecStartPre`
  before each scheduled scan.
- **Automated background scanning** (`cau scan --interval <dur>`, plus systemd
  units in `packaging/systemd/`): a scheduled/resident scan daemon that re-scans
  on a fixed interval until `SIGINT`/`SIGTERM`, writing the report each cycle (a
  finding never stops the daemon; it exits 0 on a clean shutdown). It is portable
  — register it as a systemd service (`cau-daemon.service`), a timer-driven
  one-shot (`cau-scan.service` + `cau-scan.timer`), a container entrypoint, or a
  Windows/`launchd` service. This is a *scheduled* scanner; real-time
  kernel-level file monitoring remains the resident sensor's job.
- **Daemon crash & hang auto-recovery** (`cau scan --interval`). A long-lived
  scanner is a target, so the daemon now supervises itself: every scan cycle
  runs behind a panic barrier (`runCycle`) — a panic in a detector, report
  writing, or quarantine is caught, logged with its stack, counted, and the
  daemon continues to the next cycle instead of dying. Under a `Type=notify`
  systemd unit it speaks the sd_notify protocol (new dependency-free
  `internal/sdnotify`): `READY=1` on start, a `STATUS=` line per cycle, and a
  `WATCHDOG=1` keep-alive on its own cadence (half `WatchdogSec`, independent of
  the scan interval) — so a true hang, deadlock, OOM kill, or hard crash stops
  the pings and systemd restarts the process, with `StartLimitBurst` capping a
  crash-loop. All of it is a silent no-op with no `NOTIFY_SOCKET`, so a
  hand-run or plain-container daemon still gets cycle-level recovery.
- **Daemon process self-protection** (new `internal/harden`, Linux). On startup
  the scan daemon makes its process **non-dumpable** (`PR_SET_DUMPABLE=0`) — the
  kernel then refuses `ptrace`/`/proc/<pid>/mem` from a non-owner and emits no
  core dump, closing the cheapest paths to reading its in-memory state (the
  pinned trust anchor, the loaded signatures) — and sets **`no_new_privs`** so a
  coerced `exec` cannot escalate. It also logs the running binary's own SHA-256
  for comparison against the signed release (`cau verify-self`). Best-effort and
  fail-open: a host that denies a step is reported, never fatal, because
  detection must keep running. Stdlib-only (raw `prctl`), so the default build
  stays dependency-free.
- **Hardened systemd units.** `cau-daemon.service` / `cau-scan.service` now run
  as an unprivileged `cau` user holding only `CAP_DAC_READ_SEARCH` (read any
  file, no root), under a full sandbox: `ProtectProc=invisible` + `ProcSubset=pid`
  (other users cannot see or inspect the process), `ProtectSystem=strict`,
  `PrivateDevices`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service`,
  `LockPersonality`, `UMask=0077`, systemd-managed `StateDirectory`/`LogsDirectory`.
  The daemon unit adds `Type=notify` + `WatchdogSec=60s` + `Restart=always` for
  the recovery above.
- **Scan-time prevention** (`cau scan --quarantine`): auto-detect *and* block in
  one pass — after scanning, flagged files are moved into the integrity-sealed
  vault, with the driving evidence recorded as the threat label. Explicit and
  off by default (the move is destructive). `--quarantine-level` chooses the bar:
  `malicious` (the default) blocks only a hard hash/YARA hit, while `suspicious`
  **also** blocks files the fusion lattice places at the SUSPICIOUS tier — the
  fused, multi-indicator score where each indicator contributes at its own
  weighted level and the sum crosses the threshold, with or without any single
  detector crossing on its own (this is the score-based auto-block, and the
  recorded label names the score and the agreeing indicators). `--quarantine-store`
  sets the vault. On-host prevention is free, in line with the licensing model
  (only multi-agent management is paid).
- **Known-abused code-signing certificate blocklist** (`cau scan --signers`,
  `static.SignerBlocklist`): the static pass now extracts each Authenticode
  certificate's SHA-1 and SHA-256 thumbprint and matches it — or its
  serial+issuer — against an operator-supplied blocklist (lolcerts), emitting the
  `authenticode.known-abused-signer` anomaly (weight 9, T1553.002). A valid
  signature from a stolen or abused key is the ground truth behind the "Certs
  Are Useless" thesis, and this flags it. The blocklist is a JSON array or a
  `thumbprint|issuer|reason` line file (stdlib only; `$CAU_SIGNERS` also sets
  it); converting the lolcerts YAML feed into that file is an ops step.
- **Unified Kill Chain binding** (`cau coverage --frameworks`,
  `internal/frameworks`): maps each covered ATT&CK technique through its tactic
  onto the 18-phase Unified Kill Chain (Paul Pols / Fox-IT) and prints the
  sequencing view grouped by stage, with empty phases named as honest gaps — so
  mapping does not hinge on a single registry. The binding type also carries
  MISP-cluster and Malpedia-family fields, left for an intel feed to populate
  because they tag a sample, not a technique. Scan report findings also carry a
  `frameworks` array on the `fusion` object (ATT&CK id + UKC phase/stage per
  technique) — JSON report schema **1.10.0** — so a consumer can pick its scheme.
- **Signed update channel** (`cau update`, `internal/updater`): installs a
  signature-database bundle fail-closed. The bundle is three files —
  `hashes.txt`, `manifest.json`, and a detached `manifest.json.sig` (one Ed25519
  signature over the manifest, which carries the payload's SHA-256). Nothing on
  disk changes unless the signature verifies against the trusted key, the payload
  digest matches the signed manifest, and the bundle's `min_engine_version` is
  satisfied; a success replaces the database atomically and keeps `<db>.bak` for
  rollback. Read from `--from <dir>` or an explicit `--url` fetch (never
  automatic); `--dry-run` verifies only. The trusted key comes from `--pubkey`,
  `$CAU_UPDATE_PUBKEY`, or the source-pinned key — with none configured, update
  refuses to install anything. Release-side keypair/signing and the CI publish
  step are tracked as ops follow-ons in PLAN.md.
- **Threat-intel intake** (`cau intake`, `internal/intake`): parsers that feed
  the hash signature database from machine-readable feeds instead of hand-typed
  entries — STIX 2.1 bundles (indicator `file:hashes` patterns), MISP event JSON
  (md5/sha1/sha256 attributes, including `filename|hash` composites),
  MalwareBazaar query/dump JSON and the abuse.ch CSV, and the LOLDrivers catalog
  (known-malicious driver hashes). Each normalizes to validated signatures,
  dedupes against the live database (an existing hash is never re-labelled), and
  appends in the database's own `TYPE|hash|name` format. Input from a file or
  stdin, or an explicit `--url` fetch (bounded, never automatic); `--dry-run` and
  `--output` for review. Fixture tests per format. The TAXII polling client and
  scheduled sync remain follow-ons in PLAN.md.
- **Obfuscation-chain peeler** (`cau peel`, `internal/peeler`): the first
  increment of NOVEL-012 — a bounded, concurrent tree walk that removes
  reversible layers (base64/base32/hex, gzip/zlib/flate/bzip2; decode only,
  never execute) under a single global per-sample budget wall shared across
  every branch, so adding layers costs latency, not spend. Chain *depth* is the
  signal; `peel-exhausted` is a first-class, scored outcome, never a silent
  clean. A revealed payload is a finding only at chain depth >= 2 (a single
  ordinary layer stays `scanner/encchain`'s job), which is why it measured
  0/116,201 false positives across `/usr/bin`, `/usr/share/doc`,
  `/usr/lib/python3` and `/usr/share/nmap`. Each peel renders a stable chain
  signature (e.g. `base64>gzip>base64`); CAS dedupe, a depth sweep, a
  decompression-bomb cap, and `FuzzPeel` (in `make fuzz`) back it. It is wired
  into `cau scan` as a first-class detector (default on, `--no-peel` /
  `--peel-threshold`): `ScanResult.Peel`, a `peeler` fusion source, the `peel` /
  `peel_*` fields in text / JSON / SARIF / OCSF, and `peeler` content in
  `cau coverage` (T1027). The eval gate is unchanged (recall / precision / FP /
  FN flat) and a repo self-scan flags 0 of 291 files. A cheap entropy estimator
  ranks each node's frontier so the bounded budget is spent on the most-probable
  transform first (reordering only — detections and the 0-FP envelope are
  unchanged); the input's Shannon entropy rides on the result. The PE/ELF
  structural-fingerprint routing and the emulation fallback are tracked as
  follow-ons in PLAN.md.
- **JSON report schema 1.9.0**: added the optional per-file `peel` object and the
  summary fields `peel_detections` / `peel_threshold` (additive, minor bump).
- **Quarantine vault** (`cau quarantine`, `internal/quarantine`): a local,
  directory-backed store for files a scan flagged, giving the OSS engine
  somewhere to put found files short of deletion. Every entry is XOR-masked at
  rest — the vault never holds a runnable PE/ELF on disk and a scanner pointed
  at it (including `cau` itself) does not re-flag it — and sealed with the
  SHA-256 of both the original and the masked bytes, so a corrupted or tampered
  vault fails *closed* (`ErrIntegrity`, exit 1) rather than writing wrong bytes
  back to the live path. Subcommands: `add` (move, or `--keep` to copy), `list`
  (text/JSON), `restore` (to the recorded original or `--to`), `verify` (one
  entry or the whole vault), `delete`. Index writes are atomic. Masking is
  reversible obfuscation for safety, never encryption for secrecy — the key is
  stored alongside the entry and the docs say so.
- **Canary / decoy files** (`cau canary`, `internal/canary`): `plant` writes
  plausible decoy files (credential, finance, key names) and records a baseline
  manifest; `check` diffs them and classifies each as intact, modified,
  deleted, or meta-changed, so a rewrite (the ransomware signal) is never
  conflated with a permission change. Cheap ground truth with near-zero false
  positives; `check` is honest about being a point-in-time comparison a cron
  job or task hook runs, not a live watch.
- **ATT&CK coverage matrix** (`cau coverage`, `internal/coverage`): derived
  from the shipped content (heuristic categories, the new static and stego
  class catalogs, compiled YARA rule meta), never typed in; text, JSON and
  ATT&CK Navigator layer output; each detector labeled with its Pyramid of
  Pain level; unmapped content listed, never padded. `--expect
  baselines/attack-coverage.txt` gates CI: a lost technique is a regression
  and a gained one must be recorded (`--record`). Four per-technique states:
  detected, partial (acknowledged incomplete), planned (a declared gap:
  T1027.013, T1140, T1564.001) and none (owned by the sensor or console);
  the SARIF rendering flags planned gaps as warnings.
- **YARA rule linter** (`cau rules lint`, `internal/rulelint`): compile
  diagnostics, required meta (description, author, threat_level 1-5, family,
  mitre_attack with a valid id), hex-written-as-text strings (the dead-rule
  class Phase 0 found), strings under four bytes, narrow-only text, trivial
  conditions; `cau` and `generic` profiles, text or JSON, `--strict`.
  `cau rules list` prints the compiled inventory. `make lint-rules` runs in CI.
- **OCSF output** (`--format ocsf`): one Detection Finding (class 2004, OCSF
  1.3.0) per suspicious or malicious file with severity, the leading
  analytic, ATT&CK techniques with names, file evidence and digests, malware
  names and the engine-native detail under `unmapped`.
- `mitre_attack` meta on every bundled rule; `static.Classes()`,
  `stego.Classes()` and `YaraScanner.RuleInfos()` expose the content
  catalogs; `internal/attack` carries technique names (ATT&CK v15).
- **ELF structural pass** (`scanner/static`): own bounds-checked ELF parser
  (32- and 64-bit, both byte orders; executables, shared objects, relocatable
  objects and kernel modules) reading segments, sections, the dynamic table,
  dynamic or `.symtab` symbols, notes, `.modinfo` and the appended module
  signature, overlay, UPX markers and the generic packed profile, and an
  import-set hash for clustering. Labeled anomaly classes for RWX and packed
  segments, stripped or invalid section tables, entry-point placement,
  executable stacks, non-system program interpreters, insecure
  `RPATH`/`RUNPATH`, text relocations, `DT_INIT` outside code,
  LD_PRELOAD-style libc interposers (known interposers named at weight 0),
  loader-only imports, unsigned or `modinfo`-less kernel modules and
  malformed tables. Rendered in text, JSON (`is_elf`, `static.elf`,
  `static.import_hash`; schema 1.3.0) and SARIF (`import_hash`, `interp`,
  `packer` properties); `cau hash` and `cau cluster` accept ELF. Measured: 0
  detections on 4,974 ELF files and 40 kernel modules from a Kali install.
- Heuristics read ELF imports (undefined dynamic symbols, or a kernel
  module's undefined `.symtab`) through the same indicator table, with a
  small Linux set (`ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd` as
  injection) and a **Kernel Rootkit** category (T1014: `kallsyms_lookup_name`,
  kprobe and ftrace registration, `set_memory_rw`, `text_poke`,
  `sys_call_table`). `HeuristicResult.IsELF`; `is_elf` in JSON.
- Smoke corpus: two synthetic ELF fixtures (a clean PIE and a dropper
  profile) written byte-for-byte by `TestWriteELFFixtures`; baseline
  re-recorded with the `static` detector's first true positive.
- Documentation set under `docs/` (installation, CLI reference, detectors,
  output formats, detection content, evaluation, library usage, architecture,
  limitations, contributing); the README is now the landing page.
- **Detection fusion lattice** (`scanner/fusion`): every detector's result is a
  source with evidence labels and ATT&CK / NOVEL ids; the strongest counts in
  full, sources at or above 0.4 of their own threshold corroborate at half
  weight, hash and YARA hits are never downgraded. Rendered in text, JSON
  (`fusion`), SARIF (`fusion/corroborated`) and the exit policy; a `fusion`
  eval detector reports only corroborated-only verdicts. Measured: 0 fused-only
  detections and 0 new false positives on the 349-file Kali Windows tool set.
- **Invisible-codepoint detector** (`scanner/stego`, NOVEL-001/002):
  zero-width characters, bidirectional overrides (Trojan Source), TAG
  characters and data-carrying variation selectors in UTF-8 / UTF-16 text and
  code, presence-based with named context exceptions (BOM, emoji sequences,
  joining and spaceless scripts, right-to-left lines, CJK variation sequences,
  flag sequences). `--no-stego`, `--stego-threshold`; SARIF `stego/<class>`
  rules with byte-offset regions. Measured: 0.10 % false positives on 70,102
  benign text artifacts.
- ATT&CK technique on every heuristic category (`scanner.CategoryTechnique`,
  `scanner.Categories`), rendered in text and JSON.
- **Static structural pass** (`scanner/static`): own bounds-checked PE parser,
  Shannon entropy (whole file and sliding window), TLSH / ssdeep / imphash,
  section / entry-point / header / import / packer / overlay / Authenticode
  anomalies as labeled classes with ATT&CK mapping, fuzzy-hash database
  (`signatures/fuzzy.txt`), import clustering. New commands `cau hash`,
  `cau cluster`, `cau add-fuzzy`; `--no-static`, `--static-threshold`,
  `--fuzzy-db`, `--no-fuzzy`.
- Evaluation harness (`cau eval validate|run|report|diff|gate|policy`,
  `internal/eval`), committed smoke corpus, baseline and regression policy;
  `make eval` in CI.
- JSON (schema 1.2.0) and SARIF 2.1.0 output, `--fail-on` exit-code policy,
  `--jobs` concurrency, resource discovery relative to the install prefix.
- **Distribution packaging.** Debian/Kali source and binary packages
  (`debian/`: control, rules, postinst creating the unprivileged `cau` user,
  postrm removing it only on purge, docs, watch with a real tagged upstream),
  an Arch `PKGBUILD` + `.SRCINFO` ready for the AUR (`packaging/arch/`), the
  systemd units installed by both, a `make install` that also carries the man
  pages, shell completions and the license (plus `make install-systemd`),
  `scripts/apt-repo.sh` for a signed apt repository, and CI that builds,
  installs and smoke-scans every one of those packages (`package.yml`).
- **Shell completion** (`cau completion bash|zsh|fish`): the scripts are
  embedded in the binary, mirror the real dispatch, accept both `-flag` and
  `--flag` spellings, and are installed for all three shells. A test asserts
  every command in `cau help` appears in every script, so the two cannot drift.
- **Man pages** for `cau` and `cau-mcp` (`docs/cau.1`, `docs/cau-mcp.1`),
  installed under the share directory and by every package.

### Changed
- **Durable atomic writes:** the quarantine vault and the update channel now
  `fsync` the temp file before the rename (and best-effort `fsync` the
  directory after), so a crash can never leave a renamed-in index or database
  with torn or zero contents — the integrity seals only mean something if the
  bytes they cover reached disk.
- **Honest MCP sandbox claim:** the path-confinement comment and `docs/mcp.md`
  no longer overstate the guarantee. Resolve-time symlink containment holds, but
  access is by resolved path (not a retained `O_NOFOLLOW` descriptor), so a
  component swapped after resolution is a residual TOCTOU; this is now stated
  plainly rather than claimed closed.
- The `cau-mcp` server now runs the full CLI detector set: the Shell Link
  (`lnk`), OLE macro (`ole`), PDF (`pdf`), ISO container (`iso`) and
  obfuscation-chain (`peel`) passes are enabled by default (each with a
  `--no-*` flag) and surfaced in the tools' per-detector scores and
  suspicious-tier verdict, so the agent-facing scan matches `cau scan` as the
  docs state.
- Remaining "Astra" naming in the plan, layout and ignore rules renamed to
  CAU, and the GitHub repository is renamed to `s-b-repo/cau` (the old name
  redirects); only the historical origin keeps the Astra name.
- YARA runs in-process through go-yara with a per-scan timeout; rules are
  compiled once; rule meta, namespaces and warnings are kept.
- Heuristics score once per pattern with category caps and a weak-category
  budget; threshold retuned to 7 on the Kali Windows tool set (60 → 28
  detections, credential tools still detected).
- Bundled rules carry `ascii wide`; two rules that could never fire were
  rewritten; the loose ransomware-extension rule requires a ransom-note name.
- Signature database loading validates type, hex and length, rejects
  duplicates and conflicting re-labels; synthetic filler entries removed.

### Removed
- Shelling out to the `yara` binary.

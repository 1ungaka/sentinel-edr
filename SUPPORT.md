# Support Policy

Two artifacts, two support models. The engine and the agents are MIT software
supported like open-source software: publicly, by issue, best effort. The
console is a commercial product with response commitments that follow the
tiers in [pricing.toml](pricing.toml). This file states which is which, so
nobody has to guess.

## Channels and hours

| | Free engine (`cau`, `cau-mcp`, content, updates) | Console (`cau-console`) |
|---|---|---|
| Channel | GitHub [issues](https://github.com/s-b-repo/cau/issues) — public | Support address named in your agreement; public email `support@cybersec.org.za` |
| Hours | Best effort, whenever a maintainer picks it up | Per tier (below) |
| Response target | None — community best effort | Per tier, contractual |
| Who answers | Maintainers and contributors | CAU support, escalated to engineering |
| Security issues | Do **not** use issues — see [SECURITY.md](SECURITY.md) | Same: report privately |

Business hours are 09:00–17:00 SAST (UTC+2), Monday to Friday. South African
public holidays are not business days.

## Scope matrix

| Surface | Free engine | Console |
|---|---|---|
| Detection (hash, YARA, heuristics, static, stego, encchain, peel, LNK, OLE, PDF, ISO, linuxpkg, archive, CHM, fusion) | Community, via issues | Commercial |
| On-host prevention (quarantine, restore, block, kill, canaries) | Community, via issues | Commercial (managed centrally) |
| `cau-mcp`, the MCP tools and sandbox | Community, via issues | Commercial (governance surfaces only) |
| Signed updates, `cau update` / `cau verify-self` | Community, via issues | Commercial |
| SIEM forwarding the agent speaks directly (Wazuh via `cau scan --wazuh-url …`; syslog / Splunk HEC / Elastic `_bulk` / OCSF Lake when added) | Community, via issues — **free** | Not a console surface |
| Console installation, upgrades, backups | Not applicable | Commercial |
| Fleet, policy, incidents, RBAC/SSO, multi-tenancy | Not applicable — nothing to install | Commercial |
| Threat Graph, evasion telemetry, prevalence | Not applicable | Commercial (Scale tier) |

What the split means in practice: everything a single host can do — detect
*and* respond — is supported for free through the issue tracker, because the
free agent is a complete product. Commercial support exists for the
fleet-management plane, which only exists in the console.

## Service levels by tier

Service levels match the tiers in [pricing.toml](pricing.toml) exactly; the
machine-readable file is the source of truth if the two ever disagree.

| Tier | Hours | Response | Availability target |
|---|---|---|---|
| Community (free engine) | Best effort | None | None |
| Starter | Business hours | Next business day for defects | None |
| Growth | Business hours | P1 within 8 business hours | 99.5% monthly |
| Scale | 24×7 for P1 | P1 within 4 hours; P2 within 1 business day | 99.9% monthly |

A P1 is: the console is down or unreachable, the fleet is blind, or a
security defect in the console plane is being actively exploited. Anything
that waits until morning without harm is not a P1.

## Escalation path

1. **Tier 1 — the issue tracker** (free engine) or the support address
   (console). Include: component and version (`cau version`), the exact
   command, the smallest input that shows the behaviour, and the verdict or
   error you got.
2. **Tier 2 — maintainer triage.** Reproduction attempt, severity and
   priority assignment. On the free engine this is the last tier; on the
   console it hands off within the tier's response target.
3. **Tier 3 — engineering.** Assigned on the console's paid tiers per the
   response targets; on the free engine it happens when a maintainer can,
   not on a clock.
4. **Security** — a suspected vulnerability leaves this path immediately for
   the private channel in [SECURITY.md](SECURITY.md); it never stays in a
   public issue.

Repeat contact about a stalled issue is fine and not rude. Reference the
issue number and what changed since the last update.

## Platform support — what stays supported, and for how long

EOL operating systems are retained deliberately, because real fleets
cannot upgrade on the vendor's clock:

| Class | Definition | Support |
|---|---|---|
| Frontline | the two newest LTS branches per major distro (Debian/Ubuntu/Kali, Fedora/RHEL, Arch) | full matrix, current release |
| Legacy/EOL | a distro past its own EOL date | at minimum two years beyond distro EOL: packages, detection and sensor keep working |
| Retired | beyond Legacy | documented here, per release, and never silently dropped between releases |

Feature degradation on an EOL platform is stated in the release notes, not
silently absorbed. Reports of hosts running an EOL OS are flagged in plain
wording by design — the product never implies an EOL host is secure and never
offers to hide the flag.

## Explicitly out of scope

- **False positives and detection tuning.** A rule that fires on legitimate
  software, or one that misses, is an issue-tracker report, not a support
  case: give the SHA-256 of the sample (never the sample), the verdict, and
  what you expected. Content changes go through the evaluation gates like any
  other detection change.
- **Feature requests and roadmap commitments.** The plan lives in
  [PLAN.md](PLAN.md); discussion belongs in issues, not in a support thread.
- **Analysis of your samples for you.** CAU is a tool, not an analysis
  service. Support helps you run the tool; it does not triage your malware.
- **Building, hosting or operating your deployment for you.** Self-hosted
  deployments are yours; professional-services engagements exist separately
  and are not part of a support tier.
- **Upstream bugs.** libyara, the C toolchain, distro packaging bugs: report
  upstream; support helps you work around them inside the console tier.
- **Windows.** Builds work with a pkg-config-findable libyara but are not
  CI-exercised; support on Windows is best effort at every tier. Linux and
  macOS are the supported targets.
- **Anything asking us to weaken a control.** Support will not help disable
  detection, exclude paths silently, or backdate a baseline. Exclusions are
  time-boxed, owned and audited in the console by design; there is no
  "risk accepted" switch, and support does not become one either.

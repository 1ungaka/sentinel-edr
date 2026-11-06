# Pricing

> **Draft.** Every number on this page is a v1 draft placeholder, rendered
> from the machine-readable source in [`pricing.toml`](../pricing.toml). The
> numbers are under owner review and must not be quoted as final until that
> review is done. Drafted 2026-11-05.

**Detection and prevention are free, forever. You pay only for fleet
management.**

That is the whole pricing story, and it is structural rather than
promotional. The engine and every agent are MIT software with no license
check at all: all detection — hash, YARA, heuristics, static structure,
invisible-codepoint, encoded-executable, obfuscation-chain, document,
container, package, archive and CHM passes, fused — and all on-host
prevention — quarantine, restore, block, kill, canaries — run on every host
with no license, no metering and no phoning home. The only paid artifact is
the multi-agent management console, because coordinating, distributing
policy to and governing many agents from one pane is inherently stateful
server-side work. It adds nothing to what a single free agent can already do
alone.

## What is free, and stays free

| Included in the free engine (MIT) | |
|---|---|
| Detection | all sixteen detectors plus the fusion lattice, shipped as content with measured false-positive rates |
| Prevention | the full on-host response set: quarantine vault, restore, block, kill, canary tamper checks |
| Output | text (control-char / bidi escaped), JSON schema 1.11.0, SARIF 2.1.0, OCSF 1.3.0 Detection Findings, CI exit codes |
| SIEM forwarders | the agent speaks SIEMs directly, so SIEM delivery is free. `cau scan --wazuh-url <manager>` posts the scan's OCSF findings to the Wazuh Manager REST API (`/security/user/authenticate` + `/events`) with JWT auth and a configurable CA bundle. syslog, Splunk HEC, Elastic/OpenSearch `_bulk` and OCSF-Lake sinks follow the same rule and ship free when added. The resident agent forwards too, not just one-off scans: `cau defend --wazuh-url <manager>` posts every correlated incident as it is raised, asynchronously and with a bounded local queue, so continuous delivery to your own SIEM needs no control plane |
| Tooling | `cau-mcp` (the Model Context Protocol server), the evaluation harness, the rule linter, the coverage matrix |
| Updates | the signed update channel, including the air-gapped bundle path — verified fail-closed before install |

No per-host charge, no scan metering, no telemetry egress fee, no
watermarks in report content.

## What you pay for

`cau-console` is a web console that runs a fleet of the free agents from one
pane. The paid-feature shape is **final**; only the monetary values on this
page are the DRAFT noted at the top.

| Paid surface (`cau-console`, proprietary) | What it does (and why it cannot live on a single host) |
|---|---|
| Fleet inventory and health | one roster across sensor agents, scan nodes and registered MCP/AI agents, with heartbeat, version and content-manifest drift — inherently cross-host |
| Central policy distribution | signed, audit-logged policy-as-code (`cau scan` flag sets, YARA rule packs, Wazuh / syslog / Splunk sink endpoints, quarantine rules) fanned out to agents, with a test-before-promote lifecycle and a diffable rollback timeline — the artefact is the fleet, not the host |
| Cross-host incident timelines | one incident across agents that each saw a piece of the attack — the correlator is a server, not a host |
| Multi-tenancy, RBAC, SSO, audit | tenants, roles, identity providers and a tamper-evident audit log — cross-identity state the agent cannot hold alone |
| Content lifecycle | review / sign / promote / revoke YARA rules, hash lists, intel feeds and bypass catalogues — one authoritative source the fleet reads |
| Threat Graph (Scale tier) | fleet-derived prevalence, evasion-distance telemetry and lateral-movement timelines — statistics over the fleet, not over one host |
| Service levels | contractual response / uptime / privacy posture — contractual, not technical |

License enforcement lives in the console server alone; if a license check
ever appears in the agent or engine, that is a bug.

**What is explicitly NOT paid**, by the same rule (restated here because
these are the places the paid/free line gets fuzzy in practice):

- Every detector and its content. Hash, YARA, heuristics, static structure,
  stego, encchain, peel, lnk, ole, pdf, iso, linuxpkg, archive, chm,
  tradecraft (LOLBAS / GTFOBins / lolol.farm / ArcticFox-bypass),
  fusion — all free.
- Every on-host response. Quarantine, restore, block, kill, canary
  checks — all free.
- Every SIEM sink the agent speaks to directly. The agent-to-Wazuh forward
  (`cau scan --wazuh-url …`) is shipped and free. syslog, Splunk HEC,
  Elastic / OpenSearch `_bulk`, and the OCSF Lake sink follow the same rule.
- `cau-mcp` and the Model Context Protocol tools.
- The evaluation harness, coverage matrix, rule linter and content-update
  channel (including the air-gapped bundle path).
- Running the agent in a fleet of one by hand, across any number of hosts.

The console is licensed **per managed agent** — one enrolled sensor agent,
scan node or registered MCP/AI analysis agent. Autonomous detection agents
run by CAU are not billed. License terms follow [PLAN.md's licensing
mechanics](../PLAN.md): the paid surface is always something a single host
cannot host alone.

## Tiers

The tier is set by the fleet's managed-agent count; the per-agent price comes
from the volume bands below.

| Tier | Managed agents | Per agent / year | Included |
|---|---|---|---|
| **Starter** | 1–25 | $18 | fleet inventory and health, central policy, incident timelines, detection-content lifecycle, 1 tenant |
| **Growth** | 26–250 | $12–15 | everything in Starter, plus RBAC/SSO, agent governance, coverage reporting and SARIF/JSON/OCSF export, 3 tenants |
| **Scale** | 251–2,500+ | $7–10 (from $5 beyond 2,500) | everything in Growth, plus Threat Graph, evasion telemetry and fleet prevalence, named contact, 10 tenants |

## Volume bands

The band the fleet falls in is the price, per managed agent per year:

| Band | Agents | Per agent / year |
|---|---|---|
| Starter | 1–25 | $18 |
| Growth (low) | 26–100 | $15 |
| Growth (high) | 101–250 | $12 |
| Scale (low) | 251–1,000 | $10 |
| Scale (high) | 1,001–2,500 | $7 |
| Enterprise | 2,501+ | from $5 — quoted per agreement |

Agents added mid-term are billed pro-rata at the new fleet size's band rate;
a fleet that crosses a band mid-term is trued-up at renewal.

## Term, renewal and air-gapped deployments

- **Term:** 1 year, billed annually in advance. Currency USD; local-currency
  invoicing is supported where the console already bills in it.
- **Renewal notice:** 30 days before expiry, so procurement is never a
  surprise.
- **Air-gapped / offline renewal:** the license is a signed file on the same
  terms as the online path — portal download, email, or physical media for
  regulated buyers. No console needs a network connection at any point. An
  air-gapped console keeps running for a **30-day grace period** past expiry
  while the renewal is in transit.
- **Multi-tenancy add-on:** the included tenants above ship per console
  deployment. Additional isolated tenants are **$40 per tenant per month**,
  billed with the console term. Tenant isolation, quota, org → group → host
  hierarchy and cross-tenant pivoting are console-licensed; the agent has no
  tenant concept by design.

## Service levels

Service levels match [SUPPORT.md](SUPPORT.md) exactly; the free engine is
community support through the issue tracker at every scale, because it is a
complete product, not a trial.

| Tier | Hours | Response | Availability target |
|---|---|---|---|
| Starter | business hours (09:00–17:00 SAST, Mon–Fri) | next business day for defects | none |
| Growth | business hours | P1 within 8 business hours | 99.5% monthly |
| Scale | 24×7 for P1 | P1 within 4 hours | 99.9% monthly |

## TCO calculator — the assumptions, labelled

The TCO model below is honest by construction: every row says whether it is
a **measured fact** (structural in this repo's licensing, or gated in CI) or
an **assumption** (a number the owner must validate). The comparison
baseline is per-host list pricing of a mainstream commercial EDR — an
observation of published list prices, not a negotiated deal.

| Row | Value | Kind | Note |
|---|---|---|---|
| CAU engine + agent license | $0 / host | Fact | MIT, free and unmetered; all detection and prevention included |
| On-host response | $0 | Fact | quarantine, restore, block, kill and canaries ship in the free agent |
| Console license | from the volume bands | Fact | the only metered surface |
| Mainstream EDR per-host list price | $150 / host / year | **Assumption** | validate against current public list prices before relying on it |
| Baseline covers protection + management | yes | **Assumption** | whole-product comparison, not detection-only |
| Host refresh cycle | 4 years | **Assumption** | licenses move with re-purchased hosts |
| Deployment labour | 1 operator-day / 100 agents | **Assumption** | enroll, group and baseline |
| Scan metering / egress | $0 | Fact | no per-scan charge for the free engine |

### Worked examples (3-year horizon, draft)

| Fleet | CAU console / year | CAU, 3 years | Baseline / year | Baseline, 3 years | Difference |
|---|---|---|---|---|---|
| 10 agents (Starter) | $180 | $540 | $1,500 | $4,500 | $3,960 |
| 100 agents (Growth) | $1,500 | $4,500 | $15,000 | $45,000 | $40,500 |
| 500 agents (Scale) | $5,000 | $15,000 | $75,000 | $225,000 | $210,000 |
| 2,000 agents (Scale) | $14,000 | $42,000 | $300,000 | $900,000 | $858,000 |

Baseline rows are the assumption-priced comparison above; they are not a
quote. The console year is agents × band rate — 10 × $18, 100 × $15, 500 ×
$10, 2,000 × $7 — and includes tenants below the included count. The honest
caveat: the saving is real only because the free agent is genuinely complete,
so nothing on the single-host detect-or-prevent surface is missing from the
$0 column. That boundary is enforced by the licensing mechanics, not by this
page.

## Common questions

**Can I run the free engine forever without the console?** Yes — one host or
a standalone agent is fully functional alone, including blocking. You lose
only the multi-agent pane: central policy, cross-host timelines, fleet
governance.

**Is any detection feature held back from the free tier?** No. The paywall
is multi-agent management. Memory, fileless and behavioural detections are
agent-side capabilities, not console upsells, and the roadmap does not move
them behind the paywall.

**How do I get a quote?** Email `support@cybersec.org.za` with the
managed-agent count and how many consoles and tenants you need. Air-gapped
and regulated deployments quote the same numbers plus the offline renewal
path.

**Where do these numbers come from?** [`pricing.toml`](../pricing.toml) — the
checked-in source of truth this page renders. If the two ever disagree, the
TOML is right and this page is stale.

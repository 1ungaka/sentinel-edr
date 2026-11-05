# Security Policy

CAU is security software, so its own vulnerabilities are reported privately
and fixed on a published clock. This policy covers both artifacts: the free
engine (`cau`, `cau-mcp`, the detection content and the signed update
channel in this repository) and the proprietary multi-agent management
console (`cau-console`).

## Supported versions

Only the newest engine line receives security fixes. The engine reports its
version with `cau version`; the default build stamp is `0.1.0-dev` until the
first release is tagged.

| Component | Version | Supported |
|---|---|---|
| Engine (`cau`, `cau-mcp`) | 0.1.x | Yes — fixes in a patch release on the next signed update channel |
| Engine (unreleased main) | latest commit on `main` | Best effort — fixes land on `main` first |
| Engine | < 0.1 | No |
| Console (`cau-console`) | current release | Yes — under the customer's commercial agreement |
| Console | end-of-life releases | No — see the console release notes for the supported window |
| `cau-kernel` (separate repository) | current release | Yes — report through the same channel |

Detection content (signatures, YARA rules) is not a "version" in this sense:
it ships through the signed update channel and is refreshed independently of
the engine. `cau update` verifies every bundle fail-closed before it installs.

## Reporting a vulnerability — privately, please

Do not open a public issue for a suspected vulnerability. Two private
channels, pick either:

1. **Email** — `security@cybersec.org.za`. Write in plain text; a proof of
   concept as a patch or a CI-safe description is welcome. Please include the
   component (`cau`, `cau-mcp`, packager, console), the version or commit,
   how you found it, and the impact you believe it has.
2. **GitHub private vulnerability reporting** — the repository's *Security*
   tab → *Report a vulnerability* on
   `github.com/s-b-repo/cau`. Reports stay private to the maintainers until
   they are disclosed. This is the preferred path for anything involving the
   public repository itself.

A PGP key for the address above is available on request; report whichever
way is easiest for you — a readable unencrypted report beats an unreadable
encrypted one.

## What happens after you report

| Step | Target |
|---|---|
| Acknowledgement | 2 business days |
| Triage and severity classification (with the reporter copied) | 5 business days |
| Status updates | at least every 14 days until closure |
| Fix window, critical | 7 days (or a stated mitigation) |
| Fix window, high | 30 days |
| Fix window, medium | 90 days |
| Fix window, low | best effort, scheduled with a release |

Severity is classified by the maintainers against the actual attack surface:
what the component runs on, with what privileges, on what input, with what
the attacker already controls. A parser that crashes on a hostile file it was
built to parse is rated differently from a console-plane flaw.

**Coordinated disclosure: 90 days.** Reporters and maintainers coordinate on
one disclosure date, targeted at 90 days from the report or from the fix's
availability, whichever the reporter prefers within that window. The reporter
gets credit unless they ask not to. The maintainers will not disclose a
reported vulnerability without telling the reporter first.

## Scope

In scope:

- The engine: `cau`, the scanning and MCP surfaces, the detection content,
  the quarantine vault, the peeler and every untrusted-input parser.
- The distribution path: the signed update channel (`cau update`), release
  signing, `cau verify-self`, package builds and the apt repository.
- The console: the web control plane, its API, authentication, multi-tenancy
  isolation, and the sensor/console protocol.
- The engine's own anti-tamper claims — a way to silently disable detection,
  gut content, or make `cau selftest` pass on tampered content is in scope.

Out of scope:

- **False positives and detection-quality reports.** A missed detection, a
  rule that fires when it should not, a score that needs retuning: these are
  not vulnerabilities and this policy does not apply. Open a normal issue and
  include the sample's SHA-256 (never the sample itself), the verdict, and
  what you expected. The evaluation corpus and regression gates handle them.
- Vulnerabilities in third-party dependencies (report those upstream; if the
  flaw is exploitable *through* CAU in a way upstream does not cover, that is
  in scope — say so in the report).
- Anything requiring an already-compromised host, physical access, or an
  attacker-controlled kernel to reach, unless it defeats a specific
  anti-tamper claim listed above.
- Social engineering of maintainers or users.

## Safe harbour

Research in good faith under this policy is authorised: no maintainer will
pursue or support legal action for good-faith testing, reporting, and
disclosure within these rules. Stay inside the law, do not access systems or
data that are not yours, do not run destructive tests against anyone else's
infrastructure, and never commit real malware samples to this repository —
reference them by hash.

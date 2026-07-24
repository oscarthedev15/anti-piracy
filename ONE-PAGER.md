# AEGIS — Precision Piracy Enforcement for Regulators

**Attribute the operator. Act with precision. Prove every action.**

---

## The problem regulators face today

State-mandated blocking of live-sports piracy is now EU policy, and the flagship
implementation — Italy's Piracy Shield — has exposed two failures that every new
regime inherits:

- **Collateral damage.** Independent 2025 analysis documented 500+ legitimate
  sites blocked, along with shared CDNs, DNS resolvers, and mail servers taken
  down by blunt IP-level blocks.
- **Trivial evasion.** Operators rotate domains and IPs within minutes. The
  blocklist chases yesterday's URL while the pirate keeps streaming — so the
  harm lands on innocent bystanders and the infringer is untouched.

The result is a system that is simultaneously **too broad** (it hurts the
public) and **too slow** (it misses the target). That is a due-process problem,
not just a technical one.

---

## What AEGIS does differently

AEGIS is a **piracy intelligence and attribution platform built for
enforcement agencies** — not another stream detector sold to broadcasters. It is
engineered against the two failures above.

**1. Target the operator, not the URL.**
AEGIS models each pirate's infrastructure over time as a graph and clusters it
into a single operator using strong, court-explainable signals — shared TLS
certificates, dedicated hosting, private nameservers, reused tracker IDs and
payment wallets. When the operator hops to a brand-new domain, it is attributed
to the known operator and queued to block **before it goes live**.

**2. Precision blocking, collateral damage engineered out.**
Every recommendation is hostname-first and time-limited to the live-event
window. IP-level blocks are emitted **only** for infrastructure proven to be
dedicated to the operator. Shared CDNs, public DNS, and mail infrastructure are
**never** blocked — by design, in code.

**3. Defensible by construction.**
Every automated action is backed by a tamper-evident, hash-chained evidence
record that an ISP or a judge can audit *before* acting. Enforcement becomes
proportionate, reviewable, and legally defensible — directly answering the
criticism aimed at current blocking regimes.

---

## Why this matters to a regulator

| Today's blocking systems | AEGIS |
|---|---|
| Block a list; lose the trail on every domain hop | Attribute the operator; pre-queue their next domain |
| Blunt IP blocks harm 500+ legitimate sites | Hostname-first; dedicated-IP-only; critical infra protected |
| Opaque, hard to defend in court | Hash-chained chain of custody for every action |
| Fully automated, no oversight | Human-in-the-loop by default for high-impact blocks |

---

## Deployment posture

- **Air-gap friendly.** The core runs offline with no external dependencies —
  suitable for sensitive government environments.
- **Auditability first.** Every action is explainable and evidence-linked.
- **Human oversight by default** for the highest-impact enforcement steps.
- **Boundaries respected.** AEGIS monitors and attributes unauthorized
  redistribution of licensed content on behalf of authorized parties. It does
  **not** host, proxy, index, or provide access to any infringing stream, and
  stores only what a lawful enforcement action requires.

---

*Reference implementation available. Core attribution, precision-blocklist, and
evidence-ledger logic is built and tested; content-detection backends and live
collectors are the defined next build phase.*

# AEGIS

**Anti-piracy Enforcement & Graph Intelligence System** — a piracy *intelligence
and attribution* platform for regulators and enforcement agencies, not just
another stream detector.

> Legitimate use only. AEGIS detects and helps enforce against **unauthorized**
> redistribution of licensed live content on behalf of rights holders and public
> authorities. It does not host, index, or facilitate access to any stream. See
> `ARCHITECTURE.md` → "Legal & ethical posture".

---

## Why this exists (the gap)

The rights-holder side of anti-piracy is crowded — Friend MTS, MUSO, Irdeto,
Verimatrix, Sportian/Piracy Guard, IBCAP and others all sell "find the stream,
issue the takedown" to leagues and broadcasters. AEGIS deliberately does **not**
compete there.

The **government/regulator** side is broken. State blocking systems — Italy's
Piracy Shield being the flagship — suffer two documented failures at once:

1. **Massive collateral damage.** Independent 2025 analysis found 500+ legitimate
   sites blocked, plus CDNs, DNS and mail servers knocked out by blunt IP blocks.
2. **Trivial evasion.** Pirates rotate domains and IPs faster than the blocklist
   updates, so the harm lands on bystanders while the operator keeps streaming.

AEGIS is built around fixing exactly those two things.

## The two differentiators

**1. Operator attribution graph (track the network, not the URL).**
Instead of treating each pirate URL as a one-off, AEGIS models the operator's
infrastructure over time — shared TLS certs, dedicated origins, nameservers,
reused tracker IDs and wallets — and clusters it into a single *operator*. When
the pirate hops to a brand-new domain that shares a strong pivot with a known
operator, it is attributed and queued **before it even streams**.

**2. Precision, collateral-damage-guarded blocklists.**
Every recommendation is FQDN-first, time-limited, and evidence-backed. IP blocks
are emitted **only** for provably dedicated single-tenant infrastructure; shared
CDN/DNS/mail IPs are never blocked. Every entry carries a hash-chained evidence
reference an ISP or judge can audit before acting.

## Quickstart (zero dependencies)

**Requirements:** Python 3.9+ only. The core pipeline, demo, and tests are
stdlib-only — no `pip install`, no venv, no services. (Verified on 3.9 and 3.11.)

```bash
# from the repo root — core pipeline is stdlib-only
python3 -m demo.run_pipeline     # runnable end-to-end scenario
python3 -m tests.test_pipeline   # behaviour tests
```

The demo runs the canonical scenario: one operator streams the same match across
three hopped domains in one match week. AEGIS confirms all three, clusters them
into one operator via shared cert + dedicated IP, emits three FQDN blocks and a
single dedicated-IP block, refuses to block the shared Cloudflare front, and
proves its evidence chain is intact.

## Run it for real (no synthetic data, still zero-install)

The attribution, blocklist and evidence stages run on **real, free, public
infrastructure metadata** — resolved DNS, live TLS certificate fingerprints, and
ASN/owner from Team Cymru's free service — all stdlib-only. Detection runs a real
page-signal classifier (HLS/DASH manifests, player libraries, live-event
language).

```bash
python3 -m aegis.live https://host-a.example/live https://host-b.example/live \
    --event "EPL: Team A vs Team B"
```

For each URL this really: fetches and scores the page, enriches confirmed hosts
with real DNS/TLS/ASN, clusters hosts that share a real cert or dedicated IP into
one operator, emits a collateral-damage-guarded blocklist from the real ASN data,
and hash-chains the evidence.

**Honest limits (these are physics, not cost):**
- *Detection* is structural resemblance ("is this a live-stream portal?"), **not**
  licensed-content proof — true content match needs the rights holder's reference
  feed, which no one can do for free. Confidence is capped accordingly.
- *"Dedicated IP"* is inferred from ASN (not a known shared CDN/cloud/VPS) and
  flagged for review — not proven single-tenancy.
- *Discovery* (auto-finding candidate URLs) is the one genuinely fragile-for-free
  stage; v1 takes URLs you supply (a watchlist / tip-offs), which is how real
  enforcement tip lines already work.

## Run the API

```bash
pip install -r requirements.txt
uvicorn aegis.api.main:app --reload     # http://localhost:8080/docs
# or: docker compose up api
```

## Layout

```
aegis/
  models.py                 shared graph/detection/blocklist data models
  pipeline.py               orchestrator: detect -> attribute -> blocklist -> evidence
  config.py                 env-driven settings (dev / air-gapped gov deploy)
  services/
    discovery/              pluggable candidate-stream collectors (stubbed)
    detection/              fingerprint/watermark matcher (stubbed backend)
    attribution/            infrastructure graph + operator clustering  <- core IP
    blocklist/              precision generator + collateral-damage guardrails <- core IP
    evidence/               append-only, hash-chained audit ledger
  api/                      FastAPI gateway
demo/                       synthetic scenario + runnable pipeline
tests/                      behaviour tests
```

## Status

**Runs end-to-end on real data, free and stdlib-only.** Enrichment (real
DNS/TLS/ASN), attribution/clustering, precision blocklist, evidence chain, and a
real heuristic detector all work on live inputs — see "Run it for real" above.

Still stubbed / next up: the **perceptual-fingerprint / watermark** backend
(needs a licensed reference feed) and **automated discovery** collectors. The
`demo/` path remains a deterministic synthetic scenario for tests. See
`ARCHITECTURE.md` for the full design and roadmap.

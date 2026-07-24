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

```bash
# from the repo root — core pipeline is stdlib-only
python -m demo.run_pipeline     # runnable end-to-end scenario
python -m tests.test_pipeline   # behaviour tests
```

The demo runs the canonical scenario: one operator streams the same match across
three hopped domains in one match week. AEGIS confirms all three, clusters them
into one operator via shared cert + dedicated IP, emits three FQDN blocks and a
single dedicated-IP block, refuses to block the shared Cloudflare front, and
proves its evidence chain is intact.

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

Skeleton. The attribution, blocklist, evidence and orchestration logic is real
and tested on synthetic data. The collectors and the perceptual-fingerprint /
watermark backends are interface stubs marked `TODO` — those are where the build
effort goes next. See `ARCHITECTURE.md` for the full design and roadmap.

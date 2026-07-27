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

**Discovery (don't hand-feed URLs).** Point it at a seed portal you already know
and it crawls that site for candidate stream/event pages and third-party iframe
embed domains, then runs the whole pipeline on what it finds:

```bash
python3 -m aegis.live --crawl https://portal.example/ --event "live sports" \
    --max-pages 25 --limit 20
```

One seed expands into the site's full catalogue (in testing, a single landing
page yielded 57 candidate event pages). The crawler and detector share one page
cache, so nothing is fetched twice. `--limit` bounds how many candidates are
scored per run and reports how many were deferred (never a silent cap).

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

## Headless detection (JS-rendered portals)

Real aggregators inject the stream via JavaScript, so static HTML shows nothing.
`--headless` renders the page in a real (headless Chromium) browser and watches
the **network**: when the player boots it *fetches* the `.m3u8`/`.mpd` manifest,
and catching that request is the definitive tell. It also captures the iframe
**embed domains** (usually the real operator) and enriches them into attribution.

```bash
pip install playwright && playwright install chromium     # one-time, ~90 MB, free
python3 -m aegis.live https://match-page.example/ --headless --event "EPL"
```

Verified: on a JS-HLS test page this captured 6 manifest requests (score 0.90)
that the static classifier could not see, and pulled the embed host into the graph.
It renders and observes requests; it never plays or downloads the video itself.

## Discovery: finding domains you don't know yet

The crawler expands a portal you already have; **discovery** surfaces new ones.
`aegis/services/discovery/sources.py` is a pluggable set:

- **Certificate Transparency** (`--discover-ct "kw1,kw2"`) — REAL. New pirate
  domains get TLS certs, published in public CT logs (crt.sh); search by keyword
  to catch them as they appear. Free, no key. (crt.sh is flaky and 502s under
  load; the source retries and fails soft.)
- **Seed crawl** — REAL. Wraps the aggregator crawler.
- **Reverse-infra, public-blocklist, search-engine, social/Telegram** — SKELETON
  interfaces with documented next steps (no fake data).

```bash
python3 -m aegis.live --discover-ct "crackstreams,streameast" --headless
```

## Attribution sweep (who is linked to whom)

Enrich a batch of domains and see the two tiers of linkage on real data:

```bash
python3 -m aegis.sweep totalsportek.com crackstreams.net example.com www.example.com
```

- **CONFIRMED operators** — tied by a strong pivot (shared TLS cert / same
  dedicated server). Auto-merged; treat as one operator.
- **SUSPECTED links** — merely co-located in the same hosting /24 on a VPS
  network. A lead for a human to investigate, **not** proof (unrelated tenants
  share those ranges), so never auto-merged. Big CDN/cloud ranges
  (Cloudflare/AWS/…) are excluded from this tier — their /24s are meaningless.

In a real run this correctly surfaced two different-brand sports-piracy domains
co-located on one Linode /24 as a *suspected* link, while keeping Cloudflare-
fronted sites `do_not_block`.

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

Detection now has two backends: the stdlib **heuristic** classifier and a
**headless** renderer (`--headless`) that catches JS-injected manifests over the
network — verified capturing manifests a static fetch cannot see. Discovery has a
real **seed crawler** (`--crawl`) and real **CT-log** search (`--discover-ct`),
plus skeleton interfaces for reverse-infra / blocklist / search / social sources.

Remaining honest gaps: (1) reaching the actual match page *during a live event*
(operational timing + deeper crawl), and (2) the **perceptual-fingerprint /
watermark** backend that proves licensed-content match — that one needs the
rights holder's reference feed and can't be done for free. The `demo/` path
remains a deterministic synthetic scenario for tests. See `ARCHITECTURE.md`.

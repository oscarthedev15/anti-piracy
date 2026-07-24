# AEGIS — Architecture & Design

## 1. Positioning

AEGIS is a **B2G (business-to-government) piracy intelligence and attribution
platform**. It is deliberately positioned away from the crowded rights-holder
detection market and toward the under-served, and currently poorly-served,
enforcement/regulator segment.

| | Incumbent detectors (Friend MTS, MUSO, Sportian…) | Govt blocking (Piracy Shield…) | **AEGIS** |
|---|---|---|---|
| Buyer | Leagues, broadcasters | Regulator, mandated to ISPs | Regulator / enforcement agency |
| Core question | "Is this URL pirated now?" | "Block this list" | "Who is the operator, and what's the *minimal* precise action?" |
| Domain hopping | Re-detect each time | Loses the trail | **Attributed to a known operator, pre-queued** |
| Collateral damage | N/A (takedown, not block) | Severe (500+ legit sites) | **Engineered out (FQDN-first, infra allowlist)** |
| Legal defensibility | Varies | Weak/opaque | **Hash-chained evidence per action** |

## 2. Data flow

```
                       ┌─────────────┐
  collectors  ───────▶ │  Discovery  │  candidate StreamObservations
 (search, social,      └──────┬──────┘
  IPTV portals, ISDs)         │
                              ▼
                       ┌─────────────┐   perceptual fingerprint / forensic
                       │  Detection  │   watermark match vs protected feed
                       └──────┬──────┘   → DetectionResult (+ evidence record)
                              │
             confirmed hosts  │  infra observations (DNS, TLS, ASN, trackers)
                              ▼
                       ┌─────────────┐   connected-components over STRONG pivots
                       │ Attribution │   → operator clusters, next-hop prediction
                       └──────┬──────┘
                              │
                              ▼
                       ┌─────────────┐   FQDN-first, TTL-bounded, infra-safe
                       │  Blocklist  │   → BlocklistEntry[]  (+ evidence record)
                       └──────┬──────┘
                              ▼
                       ┌─────────────┐   append-only hash chain, verifiable
                       │  Evidence   │   → chain of custody for legal review
                       └─────────────┘
```

## 3. Component design

### Discovery (`services/discovery`)
Source-pluggable collectors emit `StreamObservation`s. Adapters (stubbed):
search-result mining, aggregator-portal crawling, social/messaging monitors.
Production adapters need rotating egress, captcha handling, and headless
rendering for JS portals. Discovery decides *nothing about guilt* — it only
nominates candidates.

### Detection (`services/detection`)
Two signals: **perceptual fingerprint** (robust content match against the
reference feed) and **forensic watermark** (identify the leaking subscriber
source). The shipped `StubFingerprintBackend` is deterministic so the pipeline
runs; the real backend samples the manifest, decodes frames, and matches. Every
positive writes an evidence record *at detection time* — chain of custody starts
before any action.

### Attribution (`services/attribution`) — core IP
The graph stores assets (domains, IPs, certs, nameservers, trackers, wallets)
and typed edges. Operators are **connected components over `STRONG_PIVOTS`
only** — cert reuse, dedicated-IP co-residence, private nameservers, shared
tracker IDs/wallets. Weak signals (shared CDN) are stored but never merge
operators, which is what prevents "everything behind Cloudflare is one pirate"
over-linking. The design choice is *explainability*: a connected-components
result can be shown to a court far more easily than a black-box score. Scaling
path: weighted community detection on a real graph store (Neo4j/JanusGraph), with
the strong/weak split preserved as edge weights.

### Blocklist (`services/blocklist`) — core IP
Turns confirmed detections + attribution into actions, each classified by
`BlockSafety`:
- `IP_SAFE` — dedicated single-tenant IP; IP block permitted.
- `FQDN_ONLY` — shared host/CDN; hostname/URL block only.
- `DO_NOT_BLOCK` — critical shared infra (Cloudflare/Google/AWS/Akamai/MS ASNs,
  public resolvers, MX); never blocked.

Defaults: TTL-bounded to the live-event window; optional mandatory human review
for any IP block (`AEGIS_REVIEW_IP_BLOCKS`). `preemptive_from_operator()`
produces the early-warning queue — an operator's other known domains staged to
block the instant they go live.

### Evidence (`services/evidence`)
Append-only, hash-chained ledger; each record commits to the previous hash so
tampering is detectable, and `verify()` re-walks the chain. Reference impl is
in-memory; production persists to WORM/QLDB/a Merkle log and signs records with
the agency key.

## 4. Non-functional & deployment

- **Air-gap friendly:** core is stdlib-only; all config via env (`config.py`).
  Government tenants can run fully offline with reference-feed material shipped in.
- **Auditability first:** every automated action is explainable and evidence-linked.
- **Human-in-the-loop by default** for the highest-impact action (IP blocks).
- **Scale-out seams** already drawn in `docker-compose.yml` (graph DB, discovery
  workers, queue).

## 5. Legal & ethical posture

AEGIS is an enforcement-support tool for authorized parties (rights holders,
regulators, law enforcement). It monitors and attributes unauthorized
redistribution of licensed content; it does not host, proxy, index, or provide
access to any infringing stream, and stores only what a lawful enforcement
action requires. The collateral-damage guardrails and evidence chain exist
precisely so that state action is proportionate, reviewable, and defensible —
directly answering the due-process criticisms leveled at existing blocking
regimes.

## 6. Roadmap (what to build next, in order)

1. **Real fingerprint backend** — frame sampling + perceptual hashing, scored
   matching against reference feeds. (Highest technical risk → do first.)
2. **Passive-DNS / TLS / ASN enrichment** feeding the attribution graph.
3. **One real collector** end-to-end (aggregator-portal crawler) to prove yield.
4. **Graph store swap** (in-memory → Neo4j) + weighted community detection.
5. **Reviewer console** on the API (approve/deny IP blocks, inspect evidence).
6. **Forensic watermark extraction** for source attribution.
7. **Signed evidence export** in a format prosecutors/ISPs accept.

## 7. AI/ML roadmap (design intent — not yet implemented)

ML expands **recall and prediction**; the deterministic graph, guardrails, and
evidence chain remain the auditable system of record. Nothing here replaces the
explainable core — a black-box score is never the sole basis for a block.

**Detection (highest value, highest risk — build first).**
- Perceptual/robust video hashing + a self-supervised frame-embedding encoder,
  so a match survives re-encode, crop, letterbox, and logo overlay.
- Forensic watermark extraction via a CNN decoder to identify the *leaking
  subscriber source*, not merely that infringement occurred.
- Audio fingerprinting (spectrogram embeddings) as a cheap parallel signal when
  the video is obfuscated.

**Discovery.**
- LLM triage/agent to classify crawl candidates ("infringing live-sports portal?")
  and parse messy aggregator/social pages into structured `StreamObservation`s.
- Embedding similarity over DOM/text/favicon to surface sibling portals of a
  known operator; semantic search over social chatter for event-time spikes.

**Attribution (augment, don't replace, the explainable core).**
- GNN / node2vec link prediction: score whether a new domain belongs to an
  existing operator, surfacing pivots the hand-written `STRONG_PIVOTS` miss.
- Weighted community detection (Louvain/Leiden) replacing connected-components
  at scale, with the strong/weak split preserved as edge weights.
- ML *proposes*; the transparent connected-components result *justifies*.

**Blocklist / decisioning.**
- Calibrated confidence models (conformal prediction for guaranteed error
  bounds) gating the human-review threshold on IP blocks.
- Anomaly detection on infrastructure churn to predict *when* an operator hops
  next → time the preemptive queue.

**Cross-cutting.**
- RAG-backed evidence summarization: an LLM drafts prosecutor-ready enforcement
  rationale from the hash-chained evidence (ground truth), so it cannot
  hallucinate the facts.
- Human-in-the-loop feedback: reviewer approve/deny decisions become training
  signal for the attribution and confidence models.

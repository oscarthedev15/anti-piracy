# AEGIS — Partner Validation Brief

*A one-page, honest brief to decide whether this is worth building further. It
leads with a real run — including a lead the tool talked itself out of — because
the point is to find out if the output is useful, not to sell you on it.*

---

## The one line

AEGIS turns a suspected pirate URL into a **precise, evidence-backed, collateral-
damage-checked enforcement record** — and is disciplined enough to say "this lead
is probably nothing" when that's the truth.

## The problem it targets

State-mandated stream-blocking (e.g. Italy's Piracy Shield, and the EU model
pushing others to copy it) fails two ways at once: it **over-blocks** (500+
legitimate sites, CDNs, DNS and mail servers knocked out by blunt IP blocks) and
it **loses the trail** every time a pirate rotates domains. The result is a
system that harms bystanders while missing the target — a due-process problem as
much as a technical one. AEGIS is built to be the opposite: minimal, precise,
auditable action.

## A real run (unedited findings)

Fed two live sports-piracy domains, on public metadata only, in ~30 seconds:

- **Block safety:** both sit behind Cloudflare → **`do_not_block` at the IP
  level** (IP-blocking them would take down unrelated sites). Correct action:
  block the hostname only.
- **Operator link:** the two brands appeared co-located in one hosting range —
  flagged as a **SUSPECTED link, not confirmed.**
- **The tool then corrected itself:** a deeper reverse-IP check found that server
  hosts **500+ unrelated tenants** (adult sites, e-commerce, webmail) — i.e.
  shared hosting. So the "same operator" lead was **probably false**, and it was
  suppressed as noise rather than asserted.

That last step is the product. Most "connections" in this space are shared-
hosting coincidence; the value is a system that tells a real link from a
coincidence and **keeps an evidence trail for every call.**

## What's genuinely different

| | Incumbent detectors | Govt blocking today | **AEGIS** |
|---|---|---|---|
| Optimises for | Recall (find every stream) | Speed (block the list) | **Precision + proportionality** |
| Collateral damage | N/A (takedown) | Severe | **Engineered out (FQDN-first, CDN/shared-host guards)** |
| Uncertainty | — | Asserted as fact | **Labelled: confirmed vs suspected; false leads dropped** |
| Defensibility | Varies | Weak/opaque | **Hash-chained evidence per action** |

## Honest status (no overclaiming)

**Works today, free, on real data:** infrastructure enrichment (DNS/TLS/ASN),
operator attribution with confirmed/suspected tiers, precision blocklist with
guardrails, tamper-evident evidence chain, and discovery via portal crawling,
Certificate Transparency, and reverse cert/IP pivots.

**Not solved for free — needs data or a partner:**
1. **Proving licensed-content match** (this stream *is* your broadcast) requires
   your reference feed. Impossible for anyone without it.
2. **Reaching the stream** on JS-rendered sites during a live event (headless
   render works; doing it at scale is ops).
3. **Attribution depth** (passive DNS / historical infra) needs a data provider.

## What I'm actually asking

Not for a sale — for a straight answer to four questions:

1. Is a **precise, hostname-first, time-limited blocklist with a per-action
   evidence trail** something you would act on, or do you already have this?
2. Does the **"suspected vs confirmed, and here's why"** distinction matter to
   your process, or is it noise?
3. What would the output need to look like for your team / an ISP / a court to
   use it **without rework**?
4. Would you be a **design partner** — a few real targets and feedback — in
   exchange for the tool built to your acceptance bar?

## What a partnership unlocks

A design partner + a small data budget (passive DNS; and for content proof, a
reference feed) is the entire gap between "honest prototype" and "an enforcement
tool someone runs." If the answers above are yes, that's the next step. If
they're no, better to know now than after another quarter of engineering.

*Reference implementation is real and runnable (attribution, guardrails, evidence,
and discovery all work on live data). Content fingerprinting and scaled discovery
are the defined, funded-next phase.*

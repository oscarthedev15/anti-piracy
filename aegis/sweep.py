"""
Attribution sweep — enrich a batch of domains and report who is linked to whom.

    python -m aegis.sweep totalsportek.com crackstreams.net example.com www.example.com

For each domain it does the real, free enrichment (DNS / TLS cert / ASN), then
reports TWO tiers of linkage:

  CONFIRMED operators  — domains tied by a strong pivot (shared TLS cert, same
                         dedicated server). Auto-merged; safe to treat as one.
  SUSPECTED links      — domains merely co-located in the same hosting /24. A
                         lead for a human to investigate, NOT proof (unrelated
                         tenants share these ranges).

Plus the block-safety verdict per domain from real ASN data.
"""
from __future__ import annotations

import sys
from collections import defaultdict

from aegis.asn_registry import classify
from aegis.models import AssetType
from aegis.services.attribution.graph import AttributionGraph
from aegis.services.blocklist.generator import BlocklistGenerator
from aegis.services.enrichment.live import LiveEnrichment


def sweep(domains: list[str]) -> None:
    enr = LiveEnrichment(timeout=6)
    graph = AttributionGraph()

    print(f"Enriching {len(domains)} domain(s) — real DNS/TLS/ASN…\n")
    rows = []
    for d in domains:
        e = enr.enrich_into_graph(d, graph)
        rows.append(e)

    # ---- table ----
    print(f"{'domain':24} {'up':3} {'ip':16} {'asn':9} {'class':6} {'cert[:10]':12}")
    print("-" * 78)
    for e in rows:
        ip = e.ips[0] if e.ips else "-"
        cls = classify(e.asn)
        cert = (e.cert_sha256 or "-")[7:17]
        print(f"{e.host:24} {'yes' if e.reachable else 'NO ':3} {ip:16} "
              f"{('AS'+str(e.asn)) if e.asn else '-':9} {cls:6} {cert:12}")

    # ---- tier 1: confirmed operators ----
    print("\n=== CONFIRMED operators (strong pivot — shared cert / server) ===")
    labels = graph.known_operator_assets()
    clusters = defaultdict(list)
    for aid, op in labels.items():
        a = graph.assets[aid]
        if a.type == AssetType.DOMAIN:
            clusters[op].append(a.value)
    if clusters:
        for op, doms in sorted(clusters.items()):
            print(f"  {op}: {sorted(doms)}  <- treat as ONE operator")
    else:
        print("  (none)")

    # ---- tier 2: suspected links ----
    print("\n=== SUSPECTED links (same hosting /24 — investigate, not proof) ===")
    links = graph.suspected_links()
    if links:
        for i, lk in enumerate(links):
            print(f"  S-{i:02d}: {lk['domains']}")
            print(f"        {lk['reason']}")
    else:
        print("  (none)")

    # ---- block-safety verdicts ----
    print("\n=== Block-safety per domain (real ASN guardrail) ===")
    gen = BlocklistGenerator(graph=graph)
    for e in rows:
        if not e.reachable:
            continue
        dom_id = next((aid for aid, a in graph.assets.items()
                       if a.type == AssetType.DOMAIN and a.value == e.host), None)
        verdict = "FQDN-only"
        if dom_id and e.ips:
            primary = next((self_a for self_a in graph._adj.get(dom_id, set())
                            if graph.assets[self_a].type == AssetType.IP
                            and graph.assets[self_a].value == e.ips[0]), None)
            if primary:
                verdict = gen._ip_safety(graph.assets[primary]).value
        print(f"  {e.host:24} {verdict}")


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("usage: python -m aegis.sweep <domain> [<domain> ...]")
        raise SystemExit(2)
    sweep(args)


if __name__ == "__main__":
    main()

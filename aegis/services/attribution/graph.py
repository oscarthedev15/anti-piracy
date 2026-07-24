"""
Attribution service — the differentiator.

Incumbent tools mostly answer "is THIS url pirated right now?". Government
blocking systems then block that url/IP and the pirate hops to a new domain
within minutes. AEGIS instead models the *operator's infrastructure over time*
as a graph and clusters it, so enforcement can target the network — and so a
new domain that shares infrastructure with a known operator is flagged
*before* it is even used to stream.

Signals used to link assets into one operator cluster (pivots):
  - shared IP / hosting ASN
  - shared TLS certificate fingerprint (cert reuse across "new" domains)
  - shared authoritative nameservers
  - reused analytics/ad tracker IDs and favicon hashes
  - reused crypto wallet on paywalls
  - registration fingerprints (registrar, creation-time bursts)

The clustering here is a transparent connected-components pass over "strong"
pivot edges. Production would use weighted community detection + a scored
model, but the connected-components version is deliberately explainable —
important when the output feeds a legal enforcement action.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from aegis.models import Asset, AssetType, Edge


# Relations that are strong enough to imply common control. Weak signals
# (e.g. same CDN) are stored as edges but NOT used to merge operators, to
# avoid over-linking unrelated sites behind Cloudflare.
STRONG_PIVOTS = {
    "RESOLVES_TO_DEDICATED_IP",
    "SHARES_TLS_CERT",
    "SHARES_NAMESERVER_PRIVATE",
    "SHARES_TRACKER_ID",
    "SHARES_WALLET",
}


class AttributionGraph:
    def __init__(self):
        self.assets: dict[str, Asset] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, set[str]] = defaultdict(set)          # all edges
        self._pivot_adj: dict[str, set[str]] = defaultdict(set)    # strong only

    # ---- ingest -----------------------------------------------------------
    def upsert_asset(self, type_: AssetType, value: str, **attrs) -> Asset:
        aid = Asset.make_id(type_, value)
        if aid in self.assets:
            a = self.assets[aid]
            a.attributes.update(attrs)
            return a
        a = Asset(id=aid, type=type_, value=value, attributes=dict(attrs))
        self.assets[aid] = a
        return a

    def link(self, src: Asset, dst: Asset, relation: str, **attrs) -> None:
        self.edges.append(Edge(src=src.id, dst=dst.id, relation=relation,
                               attributes=dict(attrs)))
        self._adj[src.id].add(dst.id)
        self._adj[dst.id].add(src.id)
        if relation in STRONG_PIVOTS:
            self._pivot_adj[src.id].add(dst.id)
            self._pivot_adj[dst.id].add(src.id)

    # ---- clustering -------------------------------------------------------
    def operator_clusters(self) -> list[set[str]]:
        """Connected components over STRONG pivot edges = inferred operators."""
        seen: set[str] = set()
        clusters: list[set[str]] = []
        for node in self.assets:
            if node in seen:
                continue
            stack, comp = [node], set()
            while stack:
                n = stack.pop()
                if n in seen:
                    continue
                seen.add(n)
                comp.add(n)
                stack.extend(self._pivot_adj[n] - seen)
            clusters.append(comp)
        return clusters

    def cluster_for(self, asset_id: str) -> set[str]:
        for c in self.operator_clusters():
            if asset_id in c:
                return c
        return {asset_id}

    def domains_in_cluster(self, cluster: set[str]) -> list[Asset]:
        return [self.assets[a] for a in cluster
                if self.assets[a].type == AssetType.DOMAIN]

    # ---- the payoff: predict the next hop --------------------------------
    def known_operator_assets(self) -> dict[str, str]:
        """Map every asset id -> a stable operator cluster label. A brand-new
        domain sharing a strong pivot with any of these is instantly attributable
        to a known operator (early-warning, before it streams)."""
        labels: dict[str, str] = {}
        for i, cluster in enumerate(self.operator_clusters()):
            if len(cluster) < 2:
                continue  # singletons aren't operators yet
            label = f"OP-{i:04d}"
            for a in cluster:
                labels[a] = label
        return labels

    def summarise(self) -> dict:
        clusters = [c for c in self.operator_clusters() if len(c) > 1]
        return {
            "assets": len(self.assets),
            "edges": len(self.edges),
            "operators": len(clusters),
            "largest_operator_size": max((len(c) for c in clusters), default=0),
        }

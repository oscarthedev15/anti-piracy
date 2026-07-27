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

    def _domain_count(self, cluster: set[str]) -> int:
        return sum(1 for a in cluster
                   if self.assets[a].type == AssetType.DOMAIN)

    def operator_clusters_multi(self) -> list[set[str]]:
        """Only clusters that tie together 2+ DOMAINS are 'operators'. A lone
        domain (plus its own cert/IP nodes) is just one site, not a network."""
        return [c for c in self.operator_clusters() if self._domain_count(c) >= 2]

    # ---- the payoff: predict the next hop --------------------------------
    def known_operator_assets(self) -> dict[str, str]:
        """Map every asset id -> a stable operator cluster label. A brand-new
        domain sharing a strong pivot with any of these is instantly attributable
        to a known operator (early-warning, before it streams)."""
        labels: dict[str, str] = {}
        for i, cluster in enumerate(self.operator_clusters_multi()):
            label = f"OP-{i:04d}"
            for a in cluster:
                labels[a] = label
        return labels

    def summarise(self) -> dict:
        clusters = self.operator_clusters_multi()
        return {
            "assets": len(self.assets),
            "edges": len(self.edges),
            "operators": len(clusters),
            "largest_operator_size": max((len(c) for c in clusters), default=0),
        }

    # ---- tier 2: suspected links (weak co-location, for human review) -----
    def suspected_links(self) -> list[dict]:
        """Domains that share a hosting neighbourhood but NOT a strong pivot.

        Same /24 on a VPS/hosting ASN is a lead worth investigating, not proof
        of one operator (unrelated tenants share these ranges), so these are
        surfaced for review rather than merged into a confirmed cluster. Big
        CDN/cloud fronts (Cloudflare/AWS/…) are excluded — their ranges are
        meaningless for attribution.
        """
        from aegis.asn_registry import classify

        # group domains by (asn, /24)
        groups: dict[tuple[str, str], set[str]] = defaultdict(set)
        for a in self.assets.values():
            if a.type != AssetType.IP:
                continue
            asn_str = a.attributes.get("asn")            # e.g. "AS63949"
            if not asn_str:
                continue
            try:
                asn_int = int(asn_str.replace("AS", ""))
            except ValueError:
                continue
            if classify(asn_int) == "cdn":
                continue  # shared front — co-location is meaningless
            octets = a.value.split(".")
            if len(octets) != 4:
                continue
            slash24 = ".".join(octets[:3]) + ".0/24"
            for nbr in self._adj.get(a.id, set()):
                n = self.assets[nbr]
                if n.type == AssetType.DOMAIN:
                    groups[(asn_str, slash24)].add(n.value)

        confirmed = {frozenset(self.domains_and_values(c))
                     for c in self.operator_clusters_multi()}

        out: list[dict] = []
        for (asn_str, net), domains in groups.items():
            if len(domains) < 2:
                continue
            # skip if these domains are already a confirmed operator
            if any(domains <= c for c in confirmed):
                continue
            out.append({
                "domains": sorted(domains),
                "shared_network": net,
                "asn": asn_str,
                "confidence": "suspected",
                "reason": (f"{len(domains)} domains co-located in {net} on "
                           f"{asn_str} (shared host — review, not proof)."),
            })
        return out

    def domains_and_values(self, cluster: set[str]) -> set[str]:
        return {self.assets[a].value for a in cluster
                if self.assets[a].type == AssetType.DOMAIN}

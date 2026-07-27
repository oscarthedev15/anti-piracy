"""
Blocklist service — turns confirmed detections + attribution into PRECISE,
time-limited, evidence-backed enforcement recommendations.

Explicitly engineered against the documented failure modes of Italy's Piracy
Shield (APNIC/RIPE 2025 findings): 500+ legitimate sites blocked, whole shared
IPs and CDN ranges knocked out, permanent blocks with no review.

Guardrails implemented here:
  * FQDN-first: only recommend an IP block when the IP is provably dedicated to
    the operator (single-tenant). Shared IPs -> FQDN/URL block only.
  * Critical-infra allowlist: never block IPs belonging to major CDNs, public
    DNS resolvers, or mail infrastructure.
  * Time-limited by default (ttl), matching the live-event window.
  * Every entry carries an evidence_ref and a human-readable rationale, so an
    ISP or judge can audit *why* before acting.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from aegis.models import (
    Asset,
    AssetType,
    BlocklistEntry,
    BlockSafety,
    Confidence,
    DetectionResult,
)
from aegis.services.attribution.graph import AttributionGraph


from aegis.asn_registry import is_shared_front


class BlocklistGenerator:
    def __init__(self, graph: AttributionGraph, evidence=None,
                 default_ttl: int = 7200):
        self.graph = graph
        self.evidence = evidence
        self.default_ttl = default_ttl

    def _ip_safety(self, ip_asset: Asset) -> BlockSafety:
        asn_str = ip_asset.attributes.get("asn")   # e.g. "AS13335"
        asn_int = None
        if asn_str:
            try:
                asn_int = int(asn_str.replace("AS", ""))
            except ValueError:
                asn_int = None
        if is_shared_front(asn_int):
            return BlockSafety.DO_NOT_BLOCK   # never IP-block a shared CDN/cloud
        # dedicated => only this operator's assets resolve here
        if ip_asset.attributes.get("dedicated") is True:
            return BlockSafety.IP_SAFE
        return BlockSafety.FQDN_ONLY

    def generate(self, detections: list[DetectionResult]) -> list[BlocklistEntry]:
        labels = self.graph.known_operator_assets()
        entries: list[BlocklistEntry] = []

        for det in detections:
            if not det.matched:
                continue

            host = urlparse(det.url).netloc or det.url
            dom_asset = self.graph.upsert_asset(AssetType.DOMAIN, host)
            operator = labels.get(dom_asset.id)

            # 1) Always: precise FQDN/URL entry for the confirmed stream.
            entries.append(BlocklistEntry(
                target=host,
                method="fqdn",
                safety=BlockSafety.FQDN_ONLY,
                operator_cluster=operator,
                confidence=det.confidence,
                ttl_seconds=self.default_ttl,
                evidence_ref=det.evidence_ref,
                rationale=(
                    f"Confirmed live match (score={det.match_score:.2f}) "
                    f"against protected feed {det.protected_asset}."
                ),
            ))

            # 2) If the domain sits on a *dedicated* IP, add a safe IP block.
            for nbr_id in self.graph._adj.get(dom_asset.id, set()):
                nbr = self.graph.assets[nbr_id]
                if nbr.type != AssetType.IP:
                    continue
                safety = self._ip_safety(nbr)
                if safety == BlockSafety.IP_SAFE:
                    entries.append(BlocklistEntry(
                        target=nbr.value,
                        method="ip",
                        safety=safety,
                        operator_cluster=operator,
                        confidence=det.confidence,
                        ttl_seconds=self.default_ttl,
                        evidence_ref=det.evidence_ref,
                        rationale=f"Dedicated single-tenant IP for {host}.",
                    ))
                # FQDN_ONLY / DO_NOT_BLOCK: deliberately NOT emitted as IP blocks.

        return self._dedupe(entries)

    def preemptive_from_operator(self, operator_label: str,
                                 confidence: Confidence = Confidence.MEDIUM
                                 ) -> list[BlocklistEntry]:
        """Early-warning: every known domain of an operator that is not yet
        streaming can be queued for FQDN blocking the instant it goes live."""
        labels = self.graph.known_operator_assets()
        out: list[BlocklistEntry] = []
        for aid, label in labels.items():
            if label != operator_label:
                continue
            a = self.graph.assets[aid]
            if a.type != AssetType.DOMAIN:
                continue
            out.append(BlocklistEntry(
                target=a.value,
                method="fqdn",
                safety=BlockSafety.FQDN_ONLY,
                operator_cluster=operator_label,
                confidence=confidence,
                ttl_seconds=self.default_ttl,
                rationale=(f"Shares strong infrastructure pivot with confirmed "
                           f"operator {operator_label}; queue for live-window block."),
            ))
        return out

    @staticmethod
    def _dedupe(entries: list[BlocklistEntry]) -> list[BlocklistEntry]:
        seen, out = set(), []
        for e in entries:
            key = (e.target, e.method)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
        return out

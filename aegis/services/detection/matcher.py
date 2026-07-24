"""
Detection service — decides whether a candidate stream is actually carrying
a PROTECTED live feed, and with what confidence.

This is where the legally-defensible core lives. Two complementary signals:

  1. Perceptual fingerprint match  — compare frames/audio of the candidate
     against the rights-holder's reference feed (robust to re-encode/crop).
  2. Forensic watermark extraction — recover the per-subscriber watermark to
     identify the leaking source (attribution back to a compromised account).

The stub below ships a deterministic pHash-style interface so the pipeline is
runnable; swap `FingerprintBackend` for a real perceptual-hash / DNN matcher.

Design choice that differentiates from "detector" incumbents: every positive
match writes a signed evidence record (see evidence.ledger) at the moment of
detection, so the chain of custody starts before any enforcement action.
"""
from __future__ import annotations

from typing import Optional, Protocol

from aegis.models import (
    Confidence,
    DetectionResult,
    StreamObservation,
)


class FingerprintBackend(Protocol):
    def score(self, url: str, reference_id: str) -> float:
        ...


class StubFingerprintBackend:
    """Deterministic stand-in. Real impl samples the manifest, decodes frames,
    computes perceptual hashes and matches against the reference feed."""

    def __init__(self, known_matches: Optional[dict[str, tuple[str, float]]] = None):
        # map candidate url -> (protected_asset_id, score) for demo/testing
        self.known_matches = known_matches or {}

    def score(self, url: str, reference_id: str) -> float:
        hit = self.known_matches.get(url)
        if hit and hit[0] == reference_id:
            return hit[1]
        return 0.0


def _confidence(score: float) -> Confidence:
    if score >= 0.90:
        return Confidence.HIGH
    if score >= 0.70:
        return Confidence.MEDIUM
    return Confidence.LOW


class DetectionService:
    def __init__(self, backend: FingerprintBackend, reference_ids: list[str],
                 evidence=None, threshold: float = 0.70):
        self.backend = backend
        self.reference_ids = reference_ids
        self.evidence = evidence  # optional EvidenceLedger
        self.threshold = threshold

    def evaluate(self, obs: StreamObservation) -> DetectionResult:
        best_ref, best_score = None, 0.0
        for ref in self.reference_ids:
            s = self.backend.score(obs.url, ref)
            if s > best_score:
                best_ref, best_score = ref, s

        matched = best_score >= self.threshold
        evidence_ref = None
        if matched and self.evidence is not None:
            evidence_ref = self.evidence.record(
                kind="detection",
                subject=obs.url,
                payload={
                    "protected_asset": best_ref,
                    "score": best_score,
                    "source": obs.source,
                    "event_hint": obs.event_hint,
                },
            )

        return DetectionResult(
            url=obs.url,
            matched=matched,
            protected_asset=best_ref if matched else None,
            match_method=getattr(self.backend, "method", "fingerprint"),
            match_score=best_score,
            confidence=_confidence(best_score),
            evidence_ref=evidence_ref,
        )

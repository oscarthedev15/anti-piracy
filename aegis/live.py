"""
REAL end-to-end run — no synthetic data, no pip install.

    python -m aegis.live https://site-a.example/live https://site-b.example/live

For each URL this does the real thing, for free, stdlib-only:
  1. Detection  — fetch the page, score its live-stream resemblance (heuristic).
  2. Enrichment — real DNS + TLS cert fingerprint + ASN/owner for confirmed hosts.
  3. Attribution— cluster hosts that truly share a cert / dedicated IP into one operator.
  4. Blocklist  — precise, collateral-damage-guarded actions from real ASN data.
  5. Evidence   — hash-chained record of every detection and action.

Honest limits: detection is structural resemblance, not licensed-content proof
(that needs a reference feed); "dedicated IP" is inferred from ASN and flagged
for review, not proven single-tenancy. Both are stated in the output.
"""
from __future__ import annotations

import sys

from aegis.config import settings
from aegis.models import StreamObservation
from aegis.pipeline import Pipeline
from aegis.services.attribution.graph import AttributionGraph
from aegis.services.blocklist.generator import BlocklistGenerator
from aegis.services.detection.heuristic import HeuristicStreamBackend
from aegis.services.detection.matcher import DetectionService
from aegis.services.enrichment.live import LiveEnrichment
from aegis.services.evidence.ledger import EvidenceLedger


def build_live_pipeline(event_hint: str = "live stream",
                        threshold: float = 0.50) -> Pipeline:
    """Real pipeline. Heuristic detection uses a lower bar than fingerprinting
    (0.50) because it is a triage signal; confidence stays capped in the output."""
    evidence = EvidenceLedger()
    graph = AttributionGraph()
    backend = HeuristicStreamBackend()
    detector = DetectionService(backend=backend, reference_ids=[event_hint],
                                evidence=evidence, threshold=threshold)
    blocklister = BlocklistGenerator(
        graph=graph, evidence=evidence,
        default_ttl=settings.default_block_ttl_seconds)
    enricher = LiveEnrichment()
    return Pipeline(detector, graph, blocklister, evidence, enricher=enricher)


def run_live(urls: list[str], event_hint: str = "live stream") -> None:
    pipe = build_live_pipeline(event_hint=event_hint)
    backend: HeuristicStreamBackend = pipe.detector.backend  # type: ignore
    pipe.add_observations([
        StreamObservation(url=u, source="cli_input", event_hint=event_hint)
        for u in urls
    ])
    result = pipe.run()

    print("=" * 70)
    print("AEGIS — live end-to-end run (real DNS/TLS/ASN, free, stdlib-only)")
    print(f"event hint: {event_hint!r}   candidates: {len(urls)}")
    print("=" * 70)

    print("\n[1] Detection (heuristic resemblance — triage, not content proof):")
    for d in result.detections:
        tag = "MATCH" if d.matched else "skip "
        sigs = ", ".join(backend.signals_for(d.url)) or "no stream signals"
        print(f"   [{tag}] score={d.match_score:.2f} conf={d.confidence.value:6} {d.url}")
        print(f"           signals: {sigs}")

    print("\n[2] Attribution (real infrastructure graph):")
    summ = pipe.graph.summarise()
    print(f"   assets={summ['assets']} edges={summ['edges']} "
          f"operators={summ['operators']} largest={summ['largest_operator_size']}")
    labels = pipe.graph.known_operator_assets()
    for op in sorted(set(labels.values())):
        doms = sorted(pipe.graph.assets[a].value for a, l in labels.items()
                      if l == op and pipe.graph.assets[a].type.value == "domain")
        if doms:
            print(f"   {op}: {len(doms)} domains share real infra -> {doms}")
    if not labels:
        print("   (no multi-domain operator cluster — hosts share no strong pivot)")

    print("\n[3] Precision blocklist (real ASN guardrails):")
    if not result.blocklist:
        print("   (nothing confirmed to act on)")
    for e in result.blocklist:
        print(f"   [{e.safety.value:12}] {e.method:4} {e.target:34} "
              f"op={e.operator_cluster} ttl={e.ttl_seconds}s")
        print(f"                  {e.rationale}")

    print("\n[4] Evidence chain:")
    print(f"   records={len(pipe.evidence)} intact={pipe.evidence.verify()}")
    print("\nDone.")


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("usage: python -m aegis.live <url> [<url> ...] "
              "[--event \"EPL: Team A vs Team B\"]")
        raise SystemExit(2)

    event_hint = "live stream"
    if "--event" in args:
        i = args.index("--event")
        event_hint = args[i + 1] if i + 1 < len(args) else event_hint
        args = args[:i] + args[i + 2:]
    run_live(args, event_hint=event_hint)


if __name__ == "__main__":
    main()

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
from aegis.services.discovery.crawler import AggregatorCrawler
from aegis.services.enrichment.live import LiveEnrichment
from aegis.services.evidence.ledger import EvidenceLedger


def build_live_pipeline(event_hint: str = "live stream",
                        threshold: float = 0.50,
                        html_cache: Optional[dict] = None) -> Pipeline:
    """Real pipeline. Heuristic detection uses a lower bar than fingerprinting
    (0.50) because it is a triage signal; confidence stays capped in the output."""
    evidence = EvidenceLedger()
    graph = AttributionGraph()
    backend = HeuristicStreamBackend(html_cache=html_cache)
    detector = DetectionService(backend=backend, reference_ids=[event_hint],
                                evidence=evidence, threshold=threshold)
    blocklister = BlocklistGenerator(
        graph=graph, evidence=evidence,
        default_ttl=settings.default_block_ttl_seconds)
    enricher = LiveEnrichment()
    return Pipeline(detector, graph, blocklister, evidence, enricher=enricher)


def run_live(urls: list[str], event_hint: str = "live stream",
             crawl_seeds: Optional[list[str]] = None,
             max_pages: int = 25, limit: int = 20) -> None:
    # One page store shared by crawler + detector: fetch each URL at most once.
    html_cache: dict[str, str] = {}
    pipe = build_live_pipeline(event_hint=event_hint, html_cache=html_cache)
    backend: HeuristicStreamBackend = pipe.detector.backend  # type: ignore

    observations = [
        StreamObservation(url=u, source="cli_input", event_hint=event_hint)
        for u in urls
    ]
    if crawl_seeds:
        print(f"[0] Discovery: crawling {len(crawl_seeds)} seed portal(s) "
              f"(max {max_pages} pages)…", flush=True)
        found = AggregatorCrawler(max_pages=max_pages,
                                  html_cache=html_cache).crawl(crawl_seeds, event_hint)
        by_kind: dict[str, int] = {}
        for o in found:
            by_kind[o.source] = by_kind.get(o.source, 0) + 1
        print(f"      discovered {len(found)} candidate(s): "
              + ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())), flush=True)
        observations.extend(found)

    # Bound how many candidates get scored this run. Detection fetches any page
    # not already in the cache, so this caps live network work — reported, never
    # silent.
    if len(observations) > limit:
        print(f"      scoring first {limit} of {len(observations)} candidates "
              f"this run ({len(observations) - limit} deferred).", flush=True)
        observations = observations[:limit]

    pipe.add_observations(observations)
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


def _take_opt(args: list[str], flag: str) -> tuple[Optional[str], list[str]]:
    if flag in args:
        i = args.index(flag)
        val = args[i + 1] if i + 1 < len(args) else None
        return val, args[:i] + args[i + 2:]
    return None, args


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("usage:\n"
              "  python -m aegis.live <url> [<url> ...] [--event \"...\"]\n"
              "  python -m aegis.live --crawl <seed-portal-url> [--event \"...\"] "
              "[--max-pages N]\n"
              "\nDiscover-and-run: --crawl walks a seed portal for candidate\n"
              "stream/embed pages, then runs the full pipeline on all of them.")
        raise SystemExit(2)

    event_hint, args = _take_opt(args, "--event")
    event_hint = event_hint or "live stream"
    crawl_seed, args = _take_opt(args, "--crawl")
    max_pages_s, args = _take_opt(args, "--max-pages")
    max_pages = int(max_pages_s) if max_pages_s and max_pages_s.isdigit() else 25
    limit_s, args = _take_opt(args, "--limit")
    limit = int(limit_s) if limit_s and limit_s.isdigit() else 20

    run_live(args, event_hint=event_hint,
             crawl_seeds=[crawl_seed] if crawl_seed else None,
             max_pages=max_pages, limit=limit)


if __name__ == "__main__":
    main()

"""
Synthetic scenario for the runnable demo.

Story: a single pirate operator streams the same EPL match across THREE
domains during one match week. They rotate the domain each time it gets blocked,
but they reuse the same TLS certificate and the same dedicated origin IP — the
exact mistake real operators make. AEGIS should:
  * confirm all three as live matches,
  * cluster all three domains into ONE operator via the shared cert/IP pivots,
  * emit FQDN blocks for each, an IP block ONLY for the dedicated origin,
  * and NEVER emit an IP block for the shared Cloudflare front.
"""
from aegis.models import AssetType, StreamObservation
from aegis.services.attribution.graph import AttributionGraph
from aegis.services.detection.matcher import StubFingerprintBackend

# The three domains the operator hops between.
DOMAINS = ["freeeplstream.top", "epllive-hd.cc", "watchepl-now.xyz"]

# Detection ground truth: all three carry the protected EPL feed, high score.
KNOWN_MATCHES = {
    f"https://{d}/live/epl": ("feed:epl-main", 0.96) for d in DOMAINS
}

OBSERVATIONS = [
    StreamObservation(url=f"https://{d}/live/epl", source="aggregator_portal",
                      event_hint="EPL: Team A vs Team B")
    for d in DOMAINS
]


def make_backend() -> StubFingerprintBackend:
    return StubFingerprintBackend(known_matches=KNOWN_MATCHES)


def seed_graph(graph: AttributionGraph) -> None:
    """Populate infrastructure observations the collectors would produce."""
    # Shared assets: one reused TLS cert, one dedicated origin IP, one shared CDN.
    cert = graph.upsert_asset(AssetType.TLS_CERT, "sha256:deadbeefcafe")
    origin = graph.upsert_asset(AssetType.IP, "203.0.113.77",
                                dedicated=True, asn="AS64500")
    cdn_ip = graph.upsert_asset(AssetType.IP, "104.21.5.9",
                                dedicated=False, asn="AS13335")  # Cloudflare

    for d in DOMAINS:
        dom = graph.upsert_asset(AssetType.DOMAIN, d)
        # every rotated domain reuses the same cert -> STRONG pivot
        graph.link(dom, cert, "SHARES_TLS_CERT")
        # and resolves to the same dedicated origin -> STRONG pivot
        graph.link(dom, origin, "RESOLVES_TO_DEDICATED_IP")
        # they also sit behind a shared Cloudflare IP -> WEAK (won't over-link)
        graph.link(dom, cdn_ip, "RESOLVES_TO_SHARED_IP")

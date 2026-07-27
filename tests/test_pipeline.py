"""
Smoke + behaviour tests for the AEGIS reference pipeline.
Run: python -m pytest -q   (or) python -m tests.test_pipeline
"""
from aegis.models import BlockSafety
from demo.run_pipeline import build_pipeline
from demo.synthetic_data import OBSERVATIONS


def _run():
    pipe = build_pipeline()
    pipe.add_observations(OBSERVATIONS)
    result = pipe.run()
    return pipe, result


def test_all_streams_detected():
    _, result = _run()
    assert sum(1 for d in result.detections if d.matched) == 3


def test_domain_hops_cluster_into_one_operator():
    pipe, _ = _run()
    summ = pipe.graph.summarise()
    assert summ["operators"] == 1
    labels = pipe.graph.known_operator_assets()
    domains = [pipe.graph.assets[a].value for a, l in labels.items()
               if pipe.graph.assets[a].type.value == "domain"]
    assert len(domains) == 3  # all three hops attributed together


def test_no_collateral_ip_block_on_shared_cdn():
    _, result = _run()
    ip_entries = [e for e in result.blocklist if e.method == "ip"]
    # exactly one dedicated origin IP, never the shared Cloudflare address
    assert len(ip_entries) == 1
    assert ip_entries[0].target == "203.0.113.77"
    assert all(e.safety != BlockSafety.DO_NOT_BLOCK for e in result.blocklist)
    assert "104.21.5.9" not in {e.target for e in ip_entries}


def test_evidence_chain_intact():
    pipe, _ = _run()
    assert pipe.evidence.verify() is True
    assert len(pipe.evidence) >= 3


def test_same_subnet_is_suspected_not_confirmed():
    """Two brands on the same VPS /24 (different IPs) surface as a SUSPECTED
    link, and are NOT auto-merged into a confirmed operator."""
    from aegis.services.attribution.graph import AttributionGraph
    from aegis.models import AssetType
    g = AttributionGraph()
    for host, ip in [("brand-a.tv", "172.237.146.18"),
                     ("brand-b.cc", "172.237.146.46")]:
        d = g.upsert_asset(AssetType.DOMAIN, host)
        i = g.upsert_asset(AssetType.IP, ip, asn="AS63949", dedicated=True)
        g.link(d, i, "RESOLVES_TO_DEDICATED_IP")
    assert g.operator_clusters_multi() == []          # not confirmed
    links = g.suspected_links()
    assert len(links) == 1
    assert set(links[0]["domains"]) == {"brand-a.tv", "brand-b.cc"}


def test_cdn_subnet_is_never_suspected():
    """Same /24 on a CDN (Cloudflare) is meaningless — must not be flagged."""
    from aegis.services.attribution.graph import AttributionGraph
    from aegis.models import AssetType
    g = AttributionGraph()
    for host, ip in [("x.tv", "104.21.5.9"), ("y.cc", "104.21.5.40")]:
        d = g.upsert_asset(AssetType.DOMAIN, host)
        i = g.upsert_asset(AssetType.IP, ip, asn="AS13335")
        g.link(d, i, "RESOLVES_TO_SHARED_IP")
    assert g.suspected_links() == []


def test_discovery_orchestrator_dedupes_and_survives_bad_source():
    """The orchestrator unions sources, dedupes by URL, and a throwing source
    never sinks the run (network-free: uses in-memory fake sources)."""
    from aegis.services.discovery.sources import DiscoveryOrchestrator
    from aegis.models import StreamObservation

    class _Fake:
        name = "fake"
        def __init__(self, urls): self._urls = urls
        def discover(self):
            return [StreamObservation(url=u, source="fake") for u in self._urls]

    class _Broken:
        name = "broken"
        def discover(self):
            raise RuntimeError("source is down")

    out = DiscoveryOrchestrator([
        _Fake(["https://a.tv/", "https://b.tv/"]),
        _Broken(),                       # must not sink the union
        _Fake(["https://b.tv/", "https://c.tv/"]),  # b is a dup
    ]).run()
    assert sorted(o.url for o in out) == [
        "https://a.tv/", "https://b.tv/", "https://c.tv/"]


def test_reverse_infra_excludes_seed_and_dedupes():
    """Reverse pivot emits siblings, never the seed itself, deduped
    (network-free: stub the cert/CT lookups)."""
    from aegis.services.discovery.sources import ReverseInfraSource

    class _Stub(ReverseInfraSource):
        def _san_names(self, host):        # pretend the cert lists two brands
            return ["seed.tv", "brand-b.cc"]
        def _crtsh_siblings(self, domain):
            return ["brand-b.cc", "brand-c.io"]   # b is a dup

    obs = list(_Stub(["seed.tv"]).discover())
    urls = sorted(o.url for o in obs)
    assert urls == ["https://brand-b.cc/", "https://brand-c.io/"]  # no seed.tv
    assert all(o.raw["pivot_from"] == "seed.tv" for o in obs)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all tests passed")

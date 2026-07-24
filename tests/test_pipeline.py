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


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all tests passed")

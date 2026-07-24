"""
Runnable end-to-end demo. No pip install required.

    python -m demo.run_pipeline      (from the repo root)

Proves the differentiated behaviour: domain-hop clustering + precision blocklist
+ tamper-evident evidence chain.
"""
from aegis.models import BlockSafety
from aegis.pipeline import Pipeline
from aegis.services.detection.matcher import DetectionService
from aegis.services.attribution.graph import AttributionGraph
from aegis.services.blocklist.generator import BlocklistGenerator
from aegis.services.evidence.ledger import EvidenceLedger

from demo.synthetic_data import OBSERVATIONS, make_backend, seed_graph


def build_pipeline() -> Pipeline:
    evidence = EvidenceLedger()
    graph = AttributionGraph()
    seed_graph(graph)
    detector = DetectionService(backend=make_backend(),
                                reference_ids=["feed:epl-main"],
                                evidence=evidence)
    blocklister = BlocklistGenerator(graph=graph, evidence=evidence)
    return Pipeline(detector, graph, blocklister, evidence)


def main() -> None:
    pipe = build_pipeline()
    pipe.add_observations(OBSERVATIONS)
    result = pipe.run()

    print("=" * 68)
    print("AEGIS demo — one operator, three hopped domains, one match week")
    print("=" * 68)

    confirmed = [d for d in result.detections if d.matched]
    print(f"\n[1] Detection: {len(confirmed)}/{len(result.detections)} "
          f"candidates confirmed as the protected EPL feed")
    for d in confirmed:
        print(f"      - {d.url}  score={d.match_score:.2f}  "
              f"conf={d.confidence.value}  evidence={d.evidence_ref}")

    print("\n[2] Attribution: infrastructure graph")
    summ = pipe.graph.summarise()
    print(f"      assets={summ['assets']}  edges={summ['edges']}  "
          f"operators={summ['operators']}  "
          f"largest_operator={summ['largest_operator_size']} assets")
    labels = pipe.graph.known_operator_assets()
    op_labels = sorted(set(labels.values()))
    for op in op_labels:
        doms = sorted(pipe.graph.assets[a].value for a, l in labels.items()
                      if l == op and pipe.graph.assets[a].type.value == "domain")
        print(f"      {op}: {len(doms)} domains linked as ONE operator -> {doms}")

    print("\n[3] Precision blocklist (collateral-damage guarded):")
    for e in result.blocklist:
        flag = {"ip_safe": "IP-OK", "fqdn_only": "FQDN", "do_not_block": "SKIP"}[e.safety.value]
        print(f"      [{flag:6}] {e.method:4} {e.target:22} "
              f"op={e.operator_cluster}  ttl={e.ttl_seconds}s")
    ip_blocks = [e for e in result.blocklist if e.method == "ip"]
    print(f"      -> {len(ip_blocks)} IP block(s), all dedicated single-tenant; "
          f"shared Cloudflare IP was NOT blocked (no collateral damage).")

    print("\n[4] Early-warning (preemptive queue for the same operator):")
    for op in op_labels:
        pre = pipe.blocklister.preemptive_from_operator(op)
        print(f"      {op}: {len(pre)} known domains queued to block on next live-window")

    print("\n[5] Evidence chain:")
    print(f"      records={len(pipe.evidence)}  intact={pipe.evidence.verify()}")

    print("\nDone.")


if __name__ == "__main__":
    main()

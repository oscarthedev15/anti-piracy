"""
Pipeline orchestrator — wires the services into one flow:

    observations -> detection -> attribution graph -> precision blocklist
                                                   \-> evidence ledger

Kept dependency-free so it runs in the demo and under the API alike.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from aegis.models import (
    AssetType,
    BlocklistEntry,
    DetectionResult,
    StreamObservation,
)
from aegis.services.detection.matcher import DetectionService, StubFingerprintBackend
from aegis.services.attribution.graph import AttributionGraph
from aegis.services.blocklist.generator import BlocklistGenerator
from aegis.services.evidence.ledger import EvidenceLedger


@dataclass
class PipelineResult:
    detections: list[DetectionResult] = field(default_factory=list)
    blocklist: list[BlocklistEntry] = field(default_factory=list)


class Pipeline:
    def __init__(self, detector: DetectionService, graph: AttributionGraph,
                 blocklister: BlocklistGenerator, evidence: EvidenceLedger):
        self.detector = detector
        self.graph = graph
        self.blocklister = blocklister
        self.evidence = evidence
        self._observations: list[StreamObservation] = []
        self.last_blocklist: list[BlocklistEntry] = []

    def add_observations(self, obs: list[StreamObservation]) -> None:
        self._observations.extend(obs)

    def run(self) -> PipelineResult:
        detections = [self.detector.evaluate(o) for o in self._observations]
        # record every confirmed detection's host into the graph as a domain
        for det in detections:
            if det.matched:
                host = urlparse(det.url).netloc or det.url
                self.graph.upsert_asset(AssetType.DOMAIN, host)
        blocklist = self.blocklister.generate(detections)
        for entry in blocklist:
            self.evidence.record(kind="blocklist", subject=entry.target,
                                 payload={"method": entry.method,
                                          "safety": entry.safety.value,
                                          "operator": entry.operator_cluster})
        self.last_blocklist = blocklist
        return PipelineResult(detections=detections, blocklist=blocklist)

    # -- convenience factory used by the API and quickstart -----------------
    @classmethod
    def demo_instance(cls) -> "Pipeline":
        evidence = EvidenceLedger()
        graph = AttributionGraph()
        detector = DetectionService(
            backend=StubFingerprintBackend(),
            reference_ids=["feed:epl-main"],
            evidence=evidence,
        )
        blocklister = BlocklistGenerator(graph=graph, evidence=evidence)
        return cls(detector, graph, blocklister, evidence)

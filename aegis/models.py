"""
AEGIS shared domain models.

Deliberately dependency-free (stdlib dataclasses) so the reference pipeline
runs anywhere without a pip install. Production would likely back these with
pydantic + a graph store (Neo4j/JanusGraph) and a relational evidence DB.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetType(str, Enum):
    """A node type in the infrastructure attribution graph."""
    STREAM_URL = "stream_url"      # the actual playable manifest/page
    DOMAIN = "domain"              # fqdn serving the stream or portal
    IP = "ip"                      # resolved address
    CDN = "cdn"                    # fronting CDN / reverse proxy
    TLS_CERT = "tls_cert"          # cert fingerprint (SHA-256)
    NAMESERVER = "nameserver"      # authoritative NS
    WALLET = "wallet"             # crypto payment address on a paywall
    TRACKER_ID = "tracker_id"      # analytics/ad ID reused across sites
    OPERATOR = "operator"          # inferred controlling entity (cluster root)


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Whether an asset can be safely blocked at the IP layer, or must be
# restricted to FQDN/URL blocking to avoid collateral damage. This is the
# heart of the "don't be Piracy Shield" guardrail.
class BlockSafety(str, Enum):
    IP_SAFE = "ip_safe"            # dedicated infra, IP block won't hurt bystanders
    FQDN_ONLY = "fqdn_only"        # shared IP (CDN/host) -> block hostname only
    DO_NOT_BLOCK = "do_not_block"  # critical shared infra (DNS/MX/major CDN)


@dataclass
class Asset:
    """A single node in the attribution graph."""
    id: str
    type: AssetType
    value: str
    first_seen: str = field(default_factory=_utcnow)
    last_seen: str = field(default_factory=_utcnow)
    attributes: dict = field(default_factory=dict)

    @staticmethod
    def make_id(type_: AssetType, value: str) -> str:
        return f"{type_.value}:{hashlib.sha1(value.encode()).hexdigest()[:12]}"


@dataclass
class Edge:
    """A relationship between two assets (e.g. domain -RESOLVES_TO-> ip)."""
    src: str
    dst: str
    relation: str
    first_seen: str = field(default_factory=_utcnow)
    last_seen: str = field(default_factory=_utcnow)
    attributes: dict = field(default_factory=dict)


@dataclass
class StreamObservation:
    """A candidate illegal stream surfaced by the discovery service."""
    url: str
    source: str                    # where we found it (search, social, aggregator)
    event_hint: Optional[str] = None   # e.g. "EPL: Team A vs Team B"
    observed_at: str = field(default_factory=_utcnow)
    raw: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Output of the content-matching stage for one observation."""
    url: str
    matched: bool
    protected_asset: Optional[str] = None   # which rights-holder feed it matched
    match_method: str = "fingerprint"        # fingerprint | watermark | metadata
    match_score: float = 0.0
    confidence: Confidence = Confidence.LOW
    evidence_ref: Optional[str] = None       # id in the evidence ledger


@dataclass
class BlocklistEntry:
    """A single actionable enforcement recommendation."""
    target: str                    # the domain / url / ip to act on
    method: str                    # "fqdn" | "url" | "ip"
    safety: BlockSafety
    operator_cluster: Optional[str] = None
    confidence: Confidence = Confidence.MEDIUM
    ttl_seconds: int = 7200        # time-limited by default (per EUIPO guidance)
    evidence_ref: Optional[str] = None
    rationale: str = ""


def to_json(obj) -> str:
    """Serialise any dataclass (or list of them) to stable JSON."""
    def default(o):
        if hasattr(o, "__dataclass_fields__"):
            return asdict(o)
        if isinstance(o, Enum):
            return o.value
        raise TypeError(f"not serialisable: {type(o)}")
    return json.dumps(obj, default=default, indent=2, sort_keys=True)

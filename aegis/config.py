"""Central configuration. Values are read from the environment so the same
image runs in dev and in an air-gapped government deployment."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    env: str = os.getenv("AEGIS_ENV", "dev")

    # detection
    match_threshold: float = float(os.getenv("AEGIS_MATCH_THRESHOLD", "0.70"))

    # blocklist policy
    default_block_ttl_seconds: int = int(os.getenv("AEGIS_BLOCK_TTL", "7200"))
    # if True, IP blocks require a human sign-off even when marked ip_safe
    require_review_for_ip_blocks: bool = (
        os.getenv("AEGIS_REVIEW_IP_BLOCKS", "true").lower() == "true"
    )

    # attribution
    min_cluster_size_for_operator: int = int(os.getenv("AEGIS_MIN_CLUSTER", "2"))


settings = Settings()

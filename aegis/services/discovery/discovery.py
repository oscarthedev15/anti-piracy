"""
Discovery service — surfaces CANDIDATE illegal streams.

Responsibility: cast a wide net across the vectors pirates actually use, and
emit StreamObservation records for downstream detection. This is intentionally
source-pluggable: each `Source` is a small adapter. In production these become
real collectors (search-result scraping with rotating egress, social platform
APIs, IPTV portal crawlers, Telegram/Discord channel monitors, ISD/app probes).

Nothing here decides guilt — it only says "worth looking at".
"""
from __future__ import annotations

from typing import Iterable, Protocol

from aegis.models import StreamObservation


class Source(Protocol):
    """A pluggable discovery adapter."""
    name: str

    def search(self, event_hint: str) -> Iterable[StreamObservation]:
        ...


class SearchEngineSource:
    """Stub: query open search engines for '<event> free live stream' patterns."""
    name = "search_engine"

    def search(self, event_hint: str) -> Iterable[StreamObservation]:
        # TODO: real collector w/ rotating egress + captcha handling.
        return []


class AggregatorSource:
    """Stub: crawl known link-aggregator portals that index many streams."""
    name = "aggregator_portal"

    def search(self, event_hint: str) -> Iterable[StreamObservation]:
        return []


class SocialSource:
    """Stub: monitor social platforms / messaging channels for stream links."""
    name = "social"

    def search(self, event_hint: str) -> Iterable[StreamObservation]:
        return []


class DiscoveryService:
    def __init__(self, sources: list[Source] | None = None):
        self.sources = sources or [
            SearchEngineSource(),
            AggregatorSource(),
            SocialSource(),
        ]

    def discover(self, event_hint: str) -> list[StreamObservation]:
        found: list[StreamObservation] = []
        for src in self.sources:
            found.extend(src.search(event_hint))
        return found

    def ingest(self, observations: list[StreamObservation]) -> list[StreamObservation]:
        """Accept externally-provided observations (e.g. tip-offs, demo data)."""
        return list(observations)

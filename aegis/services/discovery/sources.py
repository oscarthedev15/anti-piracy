"""
Discovery sources — how candidate pirate domains are FOUND in the first place.

The crawler (crawler.py) expands a portal you already know. Discovery is the
harder, upstream problem: surfacing portals you *don't* know yet. No single free
signal solves it, so this is a pluggable set of sources, each blind to the
others, unioned by a `DiscoveryOrchestrator`.

Status of each source is marked REAL or SKELETON:

  REAL      CertTransparencySource  — new pirate domains get TLS certs, which are
                                      published in public CT logs (crt.sh). Search
                                      them by keyword and you catch domains as they
                                      come online — often before they're indexed
                                      anywhere else. Free, no key.
  REAL      SeedCrawlSource         — wraps the aggregator crawler.
  SKELETON  ReverseInfraSource      — from a KNOWN operator's cert/IP, pivot to its
                                      other domains (CT cert search / passive DNS).
  SKELETON  PublicBlocklistSource   — ingest existing public anti-piracy blJocklists
                                      / community lists as candidate seeds.
  SKELETON  SearchEngineSource      — query engines for "<event> free live stream".
  SKELETON  SocialTelegramSource    — monitor public channels where links are posted.

None of these decide guilt; they only nominate candidates for detection.
"""
from __future__ import annotations

import json
import re
import time
from typing import Iterable, Optional, Protocol
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from aegis.models import StreamObservation

_UA = "Mozilla/5.0 (compatible; AEGIS-enforcement-scan/0.1; +anti-piracy discovery)"


class DiscoverySource(Protocol):
    name: str
    def discover(self) -> Iterable[StreamObservation]: ...


# --------------------------------------------------------------------------
# REAL: Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------
class CertTransparencySource:
    """Find domains whose TLS certs match piracy-ish keywords, via crt.sh.

    Example keywords: 'sportstream', 'livefootball', 'crackstream', 'streameast'.
    Every HTTPS pirate site issues a cert, and CT logs are public — so this
    surfaces new/rotated domains as they appear.
    """
    name = "ct_log"

    def __init__(self, keywords: list[str], per_keyword_limit: int = 40,
                 timeout: float = 20.0, retries: int = 3):
        self.keywords = keywords
        self.per_keyword_limit = per_keyword_limit
        self.timeout = timeout
        self.retries = retries

    def _query(self, keyword: str) -> list[str]:
        url = f"https://crt.sh/?q=%25{quote(keyword)}%25&output=json"
        req = Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        data = None
        # crt.sh frequently 502s under load; retry a few times with backoff.
        for attempt in range(self.retries):
            try:
                with urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                break
            except Exception:
                if attempt < self.retries - 1:
                    time.sleep(1.5 * (attempt + 1))
        if data is None:
            return []
        domains: list[str] = []
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                d = name.strip().lower().lstrip("*.")
                if d and keyword.lower() in d and d not in domains:
                    domains.append(d)
        return domains[: self.per_keyword_limit]

    def discover(self) -> Iterable[StreamObservation]:
        seen: set[str] = set()
        for kw in self.keywords:
            for d in self._query(kw):
                if d in seen:
                    continue
                seen.add(d)
                yield StreamObservation(
                    url=f"https://{d}/",
                    source="ct_log",
                    event_hint=None,
                    raw={"matched_keyword": kw, "via": "crt.sh"},
                )


# --------------------------------------------------------------------------
# REAL: wrap the aggregator crawler as a discovery source
# --------------------------------------------------------------------------
class SeedCrawlSource:
    name = "seed_crawl"

    def __init__(self, seeds: list[str], max_pages: int = 25,
                 event_hint: str = ""):
        self.seeds = seeds
        self.max_pages = max_pages
        self.event_hint = event_hint

    def discover(self) -> Iterable[StreamObservation]:
        from aegis.services.discovery.crawler import AggregatorCrawler
        return AggregatorCrawler(max_pages=self.max_pages).crawl(
            self.seeds, self.event_hint)


# --------------------------------------------------------------------------
# SKELETON sources — clear interface, documented next steps, no fake data
# --------------------------------------------------------------------------
class ReverseInfraSource:
    """SKELETON. Given a known operator's TLS cert hash or origin IP, find its
    OTHER domains — the highest-yield pivot once you have one confirmed site.

    Build: crt.sh advanced search by cert SHA-256, and/or a passive-DNS provider
    (reverse-IP) to list co-hosted domains. Feed results back as candidates.
    """
    name = "reverse_infra"

    def __init__(self, cert_hashes: Optional[list[str]] = None,
                 ips: Optional[list[str]] = None):
        self.cert_hashes = cert_hashes or []
        self.ips = ips or []

    def discover(self) -> Iterable[StreamObservation]:
        # TODO: crt.sh cert-hash search + passive-DNS reverse-IP lookup.
        return []


class PublicBlocklistSource:
    """SKELETON. Ingest existing public anti-piracy / abuse blocklists (e.g.
    community-maintained lists) as candidate seeds to enrich and attribute."""
    name = "public_blocklist"

    def __init__(self, list_urls: Optional[list[str]] = None):
        self.list_urls = list_urls or []

    def discover(self) -> Iterable[StreamObservation]:
        # TODO: fetch + parse each list; emit one observation per entry.
        return []


class SearchEngineSource:
    """SKELETON. Query search engines for '<event> free live stream' patterns.
    Needs rotating egress + result parsing; SERP scraping is ToS-sensitive and
    gets blocked, so treat as a lead source, not a backbone."""
    name = "search_engine"

    def __init__(self, queries: Optional[list[str]] = None):
        self.queries = queries or []

    def discover(self) -> Iterable[StreamObservation]:
        return []  # TODO


class SocialTelegramSource:
    """SKELETON. Monitor public social/Telegram channels where stream links are
    posted around event time. Needs platform API access / channel subscriptions."""
    name = "social_telegram"

    def __init__(self, channels: Optional[list[str]] = None):
        self.channels = channels or []

    def discover(self) -> Iterable[StreamObservation]:
        return []  # TODO


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------
class DiscoveryOrchestrator:
    """Runs every configured source and unions their candidates, deduped by URL.
    A source that errors or yields nothing simply contributes nothing."""

    def __init__(self, sources: list[DiscoverySource]):
        self.sources = sources

    def run(self) -> list[StreamObservation]:
        seen: set[str] = set()
        out: list[StreamObservation] = []
        for src in self.sources:
            try:
                for obs in src.discover():
                    key = obs.url.rstrip("/")
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(obs)
            except Exception:
                continue  # one bad source never sinks discovery
        return out

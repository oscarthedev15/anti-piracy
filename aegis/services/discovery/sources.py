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
  REAL      ReverseInfraSource      — from a confirmed domain, pivot to siblings via
                                      the served cert's SANs + crt.sh history.
  REAL      ReverseIPSource         — from a confirmed domain, find other domains
                                      co-hosted on the same origin IP (HackerTarget
                                      free reverse-IP). Guarded to skip CDN fronts.
  SKELETON  PublicBlocklistSource   — ingest existing public anti-piracy blocklists
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
    """REAL. Given one or more CONFIRMED domains, pivot to the operator's OTHER
    domains — the highest-yield discovery once you have a single confirmed site.

    Two free signals, no API key:
      1. Live TLS SANs — the cert served for the confirmed site frequently lists
         every domain it covers in Subject Alternative Names. A cert covering
         several different-brand domains is a strong same-operator link.
      2. crt.sh history — all names ever seen on certs mentioning the domain
         (catches rotated subdomains / related names over time).

    Reverse-IP (other domains co-hosted on the same origin) needs a passive-DNS
    provider and is left as a documented extension below.
    """
    name = "reverse_infra"

    def __init__(self, domains: Optional[list[str]] = None,
                 timeout: float = 6.0, use_crtsh: bool = True,
                 crtsh_limit: int = 60):
        self.seed_domains = [d.strip().lower() for d in (domains or [])]
        self.timeout = timeout
        self.use_crtsh = use_crtsh
        self.crtsh_limit = crtsh_limit

    def _san_names(self, host: str) -> list[str]:
        import socket
        import ssl
        # 1) strict handshake: parsed SANs for a cert that validates.
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            out = [v.strip().lower().lstrip("*.")
                   for typ, v in cert.get("subjectAltName", ())
                   if typ.lower() == "dns"]
            if out:
                return out
        except Exception:
            pass
        # 2) fallback: pirate sites often serve certs that don't validate. Read
        #    the SANs off the raw cert anyway (needs `cryptography`; no-op without).
        try:
            from cryptography import x509
        except Exception:
            return []
        try:
            unv = ssl._create_unverified_context()
            with socket.create_connection((host, 443), timeout=self.timeout) as s:
                with unv.wrap_socket(s, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [n.strip().lower().lstrip("*.")
                    for n in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            return []

    def _crtsh_siblings(self, domain: str) -> list[str]:
        # reuse the CT source's resilient fetch
        rows = CertTransparencySource([domain], per_keyword_limit=self.crtsh_limit,
                                      timeout=self.timeout)._query(domain)
        return rows

    def discover(self) -> Iterable[StreamObservation]:
        seen: set[str] = set(self.seed_domains)
        for seed in self.seed_domains:
            siblings: set[str] = set(self._san_names(seed))
            if self.use_crtsh:
                siblings.update(self._crtsh_siblings(seed))
            for d in sorted(siblings):
                if not d or d in seen:
                    continue
                seen.add(d)
                yield StreamObservation(
                    url=f"https://{d}/",
                    source="reverse_infra",
                    event_hint=None,
                    raw={"pivot_from": seed,
                         "reason": "shares a TLS cert / CT history with a "
                                   "confirmed operator domain"},
                )

    # Extension: reverse-IP co-hosting via passive DNS (needs a provider key).
    def reverse_ip_todo(self, ip: str) -> list[str]:  # pragma: no cover
        return []


class ReverseIPSource:
    """REAL. From a confirmed domain, find OTHER domains co-hosted on the same
    origin IP — the operator's other brands parked on one box.

    Uses HackerTarget's free (no-key, rate-limited) reverse-IP lookup. Critically
    guarded: reverse-IP is only run on VPS/dedicated IPs, NEVER on a CDN/cloud
    front (a Cloudflare IP fronts millions of unrelated sites, so the result
    would be pure noise). That guard is the same "don't treat shared infra as an
    operator" principle used everywhere else.
    """
    name = "reverse_ip"
    PROVIDER = "https://api.hackertarget.com/reverseiplookup/?q="

    def __init__(self, domains: Optional[list[str]] = None,
                 ips: Optional[list[str]] = None, timeout: float = 12.0,
                 per_ip_limit: int = 500, skip_cdn: bool = True,
                 shared_host_threshold: int = 25):
        self.seed_domains = [d.strip().lower() for d in (domains or [])]
        self.seed_ips = ips or []
        self.timeout = timeout
        self.per_ip_limit = per_ip_limit
        self.skip_cdn = skip_cdn
        # If an IP hosts more than this many domains it is shared hosting
        # (cPanel/reseller), not one operator's box — its co-tenants are noise.
        self.shared_host_threshold = shared_host_threshold
        self.last_skipped: list[dict] = []   # IPs suppressed as shared hosting

    def _lookup_ip(self, ip: str) -> list[str]:
        req = Request(self.PROVIDER + quote(ip),
                      headers={"User-Agent": _UA, "Accept": "text/plain"})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
        except Exception:
            return []
        low = text.lower()
        if "api count exceeded" in low or "error" in low[:40]:
            return []   # rate-limited or bad input — fail soft
        out: list[str] = []
        for line in text.splitlines():
            d = line.strip().lower().lstrip("*.")
            if d and "." in d and d not in out:
                out.append(d)
        return out[: self.per_ip_limit]

    def discover(self) -> Iterable[StreamObservation]:
        from aegis.asn_registry import classify
        from aegis.services.enrichment.live import LiveEnrichment

        enr = LiveEnrichment(timeout=self.timeout)
        targets: list[tuple[str, str]] = []  # (ip, pivot_label)
        for d in self.seed_domains:
            e = enr.enrich(d)
            if not e.ips:
                continue
            if self.skip_cdn and classify(e.asn) == "cdn":
                continue  # reverse-IP on a CDN front is meaningless
            targets.append((e.ips[0], d))
        for ip in self.seed_ips:
            targets.append((ip, ip))

        seen = set(self.seed_domains)
        self.last_skipped = []
        for ip, pivot in targets:
            cohosted = self._lookup_ip(ip)
            # Shared-hosting guard: a box with dozens of unrelated tenants is not
            # one operator — its co-tenants are noise, so suppress them.
            if len(cohosted) > self.shared_host_threshold:
                self.last_skipped.append({"ip": ip, "pivot": pivot,
                                          "cohosting_count": len(cohosted)})
                continue
            for d in cohosted:
                if d in seen:
                    continue
                seen.add(d)
                yield StreamObservation(
                    url=f"https://{d}/",
                    source="reverse_ip",
                    event_hint=None,
                    raw={"pivot_from": pivot, "co_hosted_ip": ip,
                         "cohosting_count": len(cohosted),
                         "reason": f"co-hosted with {pivot} on {ip} "
                                   f"({len(cohosted)} tenants — small, likely same op)"},
                )


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

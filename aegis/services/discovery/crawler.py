"""
Aggregator crawler — real, local, free Discovery.

The manual "paste a URL" flow doesn't scale: real pirate portals are link
directories (we measured 148+ event links on one landing page). You should hand
the system a few *seed* portals you know, and it should find the many candidate
stream pages — and, crucially, the third-party **iframe embed domains**, which
are usually the real streaming infrastructure behind many front-end brands.

This is a polite, bounded BFS crawler (stdlib-only): it walks internal links of
each seed up to a depth/page cap, and emits a `StreamObservation` for every page
that looks like a stream/event page, every iframe embed, and any direct
`.m3u8`/`.mpd` reference it sees in static HTML.

It decides nothing about guilt — it only nominates candidates for detection and
enrichment. It never fetches video; it reads HTML for links, same as a search
crawler.
"""
from __future__ import annotations

import re
import time
from collections import deque
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from aegis.models import StreamObservation


_UA = ("Mozilla/5.0 (compatible; AEGIS-enforcement-scan/0.1; "
       "+anti-piracy discovery crawler)")

# A link/path that looks like a live-event or embedded-player page.
_EVENT_HINT = re.compile(
    r"stream|live|watch|match|embed|player|/[a-z0-9]+-vs-[a-z0-9]+|"
    r"soccer|football|nba|nfl|f1|ufc|boxing|cricket|motogp", re.I)
_MANIFEST = re.compile(r"https?://[^\s\"'<>]+\.(?:m3u8|mpd)", re.I)


class _LinkExtractor(HTMLParser):
    """Pulls <a href>, <iframe src>, <source src> out of a page."""

    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []
        self.iframes: list[str] = []
        self.media: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.hrefs.append(d["href"])
        elif tag == "iframe" and d.get("src"):
            self.iframes.append(d["src"])
        elif tag in ("source", "video") and d.get("src"):
            self.media.append(d["src"])


def _registrable(host: str) -> str:
    """Cheap eTLD+1 approximation (no external deps): last two labels. Good
    enough to keep the crawl on the seed's site vs. jumping to embed domains."""
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class AggregatorCrawler:
    name = "aggregator_crawler"

    def __init__(self, max_pages: int = 25, max_depth: int = 2,
                 timeout: float = 6.0, delay: float = 0.3,
                 max_bytes: int = 600_000, max_candidates: int = 60,
                 html_cache: Optional[dict[str, str]] = None):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay              # politeness between requests
        self.max_bytes = max_bytes
        self.max_candidates = max_candidates
        # Shared with the detector so a crawled page is never re-fetched.
        self.html_cache: dict[str, str] = html_cache if html_cache is not None else {}

    def _fetch(self, url: str) -> str:
        req = Request(url, headers={"User-Agent": _UA,
                                    "Accept": "text/html,*/*"})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                html = resp.read(self.max_bytes).decode("utf-8", errors="replace")
        except Exception:
            return ""
        self.html_cache[url] = html   # let detection reuse this fetch
        return html

    def crawl(self, seeds: list[str], event_hint: str = "") -> list[StreamObservation]:
        seen_pages: set[str] = set()
        emitted: dict[str, StreamObservation] = {}   # url -> observation (dedup)
        frontier: deque[tuple[str, int]] = deque()

        seed_sites = set()
        for s in seeds:
            frontier.append((s, 0))
            seed_sites.add(_registrable(urlparse(s).hostname or ""))

        pages_fetched = 0
        while frontier and pages_fetched < self.max_pages:
            if len(emitted) >= self.max_candidates:
                break  # candidate cap reached (reported by the caller)
            url, depth = frontier.popleft()
            if url in seen_pages:
                continue
            seen_pages.add(url)

            html = self._fetch(url)
            pages_fetched += 1
            if self.delay:
                time.sleep(self.delay)
            if not html:
                continue

            host = urlparse(url).hostname or ""
            site = _registrable(host)
            ex = _LinkExtractor()
            try:
                ex.feed(html)
            except Exception:
                pass

            # 1) direct manifest references (rare in static HTML, highest value)
            for m in set(_MANIFEST.findall(html)):
                self._emit(emitted, m, "manifest", url, event_hint)

            # 2) iframe embeds — cross-site ones are the real infra targets
            for src in ex.iframes:
                emb = urljoin(url, src)
                emb_site = _registrable(urlparse(emb).hostname or "")
                if emb_site and emb_site not in seed_sites:
                    self._emit(emitted, emb, "embed", url, event_hint)

            # 3) internal links: enqueue for deeper crawl + emit event-like ones
            for href in ex.hrefs:
                nxt = urljoin(url, href)
                p = urlparse(nxt)
                if p.scheme not in ("http", "https"):
                    continue
                if _registrable(p.hostname or "") != site:
                    continue  # stay on the seed's site for crawling
                if _EVENT_HINT.search(nxt):
                    self._emit(emitted, nxt, "event_page", url, event_hint)
                if depth < self.max_depth and nxt not in seen_pages:
                    frontier.append((nxt, depth + 1))

        return list(emitted.values())

    @staticmethod
    def _emit(bucket: dict, url: str, kind: str, via: str, event_hint: str) -> None:
        if url in bucket:
            return
        # derive a per-candidate hint from the slug if no global one given
        slug = urlparse(url).path.rsplit("/", 1)[-1].replace("-", " ").strip()
        bucket[url] = StreamObservation(
            url=url,
            source=f"crawler:{kind}",
            event_hint=event_hint or (slug or None),
            raw={"discovered_via": via, "kind": kind},
        )

"""
Headless-render detection — the real answer to JS-rendered piracy portals.

The static-HTML classifier (heuristic.py) can't see the stream on modern
aggregators: the `.m3u8` manifest is injected by JavaScript, often inside a
third-party iframe, several clicks deep. This backend renders the page in a real
(headless Chromium) browser and watches the NETWORK: when the player boots it
*fetches* the HLS/DASH manifest, and that request is the definitive tell — you
don't need the markup, you catch the request.

It also collects the iframe/frame domains the page loads: the embed host is
usually the real streaming operator behind many aggregator front-ends, so those
domains are handed to enrichment/attribution.

Optional dependency: `pip install playwright && playwright install chromium`.
If Playwright isn't present the class raises a clear error at construction, and
the rest of AEGIS keeps working on the stdlib heuristic backend.

It renders pages and observes requests; it never plays, downloads, or stores the
video itself — capturing a manifest URL is seeing a request, not fetching a feed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

_MANIFEST = re.compile(r"\.(m3u8|mpd)(?:[?#]|$)", re.I)


@dataclass
class HeadlessProbe:
    url: str
    manifests: list[str] = field(default_factory=list)   # .m3u8/.mpd requests seen
    embed_domains: list[str] = field(default_factory=list)  # iframe/frame hosts
    player_found: bool = False
    error: Optional[str] = None


class HeadlessStreamBackend:
    """Plugs into DetectionService via score(). Lazily launches one browser and
    reuses it across probes; call close() when done."""

    method = "headless"

    def __init__(self, nav_timeout_ms: int = 15000, settle_ms: int = 4000,
                 block_media: bool = True):
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "HeadlessStreamBackend needs Playwright. Install with:\n"
                "  pip install playwright && playwright install chromium"
            ) from e
        self.nav_timeout_ms = nav_timeout_ms
        self.settle_ms = settle_ms
        self.block_media = block_media
        self._pw = None
        self._browser = None
        self._cache: dict[str, HeadlessProbe] = {}

    # ---- browser lifecycle ----------------------------------------------
    def _ensure_browser(self):
        if self._browser is not None:
            return
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        finally:
            self._browser = None
            self._pw = None

    # ---- the probe -------------------------------------------------------
    def probe(self, url: str) -> HeadlessProbe:
        if url in self._cache:
            return self._cache[url]
        result = HeadlessProbe(url=url)
        try:
            self._ensure_browser()
            context = self._browser.new_context(
                user_agent=("Mozilla/5.0 (compatible; AEGIS-enforcement-scan/0.1; "
                            "+anti-piracy detection)"),
                ignore_https_errors=True,
            )
            # Don't pull the actual video/large media — we only need to SEE the
            # manifest request, not download the stream.
            if self.block_media:
                context.route(
                    re.compile(r"\.(ts|m4s|mp4|aac|webm|jpg|png|gif|woff2?)(\?|$)", re.I),
                    lambda route: route.abort(),
                )
            page = context.new_page()

            seen_manifests: set[str] = set()

            def _on_request(req):
                if _MANIFEST.search(req.url):
                    seen_manifests.add(req.url.split("?")[0])
            page.on("request", _on_request)

            page.goto(url, timeout=self.nav_timeout_ms, wait_until="domcontentloaded")
            page.wait_for_timeout(self.settle_ms)  # let the player boot

            # rendered-DOM player signal
            try:
                result.player_found = bool(page.query_selector(
                    "video, [class*=player], [id*=player], [class*=jwplayer]"))
            except Exception:
                pass

            # iframe/frame hosts = candidate embed operators
            seed_host = urlparse(url).hostname or ""
            embeds: set[str] = set()
            for fr in page.frames:
                fh = urlparse(fr.url).hostname or ""
                if fh and fh != seed_host:
                    embeds.add(fh)

            result.manifests = sorted(seen_manifests)
            result.embed_domains = sorted(embeds)
            context.close()
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
        self._cache[url] = result
        return result

    # ---- DetectionService interface -------------------------------------
    def score(self, url: str, reference_id: str) -> float:
        p = self.probe(url)
        if p.manifests:
            return 0.9   # a real manifest was fetched on render — definitive-ish
        if p.player_found and p.embed_domains:
            return 0.6   # a player mounted inside a third-party embed
        if p.player_found:
            return 0.45
        return 0.0

    def embeds_for(self, url: str) -> list[str]:
        return self._cache.get(url, HeadlessProbe(url)).embed_domains

    def manifests_for(self, url: str) -> list[str]:
        return self._cache.get(url, HeadlessProbe(url)).manifests

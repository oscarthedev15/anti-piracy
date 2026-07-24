"""
Heuristic live-stream detector — a REAL, free detection signal.

Honest scope: without a licensed copy of the protected broadcast there is no way
to *prove* "this stream carries the EPL feed" — that requires perceptual
fingerprinting against a reference, which no one can do for free. What CAN be
done for free, and is genuinely useful, is to decide *"is this page a live-video
streaming portal?"* from its own markup:

  * HLS (`.m3u8`) or DASH (`.mpd`) manifest references
  * embedded player libraries (hls.js, video.js, jwplayer, clappr, dplayer…)
  * a <video> element / streaming <iframe>
  * live-event language, boosted when it matches the event we're hunting

This is a triage signal — high structural resemblance, NOT proof of
infringement — so its confidence is deliberately capped. It plugs into the same
DetectionService as the (stubbed) fingerprint backend via `score()`.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen


_UA = ("Mozilla/5.0 (compatible; AEGIS-enforcement-scan/0.1; "
       "+anti-piracy metadata classifier)")

_PLAYER_LIBS = re.compile(
    r"hls\.js|video\.js|jwplayer|clappr|dplayer|flowplayer|shaka-player|plyr",
    re.I)
_MANIFEST_HLS = re.compile(r"\.m3u8", re.I)
_MANIFEST_DASH = re.compile(r"\.mpd(?:[\"'?]|$)", re.I)
_VIDEO_TAG = re.compile(r"<video[\s>]", re.I)
_IFRAME = re.compile(r"<iframe[\s>]", re.I)
_LIVE_WORDS = re.compile(
    r"live\s*stream|watch\s*live|free\s*stream|streaming\s*(?:now|live)|"
    r"live\s*hd|full\s*match", re.I)


class HeuristicStreamBackend:
    """Fetches a candidate page once and scores its live-stream resemblance.

    Implements the FingerprintBackend protocol (`score(url, reference_id)`), so
    DetectionService can use it unchanged. `reference_id` is used only as a
    keyword hint (e.g. the event name) for a small relevance boost.
    """

    method = "heuristic"  # DetectionService labels DetectionResult with this

    def __init__(self, timeout: float = 8.0, max_bytes: int = 500_000):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._cache: dict[str, tuple[float, list[str]]] = {}

    # ---- network ---------------------------------------------------------
    def _is_public_host(self, host: str) -> bool:
        try:
            for info in socket.getaddrinfo(host, None):
                if not ipaddress.ip_address(info[4][0]).is_global:
                    return False
        except (socket.gaierror, ValueError):
            return False
        return True

    def _fetch(self, url: str) -> str:
        host = urlparse(url).hostname
        if not host or not self._is_public_host(host):
            return ""   # SSRF guard: never fetch internal/unresolvable hosts
        req = Request(url, headers={"User-Agent": _UA, "Accept": "text/html,*/*"})
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(self.max_bytes)
        except Exception:
            return ""
        return raw.decode("utf-8", errors="replace")

    # ---- scoring ---------------------------------------------------------
    def _signals(self, html: str, reference_id: str) -> tuple[float, list[str]]:
        score, hits = 0.0, []
        if _MANIFEST_HLS.search(html):
            score += 0.40; hits.append("hls_manifest(.m3u8)")
        if _MANIFEST_DASH.search(html):
            score += 0.30; hits.append("dash_manifest(.mpd)")
        if _PLAYER_LIBS.search(html):
            score += 0.20; hits.append("player_library")
        if _VIDEO_TAG.search(html):
            score += 0.15; hits.append("video_element")
        if _IFRAME.search(html):
            score += 0.10; hits.append("iframe_embed")
        if _LIVE_WORDS.search(html):
            score += 0.15; hits.append("live_stream_language")
            # event-specific language is a stronger signal than generic "live"
            terms = [t for t in re.split(r"[:\s]+", reference_id or "") if len(t) > 3]
            if terms and any(re.search(re.escape(t), html, re.I) for t in terms):
                score += 0.10; hits.append("matches_event_terms")
        # Capped below 1.0: this is resemblance, never proof of infringement.
        return min(score, 0.95), hits

    def score(self, url: str, reference_id: str) -> float:
        if url not in self._cache:
            html = self._fetch(url)
            self._cache[url] = self._signals(html, reference_id) if html else (0.0, [])
        return self._cache[url][0]

    def signals_for(self, url: str) -> list[str]:
        """The human-readable signal list behind the last score (for evidence)."""
        return self._cache.get(url, (0.0, []))[1]

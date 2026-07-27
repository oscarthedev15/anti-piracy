"""
Live infrastructure enrichment — the REAL, free, stdlib-only collector.

For a given host it gathers the public metadata every attribution pivot needs:
  * DNS resolution        (all A records)
  * TLS certificate hash  (SHA-256 of the leaf cert — the domain-hop tell)
  * ASN / network owner    (Team Cymru's free IP->ASN service, no key)

From those it populates the AttributionGraph with the same asset/edge shape the
demo used — except now every value is real. Two domains that genuinely share a
TLS cert or a dedicated origin IP will cluster into one operator on real data.

Nothing here fetches or stores infringing content. It is the network-metadata
equivalent of `dig` + `openssl s_client` + a whois ASN lookup — public data.
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

from aegis.asn_registry import classify, name_for
from aegis.models import Asset, AssetType
from aegis.services.attribution.graph import AttributionGraph


@dataclass
class HostEnrichment:
    host: str
    ips: list[str] = field(default_factory=list)
    cert_sha256: Optional[str] = None
    asn: Optional[int] = None
    as_name: Optional[str] = None
    dedicated: bool = False
    reachable: bool = False
    note: str = ""


class LiveEnrichment:
    """Real enrichment over public network metadata. Pure stdlib."""

    def __init__(self, timeout: float = 6.0,
                 cymru_host: str = "whois.cymru.com", cymru_port: int = 43):
        self.timeout = timeout
        self.cymru_host = cymru_host
        self.cymru_port = cymru_port

    # ---- individual signals ----------------------------------------------
    def resolve(self, host: str) -> list[str]:
        """All public A records for the host. Private/loopback IPs are dropped
        (SSRF hygiene — we never want a candidate URL pointing us at internal
        infrastructure)."""
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        ips: list[str] = []
        for info in infos:
            ip = info[4][0]
            try:
                if ipaddress.ip_address(ip).is_global and ip not in ips:
                    ips.append(ip)
            except ValueError:
                continue
        return ips

    def tls_fingerprint(self, host: str) -> Optional[str]:
        """SHA-256 of the leaf certificate presented for `host`."""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except Exception:
            return None
        if not der:
            return None
        return "sha256:" + hashlib.sha256(der).hexdigest()

    def asn_lookup(self, ips: list[str]) -> dict[str, tuple[int, str]]:
        """IP -> (asn, as_name) via Team Cymru's free bulk whois. No key, no
        per-query cost. Returns {} on any failure (offline / blocked)."""
        if not ips:
            return {}
        query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
        try:
            with socket.create_connection((self.cymru_host, self.cymru_port),
                                          timeout=self.timeout) as s:
                s.sendall(query.encode())
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
        except Exception:
            return {}

        out: dict[str, tuple[int, str]] = {}
        for line in buf.decode(errors="replace").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 7:
                continue
            asn_raw, ip = parts[0], parts[1]
            if not asn_raw.isdigit():
                continue  # header row or unrouted (NA)
            out[ip] = (int(asn_raw), parts[6])
        return out

    # ---- combined --------------------------------------------------------
    def enrich(self, host: str) -> HostEnrichment:
        host = host.strip().lower()
        result = HostEnrichment(host=host)

        ips = self.resolve(host)
        result.ips = ips
        result.reachable = bool(ips)
        if not ips:
            result.note = "DNS did not resolve to a public address."
            return result

        result.cert_sha256 = self.tls_fingerprint(host)
        asn_map = self.asn_lookup(ips)
        primary = ips[0]
        if primary in asn_map:
            result.asn, result.as_name = asn_map[primary]

        # Dedicated only if we have a positive ASN signal AND that ASN is not a
        # known multi-tenant host. Absent proof, default to NOT dedicated so the
        # blocklist stays FQDN-only (never an unjustified IP block).
        cls = classify(result.asn)
        if cls == "cdn":
            result.note = f"Shared CDN/cloud front ({name_for(result.asn)})."
        elif cls == "vps":
            result.note = (f"Shared VPS host ({name_for(result.asn)}); a specific "
                           "IP may be single-tenant but same-/24 neighbours may not.")
        elif result.asn is not None:
            result.dedicated = True
            result.note = ("ASN not a known CDN/VPS; candidate single-tenant "
                           "origin (verify before IP block).")
        else:
            result.note = "ASN unavailable; treating as shared (FQDN-only)."
        return result

    def enrich_into_graph(self, host: str, graph: AttributionGraph) -> HostEnrichment:
        """Run enrichment and write real assets + pivot edges into the graph,
        using the exact relations the attribution clusterer understands."""
        e = self.enrich(host)
        dom = graph.upsert_asset(AssetType.DOMAIN, e.host)

        if e.cert_sha256:
            cert = graph.upsert_asset(AssetType.TLS_CERT, e.cert_sha256)
            # Strong pivot: a cert reused across "different" domains is the
            # classic domain-hop tell.
            graph.link(dom, cert, "SHARES_TLS_CERT")

        for ip in e.ips:
            ip_asset = graph.upsert_asset(
                AssetType.IP, ip,
                asn=(f"AS{e.asn}" if e.asn is not None else None),
                as_name=e.as_name,
                dedicated=bool(e.dedicated and ip == e.ips[0]),
            )
            relation = ("RESOLVES_TO_DEDICATED_IP"
                        if (e.dedicated and ip == e.ips[0])
                        else "RESOLVES_TO_SHARED_IP")
            graph.link(dom, ip_asset, relation)
        return e

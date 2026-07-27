"""
Single source of truth for classifying an ASN (hosting network).

Three classes drive both the block-safety guardrail and the attribution tiers:

  * CDN_CLOUD — huge shared fronts (Cloudflare, AWS, Google…). An IP here is
    shared by millions of sites: NEVER IP-block, and same-network co-location
    means nothing.
  * VPS_HOSTING — rented VPS/dedicated hosts (Linode, OVH, Hetzner…). A single
    IP is often one tenant, but neighbours in the same /24 can be unrelated —
    so same-/24 is a SUSPECTED lead for review, not proof of one operator.
  * OTHER — everything else; treated conservatively (FQDN-only unless proven).

Previously this knowledge was duplicated across enrichment and the blocklist
generator in two different formats; it now lives here.
"""
from __future__ import annotations

from typing import Optional

# Big CDNs / clouds — shared by vast numbers of unrelated sites.
CDN_CLOUD_ASNS = {
    13335: "Cloudflare",
    15169: "Google",
    16509: "Amazon/AWS",
    14618: "Amazon/AWS",
    20940: "Akamai",
    16625: "Akamai",
    8075: "Microsoft",
    54113: "Fastly",
    32934: "Meta",
    13414: "Twitter/X",
}

# VPS / hosting providers — many tenants, but a given IP is often single-use.
# Same-/24 co-location here is a lead worth investigating, not a merge.
VPS_HOSTING_ASNS = {
    14061: "DigitalOcean",
    16276: "OVH",
    24940: "Hetzner",
    63949: "Akamai-Linode",
    20473: "Vultr/Choopa",
    51167: "Contabo",
    133618: "Trellian",   # domain parking/monetisation — usually a dead site
}


def classify(asn: Optional[int]) -> str:
    """Return 'cdn', 'vps', or 'other'."""
    if asn is None:
        return "other"
    if asn in CDN_CLOUD_ASNS:
        return "cdn"
    if asn in VPS_HOSTING_ASNS:
        return "vps"
    return "other"


def name_for(asn: Optional[int]) -> Optional[str]:
    if asn is None:
        return None
    return CDN_CLOUD_ASNS.get(asn) or VPS_HOSTING_ASNS.get(asn)


def is_shared_front(asn: Optional[int]) -> bool:
    """True for big CDN/cloud fronts that must never be IP-blocked."""
    return classify(asn) == "cdn"

"""Deterministic Mock GeoIP lookup used for the MVP.

The real product would call a paid GeoIP database (MaxMind, IPinfo, etc.) and
return city/country/ASN. For the MVP we return a deterministic stub keyed on
the IP so demos and tests are reproducible without external dependencies.

Keep this file independent from the CTI provider — they enrich different facets
of an indicator and may be swapped out separately.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Optional

from pydantic import BaseModel, Field


# ASN ranges chosen so the demo log lines map to plausible-looking values.
COUNTRIES = ["US", "KR", "NL", "DE", "SG", "JP", "RU", "CN", "BR", "GB"]
CITIES = {
    "US": "Ashburn",
    "KR": "Seoul",
    "NL": "Amsterdam",
    "DE": "Frankfurt",
    "SG": "Singapore",
    "JP": "Tokyo",
    "RU": "Moscow",
    "CN": "Beijing",
    "BR": "Sao Paulo",
    "GB": "London",
}
ASNS = [
    (15169, "Google LLC"),
    (16509, "Amazon.com, Inc."),
    (8075, "Microsoft Corporation"),
    (4837, "China Unicom"),
    (4134, "China Telecom"),
    (12876, "Online S.A.S."),
    (13335, "Cloudflare, Inc."),
    (9009, "M247 Ltd"),
    (14061, "DigitalOcean, LLC"),
    (24940, "Hetzner Online GmbH"),
]
PRIVATE_GEO_NOTE = "Private/loopback IP — geo lookup skipped."
UNKNOWN_GEO_NOTE = "No source IP was available for GeoIP lookup."


class GeoLocation(BaseModel):
    """Minimal GeoIP shape consumed by the correlation/incident worker."""

    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_private: bool = False
    note: Optional[str] = None
    sources: list[str] = Field(default_factory=lambda: ["mock-geoip"])


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def lookup_geoip(ip: Optional[str]) -> GeoLocation:
    """Return a deterministic GeoLocation for ``ip``.

    Outputs are stable across runs because they are derived from a SHA-256 of
    the IP string. This keeps demo evidence consistent without external calls.
    """

    if not ip:
        return GeoLocation(note=UNKNOWN_GEO_NOTE)

    if _is_private(ip):
        return GeoLocation(ip=ip, is_private=True, note=PRIVATE_GEO_NOTE)

    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    country = COUNTRIES[digest[0] % len(COUNTRIES)]
    asn_id, asn_org = ASNS[digest[2] % len(ASNS)]
    return GeoLocation(
        ip=ip,
        country=country,
        city=CITIES.get(country),
        asn=asn_id,
        asn_org=asn_org,
        is_private=False,
        note="Deterministic mock GeoIP result for local MVP development.",
    )

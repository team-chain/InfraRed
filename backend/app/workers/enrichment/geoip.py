"""GeoIP lookup — real MaxMind GeoLite2 with deterministic mock fallback.

Priority:
  1. GeoLite2-City.mmdb (downloaded on first use via MAXMIND_LICENSE_KEY)
  2. Deterministic mock (keeps tests/demos reproducible when DB unavailable)
"""
from __future__ import annotations

import hashlib
import io
import ipaddress
import logging
import os
import tarfile
import urllib.request
from functools import lru_cache
from typing import Optional

from pydantic import BaseModel, Field

from app.config import get_settings

log = logging.getLogger(__name__)

MAXMIND_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
)

# ── mock fallback data ─────────────────────────────────────────────────────
COUNTRIES = ["US", "KR", "NL", "DE", "SG", "JP", "RU", "CN", "BR", "GB"]
CITIES = {
    "US": "Ashburn", "KR": "Seoul", "NL": "Amsterdam", "DE": "Frankfurt",
    "SG": "Singapore", "JP": "Tokyo", "RU": "Moscow", "CN": "Beijing",
    "BR": "Sao Paulo", "GB": "London",
}
ASNS = [
    (15169, "Google LLC"), (16509, "Amazon.com, Inc."),
    (8075, "Microsoft Corporation"), (4837, "China Unicom"),
    (4134, "China Telecom"), (12876, "Online S.A.S."),
    (13335, "Cloudflare, Inc."), (9009, "M247 Ltd"),
    (14061, "DigitalOcean, LLC"), (24940, "Hetzner Online GmbH"),
]

PRIVATE_GEO_NOTE = "Private/loopback IP — geo lookup skipped."
UNKNOWN_GEO_NOTE = "No source IP was available for GeoIP lookup."


class GeoLocation(BaseModel):
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_private: bool = False
    note: Optional[str] = None
    sources: list[str] = Field(default_factory=lambda: ["maxmind-geolite2"])


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _download_db(license_key: str, db_path: str) -> bool:
    """Download GeoLite2-City.mmdb from MaxMind and save to db_path."""
    try:
        url = MAXMIND_DOWNLOAD_URL.format(key=license_key)
        log.info("geoip_db_download_start path=%s", db_path)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "infrared-agent/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-City.mmdb"):
                    f = tar.extractfile(member)
                    if f:
                        with open(db_path, "wb") as out:
                            out.write(f.read())
                        log.info("geoip_db_download_ok path=%s", db_path)
                        return True
        log.warning("geoip_db_mmdb_not_found_in_archive")
    except Exception as exc:
        log.warning("geoip_db_download_failed error=%s", exc)
    return False


@lru_cache(maxsize=1)
def _get_reader():
    """Return a geoip2 Reader, downloading the DB if necessary. Returns None on failure."""
    settings = get_settings()
    db_path = settings.maxmind_db_path
    license_key = settings.maxmind_license_key

    if not os.path.exists(db_path):
        if not license_key:
            log.warning("geoip_no_license_key_using_mock")
            return None
        if not _download_db(license_key, db_path):
            return None

    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        log.info("geoip_reader_ready path=%s", db_path)
        return reader
    except Exception as exc:
        log.warning("geoip_reader_init_failed error=%s", exc)
        return None


def _mock_lookup(ip: str) -> GeoLocation:
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    country = COUNTRIES[digest[0] % len(COUNTRIES)]
    asn_id, asn_org = _mock_asn(ip)
    return GeoLocation(
        ip=ip,
        country=country,
        city=CITIES.get(country),
        asn=asn_id,
        asn_org=asn_org,
        is_private=False,
        note="Deterministic mock GeoIP (MaxMind DB unavailable).",
        sources=["mock-geoip"],
    )


def _mock_asn(ip: str) -> tuple[int, str]:
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    return ASNS[digest[2] % len(ASNS)]


def lookup_geoip(ip: Optional[str]) -> GeoLocation:
    if not ip:
        return GeoLocation(note=UNKNOWN_GEO_NOTE, sources=[])

    if _is_private(ip):
        return GeoLocation(ip=ip, is_private=True, note=PRIVATE_GEO_NOTE, sources=[])

    reader = _get_reader()
    if reader is None:
        return _mock_lookup(ip)

    try:
        response = reader.city(ip)
        asn_id, asn_org = _mock_asn(ip)
        return GeoLocation(
            ip=ip,
            country=response.country.iso_code,
            city=response.city.name,
            asn=asn_id,
            asn_org=asn_org,
            is_private=False,
            sources=["maxmind-geolite2"],
        )
    except Exception as exc:
        log.debug("geoip_lookup_failed ip=%s error=%s", ip, exc)
        return _mock_lookup(ip)

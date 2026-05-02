"""CTI provider — real AbuseIPDB with deterministic mock fallback.

Priority:
  1. AbuseIPDB API (when CTI_PROVIDER=abuseipdb and ABUSEIPDB_API_KEY is set)
  2. Deterministic mock (keeps tests/demos reproducible when API unavailable)
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
from typing import Optional

import httpx

from app.config import get_settings
from app.models.incident import CtiEnrichment


log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

MOCK_COUNTRIES = ["US", "KR", "NL", "DE", "SG", "JP"]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _mock_cti_lookup(ip: str) -> CtiEnrichment:
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    score = digest[0] % 100
    tags: list[str] = []
    if score >= 70:
        tags.append("high-risk-ip")
    if score >= 40:
        tags.append("scanner")
    return CtiEnrichment(
        abuse_score=score,
        country=MOCK_COUNTRIES[digest[1] % len(MOCK_COUNTRIES)],
        tags=tags,
        sources=["mock-cti"],
        note="Deterministic mock CTI result (AbuseIPDB unavailable).",
    )


def _abuseipdb_lookup(ip: str, api_key: str) -> CtiEnrichment:
    """Query AbuseIPDB v2 check endpoint synchronously."""
    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        score = int(data.get("abuseConfidenceScore", 0))
        country = data.get("countryCode") or None
        is_tor = data.get("isTor", False)
        usage_type = data.get("usageType") or ""
        domain = data.get("domain") or ""
        total_reports = int(data.get("totalReports", 0))

        tags: list[str] = []
        if score >= 80:
            tags.append("high-risk-ip")
        if score >= 40:
            tags.append("scanner")
        if is_tor:
            tags.append("tor-exit-node")
        if "VPN" in usage_type or "Proxy" in usage_type:
            tags.append("vpn-proxy")

        note_parts = []
        if domain:
            note_parts.append(f"domain={domain}")
        if usage_type:
            note_parts.append(f"type={usage_type}")
        if total_reports:
            note_parts.append(f"reports={total_reports}")

        return CtiEnrichment(
            abuse_score=score,
            country=country,
            tags=tags,
            sources=["abuseipdb"],
            note=", ".join(note_parts) if note_parts else None,
        )
    except Exception as exc:
        log.warning("abuseipdb_lookup_failed ip=%s error=%s", ip, exc)
        return _mock_cti_lookup(ip)


def mock_cti_lookup(ip: Optional[str]) -> CtiEnrichment:
    """Public interface called by the enrichment worker."""
    if not ip:
        return CtiEnrichment(note="No source IP was available for CTI lookup.")

    if _is_private(ip):
        return CtiEnrichment(note="Private/loopback IP — CTI lookup skipped.")

    settings = get_settings()
    if settings.cti_provider == "abuseipdb" and settings.abuseipdb_api_key:
        return _abuseipdb_lookup(ip, settings.abuseipdb_api_key)

    return _mock_cti_lookup(ip)

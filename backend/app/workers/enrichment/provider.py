"""Mock CTI provider used for local development."""
from __future__ import annotations

import hashlib

from app.models.incident import CtiEnrichment


COUNTRIES = ["US", "KR", "NL", "DE", "SG", "JP"]


def mock_cti_lookup(ip: str | None) -> CtiEnrichment:
    if not ip:
        return CtiEnrichment(note="No source IP was available for CTI lookup.")
    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    score = digest[0] % 100
    tags: list[str] = []
    if score >= 70:
        tags.append("high-risk-ip")
    if score >= 40:
        tags.append("scanner")
    return CtiEnrichment(
        abuse_score=score,
        country=COUNTRIES[digest[1] % len(COUNTRIES)],
        tags=tags,
        sources=["mock-cti"],
        note="Deterministic mock CTI result for local MVP development.",
    )

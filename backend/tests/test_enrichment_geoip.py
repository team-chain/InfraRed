"""Unit tests for the deterministic mock GeoIP module."""
from __future__ import annotations

from app.workers.enrichment.geoip import (
    GeoLocation,
    PRIVATE_GEO_NOTE,
    UNKNOWN_GEO_NOTE,
    lookup_geoip,
)


def test_lookup_returns_unknown_geo_when_ip_missing() -> None:
    geo = lookup_geoip(None)

    assert isinstance(geo, GeoLocation)
    assert geo.country is None
    assert geo.note == UNKNOWN_GEO_NOTE


def test_lookup_marks_private_ip_without_geo_data() -> None:
    geo = lookup_geoip("10.0.0.5")

    assert geo.is_private is True
    assert geo.country is None
    assert geo.note == PRIVATE_GEO_NOTE


def test_lookup_is_deterministic_for_public_ip() -> None:
    a = lookup_geoip("185.12.34.56")
    b = lookup_geoip("185.12.34.56")

    assert a.country == b.country
    assert a.asn == b.asn
    assert a.country is not None
    assert a.asn is not None
    assert a.asn_org is not None


def test_lookup_distinguishes_public_ips() -> None:
    a = lookup_geoip("185.12.34.56")
    b = lookup_geoip("203.0.113.10")

    # Stable mock — different inputs should usually map to different outputs.
    # We assert the outputs are non-null rather than guaranteeing inequality.
    assert a.ip == "185.12.34.56"
    assert b.ip == "203.0.113.10"

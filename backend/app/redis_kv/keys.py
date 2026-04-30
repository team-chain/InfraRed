"""Redis key naming helpers."""
from __future__ import annotations

import hashlib


def _ns(tenant_id: str) -> str:
    return f"tenant:{tenant_id}"


def event_dedup(tenant_id: str, event_id: str) -> str:
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    return f"{_ns(tenant_id)}:event:dedup:{digest}"


def auth_fail_ip(tenant_id: str, asset_id: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:fail:ip:{asset_id}:{ip}"


def auth_fail_user_ip(tenant_id: str, asset_id: str, username: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:fail:user_ip:{asset_id}:{username}:{ip}"


def auth_invalid_user(tenant_id: str, asset_id: str, ip: str) -> str:
    return f"{_ns(tenant_id)}:auth:invalid:{asset_id}:{ip}"


def auth_known_ip(tenant_id: str, asset_id: str, username: str) -> str:
    return f"{_ns(tenant_id)}:auth:known_ip:{asset_id}:{username}"


def killchain_stage(tenant_id: str, asset_id: str, source_ip: str) -> str:
    return f"{_ns(tenant_id)}:killchain:{asset_id}:{source_ip}"


def cti_ip(ip: str) -> str:
    return f"cti:ip:{ip}"


def incident_dedup(
    tenant_id: str,
    rule_id: str,
    asset_id: str,
    ip: str,
    username: str,
) -> str:
    return f"{_ns(tenant_id)}:incident:dedup:{rule_id}:{asset_id}:{ip}:{username}"


def llm_cache(rule_id: str, severity: str, signal_type: str) -> str:
    return f"llm:cache:{rule_id}:{severity}:{signal_type}"

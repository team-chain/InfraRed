"""Runtime detection-rule settings."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import get_settings
from app.redis_kv import keys


@dataclass(frozen=True)
class RuleSettings:
    auth_brute_force_threshold: int
    auth_brute_force_window_seconds: int
    auth_invalid_user_threshold: int
    auth_invalid_user_window_seconds: int
    auth_fail_then_success_threshold: int
    auth_fail_then_success_window_seconds: int
    web_admin_scan_threshold: int
    web_admin_scan_window_seconds: int
    web_404_threshold: int
    web_404_window_seconds: int
    off_hours_enabled: bool
    off_hours_start_kst: int
    off_hours_end_kst: int
    foreign_login_enabled: bool
    allowed_countries: str
    web_sql_injection_enabled: bool
    web_path_traversal_enabled: bool
    web_cve_probe_enabled: bool
    # NET-001: HTTP Flood (설계서 3.1)
    net_http_flood_enabled: bool
    net_http_flood_threshold: int
    net_http_flood_window_seconds: int


def _int_value(raw: dict[str, Any], key: str, fallback: int) -> int:
    value = raw.get(key)
    if value is None:
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _bool_value(raw: dict[str, Any], key: str, fallback: bool) -> bool:
    value = raw.get(key)
    if value is None:
        return fallback
    if isinstance(value, bytes):
        value = value.decode()
    return str(value).lower() in ("1", "true", "yes")


def _str_value(raw: dict[str, Any], key: str, fallback: str) -> str:
    value = raw.get(key)
    if value is None:
        return fallback
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


async def get_rule_settings(redis: Any, tenant_id: str) -> RuleSettings:
    cfg = get_settings()
    try:
        raw = await redis.hgetall(keys.tenant_settings(tenant_id))
    except Exception:
        raw = {}

    return RuleSettings(
        auth_brute_force_threshold=_int_value(raw, "auth_brute_force_threshold", cfg.auth_brute_force_threshold),
        auth_brute_force_window_seconds=_int_value(raw, "auth_brute_force_window_sec", cfg.auth_brute_force_window_seconds),
        auth_invalid_user_threshold=_int_value(raw, "auth_invalid_user_threshold", cfg.auth_invalid_user_threshold),
        auth_invalid_user_window_seconds=cfg.auth_invalid_user_window_seconds,
        auth_fail_then_success_threshold=_int_value(raw, "auth_fail_then_success_threshold", cfg.auth_fail_then_success_threshold),
        auth_fail_then_success_window_seconds=cfg.auth_fail_then_success_window_seconds,
        web_admin_scan_threshold=_int_value(raw, "web_admin_scan_threshold", cfg.web_admin_scan_threshold),
        web_admin_scan_window_seconds=cfg.web_admin_scan_window_seconds,
        web_404_threshold=_int_value(raw, "web_404_threshold", cfg.web_404_threshold),
        web_404_window_seconds=cfg.web_404_window_seconds,
        off_hours_enabled=_bool_value(raw, "off_hours_enabled", True),
        off_hours_start_kst=_int_value(raw, "off_hours_start_kst", 0),
        off_hours_end_kst=_int_value(raw, "off_hours_end_kst", 6),
        foreign_login_enabled=_bool_value(raw, "foreign_login_enabled", False),
        allowed_countries=_str_value(raw, "allowed_countries", "KR"),
        web_sql_injection_enabled=_bool_value(raw, "web_sql_injection_enabled", True),
        web_path_traversal_enabled=_bool_value(raw, "web_path_traversal_enabled", True),
        web_cve_probe_enabled=_bool_value(raw, "web_cve_probe_enabled", True),
        net_http_flood_enabled=_bool_value(raw, "net_http_flood_enabled", True),
        net_http_flood_threshold=_int_value(raw, "net_http_flood_threshold", 300),
        net_http_flood_window_seconds=_int_value(raw, "net_http_flood_window_seconds", 300),
    )

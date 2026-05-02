"""Unit tests for WEB-001..004 rule engine (nginx access.log events).

WEB-001  Web Shell Access      /uploads/*.php|*.jsp + HTTP 200
WEB-002  Admin Path Scan       /admin|/login 30+ hits / 5 min from same IP
WEB-003  Automation Tool       curl/python-requests/wget UA on non-static path
WEB-004  404 Burst             50+ 404 responses / 5 min from same IP
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.common.constants import EventType, RuleId
from app.models.envelope import NormalizedEvent
from app.workers.detection.web_rules import evaluate_web_rules


def _web_event(
    *,
    event_id: str = "web-001",
    source_ip: str = "185.12.34.56",
    path: str = "/index.html",
    method: str = "GET",
    status_code: int = 200,
    user_agent: str = "Mozilla/5.0",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        tenant_id="company-a",
        asset_id="asset-001",
        agent_id="agent-001",
        event_type=EventType.WEB_REQUEST,
        timestamp=timestamp or datetime(2026, 4, 30, 3, 12, 0, tzinfo=timezone.utc),
        host="web-01",
        source_ip=source_ip,
        request_path=path,
        request_method=method,
        status_code=status_code,
        user_agent=user_agent,
    )


# ── WEB-001: Web Shell Access ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_web001_fires_for_php_shell_200(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/uploads/shell.php", status_code=200),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_SHELL_ACCESS in rule_ids


@pytest.mark.asyncio
async def test_web001_fires_for_jsp_shell_200(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/files/backdoor.jsp", status_code=200),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_SHELL_ACCESS in rule_ids


@pytest.mark.asyncio
async def test_web001_does_not_fire_for_404(fake_redis) -> None:
    """Web shell path but non-200 status should NOT trigger WEB-001."""
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/uploads/shell.php", status_code=404),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_SHELL_ACCESS not in rule_ids


@pytest.mark.asyncio
async def test_web001_does_not_fire_for_normal_php(fake_redis) -> None:
    """Normal PHP path outside upload dirs should NOT trigger WEB-001."""
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/index.php", status_code=200),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_SHELL_ACCESS not in rule_ids


# ── WEB-002: Admin Path Scan ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_web002_fires_after_threshold_admin_hits(fake_redis) -> None:
    """30+ admin path hits from one IP within 5 min should trigger WEB-002."""
    from app.config import get_settings
    threshold = get_settings().web_admin_scan_threshold  # 30

    seen_rule = False
    for i in range(threshold):
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"adm-{i}", path="/admin", status_code=200),
        )
        if any(s.rule_id == RuleId.WEB_ADMIN_SCAN for s in signals):
            seen_rule = True

    assert seen_rule, "WEB-002 should fire at or after threshold admin hits"


@pytest.mark.asyncio
async def test_web002_does_not_fire_below_threshold(fake_redis) -> None:
    """Fewer than 30 admin hits should NOT trigger WEB-002."""
    for i in range(5):
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"adm-{i}", path="/login", status_code=200),
        )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_ADMIN_SCAN not in rule_ids


@pytest.mark.asyncio
async def test_web002_different_ips_not_aggregated(fake_redis) -> None:
    """Admin hits from different IPs should not cross-accumulate for WEB-002."""
    from app.config import get_settings
    threshold = get_settings().web_admin_scan_threshold

    for i in range(threshold - 1):
        ip = f"10.0.0.{i % 254 + 1}"
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"adm-{i}", path="/admin", source_ip=ip),
        )
        rule_ids = {s.rule_id for s in signals}
        assert RuleId.WEB_ADMIN_SCAN not in rule_ids, f"WEB-002 should not fire for IP {ip}"


@pytest.mark.asyncio
async def test_web002_triggering_event_ids_captured(fake_redis) -> None:
    """WEB-002 signal should include triggering event IDs."""
    from app.config import get_settings
    threshold = get_settings().web_admin_scan_threshold

    last_signals = []
    for i in range(threshold):
        last_signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"adm-{i}", path="/wp-admin"),
        )

    web002 = next((s for s in last_signals if s.rule_id == RuleId.WEB_ADMIN_SCAN), None)
    assert web002 is not None
    assert len(web002.triggering_event_ids) >= threshold


# ── WEB-003: Automation Tool Access ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_web003_fires_for_curl_ua(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/api/users", user_agent="curl/7.68.0"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_AUTOMATION in rule_ids


@pytest.mark.asyncio
async def test_web003_fires_for_sqlmap_ua(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/login", user_agent="sqlmap/1.7"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_AUTOMATION in rule_ids


@pytest.mark.asyncio
async def test_web003_fires_for_nikto_ua(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/etc/passwd", user_agent="Nikto/2.1.6"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_AUTOMATION in rule_ids


@pytest.mark.asyncio
async def test_web003_does_not_fire_for_normal_browser(fake_redis) -> None:
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/api/users", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_AUTOMATION not in rule_ids


@pytest.mark.asyncio
async def test_web003_does_not_fire_on_static_path(fake_redis) -> None:
    """Automation UA on a static asset path (e.g. /static/...) should NOT fire."""
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(path="/static/app.js", user_agent="curl/7.68.0"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_AUTOMATION not in rule_ids


# ── WEB-004: 404 Burst ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_web004_fires_after_threshold_404s(fake_redis) -> None:
    """50+ 404 responses from one IP within 5 min should trigger WEB-004."""
    from app.config import get_settings
    threshold = get_settings().web_404_threshold  # 50

    seen_rule = False
    for i in range(threshold):
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"n-{i}", path=f"/not-found-{i}", status_code=404),
        )
        if any(s.rule_id == RuleId.WEB_404_BURST for s in signals):
            seen_rule = True

    assert seen_rule, "WEB-004 should fire at or after threshold 404 hits"


@pytest.mark.asyncio
async def test_web004_does_not_fire_below_threshold(fake_redis) -> None:
    """Fewer than 50 404 responses should NOT trigger WEB-004."""
    for i in range(10):
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"n-{i}", path=f"/nope-{i}", status_code=404),
        )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_404_BURST not in rule_ids


@pytest.mark.asyncio
async def test_web004_does_not_fire_for_200(fake_redis) -> None:
    """200 responses should not count toward WEB-004."""
    from app.config import get_settings
    threshold = get_settings().web_404_threshold

    for i in range(threshold):
        signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"ok-{i}", path=f"/page-{i}", status_code=200),
        )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.WEB_404_BURST not in rule_ids


@pytest.mark.asyncio
async def test_web004_triggering_event_ids_captured(fake_redis) -> None:
    """WEB-004 signal should include triggering event IDs."""
    from app.config import get_settings
    threshold = get_settings().web_404_threshold

    last_signals = []
    for i in range(threshold):
        last_signals = await evaluate_web_rules(
            fake_redis,
            _web_event(event_id=f"n-{i}", path=f"/missing-{i}", status_code=404),
        )

    web004 = next((s for s in last_signals if s.rule_id == RuleId.WEB_404_BURST), None)
    assert web004 is not None
    assert len(web004.triggering_event_ids) >= threshold


# ── Edge cases ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_signals_when_source_ip_missing(fake_redis) -> None:
    """Events with no source_ip should produce no signals."""
    signals = await evaluate_web_rules(
        fake_redis,
        _web_event(source_ip=None),
    )
    assert signals == []


@pytest.mark.asyncio
async def test_no_signals_when_request_path_missing(fake_redis) -> None:
    """Events with no request_path should produce no signals."""
    event = NormalizedEvent(
        event_id="web-edge",
        tenant_id="company-a",
        asset_id="asset-001",
        agent_id="agent-001",
        event_type=EventType.WEB_REQUEST,
        timestamp=datetime(2026, 4, 30, 3, 12, 0, tzinfo=timezone.utc),
        host="web-01",
        source_ip="1.2.3.4",
        request_path=None,
        status_code=200,
    )
    signals = await evaluate_web_rules(fake_redis, event)
    assert signals == []

"""Unit tests for the AUTH-001..005 rule engine.

AUTH-004 escalation coverage (design doc 6.2):
  - failure_count < threshold        -> signal only  (escalate_to_incident=False)
  - failure_count >= threshold
      + privileged account           -> escalate
      + unknown IP                   -> escalate
      + preceding AUTH-001 marker    -> escalate
      + preceding AUTH-003 marker    -> escalate
      + none of the above            -> signal only
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.common.constants import EventType, RuleId
from app.models.envelope import NormalizedEvent
from app.workers.detection.rules import (
    PRIVILEGED_ACCOUNTS,
    _prior_signal_key,
    evaluate_rules,
)


def _event(
    *,
    event_id: str = "evt-001",
    event_type: EventType = EventType.SSH_LOGIN_FAILED,
    username: str | None = "root",
    source_ip: str | None = "185.12.34.56",
    result: str | None = "failed",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        tenant_id="company-a",
        asset_id="asset-001",
        agent_id="agent-001",
        event_type=event_type,
        timestamp=timestamp or datetime(2026, 4, 30, 3, 12, 0, tzinfo=timezone.utc),
        host="web-01",
        username=username,
        source_ip=source_ip,
        result=result,
    )


@pytest.mark.asyncio
async def test_brute_force_fires_after_three_failures(fake_redis) -> None:
    seen_rules: set[RuleId] = set()
    brute_force_signal = None
    for i in range(3):
        signals = await evaluate_rules(
            fake_redis,
            _event(event_id=f"evt-{i}", username=f"user{i}"),
        )
        seen_rules.update(s.rule_id for s in signals)
        brute_force_signal = next(
            (s for s in signals if s.rule_id == RuleId.AUTH_BRUTE_FORCE),
            brute_force_signal,
        )

    assert RuleId.AUTH_BRUTE_FORCE in seen_rules
    assert brute_force_signal is not None
    assert brute_force_signal.triggering_event_ids == ["evt-0", "evt-1", "evt-2"]


@pytest.mark.asyncio
async def test_root_login_always_fires(fake_redis) -> None:
    signals = await evaluate_rules(
        fake_redis,
        _event(event_type=EventType.SSH_LOGIN_SUCCESS, username="root", result="success"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_ROOT_LOGIN in rule_ids


@pytest.mark.asyncio
async def test_invalid_user_fires_after_two_probes(fake_redis) -> None:
    seen_rules: set[RuleId] = set()
    for i in range(2):
        signals = await evaluate_rules(
            fake_redis,
            _event(event_id=f"evt-{i}", event_type=EventType.SSH_INVALID_USER,
                   username=f"probe{i}", result="failed"),
        )
        seen_rules.update(s.rule_id for s in signals)
    assert RuleId.AUTH_INVALID_USER in seen_rules


@pytest.mark.asyncio
async def test_failed_then_success_fires_when_failure_precedes_success(fake_redis) -> None:
    for i in range(2):
        await evaluate_rules(fake_redis, _event(event_id=f"fail-{i}", username="admin", result="failed"))
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="ok-1", event_type=EventType.SSH_LOGIN_SUCCESS, username="admin", result="success"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_FAILED_THEN_SUCCESS in rule_ids
    signal = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert signal.triggering_event_ids == ["fail-0", "fail-1", "ok-1"]


@pytest.mark.asyncio
async def test_suspicious_login_fires_for_new_ip(fake_redis) -> None:
    await evaluate_rules(
        fake_redis,
        _event(event_id="known-1", event_type=EventType.SSH_LOGIN_SUCCESS,
               username="alice", source_ip="10.0.0.10", result="success"),
    )
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="new-1", event_type=EventType.SSH_LOGIN_SUCCESS,
               username="alice", source_ip="203.0.113.5", result="success"),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_SUSPICIOUS_LOGIN in rule_ids


@pytest.mark.asyncio
async def test_no_signals_when_source_ip_missing(fake_redis) -> None:
    signals = await evaluate_rules(fake_redis, _event(source_ip=None))
    assert signals == []


# ── AUTH-004 escalation tests (design doc 6.2) ───────────────────────────────

async def _send_failures(redis, count, username, source_ip):
    for i in range(count):
        await evaluate_rules(
            redis,
            _event(event_id=f"fail-{i}", username=username, source_ip=source_ip, result="failed"),
        )


@pytest.mark.asyncio
async def test_auth004_signal_always_created_even_below_threshold(fake_redis) -> None:
    """Signal is created even when failure count is below threshold."""
    await _send_failures(fake_redis, 2, "alice", "1.2.3.4")
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="ok-1", event_type=EventType.SSH_LOGIN_SUCCESS,
               username="alice", source_ip="1.2.3.4", result="success"),
    )
    auth004 = next((s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS), None)
    assert auth004 is not None, "AUTH-004 signal should be created"
    assert auth004.escalate_to_incident is False, "Below threshold should not escalate"


@pytest.mark.asyncio
async def test_auth004_escalates_privileged_account(fake_redis) -> None:
    """failure_count >= threshold + privileged account -> escalate."""
    assert "root" in PRIVILEGED_ACCOUNTS
    await _send_failures(fake_redis, 3, "root", "5.6.7.8")
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="ok-root", event_type=EventType.SSH_LOGIN_SUCCESS,
               username="root", result="success", source_ip="5.6.7.8"),
    )
    auth004 = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert auth004.escalate_to_incident is True
    assert "privileged account" in (auth004.notes or "")


@pytest.mark.asyncio
async def test_auth004_escalates_unknown_ip(fake_redis) -> None:
    """failure_count >= threshold + unknown IP -> escalate."""
    await _send_failures(fake_redis, 3, "bob", "9.9.9.9")
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="ok-bob", event_type=EventType.SSH_LOGIN_SUCCESS,
               username="bob", result="success", source_ip="9.9.9.9"),
    )
    auth004 = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert auth004.escalate_to_incident is True
    assert "known_ips" in (auth004.notes or "")


@pytest.mark.asyncio
async def test_auth004_escalates_preceded_by_brute_force(fake_redis) -> None:
    """Preceding AUTH-001 marker + failure_count >= threshold -> escalate."""
    from app.redis_kv import keys as rkeys
    tenant_id = "company-a"
    asset_id = "asset-001"
    attacker_ip = "11.22.33.44"
    username = "charlie"

    await fake_redis.set(
        _prior_signal_key(tenant_id, asset_id, attacker_ip, RuleId.AUTH_BRUTE_FORCE),
        "1", ex=3600,
    )
    known_key = rkeys.auth_known_ip(tenant_id, asset_id, username)
    await fake_redis.sadd(known_key, attacker_ip)

    for i in range(3):
        await evaluate_rules(
            fake_redis,
            _event(event_id=f"bf-fail-{i}", username=username, source_ip=attacker_ip, result="failed"),
        )

    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="bf-ok", event_type=EventType.SSH_LOGIN_SUCCESS,
               username=username, source_ip=attacker_ip, result="success"),
    )
    auth004 = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert auth004.escalate_to_incident is True
    assert "AUTH-001" in (auth004.notes or "")


@pytest.mark.asyncio
async def test_auth004_no_escalation_when_conditions_not_met(fake_redis) -> None:
    """failure_count >= threshold but no conditions met -> no escalation."""
    from app.redis_kv import keys as rkeys
    tenant_id = "company-a"
    asset_id = "asset-001"
    source_ip = "192.168.1.50"
    username = "dave"

    known_key = rkeys.auth_known_ip(tenant_id, asset_id, username)
    await fake_redis.sadd(known_key, source_ip)

    await _send_failures(fake_redis, 3, username, source_ip)
    # 3 failures also triggers AUTH-001 which sets a prior_signal marker;
    # clear it so this test can isolate the "no conditions met" path.
    await fake_redis.delete(_prior_signal_key("company-a", "asset-001", source_ip, RuleId.AUTH_BRUTE_FORCE))
    await fake_redis.delete(_prior_signal_key("company-a", "asset-001", source_ip, RuleId.AUTH_INVALID_USER))
    signals = await evaluate_rules(
        fake_redis,
        _event(event_id="ok-dave", event_type=EventType.SSH_LOGIN_SUCCESS,
               username=username, source_ip=source_ip, result="success"),
    )
    auth004 = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert auth004.escalate_to_incident is False


@pytest.mark.asyncio
async def test_prior_signal_marker_set_after_brute_force(fake_redis) -> None:
    """AUTH-001 signal sets the prior-signal Redis marker."""
    for i in range(3):
        await evaluate_rules(
            fake_redis,
            _event(event_id=f"m-{i}", username=f"u{i}", source_ip="77.88.99.10"),
        )
    marker = await fake_redis.get(
        _prior_signal_key("company-a", "asset-001", "77.88.99.10", RuleId.AUTH_BRUTE_FORCE)
    )
    assert marker == "1"


@pytest.mark.asyncio
async def test_prior_signal_marker_set_after_invalid_user(fake_redis) -> None:
    """AUTH-003 signal sets the prior-signal Redis marker."""
    for i in range(2):
        await evaluate_rules(
            fake_redis,
            _event(event_id=f"inv-{i}", event_type=EventType.SSH_INVALID_USER,
                   source_ip="55.66.77.88", username=f"probe{i}", result="failed"),
        )
    marker = await fake_redis.get(
        _prior_signal_key("company-a", "asset-001", "55.66.77.88", RuleId.AUTH_INVALID_USER)
    )
    assert marker == "1"

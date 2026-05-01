"""Unit tests for the AUTH-001..005 rule engine."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.common.constants import EventType, RuleId
from app.models.envelope import NormalizedEvent
from app.workers.detection.rules import evaluate_rules


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
        _event(
            event_type=EventType.SSH_LOGIN_SUCCESS,
            username="root",
            result="success",
        ),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_ROOT_LOGIN in rule_ids


@pytest.mark.asyncio
async def test_invalid_user_fires_after_two_probes(fake_redis) -> None:
    seen_rules: set[RuleId] = set()
    for i in range(2):
        signals = await evaluate_rules(
            fake_redis,
            _event(
                event_id=f"evt-{i}",
                event_type=EventType.SSH_INVALID_USER,
                username=f"probe{i}",
                result="failed",
            ),
        )
        seen_rules.update(s.rule_id for s in signals)

    assert RuleId.AUTH_INVALID_USER in seen_rules


@pytest.mark.asyncio
async def test_failed_then_success_fires_when_failure_precedes_success(fake_redis) -> None:
    # Two failures from same user/IP first.
    for i in range(2):
        await evaluate_rules(
            fake_redis,
            _event(event_id=f"fail-{i}", username="admin", result="failed"),
        )

    # Then a success from same user/IP.
    signals = await evaluate_rules(
        fake_redis,
        _event(
            event_id="ok-1",
            event_type=EventType.SSH_LOGIN_SUCCESS,
            username="admin",
            result="success",
        ),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_FAILED_THEN_SUCCESS in rule_ids
    signal = next(s for s in signals if s.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS)
    assert signal.triggering_event_ids == ["fail-0", "fail-1", "ok-1"]


@pytest.mark.asyncio
async def test_suspicious_login_fires_for_new_ip(fake_redis) -> None:
    # First login from one IP — primes the "known IP" set.
    await evaluate_rules(
        fake_redis,
        _event(
            event_id="known-1",
            event_type=EventType.SSH_LOGIN_SUCCESS,
            username="alice",
            source_ip="10.0.0.10",
            result="success",
        ),
    )
    # Second login from a *different* IP for the same user.
    signals = await evaluate_rules(
        fake_redis,
        _event(
            event_id="new-1",
            event_type=EventType.SSH_LOGIN_SUCCESS,
            username="alice",
            source_ip="203.0.113.5",
            result="success",
        ),
    )
    rule_ids = {s.rule_id for s in signals}
    assert RuleId.AUTH_SUSPICIOUS_LOGIN in rule_ids


@pytest.mark.asyncio
async def test_no_signals_when_source_ip_missing(fake_redis) -> None:
    signals = await evaluate_rules(
        fake_redis,
        _event(source_ip=None),
    )
    assert signals == []

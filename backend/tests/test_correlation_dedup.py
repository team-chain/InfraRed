"""Unit tests for correlation worker — Incident Dedup and escalation gate.

Tests are intentionally DB-free: they mock save_or_merge_incident so the
focus stays on the Redis-based dedup and escalate_to_incident logic.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from app.common.constants import KillChainStage, RuleId
from app.models.incident import CtiEnrichment
from app.models.signal import Signal
from app.workers.correlation.worker import process_enriched


def _signal(
    *,
    rule_id: RuleId = RuleId.AUTH_BRUTE_FORCE,
    source_ip: str = "1.2.3.4",
    username: str = "root",
    escalate: bool = True,
) -> Signal:
    return Signal(
        tenant_id="company-a",
        asset_id="asset-001",
        rule_id=rule_id,
        rule_name="test",
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001",
        kill_chain_stage=KillChainStage.CREDENTIAL_ACCESS,
        source_ip=source_ip,
        username=username,
        detected_count=3,
        detected_at=datetime(2026, 4, 30, 3, 12, 0, tzinfo=timezone.utc),
        triggering_event_ids=["e1"],
        escalate_to_incident=escalate,
    )


def _cti() -> CtiEnrichment:
    return CtiEnrichment(abuse_score=80, country="CN")


@pytest.mark.asyncio
async def test_no_incident_when_escalate_to_incident_false(fake_redis) -> None:
    """escalate_to_incident=False 인 Signal → Incident 생성 없음."""
    sig = _signal(escalate=False)
    cti = _cti()

    with patch("app.workers.correlation.worker.get_redis", return_value=fake_redis), \
         patch("app.workers.correlation.worker.save_or_merge_incident") as mock_save:
        result = await process_enriched(sig.model_dump_json(), cti.model_dump_json())

    mock_save.assert_not_called()
    incident_id, created = result
    assert incident_id is None
    assert created is False


@pytest.mark.asyncio
async def test_incident_dedup_blocks_duplicate(fake_redis) -> None:
    """동일 rule/ip/user 의 두 번째 Signal 은 Dedup 으로 차단된다."""
    sig = _signal(escalate=True)
    cti = _cti()

    mock_save = AsyncMock(return_value=("INC-TEST-001", True))

    with patch("app.workers.correlation.worker.get_redis", return_value=fake_redis), \
         patch("app.workers.correlation.worker.save_or_merge_incident", mock_save):
        # 첫 번째 Signal → Incident 생성
        incident_id1, created1 = await process_enriched(
            sig.model_dump_json(), cti.model_dump_json()
        )
        # 두 번째 Signal (동일 key) → Dedup 으로 skip
        incident_id2, created2 = await process_enriched(
            sig.model_dump_json(), cti.model_dump_json()
        )

    assert incident_id1 == "INC-TEST-001"
    assert created1 is True
    assert incident_id2 is None   # dedup 으로 skip
    assert created2 is False
    assert mock_save.call_count == 1  # DB write 는 1회만


@pytest.mark.asyncio
async def test_different_ips_not_deduped(fake_redis) -> None:
    """서로 다른 source_ip 는 별개 Incident 로 처리된다."""
    sig_a = _signal(source_ip="1.1.1.1", escalate=True)
    sig_b = _signal(source_ip="2.2.2.2", escalate=True)
    cti = _cti()

    mock_save = AsyncMock(side_effect=[
        ("INC-A", True),
        ("INC-B", True),
    ])

    with patch("app.workers.correlation.worker.get_redis", return_value=fake_redis), \
         patch("app.workers.correlation.worker.save_or_merge_incident", mock_save):
        id_a, _ = await process_enriched(sig_a.model_dump_json(), cti.model_dump_json())
        id_b, _ = await process_enriched(sig_b.model_dump_json(), cti.model_dump_json())

    assert id_a == "INC-A"
    assert id_b == "INC-B"
    assert mock_save.call_count == 2

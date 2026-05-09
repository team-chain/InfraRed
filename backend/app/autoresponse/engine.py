"""AI 자동 대응 엔진.

LLM 분석 완료 후 호출되며 response_mode에 따라 분기합니다.

  manual   → Discord 알림만 (기존 동작과 동일)
  approval → pending_actions에 적재 후 대기
  auto     → Agent 명령 큐에 즉시 전송
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text

from app.autoresponse.actions import (
    ActionType,
    build_actions_from_llm,
    should_auto_execute,
    should_queue_approval,
)
from app.db.connection import get_session
from app.models.llm import LLMResult
from app.redis_kv.client import get_redis


log = logging.getLogger(__name__)


async def _get_tenant_settings(tenant_id: str) -> dict:
    async with get_session() as session:
        row = await session.execute(
            text("SELECT response_mode, auto_block_min_severity FROM tenant_settings WHERE tenant_id = :t"),
            {"t": tenant_id},
        )
        record = row.mappings().first()
    if record:
        return dict(record)
    return {"response_mode": "manual", "auto_block_min_severity": "critical"}


async def _save_pending_action(
    tenant_id: str,
    incident_id: str,
    action: dict,
) -> str:
    async with get_session() as session:
        row = await session.execute(
            text("""
                INSERT INTO pending_actions
                  (tenant_id, incident_id, action_type, target, payload, status)
                VALUES (:tenant_id, :incident_id, :action_type, :target, :payload::jsonb, 'pending')
                RETURNING action_id::text
            """),
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "action_type": action["action_type"],
                "target": action["target"],
                "payload": __import__("json").dumps(action["payload"]),
            },
        )
        await session.commit()
        return row.scalar()


async def _push_agent_command(tenant_id: str, asset_id: str, action: dict) -> None:
    """Redis List에 Agent 명령을 push."""
    import json
    redis = get_redis()
    command = {
        "action_type": action["action_type"],
        "target": action["target"],
        "payload": action["payload"],
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    key = f"tenant:{tenant_id}:commands:{asset_id}"
    await redis.lpush(key, json.dumps(command))
    await redis.expire(key, 3600)
    log.info("agent_command_pushed tenant=%s asset=%s action=%s", tenant_id, asset_id, action["action_type"])


async def run_autoresponse(
    tenant_id: str,
    asset_id: str,
    incident_id: str,
    severity: str,
    result: LLMResult,
    source_ip: str | None = None,
    username: str | None = None,
) -> dict:
    settings = await _get_tenant_settings(tenant_id)
    mode = settings["response_mode"]
    min_sev = settings["auto_block_min_severity"]

    actions = build_actions_from_llm(
        incident_id=incident_id,
        source_ip=source_ip,
        username=username,
        severity=severity,
        recommended_actions=result.recommended_actions,
    )

    summary = {"mode": mode, "actions_taken": [], "actions_queued": [], "actions_notified": []}

    for action in actions:
        atype = action["action_type"]

        if atype == ActionType.NOTIFY:
            summary["actions_notified"].append(atype)
            continue

        if should_auto_execute(mode, severity, min_sev):
            await _push_agent_command(tenant_id, asset_id, action)
            summary["actions_taken"].append({"type": atype, "target": action["target"]})
            log.info("autoresponse_executed tenant=%s incident=%s action=%s", tenant_id, incident_id, atype)

        elif should_queue_approval(mode, severity, min_sev):
            action_id = await _save_pending_action(tenant_id, incident_id, action)
            summary["actions_queued"].append({"type": atype, "target": action["target"], "action_id": action_id})
            log.info("autoresponse_queued tenant=%s incident=%s action=%s", tenant_id, incident_id, atype)

        else:
            summary["actions_notified"].append(atype)

    return summary

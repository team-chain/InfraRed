"""Agent 역방향 명령 채널 API.

Agent가 5초마다 polling:
  GET /commands?asset_id=asset-001   →  명령 목록 반환
  POST /commands/result              →  실행 결과 보고 (pending_actions에 저장)

관리자 승인/거부:
  GET  /actions/pending              →  승인 대기 목록
  POST /actions/{action_id}/approve  →  승인 → Agent 큐에 push
  POST /actions/{action_id}/reject   →  거부
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import require_permission, verify_agent_token
from app.redis_kv.client import get_redis


router = APIRouter()
log = logging.getLogger(__name__)


# ── Agent polling ──────────────────────────────────────────────────────────── #

@router.get("/commands")
async def poll_commands(
    asset_id: str,
    claims: dict = Depends(verify_agent_token),
) -> dict:
    tenant_id = claims["tenant_id"]
    redis = get_redis()
    key = f"tenant:{tenant_id}:commands:{asset_id}"

    commands = []
    while True:
        raw = await redis.rpop(key)
        if not raw:
            break
        try:
            commands.append(json.loads(raw))
        except Exception:
            continue

    return {"commands": commands}


class CommandResult(BaseModel):
    action_type: str
    target: str
    success: bool
    message: str | None = None
    executed_at: datetime | None = None


@router.post("/commands/result", status_code=202)
async def report_command_result(
    result: CommandResult,
    claims: dict = Depends(verify_agent_token),
) -> dict:
    tenant_id = claims["tenant_id"]
    executed_at = result.executed_at or datetime.now(timezone.utc)

    log.info(
        "command_result_received tenant=%s action=%s target=%s success=%s",
        tenant_id, result.action_type, result.target, result.success,
    )

    # pending_actions 테이블에 결과 업데이트 (target + action_type 기준 최신 레코드)
    try:
        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE pending_actions
                    SET result = CAST(:result AS JSONB),
                        status = CASE WHEN :success THEN 'executed' ELSE 'failed' END,
                        resolved_at = :executed_at
                    WHERE action_id = (
                        SELECT action_id FROM pending_actions
                        WHERE tenant_id = :tenant_id
                          AND action_type = :action_type
                          AND target = :target
                          AND status IN ('approved', 'pending')
                        ORDER BY created_at DESC
                        LIMIT 1
                    )
                """),
                {
                    "result": json.dumps({
                        "success": result.success,
                        "message": result.message,
                        "executed_at": executed_at.isoformat(),
                    }),
                    "success": result.success,
                    "executed_at": executed_at,
                    "tenant_id": tenant_id,
                    "action_type": result.action_type,
                    "target": result.target,
                },
            )
            await session.commit()
    except Exception as exc:
        log.warning("command_result_persist_failed: %s", exc)

    return {"accepted": True}


# ── 관리자 승인/거부 ──────────────────────────────────────────────────────── #

@router.get("/actions/pending")
async def list_pending_actions(
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        rows = await session.execute(
            text("""
                SELECT action_id::text, incident_id, action_type, target,
                       payload, status, created_at
                FROM pending_actions
                WHERE tenant_id = :t AND status = 'pending'
                ORDER BY created_at DESC
                LIMIT 100
            """),
            {"t": tenant_id},
        )
        items = [dict(r) for r in rows.mappings()]
    return {"items": items}


@router.post("/actions/{action_id}/approve", status_code=202)
async def approve_action(
    action_id: str,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        row = await session.execute(
            text("""
                UPDATE pending_actions
                SET status='approved', resolved_at=NOW(), resolved_by=:actor
                WHERE action_id=:id AND tenant_id=:t AND status='pending'
                RETURNING action_type, target, payload, incident_id
            """),
            {"id": action_id, "t": tenant_id, "actor": str(claims.get("sub", "unknown"))},
        )
        await session.commit()
        record = row.mappings().first()

    if not record:
        raise HTTPException(status_code=404, detail="action_not_found")

    # Asset_id를 incident에서 조회해 Agent 큐에 push
    async with get_session() as session:
        inc = await session.execute(
            text("SELECT asset_id FROM incidents WHERE incident_id=:id"),
            {"id": record["incident_id"]},
        )
        asset_row = inc.mappings().first()

    if asset_row:
        redis = get_redis()
        command = {
            "action_type": record["action_type"],
            "target": record["target"],
            "payload": record["payload"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        key = f"tenant:{tenant_id}:commands:{asset_row['asset_id']}"
        await redis.lpush(key, json.dumps(command))
        await redis.expire(key, 3600)

    log.info("action_approved tenant=%s action_id=%s", tenant_id, action_id)
    return {"approved": True, "action_id": action_id}


@router.post("/actions/{action_id}/reject", status_code=202)
async def reject_action(
    action_id: str,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        row = await session.execute(
            text("""
                UPDATE pending_actions
                SET status='rejected', resolved_at=NOW(), resolved_by=:actor
                WHERE action_id=:id AND tenant_id=:t AND status='pending'
                RETURNING action_id
            """),
            {"id": action_id, "t": tenant_id, "actor": str(claims.get("sub", "unknown"))},
        )
        await session.commit()
        if not row.mappings().first():
            raise HTTPException(status_code=404, detail="action_not_found")

    log.info("action_rejected tenant=%s action_id=%s", tenant_id, action_id)
    return {"rejected": True, "action_id": action_id}

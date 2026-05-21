"""Agent 역방향 명령 채널 API.

Agent가 5초마다 polling:
  GET /commands?asset_id=asset-001   →  명령 목록 반환
  POST /commands/result              →  실행 결과 보고 (pending_actions에 저장)

관리자 승인/거부:
  GET  /actions/pending              →  승인 대기 목록
  POST /actions/{action_id}/approve  →  승인 → Agent 큐에 push
  POST /actions/{action_id}/reject   →  거부

v7.0: nonce 기반 명령 보안 계약
  - 명령 발행 시 nonce + timestamp + HMAC 서명 추가
  - Redis에 nonce 저장 (TTL=300초), 재사용 시 거부 (Replay Attack 방어)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.security import require_permission, verify_agent_token
from app.redis_kv.client import get_redis

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# v7.0: nonce 기반 명령 보안 계약
# ---------------------------------------------------------------------------

def generate_command_nonce() -> str:
    """암호학적으로 안전한 16바이트 hex nonce 생성."""
    return secrets.token_hex(16)


def sign_command(command: dict, secret_key: str) -> dict:
    """명령에 nonce + timestamp + HMAC-SHA256 서명 추가.

    payload = "{action_type}:{target}:{nonce}:{timestamp}"
    signature = HMAC-SHA256(secret_key, payload)
    """
    nonce = generate_command_nonce()
    timestamp = int(time.time())
    action_type = command.get("action_type", "")
    target = command.get("target", "")
    payload = f"{action_type}:{target}:{nonce}:{timestamp}"
    sig = hmac.new(
        secret_key.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        **command,
        "nonce": nonce,
        "timestamp": timestamp,
        "signature": sig,
    }


async def verify_nonce_not_replayed(redis, nonce: str) -> bool:
    """nonce가 이미 사용됐는지 확인 (Replay Attack 방어).

    Redis SET NX (Not eXists) 를 이용해 nonce를 300초 TTL로 저장.
    처음 사용이면 True, 재사용이면 False 반환.
    """
    key = f"used_nonce:{nonce}"
    result = await redis.set(key, "1", ex=300, nx=True)
    return result is True


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
        settings = get_settings()
        raw_command = {
            "action_type": record["action_type"],
            "target": record["target"],
            "payload": record["payload"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        # v7.0: nonce + timestamp + HMAC 서명 추가
        command = sign_command(raw_command, settings.jwt_secret)
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

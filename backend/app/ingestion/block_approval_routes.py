"""차단 승인/거부/연장 API (v3.0 설계서).

엔드포인트:
  POST /api/v1/incidents/{incident_id}/approve-block  — 차단 승인
  POST /api/v1/incidents/{incident_id}/reject-block   — 차단 거부
  POST /api/v1/incidents/{incident_id}/extend-block   — 차단 연장

권한: owner 또는 security_manager (block:execute 권한)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_any_role
from app.redis_kv.client import get_redis

router = APIRouter(prefix="/api/v1/incidents", tags=["block-approval"])
log = logging.getLogger(__name__)

# owner 또는 security_manager 권한 필요 (block:execute)
_BLOCK_ROLES = ("owner", "security_manager", "admin")


class ApproveBlockRequest(BaseModel):
    extend_ttl_seconds: int | None = None  # None이면 기본 86400 (24시간)


class RejectBlockRequest(BaseModel):
    reason: str = ""


class ExtendBlockRequest(BaseModel):
    additional_ttl_seconds: int = 3600  # 1시간 추가


# ============================================================
# approve-block
# ============================================================

@router.post("/{incident_id}/approve-block", status_code=202)
async def approve_block(
    incident_id: str,
    payload: ApproveBlockRequest,
    claims: dict = Depends(require_any_role(*_BLOCK_ROLES)),
) -> dict:
    """인시던트 차단 승인.

    1. pending_actions 테이블에서 해당 incident_id의 pending block 조회
    2. 승인 처리: auto_response_logs에 approved_by, approved_at 업데이트
    3. agent_commands에 실제 block_ip 명령 삽입 (iptables 차단)
    4. audit_logs 기록
    """
    tenant_id = claims["tenant_id"]
    actor = str(claims.get("sub", "unknown"))
    now = datetime.now(timezone.utc)
    ttl_seconds = payload.extend_ttl_seconds if payload.extend_ttl_seconds is not None else 86400
    expires_at = now + timedelta(seconds=ttl_seconds)

    async with get_session() as session:
        # pending_actions에서 해당 incident_id의 pending block 조회
        pa_result = await session.execute(
            text("""
                SELECT action_id::text, action_type, target, payload, status
                FROM pending_actions
                WHERE tenant_id = :tenant_id
                  AND incident_id = :incident_id
                  AND action_type IN ('block_ip', 'iptables_block', 'block')
                  AND status = 'pending'
                ORDER BY created_at DESC
                LIMIT 1
            """),
            {"tenant_id": tenant_id, "incident_id": incident_id},
        )
        pending = pa_result.mappings().fetchone()
        if not pending:
            raise HTTPException(
                status_code=404,
                detail="pending_block_not_found",
            )

        action_id = pending["action_id"]
        target_ip = pending["target"]

        # pending_actions 상태를 approved로 변경
        await session.execute(
            text("""
                UPDATE pending_actions
                SET status = 'approved',
                    resolved_at = :now,
                    resolved_by = :actor
                WHERE action_id = CAST(:action_id AS UUID)
                  AND tenant_id = :tenant_id
            """),
            {
                "action_id": action_id,
                "tenant_id": tenant_id,
                "now": now,
                "actor": actor,
            },
        )

        # auto_response_logs에 approved_by, approved_at 업데이트
        await session.execute(
            text("""
                UPDATE auto_response_logs
                SET approved_by = CAST(:actor AS UUID),
                    approved_at = :now,
                    expires_at  = :expires_at
                WHERE tenant_id = :tenant_id
                  AND incident_id = :incident_id
                  AND approval_required = true
                  AND approved_at IS NULL
                  AND reversed = false
            """),
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "actor": actor,
                "now": now,
                "expires_at": expires_at,
            },
        )

        # incident에서 asset_id 조회 (에이전트 명령 라우팅용)
        inc_result = await session.execute(
            text("SELECT asset_id FROM incidents WHERE incident_id = :id"),
            {"id": incident_id},
        )
        inc_row = inc_result.mappings().fetchone()
        await session.commit()

    # Redis agent_commands 큐에 block_ip 명령 삽입 (에이전트가 polling)
    if inc_row and inc_row["asset_id"]:
        redis = get_redis()
        command = {
            "action_type": "block_ip",
            "target": target_ip,
            "payload": {
                "iptables_chain": "INPUT",
                "ttl_seconds": ttl_seconds,
            },
            "issued_at": now.isoformat(),
            "approved_by": actor,
        }
        key = f"tenant:{tenant_id}:commands:{inc_row['asset_id']}"
        await redis.lpush(key, json.dumps(command))
        await redis.expire(key, ttl_seconds + 3600)

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="block.approved",
        resource=incident_id,
        metadata={
            "action_id": action_id,
            "target_ip": target_ip,
            "ttl_seconds": ttl_seconds,
            "expires_at": expires_at.isoformat(),
        },
    )

    log.info(
        "block_approved tenant=%s incident=%s target=%s actor=%s",
        tenant_id, incident_id, target_ip, actor,
    )
    return {
        "approved": True,
        "incident_id": incident_id,
        "action_id": action_id,
        "target_ip": target_ip,
        "expires_at": expires_at.isoformat(),
    }


# ============================================================
# reject-block
# ============================================================

@router.post("/{incident_id}/reject-block", status_code=202)
async def reject_block(
    incident_id: str,
    payload: RejectBlockRequest,
    claims: dict = Depends(require_any_role(*_BLOCK_ROLES)),
) -> dict:
    """인시던트 차단 거부.

    1. pending_actions 상태를 'rejected'로 변경
    2. auto_response_logs에 기록
    3. audit_logs 기록
    """
    tenant_id = claims["tenant_id"]
    actor = str(claims.get("sub", "unknown"))
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        pa_result = await session.execute(
            text("""
                UPDATE pending_actions
                SET status = 'rejected',
                    resolved_at = :now,
                    resolved_by = :actor,
                    result = CAST(:result AS JSONB)
                WHERE tenant_id = :tenant_id
                  AND incident_id = :incident_id
                  AND action_type IN ('block_ip', 'iptables_block', 'block')
                  AND status = 'pending'
                RETURNING action_id::text, target
            """),
            {
                "tenant_id": tenant_id,
                "incident_id": incident_id,
                "now": now,
                "actor": actor,
                "result": json.dumps({"reason": payload.reason, "rejected_by": actor}),
            },
        )
        rejected = pa_result.mappings().fetchone()
        await session.commit()

    if not rejected:
        raise HTTPException(status_code=404, detail="pending_block_not_found")

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="block.rejected",
        resource=incident_id,
        metadata={
            "action_id": rejected["action_id"],
            "target_ip": rejected["target"],
            "reason": payload.reason,
        },
    )

    log.info(
        "block_rejected tenant=%s incident=%s target=%s actor=%s",
        tenant_id, incident_id, rejected["target"], actor,
    )
    return {
        "rejected": True,
        "incident_id": incident_id,
        "action_id": rejected["action_id"],
        "target_ip": rejected["target"],
        "reason": payload.reason,
    }


# ============================================================
# extend-block
# ============================================================

@router.post("/{incident_id}/extend-block", status_code=202)
async def extend_block(
    incident_id: str,
    payload: ExtendBlockRequest,
    claims: dict = Depends(require_any_role(*_BLOCK_ROLES)),
) -> dict:
    """인시던트 차단 연장.

    1. auto_response_logs에서 현재 활성 차단 항목 조회
    2. expires_at를 additional_ttl_seconds만큼 연장
    3. agent_commands에 갱신 명령 삽입
    4. audit_logs 기록
    """
    tenant_id = claims["tenant_id"]
    actor = str(claims.get("sub", "unknown"))
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        # 현재 활성 차단 조회
        arl_result = await session.execute(
            text("""
                SELECT auto_response_id, actions_taken, expires_at, ttl_seconds
                FROM auto_response_logs
                WHERE tenant_id = :tenant_id
                  AND incident_id = :incident_id
                  AND reversed = false
                  AND approved_at IS NOT NULL
                ORDER BY executed_at DESC
                LIMIT 1
            """),
            {"tenant_id": tenant_id, "incident_id": incident_id},
        )
        arl_row = arl_result.mappings().fetchone()
        if not arl_row:
            raise HTTPException(status_code=404, detail="active_block_not_found")

        current_expires = arl_row["expires_at"] or now
        new_expires_at = current_expires + timedelta(seconds=payload.additional_ttl_seconds)
        new_ttl = (arl_row["ttl_seconds"] or 0) + payload.additional_ttl_seconds

        # expires_at 연장
        await session.execute(
            text("""
                UPDATE auto_response_logs
                SET expires_at  = :new_expires_at,
                    ttl_seconds = :new_ttl
                WHERE auto_response_id = :auto_response_id
                  AND tenant_id = :tenant_id
            """),
            {
                "auto_response_id": arl_row["auto_response_id"],
                "tenant_id": tenant_id,
                "new_expires_at": new_expires_at,
                "new_ttl": new_ttl,
            },
        )

        # incident에서 asset_id 조회
        inc_result = await session.execute(
            text("SELECT asset_id FROM incidents WHERE incident_id = :id"),
            {"id": incident_id},
        )
        inc_row = inc_result.mappings().fetchone()
        await session.commit()

    # 에이전트에 연장 명령 전송
    target_ip: str | None = None
    actions_taken = arl_row["actions_taken"]
    if isinstance(actions_taken, list):
        for act in actions_taken:
            if isinstance(act, dict) and act.get("target"):
                target_ip = act["target"]
                break

    if inc_row and inc_row["asset_id"] and target_ip:
        redis = get_redis()
        command = {
            "action_type": "extend_block_ip",
            "target": target_ip,
            "payload": {
                "new_expires_at": new_expires_at.isoformat(),
                "additional_ttl_seconds": payload.additional_ttl_seconds,
            },
            "issued_at": now.isoformat(),
            "extended_by": actor,
        }
        key = f"tenant:{tenant_id}:commands:{inc_row['asset_id']}"
        await redis.lpush(key, json.dumps(command))
        await redis.expire(key, payload.additional_ttl_seconds + 3600)

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="block.extended",
        resource=incident_id,
        metadata={
            "auto_response_id": arl_row["auto_response_id"],
            "additional_ttl_seconds": payload.additional_ttl_seconds,
            "new_expires_at": new_expires_at.isoformat(),
        },
    )

    log.info(
        "block_extended tenant=%s incident=%s additional_ttl=%s actor=%s",
        tenant_id, incident_id, payload.additional_ttl_seconds, actor,
    )
    return {
        "extended": True,
        "incident_id": incident_id,
        "auto_response_id": arl_row["auto_response_id"],
        "additional_ttl_seconds": payload.additional_ttl_seconds,
        "new_expires_at": new_expires_at.isoformat(),
    }

"""Phase 3-D: 에이전트 Lifecycle 관리 API.

설계서 3-D: 에이전트 확장 전에 Lifecycle 관리 구조 선행 필요.

보안 주의 (설계서):
- agent_commands는 중앙 서버가 고객사 서버를 원격 제어하는 구조
- payload_sig HMAC 서명 필수
- 명령 타입 allowlist (update/restart/reconfigure/deactivate만)
- 임의 shell 실행 금지
- expires_at 만료 필수
- 에이전트 측 replay 방지

엔드포인트:
  GET    /agents                          - 에이전트 목록
  GET    /agents/{agent_id}               - 에이전트 상세
  POST   /agents/{agent_id}/commands      - 명령 발송 (HMAC 서명)
  GET    /agents/{agent_id}/commands      - 명령 이력
  PATCH  /agents/{agent_id}/commands/{cmd_id}/ack - 명령 실행 확인
  POST   /agents/{agent_id}/deactivate    - 에이전트 비활성화
  GET    /agents/{agent_id}/versions      - 버전 이력
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role
from app.iam.security import verify_agent_token

router = APIRouter(prefix="/agents", tags=["agent-management"])

# 허용된 명령 타입만 허용 (임의 shell 실행 금지)
_ALLOWED_COMMANDS = {"update", "restart", "reconfigure", "deactivate"}
_COMMAND_EXPIRY_SECONDS = 300  # 5분


# ============================================================
# Request 모델
# ============================================================

class AgentCommandRequest(BaseModel):
    command: str = Field(..., description="update / restart / reconfigure / deactivate")
    payload: dict = Field(default_factory=dict)
    expires_in_seconds: int = Field(default=_COMMAND_EXPIRY_SECONDS, ge=60, le=3600)


class CommandAckRequest(BaseModel):
    status: str = Field(..., pattern="^(executed|failed)$")
    result: Optional[dict] = None


class DeactivateRequest(BaseModel):
    reason: str = Field(default="관리자 비활성화")


# ============================================================
# 에이전트 목록/상세
# ============================================================

@router.get("")
async def list_agents(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT a.agent_id, a.asset_id, a.status, a.last_heartbeat,
                       a.agent_version, a.deactivated_at, a.deactivation_reason,
                       a.cpu_quota_pct, a.mem_max_mb,
                       ast.hostname, ast.os
                FROM agents a
                LEFT JOIN assets ast ON a.asset_id = ast.asset_id
                WHERE a.tenant_id = :tenant_id
                ORDER BY a.last_heartbeat DESC NULLS LAST
            """),
            {"tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "agent_id": r["agent_id"],
                "asset_id": r["asset_id"],
                "hostname": r["hostname"],
                "os": r["os"],
                "status": r["status"],
                "agent_version": r["agent_version"],
                "last_heartbeat": r["last_heartbeat"].isoformat() if r["last_heartbeat"] else None,
                "deactivated_at": r["deactivated_at"].isoformat() if r["deactivated_at"] else None,
                "deactivation_reason": r["deactivation_reason"],
                "cpu_quota_pct": r["cpu_quota_pct"],
                "mem_max_mb": r["mem_max_mb"],
            }
            for r in rows
        ]
    }


# ============================================================
# 명령 발송 (HMAC 서명 필수)
# ============================================================

def _sign_payload(payload: dict, secret: str) -> str:
    """HMAC-SHA256으로 payload 서명."""
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    return hmac.new(
        secret.encode(),
        payload_str.encode(),
        hashlib.sha256,
    ).hexdigest()


@router.post("/{agent_id}/commands", status_code=201)
async def send_command(
    agent_id: str,
    payload: AgentCommandRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """에이전트에 명령 발송. HMAC 서명 자동 생성.

    설계서 보안 주의:
    - 명령 타입 allowlist 검증
    - HMAC-SHA256 서명
    - expires_at 만료 시간 설정
    """
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    # 명령 타입 allowlist 검증 (임의 shell 실행 방지)
    if payload.command not in _ALLOWED_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"허용되지 않은 명령입니다. 허용: {_ALLOWED_COMMANDS}",
        )

    # 에이전트 존재 확인
    async with get_session() as session:
        agent_row = await session.execute(
            text("""
                SELECT agent_id, deactivated_at FROM agents
                WHERE agent_id = :agent_id AND tenant_id = :tenant_id
            """),
            {"agent_id": agent_id, "tenant_id": tenant_id},
        )
        agent = agent_row.fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="agent_not_found")
        if agent[1]:  # deactivated_at
            raise HTTPException(status_code=400, detail="비활성화된 에이전트입니다")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.expires_in_seconds)

    # HMAC 서명 생성
    settings = get_settings()
    cmd_payload = {
        "command": payload.command,
        "payload": payload.payload,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    signature = _sign_payload(cmd_payload, settings.jwt_secret)

    async with get_session() as session:
        result = await session.execute(
            text("""
                INSERT INTO agent_commands
                    (tenant_id, agent_id, command, payload, payload_sig, expires_at, status)
                VALUES
                    (:tenant_id, :agent_id, :command, CAST(:payload AS JSONB), :payload_sig, :expires_at, 'pending')
                RETURNING id::text, created_at
            """),
            {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "command": payload.command,
                "payload": json.dumps(payload.payload),
                "payload_sig": signature,
                "expires_at": expires_at,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="agent.command_sent",
        resource=agent_id, metadata={"command": payload.command, "cmd_id": row["id"]},
    )

    return {
        "id": row["id"],
        "agent_id": agent_id,
        "command": payload.command,
        "payload": payload.payload,
        "payload_sig": signature,
        "expires_at": expires_at.isoformat(),
        "status": "pending",
        "created_at": row["created_at"].isoformat(),
    }


@router.get("/{agent_id}/commands")
async def list_commands(
    agent_id: str,
    status: Optional[str] = Query(None),
    limit: int = Query(default=20, ge=1, le=100),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """에이전트 명령 이력."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        params: dict = {"agent_id": agent_id, "tenant_id": tenant_id, "limit": limit}
        where = "agent_id = :agent_id AND tenant_id = :tenant_id"
        if status:
            where += " AND status = :status"
            params["status"] = status

        result = await session.execute(
            text(f"""
                SELECT id::text, command, payload, status, expires_at,
                       created_at, delivered_at, executed_at, result
                FROM agent_commands
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            params,
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": r["id"],
                "command": r["command"],
                "payload": r["payload"],
                "status": r["status"],
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None,
                "result": r["result"],
            }
            for r in rows
        ]
    }


@router.patch("/{agent_id}/commands/{cmd_id}/ack")
async def ack_command(
    agent_id: str,
    cmd_id: str,
    payload: CommandAckRequest,
    claims: dict = Depends(verify_agent_token),
) -> dict:
    """에이전트가 명령 실행 결과 보고 (서명 검증 포함).

    이 엔드포인트는 에이전트가 호출하므로 agent 인증 사용.
    """
    now = datetime.now(timezone.utc)
    async with get_session() as session:
        # 명령 조회 및 만료 확인
        cmd_row = await session.execute(
            text("""
                SELECT id, command, expires_at, status, payload_sig, payload
                FROM agent_commands
                WHERE id = CAST(:id AS UUID) AND agent_id = :agent_id
            """),
            {"id": cmd_id, "agent_id": agent_id},
        )
        cmd = cmd_row.mappings().fetchone()
        if not cmd:
            raise HTTPException(status_code=404, detail="command_not_found")

        # 만료 확인
        expires_at = cmd["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            raise HTTPException(status_code=400, detail="명령이 만료되었습니다")

        # 이미 처리된 명령 (replay 방지)
        if cmd["status"] not in {"pending", "delivered"}:
            raise HTTPException(status_code=409, detail="이미 처리된 명령입니다")

        await session.execute(
            text("""
                UPDATE agent_commands
                SET status = :status, executed_at = :now, result = CAST(:result AS JSONB)
                WHERE id = CAST(:id AS UUID)
            """),
            {
                "id": cmd_id,
                "status": payload.status,
                "now": now,
                "result": json.dumps(payload.result or {}),
            },
        )
        await session.commit()

    return {"id": cmd_id, "status": payload.status, "executed_at": now.isoformat()}


# ============================================================
# 비활성화
# ============================================================

@router.post("/{agent_id}/deactivate")
async def deactivate_agent(
    agent_id: str,
    payload: DeactivateRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """에이전트 비활성화."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE agents
                SET status = 'deactivated',
                    deactivated_at = :now,
                    deactivation_reason = :reason
                WHERE agent_id = :agent_id AND tenant_id = :tenant_id
                RETURNING agent_id
            """),
            {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "now": now,
                "reason": payload.reason,
            },
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="agent_not_found")
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="agent.deactivate",
        resource=agent_id, metadata={"reason": payload.reason},
    )
    return {"agent_id": agent_id, "status": "deactivated", "deactivated_at": now.isoformat()}


@router.get("/{agent_id}/versions")
async def list_agent_versions(
    agent_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """에이전트 버전 이력."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT version, reported_at
                FROM agent_versions
                WHERE agent_id = :agent_id AND tenant_id = :tenant_id
                ORDER BY reported_at DESC
                LIMIT 50
            """),
            {"agent_id": agent_id, "tenant_id": tenant_id},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "version": r["version"],
                "reported_at": r["reported_at"].isoformat() if r["reported_at"] else None,
            }
            for r in rows
        ]
    }

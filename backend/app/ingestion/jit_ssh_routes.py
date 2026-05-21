"""
JIT SSH API (PERSIST-JIT)
==========================
엔드포인트:
    POST   /api/v1/assets/{asset_id}/jit-ssh/open     — SSH 임시 개방 (approval 필요)
    POST   /api/v1/assets/{asset_id}/jit-ssh/revoke   — 즉시 키 삭제
    GET    /api/v1/assets/{asset_id}/jit-ssh/history  — JIT SSH 이력 조회
    POST   /api/v1/jit-ssh/audit                       — 에이전트 → 백엔드 이벤트 보고 (내부)

설계서: InfraRed_v8_보안심화_설계서.md §7 / §12
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.db.connection import get_pool
from app.iam.rbac_v2 import require_role

router = APIRouter(prefix="/api/v1", tags=["jit-ssh"])
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 요청/응답 모델
# ---------------------------------------------------------------------------

class JITSSHOpenRequest(BaseModel):
    public_key: str = Field(..., description="SSH 공개키 (ssh-ed25519 / ssh-rsa / ecdsa-sha2-nistp256)")
    ttl_minutes: int = Field(default=10, ge=1, le=60, description="키 유효 시간 (1~60분)")
    target_user: str = Field(default="deploy", description="대상 Unix 사용자")
    reason: str = Field(default="", description="접속 사유 (감사 로그용)")


class JITSSHRevokeRequest(BaseModel):
    command_id: str = Field(..., description="revoke할 inject 커맨드 ID")


class JITAuditRequest(BaseModel):
    event_type: str          # "jit_ssh_injected" | "jit_ssh_revoked"
    asset_id: str
    command_id: Optional[str] = None
    target_user: Optional[str] = None
    fingerprint: Optional[str] = None
    expires_at: Optional[str] = None
    ttl_minutes: Optional[int] = None
    reason: Optional[str] = None
    revoked_at: Optional[str] = None


# ---------------------------------------------------------------------------
# POST /api/v1/assets/{asset_id}/jit-ssh/open
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/jit-ssh/open")
async def open_jit_ssh(
    asset_id: str,
    body: JITSSHOpenRequest,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    JIT SSH 임시 개방.

    이 API는 해당 에이전트에 `inject_temp_ssh_key` 명령을 발행합니다.
    명령은 approval_required=True로 처리되어 에이전트가 수신 후 실행합니다.

    ⚠️  보안 요구사항:
        - 에이전트의 authorized_keys는 평소 빈 파일이어야 합니다.
        - TTL 만료 시 에이전트가 자동으로 키를 삭제합니다.
        - 모든 주입/삭제 이벤트는 audit_logs에 기록됩니다.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    # 공개키 기본 검증 (상세 검증은 에이전트 측)
    key_parts = body.public_key.strip().split()
    if len(key_parts) < 2 or key_parts[0] not in {
        "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"
    }:
        raise HTTPException(
            status_code=400,
            detail="유효하지 않은 SSH 공개키 형식입니다. ssh-ed25519 / ssh-rsa / ecdsa-sha2-nistp256 지원",
        )

    import uuid as _uuid
    command_id = str(_uuid.uuid4())

    async with pool.acquire() as conn:
        # 에이전트 커맨드 발행
        await conn.execute(
            """
            INSERT INTO agent_commands
                (id, tenant_id, asset_id, action_type, payload, approval_required, status, created_at)
            VALUES ($1, $2, $3, 'inject_temp_ssh_key', $4::jsonb, true, 'pending', now())
            """,
            command_id,
            tenant_id,
            asset_id,
            __import__("json").dumps({
                "public_key": body.public_key,
                "ttl_minutes": body.ttl_minutes,
                "user": body.target_user,
            }),
        )

        # JIT SSH 이력 기록
        await conn.execute(
            """
            INSERT INTO jit_ssh_keys
                (tenant_id, agent_id, command_id, target_user, key_fingerprint, injected_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, now(),
                    now() + ($6 || ' minutes')::interval)
            """,
            tenant_id,
            asset_id,
            command_id,
            body.target_user,
            _fingerprint_from_key(body.public_key),
            str(body.ttl_minutes),
        )

        # Audit log
        await conn.execute(
            """
            INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, detail)
            VALUES ($1, $2, 'JIT_SSH_OPEN', 'agent', $3, $4::jsonb)
            """,
            tenant_id,
            claims.get("user_id", "unknown"),
            asset_id,
            __import__("json").dumps({
                "command_id": command_id,
                "target_user": body.target_user,
                "ttl_minutes": body.ttl_minutes,
                "reason": body.reason,
            }),
        )

    return {
        "status": "command_issued",
        "command_id": command_id,
        "asset_id": asset_id,
        "target_user": body.target_user,
        "ttl_minutes": body.ttl_minutes,
        "message": (
            f"inject_temp_ssh_key 명령이 발행됐습니다. "
            f"에이전트 승인 후 {body.ttl_minutes}분간 유효합니다."
        ),
    }


# ---------------------------------------------------------------------------
# POST /api/v1/assets/{asset_id}/jit-ssh/revoke
# ---------------------------------------------------------------------------

@router.post("/assets/{asset_id}/jit-ssh/revoke")
async def revoke_jit_ssh(
    asset_id: str,
    body: JITSSHRevokeRequest,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    JIT SSH 키 즉시 삭제.
    에이전트에 `revoke_temp_ssh_key` 명령을 발행합니다.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    import json as _json
    import uuid as _uuid
    revoke_cmd_id = str(_uuid.uuid4())

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO agent_commands
                (id, tenant_id, asset_id, action_type, payload, approval_required, status, created_at)
            VALUES ($1, $2, $3, 'revoke_temp_ssh_key', $4::jsonb, false, 'pending', now())
            """,
            revoke_cmd_id, tenant_id, asset_id,
            _json.dumps({"command_id": body.command_id}),
        )

        # DB 이력 업데이트
        await conn.execute(
            """
            UPDATE jit_ssh_keys
            SET revoked_at=now(), revoke_reason='manual'
            WHERE command_id=$1 AND tenant_id=$2 AND revoked_at IS NULL
            """,
            body.command_id, tenant_id,
        )

    return {
        "status": "revoke_command_issued",
        "revoke_command_id": revoke_cmd_id,
        "target_command_id": body.command_id,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/assets/{asset_id}/jit-ssh/history
# ---------------------------------------------------------------------------

@router.get("/assets/{asset_id}/jit-ssh/history")
async def get_jit_ssh_history(
    asset_id: str,
    limit: int = 50,
    claims: dict = Depends(require_role("analyst")),
    pool=Depends(get_pool),
) -> dict:
    """JIT SSH 주입/삭제 이력 조회."""
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, command_id, target_user, key_fingerprint,
                   injected_at, expires_at, revoked_at, revoke_reason
            FROM jit_ssh_keys
            WHERE tenant_id=$1 AND agent_id=$2
            ORDER BY injected_at DESC
            LIMIT $3
            """,
            tenant_id, asset_id, limit,
        )

    return {
        "asset_id": asset_id,
        "history": [
            {
                "id": str(row["id"]),
                "command_id": str(row["command_id"]) if row["command_id"] else None,
                "target_user": row["target_user"],
                "key_fingerprint": row["key_fingerprint"],
                "injected_at": row["injected_at"].isoformat() if row["injected_at"] else None,
                "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
                "revoked_at": row["revoked_at"].isoformat() if row["revoked_at"] else None,
                "revoke_reason": row["revoke_reason"],
                "status": (
                    "revoked" if row["revoked_at"]
                    else "expired" if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc)
                    else "active"
                ),
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# POST /api/v1/jit-ssh/audit  (에이전트 → 백엔드 내부 보고용)
# ---------------------------------------------------------------------------

@router.post("/jit-ssh/audit")
async def jit_ssh_audit(
    body: JITAuditRequest,
    pool=Depends(get_pool),
) -> dict:
    """
    에이전트가 JIT SSH 이벤트 발생 시 백엔드에 보고하는 내부 엔드포인트.
    (inject_temp_ssh_key / revoke_temp_ssh_key 완료 시 호출)
    """
    import json as _json
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, detail)
            SELECT tenant_id, 'agent', $1, 'jit_ssh', $2, $3::jsonb
            FROM agents WHERE id=$2
            ON CONFLICT DO NOTHING
            """,
            body.event_type.upper(),
            body.asset_id,
            _json.dumps(body.model_dump(exclude_none=True)),
        )

        if body.event_type == "jit_ssh_revoked" and body.command_id:
            await conn.execute(
                """
                UPDATE jit_ssh_keys
                SET revoked_at=now(), revoke_reason=$1
                WHERE command_id=$2 AND revoked_at IS NULL
                """,
                body.reason or "ttl_expired",
                body.command_id,
            )

    return {"status": "recorded"}


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------

def _fingerprint_from_key(public_key: str) -> str:
    """SHA-256 핑거프린트 계산 (OpenSSH 형식)."""
    import base64
    import hashlib
    parts = public_key.strip().split()
    if len(parts) < 2:
        return "unknown"
    try:
        raw = base64.b64decode(parts[1])
        digest = hashlib.sha256(raw).digest()
        encoded = base64.b64encode(digest).decode().rstrip("=")
        return f"SHA256:{encoded}"
    except Exception:
        return "unknown"

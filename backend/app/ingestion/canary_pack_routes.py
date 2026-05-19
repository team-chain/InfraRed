"""
Canary Pack 관리 API
=====================
대시보드에서 Canary Pack 배포/제거/현황을 관리하는 엔드포인트.

엔드포인트:
    POST   /api/v1/canary/install    — 프로필 기반 Canary Pack 설치 명령 발행
    DELETE /api/v1/canary/uninstall  — Canary Pack 전체 제거 명령 발행
    GET    /api/v1/canary/status     — 배포 현황 조회

설계서: InfraRed_v8_보안심화_설계서.md §8 / §12
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.db.connection import get_pool
from app.iam.rbac_v2 import require_role

router = APIRouter(prefix="/api/v1/canary", tags=["canary-pack"])
log = logging.getLogger(__name__)

VALID_PROFILES = {"web-server", "aws", "docker", "minimal"}


# ---------------------------------------------------------------------------
# 요청 모델
# ---------------------------------------------------------------------------

class CanaryInstallRequest(BaseModel):
    profile: str = Field(default="web-server", description="배포 프로필: web-server | aws | docker | minimal")
    asset_id: str = Field(..., description="대상 에이전트(에셋) ID")
    dry_run: bool = Field(default=False, description="True이면 실제 배포 없이 미리보기만 반환")


class CanaryUninstallRequest(BaseModel):
    asset_id: str = Field(..., description="대상 에이전트(에셋) ID")


# ---------------------------------------------------------------------------
# POST /api/v1/canary/install
# ---------------------------------------------------------------------------

@router.post("/install")
async def install_canary_pack(
    body: CanaryInstallRequest,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    Canary Pack을 에이전트에 설치합니다.

    - 에이전트에 `deploy_canary_pack` 명령을 발행합니다.
    - dry_run=True이면 명령 발행 없이 배포 예정 목록만 반환합니다.

    프로필별 배포 항목:
        web-server : .env, credentials_backup, config-prod.bak 등
        aws        : credentials_backup × 3개 위치
        docker     : docker config, kubeconfig 미끼
        minimal    : credentials_backup + .env.backup
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    if body.profile not in VALID_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"알 수 없는 프로필: {body.profile}. 사용 가능: {', '.join(sorted(VALID_PROFILES))}",
        )

    # dry_run: DB 조작 없이 프로필 정보만 반환
    if body.dry_run:
        from infrared_agent.cli.canary import PROFILES  # 프로필 공유
        profile_def = PROFILES.get(body.profile)
        if not profile_def:
            return {"dry_run": True, "profile": body.profile, "tokens": []}
        return {
            "dry_run": True,
            "profile": body.profile,
            "description": profile_def.description,
            "tokens": [
                {"path": spec.path, "template": spec.content_template}
                for spec in profile_def.honeytokens
            ],
        }

    command_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        # 에이전트 커맨드 발행
        await conn.execute(
            """
            INSERT INTO agent_commands
                (id, tenant_id, asset_id, action_type, payload, approval_required, status, created_at)
            VALUES ($1, $2, $3, 'deploy_canary_pack', $4::jsonb, false, 'pending', now())
            """,
            command_id, tenant_id, body.asset_id,
            json.dumps({"profile": body.profile}),
        )

        # 배포 이력 기록
        await conn.execute(
            """
            INSERT INTO canary_pack_deployments
                (tenant_id, agent_id, profile, token_paths)
            VALUES ($1, $2, $3, $4::jsonb)
            """,
            tenant_id, body.asset_id, body.profile,
            json.dumps([{"profile": body.profile, "pending": True}]),
        )

        # Audit log
        await conn.execute(
            """
            INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, detail)
            VALUES ($1, $2, 'CANARY_PACK_INSTALL', 'agent', $3, $4::jsonb)
            """,
            tenant_id, claims.get("user_id", "unknown"), body.asset_id,
            json.dumps({"profile": body.profile, "command_id": command_id}),
        )

    return {
        "status": "command_issued",
        "command_id": command_id,
        "asset_id": body.asset_id,
        "profile": body.profile,
        "message": f"deploy_canary_pack 명령이 발행됐습니다 (프로필: {body.profile})",
    }


# ---------------------------------------------------------------------------
# DELETE /api/v1/canary/uninstall
# ---------------------------------------------------------------------------

@router.delete("/uninstall")
async def uninstall_canary_pack(
    body: CanaryUninstallRequest,
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    에이전트에서 Canary Pack을 완전 제거합니다.
    InfraRed가 생성한 미끼 파일만 삭제하며 기존 서비스 파일은 건드리지 않습니다.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    command_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO agent_commands
                (id, tenant_id, asset_id, action_type, payload, approval_required, status, created_at)
            VALUES ($1, $2, $3, 'remove_canary_pack', $4::jsonb, false, 'pending', now())
            """,
            command_id, tenant_id, body.asset_id, json.dumps({}),
        )

        await conn.execute(
            """
            UPDATE canary_pack_deployments
            SET removed_at = now()
            WHERE tenant_id=$1 AND agent_id=$2 AND removed_at IS NULL
            """,
            tenant_id, body.asset_id,
        )

        await conn.execute(
            """
            INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, detail)
            VALUES ($1, $2, 'CANARY_PACK_UNINSTALL', 'agent', $3, $4::jsonb)
            """,
            tenant_id, claims.get("user_id", "unknown"), body.asset_id,
            json.dumps({"command_id": command_id}),
        )

    return {
        "status": "command_issued",
        "command_id": command_id,
        "message": "remove_canary_pack 명령이 발행됐습니다. 기존 서비스 파일은 건드리지 않습니다.",
    }


# ---------------------------------------------------------------------------
# GET /api/v1/canary/status
# ---------------------------------------------------------------------------

@router.get("/status")
async def get_canary_status(
    asset_id: Optional[str] = None,
    claims: dict = Depends(require_role("analyst")),
    pool=Depends(get_pool),
) -> dict:
    """
    Canary Pack 배포 현황 조회.
    asset_id를 지정하면 해당 에이전트의 현황만, 생략하면 전체 반환.
    """
    tenant_id = claims.get("tenant_id", "")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    async with pool.acquire() as conn:
        if asset_id:
            rows = await conn.fetch(
                """
                SELECT id, agent_id, profile, deployed_at, removed_at, token_paths
                FROM canary_pack_deployments
                WHERE tenant_id=$1 AND agent_id=$2
                ORDER BY deployed_at DESC
                LIMIT 20
                """,
                tenant_id, asset_id,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, agent_id, profile, deployed_at, removed_at, token_paths
                FROM canary_pack_deployments
                WHERE tenant_id=$1
                ORDER BY deployed_at DESC
                LIMIT 100
                """,
                tenant_id,
            )

    deployments = [
        {
            "id": str(row["id"]),
            "asset_id": str(row["agent_id"]),
            "profile": row["profile"],
            "deployed_at": row["deployed_at"].isoformat() if row["deployed_at"] else None,
            "removed_at": row["removed_at"].isoformat() if row["removed_at"] else None,
            "status": "removed" if row["removed_at"] else "active",
            "token_paths": row["token_paths"],
        }
        for row in rows
    ]

    active_count = sum(1 for d in deployments if d["status"] == "active")

    return {
        "total": len(deployments),
        "active": active_count,
        "deployments": deployments,
    }

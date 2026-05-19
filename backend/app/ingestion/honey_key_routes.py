"""
AWS Honey Key API (DECEPTION-003)
==================================
엔드포인트:
    POST   /api/v1/canary/honey-key/create  — Honey Key 생성
    GET    /api/v1/canary/honey-key/status  — 현황 조회
    DELETE /api/v1/canary/honey-key         — 비활성화

설계서: InfraRed_v8_보안심화_설계서.md §6 / §12
"""
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.db.connection import get_pool
from app.iam.rbac_v2 import require_role
from app.workers.deception.honey_key import AWSHoneyKeyManager

router = APIRouter(prefix="/api/v1/canary", tags=["deception-honey-key"])
log = logging.getLogger(__name__)


def _get_manager(pool=Depends(get_pool)) -> AWSHoneyKeyManager:
    return AWSHoneyKeyManager(pool=pool)


# ---------------------------------------------------------------------------
# POST /api/v1/canary/honey-key/create
# ---------------------------------------------------------------------------

@router.post("/honey-key/create")
async def create_honey_key(
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    Honey AWS Access Key를 생성합니다.

    - IAM User를 생성하고 Deny * 정책을 부착합니다.
    - 생성된 키는 미끼 파일에 삽입할 수 있는 형태로 반환됩니다.
    - AWS IAM 자격증명이 환경변수에 없으면 더미 키가 생성됩니다 (개발 환경).

    ⚠️  반환된 secret_access_key는 이 응답 이후 다시 조회할 수 없습니다.
        미끼 파일에 즉시 삽입하세요.
    """
    tenant_id_str = claims.get("tenant_id", "")
    if not tenant_id_str:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    try:
        tenant_id = UUID(tenant_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="tenant_id 형식이 잘못됐습니다")

    manager = AWSHoneyKeyManager(pool=pool)

    # 이미 존재하는지 확인
    existing = await manager.get_honey_key(tenant_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"이미 활성 Honey Key가 존재합니다: "
                f"key_id={existing['access_key_id'][:12]}... "
                "삭제 후 재생성하거나 기존 키를 사용하세요."
            ),
        )

    try:
        config = await manager.create_honey_key(tenant_id)
    except Exception as exc:
        log.exception("Honey Key 생성 실패 (tenant=%s): %s", tenant_id, exc)
        raise HTTPException(status_code=500, detail=f"Honey Key 생성 실패: {exc}")

    return {
        "status": "created",
        "iam_user": config.iam_user,
        "access_key_id": config.access_key_id,
        "secret_access_key": config.secret_access_key,   # ⚠️ 1회만 반환
        "decoy_locations": config.decoy_locations,
        "decoy_credentials_content": manager.get_decoy_content(config, "credentials"),
        "decoy_env_content": manager.get_decoy_content(config, "env"),
        "warning": (
            "secret_access_key는 이 응답에서만 반환됩니다. "
            "미끼 파일에 즉시 삽입하세요."
        ),
    }


# ---------------------------------------------------------------------------
# GET /api/v1/canary/honey-key/status
# ---------------------------------------------------------------------------

@router.get("/honey-key/status")
async def get_honey_key_status(
    claims: dict = Depends(require_role("analyst")),
    pool=Depends(get_pool),
) -> dict:
    """
    현재 테넌트의 Honey Key 현황을 반환합니다.
    secret_access_key는 보안상 반환하지 않습니다.
    """
    tenant_id_str = claims.get("tenant_id", "")
    if not tenant_id_str:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    manager = AWSHoneyKeyManager(pool=pool)

    try:
        config = await manager.get_honey_key(UUID(tenant_id_str))
    except ValueError:
        raise HTTPException(status_code=400, detail="tenant_id 형식이 잘못됐습니다")

    if not config:
        return {
            "status": "not_configured",
            "message": "Honey Key가 설정되지 않았습니다. POST /honey-key/create로 생성하세요.",
        }

    return {
        "status": "active" if config.get("is_active") else "inactive",
        "iam_user": config["iam_user"],
        "access_key_id": config["access_key_id"],
        "created_at": config["created_at"].isoformat() if config.get("created_at") else None,
    }


# ---------------------------------------------------------------------------
# DELETE /api/v1/canary/honey-key
# ---------------------------------------------------------------------------

@router.delete("/honey-key")
async def delete_honey_key(
    claims: dict = Depends(require_role("admin")),
    pool=Depends(get_pool),
) -> dict:
    """
    Honey Key를 비활성화합니다.
    IAM User의 Access Key를 Inactive로 변경하고 DB 플래그를 업데이트합니다.
    """
    tenant_id_str = claims.get("tenant_id", "")
    if not tenant_id_str:
        raise HTTPException(status_code=400, detail="tenant_id가 없습니다")

    manager = AWSHoneyKeyManager(pool=pool)

    try:
        deleted = await manager.delete_honey_key(UUID(tenant_id_str))
    except ValueError:
        raise HTTPException(status_code=400, detail="tenant_id 형식이 잘못됐습니다")

    if not deleted:
        raise HTTPException(status_code=404, detail="활성 Honey Key가 없습니다")

    return {"status": "deactivated", "message": "Honey Key가 비활성화되었습니다"}

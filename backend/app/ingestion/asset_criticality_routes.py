"""자산 중요도 업데이트 API (v3.0 설계서).

엔드포인트:
  PATCH /api/v1/assets/{asset_id}/criticality — 자산 중요도 속성 업데이트

트리거: trg_compute_criticality_score 가 criticality_score를 자동 재계산
권한: owner 또는 security_manager
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_any_role

router = APIRouter(prefix="/api/v1/assets", tags=["asset-criticality"])
log = logging.getLogger(__name__)

_ALLOWED_ASSET_TYPES = {"web", "api", "db", "bastion", "worker", "monitoring"}
_ALLOWED_ENVIRONMENTS = {"dev", "staging", "prod"}
_ALLOWED_EXPOSURES = {"public", "private", "internal"}
_ALLOWED_SLA_TIERS = {"standard", "premium", "critical"}

# owner 또는 security_manager 권한 필요
_CRITICALITY_ROLES = ("owner", "security_manager", "admin")


class AssetCriticalityUpdate(BaseModel):
    asset_type: str | None = None          # web/api/db/bastion/worker/monitoring
    environment: str | None = None         # dev/staging/prod
    exposure: str | None = None            # public/private/internal
    contains_sensitive_data: bool | None = None
    owner_team: str | None = None
    sla_tier: str | None = None            # standard/premium/critical


@router.patch("/{asset_id}/criticality")
async def update_asset_criticality(
    asset_id: str,
    payload: AssetCriticalityUpdate,
    claims: dict = Depends(require_any_role(*_CRITICALITY_ROLES)),
) -> dict:
    """자산 중요도 속성 부분 업데이트.

    업데이트 후 DB 트리거(trg_compute_criticality_score)가 criticality_score를 자동 재계산.
    트리거가 없는 환경에서는 scores를 직접 반환하는 것에 그침 (INSERT/UPDATE 시 트리거 적용됨).
    """
    tenant_id = claims["tenant_id"]
    actor = str(claims.get("sub", "unknown"))

    # 입력값 유효성 검증
    if payload.asset_type and payload.asset_type not in _ALLOWED_ASSET_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"asset_type은 {_ALLOWED_ASSET_TYPES} 중 하나여야 합니다",
        )
    if payload.environment and payload.environment not in _ALLOWED_ENVIRONMENTS:
        raise HTTPException(
            status_code=422,
            detail=f"environment는 {_ALLOWED_ENVIRONMENTS} 중 하나여야 합니다",
        )
    if payload.exposure and payload.exposure not in _ALLOWED_EXPOSURES:
        raise HTTPException(
            status_code=422,
            detail=f"exposure는 {_ALLOWED_EXPOSURES} 중 하나여야 합니다",
        )
    if payload.sla_tier and payload.sla_tier not in _ALLOWED_SLA_TIERS:
        raise HTTPException(
            status_code=422,
            detail=f"sla_tier는 {_ALLOWED_SLA_TIERS} 중 하나여야 합니다",
        )

    # 업데이트할 필드가 하나도 없는 경우 차단
    update_data = payload.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="변경할 필드가 없습니다")

    async with get_session() as session:
        # 자산 존재 및 테넌트 소속 확인
        check_result = await session.execute(
            text("""
                SELECT asset_id, asset_type, environment, exposure,
                       contains_sensitive_data, owner_team, sla_tier, criticality_score
                FROM assets
                WHERE asset_id = :asset_id AND tenant_id = :tenant_id
            """),
            {"asset_id": asset_id, "tenant_id": tenant_id},
        )
        existing = check_result.mappings().fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="asset_not_found")

        # 동적 SET 절 구성 (None 필드 제외)
        set_clauses = []
        params: dict = {"asset_id": asset_id, "tenant_id": tenant_id}

        if payload.asset_type is not None:
            set_clauses.append("asset_type = :asset_type")
            params["asset_type"] = payload.asset_type

        if payload.environment is not None:
            set_clauses.append("environment = :environment")
            params["environment"] = payload.environment

        if payload.exposure is not None:
            set_clauses.append("exposure = :exposure")
            params["exposure"] = payload.exposure

        if payload.contains_sensitive_data is not None:
            set_clauses.append("contains_sensitive_data = :contains_sensitive_data")
            params["contains_sensitive_data"] = payload.contains_sensitive_data

        if payload.owner_team is not None:
            set_clauses.append("owner_team = :owner_team")
            params["owner_team"] = payload.owner_team

        if payload.sla_tier is not None:
            set_clauses.append("sla_tier = :sla_tier")
            params["sla_tier"] = payload.sla_tier

        # UPDATE 실행 — 트리거가 criticality_score를 자동 재계산
        result = await session.execute(
            text(f"""
                UPDATE assets
                SET {', '.join(set_clauses)}
                WHERE asset_id = :asset_id AND tenant_id = :tenant_id
                RETURNING asset_id, asset_type, environment, exposure,
                          contains_sensitive_data, owner_team, sla_tier, criticality_score
            """),
            params,
        )
        updated = result.mappings().fetchone()
        await session.commit()

    if not updated:
        raise HTTPException(status_code=500, detail="update_failed")

    log.info(
        "asset_criticality_updated asset_id=%s tenant=%s actor=%s fields=%s",
        asset_id, tenant_id, actor, list(update_data.keys()),
    )

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="asset.criticality_update",
        resource=asset_id,
        metadata={
            "updated_fields": list(update_data.keys()),
            "criticality_score": updated["criticality_score"],
        },
    )

    return {
        "asset_id": updated["asset_id"],
        "asset_type": updated["asset_type"],
        "environment": updated["environment"],
        "exposure": updated["exposure"],
        "contains_sensitive_data": updated["contains_sensitive_data"],
        "owner_team": updated["owner_team"],
        "sla_tier": updated["sla_tier"],
        "criticality_score": updated["criticality_score"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

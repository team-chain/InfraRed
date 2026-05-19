"""공격 캠페인 조회/제어 API (v3.0 설계서).

엔드포인트:
  GET  /api/v1/campaigns                          — 캠페인 목록 조회 (tenant_id 기준)
  GET  /api/v1/campaigns/{campaign_id}            — 캠페인 상세 조회
  POST /api/v1/campaigns/{campaign_id}/contain    — 캠페인 상태를 'contained'로 변경

테이블: attack_campaigns (migrate_v4_v3_schema.sql에서 생성)
권한: analyst 이상 (조회), security_manager 이상 (contain)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role

router = APIRouter(prefix="/api/v1/campaigns", tags=["campaigns"])
log = logging.getLogger(__name__)


# ============================================================
# GET /api/v1/campaigns — 캠페인 목록
# ============================================================

@router.get("")
async def list_campaigns(
    limit: int = Query(default=50, ge=1, le=200),
    status: str | None = Query(default=None, description="active / contained / closed"),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """테넌트별 공격 캠페인 목록 조회.

    status 필터 지원 (active / contained / closed).
    """
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        if status:
            result = await session.execute(
                text("""
                    SELECT id::text, tenant_id, campaign_type, source_asn,
                           source_ips, affected_asset_ids, incident_ids,
                           first_seen_at, last_seen_at, total_signals,
                           status, campaign_label
                    FROM attack_campaigns
                    WHERE tenant_id = :tenant_id
                      AND status = :status
                    ORDER BY last_seen_at DESC
                    LIMIT :limit
                """),
                {"tenant_id": tenant_id, "status": status, "limit": limit},
            )
        else:
            result = await session.execute(
                text("""
                    SELECT id::text, tenant_id, campaign_type, source_asn,
                           source_ips, affected_asset_ids, incident_ids,
                           first_seen_at, last_seen_at, total_signals,
                           status, campaign_label
                    FROM attack_campaigns
                    WHERE tenant_id = :tenant_id
                    ORDER BY last_seen_at DESC
                    LIMIT :limit
                """),
                {"tenant_id": tenant_id, "limit": limit},
            )
        rows = result.mappings().fetchall()

    items = [
        {
            "id": r["id"],
            "campaign_type": r["campaign_type"],
            "source_asn": r["source_asn"],
            "source_ips": r["source_ips"] or [],
            "affected_asset_ids": r["affected_asset_ids"] or [],
            "incident_ids": r["incident_ids"] or [],
            "first_seen_at": r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
            "last_seen_at": r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
            "total_signals": r["total_signals"],
            "status": r["status"],
            "campaign_label": r["campaign_label"],
        }
        for r in rows
    ]

    return {"items": items, "total": len(items)}


# ============================================================
# GET /api/v1/campaigns/{campaign_id} — 캠페인 상세
# ============================================================

@router.get("/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """캠페인 상세 조회."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, tenant_id, campaign_type, source_asn,
                       source_ips, affected_asset_ids, incident_ids,
                       first_seen_at, last_seen_at, total_signals,
                       status, campaign_label
                FROM attack_campaigns
                WHERE id = CAST(:campaign_id AS UUID)
                  AND tenant_id = :tenant_id
            """),
            {"campaign_id": campaign_id, "tenant_id": tenant_id},
        )
        row = result.mappings().fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="campaign_not_found")

    return {
        "id": row["id"],
        "campaign_type": row["campaign_type"],
        "source_asn": row["source_asn"],
        "source_ips": row["source_ips"] or [],
        "affected_asset_ids": row["affected_asset_ids"] or [],
        "incident_ids": row["incident_ids"] or [],
        "first_seen_at": row["first_seen_at"].isoformat() if row["first_seen_at"] else None,
        "last_seen_at": row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
        "total_signals": row["total_signals"],
        "status": row["status"],
        "campaign_label": row["campaign_label"],
    }


# ============================================================
# POST /api/v1/campaigns/{campaign_id}/contain — 캠페인 봉쇄
# ============================================================

@router.post("/{campaign_id}/contain", status_code=202)
async def contain_campaign(
    campaign_id: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """캠페인 상태를 'contained'로 변경.

    security_manager 이상 권한 필요.
    """
    tenant_id = claims["tenant_id"]
    actor = str(claims.get("sub", "unknown"))
    now = datetime.now(timezone.utc)

    async with get_session() as session:
        result = await session.execute(
            text("""
                UPDATE attack_campaigns
                SET status = 'contained',
                    last_seen_at = :now
                WHERE id = CAST(:campaign_id AS UUID)
                  AND tenant_id = :tenant_id
                  AND status != 'contained'
                RETURNING id::text, status, campaign_type
            """),
            {
                "campaign_id": campaign_id,
                "tenant_id": tenant_id,
                "now": now,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    if not row:
        # 이미 contained이거나 존재하지 않는 경우 확인
        async with get_session() as session:
            check = await session.execute(
                text("""
                    SELECT id::text, status FROM attack_campaigns
                    WHERE id = CAST(:campaign_id AS UUID) AND tenant_id = :tenant_id
                """),
                {"campaign_id": campaign_id, "tenant_id": tenant_id},
            )
            existing = check.mappings().fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="campaign_not_found")
        # 이미 contained 상태
        return {
            "contained": False,
            "message": "campaign_already_contained",
            "campaign_id": campaign_id,
            "status": existing["status"],
        }

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="campaign.contained",
        resource=campaign_id,
        metadata={"campaign_type": row["campaign_type"]},
    )

    log.info("campaign_contained tenant=%s campaign=%s actor=%s", tenant_id, campaign_id, actor)
    return {
        "contained": True,
        "campaign_id": campaign_id,
        "status": "contained",
        "contained_at": now.isoformat(),
    }

"""포렌식 수집 및 파일 복원 API 라우터 (v5.0)."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import require_permission
from app.workers.forensic.collector import ForensicCollector
from app.workers.recovery.file_restore import FileRestoreHandler
from app.workers.recovery.reinfection import ReinfectionPrevention

router = APIRouter()
log = logging.getLogger(__name__)


# ── 요청/응답 모델 ─────────────────────────────────────────────────────────── #

class ForensicCollectRequest(BaseModel):
    incident_id: str
    asset_id: Optional[str] = None


class FileRestoreRequest(BaseModel):
    path: str
    content_b64: str
    incident_id: Optional[str] = None


# ── 라우트 ────────────────────────────────────────────────────────────────── #

@router.post("/forensic/collect", status_code=202)
async def trigger_forensic_collect(
    req: ForensicCollectRequest,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """포렌식 수집 트리거 — ps, netstat, /proc/net/tcp, last, who 수집 후 S3 WORM 저장."""
    tenant_id = claims["tenant_id"]
    collector = ForensicCollector()
    try:
        bundle = await collector.collect(
            tenant_id=tenant_id,
            incident_id=req.incident_id,
            asset_id=req.asset_id,
        )
    except Exception as exc:
        log.error("forensic_collect_failed incident=%s error=%s", req.incident_id, exc)
        raise HTTPException(status_code=500, detail=f"forensic_collect_failed: {exc}")

    return {
        "accepted": True,
        "incident_id": req.incident_id,
        "items": len(bundle.get("items", [])),
        "manifest_sig": bundle.get("manifest_sig", ""),
        "collected_at": bundle.get("collected_at"),
    }


@router.get("/forensic/{incident_id}")
async def get_forensic_bundle(
    incident_id: str,
    claims: dict = Depends(require_permission("incident:read")),
) -> dict:
    """특정 인시던트의 포렌식 번들 메타데이터 조회."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        rows = await session.execute(
            text("""
                SELECT id, tenant_id, incident_id, asset_id,
                       collected_at, s3_key, manifest_sig, item_count
                FROM forensic_bundles
                WHERE tenant_id = :tenant_id AND incident_id = :incident_id
                ORDER BY collected_at DESC
                LIMIT 50
            """),
            {"tenant_id": tenant_id, "incident_id": incident_id},
        )
        items = [dict(r) for r in rows.mappings()]

    if not items:
        raise HTTPException(status_code=404, detail="forensic_bundle_not_found")

    return {"incident_id": incident_id, "bundles": items}


@router.post("/forensic/restore")
async def restore_file(
    req: FileRestoreRequest,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """파일 복원 — 보호 경로는 approval_required=True 반환, 일반 경로는 즉시 복원."""
    handler = FileRestoreHandler()
    success, reason = handler.restore(
        path=req.path,
        content_b64=req.content_b64,
        incident_id=req.incident_id,
    )

    if not success and "approval_required" in reason:
        return {
            "success": False,
            "approval_required": True,
            "reason": reason,
            "path": req.path,
        }

    if not success:
        raise HTTPException(status_code=400, detail=reason)

    log.info("file_restored path=%s incident=%s", req.path, req.incident_id)
    return {
        "success": True,
        "approval_required": False,
        "reason": reason,
        "path": req.path,
    }


@router.get("/forensic/reinfection-check/{incident_id}")
async def check_reinfection(
    incident_id: str,
    claims: dict = Depends(require_permission("incident:read")),
) -> dict:
    """재감염 위험 점검 — SSH 설정, SUID 바이너리, 빈 패스워드, 미패치 패키지 확인."""
    tenant_id = claims["tenant_id"]
    checker = ReinfectionPrevention()
    try:
        report = checker.check_reinfection_risk(
            tenant_id=tenant_id,
            incident_id=incident_id,
        )
    except Exception as exc:
        log.error("reinfection_check_failed incident=%s error=%s", incident_id, exc)
        raise HTTPException(status_code=500, detail=f"reinfection_check_failed: {exc}")

    return report.to_dict()

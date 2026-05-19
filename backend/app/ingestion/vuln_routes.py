"""취약점 스캔 API 라우터 (v5.0)."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import require_permission
from app.workers.vuln_scanner.scanner import VulnerabilityScanner


router = APIRouter()
log = logging.getLogger(__name__)


# ── 요청 모델 ─────────────────────────────────────────────────────────────── #

class VulnScanRequest(BaseModel):
    asset_id: Optional[str] = None


# ── 라우트 ────────────────────────────────────────────────────────────────── #

@router.post("/vuln-scan", status_code=202)
async def trigger_vuln_scan(
    req: VulnScanRequest,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict:
    """취약점 스캔 실행 — SSH 설정, 파일 권한 이상 탐지."""
    tenant_id = claims["tenant_id"]
    asset_id = req.asset_id or "unknown"
    scanner = VulnerabilityScanner()
    try:
        result = await scanner.scan(tenant_id=tenant_id, asset_id=asset_id)
    except Exception as exc:
        log.error("vuln_scan_failed tenant=%s asset=%s error=%s", tenant_id, asset_id, exc)
        raise HTTPException(status_code=500, detail=f"vuln_scan_failed: {exc}")

    return {
        "accepted": True,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "scanned_at": result.scanned_at,
        "findings_count": len(result.findings),
        "severity_counts": result.severity_counts,
    }


@router.get("/vuln-scan/results/{asset_id}")
async def get_vuln_scan_results(
    asset_id: str,
    limit: int = 10,
    claims: dict = Depends(require_permission("incident:read")),
) -> dict:
    """특정 자산의 최근 취약점 스캔 결과 조회."""
    tenant_id = claims["tenant_id"]

    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")

    async with get_session() as session:
        rows = await session.execute(
            text("""
                SELECT id, tenant_id, asset_id, scanned_at,
                       findings, critical_count, high_count
                FROM vuln_scan_results
                WHERE tenant_id = :tenant_id AND asset_id = :asset_id
                ORDER BY scanned_at DESC
                LIMIT :limit
            """),
            {"tenant_id": tenant_id, "asset_id": asset_id, "limit": limit},
        )
        items = [dict(r) for r in rows.mappings()]

    if not items:
        raise HTTPException(status_code=404, detail="no_scan_results_found")

    return {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "results": items,
    }

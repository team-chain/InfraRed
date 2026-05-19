"""SSL 인증서 모니터링 API 라우터.

엔드포인트:
  POST /ssl/monitor/add        — 모니터링 도메인 추가
  GET  /ssl/monitor/status     — 모든 도메인 인증서 상태
  POST /ssl/monitor/check-now  — 즉시 점검 실행
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import get_settings
from app.iam.rbac_v2 import require_role
from app.workers.ssl_monitor.checker import SSLCertificateMonitor

router = APIRouter(prefix="/ssl", tags=["ssl"])
log = logging.getLogger(__name__)
settings = get_settings()

_monitor = SSLCertificateMonitor()


class AddDomainRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, description="모니터링할 도메인명")
    port: int = Field(default=443, ge=1, le=65535)


@router.post("/monitor/add")
async def add_domain(
    body: AddDomainRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """SSL 모니터링 대상 도메인을 추가한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    try:
        await _monitor.add_domain(tenant_id, body.domain)
    except Exception as exc:
        log.exception("도메인 추가 실패: %s", body.domain)
        raise HTTPException(status_code=500, detail=f"도메인 추가 실패: {exc}") from exc

    return {
        "status": "added",
        "domain": body.domain,
        "tenant_id": tenant_id,
    }


@router.get("/monitor/status")
async def get_status(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """등록된 모든 도메인의 SSL 인증서 상태를 반환한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    certs = await _monitor.get_all_status(tenant_id)

    critical = [c for c in certs if c["severity"] == "CRITICAL"]
    high = [c for c in certs if c["severity"] == "HIGH"]
    warning = [c for c in certs if c["severity"] == "WARNING"]

    return {
        "tenant_id": tenant_id,
        "total": len(certs),
        "critical_count": len(critical),
        "high_count": len(high),
        "warning_count": len(warning),
        "certificates": certs,
    }


@router.post("/monitor/check-now")
async def check_now(
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """등록된 모든 도메인의 SSL 인증서를 즉시 점검한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    try:
        results = await _monitor.run_all_checks(tenant_id)
    except Exception as exc:
        log.exception("SSL 즉시 점검 실패")
        raise HTTPException(status_code=500, detail=f"점검 실패: {exc}") from exc

    success = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    return {
        "tenant_id": tenant_id,
        "checked": len(results),
        "success_count": len(success),
        "failed_count": len(failed),
        "results": [
            {
                "domain": r.domain,
                "success": r.success,
                "days_remaining": r.cert_info.days_remaining if r.cert_info else None,
                "severity": r.cert_info.severity if r.cert_info else None,
                "expires_at": r.cert_info.expires_at.isoformat() if r.cert_info else None,
                "error": r.error,
            }
            for r in results
        ],
    }

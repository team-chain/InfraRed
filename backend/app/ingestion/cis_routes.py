"""CIS Benchmark 점검 API 라우터.

엔드포인트:
  GET /cis/benchmark         — CIS Level 1 전체 점검 실행
  GET /cis/benchmark/summary — 마지막 점검 결과 요약 (인메모리 캐시)
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from app.config import get_settings
from app.iam.rbac_v2 import require_role
from app.workers.cis.checker import CISBenchmarkChecker, CISReport

router = APIRouter(prefix="/cis", tags=["cis"])
log = logging.getLogger(__name__)
settings = get_settings()

_checker = CISBenchmarkChecker()
_last_report: Optional[CISReport] = None


@router.get("/benchmark")
async def run_benchmark(
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """CIS Benchmark Level 1 전체 점검을 실행하고 결과를 반환한다."""
    global _last_report
    tenant_id = claims.get("tenant_id", settings.tenant_id)

    try:
        report = _checker.check_all(tenant_id)
        _last_report = report
    except Exception as exc:
        log.exception("CIS Benchmark 점검 실패")
        raise HTTPException(status_code=500, detail=f"점검 실패: {exc}") from exc

    return report.to_dict()


@router.get("/benchmark/summary")
async def benchmark_summary(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """마지막 CIS Benchmark 점검 결과 요약을 반환한다."""
    if _last_report is None:
        return {
            "message": "점검 결과 없음. GET /cis/benchmark 를 먼저 실행하세요.",
            "last_run": None,
            "score_pct": None,
            "pass_count": 0,
            "fail_count": 0,
            "na_count": 0,
        }

    return {
        "tenant_id": _last_report.tenant_id,
        "last_run": _last_report.generated_at.isoformat(),
        "score_pct": _last_report.score_pct,
        "pass_count": _last_report.pass_count,
        "fail_count": _last_report.fail_count,
        "na_count": _last_report.na_count,
        "total_items": len(_last_report.items),
    }

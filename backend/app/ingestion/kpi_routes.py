"""KPI 요약 및 트렌드 API 라우터.

엔드포인트:
  GET /kpi/summary?days=30  — MTTD/MTTR/MTTC 요약
  GET /kpi/trend?days=90    — 주간 KPI 트렌드
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.config import get_settings
from app.iam.rbac_v2 import require_role
from app.workers.kpi.calculator import KPICalculator

router = APIRouter(prefix="/kpi", tags=["kpi"])
log = logging.getLogger(__name__)
settings = get_settings()

_calculator = KPICalculator()


def _fmt(seconds: Optional[float]) -> Optional[str]:
    """초 → 사람이 읽기 쉬운 문자열 변환."""
    if seconds is None:
        return None
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds/60:.1f}m"
    return f"{seconds/3600:.1f}h"


@router.get("/summary")
async def kpi_summary(
    days: int = Query(default=30, ge=1, le=365, description="집계 기간(일)"),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """MTTD / MTTR / MTTC KPI 요약을 반환한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    result = await _calculator.calculate_period(tenant_id, days=days)

    return {
        "tenant_id": tenant_id,
        "period_days": result.period_days,
        "period_start": result.period_start.isoformat(),
        "period_end": result.period_end.isoformat(),
        "incident_count": result.incident_count,
        "mttd": {
            "seconds": result.mttd_seconds,
            "human": _fmt(result.mttd_seconds),
            "description": "Mean Time To Detect",
        },
        "mttr": {
            "seconds": result.mttr_seconds,
            "human": _fmt(result.mttr_seconds),
            "description": "Mean Time To Respond",
        },
        "mttc": {
            "seconds": result.mttc_seconds,
            "human": _fmt(result.mttc_seconds),
            "description": "Mean Time To Contain",
        },
    }


@router.get("/trend")
async def kpi_trend(
    days: int = Query(default=90, ge=7, le=365, description="트렌드 기간(일)"),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """주간 MTTD/MTTR/MTTC 트렌드 데이터를 반환한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    points = await _calculator.calculate_weekly_trend(tenant_id, days=days)

    return {
        "tenant_id": tenant_id,
        "period_days": days,
        "data_points": [
            {
                "week_start": p.week_start.isoformat(),
                "week_end": p.week_end.isoformat(),
                "incident_count": p.incident_count,
                "mttd_seconds": p.mttd_seconds,
                "mttr_seconds": p.mttr_seconds,
                "mttc_seconds": p.mttc_seconds,
            }
            for p in points
        ],
    }

"""MTTD / MTTR / MTTC KPI 계산기.

MTTD (Mean Time To Detect)  = 이벤트 first_seen → incident created_at 평균
MTTR (Mean Time To Respond) = incident created_at → auto_response executed_at 평균
MTTC (Mean Time To Contain) = auto_response executed_at → incident resolved_at 평균
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text

from app.db.connection import get_session


@dataclass
class KPIResult:
    mttd_seconds: Optional[float]
    mttr_seconds: Optional[float]
    mttc_seconds: Optional[float]
    period_days: int
    incident_count: int
    period_start: datetime
    period_end: datetime


@dataclass
class WeeklyKPIPoint:
    week_start: datetime
    week_end: datetime
    mttd_seconds: Optional[float]
    mttr_seconds: Optional[float]
    mttc_seconds: Optional[float]
    incident_count: int


class KPICalculator:
    """MTTD/MTTR/MTTC KPI 계산기.

    incidents 테이블과 auto_response_logs 테이블을 조인하여
    지정된 기간 내의 평균 탐지·대응·억제 시간을 계산한다.
    """

    async def calculate_period(
        self,
        tenant_id: str,
        days: int = 30,
    ) -> KPIResult:
        """지정 기간의 KPI 계산."""
        now = datetime.now(tz=timezone.utc)
        period_start = now - timedelta(days=days)

        sql = text("""
            SELECT
                AVG(
                    EXTRACT(EPOCH FROM (i.created_at - i.first_event_at))
                ) AS mttd_seconds,
                AVG(
                    EXTRACT(EPOCH FROM (arl.executed_at - i.created_at))
                ) AS mttr_seconds,
                AVG(
                    EXTRACT(EPOCH FROM (i.resolved_at - arl.executed_at))
                ) AS mttc_seconds,
                COUNT(DISTINCT i.id) AS incident_count
            FROM incidents i
            LEFT JOIN auto_response_logs arl
                ON arl.incident_id = i.id
                AND arl.status = 'executed'
            WHERE i.tenant_id = :tenant_id
              AND i.created_at >= :period_start
              AND i.created_at <= :period_end
        """)

        async with get_session() as session:
            row = (await session.execute(sql, {
                "tenant_id": tenant_id,
                "period_start": period_start,
                "period_end": now,
            })).one()

        return KPIResult(
            mttd_seconds=float(row.mttd_seconds) if row.mttd_seconds is not None else None,
            mttr_seconds=float(row.mttr_seconds) if row.mttr_seconds is not None else None,
            mttc_seconds=float(row.mttc_seconds) if row.mttc_seconds is not None else None,
            period_days=days,
            incident_count=int(row.incident_count or 0),
            period_start=period_start,
            period_end=now,
        )

    async def calculate_weekly_trend(
        self,
        tenant_id: str,
        days: int = 90,
    ) -> list[WeeklyKPIPoint]:
        """최근 N일을 주 단위로 쪼개 KPI 추이를 계산한다."""
        now = datetime.now(tz=timezone.utc)
        start = now - timedelta(days=days)

        sql = text("""
            SELECT
                date_trunc('week', i.created_at) AS week_start,
                AVG(
                    EXTRACT(EPOCH FROM (i.created_at - i.first_event_at))
                ) AS mttd_seconds,
                AVG(
                    EXTRACT(EPOCH FROM (arl.executed_at - i.created_at))
                ) AS mttr_seconds,
                AVG(
                    EXTRACT(EPOCH FROM (i.resolved_at - arl.executed_at))
                ) AS mttc_seconds,
                COUNT(DISTINCT i.id) AS incident_count
            FROM incidents i
            LEFT JOIN auto_response_logs arl
                ON arl.incident_id = i.id
                AND arl.status = 'executed'
            WHERE i.tenant_id = :tenant_id
              AND i.created_at >= :start
              AND i.created_at <= :now
            GROUP BY date_trunc('week', i.created_at)
            ORDER BY week_start ASC
        """)

        async with get_session() as session:
            rows = (await session.execute(sql, {
                "tenant_id": tenant_id,
                "start": start,
                "now": now,
            })).all()

        result: list[WeeklyKPIPoint] = []
        for row in rows:
            week_start = row.week_start
            if week_start.tzinfo is None:
                week_start = week_start.replace(tzinfo=timezone.utc)
            week_end = week_start + timedelta(days=7)
            result.append(WeeklyKPIPoint(
                week_start=week_start,
                week_end=week_end,
                mttd_seconds=float(row.mttd_seconds) if row.mttd_seconds is not None else None,
                mttr_seconds=float(row.mttr_seconds) if row.mttr_seconds is not None else None,
                mttc_seconds=float(row.mttc_seconds) if row.mttc_seconds is not None else None,
                incident_count=int(row.incident_count or 0),
            ))
        return result

    async def save_snapshot(self, tenant_id: str, result: KPIResult) -> None:
        """KPI 결과를 kpi_snapshots 테이블에 저장한다."""
        sql = text("""
            INSERT INTO kpi_snapshots
                (tenant_id, period_start, period_end,
                 mttd_seconds, mttr_seconds, mttc_seconds, incident_count)
            VALUES
                (:tenant_id, :period_start, :period_end,
                 :mttd_seconds, :mttr_seconds, :mttc_seconds, :incident_count)
        """)
        async with get_session() as session:
            await session.execute(sql, {
                "tenant_id": tenant_id,
                "period_start": result.period_start,
                "period_end": result.period_end,
                "mttd_seconds": result.mttd_seconds,
                "mttr_seconds": result.mttr_seconds,
                "mttc_seconds": result.mttc_seconds,
                "incident_count": result.incident_count,
            })

"""주간/월간 보안 PDF 리포트 생성기.

ReportLab 기반 PDF 생성 → S3 저장 → FastAPI 엔드포인트 제공.
설계서 v2 enhancement: 기존 WeasyPrint 기반 pdf_report.py 의 ReportLab 대체 버전.
"""
from __future__ import annotations

import asyncio
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from fastapi import APIRouter, HTTPException, Request
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

log = logging.getLogger(__name__)

report_router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


# ────────────────────────────────────────────────────────────────────────────
# DB 데이터 수집
# ────────────────────────────────────────────────────────────────────────────

async def collect_report_data(
    db_pool,
    tenant_id: str,
    date_from: datetime,
    date_to: datetime,
) -> dict:
    """asyncpg Pool 에서 리포트용 통계 데이터 수집."""
    async with db_pool.acquire() as conn:
        incidents = await conn.fetch(
            """
            SELECT severity,
                   COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE disposition = 'false_positive') AS fp_count
            FROM incidents
            WHERE tenant_id = $1
              AND created_at BETWEEN $2 AND $3
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high'     THEN 1
                    WHEN 'medium'   THEN 2
                    ELSE 3
                END
            """,
            tenant_id, date_from, date_to,
        )

        top_rules = await conn.fetch(
            """
            SELECT primary_rule_id,
                   COUNT(*) AS cnt
            FROM incidents
            WHERE tenant_id = $1
              AND created_at BETWEEN $2 AND $3
              AND primary_rule_id IS NOT NULL
            GROUP BY primary_rule_id
            ORDER BY cnt DESC
            LIMIT 10
            """,
            tenant_id, date_from, date_to,
        )

        top_ips = await conn.fetch(
            """
            SELECT source_ip::text AS source_ip,
                   COUNT(*) AS cnt
            FROM signals
            WHERE tenant_id = $1
              AND created_at BETWEEN $2 AND $3
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 10
            """,
            tenant_id, date_from, date_to,
        )

        kpi = await conn.fetchrow(
            """
            SELECT
                AVG(
                    EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60
                ) AS avg_mttd,
                AVG(
                    EXTRACT(EPOCH FROM (resolved_at - created_at)) / 60
                ) FILTER (WHERE resolved_at IS NOT NULL) AS avg_mttr,
                COUNT(*) FILTER (WHERE disposition = 'false_positive')::float
                    / NULLIF(COUNT(*), 0) * 100 AS fp_rate
            FROM incidents
            WHERE tenant_id = $1
              AND created_at BETWEEN $2 AND $3
            """,
            tenant_id, date_from, date_to,
        )

    return {
        "incidents": [dict(r) for r in incidents],
        "top_rules": [dict(r) for r in top_rules],
        "top_ips": [dict(r) for r in top_ips],
        "kpi": dict(kpi) if kpi else {},
    }


# ────────────────────────────────────────────────────────────────────────────
# PDF 생성
# ────────────────────────────────────────────────────────────────────────────

def _header_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ])


def generate_pdf(data: dict, period_label: str, tenant_id: str) -> bytes:
    """ReportLab 으로 보안 리포트 PDF 생성 후 bytes 반환."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"InfraRed 보안 리포트 — {period_label}",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "title",
        parent=styles["Title"],
        textColor=colors.HexColor("#b71c1c"),
        alignment=TA_CENTER,
    )
    story = []

    # ── 표지 ──────────────────────────────────────────────────────────────
    story.append(Paragraph("InfraRed 보안 리포트", title_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            f"기간: {period_label} &nbsp;|&nbsp; 테넌트: {tenant_id}",
            styles["Normal"],
        )
    )
    story.append(
        Paragraph(
            f"생성일: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.6 * cm))

    # ── KPI 요약 ──────────────────────────────────────────────────────────
    kpi = data.get("kpi", {})
    story.append(Paragraph("KPI 요약", styles["Heading2"]))
    kpi_rows = [
        ["지표", "값"],
        ["평균 탐지 시간 (MTTD)", f"{round(float(kpi.get('avg_mttd') or 0), 1)} 분"],
        ["평균 대응 시간 (MTTR)", f"{round(float(kpi.get('avg_mttr') or 0), 1)} 분"],
        ["False Positive 비율", f"{round(float(kpi.get('fp_rate') or 0), 1)} %"],
    ]
    t_kpi = Table(kpi_rows, colWidths=[10 * cm, 6 * cm])
    t_kpi.setStyle(_header_style())
    story.append(t_kpi)
    story.append(Spacer(1, 0.5 * cm))

    # ── 심각도별 인시던트 ─────────────────────────────────────────────────
    story.append(Paragraph("심각도별 인시던트", styles["Heading2"]))
    inc_rows = [["심각도", "건수", "FP 건수"]]
    for row in data.get("incidents", []):
        inc_rows.append([
            str(row.get("severity", "")),
            str(row.get("cnt", 0)),
            str(row.get("fp_count", 0)),
        ])
    if len(inc_rows) > 1:
        t_inc = Table(inc_rows, colWidths=[6 * cm, 4 * cm, 4 * cm])
        t_inc.setStyle(_header_style())
        story.append(t_inc)
    else:
        story.append(Paragraph("데이터 없음", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ── 탑 탐지 룰 ────────────────────────────────────────────────────────
    story.append(Paragraph("탑 탐지 룰 (Top 10)", styles["Heading2"]))
    rule_rows = [["룰 ID", "탐지 건수"]]
    for row in data.get("top_rules", []):
        rule_rows.append([
            str(row.get("primary_rule_id", "")),
            str(row.get("cnt", 0)),
        ])
    if len(rule_rows) > 1:
        t_rules = Table(rule_rows, colWidths=[12 * cm, 4 * cm])
        t_rules.setStyle(_header_style())
        story.append(t_rules)
    else:
        story.append(Paragraph("데이터 없음", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ── 탑 소스 IP ────────────────────────────────────────────────────────
    story.append(Paragraph("탑 소스 IP (Top 10)", styles["Heading2"]))
    ip_rows = [["소스 IP", "시그널 건수"]]
    for row in data.get("top_ips", []):
        ip_rows.append([
            str(row.get("source_ip", "")),
            str(row.get("cnt", 0)),
        ])
    if len(ip_rows) > 1:
        t_ips = Table(ip_rows, colWidths=[12 * cm, 4 * cm])
        t_ips.setStyle(_header_style())
        story.append(t_ips)
    else:
        story.append(Paragraph("데이터 없음", styles["Normal"]))

    doc.build(story)
    buf.seek(0)
    return buf.read()


# ────────────────────────────────────────────────────────────────────────────
# S3 업로드 헬퍼
# ────────────────────────────────────────────────────────────────────────────

def _upload_to_s3(pdf_bytes: bytes, bucket: str, key: str) -> str:
    """S3에 PDF 업로드 후 pre-signed URL 반환."""
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=pdf_bytes,
        ContentType="application/pdf",
    )
    url: str = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=3600,
    )
    return url


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@report_router.get("/weekly", summary="주간 보안 PDF 리포트 생성")
async def weekly_report(request: Request):
    """최근 7일 통계를 PDF로 생성 후 S3 저장, pre-signed URL 반환."""
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    date_to = datetime.now(timezone.utc)
    date_from = date_to - timedelta(days=7)
    period_label = f"{date_from:%Y-%m-%d} ~ {date_to:%Y-%m-%d}"

    try:
        db_pool = request.app.state.db_pool
        data = await collect_report_data(db_pool, tenant_id, date_from, date_to)
    except Exception as exc:
        log.error("collect_report_data_failed tenant=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=500, detail="데이터 수집 실패") from exc

    try:
        pdf_bytes = generate_pdf(data, period_label, tenant_id)
    except Exception as exc:
        log.error("generate_pdf_failed error=%s", exc)
        raise HTTPException(status_code=500, detail="PDF 생성 실패") from exc

    settings = request.app.state.settings
    bucket: str = settings.s3_bucket
    key = f"reports/{tenant_id}/weekly_{date_to:%Y%m%d}.pdf"

    try:
        url = await asyncio.to_thread(_upload_to_s3, pdf_bytes, bucket, key)
    except Exception as exc:
        log.error("s3_upload_failed key=%s error=%s", key, exc)
        raise HTTPException(status_code=500, detail="S3 업로드 실패") from exc

    log.info("weekly_report_generated tenant=%s key=%s", tenant_id, key)
    return {"url": url, "key": key, "period": period_label, "tenant_id": tenant_id}


@report_router.get("/monthly", summary="월간 보안 PDF 리포트 생성")
async def monthly_report(request: Request):
    """최근 30일 통계를 PDF로 생성 후 S3 저장, pre-signed URL 반환."""
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    date_to = datetime.now(timezone.utc)
    date_from = date_to - timedelta(days=30)
    period_label = f"{date_from:%Y-%m-%d} ~ {date_to:%Y-%m-%d} (월간)"

    try:
        db_pool = request.app.state.db_pool
        data = await collect_report_data(db_pool, tenant_id, date_from, date_to)
    except Exception as exc:
        log.error("collect_report_data_failed tenant=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=500, detail="데이터 수집 실패") from exc

    try:
        pdf_bytes = generate_pdf(data, period_label, tenant_id)
    except Exception as exc:
        log.error("generate_pdf_failed error=%s", exc)
        raise HTTPException(status_code=500, detail="PDF 생성 실패") from exc

    settings = request.app.state.settings
    bucket: str = settings.s3_bucket
    key = f"reports/{tenant_id}/monthly_{date_to:%Y%m}.pdf"

    try:
        url = await asyncio.to_thread(_upload_to_s3, pdf_bytes, bucket, key)
    except Exception as exc:
        log.error("s3_upload_failed key=%s error=%s", key, exc)
        raise HTTPException(status_code=500, detail="S3 업로드 실패") from exc

    log.info("monthly_report_generated tenant=%s key=%s", tenant_id, key)
    return {"url": url, "key": key, "period": period_label, "tenant_id": tenant_id}


@report_router.get("/download/{report_id}", summary="리포트 다운로드 URL 재발급")
async def get_report_download_url(report_id: str, request: Request):
    """기존 리포트의 pre-signed URL을 재발급한다."""
    settings = request.app.state.settings
    bucket: str = settings.s3_bucket

    def _presign(key: str) -> str:
        s3 = boto3.client("s3")
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=3600,
        )

    # report_id 를 S3 키로 해석 (URL-safe base64 decode 또는 직접 키 전달)
    key = report_id  # 클라이언트가 키를 직접 전달하는 단순 버전
    try:
        url = await asyncio.to_thread(_presign, key)
    except Exception as exc:
        raise HTTPException(status_code=404, detail="리포트를 찾을 수 없습니다.") from exc

    return {"url": url, "key": key}

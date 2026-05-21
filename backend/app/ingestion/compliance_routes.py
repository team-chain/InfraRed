"""컴플라이언스 리포트 API 라우터.

엔드포인트:
  GET  /compliance/frameworks                  — 지원 프레임워크 목록
  GET  /compliance/report/{framework}          — 리포트 생성 (JSON)
  GET  /compliance/report/{framework}/pdf      — 리포트 PDF 다운로드 (v7)
  GET  /compliance/reports                     — 저장된 리포트 이력 조회
  GET  /compliance/reports/{report_id}/pdf     — 저장 리포트 PDF 다운로드 (v7)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import text

from app.config import get_settings
from app.db.connection import get_session
from app.iam.rbac_v2 import require_role
from app.workers.compliance.report import _SUPPORTED_FRAMEWORKS, ComplianceReporter

router = APIRouter(prefix="/compliance", tags=["compliance"])
log = logging.getLogger(__name__)
settings = get_settings()

_reporter = ComplianceReporter()


# ────────────────────────── 프레임워크 목록 ─────────────────────────────── #

@router.get("/frameworks")
async def list_frameworks(
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """지원하는 컴플라이언스 프레임워크 목록을 반환한다."""
    return {
        "frameworks": [
            {
                "id": "ISMS-P",
                "name": "정보보호 및 개인정보보호 관리체계 인증 (ISMS-P)",
                "region": "KR",
            },
            {
                "id": "ISO27001",
                "name": "ISO/IEC 27001 Information Security Management",
                "region": "International",
            },
            {
                "id": "PCI-DSS",
                "name": "Payment Card Industry Data Security Standard (PCI-DSS v4)",
                "region": "International",
            },
        ]
    }


# ────────────────────────── JSON 리포트 ──────────────────────────────────── #

@router.get("/report/{framework}")
async def get_compliance_report(
    framework: str,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """지정된 프레임워크에 대한 컴플라이언스 리포트를 생성·반환한다."""
    if framework not in _SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 프레임워크: {framework}. 지원 목록: {_SUPPORTED_FRAMEWORKS}",
        )

    tenant_id = claims.get("tenant_id", settings.tenant_id)

    try:
        report = await _reporter.generate_report(tenant_id, framework=framework)  # type: ignore[arg-type]
    except Exception as exc:
        log.exception("컴플라이언스 리포트 생성 실패: framework=%s", framework)
        raise HTTPException(status_code=500, detail=f"리포트 생성 실패: {exc}") from exc

    return report.to_dict()


# ────────────────────────── PDF 다운로드 (v7) ────────────────────────────── #

@router.get("/report/{framework}/pdf")
async def download_compliance_report_pdf(
    framework: str,
    claims: dict = Depends(require_role("analyst")),
) -> Response:
    """컴플라이언스 리포트를 PDF로 생성하여 다운로드한다.

    WeasyPrint가 없으면 내장 폴백 PDF 생성기를 사용한다 (pdf_report.html_to_pdf_bytes).
    """
    if framework not in _SUPPORTED_FRAMEWORKS:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 프레임워크: {framework}")

    tenant_id = claims.get("tenant_id", settings.tenant_id)

    try:
        report = await _reporter.generate_report(tenant_id, framework=framework)  # type: ignore[arg-type]
    except Exception as exc:
        log.exception("컴플라이언스 리포트 생성 실패: framework=%s", framework)
        raise HTTPException(status_code=500, detail=f"리포트 생성 실패: {exc}") from exc

    html = _build_compliance_html(report.to_dict())

    try:
        from app.workers.report.pdf_report import html_to_pdf_bytes  # noqa: PLC0415
        pdf_bytes = html_to_pdf_bytes(html, title=f"InfraRed Compliance Report — {framework}")
    except Exception as exc:
        log.exception("PDF 변환 실패")
        raise HTTPException(status_code=500, detail=f"PDF 변환 실패: {exc}") from exc

    date_str = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    filename = f"infrared_compliance_{framework}_{date_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ────────────────────────── 저장 리포트 이력 ─────────────────────────────── #

@router.get("/reports")
async def list_compliance_reports(
    framework: str = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """저장된 컴플라이언스 리포트 이력을 반환한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)

    try:
        where = "tenant_id = :tid"
        params: dict = {"tid": tenant_id}
        if framework:
            where += " AND framework = :fw"
            params["fw"] = framework

        params["limit"] = limit
        sql = text(
            f"SELECT id, framework, score_pct, generated_at "  # noqa: S608
            f"FROM compliance_reports WHERE {where} "
            f"ORDER BY generated_at DESC LIMIT :limit"
        )
        async with get_session() as session:
            rows = (await session.execute(sql, params)).mappings().all()

        return {
            "tenant_id": tenant_id,
            "count": len(rows),
            "reports": [
                {
                    "id": r["id"],
                    "framework": r["framework"],
                    "score_pct": r["score_pct"],
                    "generated_at": r["generated_at"].isoformat()
                    if hasattr(r["generated_at"], "isoformat") else str(r["generated_at"]),
                }
                for r in rows
            ],
        }
    except Exception as exc:
        log.warning("compliance_reports 조회 실패: %s", exc)
        return {"tenant_id": tenant_id, "count": 0, "reports": []}


@router.get("/reports/{report_id}/pdf")
async def download_saved_report_pdf(
    report_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> Response:
    """저장된 리포트 ID로 PDF를 다운로드한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)

    try:
        sql = text(
            "SELECT framework, report_data, generated_at "
            "FROM compliance_reports "
            "WHERE id = :rid AND tenant_id = :tid LIMIT 1"
        )
        async with get_session() as session:
            row = (await session.execute(sql, {"rid": report_id, "tid": tenant_id})).mappings().first()
    except Exception as exc:
        log.warning("compliance_reports 조회 실패: %s", exc)
        row = None

    if not row:
        raise HTTPException(status_code=404, detail="리포트를 찾을 수 없습니다.")

    framework = row["framework"]
    report_data = (
        row["report_data"]
        if isinstance(row["report_data"], dict)
        else json.loads(row["report_data"])
    )
    html = _build_compliance_html(report_data)

    try:
        from app.workers.report.pdf_report import html_to_pdf_bytes  # noqa: PLC0415
        pdf_bytes = html_to_pdf_bytes(html, title=f"InfraRed Compliance Report — {framework}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF 변환 실패: {exc}") from exc

    gen_at = row["generated_at"]
    date_str = gen_at.strftime("%Y%m%d") if hasattr(gen_at, "strftime") else "unknown"
    filename = f"infrared_compliance_{framework}_{date_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ────────────────────────── HTML 증적 빌더 ───────────────────────────────── #

def _build_compliance_html(report_data: dict) -> str:
    """컴플라이언스 리포트 딕셔너리에서 HTML 증적 리포트를 생성한다."""
    framework = report_data.get("framework", "Unknown")
    tenant_id = report_data.get("tenant_id", "")
    score_pct = report_data.get("score_pct", 0.0)
    generated_at = report_data.get("generated_at", "")
    items = report_data.get("items", [])

    status_counts: dict[str, int] = {"pass": 0, "fail": 0, "partial": 0, "not_applicable": 0}
    for item in items:
        s = item.get("status", "not_applicable")
        status_counts[s] = status_counts.get(s, 0) + 1

    rows_html = ""
    for item in items:
        status = item.get("status", "not_applicable")
        color = {
            "pass": "#22c55e",
            "fail": "#ef4444",
            "partial": "#f59e0b",
            "not_applicable": "#94a3b8",
        }.get(status, "#94a3b8")
        badge = (
            f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:12px">{status.upper()}</span>'
        )
        rows_html += (
            f"<tr>"
            f'<td style="padding:8px;border-bottom:1px solid #e2e8f0;font-family:monospace">'
            f'{item.get("control_id","")}</td>'
            f'<td style="padding:8px;border-bottom:1px solid #e2e8f0">{item.get("title","")}</td>'
            f'<td style="padding:8px;border-bottom:1px solid #e2e8f0;text-align:center">{badge}</td>'
            f'<td style="padding:8px;border-bottom:1px solid #e2e8f0;font-size:13px;color:#64748b">'
            f'{item.get("evidence","")}</td>'
            f"</tr>"
        )

    return (
        "<!DOCTYPE html>\n<html lang='ko'>\n<head>\n"
        "<meta charset='UTF-8'>\n"
        f"<title>InfraRed Compliance Report — {framework}</title>\n"
        "<style>"
        "body{font-family:'Segoe UI',Arial,sans-serif;margin:40px;color:#1e293b}"
        "h1{color:#dc2626}"
        ".meta{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin-bottom:24px}"
        ".score{font-size:48px;font-weight:700;color:#dc2626}"
        "table{width:100%;border-collapse:collapse;margin-top:16px}"
        "th{background:#f1f5f9;padding:10px 8px;text-align:left;font-size:13px;color:#475569}"
        "tr:hover{background:#f8fafc}"
        ".summary{display:flex;gap:16px;margin:16px 0}"
        ".badge{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600}"
        "</style>\n</head>\n<body>\n"
        "<h1>InfraRed — Compliance Evidence Report</h1>\n"
        "<div class='meta'>"
        f"<p><strong>Framework:</strong> {framework}</p>"
        f"<p><strong>Tenant:</strong> {tenant_id}</p>"
        f"<p><strong>Generated:</strong> {generated_at}</p>"
        f"<p><strong>Overall Score:</strong> <span class='score'>{score_pct:.1f}%</span></p>"
        "</div>\n"
        "<div class='summary'>"
        f"<span class='badge' style='background:#dcfce7;color:#166534'>PASS: {status_counts['pass']}</span>"
        f"<span class='badge' style='background:#fee2e2;color:#991b1b'>FAIL: {status_counts['fail']}</span>"
        f"<span class='badge' style='background:#fef9c3;color:#854d0e'>PARTIAL: {status_counts['partial']}</span>"
        f"<span class='badge' style='background:#f1f5f9;color:#64748b'>N/A: {status_counts['not_applicable']}</span>"
        "</div>\n"
        "<table>\n<thead><tr>"
        "<th>Control ID</th><th>Title</th><th>Status</th><th>Evidence</th>"
        "</tr></thead>\n"
        f"<tbody>{rows_html}</tbody>\n</table>\n"
        "<p style='margin-top:32px;font-size:12px;color:#94a3b8'>"
        "Generated by InfraRed Security Platform — Confidential</p>\n"
        "</body>\n</html>"
    )

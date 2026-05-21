"""Phase 4-D: 주간/월간 PDF 리포트 생성.

설계서 4-D:
- PDF 생성: WeasyPrint (서버 사이드 HTML → PDF)
- 저장: S3 업로드 후 다운로드 링크 제공
- 이메일: SendGrid Free Plan (리포트 메일)
  - Critical 보안 알림은 여전히 AWS SES 유지
- 스케줄: 매주 월요일 09:00 / 매월 1일 09:00 자동 생성
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text

from app.common.logging import get_logger
from app.config import get_settings
from app.db.connection import get_session
from app.redis_kv.client import get_redis

REPORT_CACHE_TTL = 86400  # 24시간

log = get_logger(__name__)


# ============================================================
# HTML 템플릿 (인라인)
# ============================================================

_REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>InfraRed 보안 리포트</title>
<style>
  body {{ font-family: 'Noto Sans KR', sans-serif; color: #333; margin: 40px; }}
  h1 {{ color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 10px; }}
  h2 {{ color: #2c3e50; margin-top: 30px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
  th {{ background: #2c3e50; color: white; padding: 8px 12px; text-align: left; }}
  td {{ border: 1px solid #ddd; padding: 8px 12px; }}
  tr:nth-child(even) {{ background: #f8f9fa; }}
  .critical {{ color: #e74c3c; font-weight: bold; }}
  .high {{ color: #e67e22; font-weight: bold; }}
  .medium {{ color: #f1c40f; }}
  .info {{ color: #3498db; }}
  .stat-box {{ display: inline-block; background: #f8f9fa; border: 1px solid #ddd;
               border-radius: 8px; padding: 15px 25px; margin: 10px; text-align: center; }}
  .stat-number {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
  .stat-label {{ font-size: 14px; color: #7f8c8d; }}
  .footer {{ margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px;
             font-size: 12px; color: #7f8c8d; }}
</style>
</head>
<body>
<h1>🔴 InfraRed 보안 관제 리포트</h1>
<p><strong>기간:</strong> {period_start} ~ {period_end}</p>
<p><strong>테넌트:</strong> {tenant_id}</p>
<p><strong>생성일:</strong> {generated_at}</p>

<h2>📊 요약 통계</h2>
<div>
  <div class="stat-box">
    <div class="stat-number">{total_incidents}</div>
    <div class="stat-label">전체 인시던트</div>
  </div>
  <div class="stat-box">
    <div class="stat-number critical">{critical_incidents}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-box">
    <div class="stat-number high">{high_incidents}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-box">
    <div class="stat-number">{resolved_incidents}</div>
    <div class="stat-label">해결됨</div>
  </div>
  <div class="stat-box">
    <div class="stat-number">{fp_count}</div>
    <div class="stat-label">오탐(FP)</div>
  </div>
</div>

<h2>🚨 심각도별 인시던트</h2>
<table>
  <tr><th>심각도</th><th>건수</th><th>비율</th></tr>
  {severity_rows}
</table>

<h2>📋 룰별 탐지 현황</h2>
<table>
  <tr><th>룰 ID</th><th>탐지 건수</th><th>FP 비율</th><th>상태</th></tr>
  {rule_rows}
</table>

<h2>🔍 주요 인시던트 (Top 10)</h2>
<table>
  <tr><th>인시던트 ID</th><th>심각도</th><th>소스 IP</th><th>상태</th><th>생성일</th></tr>
  {incident_rows}
</table>

<div class="footer">
  <p>본 리포트는 InfraRed 보안 관제 플랫폼에서 자동 생성되었습니다.</p>
  <p>문의: security@infrared.local</p>
</div>
</body>
</html>"""


# ============================================================
# 리포트 데이터 수집
# ============================================================

async def collect_report_data(
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
) -> dict:
    """리포트 데이터 수집."""
    async with get_session() as session:
        # 전체 통계
        stats_result = await session.execute(
            text("""
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE severity = 'info') as info,
                    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed')) as resolved,
                    COUNT(*) FILTER (WHERE disposition = 'false_positive') as fp_count,
                    COUNT(*) FILTER (WHERE disposition = 'true_positive') as tp_count
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at BETWEEN :start AND :end
            """),
            {"tenant_id": tenant_id, "start": period_start, "end": period_end},
        )
        stats = dict(stats_result.mappings().fetchone() or {})

        # 룰별 통계
        rule_result = await session.execute(
            text("""
                SELECT
                    primary_rule_id as rule_id,
                    COUNT(*) as count,
                    ROUND(
                        COUNT(*) FILTER (WHERE disposition = 'false_positive')::numeric
                        / NULLIF(COUNT(*) FILTER (WHERE disposition IS NOT NULL), 0) * 100, 1
                    ) as fp_rate
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at BETWEEN :start AND :end
                  AND primary_rule_id IS NOT NULL
                GROUP BY primary_rule_id
                ORDER BY count DESC
                LIMIT 20
            """),
            {"tenant_id": tenant_id, "start": period_start, "end": period_end},
        )
        rule_stats = [dict(r) for r in rule_result.mappings().fetchall()]

        # 주요 인시던트 Top 10
        top_result = await session.execute(
            text("""
                SELECT incident_id, severity, source_ip::text, status, created_at
                FROM incidents
                WHERE tenant_id = :tenant_id
                  AND created_at BETWEEN :start AND :end
                  AND severity IN ('critical', 'high')
                ORDER BY
                    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                    created_at DESC
                LIMIT 10
            """),
            {"tenant_id": tenant_id, "start": period_start, "end": period_end},
        )
        top_incidents = [dict(r) for r in top_result.mappings().fetchall()]

    return {
        "stats": stats,
        "rule_stats": rule_stats,
        "top_incidents": top_incidents,
    }


# ============================================================
# HTML → PDF 변환
# ============================================================

def generate_pdf_bytes(
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    data: dict,
) -> bytes:
    """WeasyPrint로 HTML → PDF 변환."""
    stats = data["stats"]
    rule_stats = data["rule_stats"]
    top_incidents = data["top_incidents"]

    # 심각도 행
    severity_rows = ""
    total = int(stats.get("total", 0)) or 1
    for sev, key in [("critical", "critical"), ("high", "high"), ("medium", "medium"), ("info", "info")]:
        count = int(stats.get(key, 0))
        pct = round(count / total * 100, 1)
        severity_rows += f'<tr><td class="{sev}">{sev.upper()}</td><td>{count}</td><td>{pct}%</td></tr>'

    # 룰별 행
    rule_rows = ""
    for r in rule_stats:
        fp_rate = r.get("fp_rate")
        fp_str = f"{fp_rate}%" if fp_rate is not None else "데이터 부족"
        review = " ⚠️ 검토 권장" if fp_rate and float(fp_rate) >= 30 else ""
        rule_rows += (
            f'<tr><td>{r.get("rule_id", "")}</td>'
            f'<td>{r.get("count", 0)}</td>'
            f'<td>{fp_str}{review}</td>'
            f'<td>Active</td></tr>'
        )

    # 인시던트 행
    incident_rows = ""
    for inc in top_incidents:
        created = inc.get("created_at")
        date_str = created.strftime("%Y-%m-%d %H:%M") if isinstance(created, datetime) else str(created)
        sev = inc.get("severity", "")
        incident_rows += (
            f'<tr><td>{inc.get("incident_id", "")[:16]}...</td>'
            f'<td class="{sev}">{sev.upper()}</td>'
            f'<td>{inc.get("source_ip") or "-"}</td>'
            f'<td>{inc.get("status", "")}</td>'
            f'<td>{date_str}</td></tr>'
        )

    html = _REPORT_HTML_TEMPLATE.format(
        tenant_id=tenant_id,
        period_start=period_start.strftime("%Y-%m-%d"),
        period_end=period_end.strftime("%Y-%m-%d"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total_incidents=stats.get("total", 0),
        critical_incidents=stats.get("critical", 0),
        high_incidents=stats.get("high", 0),
        resolved_incidents=stats.get("resolved", 0),
        fp_count=stats.get("fp_count", 0),
        severity_rows=severity_rows,
        rule_rows=rule_rows,
        incident_rows=incident_rows,
    )

    try:
        from weasyprint import HTML  # noqa: PLC0415
        pdf_bytes = HTML(string=html).write_pdf()
        return pdf_bytes
    except ImportError:
        # WeasyPrint 미설치 시 HTML 바이트 반환 (개발용)
        log.warning("weasyprint_not_installed - using built-in simple PDF fallback")
        return _simple_pdf_bytes(
            _report_plain_text(tenant_id, period_start, period_end, data)
        )


# ============================================================
# S3 업로드
# ============================================================

def _report_plain_text(
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    data: dict,
) -> list[str]:
    """Build a compact text version for the no-WeasyPrint PDF fallback."""
    stats = data.get("stats", {})
    rule_stats = data.get("rule_stats", [])
    top_incidents = data.get("top_incidents", [])

    lines = [
        "InfraRed Security Report",
        f"Tenant: {tenant_id}",
        f"Period: {period_start:%Y-%m-%d} ~ {period_end:%Y-%m-%d}",
        f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
        "",
        "Summary",
        f"- Total incidents: {stats.get('total', 0)}",
        f"- Critical: {stats.get('critical', 0)}",
        f"- High: {stats.get('high', 0)}",
        f"- Resolved: {stats.get('resolved', 0)}",
        f"- False positives: {stats.get('fp_count', 0)}",
        "",
        "Severity",
    ]

    total = int(stats.get("total", 0)) or 1
    for severity in ("critical", "high", "medium", "info"):
        count = int(stats.get(severity, 0))
        pct = round(count / total * 100, 1)
        lines.append(f"- {severity.upper()}: {count} ({pct}%)")

    lines.extend(["", "Rules"])
    if rule_stats:
        for row in rule_stats[:10]:
            fp_rate = row.get("fp_rate")
            fp_text = f"{fp_rate}%" if fp_rate is not None else "n/a"
            lines.append(
                f"- {row.get('rule_id') or 'unknown'}: "
                f"{row.get('count', 0)} incidents, FP {fp_text}"
            )
    else:
        lines.append("- No rule data")

    lines.extend(["", "Top Incidents"])
    if top_incidents:
        for inc in top_incidents[:10]:
            created_at = inc.get("created_at")
            if isinstance(created_at, datetime):
                created_text = f"{created_at:%Y-%m-%d %H:%M}"
            else:
                created_text = str(created_at or "-")
            lines.append(
                f"- {inc.get('incident_id')}: {inc.get('severity')} "
                f"{inc.get('source_ip') or '-'} {inc.get('status')} {created_text}"
            )
    else:
        lines.append("- No critical or high incidents")

    return lines


def html_to_pdf_bytes(html_content: str, title: str = "InfraRed Report") -> bytes:
    """범용 HTML → PDF 변환 함수 (v7 ComplianceReport 등에서 사용).

    WeasyPrint가 설치된 경우 사용하고, 없으면 내장 폴백 PDF를 반환한다.

    Args:
        html_content: 완전한 HTML 문자열 (<!DOCTYPE html> 포함).
        title: PDF 메타데이터 제목 (폴백 PDF 첫 줄 사용).

    Returns:
        PDF 바이트.
    """
    try:
        from weasyprint import HTML  # noqa: PLC0415
        return HTML(string=html_content).write_pdf()
    except ImportError:
        log.warning("weasyprint_not_installed — falling back to simple PDF for: %s", title)
        import re  # noqa: PLC0415
        # HTML 태그 제거 후 텍스트만 추출
        text = re.sub(r"<[^>]+>", " ", html_content)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:52]
        return _simple_pdf_bytes([title, ""] + lines)
    except Exception as exc:
        log.error("html_to_pdf_bytes failed: %s", exc)
        return _simple_pdf_bytes([title, f"PDF 생성 실패: {exc}"])


def _pdf_escape(text_value: object) -> str:
    text = str(text_value)
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _simple_pdf_bytes(lines: list[str]) -> bytes:
    """Return a minimal single-page PDF with built-in Helvetica text."""
    content = ["BT", "/F1 11 Tf", "50 790 Td", "14 TL"]
    for idx, line in enumerate(lines[:52]):
        if idx:
            content.append("T*")
        content.append(f"({_pdf_escape(line)}) Tj")
    content.append("ET")
    stream = "\n".join(content).encode("utf-8")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 4 0 R >> >> "
            b"/Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj_num, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(pdf)


async def upload_to_s3(
    pdf_bytes: bytes,
    tenant_id: str,
    report_type: str,
    period_start: datetime,
) -> Optional[str]:
    """S3에 리포트 업로드. S3 키 반환."""
    import asyncio  # noqa: PLC0415
    settings = get_settings()

    if not settings.s3_bucket:
        return None

    s3_key = (
        f"reports/{tenant_id}/{report_type}/"
        f"{period_start.strftime('%Y%m')}_report.pdf"
    )

    def _upload():
        import boto3  # noqa: PLC0415
        s3 = boto3.client(
            "s3",
            region_name=settings.s3_region,
            aws_access_key_id=settings.aws_access_key_id or None,
            aws_secret_access_key=settings.aws_secret_access_key or None,
        )
        s3.put_object(
            Bucket=settings.s3_bucket,
            Key=s3_key,
            Body=pdf_bytes,
            ContentType="application/pdf",
        )
        return s3_key

    try:
        return await asyncio.to_thread(_upload)
    except Exception as exc:
        log.error("s3_upload_failed", error=str(exc))
        return None


async def get_s3_download_url(s3_key: str) -> Optional[str]:
    """S3 pre-signed URL 생성 (24시간 유효)."""
    import asyncio  # noqa: PLC0415
    settings = get_settings()

    if not settings.s3_bucket:
        return None

    def _presign():
        import boto3  # noqa: PLC0415
        s3 = boto3.client("s3", region_name=settings.s3_region)
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.s3_bucket, "Key": s3_key},
            ExpiresIn=86400,
        )

    try:
        return await asyncio.to_thread(_presign)
    except Exception:
        return None


# ============================================================
# SendGrid 이메일 발송 (리포트 메일 전용)
# ============================================================

async def send_report_email(
    to_email: str,
    tenant_id: str,
    report_type: str,
    period_start: datetime,
    download_url: Optional[str],
    stats: dict,
) -> bool:
    """SendGrid로 리포트 이메일 발송.

    설계서: Critical 보안 알림은 AWS SES 유지, 리포트 메일만 SendGrid.
    """
    import asyncio  # noqa: PLC0415
    settings = get_settings()

    if not settings.sendgrid_api_key:
        log.warning("sendgrid_api_key_not_set - skipping report email")
        return False

    period_label = "주간" if report_type == "weekly" else "월간"

    subject = (
        f"[InfraRed] {period_label} 보안 리포트 - "
        f"{period_start.strftime('%Y년 %m월')}"
    )
    body = (
        f"안녕하세요,\n\n"
        f"InfraRed {period_label} 보안 관제 리포트가 준비되었습니다.\n\n"
        f"📊 요약:\n"
        f"- 전체 인시던트: {stats.get('total', 0)}건\n"
        f"- Critical: {stats.get('critical', 0)}건\n"
        f"- High: {stats.get('high', 0)}건\n"
        f"- 해결됨: {stats.get('resolved', 0)}건\n"
        f"- 오탐(FP): {stats.get('fp_count', 0)}건\n\n"
    )

    if download_url:
        body += f"📥 리포트 다운로드:\n{download_url}\n\n(링크 유효 기간: 24시간)\n"

    body += "\nInfraRed 보안 관제 플랫폼"

    def _send():
        import sendgrid  # noqa: PLC0415
        from sendgrid.helpers.mail import Mail  # noqa: PLC0415

        message = Mail(
            from_email=settings.report_email_from,
            to_emails=to_email,
            subject=subject,
            plain_text_content=body,
        )
        sg = sendgrid.SendGridAPIClient(api_key=settings.sendgrid_api_key)
        response = sg.send(message)
        return response.status_code < 300

    try:
        return await asyncio.to_thread(_send)
    except Exception as exc:
        log.error("sendgrid_send_failed", error=str(exc))
        return False


# ============================================================
# 리포트 생성 메인 함수
# ============================================================

async def generate_and_store_report(
    tenant_id: str,
    report_type: str = "weekly",
) -> dict:
    """리포트 생성 → S3 업로드 → 이메일 발송 → DB 저장."""
    now = datetime.now(timezone.utc)

    if report_type == "weekly":
        period_end = now
        period_start = now - timedelta(days=7)
    else:  # monthly
        period_end = now
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    log.info("report_generation_started", tenant_id=tenant_id, type=report_type)

    # 데이터 수집
    data = await collect_report_data(tenant_id, period_start, period_end)

    # PDF 생성
    pdf_bytes = generate_pdf_bytes(tenant_id, period_start, period_end, data)

    # S3 업로드 (S3_BUCKET 설정 시)
    s3_key = await upload_to_s3(pdf_bytes, tenant_id, report_type, period_start)
    download_url = await get_s3_download_url(s3_key) if s3_key else None

    # 이메일 발송
    email_sent = False
    async with get_session() as session:
        email_result = await session.execute(
            text("SELECT report_email_to FROM tenant_settings WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        email_row = email_result.fetchone()
        report_email = email_row[0] if email_row else None

    if report_email:
        email_sent = await send_report_email(
            to_email=report_email,
            tenant_id=tenant_id,
            report_type=report_type,
            period_start=period_start,
            download_url=download_url,
            stats=data["stats"],
        )

    # DB 저장
    async with get_session() as session:
        result = await session.execute(
            text("""
                INSERT INTO report_history
                    (tenant_id, report_type, period_start, period_end,
                     s3_key, download_url, email_sent, generated_at)
                VALUES
                    (:tenant_id, :report_type, :period_start, :period_end,
                     :s3_key, :download_url, :email_sent, :generated_at)
                RETURNING id::text
            """),
            {
                "tenant_id": tenant_id,
                "report_type": report_type,
                "period_start": period_start,
                "period_end": period_end,
                "s3_key": s3_key,
                "download_url": download_url,
                "email_sent": email_sent,
                "generated_at": now,
            },
        )
        report_id = result.scalar()
        await session.commit()

    # S3 없는 환경: Redis에 PDF 캐시 (report_id 키, 24시간)
    if not s3_key and report_id:
        try:
            redis = await get_redis()
            await redis.set(f"report:pdf:{report_id}", pdf_bytes, ex=REPORT_CACHE_TTL)
            log.info("report_cached_in_redis", report_id=report_id)
        except Exception as exc:
            log.warning("report_redis_cache_failed", error=str(exc))

    log.info(
        "report_generated",
        tenant_id=tenant_id,
        report_id=report_id,
        s3_key=s3_key,
        email_sent=email_sent,
    )

    return {
        "report_id": report_id,
        "report_type": report_type,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "download_url": download_url,
        "email_sent": email_sent,
        "stats": data["stats"],
    }

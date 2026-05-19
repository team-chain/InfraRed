"""Phase 5: 엔터프라이즈 기능 API.

5-A: 자연어 검색 (NL2SQL 안전 파라미터 방식)
5-B: Slack / Teams 알림 연동
5-C: 설정 백업/복원
5-D: Prometheus 메트릭 고도화

엔드포인트:
  POST /search/natural          - 자연어 인시던트 검색
  POST /notify/slack            - Slack 알림 테스트
  POST /notify/teams            - Teams 알림 테스트
  GET  /config/backup           - 설정 export
  POST /config/restore          - 설정 import
  GET  /config/backup/history   - 백업 이력
  GET  /reports                 - 리포트 목록
  POST /reports/generate        - 리포트 즉시 생성
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log
from app.iam.rbac_v2 import require_role
from app.redis_kv.client import get_redis
from app.common.logging import get_logger

router = APIRouter(tags=["enterprise"])
log = get_logger(__name__)

# ============================================================
# Phase 5-A: 자연어 검색
# ============================================================

# 허용 검색 파라미터 (설계서 5-A)
_ALLOWED_SEARCH_PARAMS = {
    "rule_id", "severity", "source_ip", "status", "disposition",
    "date_from", "date_to", "asset_id", "assignee_id", "mitre_technique",
}

_SEVERITY_VALUES = {"info", "medium", "high", "critical"}
_STATUS_VALUES = {"open", "acknowledged", "in_progress", "contained", "resolved", "closed"}
_DISPOSITION_VALUES = {"true_positive", "false_positive", "benign", "duplicate"}


class NaturalSearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=500)
    limit: int = Field(default=20, ge=1, le=100)


def _parse_natural_query(query: str, tenant_id: str) -> dict:
    """자연어 쿼리를 안전한 파라미터로 변환.

    설계서 5-A: NL2SQL 직접 생성 방식 금지 (SQL 인젝션 위험).
    AI가 구조화된 파라미터만 반환하고 서버에서 안전한 쿼리 실행.
    """
    query_lower = query.lower()
    params: dict = {}

    # 날짜 파싱
    if "오늘" in query_lower or "today" in query_lower:
        params["date_from"] = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0).isoformat()
    elif "어제" in query_lower or "yesterday" in query_lower:
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        params["date_from"] = yesterday.replace(hour=0, minute=0, second=0).isoformat()
        params["date_to"] = yesterday.replace(hour=23, minute=59, second=59).isoformat()
    elif "지난주" in query_lower or "last week" in query_lower:
        params["date_from"] = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    elif "지난달" in query_lower or "last month" in query_lower:
        params["date_from"] = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    # 심각도 파싱
    for sev in _SEVERITY_VALUES:
        if sev in query_lower or sev.upper() in query:
            params["severity"] = sev
            break

    # 상태 파싱
    for status in _STATUS_VALUES:
        if status.replace("_", " ") in query_lower or status in query_lower:
            params["status"] = status
            break

    # 미해결 관련
    if "미해결" in query or "open" in query_lower or "미처리" in query:
        params["status"] = "open"

    # SSH 공격 패턴
    if "ssh" in query_lower or "brute" in query_lower or "무차별" in query:
        params["rule_id"] = "AUTH-001"

    # 오탐
    if "오탐" in query or "false positive" in query_lower:
        params["disposition"] = "false_positive"

    # 날짜 범위 최대 90일 제한
    if "date_from" in params:
        try:
            df = datetime.fromisoformat(params["date_from"])
            min_date = datetime.now(timezone.utc) - timedelta(days=90)
            if df < min_date:
                params["date_from"] = min_date.isoformat()
        except Exception:
            pass

    # tenant_id 강제 주입 (RBAC 우회 방지)
    params["tenant_id"] = tenant_id

    return params


async def _execute_safe_search(params: dict, limit: int) -> list[dict]:
    """파라미터 기반 안전한 인시던트 검색."""
    tenant_id = params.get("tenant_id")
    where_clauses = ["i.tenant_id = :tenant_id"]
    bind_params: dict = {"tenant_id": tenant_id, "limit": limit}

    for param, column, values in [
        ("rule_id", "i.primary_rule_id", None),
        ("severity", "i.severity", _SEVERITY_VALUES),
        ("status", "i.status", _STATUS_VALUES),
        ("disposition", "i.disposition", _DISPOSITION_VALUES),
        ("source_ip", "i.source_ip::text", None),
        ("asset_id", "i.asset_id", None),
        ("assignee_id", "i.assignee_id", None),
        ("mitre_technique", "i.mitre_technique", None),
    ]:
        val = params.get(param)
        if val is not None:
            # enum 검증
            if values and val not in values:
                continue
            where_clauses.append(f"{column} = :{param}")
            bind_params[param] = val

    if "date_from" in params:
        try:
            where_clauses.append("i.created_at >= :date_from")
            bind_params["date_from"] = datetime.fromisoformat(params["date_from"])
        except Exception:
            pass

    if "date_to" in params:
        try:
            where_clauses.append("i.created_at <= :date_to")
            bind_params["date_to"] = datetime.fromisoformat(params["date_to"])
        except Exception:
            pass

    async with get_session() as session:
        result = await session.execute(
            text(f"""
                SELECT i.incident_id, i.severity, i.status, i.disposition,
                       i.primary_rule_id, i.source_ip::text, i.mitre_tactic,
                       i.mitre_technique, i.assignee_id, i.created_at
                FROM incidents i
                WHERE {' AND '.join(where_clauses)}
                ORDER BY i.created_at DESC
                LIMIT :limit
            """),
            bind_params,
        )
        rows = result.mappings().fetchall()

    return [
        {
            "incident_id": r["incident_id"],
            "severity": r["severity"],
            "status": r["status"],
            "disposition": r["disposition"],
            "rule_id": r["primary_rule_id"],
            "source_ip": r["source_ip"],
            "mitre_tactic": r["mitre_tactic"],
            "mitre_technique": r["mitre_technique"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@router.post("/search/natural")
async def natural_language_search(
    payload: NaturalSearchRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """자연어 인시던트 검색.

    설계서 5-A: 검색 편의 기능 전용. 권한 우회 수단 아님.
    모든 결과는 RBAC 필터 후 반환.

    예: "지난주 SSH 공격" → { rule_id: 'AUTH-001', date_from: '...' }
    """
    tenant_id = claims["tenant_id"]

    # 파라미터 추출 (안전한 방식)
    search_params = _parse_natural_query(payload.query, tenant_id)
    search_params["tenant_id"] = tenant_id  # RBAC 강제

    items = await _execute_safe_search(search_params, payload.limit)

    return {
        "query": payload.query,
        "parsed_params": {k: v for k, v in search_params.items() if k != "tenant_id"},
        "items": items,
        "count": len(items),
    }


# ============================================================
# Phase 5-B: Slack / Teams 알림
# ============================================================

class NotificationTestRequest(BaseModel):
    message: str = Field(default="InfraRed 알림 테스트입니다.", max_length=500)


async def send_slack_notification(webhook_url: str, message: str, incident: Optional[dict] = None) -> bool:
    """Slack Incoming Webhook + Block Kit UI 알림."""
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔴 InfraRed 보안 알림"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": message}
        }
    ]

    if incident:
        severity = incident.get("severity", "").upper()
        severity_emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📢", "INFO": "ℹ️"}.get(severity, "🔔")
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*심각도:* {severity_emoji} {severity}"},
                {"type": "mrkdwn", "text": f"*룰 ID:* {incident.get('rule_id', '-')}"},
                {"type": "mrkdwn", "text": f"*소스 IP:* {incident.get('source_ip', '-')}"},
                {"type": "mrkdwn", "text": f"*상태:* {incident.get('status', '-')}"},
            ]
        })

    payload = {"blocks": blocks}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=payload)
            return response.status_code == 200
    except Exception as exc:
        log.error("slack_send_failed", error=str(exc))
        return False


async def send_teams_notification(webhook_url: str, message: str, incident: Optional[dict] = None) -> bool:
    """Microsoft Teams Incoming Webhook 알림."""
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": "InfraRed 보안 알림",
        "sections": [
            {
                "activityTitle": "🔴 InfraRed 보안 알림",
                "activityText": message,
            }
        ]
    }

    if incident:
        card["sections"].append({
            "facts": [
                {"name": "심각도", "value": incident.get("severity", "-").upper()},
                {"name": "룰 ID", "value": incident.get("rule_id", "-")},
                {"name": "소스 IP", "value": incident.get("source_ip", "-")},
                {"name": "상태", "value": incident.get("status", "-")},
            ]
        })

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=card)
            return response.status_code == 200
    except Exception as exc:
        log.error("teams_send_failed", error=str(exc))
        return False


@router.post("/notify/slack/test")
async def test_slack_notification(
    payload: NotificationTestRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """Slack 알림 테스트."""
    from app.config import get_settings  # noqa: PLC0415
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("SELECT slack_webhook_url FROM tenant_settings WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        row = result.fetchone()
        webhook_url = row[0] if row else None

    if not webhook_url:
        raise HTTPException(status_code=400, detail="Slack 웹훅 URL이 설정되지 않았습니다")

    success = await send_slack_notification(webhook_url, payload.message)
    return {"sent": success}


@router.post("/notify/teams/test")
async def test_teams_notification(
    payload: NotificationTestRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """Teams 알림 테스트."""
    tenant_id = claims["tenant_id"]

    async with get_session() as session:
        result = await session.execute(
            text("SELECT teams_webhook_url FROM tenant_settings WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        row = result.fetchone()
        webhook_url = row[0] if row else None

    if not webhook_url:
        raise HTTPException(status_code=400, detail="Teams 웹훅 URL이 설정되지 않았습니다")

    success = await send_teams_notification(webhook_url, payload.message)
    return {"sent": success}


# ============================================================
# Phase 5-C: 설정 백업/복원
# ============================================================

_BACKUP_TARGETS = ["rules", "policies", "allowlist", "suppressions", "maintenance_windows"]


async def _export_config(tenant_id: str) -> dict:
    """설정 export. rules / policies / allowlist / suppressions / mw."""
    async with get_session() as session:
        rules_result = await session.execute(
            text("""
                SELECT rule_id, display_name, name, source, enabled, status,
                       severity, window_seconds, threshold, scope, config
                FROM detection_rules
                WHERE tenant_id = :tid OR tenant_id IS NULL
            """),
            {"tid": tenant_id},
        )
        rules = [dict(r) for r in rules_result.mappings().fetchall()]

        policies_result = await session.execute(
            text("SELECT * FROM tenant_settings WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        policies = dict(policies_result.mappings().fetchone() or {})

        allowlist_result = await session.execute(
            text("SELECT entry_type, value, description FROM allowlist_entries WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        allowlist = [dict(r) for r in allowlist_result.mappings().fetchall()]

        sup_result = await session.execute(
            text("""
                SELECT rule_id, asset_id, source_ip::text, username, expires_at, reason
                FROM suppressions WHERE tenant_id = :tid AND enabled = true
            """),
            {"tid": tenant_id},
        )
        suppressions = [dict(r) for r in sup_result.mappings().fetchall()]

        mw_result = await session.execute(
            text("""
                SELECT name, start_at, end_at, recurrence, affected_rules, affected_assets, reason
                FROM maintenance_windows WHERE tenant_id = :tid AND enabled = true
            """),
            {"tid": tenant_id},
        )
        maintenance_windows = [dict(r) for r in mw_result.mappings().fetchall()]

    return {
        "version": "2.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "rules": rules,
        "policies": policies,
        "allowlist": allowlist,
        "suppressions": suppressions,
        "maintenance_windows": maintenance_windows,
    }


@router.get("/config/backup")
async def export_config(
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """설정 export (rules / policies / allowlist / suppressions / mw)."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    config = await _export_config(tenant_id)

    # 백업 이력 저장
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO config_backup_history
                    (tenant_id, backup_type, snapshot, created_by)
                VALUES (:tenant_id, 'manual', CAST(:snapshot AS JSONB), :created_by)
            """),
            {
                "tenant_id": tenant_id,
                "snapshot": json.dumps(config, default=str),
                "created_by": user_id,
            },
        )
        await session.commit()

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="config.export", resource="all"
    )
    return config


@router.post("/config/restore")
async def import_config(
    config: dict,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """설정 import. 기존 설정은 S3에 자동 백업 후 덮어쓰기."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    # 버전 확인
    if config.get("version") != "2.0":
        raise HTTPException(status_code=400, detail="지원하지 않는 설정 버전입니다")

    # 현재 설정 자동 백업
    current_config = await _export_config(tenant_id)
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO config_backup_history
                    (tenant_id, backup_type, snapshot, created_by)
                VALUES (:tenant_id, 'pre_import', CAST(:snapshot AS JSONB), :created_by)
            """),
            {
                "tenant_id": tenant_id,
                "snapshot": json.dumps(current_config, default=str),
                "created_by": user_id,
            },
        )
        await session.commit()

    results = {"imported": [], "errors": []}

    # Allowlist 복원
    if "allowlist" in config:
        try:
            async with get_session() as session:
                await session.execute(
                    text("DELETE FROM allowlist_entries WHERE tenant_id = :tid"),
                    {"tid": tenant_id},
                )
                for entry in config["allowlist"]:
                    await session.execute(
                        text("""
                            INSERT INTO allowlist_entries (tenant_id, entry_type, value, description)
                            VALUES (:tid, :entry_type, :value, :description)
                            ON CONFLICT DO NOTHING
                        """),
                        {
                            "tid": tenant_id,
                            "entry_type": entry.get("entry_type", "ip"),
                            "value": entry.get("value", ""),
                            "description": entry.get("description"),
                        },
                    )
                await session.commit()
            results["imported"].append("allowlist")
        except Exception as exc:
            results["errors"].append(f"allowlist: {str(exc)}")

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="config.import",
        resource="all", metadata={"results": results},
    )
    return results


@router.get("/config/backup/history")
async def list_backup_history(
    limit: int = Query(default=20, ge=1, le=100),
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """설정 백업 이력."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, backup_type, created_by, created_at
                FROM config_backup_history
                WHERE tenant_id = :tenant_id
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"tenant_id": tenant_id, "limit": limit},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": r["id"],
                "backup_type": r["backup_type"],
                "created_by": r["created_by"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


# ============================================================
# 리포트 관련
# ============================================================

@router.get("/reports")
async def list_reports(
    limit: int = Query(default=20, ge=1, le=100),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """리포트 이력 목록."""
    tenant_id = claims["tenant_id"]
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT id::text, report_type, period_start, period_end,
                       download_url, email_sent, generated_at
                FROM report_history
                WHERE tenant_id = :tenant_id
                ORDER BY generated_at DESC
                LIMIT :limit
            """),
            {"tenant_id": tenant_id, "limit": limit},
        )
        rows = result.mappings().fetchall()

    return {
        "items": [
            {
                "id": r["id"],
                "report_type": r["report_type"],
                "period_start": r["period_start"].isoformat() if r["period_start"] else None,
                "period_end": r["period_end"].isoformat() if r["period_end"] else None,
                "download_url": r["download_url"],
                "email_sent": r["email_sent"],
                "generated_at": r["generated_at"].isoformat() if r["generated_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    claims: dict = Depends(require_role("analyst")),
) -> Response:
    """리포트 다운로드 (S3 presigned URL 또는 Redis 캐시에서 직접 서빙)."""
    tenant_id = claims["tenant_id"]

    # DB에서 리포트 메타 조회
    async with get_session() as session:
        row = await session.execute(
            text("""
                SELECT report_type, period_start, download_url, s3_key
                FROM report_history
                WHERE id::text = :report_id AND tenant_id = :tenant_id
            """),
            {"report_id": report_id, "tenant_id": tenant_id},
        )
        report = row.fetchone()

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report_type, period_start, download_url, s3_key = report

    # S3 presigned URL이 있으면 리다이렉트
    if download_url:
        from fastapi.responses import RedirectResponse  # noqa: PLC0415
        return RedirectResponse(url=download_url)

    # Redis 캐시에서 PDF 서빙
    try:
        redis = await get_redis()
        pdf_bytes = await redis.get(f"report:pdf:{report_id}")
    except Exception:
        pdf_bytes = None

    if not pdf_bytes:
        raise HTTPException(
            status_code=404,
            detail="Report file not available. S3를 연결하거나 보고서를 다시 생성하세요.",
        )

    date_str = period_start.strftime('%Y%m%d') if period_start else "unknown"
    filename = f"infrared_{report_type}_report_{date_str}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/reports/{report_id}")
async def delete_report(
    report_id: str,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """보고서 삭제 (DB 기록 + S3 오브젝트)."""
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])
    async with get_session() as session:
        result = await session.execute(
            text("""
                DELETE FROM report_history
                WHERE id::text = :report_id AND tenant_id = :tenant_id
                RETURNING id::text, s3_key
            """),
            {"report_id": report_id, "tenant_id": tenant_id},
        )
        row = result.mappings().fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다")

    # S3 오브젝트 삭제 (있으면)
    if row.get("s3_key"):
        try:
            import boto3  # noqa: PLC0415
            s3 = boto3.client("s3")
            from app.config import get_settings  # noqa: PLC0415
            s3.delete_object(Bucket=get_settings().s3_bucket, Key=row["s3_key"])
        except Exception:
            pass  # S3 삭제 실패해도 DB 삭제는 유지

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="report.delete",
        resource=report_id, metadata={},
    )
    return {"deleted": row["id"]}


@router.post("/reports/generate")
async def generate_report(
    report_type: str = Query(default="weekly", pattern="^(weekly|monthly)$"),
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """리포트 즉시 생성."""
    from app.workers.report.pdf_report import generate_and_store_report  # noqa: PLC0415
    tenant_id = claims["tenant_id"]
    user_id = str(claims["sub"])

    result = await generate_and_store_report(tenant_id, report_type)

    await write_audit_log(
        tenant_id=tenant_id, actor=user_id, action="report.generate",
        resource=report_type, metadata={"report_id": result.get("report_id")},
    )
    return result

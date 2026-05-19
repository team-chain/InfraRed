"""Tamper Detection 보고 API (v3.0 설계서).

엔드포인트:
  POST /api/v1/tamper-report  — 에이전트 워치독이 Tamper 이벤트를 서버에 직접 보고

인증: 기존 verify_agent_token (JWT role=agent)
저장: watchdog_events 테이블
SSE:  publish_incident_event() 로 대시보드에 즉시 Push
알림: Discord Critical 알림 발송
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.security import verify_agent_token
from app.ingestion.sse_routes import publish_incident_event
from app.dispatcher.discord import send_discord_alert
from app.config import get_settings

router = APIRouter(prefix="/api/v1", tags=["tamper"])
log = logging.getLogger(__name__)


class TamperReport(BaseModel):
    agent_id: str
    event_type: str  # agent_unexpectedly_stopped / log_file_truncated / log_file_deleted
    severity: str = "CRITICAL"
    mitre: str = ""
    detail: dict = {}


@router.post("/tamper-report", status_code=202)
async def receive_tamper_report(
    report: TamperReport,
    agent_info: dict = Depends(verify_agent_token),
) -> dict:
    """에이전트 워치독 Tamper 이벤트 수신.

    1. JWT에서 tenant_id 추출, agent_id 일치 검증
    2. watchdog_events 테이블에 INSERT
    3. SSE 채널에 tamper_detected 이벤트 발행
    4. Discord Critical 알림 발송
    """
    tenant_id: str = agent_info["tenant_id"]
    token_agent_id: str | None = agent_info.get("agent_id")

    # 토큰의 agent_id와 보고된 agent_id 일치 검증
    if token_agent_id and token_agent_id != report.agent_id:
        raise HTTPException(status_code=403, detail="agent_id_mismatch")

    now = datetime.now(timezone.utc)

    # watchdog_events 테이블에 INSERT
    async with get_session() as session:
        result = await session.execute(
            text("""
                INSERT INTO watchdog_events
                    (tenant_id, agent_id, event_type, severity, mitre, detail, reported_at)
                VALUES (:tenant_id, :agent_id, :event_type, :severity, :mitre,
                        CAST(:detail AS JSONB), :reported_at)
                RETURNING id
            """),
            {
                "tenant_id": tenant_id,
                "agent_id": report.agent_id,
                "event_type": report.event_type,
                "severity": report.severity,
                "mitre": report.mitre or None,
                "detail": json.dumps(report.detail),
                "reported_at": now,
            },
        )
        row = result.mappings().fetchone()
        await session.commit()

    event_id = str(row["id"]) if row else None
    log.warning(
        "tamper_event_received agent_id=%s event_type=%s severity=%s tenant=%s id=%s",
        report.agent_id, report.event_type, report.severity, tenant_id, event_id,
    )

    # SSE 즉시 Push (대시보드 실시간 알림)
    await publish_incident_event(
        tenant_id=tenant_id,
        event_type="tamper_detected",
        data={
            "watchdog_event_id": event_id,
            "agent_id": report.agent_id,
            "event_type": report.event_type,
            "severity": report.severity,
            "mitre": report.mitre,
            "detail": report.detail,
            "reported_at": now.isoformat(),
        },
    )

    # Discord Critical 알림 발송
    settings = get_settings()
    discord_url = getattr(settings, "discord_webhook_url", None)
    try:
        alert_text = (
            f"\U0001f6a8 [TAMPER DETECTED] agent={report.agent_id} "
            f"type={report.event_type} severity={report.severity} "
            f"tenant={tenant_id}"
        )
        await send_discord_alert(alert_text, webhook_url=discord_url)
    except Exception as exc:
        log.warning("tamper_discord_notify_failed agent_id=%s error=%s", report.agent_id, exc)

    return {
        "accepted": True,
        "watchdog_event_id": event_id,
        "reported_at": now.isoformat(),
    }

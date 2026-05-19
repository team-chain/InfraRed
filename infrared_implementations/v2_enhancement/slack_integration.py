"""Slack / Microsoft Teams 알림 연동.

- Slack Incoming Webhook (Block Kit)
- Teams Adaptive Card (Power Automate Webhook)
- 5분 윈도우 알림 그룹핑 (Redis 기반)
- FastAPI 엔드포인트: POST /api/v1/notify/test, GET /api/v1/notify/config
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Literal, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, HttpUrl, Field

log = logging.getLogger(__name__)

notify_router = APIRouter(prefix="/api/v1/notify", tags=["notifications"])

# 그룹핑 윈도우 (초)
GROUPING_WINDOW_SECONDS = 300  # 5분
GROUPING_MAX_BATCH = 10        # 한 번에 보낼 최대 알림 수


# ────────────────────────────────────────────────────────────────────────────
# 데이터 모델
# ────────────────────────────────────────────────────────────────────────────

class AlertPayload(BaseModel):
    incident_id: str
    severity: Literal["critical", "high", "medium", "info"]
    title: str
    description: str
    source_ip: Optional[str] = None
    rule_id: Optional[str] = None
    tenant_id: str
    dashboard_url: Optional[str] = None
    created_at: Optional[datetime] = None


class NotifyTestRequest(BaseModel):
    channel: Literal["slack", "teams", "both"] = "both"
    message: str = "InfraRed 연결 테스트"


# ────────────────────────────────────────────────────────────────────────────
# Slack Block Kit 메시지 빌더
# ────────────────────────────────────────────────────────────────────────────

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "info": ":blue_circle:",
}

_SEVERITY_COLOR = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFC107",
    "info": "#2196F3",
}


def build_slack_blocks(alert: AlertPayload) -> dict[str, Any]:
    """Slack Block Kit attachment 포맷."""
    emoji = _SEVERITY_EMOJI.get(alert.severity, ":white_circle:")
    color = _SEVERITY_COLOR.get(alert.severity, "#9E9E9E")
    ts = (alert.created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} InfraRed 보안 알림",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*심각도*\n{alert.severity.upper()}"},
                {"type": "mrkdwn", "text": f"*룰 ID*\n{alert.rule_id or '-'}"},
                {"type": "mrkdwn", "text": f"*소스 IP*\n{alert.source_ip or '-'}"},
                {"type": "mrkdwn", "text": f"*발생 시각*\n{ts}"},
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{alert.title}*\n{alert.description}"},
        },
    ]

    if alert.dashboard_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "대시보드 바로가기"},
                    "url": alert.dashboard_url,
                    "style": "primary" if alert.severity in ("critical", "high") else "default",
                }
            ],
        })

    blocks.append({"type": "divider"})

    return {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
                "fallback": f"[{alert.severity.upper()}] {alert.title}",
            }
        ]
    }


def build_slack_grouped_blocks(alerts: list[AlertPayload]) -> dict[str, Any]:
    """여러 알림을 하나의 Slack 메시지로 그룹화."""
    critical_count = sum(1 for a in alerts if a.severity == "critical")
    high_count = sum(1 for a in alerts if a.severity == "high")

    rows = []
    for a in alerts[:GROUPING_MAX_BATCH]:
        emoji = _SEVERITY_EMOJI.get(a.severity, ":white_circle:")
        rows.append(f"{emoji} `{a.rule_id or '?'}` — {a.title[:60]}")

    summary = f"*{len(alerts)}건 일괄 알림 (Critical: {critical_count}, High: {high_count})*"
    body = "\n".join(rows)
    if len(alerts) > GROUPING_MAX_BATCH:
        body += f"\n... 외 {len(alerts) - GROUPING_MAX_BATCH}건"

    return {
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f":alarm: {summary}\n{body}"},
            }
        ]
    }


# ────────────────────────────────────────────────────────────────────────────
# Teams Adaptive Card 빌더
# ────────────────────────────────────────────────────────────────────────────

def build_teams_card(alert: AlertPayload) -> dict[str, Any]:
    """Microsoft Teams Adaptive Card 포맷 (Power Automate / Connector)."""
    ts = (alert.created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    severity_color = {
        "critical": "attention",
        "high": "warning",
        "medium": "accent",
        "info": "default",
    }.get(alert.severity, "default")

    card: dict[str, Any] = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "InfraRed 보안 알림",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": severity_color,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "심각도", "value": alert.severity.upper()},
                                {"title": "룰 ID", "value": alert.rule_id or "-"},
                                {"title": "소스 IP", "value": alert.source_ip or "-"},
                                {"title": "발생 시각", "value": ts},
                                {"title": "인시던트 ID", "value": alert.incident_id},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.title,
                            "weight": "Bolder",
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.description,
                            "wrap": True,
                            "color": "default",
                        },
                    ],
                    "actions": (
                        [
                            {
                                "type": "Action.OpenUrl",
                                "title": "대시보드 바로가기",
                                "url": alert.dashboard_url,
                            }
                        ]
                        if alert.dashboard_url
                        else []
                    ),
                },
            }
        ],
    }
    return card


# ────────────────────────────────────────────────────────────────────────────
# 알림 전송 함수
# ────────────────────────────────────────────────────────────────────────────

async def send_slack_alert(webhook_url: str, payload: dict[str, Any]) -> bool:
    """Slack Incoming Webhook 으로 메시지 전송."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code != 200:
                log.warning(
                    "slack_send_failed status=%d body=%s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
        log.info("slack_alert_sent")
        return True
    except httpx.TimeoutException:
        log.error("slack_send_timeout")
        return False
    except Exception as exc:
        log.error("slack_send_error error=%s", exc)
        return False


async def send_teams_alert(webhook_url: str, payload: dict[str, Any]) -> bool:
    """Teams Power Automate Webhook 으로 메시지 전송."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            # Teams 는 성공 시 200 또는 202
            if resp.status_code not in (200, 202):
                log.warning(
                    "teams_send_failed status=%d body=%s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
        log.info("teams_alert_sent")
        return True
    except httpx.TimeoutException:
        log.error("teams_send_timeout")
        return False
    except Exception as exc:
        log.error("teams_send_error error=%s", exc)
        return False


# ────────────────────────────────────────────────────────────────────────────
# 알림 그룹핑 (Redis 기반 5분 윈도우)
# ────────────────────────────────────────────────────────────────────────────

async def enqueue_alert(redis, tenant_id: str, alert: AlertPayload) -> None:
    """Redis LIST 에 알림 적재. 5분 윈도우 키 사용."""
    window_start = int(time.time() // GROUPING_WINDOW_SECONDS) * GROUPING_WINDOW_SECONDS
    key = f"notify:group:{tenant_id}:{window_start}"
    await redis.rpush(key, alert.model_dump_json())
    await redis.expire(key, GROUPING_WINDOW_SECONDS * 2)


async def flush_grouped_alerts(
    redis,
    tenant_id: str,
    slack_webhook: Optional[str],
    teams_webhook: Optional[str],
) -> int:
    """현재 윈도우 알림을 한 번에 전송. 전송한 건수 반환."""
    window_start = int(time.time() // GROUPING_WINDOW_SECONDS) * GROUPING_WINDOW_SECONDS
    key = f"notify:group:{tenant_id}:{window_start}"

    raw_items = await redis.lrange(key, 0, -1)
    if not raw_items:
        return 0

    alerts = []
    for raw in raw_items:
        try:
            alerts.append(AlertPayload.model_validate_json(raw))
        except Exception:
            pass

    if not alerts:
        return 0

    tasks = []
    if slack_webhook:
        if len(alerts) == 1:
            payload = build_slack_blocks(alerts[0])
        else:
            payload = build_slack_grouped_blocks(alerts)
        tasks.append(send_slack_alert(slack_webhook, payload))

    if teams_webhook:
        if len(alerts) == 1:
            payload_t = build_teams_card(alerts[0])
        else:
            # Teams 그룹 요약 카드 (간단 텍스트)
            payload_t = {
                "text": f"InfraRed: {len(alerts)}건 보안 알림 발생 "
                        f"(Critical: {sum(1 for a in alerts if a.severity=='critical')}, "
                        f"High: {sum(1 for a in alerts if a.severity=='high')})"
            }
        tasks.append(send_teams_alert(teams_webhook, payload_t))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        sent_count = sum(1 for r in results if r is True)
        log.info("grouped_alerts_flushed count=%d sent=%d", len(alerts), sent_count)

    # 전송 후 키 삭제
    await redis.delete(key)
    return len(alerts)


# ────────────────────────────────────────────────────────────────────────────
# 공개 API: 단일 알림 즉시 전송
# ────────────────────────────────────────────────────────────────────────────

async def dispatch_alert(
    alert: AlertPayload,
    slack_webhook: Optional[str],
    teams_webhook: Optional[str],
    group: bool = False,
    redis=None,
) -> dict[str, bool]:
    """알림 전송 진입점. group=True 면 Redis 큐에 적재."""
    if group and redis:
        await enqueue_alert(redis, alert.tenant_id, alert)
        return {"queued": True}

    results: dict[str, bool] = {}
    tasks = []
    labels = []

    if slack_webhook:
        tasks.append(send_slack_alert(slack_webhook, build_slack_blocks(alert)))
        labels.append("slack")

    if teams_webhook:
        tasks.append(send_teams_alert(teams_webhook, build_teams_card(alert)))
        labels.append("teams")

    if tasks:
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for label, outcome in zip(labels, outcomes):
            results[label] = outcome is True
    else:
        log.warning("dispatch_alert_no_webhooks_configured")

    return results


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@notify_router.post("/test", summary="Slack/Teams 연결 테스트")
async def test_notification(body: NotifyTestRequest, request: Request):
    """설정된 Webhook 으로 테스트 메시지를 전송한다."""
    settings = request.app.state.settings

    slack_url: Optional[str] = getattr(settings, "slack_webhook_url", None)
    teams_url: Optional[str] = getattr(settings, "teams_webhook_url", None)

    test_alert = AlertPayload(
        incident_id="TEST-000",
        severity="info",
        title="InfraRed 연결 테스트",
        description=body.message,
        tenant_id=request.headers.get("X-Tenant-ID", "global"),
        created_at=datetime.now(timezone.utc),
    )

    results: dict[str, Any] = {}

    if body.channel in ("slack", "both") and slack_url:
        results["slack"] = await send_slack_alert(
            slack_url, build_slack_blocks(test_alert)
        )
    elif body.channel in ("slack", "both"):
        results["slack"] = "not_configured"

    if body.channel in ("teams", "both") and teams_url:
        results["teams"] = await send_teams_alert(
            teams_url, build_teams_card(test_alert)
        )
    elif body.channel in ("teams", "both"):
        results["teams"] = "not_configured"

    return {"status": "ok", "results": results}


@notify_router.get("/config", summary="알림 설정 조회")
async def get_notify_config(request: Request):
    """현재 Webhook 설정 상태를 반환한다. (URL 값은 노출하지 않음)"""
    settings = request.app.state.settings
    slack_url: Optional[str] = getattr(settings, "slack_webhook_url", None)
    teams_url: Optional[str] = getattr(settings, "teams_webhook_url", None)

    return {
        "slack": {
            "configured": bool(slack_url),
            "grouping_window_seconds": GROUPING_WINDOW_SECONDS,
        },
        "teams": {
            "configured": bool(teams_url),
            "grouping_window_seconds": GROUPING_WINDOW_SECONDS,
        },
    }


@notify_router.post("/flush", summary="그룹화된 알림 즉시 플러시")
async def flush_alerts(request: Request):
    """대기 중인 그룹 알림을 즉시 전송한다 (스케줄러 대신 수동 호출)."""
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    settings = request.app.state.settings
    redis = request.app.state.redis

    slack_url: Optional[str] = getattr(settings, "slack_webhook_url", None)
    teams_url: Optional[str] = getattr(settings, "teams_webhook_url", None)

    sent = await flush_grouped_alerts(redis, tenant_id, slack_url, teams_url)
    return {"flushed": sent}

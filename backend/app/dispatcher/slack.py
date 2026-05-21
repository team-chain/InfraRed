"""Slack webhook dispatcher.

설계서 v3 Phase 5: Slack 알림 (Discord와 동일한 정보량).
- attachments[].color 로 severity 색상 표시
- Block Kit (section / fields) 로 구조화된 메시지
- Webhook URL은 절대 로그에 남기지 않음
"""
from __future__ import annotations

from typing import Sequence

import httpx

from app.config import get_settings

_SEVERITY_COLOR = {
    "critical": "#CC2200",
    "high":     "#E07000",
    "medium":   "#D4A017",
    "info":     "#4A90D9",
}


async def send_slack_alert(text: str, *, webhook_url: str | None = None) -> bool:
    """간단 텍스트 알림 (기본/레거시 호환)."""
    url = webhook_url or get_settings().slack_webhook_url
    if not url:
        return False
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, json={"text": text})
        response.raise_for_status()
    return True


async def send_slack_ai_analysis(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    asset_name: str,
    event_type: str,
    summary: str,
    kill_chain_stage: str | None = None,
    mitre_techniques: Sequence[str] | None = None,
    manual_actions_needed: Sequence[str] | None = None,
    ai_confidence: float | None = None,
    analysis_elapsed_sec: int | None = None,
    webhook_url: str | None = None,
) -> bool:
    """AI 분석 완료 후 풍성한 Slack 알림.

    Discord의 send_discord_ai_analysis 와 동일한 정보 모델.
    """
    url = webhook_url or get_settings().slack_webhook_url
    if not url:
        return False

    sev_norm = severity.lower()
    color = _SEVERITY_COLOR.get(sev_norm, _SEVERITY_COLOR["info"])
    title = f"[{sev_norm.upper()}] {event_type} — {asset_name or 'unknown'}"

    fields: list[dict] = [
        {"title": "Incident", "value": f"`{incident_id}`", "short": True},
        {"title": "Tenant",   "value": f"`{tenant_id}`",   "short": True},
    ]
    if kill_chain_stage:
        fields.append({"title": "Kill Chain", "value": kill_chain_stage, "short": True})
    if mitre_techniques:
        fields.append({
            "title": "MITRE ATT&CK",
            "value": ", ".join(f"`{t}`" for t in mitre_techniques[:6]),
            "short": True,
        })
    if ai_confidence is not None:
        fields.append({
            "title": "AI Confidence",
            "value": f"{ai_confidence * 100:.0f}%",
            "short": True,
        })
    if analysis_elapsed_sec is not None:
        fields.append({
            "title": "Analysis Time",
            "value": f"{analysis_elapsed_sec}s",
            "short": True,
        })
    if manual_actions_needed:
        fields.append({
            "title": "Recommended Actions (manual)",
            "value": "\n".join(f"• {a}" for a in list(manual_actions_needed)[:5]) or "—",
            "short": False,
        })

    # Slack의 attachment 모델 — 사이드바 색상 + 풍부한 필드
    payload = {
        "text": title,  # fallback for notifications
        "attachments": [{
            "color": color,
            "title": title,
            "text": summary[:2000],
            "fields": fields,
            "footer": "InfraRed Security",
            "mrkdwn_in": ["text", "fields"],
        }],
    }

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
    return True

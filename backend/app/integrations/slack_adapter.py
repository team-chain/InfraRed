"""
Slack Integration Adapter - Block Kit 기반 인시던트 알림.
v4.0 설계서 §10 참조.
"""
from __future__ import annotations
import logging
from app.integrations.base import NotificationAdapter, IncidentPayload

logger = logging.getLogger(__name__)

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class SlackAdapter(NotificationAdapter):
    adapter_type = "slack"

    SEVERITY_EMOJI = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"
    }

    async def send_incident(self, incident: IncidentPayload, config: dict) -> bool:
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            logger.error("Slack webhook_url not configured")
            return False

        emoji = self.SEVERITY_EMOJI.get(incident.severity, "⚪")
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {incident.severity} — {incident.display_name}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*자산:* {incident.asset_hostname}"},
                    {"type": "mrkdwn", "text": f"*공격자 IP:* {incident.source_ip}"},
                    {"type": "mrkdwn", "text": f"*신뢰도:* {incident.confidence_score:.0%}"},
                    {"type": "mrkdwn", "text": f"*MITRE:* {', '.join(incident.mitre_techniques) or 'N/A'}"},
                ]
            },
        ]
        if incident.ai_summary:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*AI 분석:*\n{incident.ai_summary[:500]}"}
            })
        
        actions = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "대시보드에서 보기"},
                "url": incident.dashboard_url or "https://app.infrared.io",
            }
        ]
        if incident.approval_required:
            actions.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "✅ 차단 승인"},
                "style": "danger",
                "url": f"{incident.dashboard_url}/approve-block" if incident.dashboard_url else "#",
            })
        blocks.append({"type": "actions", "elements": actions})

        return await self._post(webhook_url, {"blocks": blocks})

    async def send_test(self, config: dict) -> bool:
        webhook_url = config.get("webhook_url", "")
        payload = {"text": "✅ InfraRed Slack 연동 테스트 성공"}
        return await self._post(webhook_url, payload)

    async def _post(self, url: str, payload: dict) -> bool:
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available for Slack integration")
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False

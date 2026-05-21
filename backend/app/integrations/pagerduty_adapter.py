"""
PagerDuty Integration Adapter - CRITICAL 인시던트 → 온콜 에스컬레이션.
v4.0 설계서 §10 참조.
"""
from __future__ import annotations

import logging

from app.integrations.base import IncidentPayload, NotificationAdapter

logger = logging.getLogger(__name__)

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class PagerDutyAdapter(NotificationAdapter):
    adapter_type = "pagerduty"

    PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

    SEVERITY_MAP = {
        "CRITICAL": "critical",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "info",
    }

    async def send_incident(self, incident: IncidentPayload, config: dict) -> bool:
        integration_key = config.get("integration_key", "")
        if not integration_key:
            logger.error("PagerDuty integration_key not configured")
            return False

        severity = self.SEVERITY_MAP.get(incident.severity, "warning")

        payload = {
            "routing_key": integration_key,
            "event_action": "trigger",
            "dedup_key": incident.incident_id,
            "payload": {
                "summary": f"[InfraRed] {incident.severity} — {incident.display_name}",
                "severity": severity,
                "source": incident.asset_hostname,
                "timestamp": incident.created_at,
                "component": "infrared-detection",
                "group": incident.scenario_id or incident.asset_hostname,
                "class": "security_incident",
                "custom_details": {
                    "source_ip": incident.source_ip,
                    "asset": f"{incident.asset_hostname} ({incident.asset_type})",
                    "confidence": f"{incident.confidence_score:.0%}",
                    "mitre": ", ".join(incident.mitre_techniques),
                    "ai_analysis": incident.ai_summary[:500] if incident.ai_summary else "",
                    "dashboard_url": incident.dashboard_url,
                }
            },
            "links": [
                {"href": incident.dashboard_url, "text": "InfraRed 대시보드"}
            ] if incident.dashboard_url else [],
        }

        return await self._post(payload)

    async def resolve_incident(self, incident_id: str, integration_key: str) -> bool:
        """인시던트 해결 시 PagerDuty 알림 해제"""
        payload = {
            "routing_key": integration_key,
            "event_action": "resolve",
            "dedup_key": incident_id,
        }
        return await self._post(payload)

    async def send_test(self, config: dict) -> bool:
        integration_key = config.get("integration_key", "")
        payload = {
            "routing_key": integration_key,
            "event_action": "trigger",
            "dedup_key": "infrared-test-001",
            "payload": {
                "summary": "[InfraRed] PagerDuty 연동 테스트",
                "severity": "info",
                "source": "infrared-test",
            }
        }
        result = await self._post(payload)
        if result:
            # 즉시 해결 처리
            await self.resolve_incident("infrared-test-001", integration_key)
        return result

    async def _post(self, payload: dict) -> bool:
        if not AIOHTTP_AVAILABLE:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.PD_EVENTS_URL,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status in (200, 202):
                        return True
                    text = await resp.text()
                    logger.error(f"PagerDuty error {resp.status}: {text[:200]}")
                    return False
        except Exception as e:
            logger.error(f"PagerDuty send failed: {e}")
            return False

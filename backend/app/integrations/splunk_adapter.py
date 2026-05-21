"""
Splunk HEC (HTTP Event Collector) Adapter.
인시던트/시그널 → 기업 SIEM 실시간 전송.
v4.0 설계서 §10.3 참조.
"""
from __future__ import annotations

import logging
import time

from app.integrations.base import IncidentPayload, NotificationAdapter

logger = logging.getLogger(__name__)

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class SplunkHECAdapter(NotificationAdapter):
    adapter_type = "splunk"

    async def send_incident(self, incident: IncidentPayload, config: dict) -> bool:
        hec_url = config.get("hec_url", "")
        hec_token = config.get("hec_token", "")
        index = config.get("index", "main")
        verify_ssl = config.get("verify_ssl", True)

        if not all([hec_url, hec_token]):
            logger.error("Splunk HEC config incomplete")
            return False

        event = {
            "time": time.time(),
            "host": incident.asset_hostname,
            "source": "infrared",
            "sourcetype": "infrared:incident",
            "index": index,
            "event": {
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "display_name": incident.display_name,
                "scenario_id": incident.scenario_id,
                "source_ip": incident.source_ip,
                "asset_type": incident.asset_type,
                "asset_environment": incident.asset_environment,
                "confidence_score": incident.confidence_score,
                "mitre_techniques": incident.mitre_techniques,
                "ai_summary": incident.ai_summary[:1000] if incident.ai_summary else "",
                "dashboard_url": incident.dashboard_url,
                "created_at": incident.created_at,
            }
        }

        return await self._post(hec_url, hec_token, event, verify_ssl)

    async def send_test(self, config: dict) -> bool:
        hec_url = config.get("hec_url", "")
        hec_token = config.get("hec_token", "")
        event = {
            "time": time.time(),
            "source": "infrared",
            "sourcetype": "infrared:test",
            "event": {"message": "InfraRed Splunk HEC 연동 테스트", "status": "ok"}
        }
        return await self._post(hec_url, hec_token, event, config.get("verify_ssl", True))

    async def _post(self, hec_url: str, hec_token: str, event: dict, verify_ssl: bool) -> bool:
        if not AIOHTTP_AVAILABLE:
            return False
        try:
            collector_url = f"{hec_url.rstrip('/')}/services/collector"
            connector = aiohttp.TCPConnector(ssl=verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    collector_url,
                    headers={"Authorization": f"Splunk {hec_token}"},
                    json=event,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return True
                    text = await resp.text()
                    logger.error(f"Splunk HEC error {resp.status}: {text[:200]}")
                    return False
        except Exception as e:
            logger.error(f"Splunk HEC send failed: {e}")
            return False

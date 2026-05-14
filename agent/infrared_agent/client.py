"""HTTP client for ingestion and heartbeat."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from infrared_agent import __version__
from infrared_agent.config import AgentSettings


class AgentClient:
    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self._client = httpx.AsyncClient(timeout=10)

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.agent_token}"}

    async def close(self) -> None:
        await self._client.aclose()

    async def send_event(self, envelope: dict[str, Any]) -> None:
        response = await self._client.post(
            self.settings.backend_url,
            headers=self._headers,
            json=envelope,
        )
        response.raise_for_status()

    async def send_heartbeat(
        self,
        last_event_id: str | None = None,
        status: str = "online",
        deactivation_reason: str | None = None,
    ) -> None:
        """Heartbeat 전송.

        설계서 v2.0 Phase 3-D:
        - status="online"      : 정상 Heartbeat (기본값)
        - status="deactivated" : StartLimitBurst(5회) 초과 종료 직전 최종 보고
        """
        payload: dict = {
            "tenant_id": self.settings.tenant_id,
            "agent_id": self.settings.agent_id,
            "asset_id": self.settings.asset_id,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "agent_version": __version__,
            "pending_buffered_events": 0,
            "last_event_id": last_event_id,
            "status": status,
        }
        if deactivation_reason:
            payload["deactivation_reason"] = deactivation_reason
        response = await self._client.post(
            self.settings.heartbeat_url,
            headers=self._headers,
            json=payload,
        )
        response.raise_for_status()

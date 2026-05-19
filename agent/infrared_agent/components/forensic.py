"""Agent Forensic 컴포넌트 — v7.0 설계서

역할: 인시던트 발생 시 증거 수집 + S3 Object Lock 업로드 (루트 권한)
통신: UDS server ← collector (포렌식 요청 수신)

네트워크 접근: S3 업로드만 허용 (인바운드 없음).
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from infrared_agent.component_bridge import (
    MSG_ACK,
    MSG_ERROR,
    MSG_FORENSIC_REQ,
    UDSServer,
)
from infrared_agent.config import AgentSettings
from infrared_agent.forensic_collector import ForensicCollector

log = logging.getLogger("infrared.forensic")


class ForensicComponent:
    """
    최소 권한: CAP_DAC_READ_SEARCH (임의 파일 읽기), S3 Put 권한
    systemd: infrared-forensic.service
    """

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.collector = ForensicCollector(settings)
        self._server = UDSServer("forensic", self._handle_message)

    async def _handle_message(
        self, msg: dict[str, Any]
    ) -> dict[str, Any] | None:
        msg_type = msg.get("type")

        if msg_type != MSG_FORENSIC_REQ:
            return {"type": MSG_ERROR, "reason": f"unknown message type: {msg_type}"}

        incident_id = msg.get("incident_id", "unknown")
        target_paths = msg.get("target_paths", [])

        log.info(
            "forensic_collection_started incident_id=%s paths=%d",
            incident_id, len(target_paths),
        )

        try:
            result = await self.collector.collect_and_upload(
                incident_id=incident_id,
                target_paths=target_paths,
            )
            log.info("forensic_collection_done incident_id=%s", incident_id)
            return {"type": MSG_ACK, "result": result}
        except Exception as exc:
            log.exception("forensic_collection_failed incident_id=%s", incident_id)
            return {"type": MSG_ERROR, "reason": str(exc)}

    async def start(self) -> None:
        log.info("forensic_component_starting pid=%d uid=%d", os.getpid(), os.getuid())
        await self._server.start()
        await self._server._server.serve_forever()

    async def stop(self) -> None:
        await self._server.stop()
        log.info("forensic_component_stopped")


def main() -> None:
    settings = AgentSettings()
    forensic = ForensicComponent(settings)
    asyncio.run(forensic.start())


if __name__ == "__main__":
    main()

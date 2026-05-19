"""Agent Collector 컴포넌트 — v7.0 설계서

역할: 로그 수집 + backend 전송 (비특권)
통신:
  - UDS server ← sensor (이벤트 수신)
  - UDS client → responder (명령 전달)
  - UDS client → forensic (포렌식 요청)
  - UDS client → updater  (업데이트 확인)
  - HTTP/mTLS → backend   (이벤트 전송 + heartbeat + 명령 폴링)

설계 원칙:
  1. 네트워크 권한 有, 파일 시스템 특권 無
  2. sensor/responder/forensic/updater와 UDS로 통신
  3. backend에서 명령 수신 시 responder로 위임
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from infrared_agent.client import AgentClient
from infrared_agent.component_bridge import (
    MSG_ACK,
    MSG_ERROR,
    MSG_EVENT,
    ComponentBridge,
    UDSServer,
)
from infrared_agent.config import AgentSettings

log = logging.getLogger("infrared.collector")


class CollectorComponent:
    """
    비특권 컴포넌트: 로그/이벤트 수집 → backend 전송.
    systemd: infrared-collector.service (User=infrared-agent)

    UDS 서버로 sensor의 이벤트를 수신하고, backend로 전달.
    ComponentBridge를 통해 responder/forensic/updater에 명령/요청 위임.
    """

    HEARTBEAT_INTERVAL = 30.0       # 초
    COMMAND_POLL_INTERVAL = 5.0     # 초
    UPDATE_CHECK_INTERVAL = 86400.0 # 24시간

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.client = AgentClient(settings)
        self.bridge = ComponentBridge()
        self._server = UDSServer("collector", self._handle_sensor_event)

        self._last_heartbeat: float = 0.0
        self._last_command_poll: float = 0.0
        self._last_update_check: float = 0.0
        self._last_event_id: str | None = None
        self._current_version = getattr(settings, "agent_version", "0.0.0")

    async def _handle_sensor_event(
        self, msg: dict[str, Any]
    ) -> dict[str, Any] | None:
        """sensor에서 수신한 이벤트를 backend로 전달."""
        msg_type = msg.get("type")

        if msg_type != MSG_EVENT:
            log.warning("collector_unknown_msg_type type=%s", msg_type)
            return {"type": MSG_ERROR, "reason": f"unknown message type: {msg_type}"}

        event = msg.get("payload", {})
        # event_id가 없으면 생성
        if not event.get("event_id"):
            event["event_id"] = f"SENSOR-{uuid.uuid4().hex[:12]}"

        try:
            await self.client.send_event(event)
            self._last_event_id = event["event_id"]
            log.debug(
                "collector_event_forwarded rule_id=%s event_id=%s",
                event.get("rule_id"),
                event["event_id"],
            )
            return {"type": MSG_ACK, "event_id": event["event_id"]}
        except Exception as exc:
            log.exception("collector_event_forward_failed event_id=%s", event.get("event_id"))
            return {"type": MSG_ERROR, "reason": str(exc)}

    async def _heartbeat_loop(self) -> None:
        """주기적으로 backend에 heartbeat 전송."""
        while True:
            now = time.monotonic()
            if now - self._last_heartbeat >= self.HEARTBEAT_INTERVAL:
                try:
                    await self.client.send_heartbeat(last_event_id=self._last_event_id)
                    self._last_heartbeat = now
                    log.debug("collector_heartbeat_sent")
                except Exception:
                    log.exception("collector_heartbeat_failed")
            await asyncio.sleep(5.0)

    async def _command_poll_loop(self) -> None:
        """backend에서 명령을 폴링하여 responder로 위임."""
        while True:
            now = time.monotonic()
            if now - self._last_command_poll >= self.COMMAND_POLL_INTERVAL:
                try:
                    commands = await self.client.poll_commands()
                    for cmd in (commands or []):
                        await self._dispatch_command(cmd)
                    self._last_command_poll = now
                except Exception:
                    log.exception("collector_command_poll_failed")
            await asyncio.sleep(1.0)

    async def _dispatch_command(self, cmd: dict[str, Any]) -> None:
        """backend 명령을 적절한 컴포넌트로 라우팅."""
        cmd_type = cmd.get("type") or cmd.get("command")
        log.info("collector_dispatching_command cmd=%s", cmd_type)

        forensic_commands = {"collect_forensics", "start_forensic_collection"}
        if cmd_type in forensic_commands:
            result = await self.bridge.request_forensic_collection(
                incident_id=cmd.get("incident_id", str(uuid.uuid4())),
                target_paths=cmd.get("target_paths", []),
            )
            log.info("collector_forensic_result result=%s", result)
        else:
            # 나머지는 responder로 전달 (block_ip, lock_account 등)
            result = await self.bridge.send_command_to_responder(cmd)
            log.info("collector_responder_result cmd=%s result=%s", cmd_type, result)

        # backend에 결과 보고
        try:
            await self.client.report_command_result(
                command_id=cmd.get("command_id", ""),
                result=result,
            )
        except Exception:
            log.exception("collector_command_result_report_failed")

    async def _update_check_loop(self) -> None:
        """주기적으로 업데이트 가능 여부 확인 후 backend에 보고."""
        while True:
            now = time.monotonic()
            if now - self._last_update_check >= self.UPDATE_CHECK_INTERVAL:
                try:
                    result = await self.bridge.check_for_update(self._current_version)
                    if result.get("update_available"):
                        log.info(
                            "collector_update_available current=%s latest=%s",
                            self._current_version,
                            result.get("latest_version"),
                        )
                    self._last_update_check = now
                except Exception:
                    log.exception("collector_update_check_failed")
            await asyncio.sleep(60.0)

    async def start(self) -> None:
        log.info(
            "collector_component_starting pid=%d uid=%d version=%s",
            os.getpid(), os.getuid(), self._current_version,
        )

        # 다른 컴포넌트들과 UDS 연결
        await self.bridge.connect_all()
        log.info("collector_bridge_connected")

        # UDS 서버 시작 (sensor 이벤트 수신)
        await self._server.start()

        # 백그라운드 루프 시작
        tasks = [
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._command_poll_loop(), name="cmd_poll"),
            asyncio.create_task(self._update_check_loop(), name="update_check"),
        ]

        try:
            await self._server._server.serve_forever()
        finally:
            for task in tasks:
                task.cancel()
            await self.bridge.close_all()
            await self._server.stop()
            try:
                await self.client.close()
            except Exception:
                pass

    async def stop(self) -> None:
        await self._server.stop()
        await self.bridge.close_all()
        log.info("collector_component_stopped")


def main() -> None:
    settings = AgentSettings()
    collector = CollectorComponent(settings)
    asyncio.run(collector.start())


if __name__ == "__main__":
    main()

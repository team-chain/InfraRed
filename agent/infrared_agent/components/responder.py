"""Agent Responder 컴포넌트 — v7.0 설계서

역할: iptables 차단, SSH 키 주입(JIT SSH) 등 특권 명령 실행 (루트 권한)
통신: UDS server ← collector (명령 수신)

네트워크 접근 없음. 명령 실행만 담당.
HMAC 서명이 없는 명령은 거부.
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
    MSG_COMMAND,
    MSG_ERROR,
    UDSServer,
)
from infrared_agent.commander import Commander
from infrared_agent.config import AgentSettings

log = logging.getLogger("infrared.responder")

# 허용된 명령 목록 (설계서 v7.0 §4.3 RESPONDER_ALLOWED_COMMANDS + v8.0 신규)
ALLOWED_COMMANDS = frozenset({
    "block_ip",
    "unblock_ip",
    "lock_account",
    "unlock_account",
    "kill_process",
    "isolate_server",
    "unisolate_server",
    # v8.0 신규
    "inject_temp_ssh_key",
    "revoke_temp_ssh_key",
})


class ResponderComponent:
    """
    최소 권한: CAP_NET_ADMIN (iptables), CAP_SETUID (계정 잠금)
    systemd: infrared-responder.service (User=root, CapabilityBoundingSet)

    UDS 서버로 collector의 명령을 수신하고 실행.
    """

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.commander = Commander(settings, client=None)  # 네트워크 없음
        self._server = UDSServer("responder", self._handle_message)

    async def _handle_message(
        self, msg: dict[str, Any]
    ) -> dict[str, Any] | None:
        msg_type = msg.get("type")

        if msg_type != MSG_COMMAND:
            log.warning("responder_unknown_msg_type type=%s", msg_type)
            return {"type": MSG_ERROR, "reason": f"unknown message type: {msg_type}"}

        payload = msg.get("payload", {})
        command_name = payload.get("command") or payload.get("cmd")

        if command_name not in ALLOWED_COMMANDS:
            log.warning("responder_rejected_command command=%s", command_name)
            return {
                "type": MSG_ERROR,
                "reason": f"command not allowed: {command_name}",
            }

        log.info("responder_executing command=%s", command_name)
        try:
            result = await self.commander.execute_command_direct(payload)
            return {"type": MSG_ACK, "result": result}
        except Exception as exc:
            log.exception("responder_command_failed command=%s", command_name)
            return {"type": MSG_ERROR, "reason": str(exc)}

    async def start(self) -> None:
        log.info("responder_component_starting pid=%d uid=%d", os.getpid(), os.getuid())
        await self._server.start()
        # TTL 만료 루프도 함께 실행
        ttl_task = asyncio.create_task(self.commander.ttl_expiry_loop())
        try:
            await self._server._server.serve_forever()
        finally:
            ttl_task.cancel()
            await self._server.stop()

    async def stop(self) -> None:
        await self._server.stop()
        log.info("responder_component_stopped")


def main() -> None:
    settings = AgentSettings()
    responder = ResponderComponent(settings)
    asyncio.run(responder.start())


if __name__ == "__main__":
    main()

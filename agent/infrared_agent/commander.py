"""역방향 명령 채널 — 백엔드에서 보낸 명령을 수신하고 실행."""
from __future__ import annotations

import logging
import shlex
import subprocess

import httpx

from infrared_agent.config import AgentSettings


log = logging.getLogger("infrared_agent.commander")


class Commander:
    def __init__(self, settings: AgentSettings, client: "AgentClient") -> None:  # noqa: F821
        self.settings = settings
        self.client = client

    async def poll_and_execute(self) -> None:
        """명령 큐를 polling해서 수신된 명령을 순서대로 실행."""
        try:
            commands = await self._fetch_commands()
        except Exception as exc:
            log.debug("command_poll_failed: %s", exc)
            return

        for cmd in commands:
            await self._execute(cmd)

    async def _fetch_commands(self) -> list[dict]:
        settings = self.settings
        url = (
            f"{settings.backend_url.rstrip('/')}/commands"
            f"?asset_id={settings.asset_id}"
        )
        async with httpx.AsyncClient(timeout=5) as http:
            resp = await http.get(
                url,
                headers={"Authorization": f"Bearer {settings.agent_token}"},
            )
            resp.raise_for_status()
            return resp.json().get("commands", [])

    async def _execute(self, cmd: dict) -> None:
        action_type = cmd.get("action_type", "")
        target = cmd.get("target", "")
        success = False
        message = ""

        try:
            if action_type == "block_ip":
                success, message = self._block_ip(target)
            elif action_type == "lock_account":
                success, message = self._lock_account(target)
            elif action_type == "escalate":
                success, message = True, "escalate is handled server-side"
            else:
                success, message = False, f"unknown action_type: {action_type}"
        except Exception as exc:
            success, message = False, str(exc)

        log.info("command_executed action=%s target=%s success=%s msg=%s", action_type, target, success, message)
        await self._report_result(action_type, target, success, message)

    def _block_ip(self, ip: str) -> tuple[bool, str]:
        """iptables로 IP 차단. 이미 차단된 경우도 성공으로 처리."""
        # 입력 검증 (IPv4/IPv6 기본 패턴)
        if not ip or any(c in ip for c in [";", "&", "|", "$", "`"]):
            return False, f"invalid ip: {ip}"
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, f"blocked {ip}"
        return False, result.stderr.strip()

    def _lock_account(self, username: str) -> tuple[bool, str]:
        """passwd -l로 계정 잠금."""
        if not username or any(c in username for c in [";", "&", "|", "$", " "]):
            return False, f"invalid username: {username}"
        result = subprocess.run(
            ["passwd", "-l", username],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, f"locked {username}"
        return False, result.stderr.strip()

    async def _report_result(self, action_type: str, target: str, success: bool, message: str) -> None:
        try:
            url = f"{self.settings.backend_url.rstrip('/')}/commands/result"
            async with httpx.AsyncClient(timeout=5) as http:
                await http.post(
                    url,
                    json={
                        "action_type": action_type,
                        "target": target,
                        "success": success,
                        "message": message,
                    },
                    headers={"Authorization": f"Bearer {self.settings.agent_token}"},
                )
        except Exception as exc:
            log.debug("result_report_failed: %s", exc)

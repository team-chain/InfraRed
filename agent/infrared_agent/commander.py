"""역방향 명령 채널 — 백엔드에서 보낸 명령을 수신하고 실행."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
from datetime import datetime, timedelta

import httpx

from infrared_agent.config import AgentSettings


log = logging.getLogger("infrared_agent.commander")


class Commander:
    # TTL 기반 차단 목록: ip → expires_at (UTC)
    BLOCKED_IPS: dict[str, datetime] = {}

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
                ttl_seconds = cmd.get("ttl_seconds") or cmd.get("payload", {}).get("ttl_seconds")
                success, message = self._block_ip(target, ttl_seconds=ttl_seconds)
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

    def _block_ip(self, ip: str, ttl_seconds: int | None = None) -> tuple[bool, str]:
        """iptables로 IP 차단 (TTL 지원). 사설/루프백 IP 차단 금지."""
        # 1. 입력 검증 — ipaddress 모듈로 파싱
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"invalid ip address: {ip!r}"

        # 2. 사설/루프백 IP 차단 금지
        if addr.is_private or addr.is_loopback:
            return False, f"refusing to block private/loopback ip: {ip}"

        # 3. TTL 결정 (기본 1800초 = 30분)
        effective_ttl = int(ttl_seconds) if ttl_seconds else 1800
        expires_at = datetime.utcnow() + timedelta(seconds=effective_ttl)

        # 4. 이미 차단 중이면 TTL만 갱신
        if ip in self.BLOCKED_IPS:
            self.BLOCKED_IPS[ip] = expires_at
            log.info("block_ip_ttl_refreshed ip=%s expires_at=%s", ip, expires_at.isoformat())
            return True, f"ttl refreshed for {ip} (expires in {effective_ttl}s)"

        # 5. iptables -I INPUT 1 (최우선 삽입) + comment
        comment = f"infrared-block-ttl={effective_ttl}"
        cmd = [
            "iptables", "-I", "INPUT", "1",
            "-s", ip,
            "-j", "DROP",
            "-m", "comment", "--comment", comment,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode == 0:
            self.BLOCKED_IPS[ip] = expires_at
            log.info("block_ip_added ip=%s ttl=%ss expires_at=%s", ip, effective_ttl, expires_at.isoformat())
            return True, f"blocked {ip} for {effective_ttl}s"
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

    async def _unblock_ip(self, ip: str) -> bool:
        """iptables에서 IP 차단 해제 및 BLOCKED_IPS에서 제거."""
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10, check=False,
        )
        self.BLOCKED_IPS.pop(ip, None)
        success = result.returncode == 0
        log.info("unblock_ip ip=%s success=%s", ip, success)
        return success

    async def ttl_expiry_loop(self) -> None:
        """10초마다 만료된 IP를 자동으로 iptables에서 해제."""
        while True:
            now = datetime.utcnow()
            expired = [ip for ip, exp in list(self.BLOCKED_IPS.items()) if exp <= now]
            for ip in expired:
                log.info("ttl_expired_unblocking ip=%s", ip)
                await self._unblock_ip(ip)
            await asyncio.sleep(10)

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

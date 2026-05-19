"""역방향 명령 채널 — 백엔드에서 보낸 명령을 수신하고 실행."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import subprocess
from datetime import datetime, timedelta

import httpx

from infrared_agent.config import AgentSettings
from infrared_agent.jit_ssh import JITSSHManager


log = logging.getLogger("infrared_agent.commander")

# 절대 종료할 수 없는 안전 PID 목록
_SAFE_PIDS = {1, os.getpid()}


class Commander:
    # TTL 기반 차단 목록: ip → expires_at (UTC)
    BLOCKED_IPS: dict[str, datetime] = {}

    def __init__(self, settings: AgentSettings, client: "AgentClient") -> None:  # noqa: F821
        self.settings = settings
        self.client = client
        self.jit_ssh = JITSSHManager(report_callback=self._jit_report)

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
        payload = cmd.get("payload", {})
        success = False
        message = ""

        try:
            if action_type == "block_ip":
                ttl_seconds = cmd.get("ttl_seconds") or payload.get("ttl_seconds")
                success, message = self._block_ip(target, ttl_seconds=ttl_seconds)
            elif action_type == "lock_account":
                success, message = self._lock_account(target)
            elif action_type == "escalate":
                success, message = True, "escalate is handled server-side"
            elif action_type == "isolate_server":
                success, message = self._isolate_server(payload)
            elif action_type == "kill_process":
                success, message = self._kill_process(payload)
            elif action_type == "collect_forensics":
                success, message = await self._collect_forensics(payload)
            elif action_type == "inject_temp_ssh_key":
                result = await self.jit_ssh.inject_temp_key(cmd)
                success = result.success
                message = result.reason if not result.success else str(result.data)
            elif action_type == "revoke_temp_ssh_key":
                result = await self.jit_ssh.revoke_temp_key(cmd)
                success = result.success
                message = result.reason if not result.success else "revoked"
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

    def _isolate_server(self, payload: dict) -> tuple[bool, str]:
        """서버 격리: iptables ALL DROP (루프백 허용) + Dead Man's Switch TTL 기록.

        격리 순서:
        1. 루프백 인터페이스 트래픽은 허용 (lo)
        2. 기존 연결 상태 유지 룰 추가 (--state ESTABLISHED,RELATED)
        3. INPUT / OUTPUT 모든 트래픽 DROP
        4. Dead Man's Switch TTL 기록
        """
        incident_id = payload.get("incident_id", "unknown")
        ttl_seconds = int(payload.get("ttl_seconds", 3600))

        errors: list[str] = []

        # iptables 명령 목록: (chain, args_extra)
        rules: list[list[str]] = [
            # 루프백 허용
            ["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"],
            # 기존 ESTABLISHED/RELATED 연결 유지 (관리 세션 끊김 방지)
            ["iptables", "-I", "INPUT", "2", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "2", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            # 나머지 전부 DROP
            ["iptables", "-I", "INPUT", "3", "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "3", "-j", "DROP"],
        ]

        for rule in rules:
            result = subprocess.run(rule, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0:
                errors.append(f"{' '.join(rule[1:3])}: {result.stderr.strip()}")

        # Dead Man's Switch TTL 기록 (파일 기반 — 외부 watchdog이 주기적으로 갱신 확인)
        dms_path = "/var/lib/infrared/isolation_dms.json"
        try:
            import json
            expires_at = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
            dms_data = {
                "incident_id": incident_id,
                "isolated_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at,
                "ttl_seconds": ttl_seconds,
            }
            os.makedirs(os.path.dirname(dms_path), exist_ok=True)
            with open(dms_path, "w") as f:
                json.dump(dms_data, f)
            log.info("isolation_dms_written incident=%s expires_at=%s", incident_id, expires_at)
        except Exception as dms_exc:
            log.warning("isolation_dms_write_failed: %s", dms_exc)

        if errors:
            return False, f"isolate_server partial failure: {'; '.join(errors)}"
        log.info("server_isolated incident=%s ttl=%ss", incident_id, ttl_seconds)
        return True, f"server isolated for {ttl_seconds}s (incident={incident_id})"

    def _kill_process(self, payload: dict) -> tuple[bool, str]:
        """PID로 악성 프로세스 종료. 안전 PID(1, 현재 프로세스) 차단."""
        try:
            pid = int(payload.get("pid", 0))
        except (ValueError, TypeError):
            return False, "invalid or missing pid in payload"

        if pid <= 0:
            return False, f"invalid pid: {pid}"

        # 안전 PID 목록 차단
        if pid in _SAFE_PIDS:
            return False, f"refusing to kill protected pid: {pid}"

        # /proc/{pid} 존재 여부 확인 (프로세스 실존 검증)
        proc_path = f"/proc/{pid}"
        if not os.path.exists(proc_path):
            return False, f"process {pid} does not exist"

        try:
            os.kill(pid, signal.SIGKILL)
            log.info("kill_process_sent pid=%d incident=%s", pid, payload.get("incident_id", "unknown"))
            return True, f"SIGKILL sent to pid {pid}"
        except ProcessLookupError:
            return False, f"process {pid} not found (already exited)"
        except PermissionError:
            return False, f"permission denied to kill pid {pid}"
        except Exception as exc:
            return False, str(exc)

    async def _collect_forensics(self, payload: dict) -> tuple[bool, str]:
        """ForensicCollector.collect() 호출 후 S3 업로드."""
        try:
            from infrared_agent.forensic_collector import ForensicCollector
            tenant_id = payload.get("tenant_id", self.settings.tenant_id)
            incident_id = payload.get("incident_id", "unknown")
            asset_id = payload.get("asset_id", self.settings.asset_id)
            collector = ForensicCollector(settings=self.settings)
            bundle = await collector.collect(tenant_id=tenant_id, incident_id=incident_id, asset_id=asset_id)
            log.info(
                "forensics_collected incident=%s items=%d manifest_sig=%s",
                incident_id, len(bundle.get("items", [])), bundle.get("manifest_sig", "")[:16],
            )
            return True, f"forensics collected for incident={incident_id} items={len(bundle.get('items', []))}"
        except Exception as exc:
            log.error("collect_forensics_failed: %s", exc)
            return False, str(exc)

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

    async def _jit_report(self, event_type: str, data: dict) -> None:
        """JIT SSH 이벤트(주입/삭제)를 백엔드 audit 엔드포인트에 보고."""
        try:
            url = f"{self.settings.backend_url.rstrip('/')}/api/v1/jit-ssh/audit"
            async with httpx.AsyncClient(timeout=5) as http:
                await http.post(
                    url,
                    json={"event_type": event_type, "asset_id": self.settings.asset_id, **data},
                    headers={"Authorization": f"Bearer {self.settings.agent_token}"},
                )
        except Exception as exc:
            log.debug("jit_report_failed event=%s: %s", event_type, exc)

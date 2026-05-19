"""InfraRed Agent Watchdog — 에이전트를 독립적으로 감시.

v3.0 설계서 기반:
- 에이전트 프로세스 생존 감시 (GRACE_PERIOD 초과 시 tamper-report 전송)
- 로그 파일 무결성 감지 (auth.log/syslog truncation/deletion)
- Watchdog 전용 JWT는 WATCHDOG_TOKEN 환경변수에서 로드
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

import aiohttp

log = logging.getLogger("infrared_agent.watchdog")

WATCHDOG_JWT = os.environ.get("WATCHDOG_TOKEN", "")
SERVER_URL = os.environ.get("INFRARED_SERVER_URL", "http://localhost:8000")
AGENT_ID = os.environ.get("AGENT_ID", "")
CHECK_INTERVAL = 10   # 초
GRACE_PERIOD = 30     # 초


class AgentWatchdog:
    """에이전트 프로세스 및 로그 무결성 독립 감시자."""

    def __init__(self, server_url: str, agent_id: str, watchdog_jwt: str):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.watchdog_jwt = watchdog_jwt
        self.log_size_baseline: dict[str, int] = {}

    def _is_agent_running(self) -> bool:
        """infrared_agent 프로세스가 실행 중인지 /proc 스캔으로 확인.

        자기 자신(watchdog 프로세스)은 제외.
        """
        my_pid = str(os.getpid())
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                if pid_dir.name == my_pid:
                    continue
                try:
                    cmdline = (pid_dir / "cmdline").read_bytes().decode(errors="replace")
                    if "infrared_agent" in cmdline or "infrared-agent" in cmdline:
                        return True
                except (PermissionError, FileNotFoundError):
                    pass
        except (PermissionError, OSError):
            pass
        return False

    async def _report_tamper(
        self,
        event_type: str,
        severity: str = "CRITICAL",
        mitre: str = "",
        detail: dict | None = None,
    ) -> None:
        """Ingestion API /api/v1/tamper-report 엔드포인트로 변조 보고."""
        payload = {
            "agent_id": self.agent_id,
            "event_type": event_type,
            "severity": severity,
            "mitre": mitre,
            "detail": detail or {},
        }
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.server_url}/api/v1/tamper-report",
                    json=payload,
                    headers={"Authorization": f"Bearer {self.watchdog_jwt}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                )
            log.warning("tamper_reported event_type=%s", event_type)
        except Exception as exc:
            log.error("tamper_report_failed: %s", exc)

    async def _check_log_integrity(self) -> None:
        """auth.log / syslog 크기 감시.

        - 이전 크기의 10% 미만으로 줄어들면 truncation 경보
        - 파일이 사라지면 deletion 경보
        - 최솟값은 10 KiB 이상일 때만 경보 (소형 파일 오탐 방지)
        """
        for log_path in ["/var/log/auth.log", "/var/log/syslog"]:
            try:
                current_size = os.path.getsize(log_path)
                prev_size = self.log_size_baseline.get(log_path, current_size)
                if current_size < prev_size * 0.1 and prev_size > 10240:
                    await self._report_tamper(
                        event_type="log_file_truncated",
                        mitre="T1070.002",
                        detail={
                            "path": log_path,
                            "prev_size": prev_size,
                            "current_size": current_size,
                        },
                    )
                # 베이스라인은 최대값으로 갱신 (일반적 로테이션 이후 0→증가 패턴 구별)
                self.log_size_baseline[log_path] = max(current_size, prev_size)
            except FileNotFoundError:
                # 이전에 존재하던 파일이 사라진 경우만 경보
                if log_path in self.log_size_baseline:
                    await self._report_tamper(
                        event_type="log_file_deleted",
                        mitre="T1070.002",
                        detail={"path": log_path},
                    )

    async def run(self) -> None:
        """Watchdog 메인 루프."""
        agent_was_running = False
        stopped_at: float | None = None
        log.info("watchdog_started agent_id=%s", self.agent_id)

        while True:
            is_running = self._is_agent_running()

            if agent_was_running and not is_running:
                if stopped_at is None:
                    stopped_at = time.time()
                    log.warning("agent_process_not_found — starting grace period (%ds)", GRACE_PERIOD)
                elif time.time() - stopped_at > GRACE_PERIOD:
                    await self._report_tamper(
                        event_type="agent_unexpectedly_stopped",
                        mitre="T1562.001",
                        detail={"stopped_duration_seconds": int(time.time() - stopped_at)},
                    )
                    # 재보고 방지: 다음 주기부터 다시 추적
                    stopped_at = None
                    agent_was_running = False
            elif is_running:
                if stopped_at is not None:
                    log.info("agent_process_recovered")
                stopped_at = None
                agent_was_running = True

            await self._check_log_integrity()
            await asyncio.sleep(CHECK_INTERVAL)


def main() -> None:
    """Watchdog 독립 실행 진입점."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    watchdog = AgentWatchdog(
        server_url=SERVER_URL,
        agent_id=AGENT_ID,
        watchdog_jwt=WATCHDOG_JWT,
    )
    asyncio.run(watchdog.run())


if __name__ == "__main__":
    main()

"""Agent Sensor 컴포넌트 — v7.0 설계서

역할: /proc 스캔, FIM, 프로세스 계보 수집 (루트 권한으로 실행)
통신: UDS server → collector에 이벤트 전달

특권 작업만 담당하며, 네트워크 통신 권한 없음.
수집된 이벤트는 UDS를 통해 collector 컴포넌트로 전달.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from infrared_agent.component_bridge import (  # noqa: E402
    MSG_EVENT,
    UDSClient,
)
from infrared_agent.config import AgentSettings  # noqa: E402
from infrared_agent.fim_watcher import (  # noqa: E402
    BulkFileModificationMonitor,
    FIMWatcher,
    TmpExecutionMonitor,
    WebServerChildProcessMonitor,
)
from infrared_agent.ntp_monitor import NTPMonitor  # noqa: E402

log = logging.getLogger("infrared.sensor")


class SensorComponent:
    """
    최소 권한: CAP_SYS_PTRACE (proc 읽기), CAP_AUDIT_READ (auditd)
    systemd: infrared-sensor.service (User=root, CapabilityBoundingSet)
    """

    POLL_INTERVAL = 10  # 초

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.fim = FIMWatcher(settings)
        self.tmp_exec = TmpExecutionMonitor()
        self.webshell = WebServerChildProcessMonitor()
        self.bulk_mod = BulkFileModificationMonitor()
        # v7.0: NTP 드리프트 감시
        self.ntp_monitor = NTPMonitor(settings)

        # collector로 이벤트를 보내는 클라이언트
        self._collector_client = UDSClient("collector")

        self._last_fim_check: float = 0.0
        self._fim_interval = getattr(settings, "agent_fim_interval_seconds", 60)

    async def start(self) -> None:
        """sensor 컴포넌트 메인 루프."""
        log.info("sensor_component_starting pid=%d uid=%d", os.getpid(), os.getuid())
        await self._collector_client.connect()
        log.info("sensor_connected_to_collector")

        while True:
            import time
            now = time.monotonic()
            events = []

            # FIM 감시 (60초 간격)
            if now - self._last_fim_check >= self._fim_interval:
                try:
                    changes = self.fim.check_changes()
                    events.extend(changes)
                    self._last_fim_check = now
                except Exception:
                    log.exception("fim_check_failed")

            # EXEC-001: /tmp 실행 탐지 (매 폴링마다)
            try:
                events.extend(self.tmp_exec.check())
            except Exception:
                log.exception("tmp_exec_check_failed")

            # EXEC-002: 웹서버 자식 프로세스 (매 폴링마다)
            try:
                events.extend(self.webshell.check())
            except Exception:
                log.exception("webshell_check_failed")

            # EXEC-003: 대량 파일 변경 (매 폴링마다)
            try:
                events.extend(self.bulk_mod.check())
            except Exception:
                log.exception("bulk_mod_check_failed")

            # TAMPER-NTP-001/002: NTP 드리프트 감지 (내부 check_interval 기준)
            try:
                events.extend(self.ntp_monitor.check())
            except Exception:
                log.exception("ntp_monitor_check_failed")

            # 수집된 이벤트를 collector로 전송
            for event in events:
                try:
                    await self._collector_client.send({
                        "type": MSG_EVENT,
                        "payload": event,
                    })
                except Exception:
                    log.exception("event_send_failed event=%s", event.get("rule_id"))

            await asyncio.sleep(self.POLL_INTERVAL)

    async def stop(self) -> None:
        await self._collector_client.close()
        log.info("sensor_component_stopped")


def main() -> None:
    settings = AgentSettings()
    sensor = SensorComponent(settings)
    asyncio.run(sensor.start())


if __name__ == "__main__":
    main()

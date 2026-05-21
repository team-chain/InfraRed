"""NTP 조작 감지 모듈 — v7.0 설계서

역할:
  NTP 서버 시간과 시스템 시계 간의 드리프트를 감지.
  공격자가 로그 타임스탬프를 조작하거나 인증서 유효성 검사를 우회하기 위해
  시스템 시계를 조작하는 행위를 탐지.

탐지 룰:
  TAMPER-NTP-001: NTP 드리프트 임계값 초과 (기본 ±60초)
  TAMPER-NTP-002: NTP 서버 응답 실패 (오프라인 또는 차단 의심)

MITRE ATT&CK:
  T1070.006 — Indicator Removal: Timestomp
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("infrared.ntp_monitor")

# NTP 에포크 오프셋 (1900-01-01 → 1970-01-01)
_NTP_DELTA = 2208988800

# 기본 NTP 서버 목록 (pool.ntp.org 국내 노드 포함)
_DEFAULT_NTP_SERVERS = [
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "ntp.ubuntu.com",
]

# 드리프트 임계값 (초)
DRIFT_WARN_SECONDS = 30.0    # TAMPER-NTP-001 경고
DRIFT_ALERT_SECONDS = 60.0   # TAMPER-NTP-001 경보 (인시던트 생성)


@dataclass
class NTPResult:
    server: str
    ntp_time: float         # NTP 서버 현재 시간 (Unix timestamp)
    local_time: float       # 로컬 시스템 시간 (Unix timestamp)
    drift_seconds: float    # 드리프트 = local_time - ntp_time
    success: bool
    error: str | None = None


def _query_ntp(server: str, timeout: float = 3.0) -> NTPResult:
    """단일 NTP 서버에 UDP 쿼리를 전송하고 시간을 읽어온다."""
    local_before = time.time()
    try:
        # NTP 패킷: LI=0, VN=3, Mode=3 (client)
        packet = b"\x1b" + 47 * b"\0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 123))
            data, _ = s.recvfrom(1024)

        local_after = time.time()
        local_time = (local_before + local_after) / 2.0

        # Transmit Timestamp 필드 (바이트 40~47)
        if len(data) < 48:
            raise ValueError(f"NTP 응답 크기 이상: {len(data)} bytes")

        integ, frac = struct.unpack("!II", data[40:48])
        ntp_time = integ + frac / 2**32 - _NTP_DELTA

        drift = local_time - ntp_time
        return NTPResult(
            server=server,
            ntp_time=ntp_time,
            local_time=local_time,
            drift_seconds=drift,
            success=True,
        )
    except Exception as exc:
        return NTPResult(
            server=server,
            ntp_time=0.0,
            local_time=local_before,
            drift_seconds=0.0,
            success=False,
            error=str(exc),
        )


class NTPMonitor:
    """
    NTP 시간 드리프트 감시자.

    사용법:
      monitor = NTPMonitor(settings)
      events = monitor.check()  # 이상 감지 시 이벤트 목록 반환
    """

    def __init__(
        self,
        settings: Any = None,
        servers: list[str] | None = None,
        warn_seconds: float = DRIFT_WARN_SECONDS,
        alert_seconds: float = DRIFT_ALERT_SECONDS,
        check_interval: float = 300.0,  # 5분마다 검사
    ) -> None:
        self.servers = servers or _DEFAULT_NTP_SERVERS
        self.warn_seconds = warn_seconds
        self.alert_seconds = alert_seconds
        self.check_interval = check_interval
        self._last_check: float = 0.0
        self._consecutive_failures: int = 0
        self._max_consecutive_failures: int = 3   # TAMPER-NTP-002 임계값

    def check(self) -> list[dict[str, Any]]:
        """
        NTP 드리프트 검사를 수행하고 이상 감지 시 이벤트를 반환.

        Returns:
          탐지된 이벤트 목록 (정상이면 빈 리스트).
        """
        now = time.monotonic()
        if now - self._last_check < self.check_interval:
            return []
        self._last_check = now

        events: list[dict[str, Any]] = []

        # 여러 NTP 서버 중 첫 번째 성공한 응답을 사용
        result: NTPResult | None = None
        failure_count = 0

        for server in self.servers:
            r = _query_ntp(server)
            if r.success:
                result = r
                self._consecutive_failures = 0
                break
            else:
                failure_count += 1
                log.debug("ntp_query_failed server=%s err=%s", server, r.error)

        if result is None:
            # 모든 서버 실패
            self._consecutive_failures += 1
            log.warning(
                "ntp_all_servers_failed consecutive=%d",
                self._consecutive_failures,
            )
            if self._consecutive_failures >= self._max_consecutive_failures:
                events.append(self._make_event(
                    rule_id="TAMPER-NTP-002",
                    severity="medium",
                    description=(
                        f"NTP 서버 연속 {self._consecutive_failures}회 응답 실패. "
                        "NTP 통신이 차단되었거나 NTP 서비스가 비활성화된 것으로 의심됩니다."
                    ),
                    drift=None,
                    server=None,
                ))
            return events

        # 드리프트 검사
        abs_drift = abs(result.drift_seconds)
        log.debug(
            "ntp_check server=%s drift=%.3fs local=%s",
            result.server,
            result.drift_seconds,
            datetime.fromtimestamp(result.local_time, tz=timezone.utc).isoformat(),
        )

        if abs_drift >= self.alert_seconds:
            log.warning(
                "ntp_drift_alert server=%s drift=%.1fs threshold=%.1fs",
                result.server, result.drift_seconds, self.alert_seconds,
            )
            events.append(self._make_event(
                rule_id="TAMPER-NTP-001",
                severity="high",
                description=(
                    f"시스템 시계가 NTP 서버({result.server})보다 "
                    f"{result.drift_seconds:+.1f}초 차이납니다. "
                    f"타임스탬프 조작 또는 시스템 시계 변조가 의심됩니다. "
                    f"(임계값: ±{self.alert_seconds}초)"
                ),
                drift=result.drift_seconds,
                server=result.server,
            ))
        elif abs_drift >= self.warn_seconds:
            log.info(
                "ntp_drift_warn server=%s drift=%.1fs threshold=%.1fs",
                result.server, result.drift_seconds, self.warn_seconds,
            )
            events.append(self._make_event(
                rule_id="TAMPER-NTP-001",
                severity="low",
                description=(
                    f"시스템 시계가 NTP 서버({result.server})보다 "
                    f"{result.drift_seconds:+.1f}초 차이납니다. (경고)"
                ),
                drift=result.drift_seconds,
                server=result.server,
            ))

        return events

    @staticmethod
    def _make_event(
        rule_id: str,
        severity: str,
        description: str,
        drift: float | None,
        server: str | None,
    ) -> dict[str, Any]:
        return {
            "rule_id": rule_id,
            "event_type": "ntp_drift_detected",
            "mitre_technique": "T1070.006",
            "severity": severity,
            "description": description,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "drift_seconds": drift,
            "ntp_server": server,
        }


async def ntp_monitor_loop(
    monitor: NTPMonitor,
    on_event: Any,  # async callable(event: dict)
) -> None:
    """비동기 NTP 감시 루프 (백그라운드 태스크로 사용)."""
    while True:
        try:
            events = monitor.check()
            for event in events:
                await on_event(event)
        except Exception:
            log.exception("ntp_monitor_loop_error")
        await asyncio.sleep(60.0)  # 1분마다 루프 (내부에서 check_interval 체크)

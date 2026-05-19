"""Windows ETW (Event Tracing for Windows) 구독 모듈 — v4 보안고도화.

기존 `event_log_collector.py`의 10초 폴링 방식 대신
ETW 실시간 구독 방식으로 이벤트를 수신한다.

ETW 백엔드:
  - pyetw 패키지 (설치된 경우)
  - pywintrace 패키지 (설치된 경우)
  - 둘 다 없으면 기존 win32evtlog 폴링 방식으로 자동 폴백

지원 이벤트 제공자 (Provider):
  - Microsoft-Windows-Security-Auditing (Security 채널 — 4624/4625/4688 등)
  - Microsoft-Windows-Sysmon/Operational (Sysmon 이벤트 — 설치 시)
  - Microsoft-Windows-PowerShell/Operational (PowerShell 스크립트 블록)

사용법:
    subscriber = ETWSubscriber(server_url=..., agent_jwt=..., agent_id=..., tenant_id=...)
    subscriber.start()   # 백그라운드 스레드 시작
    subscriber.stop()    # 정지
"""
from __future__ import annotations

import logging
import platform
import queue
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ETW 이벤트 제공자 GUID
ETW_PROVIDERS = {
    "Microsoft-Windows-Security-Auditing": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
    "Microsoft-Windows-Sysmon": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
    "Microsoft-Windows-PowerShell": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
}

# ETW로 수신 대상 이벤트 ID (Security-Auditing)
SECURITY_ETWS_OF_INTEREST = frozenset({
    4624, 4625, 4688, 4698, 4719, 4720, 4728, 4732, 4663, 1102, 7045,
    # Sysmon
    1,   # 프로세스 생성
    3,   # 네트워크 연결
    11,  # 파일 생성
    13,  # 레지스트리 값 변경
})

IS_WINDOWS = platform.system() == "Windows"


# ─────────────────────────────────────────────────────────────────── #
# ETW 구독 (pywintrace / pyetw 사용)
# ─────────────────────────────────────────────────────────────────── #

class _PywintraceBackend:
    """pywintrace 라이브러리를 이용한 ETW 구독."""

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._session = None

    def start(self) -> bool:
        try:
            from etw import ETW, ProviderInfo  # type: ignore  # noqa: PLC0415
            providers = [
                ProviderInfo(
                    "Microsoft-Windows-Security-Auditing",
                    ETW_PROVIDERS["Microsoft-Windows-Security-Auditing"],
                ),
            ]
            self._session = ETW(providers=providers, event_callback=self._on_event)
            threading.Thread(target=self._session.start, daemon=True).start()
            logger.info("ETW 구독 시작 (pywintrace 백엔드)")
            return True
        except Exception as exc:
            logger.debug("pywintrace 백엔드 시작 실패: %s", exc)
            return False

    def stop(self):
        if self._session:
            try:
                self._session.stop()
            except Exception:
                pass

    def _on_event(self, event_tuple):
        """ETW 이벤트 콜백."""
        try:
            if hasattr(event_tuple, "EventHeader"):
                event_id = getattr(event_tuple.EventHeader, "EventDescriptor", None)
                if event_id and hasattr(event_id, "Id"):
                    eid = event_id.Id
                    if eid not in SECURITY_ETWS_OF_INTEREST:
                        return
                props = {}
                if hasattr(event_tuple, "Properties"):
                    props = {k: str(v) for k, v in event_tuple.Properties.items()}
                self._callback({
                    "event_id": eid,
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "properties": props,
                })
        except Exception as exc:
            logger.debug("ETW 이벤트 파싱 오류: %s", exc)


class _PollingFallbackBackend:
    """ETW 라이브러리 없을 때 win32evtlog 폴링 폴백."""

    POLL_INTERVAL = 5  # 초 (기존 10초 → 5초로 개선)

    def __init__(self, callback: Callable[[dict], None]):
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if not IS_WINDOWS:
            logger.info("비-Windows 환경: ETW 폴백 비활성 (시뮬레이션 모드)")
            return False
        try:
            import win32evtlog  # type: ignore  # noqa: PLC0415, F401
            self._thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()
            logger.info("ETW 폴백 시작: win32evtlog %ds 폴링", self.POLL_INTERVAL)
            return True
        except ImportError:
            logger.warning("win32evtlog 없음 — ETW/폴링 모두 비활성")
            return False

    def stop(self):
        self._stop_event.set()

    def _poll_loop(self):
        import win32evtlog  # type: ignore  # noqa: PLC0415
        import win32con  # type: ignore  # noqa: PLC0415

        channels = {
            "Security": win32evtlog.OpenEventLog(None, "Security"),
            "System": win32evtlog.OpenEventLog(None, "System"),
        }
        from collectors.event_log_collector import normalize_event_id  # noqa: PLC0415

        while not self._stop_event.is_set():
            for channel, handle in channels.items():
                try:
                    flags = (
                        win32evtlog.EVENTLOG_FORWARDS_READ
                        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    )
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    for ev in events:
                        eid = ev.EventID & 0xFFFF
                        if eid not in SECURITY_ETWS_OF_INTEREST:
                            continue
                        inserts = [str(s) for s in (ev.StringInserts or [])]
                        self._callback({
                            "event_id": eid,
                            "channel": channel,
                            "properties": {f"param{i}": v for i, v in enumerate(inserts)},
                        })
                except Exception as exc:
                    logger.debug("폴링 오류 channel=%s: %s", channel, exc)
            self._stop_event.wait(timeout=self.POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────────── #
# 통합 ETW 구독자
# ─────────────────────────────────────────────────────────────────── #

class ETWSubscriber:
    """ETW 실시간 구독 + 폴링 폴백을 통합 관리하는 클래스.

    사용 예:
        subscriber = ETWSubscriber(server_url=..., agent_jwt=..., ...)
        subscriber.start()
    """

    def __init__(
        self,
        server_url: str,
        agent_jwt: str,
        agent_id: str = "windows-agent-001",
        tenant_id: str = "",
    ):
        self.server_url = server_url
        self.agent_jwt = agent_jwt
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self._event_queue: queue.Queue[dict] = queue.Queue(maxsize=10_000)
        self._sender_thread: Optional[threading.Thread] = None
        self._backend: Optional[_PywintraceBackend | _PollingFallbackBackend] = None

    def start(self):
        """ETW 구독을 시작한다. ETW 라이브러리가 없으면 폴링 폴백을 사용한다."""
        # 이벤트 전송 스레드 시작
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()

        # ETW 백엔드 선택: pywintrace → win32evtlog 폴링
        backend = _PywintraceBackend(callback=self._on_event)
        if not backend.start():
            backend = _PollingFallbackBackend(callback=self._on_event)
            if not backend.start():
                logger.warning("ETW 구독 비활성 — Windows가 아니거나 pywin32 미설치")
                return

        self._backend = backend
        logger.info("ETWSubscriber 시작 완료")

    def stop(self):
        if self._backend:
            self._backend.stop()

    # ---------------------------------------------------------------- #
    # 이벤트 콜백 → 큐
    # ---------------------------------------------------------------- #

    def _on_event(self, raw: dict):
        """ETW/폴링 백엔드에서 이벤트를 수신해 전송 큐에 넣는다."""
        try:
            self._event_queue.put_nowait(raw)
        except queue.Full:
            logger.debug("ETW 이벤트 큐 가득 참 — 드롭")

    # ---------------------------------------------------------------- #
    # 전송 루프
    # ---------------------------------------------------------------- #

    def _sender_loop(self):
        """큐에서 이벤트를 꺼내 InfraRed Ingestion API로 전송한다."""
        import json  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415
        from collectors.event_log_collector import normalize_event_id  # noqa: PLC0415

        while True:
            try:
                raw = self._event_queue.get(timeout=5)
            except queue.Empty:
                continue

            eid = raw.get("event_id", 0)
            props = raw.get("properties", {})
            # 단순 param0~N 리스트로 변환 (normalize_event_id 호환)
            inserts = [props.get(f"param{i}", "") for i in range(len(props))]

            normalized = normalize_event_id(eid, inserts)
            if normalized is None:
                continue

            payload = {
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": normalized.event_type,
                "source": "windows_etw",
                "log_source": normalized.log_source,
                "source_ip": normalized.source_ip,
                "user": normalized.target_account,
                "raw_event_id": eid,
                **normalized.extra,
            }

            try:
                req = urllib.request.Request(
                    f"{self.server_url}/api/v1/ingest",
                    data=json.dumps(payload).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.agent_jwt}",
                    },
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception as exc:
                logger.error("ETW 이벤트 전송 실패 eid=%d: %s", eid, exc)

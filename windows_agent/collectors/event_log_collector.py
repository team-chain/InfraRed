"""
Windows Security Event Log Collector
수집 대상: 4625/4624/4688/4698/4720/4728/4732/7045/4663/1102/4719
배포: PyInstaller 단일 .exe
Linux에서 테스트 가능하도록 win32evtlog import를 조건부로 처리
"""
from __future__ import annotations
import sys, time, logging, platform
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

TARGET_EVENT_IDS = {4625, 4624, 4720, 4728, 4732, 4698, 7045, 4688, 4663, 1102, 4719}

WATCHED_CHANNELS = {
    "Security": [4625, 4624, 4720, 4728, 4732, 4698, 4688, 4663, 1102, 4719],
    "System": [7045],
}

@dataclass
class NormalizedEvent:
    event_type: str
    source_ip: str = "unknown"
    target_account: str = "unknown"
    log_source: str = "windows_security"
    raw_event_id: int = 0
    extra: dict = field(default_factory=dict)

def normalize_event_id(event_id: int, string_inserts: list) -> Optional[NormalizedEvent]:
    """Windows 이벤트 ID → InfraRed AgentEvent 형식 변환"""
    def safe_get(lst, idx, default="unknown"):
        try:
            v = lst[idx] if lst and len(lst) > idx else default
            return v if v and v != "-" else default
        except Exception:
            return default

    if event_id == 4625:  # 로그인 실패
        return NormalizedEvent(
            event_type="ssh_login_failed",
            source_ip=safe_get(string_inserts, 19),
            target_account=safe_get(string_inserts, 5),
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"logon_type": safe_get(string_inserts, 10)},
        )
    elif event_id == 4624:  # 로그인 성공
        return NormalizedEvent(
            event_type="login_success",
            source_ip=safe_get(string_inserts, 18),
            target_account=safe_get(string_inserts, 5),
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"logon_type": safe_get(string_inserts, 8)},
        )
    elif event_id == 4688:  # 프로세스 생성
        proc_name = safe_get(string_inserts, 5)
        cmdline = safe_get(string_inserts, 8)
        parent = safe_get(string_inserts, 13)
        return NormalizedEvent(
            event_type="process_created",
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"process_name": proc_name, "cmdline": cmdline[:200], "parent_process": parent},
        )
    elif event_id == 4698:  # Scheduled Task 생성
        return NormalizedEvent(
            event_type="scheduled_task_created",
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"task_name": safe_get(string_inserts, 4)},
        )
    elif event_id == 7045:  # 새 서비스 설치
        return NormalizedEvent(
            event_type="service_installed",
            log_source="windows_system",
            raw_event_id=event_id,
            extra={"service_name": safe_get(string_inserts, 0), "service_path": safe_get(string_inserts, 1)},
        )
    elif event_id in (4720,):  # 계정 생성
        return NormalizedEvent(
            event_type="user_account_created",
            target_account=safe_get(string_inserts, 0),
            log_source="windows_security",
            raw_event_id=event_id,
        )
    elif event_id in (4728, 4732):  # 그룹 멤버 추가
        return NormalizedEvent(
            event_type="group_membership_changed",
            target_account=safe_get(string_inserts, 0),
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"group_name": safe_get(string_inserts, 2)},
        )
    elif event_id == 1102:  # 감사 로그 삭제
        return NormalizedEvent(
            event_type="audit_log_cleared",
            log_source="windows_security",
            raw_event_id=event_id,
        )
    elif event_id == 4719:  # 감사 정책 변경
        return NormalizedEvent(
            event_type="audit_policy_changed",
            log_source="windows_security",
            raw_event_id=event_id,
        )
    elif event_id == 4663:  # 파일 접근
        return NormalizedEvent(
            event_type="file_accessed",
            log_source="windows_security",
            raw_event_id=event_id,
            extra={"object_name": safe_get(string_inserts, 6)},
        )
    return None


class WindowsEventLogCollector:
    """
    Windows Security Event Log 실시간 수집.
    Windows 환경에서만 실제 동작. 다른 OS에서는 시뮬레이션 모드.
    """
    def __init__(self, server_url: str, agent_jwt: str, agent_id: str, tenant_id: str):
        self.server_url = server_url
        self.agent_jwt = agent_jwt
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.is_windows = platform.system() == "Windows"
        self._handles = {}
        self._session = None

    def _get_string_inserts(self, event) -> list:
        try:
            return list(event.StringInserts or [])
        except Exception:
            return []

    def start(self):
        if not self.is_windows:
            logger.warning("WindowsEventLogCollector: not running on Windows, entering simulation mode")
            self._simulate_loop()
            return
        
        try:
            import win32evtlog
            for channel in WATCHED_CHANNELS:
                handle = win32evtlog.OpenEventLog(None, channel)
                self._handles[channel] = handle
            self._poll_loop()
        except ImportError:
            logger.error("win32evtlog not available. Install pywin32.")
            self._simulate_loop()

    def _poll_loop(self):
        """10초 폴링으로 새 이벤트 수집"""
        import win32evtlog
        import win32con
        last_record = {ch: 0 for ch in WATCHED_CHANNELS}
        
        while True:
            for channel, handle in self._handles.items():
                try:
                    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    for ev in events:
                        eid = ev.EventID & 0xFFFF
                        if eid not in TARGET_EVENT_IDS:
                            continue
                        inserts = self._get_string_inserts(ev)
                        normalized = normalize_event_id(eid, inserts)
                        if normalized:
                            self._send_event(normalized)
                except Exception as e:
                    logger.error(f"Event log read error ({channel}): {e}")
            time.sleep(10)

    def _simulate_loop(self):
        """테스트/비Windows 환경 시뮬레이션"""
        import json, time
        logger.info("Windows Agent simulation mode - no events will be sent")
        while True:
            time.sleep(60)

    def _send_event(self, event: NormalizedEvent):
        """InfraRed Ingestion API로 이벤트 전송"""
        import urllib.request
        import json
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event.event_type,
            "source": "windows_agent",
            "log_source": event.log_source,
            "source_ip": event.source_ip,
            "user": event.target_account,
            "raw_event_id": event.raw_event_id,
            **event.extra,
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
        except Exception as e:
            logger.error(f"Event send failed: {e}")

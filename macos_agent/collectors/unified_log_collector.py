"""
macOS Unified Logging System Collector
수집: SSH 로그인, 인증 실패, LaunchDaemon 변조, 시스템 환경설정 변경
"""
from __future__ import annotations
import subprocess, time, hashlib, logging, platform
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

WATCH_DIRS = [
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/System/Library/LaunchDaemons/",
]

@dataclass
class MacOSEvent:
    event_type: str
    severity: str = "MEDIUM"
    rule_id: str = ""
    mitre: str = ""
    data: dict = field(default_factory=dict)

class MacOSUnifiedLogCollector:
    """macOS Unified Logging + LaunchDaemon 변조 감지"""

    LOG_PREDICATES = [
        'process == "sshd"',
        'subsystem == "com.apple.securityd" AND category == "Auth"',
        'subsystem == "com.apple.SystemConfiguration"',
    ]

    def __init__(self, server_url: str, agent_jwt: str, agent_id: str, tenant_id: str):
        self.server_url = server_url
        self.agent_jwt = agent_jwt
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.is_macos = platform.system() == "Darwin"
        self._launchd_baseline: dict[str, str] = {}

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except Exception:
            pass
        return h.hexdigest()

    def collect_baseline_launchd(self):
        """LaunchDaemon/Agent 파일 해시 기준선 수립"""
        for watch_dir in WATCH_DIRS:
            p = Path(watch_dir)
            if p.exists():
                for plist in p.glob("*.plist"):
                    self._launchd_baseline[str(plist)] = self._sha256(str(plist))
        logger.info(f"LaunchDaemon baseline: {len(self._launchd_baseline)} files")

    def check_launchd_changes(self) -> list[MacOSEvent]:
        """PERSIST-003 대응: LaunchDaemon 변조 감지"""
        events = []
        for watch_dir in WATCH_DIRS:
            p = Path(watch_dir)
            if not p.exists():
                continue
            for plist in p.glob("*.plist"):
                path = str(plist)
                current_hash = self._sha256(path)
                if path not in self._launchd_baseline:
                    events.append(MacOSEvent(
                        event_type="launchdaemon_created",
                        severity="HIGH",
                        rule_id="PERSIST-003",
                        mitre="T1543.001",
                        data={"path": path, "action": "created"},
                    ))
                elif current_hash != self._launchd_baseline[path]:
                    events.append(MacOSEvent(
                        event_type="launchdaemon_modified",
                        severity="HIGH",
                        rule_id="PERSIST-003",
                        mitre="T1543.001",
                        data={"path": path, "action": "modified",
                              "prev_hash": self._launchd_baseline[path][:8],
                              "curr_hash": current_hash[:8]},
                    ))
                self._launchd_baseline[path] = current_hash
        return events

    def stream_unified_logs(self):
        """log stream 명령으로 실시간 로그 수집"""
        if not self.is_macos:
            logger.warning("Not running on macOS, simulation mode")
            return

        predicate = " OR ".join(f"({p})" for p in self.LOG_PREDICATES)
        cmd = ["log", "stream", "--predicate", predicate, "--style", "json"]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in proc.stdout:
                line = line.strip()
                if not line or line.startswith("["):
                    continue
                event = self._parse_log_line(line)
                if event:
                    self._send_event(event)
        except Exception as e:
            logger.error(f"Unified log stream failed: {e}")

    def _parse_log_line(self, line: str) -> Optional[MacOSEvent]:
        """로그 라인 파싱 → MacOSEvent"""
        import json
        try:
            data = json.loads(line)
            msg = data.get("eventMessage", "")
            proc = data.get("processImagePath", "")

            if "sshd" in proc:
                if "Failed" in msg or "Invalid" in msg:
                    return MacOSEvent(
                        event_type="ssh_login_failed",
                        severity="MEDIUM",
                        rule_id="AUTH-001",
                        data={"message": msg[:200], "process": proc},
                    )
                elif "Accepted" in msg:
                    return MacOSEvent(
                        event_type="login_success",
                        severity="LOW",
                        rule_id="AUTH-004",
                        data={"message": msg[:200]},
                    )
        except Exception:
            pass
        return None

    def _send_event(self, event: MacOSEvent):
        import urllib.request, json
        payload = {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event.event_type,
            "source": "macos_agent",
            "log_source": "macos_unified_log",
            "severity": event.severity,
            "rule_id": event.rule_id,
            "mitre": event.mitre,
            **event.data,
        }
        try:
            req = urllib.request.Request(
                f"{self.server_url}/api/v1/ingest",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.agent_jwt}"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.error(f"macOS event send failed: {e}")

    def start(self):
        import threading
        self.collect_baseline_launchd()
        
        # LaunchDaemon 감시 스레드
        def fim_loop():
            while True:
                events = self.check_launchd_changes()
                for ev in events:
                    self._send_event(ev)
                time.sleep(30)
        
        t = threading.Thread(target=fim_loop, daemon=True)
        t.start()
        
        # Unified Log 스트림
        self.stream_unified_logs()

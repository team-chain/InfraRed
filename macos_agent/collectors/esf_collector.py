"""
macOS EndpointSecurity Framework (ESF) Collector — v4 보안고도화.

ESF는 macOS 10.15+ 에서 Apple이 제공하는 커널 보안 API다.
Python에서 직접 호출이 불가하므로 두 가지 접근 방식을 제공한다:

  1. Swift 헬퍼 바이너리 (esf_helper) 를 subprocess로 실행 → JSON 이벤트 스트리밍
  2. esf_helper 가 없으면 OpenBSM audit 로그 파싱으로 폴백

ESF가 잡는 이벤트 (ESAPI):
  - ES_EVENT_TYPE_NOTIFY_EXEC        (프로세스 실행)
  - ES_EVENT_TYPE_NOTIFY_FORK        (포크)
  - ES_EVENT_TYPE_NOTIFY_EXIT        (종료)
  - ES_EVENT_TYPE_NOTIFY_CREATE      (파일 생성)
  - ES_EVENT_TYPE_NOTIFY_UNLINK      (파일 삭제)
  - ES_EVENT_TYPE_NOTIFY_OPEN        (파일 열기)
  - ES_EVENT_TYPE_NOTIFY_WRITE       (파일 쓰기)
  - ES_EVENT_TYPE_NOTIFY_RENAME      (파일 이동)
  - ES_EVENT_TYPE_NOTIFY_MOUNT       (마운트)
  - ES_EVENT_TYPE_AUTH_EXEC          (실행 허가/거부 인터셉트)
  - ES_EVENT_TYPE_NOTIFY_SIGNAL      (시그널 전송)
  - ES_EVENT_TYPE_NOTIFY_KEXTLOAD    (커널 확장 로드)

ESF 헬퍼 Swift 바이너리: macos_agent/esf_helper/main.swift
빌드: xcodebuild / swiftc (Entitlement com.apple.developer.endpoint-security.client 필요)
"""
from __future__ import annotations

import json
import logging
import os
import platform
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# ESF 헬퍼 바이너리 경로
# ────────────────────────────────────────────────────────────────────────────
_ESF_HELPER_PATHS = [
    Path(__file__).parent.parent / "bin" / "esf_helper",
    Path("/usr/local/infrared/esf_helper"),
    Path("/opt/infrared/bin/esf_helper"),
]


def _find_esf_helper() -> Optional[Path]:
    for p in _ESF_HELPER_PATHS:
        if p.exists() and os.access(p, os.X_OK):
            return p
    return None


# ────────────────────────────────────────────────────────────────────────────
# 이벤트 데이터클래스
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ESFEvent:
    event_type: str
    pid: int
    ppid: int
    uid: int
    gid: int
    process_path: str
    timestamp: str
    severity: str = "LOW"
    rule_id: str = ""
    mitre: str = ""
    data: dict = field(default_factory=dict)

    def to_signal(self, agent_id: str, tenant_id: str) -> dict:
        return {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "rule_id": self.rule_id or f"ESF-{self.event_type}-001",
            "severity": self.severity,
            "mitre": self.mitre,
            "raw": json.dumps({
                "event_type": self.event_type,
                "pid": self.pid,
                "ppid": self.ppid,
                "uid": self.uid,
                "gid": self.gid,
                "process_path": self.process_path,
                "timestamp": self.timestamp,
                **self.data,
            }),
            "source": "esf",
            "ts": self.timestamp,
        }


# ────────────────────────────────────────────────────────────────────────────
# 탐지 규칙
# ────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_EXEC_PATTERNS = [
    re.compile(r"/tmp/[^/]+$"),
    re.compile(r"/var/folders/.+/[^/]+$"),
    re.compile(r"/Users/[^/]+/Downloads/"),
]

_LAUNCHDAEMON_PATHS = [
    "/Library/LaunchDaemons/",
    "/Library/LaunchAgents/",
    "/System/Library/LaunchDaemons/",
    "/System/Library/LaunchAgents/",
]

_MITRE_MAP = {
    "EXEC": "T1059",
    "FORK": "T1106",
    "CREATE": "T1105",
    "UNLINK": "T1485",
    "KEXTLOAD": "T1215",
    "AUTH_EXEC": "T1059",
    "SIGNAL": "T1106",
}


def _classify_esf_event(event: dict) -> ESFEvent:
    etype = event.get("event_type", "UNKNOWN")
    pid = int(event.get("pid", 0))
    ppid = int(event.get("ppid", 0))
    uid = int(event.get("uid", 0))
    gid = int(event.get("gid", 0))
    proc_path = event.get("process_path", "")
    ts = event.get("timestamp", datetime.now(tz=timezone.utc).isoformat())

    severity = "LOW"
    rule_id = ""
    mitre = _MITRE_MAP.get(etype, "")
    extra: dict = {}

    if etype == "EXEC":
        for pat in _SUSPICIOUS_EXEC_PATTERNS:
            if pat.search(proc_path):
                severity = "HIGH"
                rule_id = "ESF-EXEC-SUSPICIOUS-001"
                extra["matched_pattern"] = pat.pattern
                break
        if uid == 0 and "/tmp/" in proc_path:
            severity = "CRITICAL"
            rule_id = "ESF-EXEC-ROOT-TMP-001"

    elif etype == "AUTH_EXEC":
        if not event.get("is_signed", True):
            severity = "HIGH"
            rule_id = "ESF-AUTH-UNSIGNED-001"
            mitre = "T1036"

    elif etype == "CREATE":
        target_path = event.get("target_path", "")
        for daemon_path in _LAUNCHDAEMON_PATHS:
            if target_path.startswith(daemon_path):
                severity = "HIGH"
                rule_id = "ESF-PERSIST-LAUNCHDAEMON-001"
                mitre = "T1543.001"
                extra["target_path"] = target_path
                break
        if target_path.endswith(".plist") and any(
            target_path.startswith(p) for p in _LAUNCHDAEMON_PATHS
        ):
            severity = "CRITICAL"
            rule_id = "ESF-PERSIST-PLIST-001"

    elif etype == "KEXTLOAD":
        kext_id = event.get("kext_identifier", "")
        if not kext_id.startswith(("com.apple.", "com.vmware.", "com.parallels.")):
            severity = "CRITICAL"
            rule_id = "ESF-KEXTLOAD-UNKNOWN-001"
            extra["kext_id"] = kext_id

    elif etype == "UNLINK":
        target_path = event.get("target_path", "")
        if target_path.startswith("/var/log/") or target_path.startswith("/Library/Logs/"):
            severity = "HIGH"
            rule_id = "ESF-TAMPER-LOG-DELETE-001"
            mitre = "T1070.002"

    return ESFEvent(
        event_type=etype,
        pid=pid, ppid=ppid, uid=uid, gid=gid,
        process_path=proc_path,
        timestamp=ts,
        severity=severity,
        rule_id=rule_id,
        mitre=mitre,
        data=extra,
    )


# ────────────────────────────────────────────────────────────────────────────
# OpenBSM 폴백 파서
# ────────────────────────────────────────────────────────────────────────────

class _OpenBSMAuditParser:
    _HEADER_RE = re.compile(r"header,\d+,\d+,(\w+)\(\d+\),\d+,(.+?), \+")
    _PATH_RE = re.compile(r"path,(.+)")
    _SUBJECT_RE = re.compile(r"subject,.+?,.+?,.+?,.+?,(\d+),(\d+),(\d+),")

    def __init__(self, event_callback: Callable[[dict], None]) -> None:
        self._cb = event_callback
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()

    def start(self) -> bool:
        try:
            self._proc = subprocess.Popen(
                ["praudit", "-l", "/dev/auditpipe"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except (FileNotFoundError, PermissionError) as exc:
            logger.warning("OpenBSM praudit unavailable: %s", exc)
            return False

        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_evt.set()
        if self._proc:
            self._proc.terminate()
        if self._thread:
            self._thread.join(timeout=5)

    def _read_loop(self) -> None:
        current: dict = {}
        for line in self._proc.stdout:  # type: ignore[union-attr]
            if self._stop_evt.is_set():
                break
            line = line.strip()
            m = self._HEADER_RE.search(line)
            if m:
                if current:
                    self._cb(current)
                syscall = m.group(1)
                etype = {
                    "execve": "EXEC", "open": "OPEN",
                    "unlink": "UNLINK", "rename": "RENAME", "fork": "FORK",
                }.get(syscall, syscall.upper())
                current = {
                    "event_type": etype,
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "pid": 0, "ppid": 0, "uid": 0, "gid": 0,
                    "process_path": "",
                }
                continue
            m = self._PATH_RE.search(line)
            if m and current:
                current.setdefault("process_path", m.group(1).strip())
                continue
            m = self._SUBJECT_RE.search(line)
            if m and current:
                current["uid"] = int(m.group(1))
                current["pid"] = int(m.group(2))
                current["gid"] = int(m.group(3))
        if current:
            self._cb(current)


# ────────────────────────────────────────────────────────────────────────────
# 메인 ESF 컬렉터
# ────────────────────────────────────────────────────────────────────────────

class ESFCollector:
    """
    macOS EndpointSecurity Framework 이벤트 수집기.

    1) esf_helper 바이너리가 있으면 ESF 직접 구독
    2) 없으면 OpenBSM audit 파이프 폴백
    3) 이벤트를 분류하여 InfraRed 백엔드로 전송
    """

    SEND_INTERVAL = 5.0
    BATCH_SIZE = 50
    RECONNECT_DELAY = 10

    def __init__(
        self,
        server_url: str,
        agent_jwt: str,
        agent_id: str,
        tenant_id: str,
        min_severity: str = "MEDIUM",
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.agent_jwt = agent_jwt
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.min_severity = min_severity

        self._queue: queue.Queue[ESFEvent] = queue.Queue(maxsize=2000)
        self._stop_evt = threading.Event()
        self._esf_proc: Optional[subprocess.Popen] = None
        self._threads: list[threading.Thread] = []
        self._bsm: Optional[_OpenBSMAuditParser] = None
        self._mode = "none"
        self._sent_total = 0
        self._dropped_total = 0

    def start(self) -> None:
        if platform.system() != "Darwin":
            logger.warning("ESFCollector: 비-macOS 환경, 비활성화")
            return

        helper = _find_esf_helper()
        if helper:
            logger.info("ESF 헬퍼 바이너리 발견: %s", helper)
            self._start_esf_helper(helper)
        else:
            logger.info("ESF 헬퍼 없음 → OpenBSM audit 폴백")
            self._start_bsm_fallback()

        sender = threading.Thread(target=self._sender_loop, daemon=True)
        sender.start()
        self._threads.append(sender)
        logger.info("ESFCollector 시작 (mode=%s)", self._mode)

    def stop(self) -> None:
        self._stop_evt.set()
        if self._esf_proc:
            self._esf_proc.terminate()
        if self._bsm:
            self._bsm.stop()
        for t in self._threads:
            t.join(timeout=5)
        logger.info("ESFCollector 종료 — 전송=%d 드롭=%d", self._sent_total, self._dropped_total)

    def _start_esf_helper(self, helper_path: Path) -> None:
        self._mode = "esf"

        def _run():
            while not self._stop_evt.is_set():
                try:
                    self._esf_proc = subprocess.Popen(
                        [str(helper_path), "--json"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    for line in self._esf_proc.stdout:  # type: ignore[union-attr]
                        if self._stop_evt.is_set():
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                            esf_evt = _classify_esf_event(raw)
                            self._enqueue(esf_evt)
                        except json.JSONDecodeError:
                            logger.debug("ESF JSON 파싱 실패: %s", line[:80])
                except Exception as exc:
                    logger.error("ESF 헬퍼 오류: %s", exc)
                if not self._stop_evt.is_set():
                    time.sleep(self.RECONNECT_DELAY)

        t = threading.Thread(target=_run, daemon=True, name="esf-reader")
        t.start()
        self._threads.append(t)

    def _start_bsm_fallback(self) -> None:
        self._bsm = _OpenBSMAuditParser(event_callback=self._on_bsm_event)
        ok = self._bsm.start()
        self._mode = "bsm" if ok else "none"

    def _on_bsm_event(self, raw: dict) -> None:
        try:
            self._enqueue(_classify_esf_event(raw))
        except Exception as exc:
            logger.debug("BSM 이벤트 처리 오류: %s", exc)

    def _enqueue(self, evt: ESFEvent) -> None:
        _SEV = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if _SEV.get(evt.severity, 0) < _SEV.get(self.min_severity, 0):
            return
        try:
            self._queue.put_nowait(evt)
        except queue.Full:
            self._dropped_total += 1

    def _sender_loop(self) -> None:
        while not self._stop_evt.is_set():
            time.sleep(self.SEND_INTERVAL)
            batch: list[dict] = []
            while len(batch) < self.BATCH_SIZE:
                try:
                    evt = self._queue.get_nowait()
                    batch.append(evt.to_signal(self.agent_id, self.tenant_id))
                except queue.Empty:
                    break
            if batch:
                self._send_batch(batch)

    def _send_batch(self, signals: list[dict]) -> None:
        url = f"{self.server_url}/ingest/signals/batch"
        headers = {
            "Authorization": f"Bearer {self.agent_jwt}",
            "Content-Type": "application/json",
            "X-Agent-Source": "esf",
        }
        try:
            resp = requests.post(url, json={"signals": signals}, headers=headers, timeout=10)
            if resp.status_code == 200:
                self._sent_total += len(signals)
            else:
                logger.warning("ESF 전송 실패 HTTP %s", resp.status_code)
        except requests.RequestException as exc:
            logger.error("ESF 전송 오류: %s", exc)

    def status(self) -> dict:
        return {
            "mode": self._mode,
            "queue_size": self._queue.qsize(),
            "sent_total": self._sent_total,
            "dropped_total": self._dropped_total,
            "running": not self._stop_evt.is_set(),
        }

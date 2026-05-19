"""
InfraRed v1 — auditd 로그 수집 파서
설계서_최종.docx 구현 순서 #6

auditd 기반 확장 탐지 룰:
  - EXEC-001: /tmp·/dev/shm 에서 실행 파일 실행 (execve)
  - EXEC-002: Python/Perl/bash 등으로 스크립트 원격 실행
  - PRIV-001: sudo / su 사용 (권한 상승 시도)
  - OPEN-001: /etc/shadow, /etc/passwd 읽기 시도
  - NET-CONN-001: 비정상 포트 바인딩 (< 1024, 비표준 포트)

데모 환경에서는 기본 비활성 (설계서 명시)
환경변수 ENABLE_AUDITD=true 로 활성화
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator, Callable

logger = logging.getLogger("infrared.auditd")

ENABLE_AUDITD = os.getenv("ENABLE_AUDITD", "false").lower() == "true"

# ──────────────────────────────────────────────────────────────
# auditd 이벤트 파싱
# ──────────────────────────────────────────────────────────────
@dataclass
class AuditEvent:
    audit_id: str
    type:     str
    timestamp: float
    fields:   dict[str, str] = field(default_factory=dict)
    raw:      str = ""


_AUDIT_HEADER_RE = re.compile(
    r"audit\((\d+\.\d+):(\d+)\):\s*(.*)"
)
_FIELD_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:\S+)))')


def parse_audit_line(line: str) -> AuditEvent | None:
    """
    auditd 로그 한 줄 파싱.

    예: audit(1716000000.123:456): type=EXECVE msg=audit(...) ...
    """
    line = line.strip()
    if not line:
        return None

    # 타입 추출
    type_match = re.search(r"type=(\w+)", line)
    event_type = type_match.group(1) if type_match else "UNKNOWN"

    # 헤더 파싱
    header_match = _AUDIT_HEADER_RE.search(line)
    if not header_match:
        return None

    ts_str, audit_id, rest = header_match.groups()
    fields: dict[str, str] = {}

    for m in _FIELD_RE.finditer(rest):
        key   = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        fields[key] = value

    return AuditEvent(
        audit_id  = audit_id,
        type      = event_type,
        timestamp = float(ts_str),
        fields    = fields,
        raw       = line,
    )


# ──────────────────────────────────────────────────────────────
# 탐지 룰
# ──────────────────────────────────────────────────────────────
@dataclass
class InfraRedEvent:
    rule_id:    str
    event_type: str
    severity:   str
    mitre:      str
    description: str
    data:       dict
    timestamp:  float = field(default_factory=time.time)


_SUSPICIOUS_EXEC_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"]
_REMOTE_EXEC_COMMANDS  = ["python", "python3", "perl", "ruby", "php", "nc", "ncat", "bash", "sh"]
_SENSITIVE_FILES       = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh/id_rsa"]


def _check_exec_from_temp(evt: AuditEvent) -> InfraRedEvent | None:
    """EXEC-001: /tmp·/dev/shm 에서 실행"""
    if evt.type not in ("EXECVE", "SYSCALL"):
        return None
    exe = evt.fields.get("exe", evt.fields.get("a0", "")).strip('"')
    if any(exe.startswith(p) for p in _SUSPICIOUS_EXEC_PATHS):
        return InfraRedEvent(
            rule_id     = "EXEC-001",
            event_type  = "exec_from_temp",
            severity    = "HIGH",
            mitre       = "T1059",
            description = f"임시 디렉토리에서 실행 파일 실행: {exe}",
            data        = {
                "exe":  exe,
                "pid":  evt.fields.get("pid"),
                "uid":  evt.fields.get("uid"),
                "comm": evt.fields.get("comm", ""),
            },
        )
    return None


def _check_remote_exec(evt: AuditEvent) -> InfraRedEvent | None:
    """EXEC-002: 원격 코드 실행 의심 (인터프리터 + stdin 파이프)"""
    if evt.type != "EXECVE":
        return None
    exe = evt.fields.get("exe", "").strip('"')
    a0  = evt.fields.get("a0", "").strip('"')
    exe_name = Path(exe).name
    if exe_name in _REMOTE_EXEC_COMMANDS:
        # -c 플래그 또는 stdin으로 스크립트 실행
        args_str = " ".join(
            v for k, v in evt.fields.items() if k.startswith("a") and k[1:].isdigit()
        )
        if any(flag in args_str for flag in ["-c ", "stdin", "<&"]):
            return InfraRedEvent(
                rule_id     = "EXEC-002",
                event_type  = "remote_code_exec",
                severity    = "CRITICAL",
                mitre       = "T1059",
                description = f"원격 코드 실행 의심: {exe_name} -c ...",
                data        = {
                    "exe":  exe,
                    "args": args_str[:200],
                    "pid":  evt.fields.get("pid"),
                    "uid":  evt.fields.get("uid"),
                },
            )
    return None


def _check_privilege_escalation(evt: AuditEvent) -> InfraRedEvent | None:
    """PRIV-001: sudo / su 사용"""
    if evt.type != "EXECVE":
        return None
    exe = Path(evt.fields.get("exe", "").strip('"')).name
    if exe in ("sudo", "su", "pkexec"):
        uid = evt.fields.get("uid", "")
        return InfraRedEvent(
            rule_id     = "PRIV-001",
            event_type  = "privilege_escalation_attempt",
            severity    = "MEDIUM",
            mitre       = "T1548.003",
            description = f"권한 상승 시도: {exe} (uid={uid})",
            data        = {
                "exe": exe,
                "uid": uid,
                "pid": evt.fields.get("pid"),
            },
        )
    return None


def _check_sensitive_file_open(evt: AuditEvent) -> InfraRedEvent | None:
    """OPEN-001: 민감 파일 열기 시도"""
    if evt.type not in ("OPEN", "OPENAT", "PATH"):
        return None
    path = evt.fields.get("name", evt.fields.get("path", "")).strip('"')
    for sensitive in _SENSITIVE_FILES:
        if path == sensitive or path.endswith(sensitive):
            return InfraRedEvent(
                rule_id     = "OPEN-001",
                event_type  = "sensitive_file_access",
                severity    = "HIGH",
                mitre       = "T1003",
                description = f"민감 파일 접근: {path}",
                data        = {
                    "path": path,
                    "uid":  evt.fields.get("uid"),
                    "pid":  evt.fields.get("pid"),
                    "comm": evt.fields.get("comm", ""),
                },
            )
    return None


# 모든 탐지 함수 목록
_DETECTORS: list[Callable[[AuditEvent], InfraRedEvent | None]] = [
    _check_exec_from_temp,
    _check_remote_exec,
    _check_privilege_escalation,
    _check_sensitive_file_open,
]


def detect(evt: AuditEvent) -> list[InfraRedEvent]:
    """단일 auditd 이벤트에 모든 탐지 룰 적용"""
    results = []
    for detector in _DETECTORS:
        try:
            result = detector(evt)
            if result:
                results.append(result)
        except Exception as exc:
            logger.debug("탐지 오류 (rule=%s): %s", detector.__name__, exc)
    return results


# ──────────────────────────────────────────────────────────────
# auditd 로그 테일러 (실시간 수집)
# ──────────────────────────────────────────────────────────────
AUDIT_LOG_PATH = Path("/var/log/audit/audit.log")


async def tail_auditd(
    on_event: Callable[[InfraRedEvent], None],
    log_path: Path = AUDIT_LOG_PATH,
    poll_interval: float = 0.5,
) -> None:
    """
    auditd 로그를 tail -F 방식으로 실시간 모니터링.
    새 이벤트 탐지 시 on_event 콜백 호출.

    ENABLE_AUDITD=false 면 즉시 반환.
    """
    if not ENABLE_AUDITD:
        logger.info("auditd 수집 비활성화됨 (ENABLE_AUDITD=false)")
        return

    if not log_path.exists():
        logger.warning("auditd 로그 파일 없음: %s", log_path)
        return

    logger.info("auditd 테일링 시작: %s", log_path)

    # ausearch 방식 (더 신뢰성 높음)
    try:
        proc = await asyncio.create_subprocess_exec(
            "tail", "-F", "-n", "0", str(log_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert proc.stdout

        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                await asyncio.sleep(poll_interval)
                continue
            line = line_bytes.decode("utf-8", errors="replace")
            evt  = parse_audit_line(line)
            if evt:
                for ir_evt in detect(evt):
                    try:
                        on_event(ir_evt)
                    except Exception as exc:
                        logger.error("이벤트 처리 오류: %s", exc)
    except FileNotFoundError:
        logger.error("tail 바이너리 없음")
    except asyncio.CancelledError:
        logger.info("auditd 테일러 종료")
        if proc:
            proc.terminate()


# ──────────────────────────────────────────────────────────────
# auditd 설정 초기화 스크립트
# ──────────────────────────────────────────────────────────────
AUDITD_RULES = """
# InfraRed auditd 탐지 규칙
# 파일: /etc/audit/rules.d/infrared.rules

# 임시 디렉토리 실행 파일 탐지
-a always,exit -F dir=/tmp -F perm=x -F auid>=1000 -k exec_from_tmp
-a always,exit -F dir=/dev/shm -F perm=x -k exec_from_shm

# 권한 상승 명령 실행 감시
-w /usr/bin/sudo -p x -k priv_escalation
-w /bin/su -p x -k priv_escalation
-w /usr/bin/pkexec -p x -k priv_escalation

# 민감 파일 접근 감시
-w /etc/shadow -p rwxa -k sensitive_file
-w /etc/passwd -p wa -k sensitive_file
-w /etc/sudoers -p wa -k sensitive_file
-w /root/.ssh -p wa -k ssh_key_access

# 네트워크 설정 변경
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config

# 시스템 시간 변경 (증거 조작)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
"""


def install_auditd_rules() -> bool:
    """InfraRed auditd 규칙 설치"""
    rules_path = Path("/etc/audit/rules.d/infrared.rules")
    try:
        rules_path.write_text(AUDITD_RULES)
        result = subprocess.run(
            ["augenrules", "--load"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.error("augenrules 로드 실패: %s", result.stderr)
            return False
        logger.info("auditd 규칙 설치 완료")
        return True
    except PermissionError:
        logger.error("auditd 규칙 설치 실패: root 권한 필요")
        return False


# ──────────────────────────────────────────────────────────────
# Docker Agent 연동 인터페이스
# ──────────────────────────────────────────────────────────────
class AuditdCollector:
    """
    Agent v1의 log_tailing 루프에 통합되는 auditd 수집기.

    사용법:
        collector = AuditdCollector(send_event_fn=agent.send_event)
        await collector.start()
    """

    def __init__(self, send_event_fn: Callable):
        self.send_event = send_event_fn
        self._task: asyncio.Task | None = None

    async def start(self):
        if not ENABLE_AUDITD:
            return
        self._task = asyncio.create_task(
            tail_auditd(self._on_event),
            name="auditd-collector",
        )

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def _on_event(self, evt: InfraRedEvent):
        self.send_event({
            "rule_id":    evt.rule_id,
            "event_type": evt.event_type,
            "severity":   evt.severity,
            "mitre":      evt.mitre,
            "description": evt.description,
            "timestamp":  evt.timestamp,
            "data":       evt.data,
            "source":     "auditd",
        })

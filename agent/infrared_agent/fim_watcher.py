"""Phase 4-A: 파일 무결성 모니터링 (FIM) 및 탐지 소스 확장.

설계서 4-A 탐지 소스 우선순위:
  1. auditd 강화                  (T1078, T1059) - 민감 파일 접근 / 의심 프로세스
  2. authorized_keys 변경 감지    (T1098.004)    - /root/.ssh/authorized_keys 해시 변경
  3. sshd_config 변경 감지        (T1563.001)    - /etc/ssh/sshd_config 변경
  4. cron job 변조 감지            (T1053.003)    - /etc/crontab, /etc/cron.d/* 변경
  5. systemd service 변조          (T1543.002)    - /etc/systemd/system/*.service 변경
  6. 파일 무결성 모니터링          (T1565)        - /etc/passwd, /etc/shadow, sudoers
  7. Windows Event Log             (T1078)        - 4625(로그인 실패), 4720(계정 생성)

권한 정책 (설계서):
  - 에이전트는 민감 파일의 원문을 서버로 전송하지 않음
  - 로컬에서 hash/mtime만 계산하여 전송
  - 높은 권한 탐지는 optional privileged mode로 분리
  - 기본 모드: low-privilege mode (auth.log/nginx.log 중심)
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from infrared_agent.config import AgentSettings


# ============================================================
# 모니터링 대상 파일 정의
# ============================================================

class WatchedFile:
    """모니터링 대상 파일 정보."""

    def __init__(
        self,
        path: str,
        rule_id: str,
        mitre_technique: str,
        description: str,
        requires_root: bool = False,
    ):
        self.path = path
        self.rule_id = rule_id
        self.mitre_technique = mitre_technique
        self.description = description
        self.requires_root = requires_root


# 기본 모드 (low-privilege) - auth.log/nginx.log 외 추가 모니터링
_DEFAULT_WATCHED_FILES: list[WatchedFile] = [
    WatchedFile(
        "/root/.ssh/authorized_keys",
        "FIM-001",
        "T1098.004",
        "SSH authorized_keys 변경 감지",
        requires_root=True,
    ),
    WatchedFile(
        "/etc/ssh/sshd_config",
        "FIM-002",
        "T1563.001",
        "sshd_config 설정 변경 감지",
        requires_root=True,
    ),
    WatchedFile(
        "/etc/crontab",
        "FIM-003",
        "T1053.003",
        "crontab 변조 감지",
    ),
    WatchedFile(
        "/etc/passwd",
        "FIM-004",
        "T1565",
        "/etc/passwd 변조 감지 (계정 추가/변경)",
    ),
    WatchedFile(
        "/etc/sudoers",
        "FIM-005",
        "T1565",
        "sudoers 변조 감지 (권한 상승)",
        requires_root=True,
    ),
]

# cron.d 디렉토리 패턴 (동적으로 파일 목록)
_CRON_D_DIR = "/etc/cron.d"
_SYSTEMD_DIR = "/etc/systemd/system"


# ============================================================
# 파일 해시 계산 (원문 미전송 - hash/mtime만)
# ============================================================

def compute_file_hash(path: str) -> Optional[str]:
    """파일 SHA256 해시 계산. 접근 불가 시 None 반환."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_file_mtime(path: str) -> Optional[float]:
    """파일 mtime 반환."""
    try:
        return os.path.getmtime(path)
    except (PermissionError, FileNotFoundError, OSError):
        return None


def get_file_stat(path: str) -> Optional[dict]:
    """파일 stat 정보 (hash + mtime만, 원문 미포함)."""
    try:
        st = os.stat(path)
        file_hash = compute_file_hash(path)
        return {
            "path": path,
            "hash": file_hash,
            "mtime": st.st_mtime,
            "size": st.st_size,
            "mode": oct(stat.S_IMODE(st.st_mode)),
        }
    except (PermissionError, FileNotFoundError, OSError):
        return None


# ============================================================
# FIM 상태 저장소 (로컬)
# ============================================================

class FIMStateStore:
    """FIM 이전 상태 저장소 (로컬 JSON 파일)."""

    def __init__(self, state_path: str = "/var/lib/infrared/fim_state.json"):
        self.state_path = state_path
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        self._state: dict = self._load()

    def _load(self) -> dict:
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save(self) -> None:
        try:
            with open(self.state_path, "w") as f:
                json.dump(self._state, f)
        except OSError:
            pass

    def get(self, path: str) -> Optional[dict]:
        return self._state.get(path)

    def set(self, path: str, info: dict) -> None:
        self._state[path] = info
        self._save()


# ============================================================
# FIM 감시자
# ============================================================

class FIMWatcher:
    """파일 무결성 모니터링 감시자."""

    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self.privileged_mode = getattr(settings, "agent_privileged_mode", False)
        state_path = getattr(settings, "fim_state_path", "/var/lib/infrared/fim_state.json")
        self.store = FIMStateStore(state_path)
        self._watched = self._build_watch_list()

    def _build_watch_list(self) -> list[WatchedFile]:
        """감시 파일 목록 구성."""
        watched = []
        for wf in _DEFAULT_WATCHED_FILES:
            # 권한 필요 파일은 privileged mode에서만
            if wf.requires_root and not self.privileged_mode:
                continue
            if Path(wf.path).exists():
                watched.append(wf)

        # cron.d 디렉토리 파일들
        if Path(_CRON_D_DIR).is_dir():
            for cron_file in Path(_CRON_D_DIR).iterdir():
                if cron_file.is_file():
                    watched.append(WatchedFile(
                        str(cron_file),
                        "FIM-003",
                        "T1053.003",
                        f"cron job 파일 변조 감지: {cron_file.name}",
                    ))

        # systemd service 파일들 (privileged mode에서만)
        if self.privileged_mode and Path(_SYSTEMD_DIR).is_dir():
            for svc_file in Path(_SYSTEMD_DIR).glob("*.service"):
                watched.append(WatchedFile(
                    str(svc_file),
                    "FIM-005-SVC",
                    "T1543.002",
                    f"systemd 서비스 변조 감지: {svc_file.name}",
                    requires_root=True,
                ))

        return watched

    def check_changes(self) -> list[dict]:
        """변경된 파일 탐지. 원문 미포함, hash/mtime만 반환."""
        changes = []
        now = datetime.now(timezone.utc)

        for wf in self._watched:
            current = get_file_stat(wf.path)
            if current is None:
                continue

            previous = self.store.get(wf.path)

            if previous is None:
                # 최초 기록 (변경 아님)
                self.store.set(wf.path, current)
                continue

            # 해시 또는 mtime 변경 감지
            hash_changed = current["hash"] != previous.get("hash")
            mtime_changed = abs((current["mtime"] or 0) - (previous.get("mtime") or 0)) > 1

            if hash_changed or mtime_changed:
                change_event = {
                    "event_type": "fim_change",
                    "rule_id": wf.rule_id,
                    "mitre_technique": wf.mitre_technique,
                    "description": wf.description,
                    "path": wf.path,
                    # 원문 미포함 - hash/mtime만
                    "previous_hash": previous.get("hash"),
                    "current_hash": current["hash"],
                    "previous_mtime": previous.get("mtime"),
                    "current_mtime": current["mtime"],
                    "detected_at": now.isoformat(),
                }
                changes.append(change_event)

                # 상태 업데이트
                self.store.set(wf.path, current)

        return changes


# ============================================================
# auditd 로그 파서 (Phase 4-A 우선순위 1)
# ============================================================

class AuditdWatcher:
    """auditd 로그 감시자 (T1078, T1059).

    auditd는 커널 레벨 감사 로그.
    민감 파일 접근 / 의심 프로세스 실행 탐지.
    """

    _AUDITD_LOG_PATH = "/var/log/audit/audit.log"
    _SUSPICIOUS_COMMANDS = {
        "wget", "curl", "nc", "ncat", "netcat", "bash", "sh",
        "python", "python3", "perl", "ruby", "base64", "chmod",
        "chown", "useradd", "adduser", "passwd", "su", "sudo",
    }

    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self.log_path = getattr(settings, "auditd_log_path", self._AUDITD_LOG_PATH)
        self._last_position = 0

    def read_new_events(self) -> list[dict]:
        """새 auditd 이벤트 읽기."""
        if not os.path.exists(self.log_path):
            return []

        events = []
        try:
            with open(self.log_path, "r") as f:
                f.seek(self._last_position)
                for line in f:
                    event = self._parse_auditd_line(line.strip())
                    if event:
                        events.append(event)
                self._last_position = f.tell()
        except (PermissionError, OSError):
            pass

        return events

    def _parse_auditd_line(self, line: str) -> Optional[dict]:
        """auditd 로그 라인 파싱. 의심 이벤트만 반환."""
        if not line.startswith("type="):
            return None

        # EXECVE 타입 (프로세스 실행)
        if "type=EXECVE" in line or "type=SYSCALL" in line:
            for cmd in self._SUSPICIOUS_COMMANDS:
                if f' a0="{cmd}"' in line or f' exe="{cmd}"' in line or f'/{cmd}"' in line:
                    return {
                        "event_type": "suspicious_process",
                        "rule_id": "AUDITD-001",
                        "mitre_technique": "T1059",
                        "description": f"의심스러운 프로세스 실행 탐지: {cmd}",
                        "raw_summary": line[:200],  # 원문 200자 제한
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }

        # OPEN 타입 (민감 파일 접근)
        sensitive_paths = ["/etc/shadow", "/etc/passwd", "/root/.ssh", "/proc/"]
        if "type=PATH" in line:
            for spath in sensitive_paths:
                if spath in line:
                    return {
                        "event_type": "sensitive_file_access",
                        "rule_id": "AUDITD-002",
                        "mitre_technique": "T1078",
                        "description": f"민감 파일 접근 탐지: {spath}",
                        "raw_summary": line[:200],
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }

        return None


# ============================================================
# Windows Event Log 파서 (Phase 4-A 우선순위 7)
# ============================================================

class WindowsEventLogWatcher:
    """Windows Event Log 감시자.

    설계서 4-A:
    - 4625: 로그인 실패
    - 4720: 계정 생성
    """

    def __init__(self, settings: AgentSettings):
        self.settings = settings
        self._is_windows = platform.system() == "Windows"

    def read_new_events(self) -> list[dict]:
        """Windows 이벤트 로그에서 보안 이벤트 읽기."""
        if not self._is_windows:
            return []

        try:
            import win32evtlog  # type: ignore  # noqa: PLC0415
            return self._read_security_events()
        except ImportError:
            return []

    def _read_security_events(self) -> list[dict]:
        import win32evtlog  # type: ignore  # noqa: PLC0415
        events = []
        now = datetime.now(timezone.utc)

        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            win_events = win32evtlog.ReadEventLog(handle, flags, 0)

            for we in win_events[:50]:  # 최근 50개만
                event_id = we.EventID & 0xFFFF

                if event_id == 4625:  # 로그인 실패
                    events.append({
                        "event_type": "windows_login_failure",
                        "rule_id": "WIN-001",
                        "mitre_technique": "T1078",
                        "description": "Windows 로그인 실패",
                        "event_id": 4625,
                        "detected_at": now.isoformat(),
                    })
                elif event_id == 4720:  # 계정 생성
                    events.append({
                        "event_type": "windows_account_created",
                        "rule_id": "WIN-002",
                        "mitre_technique": "T1078",
                        "description": "Windows 계정 생성",
                        "event_id": 4720,
                        "detected_at": now.isoformat(),
                    })

            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

        return events


# ============================================================
# EXEC-001: /tmp 실행 파일 탐지 (v3.0)
# ============================================================

class TmpExecutionMonitor:
    """룰 ID: EXEC-001, MITRE: T1059.
    /proc/*/exe 심볼릭 링크가 /tmp, /var/tmp, /dev/shm을 가리키는 프로세스 탐지.
    10초 주기 폴링.
    """

    SUSPICIOUS_DIRS = ["/tmp/", "/var/tmp/", "/dev/shm/"]

    def check(self) -> list[dict]:
        events = []
        my_pid = str(os.getpid())
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            # 자기 자신(watchdog/에이전트 프로세스) 제외
            if pid_dir.name == my_pid:
                continue
            try:
                exe_path = str((pid_dir / "exe").resolve())
                if any(exe_path.startswith(d) for d in self.SUSPICIOUS_DIRS):
                    try:
                        cmdline = (
                            (pid_dir / "cmdline")
                            .read_bytes()
                            .replace(b"\x00", b" ")
                            .decode(errors="replace")
                            .strip()
                        )
                    except Exception:
                        cmdline = ""
                    events.append({
                        "event_type": "suspicious_process_execution",
                        "rule_id": "EXEC-001",
                        "mitre_technique": "T1059",
                        "description": "/tmp 계열 경로에서 실행 중인 의심 프로세스 탐지",
                        "pid": pid_dir.name,
                        "exe_path": exe_path,
                        "cmdline": cmdline[:200],
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    })
            except (PermissionError, FileNotFoundError, OSError):
                continue
        return events


# ============================================================
# EXEC-002: 웹서버 Child Process Shell 감지 (v3.0)
# ============================================================

class WebServerChildProcessMonitor:
    """룰 ID: EXEC-002, MITRE: T1505.003.
    nginx/apache2/php-fpm의 자식 프로세스 중 shell이 포함된 것 탐지.
    """

    WEB_PROCESS_NAMES = {"nginx", "apache2", "apache", "httpd", "php-fpm", "php"}
    SHELL_NAMES = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "nc", "ncat"}

    def _get_process_name(self, pid_str: str) -> str:
        try:
            return Path(f"/proc/{pid_str}/comm").read_text().strip()
        except (PermissionError, FileNotFoundError):
            return ""

    def _get_children(self, pid_str: str) -> list[str]:
        children = []
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                try:
                    status = (pid_dir / "status").read_text()
                    for line in status.splitlines():
                        if line.startswith("PPid:") and line.split()[1] == pid_str:
                            children.append(pid_dir.name)
                except (PermissionError, FileNotFoundError):
                    pass
        except (PermissionError, OSError):
            pass
        return children

    def check(self) -> list[dict]:
        events = []
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                name = self._get_process_name(pid_dir.name)
                if name not in self.WEB_PROCESS_NAMES:
                    continue
                for child_pid in self._get_children(pid_dir.name):
                    child_name = self._get_process_name(child_pid)
                    if child_name in self.SHELL_NAMES:
                        try:
                            cmdline = (
                                Path(f"/proc/{child_pid}/cmdline")
                                .read_bytes()
                                .replace(b"\x00", b" ")
                                .decode(errors="replace")
                                .strip()
                            )
                        except Exception:
                            cmdline = ""
                        events.append({
                            "event_type": "webserver_shell_spawn",
                            "rule_id": "EXEC-002",
                            "mitre_technique": "T1505.003",
                            "description": "웹서버 자식 프로세스에서 shell 실행 감지 — 웹셸 가능성",
                            "parent_pid": pid_dir.name,
                            "parent_process": name,
                            "child_pid": child_pid,
                            "child_process": child_name,
                            "cmdline": cmdline[:200],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        })
        except (PermissionError, OSError):
            pass
        return events


# ============================================================
# EXEC-003: 대량 파일 변경 감지 (랜섬웨어 전조) (v3.0)
# ============================================================

class BulkFileModificationMonitor:
    """룰 ID: EXEC-003, MITRE: T1486.
    60초 슬라이딩 윈도우에서 100건 이상 파일 변경 시 경보.
    inotify 없으면 mtime 폴링으로 대체.
    """

    WINDOW_SECONDS = 60
    THRESHOLD = 100
    WATCH_DIRS = ["/home", "/var/www", "/opt"]

    def __init__(self):
        self._event_times: deque = deque()
        self._last_mtimes: dict[str, float] = {}

    def check(self) -> list[dict]:
        now = time.time()
        # 윈도우 밖 이벤트 제거
        while self._event_times and self._event_times[0] < now - self.WINDOW_SECONDS:
            self._event_times.popleft()

        # mtime 폴링으로 변경 감지
        for watch_dir in self.WATCH_DIRS:
            if not Path(watch_dir).exists():
                continue
            try:
                for root, _, files in os.walk(watch_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            mtime = os.path.getmtime(fpath)
                            prev = self._last_mtimes.get(fpath)
                            if prev is not None and mtime > prev:
                                self._event_times.append(now)
                            self._last_mtimes[fpath] = mtime
                        except OSError:
                            pass
            except (PermissionError, OSError):
                pass

        if len(self._event_times) >= self.THRESHOLD:
            return [{
                "event_type": "bulk_file_modification",
                "rule_id": "EXEC-003",
                "mitre_technique": "T1486",
                "description": "60초 내 대량 파일 변경 감지 — 랜섬웨어 전조 가능성",
                "change_count": len(self._event_times),
                "window_seconds": self.WINDOW_SECONDS,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }]
        return []

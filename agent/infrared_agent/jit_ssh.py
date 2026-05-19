"""
JIT SSH — Just-In-Time SSH 키 주입 관리자 (PERSIST-JIT)
========================================================
평소에는 authorized_keys = 빈 파일.
관리자가 대시보드에서 요청 시 TTL 기반으로 임시 공개키를 주입하고
만료 후 자동 삭제한다.

설계서: InfraRed_v8_보안심화_설계서.md §7
MITRE:  T1098.004 (SSH Authorized Keys)

보안 특성:
  - authorized_keys는 평소 0 bytes (SSH 브루트포스 원천 차단)
  - 키 주입은 반드시 approval_required=True 경로
  - TTL(기본 10분, 최대 60분) 만료 시 자동 삭제
  - 주입/삭제 모든 이벤트 audit_logs에 기록
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID

logger = logging.getLogger("infrared_agent.jit_ssh")

# ---------------------------------------------------------------------------
# 상수
# ---------------------------------------------------------------------------

DEFAULT_TTL_MINUTES = 10
MAX_TTL_MINUTES = 60

VALID_KEY_TYPES = frozenset({"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"})

JIT_MARKER_PREFIX = "# InfraRed JIT SSH"


# ---------------------------------------------------------------------------
# 데이터 구조체
# ---------------------------------------------------------------------------

@dataclass
class JITKeyEntry:
    command_id: str
    target_user: str
    public_key: str
    expires_at: datetime
    auth_keys_path: str
    original_content: str = ""


@dataclass
class CommandResult:
    success: bool
    reason: str = ""
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 키 검증 / 핑거프린트
# ---------------------------------------------------------------------------

def _is_valid_pubkey(key: str) -> bool:
    """SSH 공개키 형식 검증 (타입 + base64 페이로드)."""
    parts = key.strip().split()
    if len(parts) < 2:
        return False
    if parts[0] not in VALID_KEY_TYPES:
        return False
    try:
        base64.b64decode(parts[1], validate=True)
    except Exception:
        return False
    return True


def _fingerprint(public_key: str) -> str:
    """SHA-256 기반 SSH 키 핑거프린트 (OpenSSH 형식)."""
    parts = public_key.strip().split()
    if len(parts) < 2:
        return "unknown"
    try:
        raw = base64.b64decode(parts[1])
        digest = hashlib.sha256(raw).digest()
        encoded = base64.b64encode(digest).decode().rstrip("=")
        return f"SHA256:{encoded}"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# JITSSHManager
# ---------------------------------------------------------------------------

class JITSSHManager:
    """
    Just-In-Time SSH 키 주입 관리자.

    Commander에서 inject_temp_ssh_key / revoke_temp_ssh_key 명령을 수신하면
    이 클래스가 실제 authorized_keys 파일을 조작한다.
    """

    def __init__(self, report_callback=None):
        """
        report_callback: 이벤트를 백엔드에 보고하는 async 함수 (선택)
            signature: async (event_type: str, data: dict) -> None
        """
        self._entries: dict[str, JITKeyEntry] = {}  # command_id → entry
        self._report = report_callback
        self._watcher_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    async def inject_temp_key(self, command: dict) -> CommandResult:
        """
        임시 SSH 공개키를 authorized_keys에 추가.

        command 필드:
            id           — command_id
            payload:
                public_key   — SSH 공개키 (필수)
                ttl_minutes  — 유효 시간 (기본 10분, 최대 60분)
                user         — 대상 Unix 사용자 (기본 "deploy")
        """
        payload = command.get("payload", {})
        public_key = payload.get("public_key", "").strip()
        ttl_minutes = min(
            int(payload.get("ttl_minutes", DEFAULT_TTL_MINUTES)),
            MAX_TTL_MINUTES,
        )
        target_user = payload.get("user", "deploy")
        command_id = command.get("id", "unknown")

        # 키 형식 검증
        if not _is_valid_pubkey(public_key):
            return CommandResult(success=False, reason="invalid_public_key_format")

        auth_keys_path = Path(f"/home/{target_user}/.ssh/authorized_keys")

        # .ssh 디렉토리 생성
        auth_keys_path.parent.mkdir(parents=True, exist_ok=True)

        # 기존 내용 백업 (복원용)
        current_content = auth_keys_path.read_text() if auth_keys_path.exists() else ""

        # 키 주입
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        marker = (
            f"{JIT_MARKER_PREFIX} — expires {expires_at.isoformat()} "
            f"command_id={command_id}\n"
        )
        with open(auth_keys_path, "a") as f:
            f.write(f"\n{marker}")
            f.write(f"{public_key}\n")

        # 파일 권한 600 강제
        auth_keys_path.chmod(0o600)

        entry = JITKeyEntry(
            command_id=command_id,
            target_user=target_user,
            public_key=public_key,
            expires_at=expires_at,
            auth_keys_path=str(auth_keys_path),
            original_content=current_content,
        )
        self._entries[command_id] = entry

        fingerprint = _fingerprint(public_key)
        logger.info(
            "JIT SSH 키 주입: user=%s ttl=%dmin fingerprint=%s command_id=%s",
            target_user, ttl_minutes, fingerprint, command_id,
        )

        if self._report:
            await self._report("jit_ssh_injected", {
                "command_id": command_id,
                "target_user": target_user,
                "fingerprint": fingerprint,
                "expires_at": expires_at.isoformat(),
                "ttl_minutes": ttl_minutes,
            })

        return CommandResult(
            success=True,
            data={
                "ttl_minutes": ttl_minutes,
                "expires_at": expires_at.isoformat(),
                "target_user": target_user,
                "key_fingerprint": fingerprint,
            },
        )

    async def revoke_temp_key(self, command: dict) -> CommandResult:
        """
        임시 SSH 키 즉시 삭제.

        command 필드:
            payload.command_id — 삭제할 inject 커맨드 ID
        """
        payload = command.get("payload", {})
        target_command_id = payload.get("command_id")

        if not target_command_id or target_command_id not in self._entries:
            return CommandResult(success=False, reason="command_id_not_found")

        entry = self._entries.pop(target_command_id)
        await self._do_revoke(entry, reason="manual")

        return CommandResult(success=True, data={"revoked_command_id": target_command_id})

    async def start_ttl_watcher(self) -> None:
        """TTL 만료 감시 루프를 백그라운드 태스크로 시작."""
        if self._watcher_task and not self._watcher_task.done():
            return
        self._watcher_task = asyncio.create_task(self._ttl_expiry_worker())
        logger.info("JIT SSH TTL 감시 시작")

    async def stop_ttl_watcher(self) -> None:
        """TTL 감시 루프 정지."""
        if self._watcher_task:
            self._watcher_task.cancel()
            try:
                await self._watcher_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    async def _ttl_expiry_worker(self) -> None:
        """30초마다 TTL 만료 키를 자동 삭제 (Dead Man's Switch 패턴)."""
        while True:
            now = datetime.now(timezone.utc)
            expired = [
                entry for entry in self._entries.values()
                if entry.expires_at <= now
            ]
            for entry in expired:
                self._entries.pop(entry.command_id, None)
                await self._do_revoke(entry, reason="ttl_expired")
            await asyncio.sleep(30)

    async def _do_revoke(self, entry: JITKeyEntry, reason: str) -> None:
        """authorized_keys에서 JIT 마커 및 키를 제거."""
        auth_path = Path(entry.auth_keys_path)
        if not auth_path.exists():
            return

        lines = auth_path.read_text().splitlines(keepends=True)
        cleaned: list[str] = []
        skip_next = False

        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if JIT_MARKER_PREFIX in line and entry.command_id in line:
                skip_next = True  # 마커 다음 줄 = 실제 키 → 스킵
                continue
            cleaned.append(line)

        auth_path.write_text("".join(cleaned))
        auth_path.chmod(0o600)

        logger.info(
            "JIT SSH 키 삭제: user=%s reason=%s command_id=%s",
            entry.target_user, reason, entry.command_id,
        )

        if self._report:
            await self._report("jit_ssh_revoked", {
                "command_id": entry.command_id,
                "target_user": entry.target_user,
                "reason": reason,
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            })

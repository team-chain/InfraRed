"""Honeytoken(허니토큰) 배포 및 탐지 관리자.

허니토큰 종류:
  - file    : /tmp 등에 가짜 민감 파일을 생성하고 접근 감시
  - account : 더미 시스템 계정을 생성하고 로그인 감시

탐지 룰:
  - DECEPTION-001 : 허니토큰 파일 접근 (FIM 이벤트에서 honeytoken 경로 매칭)
  - DECEPTION-002 : 허니토큰 계정 로그인 (AUTH 이벤트에서 ir_honeypot_ 계정명 매칭)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.db.connection import get_session

log = logging.getLogger(__name__)

_HONEYTOKEN_FILE_PREFIX = "/tmp/.infrared_token_"
_HONEYTOKEN_ACCOUNT_PREFIX = "ir_honeypot_"
_HONEYTOKEN_CONTENT = (
    "# InfraRed Honeytoken — DO NOT USE\n"
    "# Accessing this file triggers a security alert.\n"
    "INFRARED_TOKEN=honeytoken_active\n"
)


@dataclass
class HoneytokenAlert:
    token_id: str
    token_type: str         # 'file' | 'account'
    tenant_id: str
    triggered_at: datetime
    source_ip: Optional[str]
    username: Optional[str]
    raw_event: dict


class HoneytokenManager:
    """허니토큰을 배포하고 트리거 이벤트를 처리한다."""

    # ------------------------------------------------------------------ #
    # 배포
    # ------------------------------------------------------------------ #

    async def deploy_file_token(
        self,
        tenant_id: str,
        path: Optional[str] = None,
    ) -> str:
        """파일 허니토큰을 배포하고 token_id를 반환한다.

        파일을 생성하고, auditd 룰(가능한 경우)을 설정한다.
        이 메서드는 최선을 다해 실행하며, OS 명령 실패 시 로그만 남긴다.
        """
        token_id = str(uuid.uuid4()).replace("-", "")[:16]
        if path is None:
            path = f"{_HONEYTOKEN_FILE_PREFIX}{token_id}"

        # 파일 생성
        try:
            with open(path, "w") as fh:
                fh.write(_HONEYTOKEN_CONTENT)
            os.chmod(path, 0o644)
            log.info("honeytoken file deployed: path=%s token_id=%s", path, token_id)
        except OSError as exc:
            log.warning("honeytoken file creation failed (path=%s): %s", path, exc)

        # auditd 룰 추가 (가능한 경우)
        try:
            subprocess.run(
                ["auditctl", "-w", path, "-p", "rwa", "-k", f"honeytoken_{token_id}"],
                capture_output=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            log.debug("auditctl not available; skipping audit rule for %s", path)

        await self._persist_token(tenant_id, token_id, "file", {"path": path})
        return token_id

    async def deploy_account_token(
        self,
        tenant_id: str,
        username: Optional[str] = None,
    ) -> str:
        """계정 허니토큰을 배포하고 token_id를 반환한다.

        useradd -M -s /bin/false 로 더미 계정을 생성한다.
        권한이 없으면 로그만 남기고 token_id를 반환한다.
        """
        token_id = str(uuid.uuid4()).replace("-", "")[:8]
        if username is None:
            username = f"{_HONEYTOKEN_ACCOUNT_PREFIX}{token_id}"

        try:
            result = subprocess.run(
                ["useradd", "-M", "-s", "/bin/false", username],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                log.info("honeytoken account deployed: username=%s token_id=%s", username, token_id)
            else:
                log.warning(
                    "useradd failed (rc=%d): %s",
                    result.returncode,
                    result.stderr.decode(errors="replace"),
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            log.warning("honeytoken account creation failed (username=%s): %s", username, exc)

        await self._persist_token(tenant_id, token_id, "account", {"username": username})
        return token_id

    # ------------------------------------------------------------------ #
    # 트리거 감지
    # ------------------------------------------------------------------ #

    def check_trigger(self, event_log: dict) -> Optional[HoneytokenAlert]:
        """이벤트 로그에서 허니토큰 트리거 여부를 확인하고 알림을 반환한다.

        DECEPTION-001: FIM 이벤트에서 honeytoken 파일 경로 포함 여부
        DECEPTION-002: AUTH 이벤트에서 ir_honeypot_ 계정명 포함 여부
        """
        event_type = str(event_log.get("event_type", "")).lower()
        tenant_id = str(event_log.get("tenant_id", ""))
        now = datetime.now(tz=timezone.utc)

        # DECEPTION-001: FIM 이벤트
        if event_type in ("fim", "file_access", "file_integrity"):
            file_path = str(event_log.get("file_path", event_log.get("path", "")))
            if _HONEYTOKEN_FILE_PREFIX in file_path:
                # token_id를 경로에서 추출
                token_id = file_path.replace(_HONEYTOKEN_FILE_PREFIX, "")[:16]
                return HoneytokenAlert(
                    token_id=token_id,
                    token_type="file",
                    tenant_id=tenant_id,
                    triggered_at=now,
                    source_ip=event_log.get("source_ip"),
                    username=event_log.get("username"),
                    raw_event=event_log,
                )

        # DECEPTION-002: AUTH 이벤트
        if event_type in ("auth", "ssh_login", "ssh_login_success", "ssh_login_failed", "login"):
            username = str(event_log.get("username", ""))
            if username.startswith(_HONEYTOKEN_ACCOUNT_PREFIX):
                # token_id를 계정명에서 추출
                token_id = username.replace(_HONEYTOKEN_ACCOUNT_PREFIX, "")
                return HoneytokenAlert(
                    token_id=token_id,
                    token_type="account",
                    tenant_id=tenant_id,
                    triggered_at=now,
                    source_ip=event_log.get("source_ip"),
                    username=username,
                    raw_event=event_log,
                )

        return None

    # ------------------------------------------------------------------ #
    # DB 헬퍼
    # ------------------------------------------------------------------ #

    async def _persist_token(
        self,
        tenant_id: str,
        token_id: str,
        token_type: str,
        metadata: dict,
    ) -> None:
        """허니토큰 정보를 honeytoken_events 테이블에 기록한다."""
        try:
            sql = text("""
                INSERT INTO honeytoken_events
                    (tenant_id, token_id, token_type, source_ip, username, raw_event)
                VALUES
                    (:tenant_id, :token_id, :token_type, NULL, NULL, :raw_event::jsonb)
            """)
            async with get_session() as session:
                await session.execute(sql, {
                    "tenant_id": tenant_id,
                    "token_id": token_id,
                    "token_type": token_type,
                    "raw_event": json.dumps({"action": "deployed", **metadata}),
                })
        except Exception as exc:
            log.warning("honeytoken persist 실패: %s", exc)

    async def record_trigger(self, tenant_id: str, alert: HoneytokenAlert) -> None:
        """트리거된 허니토큰 이벤트를 DB에 기록한다."""
        try:
            sql = text("""
                INSERT INTO honeytoken_events
                    (tenant_id, token_id, token_type, triggered_at, source_ip, username, raw_event)
                VALUES
                    (:tenant_id, :token_id, :token_type, :triggered_at,
                     :source_ip, :username, :raw_event::jsonb)
            """)
            async with get_session() as session:
                await session.execute(sql, {
                    "tenant_id": tenant_id,
                    "token_id": alert.token_id,
                    "token_type": alert.token_type,
                    "triggered_at": alert.triggered_at,
                    "source_ip": alert.source_ip,
                    "username": alert.username,
                    "raw_event": json.dumps(alert.raw_event, default=str),
                })
        except Exception as exc:
            log.warning("honeytoken trigger record 실패: %s", exc)

    async def list_events(self, tenant_id: str, limit: int = 100) -> list[dict]:
        """허니토큰 트리거 이벤트 목록을 반환한다."""
        try:
            sql = text("""
                SELECT id, token_id, token_type, triggered_at, source_ip, username, raw_event
                FROM honeytoken_events
                WHERE tenant_id = :tenant_id
                ORDER BY triggered_at DESC
                LIMIT :limit
            """)
            async with get_session() as session:
                rows = (await session.execute(sql, {"tenant_id": tenant_id, "limit": limit})).all()
            return [
                {
                    "id": row.id,
                    "token_id": row.token_id,
                    "token_type": row.token_type,
                    "triggered_at": row.triggered_at.isoformat() if row.triggered_at else None,
                    "source_ip": row.source_ip,
                    "username": row.username,
                }
                for row in rows
            ]
        except Exception as exc:
            log.warning("honeytoken list_events 실패: %s", exc)
            return []

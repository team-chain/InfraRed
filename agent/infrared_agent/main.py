"""InfraRed agent entrypoint.

수집 소스 (설계서 v2.0 Phase 4-A):
  - auth.log       → SSH 이상 행위 탐지 (AUTH-001~006)
  - nginx.log      → 웹 공격 탐지 (WEB-HNY-001, WEB-001~007, NET-001)
  - FIM 감시       → authorized_keys / sshd_config / cron / sudoers 변경 감지
  - auditd (opt)   → 의심 프로세스 실행 / 민감 파일 접근 (privileged mode)
  - Windows (opt)  → 이벤트 ID 4625/4720 (Windows 에이전트)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid

from infrared_agent.client import AgentClient
from infrared_agent.commander import Commander
from infrared_agent.config import AgentSettings
from infrared_agent.fim_watcher import AuditdWatcher, FIMWatcher, WindowsEventLogWatcher
from infrared_agent.nginx_tailer import NginxLogTailer
from infrared_agent.offset_store import OffsetStore
from infrared_agent.s3_uploader import S3LogUploader
from infrared_agent.tailer import AuthLogTailer


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("infrared_agent")


async def _send_log_events(
    tailer: AuthLogTailer | NginxLogTailer,
    client: AgentClient,
    store: OffsetStore,
    log_path: str,
    s3: S3LogUploader | None = None,
    s3_enabled: bool = False,
) -> str | None:
    """로그 타일러에서 새 이벤트를 읽어 백엔드로 전송. 마지막 event_id 반환."""
    last_event_id = None
    try:
        for envelope, new_offset, inode in tailer.read_new_events():
            await client.send_event(envelope)
            store.set(log_path, inode, new_offset)
            last_event_id = envelope["event_id"]
            log.info(
                "sent source=%s event_id=%s offset=%s",
                envelope.get("raw_source", "unknown"),
                last_event_id,
                new_offset,
            )
            if s3_enabled and s3:
                raw_line = envelope.get("raw_line") or str(envelope.get("timestamp", ""))
                s3.push(raw_line)
    except FileNotFoundError as exc:
        log.warning("log file not found path=%s", exc.filename)
    except Exception:
        log.exception("event send loop failed source=%s", log_path)
    return last_event_id


async def run() -> None:
    settings = AgentSettings()
    if not settings.agent_token:
        raise RuntimeError("AGENT_TOKEN is required")

    offset_dir = os.path.dirname(settings.agent_offset_db)
    if offset_dir:
        os.makedirs(offset_dir, exist_ok=True)

    store = OffsetStore(settings.agent_offset_db)
    auth_tailer = AuthLogTailer(settings, store)
    nginx_tailer = NginxLogTailer(settings, store) if settings.agent_nginx_enabled else None
    client = AgentClient(settings)
    commander = Commander(settings, client)
    s3 = S3LogUploader(settings)

    # Phase 4-A: FIM / auditd / Windows 감시자 초기화
    fim_enabled = getattr(settings, "agent_fim_enabled", True)
    fim_watcher = FIMWatcher(settings) if fim_enabled else None
    auditd_enabled = getattr(settings, "agent_auditd_enabled", False)
    auditd_watcher = AuditdWatcher(settings) if auditd_enabled else None
    windows_watcher = WindowsEventLogWatcher(settings)

    last_heartbeat = 0.0
    last_command_poll = 0.0
    last_fim_check = 0.0
    last_event_id: str | None = None

    _fim_check_interval = getattr(settings, "agent_fim_interval_seconds", 60)

    log.info(
        "agent_started auth_log=%s nginx_log=%s nginx_enabled=%s s3=%s fim=%s auditd=%s",
        settings.agent_auth_log_path,
        settings.agent_nginx_log_path,
        settings.agent_nginx_enabled,
        settings.s3_enabled,
        fim_enabled,
        auditd_enabled,
    )

    try:
        while True:
            # ── auth.log 수집 ─────────────────────────────────────────────────
            ev_id = await _send_log_events(
                auth_tailer, client, store,
                settings.agent_auth_log_path,
                s3=s3, s3_enabled=settings.s3_enabled,
            )
            if ev_id:
                last_event_id = ev_id

            # -- nginx.log 수집 ------------------------------------------------
            if nginx_tailer is not None:
                ev_id = await _send_log_events(
                    nginx_tailer, client, store,
                    settings.agent_nginx_log_path,
                    s3=s3, s3_enabled=settings.s3_enabled,
                )
                if ev_id:
                    last_event_id = ev_id

            # -- Heartbeat (설정 간격마다) ---------------------------------------
            now = time.monotonic()
            if now - last_heartbeat >= settings.heartbeat_interval_sec:
                try:
                    await client.send_heartbeat()
                    last_heartbeat = now
                except Exception:
                    log.exception("heartbeat failed")

            # -- Command poll ---------------------------------------------------
            if now - last_command_poll >= settings.agent_command_poll_interval_seconds:
                try:
                    await commander.poll_and_execute()
                    last_command_poll = now
                except Exception:
                    log.exception("command poll failed")

            # -- Phase 4-A: FIM 감시 (60초 간격) --------------------------------
            if fim_watcher and (now - last_fim_check >= _fim_check_interval):
                try:
                    changes = fim_watcher.check_changes()
                    for change in changes:
                        envelope = _build_fim_envelope(change, settings)
                        await client.send_event(envelope)
                        log.warning(
                            "fim_change_detected rule=%s path=%s",
                            change.get("rule_id"),
                            change.get("path"),
                        )
                    last_fim_check = now
                except Exception:
                    log.exception("fim check failed")

            # -- Phase 4-A: auditd 감시 (있으면) ---------------------------------
            if auditd_watcher:
                try:
                    auditd_events = auditd_watcher.read_new_events()
                    for evt in auditd_events:
                        envelope = _build_fim_envelope(evt, settings)
                        await client.send_event(envelope)
                except Exception:
                    log.exception("auditd watch failed")

            # -- Phase 4-A: Windows Event Log ------------------------------------
            try:
                win_events = windows_watcher.read_new_events()
                for evt in win_events:
                    envelope = _build_fim_envelope(evt, settings)
                    await client.send_event(envelope)
            except Exception:
                pass  # Windows 이벤트는 선택적

            await asyncio.sleep(settings.agent_poll_interval_seconds)

    except asyncio.CancelledError:
        log.info("agent_stopped")
    finally:
        try:
            await client.close()
        except Exception:
            pass


def _build_fim_envelope(change: dict, settings: AgentSettings) -> dict:
    """FIM/auditd 이벤트를 Ingestion API 형식으로 변환."""
    return {
        "event_id": f"FIM-{uuid.uuid4().hex[:12]}",
        "agent_id": settings.agent_id,
        "tenant_id": settings.tenant_id,
        "asset_id": settings.asset_id,
        "event_type": change.get("event_type", "fim_change"),
        "timestamp": change.get("detected_at"),
        "raw_source": "fim",
        "rule_id": change.get("rule_id"),
        "mitre_technique": change.get("mitre_technique"),
        "description": change.get("description"),
        "payload": {
            k: v for k, v in change.items()
            if k not in {"detected_at", "event_type", "rule_id", "mitre_technique", "description"}
        },
    }


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()

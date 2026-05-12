"""InfraRed agent entrypoint.

수집 소스 (설계서 2.1):
  - auth.log    → SSH 이상 행위 탐지 (AUTH-001~006)
  - nginx.log   → 웹 공격 탐지 (WEB-HNY-001, WEB-001~007, NET-001)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time

from infrared_agent.client import AgentClient
from infrared_agent.commander import Commander
from infrared_agent.config import AgentSettings
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

    last_heartbeat = 0.0
    last_command_poll = 0.0
    last_event_id: str | None = None

    log.info(
        "agent_started auth_log=%s nginx_log=%s nginx_enabled=%s s3=%s",
        settings.agent_auth_log_path,
        settings.agent_nginx_log_path,
        settings.agent_nginx_enabled,
        settings.s3_enabled,
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
            if now - last_heartbeat >= settings.agent_heartbeat_interval_seconds:
                try:
                    await client.send_heartbeat()
                    last_heartbeat = now
                except Exception:
                    log.exception("heartbeat failed")

            # -- Command poll ---------------------------------------------------
            if now - last_command_poll >= settings.agent_command_poll_interval_seconds:
                try:
                    await commander.poll()
                    last_command_poll = now
                except Exception:
                    log.exception("command poll failed")

            await asyncio.sleep(settings.agent_poll_interval_seconds)

    except asyncio.CancelledError:
        log.info("agent_stopped")
    finally:
        try:
            await client.close()
        except Exception:
            pass


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
